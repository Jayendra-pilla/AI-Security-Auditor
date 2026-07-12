"""
SSRF Protection and DNS Rebinding prevention layer.

Provides:
- Safe DNS Pinning: context manager to bind hostnames to verified IPs.
- Safe HTTP Client: a secure wrapper around httpx.Client with manual redirect
  validation and DNS rebinding protections.
"""
import ipaddress
import socket
import threading
from contextlib import contextmanager
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, Optional
import httpx
import logging

logger = logging.getLogger(__name__)

# Thread-local storage to hold the DNS overrides during request execution
_thread_local = threading.local()


def is_safe_ip(ip_str: str) -> bool:
    """
    Check if an IP string is safe (not loopback, private, link-local, multicast,
    or otherwise reserved). Supports IPv4 and IPv6.
    """
    try:
        ip = ipaddress.ip_address(ip_str)

        # Block loopback, private networks, link-local, reserved, multicast
        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        ):
            return False

        # Additional specific checks
        ip_s = str(ip)
        if ip_s in ("0.0.0.0", "255.255.255.255", "::"):
            return False

        return True
    except ValueError:
        return False


def resolve_and_verify_ip(host: str) -> str:
    """
    Resolve a hostname to all its IP addresses.
    Raises ValueError if ANY resolved IP address is unsafe (prevents split-horizon
    or mixed public/private DNS records).
    Returns the first resolved IP if all are safe.
    """
    if not host:
        raise ValueError("Invalid host")

    try:
        # Check if the host is already an IP address
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        if not is_safe_ip(host):
            raise ValueError(f"Target host is an unsafe IP: {host}")
        return host

    try:
        # Resolve all addresses (v4/v6)
        addr_info = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        resolved_ips = set(info[4][0] for info in addr_info)

        if not resolved_ips:
            raise ValueError(f"Could not resolve host: {host}")

        # If any resolved IP is unsafe, block the entire resolution
        for ip in resolved_ips:
            if not is_safe_ip(ip):
                raise ValueError(f"Host '{host}' resolved to unsafe IP: {ip}")

        # Return the first resolved IP
        return list(resolved_ips)[0]
    except socket.gaierror as e:
        raise ValueError(f"DNS lookup failed for host '{host}': {str(e)}")
    except ValueError as ve:
        raise ValueError(str(ve))
    except Exception as e:
        raise ValueError(f"Unexpected error resolving host '{host}': {str(e)}")


# ---------------------------------------------------------------------------
# Global socket.getaddrinfo hook
# ---------------------------------------------------------------------------

_original_getaddrinfo = socket.getaddrinfo


def _patched_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    """
    Patched version of socket.getaddrinfo that inspects thread-local storage
    for a host-to-IP pin. If pinned, forces resolution to that IP.
    """
    overrides = getattr(_thread_local, "dns_overrides", None)
    if overrides and host in overrides:
        pinned_ip = overrides[host]
        # Resolve the pinned IP instead
        return _original_getaddrinfo(pinned_ip, port, family, type, proto, flags)
    return _original_getaddrinfo(host, port, family, type, proto, flags)


def install_dns_patch() -> None:
    """Install the global DNS lookup patch."""
    socket.getaddrinfo = _patched_getaddrinfo


@contextmanager
def pin_dns(host: str, ip: str):
    """Context manager to bind a hostname to a verified IP thread-locally."""
    if not hasattr(_thread_local, "dns_overrides"):
        _thread_local.dns_overrides = {}
    _thread_local.dns_overrides[host] = ip
    try:
        yield
    finally:
        if host in _thread_local.dns_overrides:
            del _thread_local.dns_overrides[host]


# ---------------------------------------------------------------------------
# Safe HTTP Client
# ---------------------------------------------------------------------------

class SafeHTTPClient:
    """
    SSRF-resistant HTTP client.
    - Pins hostname DNS queries to verified IPs to prevent DNS rebinding.
    - Handles redirects manually, validating the target IP at each hop.
    - Limits redirection depth to prevent resource exhaustion.
    """

    def __init__(self, timeout: float = 2.0, max_redirects: int = 5):
        self.timeout = timeout
        self.max_redirects = max_redirects
        # Disable redirects inside the underlying httpx Client
        self.client = httpx.Client(timeout=timeout, follow_redirects=False)

    def __enter__(self):
        self.client.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.client.__exit__(exc_type, exc_val, exc_tb)

    def get(self, url: str, **kwargs) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs) -> httpx.Response:
        return self.request("HEAD", url, **kwargs)

    def post(self, url: str, **kwargs) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """
        Send a request, verifying host safety and handling redirects safely.
        """
        current_url = url
        redirects_followed = 0

        while True:
            parsed = urlparse(current_url)
            host = parsed.hostname
            if not host:
                raise ValueError(f"Invalid hostname in target URL: {current_url}")

            # Verify and resolve host IP
            safe_ip = resolve_and_verify_ip(host)

            # Pin host to the resolved safe IP thread-locally during this call
            with pin_dns(host, safe_ip):
                resp = self.client.request(method, current_url, **kwargs)

            # Check for redirect status codes
            if resp.status_code in (301, 302, 303, 307, 308):
                if redirects_followed >= self.max_redirects:
                    raise ValueError(f"SSRF Prevention: Redirect limit of {self.max_redirects} exceeded.")

                location = resp.headers.get("Location")
                if not location:
                    # No redirect target provided, return response
                    return resp

                # Construct absolute redirect URL
                current_url = urljoin(current_url, location)
                redirects_followed += 1

                # If status code is 303, standard behavior is redirect with GET
                if resp.status_code == 303:
                    method = "GET"
            else:
                return resp
