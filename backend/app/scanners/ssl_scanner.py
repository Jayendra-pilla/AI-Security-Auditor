from app.observability.ssrf_prevention import SafeHTTPClient
import time
import logging
import socket
import ssl
import urllib.parse
from datetime import datetime, timezone
from app.scanners.scanner_utils import datetime_now_utc_str, get_cvss, get_mitre_mapping
from app.scanners.confidence_engine import confidence_for_network_finding, calculate_confidence

logger = logging.getLogger(__name__)

class SSLScanner:
    """
    Scanner to inspect TLS/SSL encryption configuration.
    Includes multi-hop HTTP→HTTPS redirect validation with loop and downgrade detection.
    """
    def scan(self, target: str) -> dict:
        logger.info(f"SSLScanner starting for target: {target}")
        start_time = time.perf_counter()
        findings = []
        status = "success"
        severity = "Informational"

        # Determine hostname
        base_url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        parsed = urllib.parse.urlparse(base_url)
        hostname = parsed.hostname or target
        if not hostname:
            hostname = target

        # ────────────────────────────────────────────────────────────
        # 1. HTTP → HTTPS redirection check (multi-hop, loop detection)
        # ────────────────────────────────────────────────────────────
        try:
            http_url = f"http://{hostname}"
            max_redirects = 10
            current_url = http_url
            visited_urls = set()
            redirect_chain = []
            reaches_https = False
            downgrade_detected = False
            loop_detected = False
            final_status = None
            final_headers = {}

            with SafeHTTPClient(timeout=2.0) as client:
                for hop in range(max_redirects + 1):
                    if current_url in visited_urls:
                        loop_detected = True
                        break
                    visited_urls.add(current_url)

                    resp = client.get(current_url, follow_redirects=False)
                    redirect_chain.append({
                        "url": current_url,
                        "status": resp.status_code,
                        "location": resp.headers.get("Location", ""),
                    })
                    final_status = resp.status_code
                    final_headers = dict(resp.headers)

                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("Location", "")
                        if not location:
                            break

                        # Resolve relative URLs
                        next_url = urllib.parse.urljoin(current_url, location)

                        # Check if we've reached HTTPS
                        if next_url.startswith("https://"):
                            reaches_https = True
                            # Keep resolving to get the final HTTPS URL and verify it
                            current_url = next_url
                            continue

                        # Detect downgrade: HTTPS → HTTP
                        if current_url.startswith("https://") and next_url.startswith("http://"):
                            downgrade_detected = True
                            break

                        current_url = next_url
                    else:
                        # Non-redirect response — check if we're on HTTPS
                        if current_url.startswith("https://"):
                            reaches_https = True
                        break

            chain_evidence = " → ".join(
                f"{hop['url']} [{hop['status']}]" for hop in redirect_chain
            )

            # Check ALPN and HTTP/2 support
            alpn_protocols = []
            http2_supported = False
            try:
                ssl_context = ssl.create_default_context()
                ssl_context.set_alpn_protocols(['h2', 'http/1.1'])
                with socket.create_connection((hostname, 443), timeout=2.0) as sock:
                    with ssl_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        negotiated_protocol = ssock.selected_alpn_protocol()
                        if negotiated_protocol:
                            alpn_protocols.append(negotiated_protocol)
                            if negotiated_protocol == 'h2':
                                http2_supported = True
            except Exception:
                pass

            # Detect HTTP/3 from Alt-Svc header
            http3_supported = False
            alt_svc = final_headers.get("Alt-Svc", "")
            if "h3" in alt_svc.lower():
                http3_supported = True

            if loop_detected:
                conf = calculate_confidence(
                    validation_methods=["Network Validation", "Redirect Chain Validation"],
                    evidence_quality="high",
                    evidence_count=len(redirect_chain),
                    detection_method="Active HTTP Scan",
                    verification_method="Redirect Loop Trace Validation",
                )
                findings.append({
                    "title": "HTTP Redirect Loop Detected",
                    "severity": "Medium",
                    "confidence": conf["confidence"],
                    **{k: v for k, v in conf.items() if k != "confidence"},
                    "evidence": f"Redirect loop: {chain_evidence}",
                    "http_status": final_status,
                    "affected_url": http_url,
                    "scanner_name": "SSLScanner",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": "GET",
                    "response_headers": str(final_headers)[:200],
                    "owasp_mapping": "A05:2021-Security Misconfiguration",
                    "cwe_mapping": "CWE-319",
                    "description": f"HTTP redirect chain forms a loop and never reaches HTTPS. Chain: {chain_evidence}",
                    "recommendation": "Fix the redirect configuration to avoid loops and ensure HTTP traffic reaches HTTPS."
                })
                severity = "Medium"
                status = "warning"

            elif downgrade_detected:
                cvss = get_cvss("missing_https_redirect")
                mitre = get_mitre_mapping("missing_https")
                conf = calculate_confidence(
                    validation_methods=["Network Validation", "Redirect Chain Validation"],
                    evidence_quality="high",
                    evidence_count=len(redirect_chain),
                    detection_method="Active HTTP Scan",
                    verification_method="Redirect Downgrade Trace Validation",
                )
                findings.append({
                    "title": "HTTPS Downgrade Redirect Detected",
                    "severity": "High",
                    "confidence": conf["confidence"],
                    **{k: v for k, v in conf.items() if k != "confidence"},
                    "evidence": f"Redirect chain downgrades from HTTPS to HTTP: {chain_evidence}",
                    "http_status": final_status,
                    "affected_url": http_url,
                    "scanner_name": "SSLScanner",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": "GET",
                    "response_headers": str(final_headers)[:200],
                    "owasp_mapping": "A02:2021-Cryptographic Failures",
                    "cwe_mapping": "CWE-319",
                    "cvss_estimate": str(cvss.get("base_score", "6.5")),
                    "cvss_vector": cvss.get("vector", ""),
                    "mitre_attack": mitre,
                    "references": ["https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures"],
                    "description": f"The redirect chain downgrades from HTTPS back to HTTP, exposing traffic to interception. Chain: {chain_evidence}",
                    "recommendation": "Ensure all redirects in the chain maintain HTTPS. Never redirect from HTTPS to HTTP."
                })
                severity = "High"
                status = "warning"

            elif not reaches_https:
                cvss = get_cvss("missing_https_redirect")
                mitre = get_mitre_mapping("missing_https")
                conf = calculate_confidence(
                    validation_methods=["Network Validation", "Redirect Chain Validation"],
                    evidence_quality="high",
                    evidence_count=len(redirect_chain),
                    detection_method="Active HTTP Scan",
                    verification_method="10-Hop Redirect Path Validation",
                )
                findings.append({
                    "title": "Missing HTTP to HTTPS Redirection",
                    "severity": "Medium",
                    "confidence": conf["confidence"],
                    **{k: v for k, v in conf.items() if k != "confidence"},
                    "evidence": f"After following {len(redirect_chain)} hop(s), HTTPS was never reached. Chain: {chain_evidence}",
                    "http_status": final_status,
                    "affected_url": http_url,
                    "scanner_name": "SSLScanner",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": "GET",
                    "response_headers": str(final_headers)[:200],
                    "response_snippet": "",
                    "matched_payload": "N/A",
                    "matched_header": "N/A",
                    "owasp_mapping": "A05:2021-Security Misconfiguration",
                    "cwe_mapping": "CWE-319",
                    "cvss_estimate": str(cvss.get("base_score", "6.5")),
                    "cvss_vector": cvss.get("vector", ""),
                    "mitre_attack": mitre,
                    "references": ["https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration"],
                    "description": f"The web server does not redirect HTTP to HTTPS after following up to {max_redirects} redirects. Chain: {chain_evidence}",
                    "recommendation": "Configure a permanent 301 redirect from HTTP (port 80) to HTTPS (port 443) for all routes."
                })
                severity = "Medium"
                status = "warning"

            # Check for HTTP/2 and HTTP/3 support disclosures
            h2_info = "Supported" if http2_supported else "Not Supported"
            h3_info = "Supported" if http3_supported else "Not Supported"
            conf_h2 = calculate_confidence(
                validation_methods=["Network Validation", "TLS Handshake Validation"],
                evidence_quality="high",
                evidence_count=2,
                detection_method="ALPN Probing",
                verification_method="TLS Handshake Negotiation",
            )
            findings.append({
                "title": "HTTP/2 and HTTP/3 Protocol Support Discovered",
                "severity": "Informational",
                "confidence": conf_h2["confidence"],
                **{k: v for k, v in conf_h2.items() if k != "confidence"},
                "evidence": f"HTTP/2 Support: {h2_info} (ALPN: {alpn_protocols}), HTTP/3 Support: {h3_info} (Alt-Svc: '{alt_svc}')",
                "http_status": "N/A",
                "affected_url": f"https://{hostname}",
                "scanner_name": "SSLScanner",
                "timestamp": datetime_now_utc_str(),
                "request_method": "CONNECT",
                "description": f"Audited HTTP/2 and HTTP/3 protocols support. HTTP/2: {h2_info}, HTTP/3: {h3_info}.",
                "recommendation": "Configure modern protocols to speed up performance and improve transport encryption efficiency."
            })

        except Exception as e:
            logger.debug(f"HTTP to HTTPS redirect check failed: {str(e)}")

        # ────────────────────────────────────────────────────────────
        # 2. SSL/TLS socket inspections
        # ────────────────────────────────────────────────────────────
        cert_data = None
        tls_version = None
        cipher_info = None
        conn_error = None
        self_signed = False
        expired = False
        hostname_mismatch = False

        # Attempt secure handshake first
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=3.0) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_data = ssock.getpeercert()
                    tls_version = ssock.version()
                    cipher_info = ssock.cipher()
        except Exception as err:
            conn_error = err
            logger.debug(f"SSL standard connection failed: {str(err)}. Attempting unverified diagnosis...")

        # If standard connection fails, perform diagnosis using unverified context
        if conn_error:
            try:
                unverified_context = ssl._create_unverified_context()
                with socket.create_connection((hostname, 443), timeout=3.0) as sock:
                    with unverified_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert_data = ssock.getpeercert(binary_form=False)
                        tls_version = ssock.version()
                        cipher_info = ssock.cipher()
                
                # Check for Self-Signed cert
                if cert_data:
                    issuer = dict(x[0] for x in cert_data.get("issuer", []))
                    subject = dict(x[0] for x in cert_data.get("subject", []))
                    if issuer and subject and issuer == subject:
                        self_signed = True

                    # Check expiration
                    not_after_str = cert_data.get("notAfter")
                    if not_after_str:
                        try:
                            expiry_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            if expiry_date < datetime.now(timezone.utc):
                                expired = True
                        except Exception:
                            pass

                # Check for Hostname mismatch
                if not self_signed and not expired:
                    hostname_mismatch = True

            except Exception as diag_err:
                logger.debug(f"SSL diagnostic connection failed: {str(diag_err)}")

        # ────────────────────────────────────────────────────────────
        # 3. Report socket inspection findings
        # ────────────────────────────────────────────────────────────
        if cert_data:
            # TLS Version check
            if tls_version and tls_version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                cvss = get_cvss("deprecated_tls")
                mitre = get_mitre_mapping("deprecated_tls")
                conf = confidence_for_network_finding(True, False, True)
                findings.append({
                    "title": f"Deprecated TLS Protocol Enabled: {tls_version}",
                    "severity": "High",
                    "confidence": conf["confidence"],
                    "evidence": f"TLS protocol version negotiation: {tls_version}",
                    "http_status": "N/A",
                    "affected_url": f"https://{hostname}",
                    "scanner_name": "SSLScanner",
                    "detection_method": "TLS Version Negotiation",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": "CONNECT",
                    "response_headers": "N/A",
                    "response_snippet": f"Protocol: {tls_version}, Cipher: {cipher_info}",
                    "matched_payload": "N/A",
                    "matched_header": "N/A",
                    "owasp_mapping": "A02:2021-Cryptographic Failures",
                    "cwe_mapping": "CWE-326",
                    "cvss_estimate": str(cvss.get("base_score", "7.5")),
                    "cvss_vector": cvss.get("vector", ""),
                    "mitre_attack": mitre,
                    "references": ["https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures"],
                    "description": f"The target supports deprecated TLS protocol version '{tls_version}', which is vulnerable to POODLE, BEAST, or other attacks.",
                    "recommendation": "Configure the server to disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1, allowing only TLS 1.2 and TLS 1.3."
                })
                severity = "High"
                status = "warning"

            # Weak ciphers check
            if cipher_info:
                cipher_name, ssl_ver, secret_bits = cipher_info
                is_weak = False
                reasons = []
                if secret_bits < 128:
                    is_weak = True
                    reasons.append(f"weak key length ({secret_bits} bits)")
                for weak_alg in ("rc4", "3des", "des", "md5", "cbc"):
                    if weak_alg in cipher_name.lower():
                        is_weak = True
                        reasons.append(f"deprecated algorithm '{weak_alg}'")
                
                if is_weak:
                    cvss = get_cvss("weak_cipher")
                    conf = confidence_for_network_finding(True, False, True)
                    findings.append({
                        "title": f"Weak Cipher Suite Supported: {cipher_name}",
                        "severity": "Medium",
                        "confidence": conf["confidence"],
                        "evidence": f"Cipher suite negotiated: {cipher_name} ({secret_bits} bits)",
                        "http_status": "N/A",
                        "affected_url": f"https://{hostname}",
                        "scanner_name": "SSLScanner",
                        "detection_method": "TLS Cipher Inspection",
                        "timestamp": datetime_now_utc_str(),
                        "request_method": "CONNECT",
                        "response_headers": "N/A",
                        "response_snippet": f"Cipher: {cipher_info}",
                        "matched_payload": "N/A",
                        "matched_header": "N/A",
                        "owasp_mapping": "A02:2021-Cryptographic Failures",
                        "cwe_mapping": "CWE-327",
                        "cvss_estimate": str(cvss.get("base_score", "5.9")),
                        "cvss_vector": cvss.get("vector", ""),
                        "references": ["https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures"],
                        "description": f"The server negotiated a weak cipher suite: {cipher_name} ({', '.join(reasons)}).",
                        "recommendation": "Configure the web server to disable weak cipher suites (particularly RC4, 3DES, and export-grade ciphers)."
                    })
                    if severity in ("Informational", "Low"):
                        severity = "Medium"
                        status = "warning"

            # Expiration
            if expired:
                cvss = get_cvss("expired_cert")
                conf = confidence_for_network_finding(True, False, True)
                findings.append({
                    "title": "Expired SSL/TLS Certificate",
                    "severity": "High",
                    "confidence": conf["confidence"],
                    "evidence": f"Certificate notAfter date: {cert_data.get('notAfter')}",
                    "http_status": "N/A",
                    "affected_url": f"https://{hostname}",
                    "scanner_name": "SSLScanner",
                    "detection_method": "Certificate Expiration Verification",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": "CONNECT",
                    "response_headers": "N/A",
                    "response_snippet": str(cert_data)[:200],
                    "matched_payload": "N/A",
                    "matched_header": "N/A",
                    "owasp_mapping": "A05:2021-Security Misconfiguration",
                    "cwe_mapping": "CWE-298",
                    "cvss_estimate": str(cvss.get("base_score", "7.4")),
                    "cvss_vector": cvss.get("vector", ""),
                    "references": ["https://cwe.mitre.org/data/definitions/298.html"],
                    "description": f"The TLS certificate for {hostname} expired on {cert_data.get('notAfter')}.",
                    "recommendation": "Renew the SSL/TLS certificate immediately."
                })
                severity = "High"
                status = "warning"

            # Self-signed cert
            if self_signed:
                cvss = get_cvss("self_signed_cert")
                conf = confidence_for_network_finding(True, False, True)
                findings.append({
                    "title": "Self-Signed SSL/TLS Certificate",
                    "severity": "High",
                    "confidence": conf["confidence"],
                    "evidence": f"Issuer CN matches Subject CN: {dict(cert_data.get('issuer', [])).get('commonName', 'Unknown')}",
                    "http_status": "N/A",
                    "affected_url": f"https://{hostname}",
                    "scanner_name": "SSLScanner",
                    "detection_method": "Certificate Issuer Verification",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": "CONNECT",
                    "response_headers": "N/A",
                    "response_snippet": str(cert_data)[:200],
                    "matched_payload": "N/A",
                    "matched_header": "N/A",
                    "owasp_mapping": "A02:2021-Cryptographic Failures",
                    "cwe_mapping": "CWE-295",
                    "cvss_estimate": str(cvss.get("base_score", "7.4")),
                    "cvss_vector": cvss.get("vector", ""),
                    "references": ["https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures"],
                    "description": f"The target uses a self-signed TLS certificate. Browsers will show security warnings.",
                    "recommendation": "Install a valid TLS certificate issued by a trusted Certificate Authority (CA) (e.g. Let's Encrypt)."
                })
                severity = "High"
                status = "warning"

            # Hostname mismatch
            if hostname_mismatch:
                cvss = get_cvss("hostname_mismatch")
                conf = confidence_for_network_finding(True, False, True)
                findings.append({
                    "title": "SSL/TLS Hostname Mismatch",
                    "severity": "High",
                    "confidence": conf["confidence"],
                    "evidence": f"Requested hostname: {hostname}, Subject Alternative Names: {cert_data.get('subjectAltName', 'None')}",
                    "http_status": "N/A",
                    "affected_url": f"https://{hostname}",
                    "scanner_name": "SSLScanner",
                    "detection_method": "Certificate Hostname Verification",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": "CONNECT",
                    "response_headers": "N/A",
                    "response_snippet": str(cert_data)[:200],
                    "matched_payload": "N/A",
                    "matched_header": "N/A",
                    "owasp_mapping": "A05:2021-Security Misconfiguration",
                    "cwe_mapping": "CWE-297",
                    "cvss_estimate": str(cvss.get("base_score", "7.4")),
                    "cvss_vector": cvss.get("vector", ""),
                    "references": ["https://cwe.mitre.org/data/definitions/297.html"],
                    "description": f"The TLS certificate subject names do not match the requested hostname '{hostname}'.",
                    "recommendation": "Configure the web server with an SSL certificate matching the requested domain or SAN list."
                })
                severity = "High"
                status = "warning"

            # OCSP Check
            ocsp = cert_data.get("OCSP")
            if not ocsp:
                findings.append({
                    "title": "OCSP Stapling Not Configured",
                    "severity": "Informational",
                    "confidence": "High",
                    "evidence": "Certificate contains no OCSP information.",
                    "http_status": "N/A",
                    "affected_url": f"https://{hostname}",
                    "scanner_name": "SSLScanner",
                    "detection_method": "Certificate Parsing",
                    "timestamp": datetime_now_utc_str(),
                    "request_method": "CONNECT",
                    "description": "OCSP stapling or revocation check references are missing from the certificate.",
                    "recommendation": "Enable OCSP stapling on the web server configuration to speed up SSL handshake validation."
                })

        elif conn_error:
            findings.append({
                "title": "SSL/TLS Handshake Error",
                "severity": "Low",
                "confidence": "Low",
                "evidence": str(conn_error),
                "http_status": "N/A",
                "affected_url": f"https://{hostname}",
                "scanner_name": "SSLScanner",
                "detection_method": "TLS Socket Connection",
                "timestamp": datetime_now_utc_str(),
                "description": f"Could not perform TLS connection handshake with target. Error: {str(conn_error)}",
                "recommendation": "Verify target SSL configuration and port 443 binding."
            })
            severity = "Low"
            status = "failed"

        # Baseline info if no issues found
        if not findings:
            findings.append({
                "title": "SSL/TLS Configuration Verified",
                "severity": "Informational",
                "confidence": "High",
                "evidence": f"TLS version: {tls_version}, Cipher: {cipher_info[0] if cipher_info else 'N/A'}",
                "http_status": "N/A",
                "affected_url": f"https://{hostname}",
                "scanner_name": "SSLScanner",
                "detection_method": "TLS Handshake Inspection",
                "timestamp": datetime_now_utc_str(),
                "description": "The TLS certificate is valid, matches the target hostname, and uses secure TLS protocols/ciphers.",
                "recommendation": "Regularly audit TLS ciphers to phase out newly deprecated standards."
            })

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        logger.info(f"SSLScanner finished for target: {target} in {duration_ms}ms")
        return {
            "scanner": "SSLScanner",
            "status": status,
            "severity": severity,
            "findings": findings,
            "duration_ms": duration_ms
        }
