from pydantic import BaseModel, ConfigDict, field_validator
from datetime import datetime
from typing import Literal
from app.schemas.enums import ScanStatus

class URLScanRequest(BaseModel):
    url: str

class ScanResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    target: str
    scan_type: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class ScanCreateRequest(BaseModel):
    target: str
    scan_type: Literal["url", "file", "api"] = "url"

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 5:
            raise ValueError("Target must be at least 5 characters long.")
        if not v.startswith(("http://", "https://")):
            raise ValueError("Target must start with http:// or https://")
        
        # SSRF Protection
        from app.config import settings
        if not settings.ALLOW_PRIVATE_SCANS:
            from urllib.parse import urlparse
            import socket
            import ipaddress
            try:
                parsed = urlparse(v)
                host = parsed.hostname
                if not host:
                    raise ValueError("Target URL does not contain a valid hostname.")
                # Resolve hostname to IP
                ip_str = socket.gethostbyname(host)
                ip = ipaddress.ip_address(ip_str)
                if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                    raise ValueError(f"Scanning private or loopback IP ranges ({ip_str}) is forbidden for security reasons.")
            except socket.gaierror:
                raise ValueError("Could not resolve target hostname.")
            except ValueError as ve:
                raise ValueError(str(ve))
            except Exception:
                raise ValueError("Invalid target host configuration.")
        return v

class ScanCreateResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    results: dict

class ScanDetailResponse(BaseModel):
    scan_id: str
    target: str
    scan_type: str
    status: ScanStatus
    created_at: datetime
    user_id: int

    model_config = ConfigDict(from_attributes=True)


