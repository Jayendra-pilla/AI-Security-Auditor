import json
import logging
import pytest
from fastapi import FastAPI, Depends, Request
from fastapi.testclient import TestClient
from unittest.mock import MagicMock
from app.reports.html_generator import HTMLReportGenerator
from app.reports.pdf_generator import PDFReportGenerator
from app.observability.ssrf_prevention import resolve_and_verify_ip, is_safe_ip, pin_dns, SafeHTTPClient, install_dns_patch
from app.observability.rate_limiter import RateLimiter
from app.observability.logging_config import redact_secrets
from app.models.scan import Scan
from app.models.report import Report
from app.models.vulnerability import Vulnerability
from datetime import datetime, timezone
import socket
import httpx

# Explicitly install the DNS patch for the test execution environment
install_dns_patch()

# 1. Output Encoding / Escaping test
def test_html_report_generator_escapes_xss():
    """Verify HTMLReportGenerator escapes dangerous XSS characters in scan target/findings."""
    scan = Scan(
        scan_id="scan-xss-123",
        target="<script>alert(1)</script>",
        scan_type="url",
        created_at=datetime.now(timezone.utc),
        status="completed"
    )
    report = Report(
        scan_id="scan-xss-123",
        grade="A",
        risk_score=15.0,
        summary="<script>alert('summary')</script>",
        statistics={},
        recommendations=["<script>alert('rec')</script>"],
        completed_at=datetime.now(timezone.utc)
    )
    vuln = Vulnerability(
        scan_id=1,
        severity="high",
        title="<script>alert('vuln')</script>",
        description="<script>alert('desc')</script>",
        recommendation="<script>alert('recom')</script>"
    )
    scan.vulnerabilities = [vuln]

    html_out = HTMLReportGenerator.generate(scan, report)
    
    # Verify no raw scripts are in the generated HTML
    assert "<script>alert(1)</script>" not in html_out
    assert "<script>alert('summary')</script>" not in html_out
    assert "<script>alert('vuln')</script>" not in html_out
    assert "<script>alert('desc')</script>" not in html_out
    assert "<script>alert('recom')</script>" not in html_out
    
    # Verify escaped equivalents are present
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_out
    assert "&lt;script&gt;alert(&#x27;summary&#x27;)&lt;/script&gt;" in html_out


def test_pdf_report_generator_escapes_special_chars():
    """Verify PDFReportGenerator escapes XML/HTML syntax characters to prevent ReportLab crashes."""
    scan = Scan(
        scan_id="scan-pdf-123",
        target="http://unsafe.com/?q=<val>&key=val2",
        scan_type="url",
        created_at=datetime.now(timezone.utc),
        status="completed"
    )
    report = Report(
        scan_id="scan-pdf-123",
        grade="B",
        risk_score=45.0,
        summary="Audit summary & recommendations <test>",
        statistics={},
        recommendations=["Mitigate & update <system>"],
        completed_at=datetime.now(timezone.utc)
    )
    vuln = Vulnerability(
        scan_id=1,
        severity="medium",
        title="SQL Injection & XSS vulnerability",
        description="Unsafe payload: <img src=x onerror=alert(1)>",
        recommendation="Escape & parameterize inputs"
    )
    scan.vulnerabilities = [vuln]

    pdf_bytes = PDFReportGenerator.generate(scan, report)
    assert len(pdf_bytes) > 0


# 2. SSRF prevention checks
def test_ssrf_safe_ip_detection():
    """Verify is_safe_ip rejects private, local, and loopback IP spaces."""
    assert is_safe_ip("1.1.1.1") is True
    assert is_safe_ip("8.8.8.8") is True
    assert is_safe_ip("127.0.0.1") is False
    assert is_safe_ip("10.0.0.1") is False
    assert is_safe_ip("172.16.50.2") is False
    assert is_safe_ip("192.168.1.100") is False
    assert is_safe_ip("169.254.169.254") is False
    assert is_safe_ip("::1") is False
    assert is_safe_ip("fc00::1") is False
    assert is_safe_ip("fe80::1") is False
    assert is_safe_ip("0.0.0.0") is False


def test_ssrf_resolve_and_verify_ip_loopback():
    """Verify resolve_and_verify_ip raises ValueError for local/loopback resolution."""
    with pytest.raises(ValueError):
        resolve_and_verify_ip("localhost")
    with pytest.raises(ValueError):
        resolve_and_verify_ip("127.0.0.1")
    with pytest.raises(ValueError):
        resolve_and_verify_ip("169.254.169.254")


# 3. DNS rebinding prevention via local pinning
def test_dns_rebinding_pinning():
    """Verify that pin_dns overrides the address returned by socket.getaddrinfo thread-locally."""
    test_host = "rebinding-target.xyz"
    pinned_ip = "1.2.3.4"
    
    with pin_dns(test_host, pinned_ip):
        res = socket.getaddrinfo(test_host, 80)
        assert len(res) > 0
        # The first address field should match pinned IP
        assert res[0][4][0] == pinned_ip


# 4. Redirect SSRF Protection
def test_safe_http_client_redirect_block():
    """Verify SafeHTTPClient blocks redirects pointing to private range destinations."""
    with SafeHTTPClient(timeout=1.0) as client:
        # Mock the underlying client request to return a redirect to a private IP
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 302
        mock_resp.headers = {"Location": "http://127.0.0.1/unsafe"}
        
        # Patch the client's internal request method
        client.client.request = MagicMock(return_value=mock_resp)
        
        with pytest.raises(ValueError) as excinfo:
            client.request("GET", "http://example.com/redirect")
        
        assert "unsafe" in str(excinfo.value).lower()


# 5. Rate Limiting Tests
def test_rate_limiter_blocks_bursts():
    """Verify RateLimiter triggers 429 after limit is reached."""
    limiter = RateLimiter(requests_limit=3, window_seconds=10)
    limiter.bypass_in_test = False
    app = FastAPI()
    
    @app.get("/limited", dependencies=[Depends(limiter)])
    def read_limited():
        return {"status": "ok"}
        
    client = TestClient(app)
    
    # First 3 requests should pass
    for _ in range(3):
        assert client.get("/limited").status_code == 200
        
    # 4th request must be blocked
    resp = client.get("/limited")
    assert resp.status_code == 429
    assert resp.json()["detail"] == "Too many requests. Please try again later."


# 6. Global Exception Handler & Detail Sanitization
def test_global_exception_handler_sanitizes_uncaught():
    """Verify that uncaught exceptions return a generic error message and hide database/paths info."""
    from app.main import app as main_app
    
    @main_app.get("/test-db-crash")
    def db_crash():
        raise Exception("OperationalError: database connection to postgres://postgres:password@localhost failed")
        
    # Set raise_server_exceptions=False so FastAPI handlers process the error
    client = TestClient(main_app, raise_server_exceptions=False)
    resp = client.get("/test-db-crash")
    
    assert resp.status_code == 500
    # Client should only receive the generic message, never the raw db connection string
    assert "postgres" not in resp.text
    assert "password" not in resp.text
    assert "OperationalError" not in resp.text
    assert resp.json()["detail"] == "An internal server error occurred."


# 7. Extended Logging Redaction
def test_extended_logs_redaction():
    """Verify redact_secrets handles Authorization header, Cookie header, and postgres password fields."""
    # Test Bearer header redaction
    log_line_auth = '{"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"}'
    redacted_auth = redact_secrets(log_line_auth)
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in redacted_auth
    assert "***REDACTED***" in redacted_auth

    # Test Cookie header redaction
    log_line_cookie = '{"Cookie": "session_id=abcdef12345"}'
    redacted_cookie = redact_secrets(log_line_cookie)
    assert "abcdef12345" not in redacted_cookie
    assert "***REDACTED***" in redacted_cookie

    # Test Postgres Password URI redaction
    log_line_db = "Connecting to postgresql://admin:SuperSecretPassword123@localhost:5432/mydb"
    redacted_db = redact_secrets(log_line_db)
    assert "SuperSecretPassword123" not in redacted_db
    assert "***REDACTED***" in redacted_db
