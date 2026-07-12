import json
import logging
import uuid
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.observability.context import request_id_var, user_id_var, scan_id_var
from app.observability.logging_config import JsonFormatter, SecretRedactionFilter, redact_secrets
from app.observability.metrics import MetricsService
from app.config import settings

# A test client specifically using app to test health endpoint and request ID headers
from app.main import app as main_app

@pytest.fixture
def client():
    return TestClient(main_app)

def test_request_id_middleware_generates_id(client):
    """Verify that every response has an X-Request-ID header generated if none is sent."""
    response = client.get("/")
    assert response.status_code == 200
    assert "X-Request-ID" in response.headers
    # Verify it is a valid UUID
    val = response.headers["X-Request-ID"]
    uuid.UUID(val)

def test_request_id_middleware_propagates_existing(client):
    """Verify that an incoming X-Request-ID is returned back in the response headers."""
    test_id = "test-request-id-12345"
    response = client.get("/", headers={"X-Request-ID": test_id})
    assert response.status_code == 200
    assert response.headers.get("X-Request-ID") == test_id

def test_health_endpoint_enhanced(client):
    """Verify that the health endpoint returns the enhanced status payload."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "database" in data
    assert "gemini" in data
    assert "version" in data
    assert "uptime_seconds" in data
    assert data["version"] == settings.APP_VERSION
    assert isinstance(data["uptime_seconds"], float)

def test_metrics_service_calculations():
    """Verify that MetricsService singleton tracks metrics correctly."""
    metrics = MetricsService()
    metrics.reset()

    # Base values
    summary = metrics.get_summary()
    assert summary["total_scans"] == 0
    assert summary["successful_scans"] == 0
    assert summary["failed_scans"] == 0
    assert summary["avg_scan_time_ms"] == 0.0
    assert summary["avg_ai_analysis_time_ms"] == 0.0

    # Record some scans
    metrics.record_scan(100.0, success=True)
    metrics.record_scan(200.0, success=False)
    metrics.record_scan(150.0, success=True)

    # Record AI Analysis
    metrics.record_ai_analysis(50.0)
    metrics.record_ai_analysis(70.0)

    # Record Scanner
    metrics.record_scanner("HeaderScanner", 12.0)
    metrics.record_scanner("HeaderScanner", 18.0)

    summary = metrics.get_summary()
    assert summary["total_scans"] == 3
    assert summary["successful_scans"] == 2
    assert summary["failed_scans"] == 1
    # Average scan: (100 + 200 + 150) / 3 = 150
    assert summary["avg_scan_time_ms"] == 150.0
    # Average AI: (50 + 70) / 2 = 60
    assert summary["avg_ai_analysis_time_ms"] == 60.0

    # Check scanner specific tracker
    assert "HeaderScanner" in metrics.scanner_durations
    assert metrics.scanner_durations["HeaderScanner"] == [12.0, 18.0]

    # Reset and check again
    metrics.reset()
    summary = metrics.get_summary()
    assert summary["total_scans"] == 0
    assert len(metrics.scanner_durations) == 0

def test_context_vars():
    """Verify context variables can be set and read."""
    request_id_var.set("req-1")
    user_id_var.set("user-2")
    scan_id_var.set("scan-3")

    assert request_id_var.get() == "req-1"
    assert user_id_var.get() == "user-2"
    assert scan_id_var.get() == "scan-3"

    # Reset to default
    request_id_var.set("-")
    user_id_var.set("-")
    scan_id_var.set("-")

def test_json_formatter_structure():
    """Verify that JsonFormatter outputs valid JSON with contextvar values."""
    request_id_var.set("req-test-999")
    user_id_var.set("user-test-777")
    scan_id_var.set("scan-test-888")

    formatter = JsonFormatter()
    logger = logging.getLogger("test_json_formatter")
    record = logger.makeRecord(
        name="test_logger",
        level=logging.INFO,
        fn="test_file.py",
        lno=42,
        msg="This is a test log message",
        args=(),
        exc_info=None
    )

    formatted_str = formatter.format(record)
    data = json.loads(formatted_str)

    assert data["message"] == "This is a test log message"
    assert data["level"] == "INFO"
    assert data["request_id"] == "req-test-999"
    assert data["user_id"] == "user-test-777"
    assert data["scan_id"] == "scan-test-888"
    assert data["lineno"] == 42

    # Reset
    request_id_var.set("-")
    user_id_var.set("-")
    scan_id_var.set("-")

def test_secret_redaction_utility():
    """Verify that redact_secrets strips keys and secrets."""
    # Test GEMINI_API_KEY redaction
    msg1 = "My key is GEMINI_API_KEY=AIzaSyA12345XYZ"
    assert "AIzaSyA12345XYZ" not in redact_secrets(msg1)
    assert "***REDACTED***" in redact_secrets(msg1)

    # Test JWT_SECRET_KEY redaction
    msg2 = "Using JWT_SECRET_KEY: supersecretkeygoeshere"
    assert "supersecretkeygoeshere" not in redact_secrets(msg2)
    assert "***REDACTED***" in redact_secrets(msg2)

    # Test generic password pattern redaction
    msg3 = '{"username": "admin", "password": "MySuperSecretPassword123"}'
    assert "MySuperSecretPassword123" not in redact_secrets(msg3)
    assert "***REDACTED***" in redact_secrets(msg3)

def test_secret_redaction_filter():
    """Verify that SecretRedactionFilter changes log record message in-place."""
    filt = SecretRedactionFilter()
    logger = logging.getLogger("test_redact")
    record = logger.makeRecord(
        name="test_logger",
        level=logging.WARNING,
        fn="test_file.py",
        lno=10,
        msg="Failed due to password=my_password_123",
        args=(),
        exc_info=None
    )

    assert filt.filter(record) is True
    assert "my_password_123" not in record.msg
    assert "***REDACTED***" in record.msg
