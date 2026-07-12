import os
import pytest

# Force SQLite for self-contained testing to avoid PostgreSQL dependency
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["ALLOW_PRIVATE_SCANS"] = "True"
os.environ["JWT_SECRET_KEY"] = "test-secret-key"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.database.db import get_db
from app.database.session import SessionLocal, engine
from app.database.base import Base
from app.models.user import User

# Ensure database tables are created in the test SQLite database
@pytest.fixture(scope="module", autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    if os.path.exists("./test.db"):
        try:
            os.remove("./test.db")
        except Exception:
            pass

@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture
def client():
    return TestClient(app)

def test_register_success(client):
    response = client.post(
        "/auth/register",
        json={
            "email": "test@example.com",
            "username": "testuser",
            "password": "Password123!",
            "role": "user"
        }
    )
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "test@example.com"
    assert data["username"] == "testuser"
    assert "id" in data
    assert "hashed_password" not in data

def test_register_duplicate_username(client):
    response = client.post(
        "/auth/register",
        json={
            "email": "test2@example.com",
            "username": "testuser",  # Duplicate
            "password": "Password123!",
            "role": "user"
        }
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "Username already registered"

def test_register_duplicate_email(client):
    response = client.post(
        "/auth/register",
        json={
            "email": "test@example.com",  # Duplicate
            "username": "testuser2",
            "password": "Password123!",
            "role": "user"
        }
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "Email already registered"

def test_register_weak_password(client):
    response = client.post(
        "/auth/register",
        json={
            "email": "weak@example.com",
            "username": "weakuser",
            "password": "123"  # Too short, fails custom validators
        }
    )
    assert response.status_code == 422

def test_login_success_username(client):
    response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "Password123!"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["token_type"] == "bearer"
    assert "access_token" in data

def test_login_success_email(client):
    response = client.post(
        "/auth/login",
        data={
            "username": "test@example.com",
            "password": "Password123!"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["token_type"] == "bearer"
    assert "access_token" in data

def test_login_fail_credentials(client):
    response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "WrongPassword!"
        }
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect username/email or password"

def test_login_inactive_user(client, db_session):
    # Retrieve test user and disable them
    user = db_session.query(User).filter(User.username == "testuser").first()
    assert user is not None
    user.is_active = False
    db_session.commit()

    response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "Password123!"
        }
    )
    assert response.status_code == 400
    assert "Inactive user" in response.json()["detail"]

    # Re-enable the user for subsequent tests
    user.is_active = True
    db_session.commit()

def test_get_me_success(client):
    # Perform login to obtain a valid access token
    login_response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "Password123!"
        }
    )
    token = login_response.json()["access_token"]

    # Access protected profile
    response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testuser"
    assert data["email"] == "test@example.com"

def test_get_me_invalid_token(client):
    response = client.get(
        "/auth/me",
        headers={"Authorization": "Bearer invalidtoken123"}
    )
    assert response.status_code == 401

def test_get_me_missing_token(client):
    response = client.get("/auth/me")
    assert response.status_code == 401

def test_create_scan_unauthenticated(client):
    response = client.post(
        "/scan",
        json={
            "target": "https://example.com",
            "scan_type": "url"
        }
    )
    assert response.status_code == 401

def test_create_scan_ssrf_prevention(client):
    # Perform login
    login_response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "Password123!"
        }
    )
    token = login_response.json()["access_token"]

    from app.config import settings
    # Override setting to False
    original_value = settings.ALLOW_PRIVATE_SCANS
    settings.ALLOW_PRIVATE_SCANS = False
    
    try:
        # Loopback URL
        response = client.post(
            "/scan",
            json={
                "target": "http://127.0.0.1",
                "scan_type": "url"
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 422
        assert "forbidden" in response.text.lower()
        
        # Private IP range URL
        response_private = client.post(
            "/scan",
            json={
                "target": "http://192.168.1.1",
                "scan_type": "url"
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response_private.status_code == 422
        assert "forbidden" in response_private.text.lower()
    finally:
        # Restore setting
        settings.ALLOW_PRIVATE_SCANS = original_value


def test_create_scan_success(client, db_session):
    login_response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "Password123!"
        }
    )
    token = login_response.json()["access_token"]

    response = client.post(
        "/scan",
        json={
            "target": "https://example.com/target",
            "scan_type": "url"
        },
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 201
    data = response.json()
    assert "scan_id" in data
    assert data["status"] == "completed"
    assert "results" in data
    scan_id_val = data["scan_id"]
    assert isinstance(scan_id_val, str)

    from app.models.scan import Scan
    scan_record = db_session.query(Scan).filter(Scan.scan_id == scan_id_val).first()
    assert scan_record is not None
    assert scan_record.target == "https://example.com/target"
    assert scan_record.scan_type == "url"
    assert scan_record.status == "completed"
    
    user = db_session.query(User).filter(User.username == "testuser").first()
    assert scan_record.user_id == user.id

def test_scan_management_flows(client, db_session):
    # Register testuser2
    response2 = client.post(
        "/auth/register",
        json={
            "email": "test2@example.com",
            "username": "testuser2",
            "password": "Password123!",
            "role": "user"
        }
    )
    assert response2.status_code == 201
    
    # Login testuser (owner)
    login_owner = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "Password123!"
        }
    )
    token_owner = login_owner.json()["access_token"]
    
    # Login testuser2 (other)
    login_other = client.post(
        "/auth/login",
        data={
            "username": "testuser2",
            "password": "Password123!"
        }
    )
    token_other = login_other.json()["access_token"]

    # Create a scan under testuser (owner)
    response_create = client.post(
        "/scan",
        json={
            "target": "https://owner-target.com",
            "scan_type": "url"
        },
        headers={"Authorization": f"Bearer {token_owner}"}
    )
    assert response_create.status_code == 201
    scan_id = response_create.json()["scan_id"]

    # Create a scan under testuser2 (other)
    response_create_other = client.post(
        "/scan",
        json={
            "target": "https://other-target.com",
            "scan_type": "url"
        },
        headers={"Authorization": f"Bearer {token_other}"}
    )
    assert response_create_other.status_code == 201

    # ---- Test GET /scan ----
    get_owner_scans = client.get(
        "/scan",
        headers={"Authorization": f"Bearer {token_owner}"}
    )
    assert get_owner_scans.status_code == 200
    owner_scans = get_owner_scans.json()
    assert len(owner_scans) >= 1
    targets = [s["target"] for s in owner_scans]
    assert "https://owner-target.com" in targets
    assert "https://other-target.com" not in targets

    # ---- Test GET /scan/{scan_id} ----
    get_details_owner = client.get(
        f"/scan/{scan_id}",
        headers={"Authorization": f"Bearer {token_owner}"}
    )
    assert get_details_owner.status_code == 200
    details = get_details_owner.json()
    assert details["scan_id"] == scan_id
    assert details["target"] == "https://owner-target.com"
    assert "user_id" in details

    get_details_other = client.get(
        f"/scan/{scan_id}",
        headers={"Authorization": f"Bearer {token_other}"}
    )
    assert get_details_other.status_code == 403
    assert get_details_other.json()["detail"] == "Access denied"

    get_details_nonexistent = client.get(
        "/scan/non-existent-uuid",
        headers={"Authorization": f"Bearer {token_owner}"}
    )
    assert get_details_nonexistent.status_code == 404
    assert get_details_nonexistent.json()["detail"] == "Scan not found"

    # ---- Test DELETE /scan/{scan_id} ----
    delete_other = client.delete(
        f"/scan/{scan_id}",
        headers={"Authorization": f"Bearer {token_other}"}
    )
    assert delete_other.status_code == 403
    assert delete_other.json()["detail"] == "Access denied"

    delete_nonexistent = client.delete(
        "/scan/non-existent-uuid",
        headers={"Authorization": f"Bearer {token_owner}"}
    )
    assert delete_nonexistent.status_code == 404
    assert delete_nonexistent.json()["detail"] == "Scan not found"

    # Setup mock cascade components
    from app.models.scan import Scan
    from app.models.report import Report
    from app.models.history import ScanHistory
    from datetime import datetime, timezone
    owner_scan_db = db_session.query(Scan).filter(Scan.scan_id == scan_id).first()
    assert owner_scan_db is not None

    # Delete existing report generated by execute_scan to prevent UNIQUE constraint violations
    db_session.query(Report).filter(Report.scan_db_id == owner_scan_db.id).delete()
    db_session.commit()

    db_report = Report(
        scan_id=scan_id,
        scan_db_id=owner_scan_db.id,
        risk_score=5.5,
        completed_at=datetime.now(timezone.utc)
    )
    db_history = ScanHistory(
        scan_id=scan_id,
        scan_db_id=owner_scan_db.id,
        user_id=owner_scan_db.user_id,
        status="completed",
        completed_at=datetime.now(timezone.utc)
    )
    db_session.add(db_report)
    db_session.add(db_history)
    db_session.commit()

    delete_success = client.delete(
        f"/scan/{scan_id}",
        headers={"Authorization": f"Bearer {token_owner}"}
    )
    assert delete_success.status_code == 200
    assert delete_success.json()["message"] == "Scan deleted successfully"

    assert db_session.query(Scan).filter(Scan.scan_id == scan_id).first() is None
    assert db_session.query(Report).filter(Report.scan_id == scan_id).first() is None
    assert db_session.query(ScanHistory).filter(ScanHistory.scan_id == scan_id).first() is None

def test_scan_management_unauthenticated(client):
    r1 = client.get("/scan")
    assert r1.status_code == 401

    r2 = client.get("/scan/some-scan-uuid")
    assert r2.status_code == 401

    r3 = client.delete("/scan/some-scan-uuid")
    assert r3.status_code == 401


def test_create_scan_execution_failed(client, db_session):
    from unittest.mock import patch
    
    # Perform login
    login_response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "Password123!"
        }
    )
    token = login_response.json()["access_token"]

    # Mock ScannerManager.run_all_scanners to raise an unexpected Exception
    with patch("app.scanners.scanner_manager.ScannerManager.run_all_scanners", side_effect=ValueError("Unexpected scan error")):
        response = client.post(
            "/scan",
            json={
                "target": "https://example.com/fail-target",
                "scan_type": "url"
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 500
        
        # Verify the database record exists and is in "failed" state
        from app.models.scan import Scan
        scan_record = db_session.query(Scan).filter(Scan.target == "https://example.com/fail-target").first()
        assert scan_record is not None
        assert scan_record.status == "failed"


def test_create_scan_status_transitions(client, db_session):
    from unittest.mock import patch
    
    # Perform login
    login_response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "Password123!"
        }
    )
    token = login_response.json()["access_token"]

    # We want to verify that scan.status goes from running to completed.
    # We mock run_all_scanners to inspect the scan status in the database DURING execution.
    status_during_execution = None
    
    def mock_run_all_scanners(target):
        nonlocal status_during_execution
        # Query the database scan record during execution
        from app.models.scan import Scan
        scan_record = db_session.query(Scan).filter(Scan.target == "https://example.com/status-transitions").first()
        if scan_record:
            status_during_execution = scan_record.status
        return {"target": target, "status": "completed"}

    with patch("app.scanners.scanner_manager.ScannerManager.run_all_scanners", side_effect=mock_run_all_scanners):
        response = client.post(
            "/scan",
            json={
                "target": "https://example.com/status-transitions",
                "scan_type": "url"
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "completed"
        
        # The status during execution should have been "running"
        assert status_during_execution == "running"
        
        # The final status in the database should be "completed"
        from app.models.scan import Scan
        scan_record = db_session.query(Scan).filter(Scan.target == "https://example.com/status-transitions").first()
        assert scan_record is not None
        assert scan_record.status == "completed"


def test_get_scan_results_success(client, db_session):
    from unittest.mock import patch
    # Perform login
    login_response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "Password123!"
        }
    )
    token = login_response.json()["access_token"]

    # We mock ScannerManager.run_all_scanners to return successful findings
    mock_scanner_results = {
        "target": "https://example.com/findings-target",
        "status": "completed",
        "total_scanners": 4,
        "completed_scanners": 4,
        "results": [
            {
                "scanner": "HeaderScanner",
                "status": "success",
                "findings": [
                    {
                        "severity": "Medium",
                        "title": "Missing Security Headers",
                        "description": "Clickjacking protection missing",
                        "recommendation": "Add X-Frame-Options header"
                    },
                    {
                        "severity": "Low",
                        "title": "Server Information Leak",
                        "description": "Server header exposes version",
                        "recommendation": "Remove Server header details"
                    }
                ]
            },
            {
                "scanner": "XSSScanner",
                "status": "success",
                "findings": {
                    "severity": "High",
                    "title": "Reflected Cross-Site Scripting",
                    "description": "Input parameter is reflected on page",
                    "recommendation": "Sanitize user input before reflection"
                }
            },
            {
                "scanner": "SSLScanner",
                "status": "failed",
                "error": "SSL handshake failure"
            },
            {
                "scanner": "CORSScanner",
                "status": "success",
                "findings": []  # Empty findings list
            }
        ]
    }

    with patch("app.scanners.scanner_manager.ScannerManager.run_all_scanners", return_value=mock_scanner_results):
        response = client.post(
            "/scan",
            json={
                "target": "https://example.com/findings-target",
                "scan_type": "url"
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 201
        data = response.json()
        scan_id = data["scan_id"]

        # Fetch findings via GET /scan/{scan_id}/results
        results_response = client.get(
            f"/scan/{scan_id}/results",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert results_response.status_code == 200
        results_data = results_response.json()
        assert results_data["scan_id"] == scan_id
        assert results_data["total_findings"] == 3
        
        # Verify findings list matches
        findings = results_data["results"]
        assert len(findings) == 3
        
        # Check HeaderScanner findings
        assert findings[0]["scanner_name"] == "HeaderScanner"
        assert findings[0]["severity"] == "Medium"
        assert findings[0]["title"] == "Missing Security Headers"
        
        assert findings[1]["scanner_name"] == "HeaderScanner"
        assert findings[1]["severity"] == "Low"
        assert findings[1]["title"] == "Server Information Leak"
        
        # Check XSSScanner findings (dict-based single finding)
        assert findings[2]["scanner_name"] == "XSSScanner"
        assert findings[2]["severity"] == "High"
        assert findings[2]["title"] == "Reflected Cross-Site Scripting"


def test_get_scan_results_ownership_and_errors(client, db_session):
    # Register and login user 1 (owner) and user 2 (other)
    # Login owner
    login_owner = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "Password123!"
        }
    )
    token_owner = login_owner.json()["access_token"]

    # Login other
    login_other = client.post(
        "/auth/login",
        data={
            "username": "testuser2",
            "password": "Password123!"
        }
    )
    token_other = login_other.json()["access_token"]

    # Create scan under owner (will complete with default failures)
    response = client.post(
        "/scan",
        json={
            "target": "https://example.com/ownership-test",
            "scan_type": "url"
        },
        headers={"Authorization": f"Bearer {token_owner}"}
    )
    assert response.status_code == 201
    scan_id = response.json()["scan_id"]

    # 1. Access by unauthorized user -> 403 Forbidden
    other_response = client.get(
        f"/scan/{scan_id}/results",
        headers={"Authorization": f"Bearer {token_other}"}
    )
    assert other_response.status_code == 403
    assert other_response.json()["detail"] == "Access denied"

    # 2. Access non-existent scan -> 404 Not Found
    non_existent_response = client.get(
        "/scan/non-existent-uuid-string/results",
        headers={"Authorization": f"Bearer {token_owner}"}
    )
    assert non_existent_response.status_code == 404
    assert non_existent_response.json()["detail"] == "Scan not found"

    # 3. Access unauthenticated -> 401 Unauthorized
    unauth_response = client.get(f"/scan/{scan_id}/results")
    assert unauth_response.status_code == 401


def test_report_generation_pipeline_success(client, db_session):
    from unittest.mock import patch
    # Perform login
    login_response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "Password123!"
        }
    )
    token = login_response.json()["access_token"]

    mock_gemini_analysis = {
        "summary": "AI generated summary of findings.",
        "risk_score": 92,
        "overall_severity": "Critical"
    }

    # We mock ScannerManager.run_all_scanners to return findings and mock Gemini Client response
    mock_scanner_results = {
        "target": "https://example.com/ai-report-success",
        "status": "completed",
        "total_scanners": 2,
        "completed_scanners": 2,
        "results": [
            {
                "scanner": "HeaderScanner",
                "status": "success",
                "findings": [
                    {
                        "severity": "High",
                        "title": "Missing CSP",
                        "description": "Content-Security-Policy is missing",
                        "recommendation": "Add CSP"
                    }
                ]
            }
        ]
    }

    with patch("app.scanners.scanner_manager.ScannerManager.run_all_scanners", return_value=mock_scanner_results), \
         patch("app.ai.gemini.GeminiClient.analyze_vulnerabilities", return_value=mock_gemini_analysis):
        
        response = client.post(
            "/scan",
            json={
                "target": "https://example.com/ai-report-success",
                "scan_type": "url"
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 201
        scan_id = response.json()["scan_id"]

        # Fetch report via GET /report/{scan_id}
        report_response = client.get(
            f"/report/{scan_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert report_response.status_code == 200
        report_data = report_response.json()
        assert report_data["scan_id"] == scan_id
        assert report_data["grade"] == "F"  # 92 -> F (high risk = bad grade)
        assert report_data["risk_score"] == 92.0
        assert report_data["summary"] == "AI generated summary of findings."
        assert report_data["statistics"]["high"] == 1
        assert "Missing Content-Security-Policy" in report_data["recommendations"][0]


def test_report_generation_gemini_timeout_fallback(client, db_session):
    from unittest.mock import patch
    import httpx
    # Perform login
    login_response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "Password123!"
        }
    )
    token = login_response.json()["access_token"]

    mock_scanner_results = {
        "target": "https://example.com/gemini-timeout",
        "status": "completed",
        "total_scanners": 2,
        "completed_scanners": 2,
        "results": [
            {
                "scanner": "HeaderScanner",
                "status": "success",
                "findings": [
                    {
                        "severity": "Medium",
                        "title": "Missing HSTS",
                        "description": "Strict-Transport-Security missing",
                        "recommendation": "Add HSTS header"
                    }
                ]
            }
        ]
    }

    # Mock timeout exception
    with patch("app.scanners.scanner_manager.ScannerManager.run_all_scanners", return_value=mock_scanner_results), \
         patch("app.ai.gemini.GeminiClient.analyze_vulnerabilities", side_effect=httpx.TimeoutException("Timeout occurred")):
        
        response = client.post(
            "/scan",
            json={
                "target": "https://example.com/gemini-timeout",
                "scan_type": "url"
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 201
        scan_id = response.json()["scan_id"]

        # Fetch report (should succeed and return fallback report)
        report_response = client.get(
            f"/report/{scan_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert report_response.status_code == 200
        report_data = report_response.json()
        assert report_data["scan_id"] == scan_id
        assert report_data["grade"] == "A"  # Medium = 8 points raw score -> A (low risk = good grade)
        assert report_data["risk_score"] == 8.0
        assert "fallback" in report_data["summary"].lower()
        assert report_data["statistics"]["medium"] == 1
        assert any("Strict-Transport-Security" in rec for rec in report_data["recommendations"])


def test_report_generation_missing_api_key_fallback(client, db_session):
    from unittest.mock import patch
    # Perform login
    login_response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "Password123!"
        }
    )
    token = login_response.json()["access_token"]

    mock_scanner_results = {
        "target": "https://example.com/missing-key",
        "status": "completed",
        "total_scanners": 2,
        "completed_scanners": 2,
        "results": [
            {
                "scanner": "CookieScanner",
                "status": "success",
                "findings": [
                    {
                        "severity": "Medium",
                        "title": "Weak Cookies",
                        "description": "Cookie missing Secure flag",
                        "recommendation": "Add Secure flag"
                    }
                ]
            }
        ]
    }

    # Mock ValueError for missing key
    with patch("app.scanners.scanner_manager.ScannerManager.run_all_scanners", return_value=mock_scanner_results), \
         patch("app.ai.gemini.GeminiClient.analyze_vulnerabilities", side_effect=ValueError("GEMINI_API_KEY is missing")):
        
        response = client.post(
            "/scan",
            json={
                "target": "https://example.com/missing-key",
                "scan_type": "url"
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 201
        scan_id = response.json()["scan_id"]

        report_response = client.get(
            f"/report/{scan_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert report_response.status_code == 200
        report_data = report_response.json()
        assert report_data["grade"] == "A"  # score = 8 -> A (low risk = good grade)
        assert report_data["risk_score"] == 8.0
        assert any("Secure, HttpOnly, and SameSite" in rec for rec in report_data["recommendations"])


def test_report_generation_gemini_api_failure_fallback(client, db_session):
    from unittest.mock import patch
    # Perform login
    login_response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "Password123!"
        }
    )
    token = login_response.json()["access_token"]

    mock_scanner_results = {
        "target": "https://example.com/api-failure",
        "status": "completed",
        "total_scanners": 2,
        "completed_scanners": 2,
        "results": [
            {
                "scanner": "OpenRedirectScanner",
                "status": "success",
                "findings": [
                    {
                        "severity": "High",
                        "title": "Open Redirect",
                        "description": "Input param is used for redirection",
                        "recommendation": "Sanitize parameter"
                    }
                ]
            }
        ]
    }

    # Mock general RuntimeError for API failure
    with patch("app.scanners.scanner_manager.ScannerManager.run_all_scanners", return_value=mock_scanner_results), \
         patch("app.ai.gemini.GeminiClient.analyze_vulnerabilities", side_effect=RuntimeError("Internal Server Error")):
        
        response = client.post(
            "/scan",
            json={
                "target": "https://example.com/api-failure",
                "scan_type": "url"
            },
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 201
        scan_id = response.json()["scan_id"]

        report_response = client.get(
            f"/report/{scan_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert report_response.status_code == 200
        report_data = report_response.json()
        assert report_data["grade"] == "B"  # High = 20 points -> B (moderate risk)
        assert report_data["risk_score"] == 20.0
        assert any("Open Redirect" in rec for rec in report_data["recommendations"])


def test_report_api_ownership_and_errors(client, db_session):
    # Perform login for two users
    login_owner = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "Password123!"
        }
    )
    token_owner = login_owner.json()["access_token"]

    login_other = client.post(
        "/auth/login",
        data={
            "username": "testuser2",
            "password": "Password123!"
        }
    )
    token_other = login_other.json()["access_token"]

    # 1. Create a scan under owner
    response = client.post(
        "/scan",
        json={
            "target": "https://example.com/owner-scan",
            "scan_type": "url"
        },
        headers={"Authorization": f"Bearer {token_owner}"}
    )
    assert response.status_code == 201
    scan_id = response.json()["scan_id"]

    # 2. Access by unauthorized user -> 403 Forbidden
    other_response = client.get(
        f"/report/{scan_id}",
        headers={"Authorization": f"Bearer {token_other}"}
    )
    assert other_response.status_code == 403
    assert other_response.json()["detail"] == "Access denied"

    # 3. Access non-existent scan -> 404 Not Found
    non_existent_response = client.get(
        "/report/non-existent-uuid-string",
        headers={"Authorization": f"Bearer {token_owner}"}
    )
    assert non_existent_response.status_code == 404
    assert non_existent_response.json()["detail"] == "Scan not found"

    # 4. Access unauthenticated -> 401 Unauthorized
    unauth_response = client.get(f"/report/{scan_id}")
    assert unauth_response.status_code == 401


def test_history_and_report_download(client, db_session):
    # Perform login for two users
    login_owner = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "Password123!"
        }
    )
    token_owner = login_owner.json()["access_token"]

    login_other = client.post(
        "/auth/login",
        data={
            "username": "testuser2",
            "password": "Password123!"
        }
    )
    token_other = login_other.json()["access_token"]

    # 1. Create a scan
    response = client.post(
        "/scan",
        json={
            "target": "https://example.com/download-test",
            "scan_type": "url"
        },
        headers={"Authorization": f"Bearer {token_owner}"}
    )
    assert response.status_code == 201
    scan_id = response.json()["scan_id"]

    # 2. Check /reports/history
    history_reports_resp = client.get(
        "/reports/history",
        headers={"Authorization": f"Bearer {token_owner}"}
    )
    assert history_reports_resp.status_code == 200
    reports_history = history_reports_resp.json()
    assert reports_history["total_count"] >= 1
    scans_list = [s["scan_id"] for s in reports_history["scans"]]
    assert scan_id in scans_list

    # Check that testuser2 does not see testuser's scan in reports history
    history_reports_other = client.get(
        "/reports/history",
        headers={"Authorization": f"Bearer {token_other}"}
    )
    assert history_reports_other.status_code == 200
    other_reports_history = history_reports_other.json()
    other_scans_list = [s["scan_id"] for s in other_reports_history["scans"]]
    assert scan_id not in other_scans_list

    # 3. Check /history
    history_list_resp = client.get(
        "/history",
        headers={"Authorization": f"Bearer {token_owner}"}
    )
    assert history_list_resp.status_code == 200
    history_data = history_list_resp.json()
    assert history_data["total"] >= 1
    history_scans_list = [s["scan_id"] for s in history_data["history"]]
    assert scan_id in history_scans_list

    # Check that testuser2 does not see testuser's scan in history list
    history_list_other = client.get(
        "/history",
        headers={"Authorization": f"Bearer {token_other}"}
    )
    assert history_list_other.status_code == 200
    other_history_data = history_list_other.json()
    other_history_scans = [s["scan_id"] for s in other_history_data["history"]]
    assert scan_id not in other_history_scans

    # 4. Test download report as owner (before report generated - should return scan status section)
    # Delete the automatically created report to simulate a pending/incomplete scan report download state
    from app.models.scan import Scan
    from app.models.report import Report
    from datetime import datetime, timezone
    scan_record = db_session.query(Scan).filter(Scan.scan_id == scan_id).first()
    assert scan_record is not None
    db_session.query(Report).filter(Report.scan_db_id == scan_record.id).delete()
    db_session.commit()

    download_owner_before = client.get(
        f"/reports/download/{scan_id}",
        headers={"Authorization": f"Bearer {token_owner}"}
    )
    assert download_owner_before.status_code == 200
    assert "report_" + scan_id in download_owner_before.headers["Content-Disposition"]
    content_before = download_owner_before.text
    assert "AI Security Audit Report for https://example.com/download-test" in content_before
    assert "This scan has not completed successfully" in content_before

    # Add a mock report to DB for the scan
    db_report = Report(
        scan_id=scan_id,
        scan_db_id=scan_record.id,
        risk_score=15.0,
        grade="B",
        summary="This is a test summary for download.",
        statistics={"critical": 0, "high": 1, "medium": 0, "low": 0, "informational": 0},
        recommendations=["Enable security headers.", "Validate SSL certificate."],
        completed_at=datetime.now(timezone.utc)
    )
    db_session.add(db_report)
    db_session.commit()


    # Test download report as owner (after report generated)
    download_owner_after = client.get(
        f"/reports/download/{scan_id}",
        headers={"Authorization": f"Bearer {token_owner}"}
    )
    assert download_owner_after.status_code == 200
    content_after = download_owner_after.text
    assert "AI Security Audit Report for https://example.com/download-test" in content_after
    assert "**Assessed Risk Score:** 15.0/100" in content_after
    assert "**Overall Grade:** B" in content_after
    assert "This is a test summary for download." in content_after
    assert "Enable security headers." in content_after

    # 5. Test download report as other user (403 Forbidden)
    download_other = client.get(
        f"/reports/download/{scan_id}",
        headers={"Authorization": f"Bearer {token_other}"}
    )
    assert download_other.status_code == 403
    assert download_other.json()["detail"] == "Access denied"

    # 6. Test download report non-existent (404 Not Found)
    download_nonexistent = client.get(
        "/reports/download/non-existent-uuid-string",
        headers={"Authorization": f"Bearer {token_owner}"}
    )
    assert download_nonexistent.status_code == 404
    assert download_nonexistent.json()["detail"] == "Scan not found"

    # 7. Test download report unauthenticated (401 Unauthorized)
    download_unauth = client.get(f"/reports/download/{scan_id}")
    assert download_unauth.status_code == 401


def test_report_exports(client, db_session):
    # Perform login for two users
    login_owner = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "Password123!"
        }
    )
    token_owner = login_owner.json()["access_token"]

    login_other = client.post(
        "/auth/login",
        data={
            "username": "testuser2",
            "password": "Password123!"
        }
    )
    token_other = login_other.json()["access_token"]

    # 1. Create a scan
    response = client.post(
        "/scan",
        json={
            "target": "https://example.com/export-test",
            "scan_type": "url"
        },
        headers={"Authorization": f"Bearer {token_owner}"}
    )
    assert response.status_code == 201
    scan_id = response.json()["scan_id"]

    # Delete the automatically created report to test the "missing report" 404 Not Found state
    from app.models.scan import Scan
    from app.models.report import Report
    from datetime import datetime, timezone
    scan_record = db_session.query(Scan).filter(Scan.scan_id == scan_id).first()
    assert scan_record is not None
    db_session.query(Report).filter(Report.scan_db_id == scan_record.id).delete()
    db_session.commit()

    # 2. Check 404 for missing report
    for fmt in ["html", "pdf", "markdown", "json"]:
        resp = client.get(
            f"/report/{scan_id}/{fmt}",
            headers={"Authorization": f"Bearer {token_owner}"}
        )
        assert resp.status_code == 404
        assert resp.json()["detail"] == "Report not found"

    # 3. Add a mock report to DB for the scan
    db_report = Report(
        scan_id=scan_id,
        scan_db_id=scan_record.id,
        risk_score=25.5,
        grade="C",
        summary="This is a test summary for exporting report.",
        statistics={"critical": 0, "high": 2, "medium": 1, "low": 3, "informational": 4},
        recommendations=["Update dependencies.", "Use secure cookies."],
        completed_at=datetime.now(timezone.utc)
    )
    db_session.add(db_report)
    db_session.commit()

    # 4. Verify exports
    # HTML Export
    html_resp = client.get(
        f"/report/{scan_id}/html",
        headers={"Authorization": f"Bearer {token_owner}"}
    )
    assert html_resp.status_code == 200
    assert "text/html" in html_resp.headers["Content-Type"]
    assert f"report_{scan_id}.html" in html_resp.headers["Content-Disposition"]
    html_text = html_resp.text
    assert "AI Security Auditor" in html_text
    assert "https://example.com/export-test" in html_text
    assert "This is a test summary for exporting report." in html_text
    assert "Update dependencies." in html_text

    # PDF Export
    pdf_resp = client.get(
        f"/report/{scan_id}/pdf",
        headers={"Authorization": f"Bearer {token_owner}"}
    )
    assert pdf_resp.status_code == 200
    assert "application/pdf" in pdf_resp.headers["Content-Type"]
    assert f"report_{scan_id}.pdf" in pdf_resp.headers["Content-Disposition"]
    assert pdf_resp.content.startswith(b"%PDF")

    # Markdown Export
    md_resp = client.get(
        f"/report/{scan_id}/markdown",
        headers={"Authorization": f"Bearer {token_owner}"}
    )
    assert md_resp.status_code == 200
    assert "text/markdown" in md_resp.headers["Content-Type"]
    assert f"report_{scan_id}.md" in md_resp.headers["Content-Disposition"]
    md_text = md_resp.text
    assert "# Executive Summary" in md_text
    assert "# Risk Score" in md_text
    assert "# Statistics" in md_text
    assert "# Vulnerabilities" in md_text
    assert "# Recommendations" in md_text
    assert "https://example.com/export-test" in md_text

    # JSON Export
    json_resp = client.get(
        f"/report/{scan_id}/json",
        headers={"Authorization": f"Bearer {token_owner}"}
    )
    assert json_resp.status_code == 200
    assert "application/json" in json_resp.headers["Content-Type"]
    assert f"report_{scan_id}.json" in json_resp.headers["Content-Disposition"]
    json_data = json_resp.json()
    assert json_data["executive_summary"] == "This is a test summary for exporting report."
    assert json_data["target_url"] == "https://example.com/export-test"
    assert json_data["scan_id"] == scan_id
    assert json_data["risk_score"] == 25.5
    assert json_data["security_grade"] == "C"
    assert json_data["statistics"]["total_vulnerabilities"] == len(scan_record.vulnerabilities)
    assert json_data["statistics"]["severity_distribution"]["high"] == 2
    assert "Update dependencies." in json_data["ai_recommendations"]

    # 5. Access control: other user gets 403 Forbidden
    for fmt in ["html", "pdf", "markdown", "json"]:
        other_resp = client.get(
            f"/report/{scan_id}/{fmt}",
            headers={"Authorization": f"Bearer {token_other}"}
        )
        assert other_resp.status_code == 403
        assert other_resp.json()["detail"] == "Access denied"

    # 6. Access control: unauthenticated gets 401 Unauthorized
    for fmt in ["html", "pdf", "markdown", "json"]:
        unauth_resp = client.get(f"/report/{scan_id}/{fmt}")
        assert unauth_resp.status_code == 401

    # 7. Non-existent scan ID gets 404 Not Found
    for fmt in ["html", "pdf", "markdown", "json"]:
        missing_resp = client.get(
            f"/report/non-existent-scan-id/{fmt}",
            headers={"Authorization": f"Bearer {token_owner}"}
        )
        assert missing_resp.status_code == 404
        assert missing_resp.json()["detail"] == "Scan not found"




