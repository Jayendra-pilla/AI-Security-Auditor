import os
import pytest
from datetime import datetime, timezone, timedelta
import time
from fastapi.testclient import TestClient

# Force SQLite for self-contained testing to avoid PostgreSQL dependency
os.environ["DATABASE_URL"] = "sqlite:///./test.db"

from app.main import app
from app.database.db import get_db
from app.database.session import SessionLocal, engine
from app.database.base import Base
from app.models.user import User
from app.models.scan import Scan
from app.models.report import Report
from app.models.vulnerability import Vulnerability

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

@pytest.fixture
def auth_headers_user_empty(client):
    client.post(
        "/auth/register",
        json={
            "email": "user_empty@example.com",
            "username": "user_empty",
            "password": "Password123!",
            "role": "user"
        }
    )
    login_response = client.post(
        "/auth/login",
        data={
            "username": "user_empty",
            "password": "Password123!"
        }
    )
    token = login_response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def auth_headers_user_a(client):
    client.post(
        "/auth/register",
        json={
            "email": "user_a@example.com",
            "username": "user_a",
            "password": "Password123!",
            "role": "user"
        }
    )
    login_response = client.post(
        "/auth/login",
        data={
            "username": "user_a",
            "password": "Password123!"
        }
    )
    token = login_response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def auth_headers_user_b(client):
    client.post(
        "/auth/register",
        json={
            "email": "user_b@example.com",
            "username": "user_b",
            "password": "Password123!",
            "role": "user"
        }
    )
    login_response = client.post(
        "/auth/login",
        data={
            "username": "user_b",
            "password": "Password123!"
        }
    )
    token = login_response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def test_empty_database(client, auth_headers_user_empty):
    # Verify dashboard returns defaults / empty list for empty database
    response = client.get("/dashboard/overview", headers=auth_headers_user_empty)
    assert response.status_code == 200
    data = response.json()
    assert data["total_scans"] == 0
    assert data["completed_scans"] == 0
    assert data["running_scans"] == 0
    assert data["failed_scans"] == 0
    assert data["total_reports"] == 0
    assert data["total_vulnerabilities"] == 0
    assert data["critical_findings"] == 0
    assert data["high_findings"] == 0
    assert data["medium_findings"] == 0
    assert data["low_findings"] == 0
    assert data["informational_findings"] == 0
    assert data["average_risk_score"] == 0.0
    assert data["latest_grade"] is None

    response = client.get("/dashboard/recent-scans", headers=auth_headers_user_empty)
    assert response.status_code == 200
    assert response.json() == []

    response = client.get("/dashboard/risk-distribution", headers=auth_headers_user_empty)
    assert response.status_code == 200
    assert response.json() == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
        "total": 0
    }

    response = client.get("/dashboard/top-vulnerabilities", headers=auth_headers_user_empty)
    assert response.status_code == 200
    assert response.json() == []

    response = client.get("/dashboard/history", headers=auth_headers_user_empty)
    assert response.status_code == 200
    assert response.json() == []

    response = client.get("/dashboard/statistics", headers=auth_headers_user_empty)
    assert response.status_code == 200
    assert response.json() == {
        "average_risk_score": 0.0,
        "highest_risk_score": 0.0,
        "lowest_risk_score": 0.0,
        "average_findings_per_scan": 0.0,
        "total_reports": 0
    }

    response = client.get("/dashboard/trends", headers=auth_headers_user_empty)
    assert response.status_code == 200
    assert response.json() == []

def test_unauthorized_access(client):
    # Verify endpoints return 401 without auth token
    for endpoint in ["overview", "recent-scans", "risk-distribution", "top-vulnerabilities", "history", "statistics", "trends"]:
        response = client.get(f"/dashboard/{endpoint}")
        assert response.status_code == 401

def test_dashboard_functionality(client, db_session, auth_headers_user_a, auth_headers_user_b):
    # Setup data for user_a
    user_a = db_session.query(User).filter(User.username == "user_a").first()
    user_b = db_session.query(User).filter(User.username == "user_b").first()
    
    # Create scans for User A
    scan1 = Scan(
        scan_id="scan_a_1",
        user_id=user_a.id,
        target="https://target-a1.com",
        scan_type="url",
        status="completed",
        created_at=datetime.now(timezone.utc) - timedelta(days=2)
    )
    scan2 = Scan(
        scan_id="scan_a_2",
        user_id=user_a.id,
        target="https://target-a2.com",
        scan_type="url",
        status="completed",
        created_at=datetime.now(timezone.utc) - timedelta(days=1)
    )
    scan3 = Scan(
        scan_id="scan_a_3",
        user_id=user_a.id,
        target="https://target-a3.com",
        scan_type="url",
        status="running",
        created_at=datetime.now(timezone.utc)
    )
    db_session.add_all([scan1, scan2, scan3])
    db_session.commit()
    db_session.refresh(scan1)
    db_session.refresh(scan2)
    db_session.refresh(scan3)

    # Create Reports for User A scans
    report1 = Report(
        scan_id="scan_a_1",
        scan_db_id=scan1.id,
        risk_score=45.0,
        grade="C",
        completed_at=datetime.now(timezone.utc) - timedelta(days=2)
    )
    report2 = Report(
        scan_id="scan_a_2",
        scan_db_id=scan2.id,
        risk_score=85.0,
        grade="A",
        completed_at=datetime.now(timezone.utc) - timedelta(days=1)
    )
    db_session.add_all([report1, report2])
    db_session.commit()

    # Create Vulnerabilities for User A scans
    vuln1 = Vulnerability(
        scan_id=scan1.id,
        scanner_name="OWASP ZAP",
        severity="High",
        title="SQL Injection",
        description="SQL injection vulnerability",
        recommendation="Use parameterized queries"
    )
    vuln2 = Vulnerability(
        scan_id=scan1.id,
        scanner_name="OWASP ZAP",
        severity="Medium",
        title="XSS",
        description="Cross-site scripting",
        recommendation="Sanitize input"
    )
    vuln3 = Vulnerability(
        scan_id=scan2.id,
        scanner_name="Nmap",
        severity="High",
        title="SQL Injection",
        description="SQL injection vulnerability",
        recommendation="Use parameterized queries"
    )
    vuln4 = Vulnerability(
        scan_id=scan2.id,
        scanner_name="Nmap",
        severity="Low",
        title="Info Disclosure",
        description="Information disclosure",
        recommendation="Hide headers"
    )
    db_session.add_all([vuln1, vuln2, vuln3, vuln4])
    db_session.commit()

    # Create a scan for User B (to verify isolation)
    scan_b = Scan(
        scan_id="scan_b_1",
        user_id=user_b.id,
        target="https://target-b.com",
        scan_type="url",
        status="completed",
        created_at=datetime.now(timezone.utc)
    )
    db_session.add(scan_b)
    db_session.commit()
    db_session.refresh(scan_b)

    report_b = Report(
        scan_id="scan_b_1",
        scan_db_id=scan_b.id,
        risk_score=95.0,
        grade="A+",
        completed_at=datetime.now(timezone.utc)
    )
    vuln_b = Vulnerability(
        scan_id=scan_b.id,
        scanner_name="OWASP ZAP",
        severity="Critical",
        title="RCE",
        description="Remote Code Execution",
        recommendation="Patch system"
    )
    db_session.add_all([report_b, vuln_b])
    db_session.commit()

    # Test User A Overview
    response = client.get("/dashboard/overview", headers=auth_headers_user_a)
    assert response.status_code == 200
    data = response.json()
    assert data["total_scans"] == 3
    assert data["completed_scans"] == 2
    assert data["running_scans"] == 1
    assert data["failed_scans"] == 0
    assert data["total_reports"] == 2
    assert data["total_vulnerabilities"] == 4
    assert data["critical_findings"] == 0
    assert data["high_findings"] == 2
    assert data["medium_findings"] == 1
    assert data["low_findings"] == 1
    assert data["informational_findings"] == 0
    assert data["average_risk_score"] == 65.0 # (45 + 85) / 2
    assert data["latest_grade"] == "A" # scan_a_2 is newest completed scan

    # Test User A Recent Scans
    response = client.get("/dashboard/recent-scans", headers=auth_headers_user_a)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 3
    assert data[0]["scan_id"] == "scan_a_3"
    assert data[0]["risk_score"] is None
    assert data[1]["scan_id"] == "scan_a_2"
    assert data[1]["risk_score"] == 85.0
    assert data[1]["grade"] == "A"
    assert data[1]["scan_type"] == "url"

    # Test User A Risk Distribution
    response = client.get("/dashboard/risk-distribution", headers=auth_headers_user_a)
    assert response.status_code == 200
    data = response.json()
    assert data == {
        "critical": 0,
        "high": 2,
        "medium": 1,
        "low": 1,
        "informational": 0,
        "total": 4
    }

    # Test User A Top Vulnerabilities
    response = client.get("/dashboard/top-vulnerabilities", headers=auth_headers_user_a)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 3
    assert data[0]["title"] == "SQL Injection"
    assert data[0]["severity"] == "High"
    assert data[0]["count"] == 2

    # Test User A History
    response = client.get("/dashboard/history", headers=auth_headers_user_a)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 3
    assert data[0]["scan_id"] == "scan_a_3"
    assert data[0]["risk_score"] is None

    # Test User A Statistics
    response = client.get("/dashboard/statistics", headers=auth_headers_user_a)
    assert response.status_code == 200
    data = response.json()
    assert data["average_risk_score"] == 65.0
    assert data["highest_risk_score"] == 85.0
    assert data["lowest_risk_score"] == 45.0
    assert data["average_findings_per_scan"] == 4 / 3 # 1.3333333333333333
    assert data["total_reports"] == 2

    # Test User A Trends
    response = client.get("/dashboard/trends", headers=auth_headers_user_a)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    assert data[0]["risk_score"] == 45.0
    assert data[1]["risk_score"] == 85.0

    # Test User B Overview (Ownership isolation)
    response = client.get("/dashboard/overview", headers=auth_headers_user_b)
    assert response.status_code == 200
    data = response.json()
    assert data["total_scans"] == 1
    assert data["completed_scans"] == 1
    assert data["total_vulnerabilities"] == 1
    assert data["critical_findings"] == 1
    assert data["average_risk_score"] == 95.0
    assert data["latest_grade"] == "A+"

def test_performance_sanity(client, db_session, auth_headers_user_a):
    user_a = db_session.query(User).filter(User.username == "user_a").first()
    
    # Bulk insert large dataset
    scans = []
    
    # Create 50 scans
    for i in range(50):
        scan_id = f"perf_scan_{i}"
        scan = Scan(
            scan_id=scan_id,
            user_id=user_a.id,
            target=f"https://perf-target-{i}.com",
            scan_type="file",
            status="completed" if i % 5 != 0 else "failed",
            created_at=datetime.now(timezone.utc) - timedelta(hours=i)
        )
        db_session.add(scan)
        scans.append(scan)
    
    db_session.commit()
    
    for i, scan in enumerate(scans):
        if scan.status == "completed":
            report = Report(
                scan_id=scan.scan_id,
                scan_db_id=scan.id,
                risk_score=float(50 + (i % 50)),
                grade="B",
                completed_at=datetime.now(timezone.utc) - timedelta(hours=i)
            )
            db_session.add(report)
            
            # Create some vulnerabilities per scan (total ~ 120)
            for j in range(3):
                vuln = Vulnerability(
                    scan_id=scan.id,
                    scanner_name="Performance Scanner",
                    severity="Medium" if j % 2 == 0 else "Low",
                    title=f"Perf Vulnerability {j}",
                    description="Performance test",
                    recommendation="Optimise"
                )
                db_session.add(vuln)
                
    db_session.commit()
    
    # Run dashboard queries and assert execution speed is fast (< 200ms)
    start_time = time.perf_counter()
    
    response = client.get("/dashboard/overview", headers=auth_headers_user_a)
    assert response.status_code == 200
    
    response = client.get("/dashboard/recent-scans", headers=auth_headers_user_a)
    assert response.status_code == 200
    
    response = client.get("/dashboard/risk-distribution", headers=auth_headers_user_a)
    assert response.status_code == 200
    
    response = client.get("/dashboard/top-vulnerabilities", headers=auth_headers_user_a)
    assert response.status_code == 200
    
    response = client.get("/dashboard/history", headers=auth_headers_user_a)
    assert response.status_code == 200
    
    response = client.get("/dashboard/statistics", headers=auth_headers_user_a)
    assert response.status_code == 200
    
    response = client.get("/dashboard/trends", headers=auth_headers_user_a)
    assert response.status_code == 200
    
    duration = time.perf_counter() - start_time
    assert duration < 0.200 # should easily be under 200ms
