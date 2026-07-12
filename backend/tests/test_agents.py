"""
Comprehensive tests for the Enterprise Agent Orchestration Layer (Sprint 8).
Tests all 5 domain agents, the Orchestrator, severity calculation, and edge cases.
"""
from app.agents.recon_agent import ReconAgent, _max_severity, _extract_scanner
from app.agents.header_agent import HeaderAgent
from app.agents.ssl_agent import SSLAgent
from app.agents.tech_agent import TechAgent
from app.agents.endpoint_agent import EndpointAgent
from app.agents.orchestrator import Orchestrator


# ---------------------------------------------------------------------------
# Shared test fixture: a realistic ScannerManager results dict
# ---------------------------------------------------------------------------

def _build_scanner_results():
    """
    Build a realistic results dict matching the output of
    ScannerManager.run_all_scanners().  Every scanner is represented.
    """
    return {
        "target": "https://example.com",
        "status": "completed",
        "total_scanners": 16,
        "completed_scanners": 16,
        "results": [
            {
                "scanner": "HeaderScanner",
                "status": "warning",
                "severity": "Medium",
                "findings": [
                    {"title": "Missing CSP Header", "severity": "Medium",
                     "description": "CSP header is not configured.", "recommendation": "Implement CSP."},
                    {"title": "Missing HSTS Header", "severity": "Low",
                     "description": "HSTS header is missing.", "recommendation": "Configure HSTS."},
                ],
                "duration_ms": 120,
            },
            {
                "scanner": "SSLScanner",
                "status": "warning",
                "severity": "High",
                "findings": [
                    {"title": "Insecure HTTP Protocol", "severity": "High",
                     "description": "Target uses HTTP.", "recommendation": "Use HTTPS."},
                ],
                "duration_ms": 50,
            },
            {
                "scanner": "CORSScanner",
                "status": "success",
                "severity": "Informational",
                "findings": [],
                "duration_ms": 80,
            },
            {
                "scanner": "CookieScanner",
                "status": "warning",
                "severity": "Medium",
                "findings": [
                    {"title": "Insecure Cookie Flag", "severity": "Medium",
                     "description": "Cookie missing Secure.", "recommendation": "Set Secure."},
                ],
                "duration_ms": 90,
            },
            {
                "scanner": "CSRFScanner",
                "status": "warning",
                "severity": "High",
                "findings": [
                    {"title": "Potential CSRF Vulnerability", "severity": "High",
                     "description": "POST form lacks CSRF token.", "recommendation": "Add CSRF tokens."},
                ],
                "duration_ms": 150,
            },
            {
                "scanner": "DNSScanner",
                "status": "success",
                "severity": "Informational",
                "findings": [
                    {"title": "DNS Host Resolution", "severity": "Informational",
                     "description": "Resolved to 93.184.216.34.", "recommendation": "Enable DNSSEC."},
                ],
                "duration_ms": 30,
            },
            {
                "scanner": "PortScanner",
                "status": "warning",
                "severity": "High",
                "findings": [
                    {"title": "Port 80 is Open", "severity": "Informational",
                     "description": "Port 80 is open.", "recommendation": "Limit exposed ports."},
                    {"title": "Insecure Service Port Open: 21", "severity": "High",
                     "description": "FTP port 21 is open.", "recommendation": "Close FTP."},
                ],
                "duration_ms": 200,
            },
            {
                "scanner": "RobotsScanner",
                "status": "warning",
                "severity": "Low",
                "findings": [
                    {"title": "Sensitive Path Exposure in robots.txt", "severity": "Low",
                     "description": "Robots.txt exposes /admin.", "recommendation": "Don't list private dirs."},
                ],
                "duration_ms": 60,
            },
            {
                "scanner": "SitemapScanner",
                "status": "success",
                "severity": "Informational",
                "findings": [
                    {"title": "Sitemap Discovered", "severity": "Informational",
                     "description": "Sitemap found.", "recommendation": "Verify no private URLs."},
                ],
                "duration_ms": 40,
            },
            {
                "scanner": "SubdomainScanner",
                "status": "success",
                "severity": "Informational",
                "findings": [
                    {"title": "Subdomains Discovered", "severity": "Informational",
                     "description": "Found www.example.com.", "recommendation": "Audit subdomains."},
                ],
                "duration_ms": 300,
            },
            {
                "scanner": "TechDetector",
                "status": "warning",
                "severity": "Low",
                "findings": [
                    {"title": "Technology Disclosure", "severity": "Low",
                     "description": "Server: nginx/1.21.", "recommendation": "Remove Server header."},
                ],
                "duration_ms": 70,
            },
            {
                "scanner": "XSSScanner",
                "status": "success",
                "severity": "Informational",
                "findings": [
                    {"title": "Reflected XSS Check Clean", "severity": "Informational",
                     "description": "No reflected XSS.", "recommendation": "Continue validating."},
                ],
                "duration_ms": 100,
            },
            {
                "scanner": "ClickjackingScanner",
                "status": "warning",
                "severity": "Medium",
                "findings": [
                    {"title": "Clickjacking Exposure", "severity": "Medium",
                     "description": "No X-Frame-Options.", "recommendation": "Set X-Frame-Options."},
                ],
                "duration_ms": 55,
            },
            {
                "scanner": "OpenRedirectScanner",
                "status": "success",
                "severity": "Informational",
                "findings": [
                    {"title": "Open Redirect Check Clean", "severity": "Informational",
                     "description": "No open redirects.", "recommendation": "Enforce redirect validation."},
                ],
                "duration_ms": 110,
            },
            {
                "scanner": "APIEndpointScanner",
                "status": "warning",
                "severity": "Medium",
                "findings": [
                    {"title": "Publicly Accessible API Endpoints", "severity": "Medium",
                     "description": "Found /api, /docs.", "recommendation": "Require authorization."},
                ],
                "duration_ms": 130,
            },
            {
                "scanner": "ExposedFilesScanner",
                "status": "warning",
                "severity": "Critical",
                "findings": [
                    {"title": "Exposed Sensitive Files", "severity": "Critical",
                     "description": "/.env is publicly accessible.", "recommendation": "Block access."},
                ],
                "duration_ms": 90,
            },
        ],
    }


# ---------------------------------------------------------------------------
# Backward compatibility — original placeholder test
# ---------------------------------------------------------------------------

def test_placeholder_agents():
    """Keep the existing placeholder test for backward compatibility."""
    assert True


# ---------------------------------------------------------------------------
# Utility function tests
# ---------------------------------------------------------------------------

def test_max_severity_ranking():
    """Verify _max_severity returns the more severe of two severities."""
    assert _max_severity("Informational", "Low") == "Low"
    assert _max_severity("Low", "Informational") == "Low"
    assert _max_severity("Medium", "High") == "High"
    assert _max_severity("High", "Critical") == "Critical"
    assert _max_severity("Critical", "Low") == "Critical"
    assert _max_severity("Informational", "Informational") == "Informational"


def test_extract_scanner_found():
    """Verify _extract_scanner locates a scanner by name."""
    results = _build_scanner_results()
    extracted = _extract_scanner(results, "DNSScanner")
    assert extracted["status"] == "success"
    assert len(extracted["findings"]) == 1
    assert extracted["findings"][0]["title"] == "DNS Host Resolution"


def test_extract_scanner_not_found():
    """Verify _extract_scanner returns a clean 'not_found' for missing scanners."""
    results = _build_scanner_results()
    extracted = _extract_scanner(results, "NonExistentScanner")
    assert extracted["status"] == "not_found"
    assert extracted["findings"] == []


# ---------------------------------------------------------------------------
# ReconAgent tests
# ---------------------------------------------------------------------------

def test_recon_agent_analyze():
    """Verify ReconAgent correctly extracts DNS, Robots, Sitemap, Subdomain results."""
    agent = ReconAgent()
    results = _build_scanner_results()
    report = agent.analyze(results)

    assert report["agent"] == "ReconAgent"
    assert report["scanner_count"] == 4
    assert report["finding_count"] == 4  # 1 DNS + 1 Robots + 1 Sitemap + 1 Subdomain
    assert report["max_severity"] == "Low"  # Robots finding is Low
    assert "dns" in report
    assert "robots" in report
    assert "sitemap" in report
    assert "subdomains" in report
    assert report["dns"]["status"] == "success"
    assert report["robots"]["status"] == "warning"
    assert "summary" in report


# ---------------------------------------------------------------------------
# HeaderAgent tests
# ---------------------------------------------------------------------------

def test_header_agent_analyze():
    """Verify HeaderAgent extracts Header, Cookie, CORS, Clickjacking results."""
    agent = HeaderAgent()
    results = _build_scanner_results()
    report = agent.analyze(results)

    assert report["agent"] == "HeaderAgent"
    assert report["scanner_count"] == 4
    # 2 Header + 0 CORS + 1 Cookie + 1 Clickjacking = 4
    assert report["finding_count"] == 4
    assert report["max_severity"] == "Medium"
    assert "headers" in report
    assert "cookies" in report
    assert "cors" in report
    assert "clickjacking" in report
    assert report["cors"]["findings"] == []


# ---------------------------------------------------------------------------
# SSLAgent tests
# ---------------------------------------------------------------------------

def test_ssl_agent_analyze():
    """Verify SSLAgent extracts SSL and Port results."""
    agent = SSLAgent()
    results = _build_scanner_results()
    report = agent.analyze(results)

    assert report["agent"] == "SSLAgent"
    assert report["scanner_count"] == 2
    assert report["finding_count"] == 3  # 1 SSL + 2 Port
    assert report["max_severity"] == "High"
    assert "ssl" in report
    assert "ports" in report
    assert len(report["ports"]["findings"]) == 2


# ---------------------------------------------------------------------------
# TechAgent tests
# ---------------------------------------------------------------------------

def test_tech_agent_analyze():
    """Verify TechAgent extracts TechDetector and ExposedFiles results."""
    agent = TechAgent()
    results = _build_scanner_results()
    report = agent.analyze(results)

    assert report["agent"] == "TechAgent"
    assert report["scanner_count"] == 2
    assert report["finding_count"] == 2  # 1 TechDetector + 1 ExposedFiles
    assert report["max_severity"] == "Critical"
    assert "tech_detection" in report
    assert "exposed_files" in report


# ---------------------------------------------------------------------------
# EndpointAgent tests
# ---------------------------------------------------------------------------

def test_endpoint_agent_analyze():
    """Verify EndpointAgent extracts API, XSS, CSRF, OpenRedirect results."""
    agent = EndpointAgent()
    results = _build_scanner_results()
    report = agent.analyze(results)

    assert report["agent"] == "EndpointAgent"
    assert report["scanner_count"] == 4
    # 1 API + 1 XSS + 1 CSRF + 1 OpenRedirect = 4
    assert report["finding_count"] == 4
    assert report["max_severity"] == "High"  # CSRF is High
    assert "api_endpoints" in report
    assert "xss" in report
    assert "csrf" in report
    assert "open_redirect" in report


# ---------------------------------------------------------------------------
# Orchestrator tests
# ---------------------------------------------------------------------------

def test_orchestrator_analyze():
    """Verify the full orchestration pipeline produces a complete combined report."""
    orchestrator = Orchestrator()
    results = _build_scanner_results()
    report = orchestrator.analyze(results)

    assert report["status"] == "completed"
    assert report["agents_executed"] == 5
    # Total: 4 Recon + 4 Header + 3 SSL + 2 Tech + 4 Endpoint = 17
    assert report["total_findings"] == 17
    assert report["overall_severity"] == "Critical"  # ExposedFiles is Critical
    assert "executive_summary" in report

    # All 5 agent reports present
    agent_reports = report["agent_reports"]
    assert "recon" in agent_reports
    assert "headers" in agent_reports
    assert "ssl" in agent_reports
    assert "tech" in agent_reports
    assert "endpoints" in agent_reports

    # Each sub-report has correct agent name
    assert agent_reports["recon"]["agent"] == "ReconAgent"
    assert agent_reports["headers"]["agent"] == "HeaderAgent"
    assert agent_reports["ssl"]["agent"] == "SSLAgent"
    assert agent_reports["tech"]["agent"] == "TechAgent"
    assert agent_reports["endpoints"]["agent"] == "EndpointAgent"


def test_orchestrator_with_empty_results():
    """Verify orchestrator handles a results dict with no scanner outputs."""
    orchestrator = Orchestrator()
    empty_results = {
        "target": "https://empty.com",
        "status": "completed",
        "total_scanners": 0,
        "completed_scanners": 0,
        "results": [],
    }
    report = orchestrator.analyze(empty_results)

    assert report["status"] == "completed"
    assert report["agents_executed"] == 5
    assert report["total_findings"] == 0
    assert report["overall_severity"] == "Informational"

    # All agents should still report with not_found status
    for key in ["recon", "headers", "ssl", "tech", "endpoints"]:
        agent_report = report["agent_reports"][key]
        assert agent_report["finding_count"] == 0


def test_orchestrator_with_failed_scanners():
    """Verify orchestrator handles scanner failures gracefully."""
    results = {
        "target": "https://failing.com",
        "status": "completed",
        "total_scanners": 16,
        "completed_scanners": 10,
        "results": [
            {"scanner": "DNSScanner", "status": "failed", "error": "Timeout"},
            {"scanner": "HeaderScanner", "status": "failed", "error": "Connection refused"},
            {
                "scanner": "SSLScanner",
                "status": "success",
                "severity": "Informational",
                "findings": [],
                "duration_ms": 50,
            },
        ],
    }
    orchestrator = Orchestrator()
    report = orchestrator.analyze(results)

    assert report["status"] == "completed"
    assert report["agents_executed"] == 5
    # DNS is failed so ReconAgent gets it but with 0 findings extracted from it
    # The failed scanner still appears with its status
    recon = report["agent_reports"]["recon"]
    assert recon["dns"]["status"] == "failed"
    # SSL has no findings
    ssl = report["agent_reports"]["ssl"]
    assert ssl["ssl"]["status"] == "success"
    assert ssl["finding_count"] == 0


def test_agent_severity_calculation():
    """Verify that severity calculation picks the highest across all findings."""
    results = {
        "target": "https://severity-test.com",
        "status": "completed",
        "total_scanners": 16,
        "completed_scanners": 2,
        "results": [
            {
                "scanner": "SSLScanner",
                "status": "success",
                "severity": "Informational",
                "findings": [
                    {"title": "Clean SSL", "severity": "Informational",
                     "description": "OK", "recommendation": "None"},
                ],
                "duration_ms": 10,
            },
            {
                "scanner": "PortScanner",
                "status": "warning",
                "severity": "High",
                "findings": [
                    {"title": "Low port", "severity": "Low",
                     "description": "Port 80", "recommendation": "Check"},
                    {"title": "FTP open", "severity": "High",
                     "description": "Port 21 open", "recommendation": "Close"},
                ],
                "duration_ms": 20,
            },
        ],
    }
    agent = SSLAgent()
    report = agent.analyze(results)
    # Highest finding severity is High (from PortScanner)
    assert report["max_severity"] == "High"
    assert report["finding_count"] == 3
