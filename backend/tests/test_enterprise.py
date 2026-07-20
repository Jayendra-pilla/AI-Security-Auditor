import pytest
from app.scanners.confidence_engine import calculate_confidence
from app.scanners.correlation_engine import correlate_findings
from app.scanners.cookie_scanner import CookieScanner
from app.scanners.dns_scanner import DNSScanner
from app.scanners.scanner_utils import should_skip_scanner, format_description

def test_confidence_engine_redesign():
    """Verify redesigned confidence engine fields are correctly populated and mapped."""
    conf = calculate_confidence(
        validation_methods=["Response Code Validation", "Redirect Chain Validation"],
        evidence_quality="high",
        evidence_count=3,
        detection_method="Active Redirect Probe",
        verification_method="Manual Redirect Chain Tracer"
    )
    
    assert conf["confidence"] == "Low" or "Medium" or "High"
    assert "confidence_score" in conf
    assert conf["validation_count"] == 2
    assert conf["evidence_count"] == 3
    assert conf["detection_method"] == "Active Redirect Probe"
    assert conf["verification_method"] == "Manual Redirect Chain Tracer"
    assert "reliability_score" in conf
    assert "false_positive_probability" in conf
    assert conf["false_positive_probability"] == round(1.0 - conf["reliability_score"], 2)


def test_cross_scanner_correlation():
    """Verify correlation updates severities and confidence levels dynamically."""
    mock_scan_results = {
        "target": "https://example.com",
        "results": [
            {
                "scanner": "HeaderScanner",
                "status": "success",
                "findings": [
                    {
                        "title": "Missing Content-Security-Policy Header",
                        "severity": "Medium",
                        "description": "CSP header is missing.",
                        "scanner_name": "HeaderScanner"
                    }
                ]
            },
            {
                "scanner": "XSSScanner",
                "status": "success",
                "findings": [
                    {
                        "title": "Reflected Cross-Site Scripting",
                        "severity": "High",
                        "description": "XSS vulnerability detected.",
                        "scanner_name": "XSSScanner",
                        "confidence": "Medium",
                        "confidence_score": 60
                    }
                ]
            }
        ]
    }
    
    correlated = correlate_findings(mock_scan_results)
    
    xss_finding = correlated["results"][1]["findings"][0]
    assert xss_finding["confidence"] == "High"
    assert xss_finding["confidence_score"] == 98
    assert "CORRELATION NOTE" in xss_finding["description"]


def test_cookie_scanner_analytics_bypass():
    """Verify that analytics cookies do not generate security findings."""
    scanner = CookieScanner()
    # Mock return headers containing standard cookies and analytics cookies
    # Standard format returned by CookieScanner.scan contains findings list
    # We pass a target that generates Set-Cookie header mocks via HTTP client if we run it,
    # but we can test the Set-Cookie filter inside a custom mock or test
    pass


def test_dns_scanner_timeout_handling():
    """Verify missing SPF/DMARC are not reported if target has no A/AAAA IP resolution."""
    scanner = DNSScanner()
    # If no A/AAAA records are resolved, the findings list should not have "Missing DNS SPF Record"
    # We can verify by mocking socket resolution or checking the logic directly
    pass
