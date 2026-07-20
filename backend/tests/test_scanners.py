from unittest.mock import MagicMock
from app.scanners.scanner_manager import ScannerManager

def test_placeholder_scanners():
    """
    Keep the existing test definition to ensure backward compatibility.
    """
    assert True

def test_scanner_manager_all_scanners_called():
    """
    Verify that ScannerManager calls every configured scanner and merges successful results.
    """
    manager = ScannerManager()
    
    mock_classes = []
    mock_instances = []
    
    # Mock each scanner class in the list to return a mock instance that implements 'scan'
    for i, cls in enumerate(manager.scanners):
        mock_instance = MagicMock()
        mock_class = MagicMock(return_value=mock_instance)
        mock_class.__name__ = cls.__name__
        
        # Configure the 'scan' method to return a dummy finding dict
        mock_instance.scan.return_value = {"finding_id": i, "details": f"Findings for {cls.__name__}"}
        
        # Remove 'run' attribute to force using 'scan'
        if hasattr(mock_instance, "run"):
            del mock_instance.run
            
        mock_classes.append(mock_class)
        mock_instances.append(mock_instance)
        
    # Inject the mock classes into the manager
    manager.scanners = mock_classes
    
    target_url = "https://example.com"
    result = manager.run_all_scanners(target_url)
    
    # Assert overall result structure
    assert result["target"] == target_url
    assert result["status"] == "completed"
    assert result["total_scanners"] == 16
    assert result["completed_scanners"] == 16
    assert len(result["results"]) == 16
    
    # Assert individual scanner execution results
    for i, res in enumerate(result["results"]):
        assert res["status"] == "success"
        assert res["findings"] == {"finding_id": i, "details": f"Findings for {mock_classes[i].__name__}"}
        
        # Verify call interactions
        mock_classes[i].assert_called_once()
        mock_instances[i].scan.assert_called_once_with(target_url)

def test_scanner_manager_failing_and_missing_methods():
    """
    Verify that ScannerManager handles crashing, fallback method ('run'),
    and unimplemented scanners gracefully without stopping the orchestration.
    """
    manager = ScannerManager()
    
    mock_classes = []
    
    # Set up distinct behaviors:
    # 0..4: scan() method succeeds
    # 5..9: run() method succeeds (fallback method)
    # 10..12: scan() raises a ValueError (crashed scanner)
    # 13..15: neither scan() nor run() exist (unimplemented placeholder)
    for i in range(16):
        mock_instance = MagicMock()
        
        if i < 5:
            mock_instance.scan.return_value = {"result_id": i}
            # Remove run to ensure it calls scan
            if hasattr(mock_instance, "run"):
                del mock_instance.run
        elif i < 10:
            mock_instance.run.return_value = {"result_id": i}
            # Remove scan to force it to use run fallback
            if hasattr(mock_instance, "scan"):
                del mock_instance.scan
        elif i < 13:
            mock_instance.scan.side_effect = ValueError(f"Crash in scanner {i}")
            if hasattr(mock_instance, "run"):
                del mock_instance.run
        else:
            # Completely strip both methods to simulate simple pass placeholder
            if hasattr(mock_instance, "scan"):
                del mock_instance.scan
            if hasattr(mock_instance, "run"):
                del mock_instance.run
                
        mock_class = MagicMock(return_value=mock_instance)
        mock_class.__name__ = f"MockScanner{i}"
        mock_classes.append(mock_class)
        
    manager.scanners = mock_classes
    
    target_url = "https://failing-test.com"
    result = manager.run_all_scanners(target_url)
    
    assert result["target"] == target_url
    assert result["status"] == "completed"
    assert result["total_scanners"] == 16
    assert result["completed_scanners"] == 10  # 5 scan + 5 run
    
    results = result["results"]
    assert len(results) == 16
    
    # 1. Verify scan() successes
    for i in range(5):
        assert results[i]["status"] == "success"
        assert results[i]["findings"] == {"result_id": i}
        
    # 2. Verify run() fallback successes
    for i in range(5, 10):
        assert results[i]["status"] == "success"
        assert results[i]["findings"] == {"result_id": i}
        
    # 3. Verify crash handling (try/except wrapper)
    for i in range(10, 13):
        assert results[i]["status"] == "failed"
        assert f"Crash in scanner {i}" in results[i]["error"]
        
    # 4. Verify unimplemented handling (NotImplementedError)
    for i in range(13, 16):
        assert results[i]["status"] == "failed"
        assert "does not implement a callable 'scan' or 'run'" in results[i]["error"]

def test_scanner_manager_default_placeholder_behavior():
    """
    Verify that all 16 implemented scanners complete successfully with the standardized format.
    """
    manager = ScannerManager()
    
    target_url = "https://placeholder-test.com"
    result = manager.run_all_scanners(target_url)
    
    assert result["target"] == target_url
    assert result["status"] == "completed"
    assert result["total_scanners"] == 16
    assert result["completed_scanners"] == 16
    assert len(result["results"]) == 16
    
    implemented_names = {
        "HeaderScanner", "SSLScanner", "CookieScanner", "ClickjackingScanner", "CORSScanner",
        "RobotsScanner", "SitemapScanner", "TechDetector", "DNSScanner", "APIEndpointScanner", "ExposedFilesScanner",
        "PortScanner", "SubdomainScanner", "OpenRedirectScanner", "CSRFScanner", "XSSScanner"
    }
    
    for res in result["results"]:
        name = res["scanner"]
        assert name in implemented_names
        assert "findings" in res
        assert "duration_ms" in res
        assert "status" in res


def test_root_domain_extraction():
    """Verify extract_root_domain correctly handles subdomains and complex TLDs."""
    from app.scanners.scanner_utils import extract_root_domain
    assert extract_root_domain("www.youtube.com") == "youtube.com"
    assert extract_root_domain("https://blog.example.co.uk/path") == "example.co.uk"
    assert extract_root_domain("sub.domain.service.gov.in") == "service.gov.in"
    assert extract_root_domain("example.com") == "example.com"


def test_api_endpoint_scanner_signatures():
    """Verify Swagger/OpenAPI and GraphQL signature validators reject generic pages."""
    from app.scanners.api_endpoint_scanner import _validate_swagger, _validate_graphql
    
    # Valid Swagger page
    swagger_body = "<html><link href='swagger-ui.css'><script src='swagger-ui-bundle.js'></script></html>"
    assert _validate_swagger(swagger_body, "text/html") >= 2

    # Clean non-swagger page
    clean_body = "<html><title>Home Page</title><body>Welcome!</body></html>"
    assert _validate_swagger(clean_body, "text/html") == 0

    # Valid GraphQL / GraphiQL page
    graphql_body = "<html><title>GraphiQL</title><body>__schema</body></html>"
    assert _validate_graphql(graphql_body, "text/html") >= 2


def test_confidence_engine():
    """Verify confidence engine correctly scores and groups results."""
    from app.scanners.confidence_engine import calculate_confidence, confidence_for_header_finding
    
    # High confidence test (needs score >= 0.80)
    high_conf = calculate_confidence(
        ["Header Validation", "Content Validation", "Payload Reflection", "Certificate Validation"],
        "high"
    )
    assert high_conf["confidence"] == "High"
    assert high_conf["score"] >= 0.80

    # Low confidence test
    low_conf = calculate_confidence(["DNS Validation"], "low")
    assert low_conf["confidence"] == "Low"


def test_deduplication():
    """Verify deduplication merging by scanner name + title and highest severity/confidence."""
    from app.scanners.deduplication import deduplicate_findings, deduplicate_recommendations
    
    findings = [
        {
            "scanner_name": "HeaderScanner",
            "title": "Missing CSP",
            "severity": "Low",
            "confidence": "Low",
            "evidence": "First evidence",
        },
        {
            "scanner_name": "HeaderScanner",
            "title": "Missing CSP",
            "severity": "Medium",
            "confidence": "High",
            "evidence": "Second evidence",
        }
    ]
    
    deduped = deduplicate_findings(findings)
    assert len(deduped) == 1
    assert deduped[0]["severity"] == "Medium"
    assert deduped[0]["confidence"] == "High"
    assert "First evidence" in deduped[0]["evidence"]
    assert "Second evidence" in deduped[0]["evidence"]

    # Recommendations deduplication
    recs = ["Fix CSP", "Fix HSTS", "Fix CSP", "  fix csp  "]
    deduped_recs = deduplicate_recommendations(recs)
    assert len(deduped_recs) == 2
    assert deduped_recs == ["Fix CSP", "Fix HSTS"]


def test_cvss_and_mitre_mapping():
    """Verify CVSS vector retrieval and MITRE ATT&CK technique mapping."""
    from app.scanners.scanner_utils import get_cvss, get_mitre_mapping
    
    # 1. Check valid mapping
    xss_cvss = get_cvss("reflected_xss")
    assert xss_cvss["base_score"] == 6.1
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" in xss_cvss["vector"]

    # 2. Check no vector for technology/dns info
    tech_cvss = get_cvss("tech_disclosure")
    assert not tech_cvss

    # 3. Check MITRE technique mapping
    xss_mitre = get_mitre_mapping("xss")
    assert xss_mitre["technique_id"] == "T1189"
    assert xss_mitre["attack_stage"] == "Initial Access"

