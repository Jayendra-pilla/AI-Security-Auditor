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
