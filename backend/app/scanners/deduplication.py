"""
Finding Deduplication Engine for the AI Security Auditor.

Merges duplicate findings before report generation to eliminate noise.
Keeps the highest severity, highest confidence, and merges evidence.
"""
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


def deduplicate_findings(findings_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate scanner findings by merging entries with identical titles
    from the same scanner.

    Rules:
      - Key: (scanner_name, title)
      - Keep the highest severity
      - Keep the highest confidence
      - Merge evidence strings (avoid exact duplicates)
      - Keep first occurrence's other fields as base

    Args:
        findings_list: Flat list of finding dicts from all scanners.

    Returns:
        Deduplicated list of finding dicts.
    """
    SEVERITY_RANK = {
        "informational": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    CONFIDENCE_RANK = {
        "low": 0,
        "medium": 1,
        "high": 2,
    }

    seen: Dict[tuple, Dict[str, Any]] = {}

    for finding in findings_list:
        scanner = finding.get("scanner_name", "Unknown")
        title = finding.get("title", "Unknown")
        key = (scanner.lower(), title.lower())

        if key not in seen:
            seen[key] = dict(finding)
        else:
            existing = seen[key]

            # Keep highest severity
            existing_sev = SEVERITY_RANK.get(existing.get("severity", "informational").lower(), 0)
            new_sev = SEVERITY_RANK.get(finding.get("severity", "informational").lower(), 0)
            if new_sev > existing_sev:
                existing["severity"] = finding["severity"]

            # Keep highest confidence
            existing_conf = CONFIDENCE_RANK.get(existing.get("confidence", "low").lower(), 0)
            new_conf = CONFIDENCE_RANK.get(finding.get("confidence", "low").lower(), 0)
            if new_conf > existing_conf:
                existing["confidence"] = finding["confidence"]

            # Merge evidence (avoid exact duplicates)
            existing_evidence = existing.get("evidence", "")
            new_evidence = finding.get("evidence", "")
            if new_evidence and new_evidence not in existing_evidence:
                existing["evidence"] = f"{existing_evidence}; {new_evidence}"

    deduplicated = list(seen.values())
    logger.info(
        f"Deduplication: {len(findings_list)} findings → {len(deduplicated)} unique findings"
    )
    return deduplicated


def deduplicate_recommendations(recommendations: List[str]) -> List[str]:
    """
    Remove exact-duplicate and near-duplicate recommendation strings.
    Preserves order, keeps first occurrence.

    Args:
        recommendations: List of recommendation strings.

    Returns:
        Deduplicated list of recommendation strings.
    """
    seen_normalized = set()
    unique = []

    for rec in recommendations:
        # Normalize for comparison: lowercase, strip whitespace
        normalized = rec.strip().lower()
        if normalized and normalized not in seen_normalized:
            seen_normalized.add(normalized)
            unique.append(rec)

    return unique
