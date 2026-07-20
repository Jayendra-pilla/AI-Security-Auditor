"""
Centralized Confidence Scoring Engine for the AI Security Auditor.

Provides a uniform confidence calculation interface for all scanners.
Confidence is determined by the number and quality of independent
validation methods that confirm a finding.
"""
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


# Validation method weights (higher = stronger evidence)
VALIDATION_WEIGHTS = {
    "Header Validation": 0.20,
    "Content Validation": 0.20,
    "Payload Reflection": 0.25,
    "Network Validation": 0.15,
    "Certificate Validation": 0.25,
    "DNS Validation": 0.15,
    "Response Code Validation": 0.15,
    "Signature Matching": 0.20,
    "Content-Type Validation": 0.15,
    "Cookie Inspection": 0.15,
    "Redirect Chain Validation": 0.20,
    "TLS Handshake Validation": 0.25,
    "Form Analysis": 0.15,
    "File Content Verification": 0.25,
    "JSON Schema Validation": 0.20,
    "HTML Structure Analysis": 0.15,
    "Port Connection Verification": 0.20,
    "Multi-Hop Verification": 0.20,
}


def calculate_confidence(
    validation_methods: List[str],
    evidence_quality: str = "medium",
    response_consistent: bool = True,
    multiple_confirmations: int = 1,
    evidence_count: int = 1,
    detection_method: str = "N/A",
    verification_method: str = "N/A",
) -> Dict[str, Any]:
    """
    Calculate a structured confidence result based on validation inputs.
    Includes validation count, evidence count, detection/verification methods,
    reliability score, and false positive probability.
    """
    if not validation_methods:
        return {
            "confidence": "Low",
            "score": 0.3,
            "validation_methods": [],
            "confidence_score": 30,
            "validation_count": 0,
            "evidence_count": evidence_count,
            "detection_method": detection_method,
            "verification_method": verification_method,
            "reliability_score": 0.3,
            "false_positive_probability": 0.7,
        }

    # Base score from validation methods
    total_weight = 0.0
    for method in validation_methods:
        total_weight += VALIDATION_WEIGHTS.get(method, 0.10)

    # Normalize to 0.0-1.0 range (cap at 1.0)
    base_score = min(1.0, total_weight)

    # Evidence quality multiplier
    quality_multiplier = {"high": 1.0, "medium": 0.85, "low": 0.65}.get(
        evidence_quality.lower(), 0.85
    )

    # Consistency bonus
    consistency_bonus = 0.05 if response_consistent else -0.10

    # Multiple confirmation bonus (diminishing returns)
    confirmation_bonus = min(0.15, (multiple_confirmations - 1) * 0.05)

    # Final score
    score = min(1.0, max(0.0, (base_score * quality_multiplier) + consistency_bonus + confirmation_bonus))

    # Map score to confidence level
    if score >= 0.80:
        confidence = "High"
    elif score >= 0.50:
        confidence = "Medium"
    else:
        confidence = "Low"

    reliability = round(score, 2)
    return {
        "confidence": confidence,
        "score": reliability,
        "validation_methods": validation_methods,
        "confidence_score": int(score * 100),
        "validation_count": len(validation_methods),
        "evidence_count": evidence_count,
        "detection_method": detection_method,
        "verification_method": verification_method,
        "reliability_score": reliability,
        "false_positive_probability": round(1.0 - score, 2),
    }


def confidence_for_header_finding(
    header_exists: bool,
    header_value: Optional[str] = None,
    content_confirms: bool = False,
) -> Dict[str, Any]:
    """Shortcut for header-based findings (CSP, HSTS, X-Frame-Options, etc.)."""
    methods = ["Header Validation"]
    quality = "high"

    if header_value is not None:
        methods.append("Content Validation")
    if content_confirms:
        methods.append("HTML Structure Analysis")

    return calculate_confidence(
        validation_methods=methods,
        evidence_quality=quality,
        response_consistent=True,
        multiple_confirmations=1 + int(content_confirms),
    )


def confidence_for_network_finding(
    connection_verified: bool,
    response_code_valid: bool = False,
    tls_verified: bool = False,
) -> Dict[str, Any]:
    """Shortcut for network-level findings (ports, TLS, redirects)."""
    methods = []
    if connection_verified:
        methods.append("Network Validation")
    if response_code_valid:
        methods.append("Response Code Validation")
    if tls_verified:
        methods.append("TLS Handshake Validation")

    quality = "high" if len(methods) >= 2 else "medium"
    return calculate_confidence(
        validation_methods=methods,
        evidence_quality=quality,
        response_consistent=connection_verified,
    )


def confidence_for_dns_finding(
    record_found: bool,
    record_value: Optional[str] = None,
    cross_validated: bool = False,
) -> Dict[str, Any]:
    """Shortcut for DNS-based findings (SPF, DMARC, CAA)."""
    methods = ["DNS Validation"]
    if record_value:
        methods.append("Content Validation")
    if cross_validated:
        methods.append("Multi-Hop Verification")

    quality = "high" if record_found else "medium"
    return calculate_confidence(
        validation_methods=methods,
        evidence_quality=quality,
        response_consistent=True,
    )
