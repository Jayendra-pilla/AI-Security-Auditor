import logging
from typing import List
from app.models.vulnerability import Vulnerability
from app.scanners.deduplication import deduplicate_recommendations

logger = logging.getLogger(__name__)

class RecommendationAgent:
    """
    RecommendationAgent inspects the scan vulnerabilities and compiles
    a clean list of actionable recommendations/remediations.
    
    Ensures recommendations are completely data-driven:
    - Never recommends fixing something that passed.
    - Never recommends CSP if CSP checks passed (no active CSP vulnerability).
    - Never recommends CORS if CORS checks passed.
    - Never recommends CSRF if CSRF checks passed.
    - Deduplicates recommendations.
    - Ranks recommendations by severity.
    """

    def generate_recommendations(self, vulnerabilities: List[Vulnerability]) -> List[str]:
        """
        Scans vulnerabilities and maps them to deterministic recommendations.

        Args:
            vulnerabilities: List of Vulnerability database records.

        Returns:
            A clean, ranked, and deduplicated list of recommendation strings.
        """
        SEVERITY_RANK = {
            "informational": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }

        # Rule-based scanner recommendation mappings
        rules = [
            ("csp", "Missing Content-Security-Policy (CSP) headers. Implement a strict CSP to block unauthorized script execution."),
            ("hsts", "Missing Strict-Transport-Security (HSTS) headers. Enable HSTS with standard max-age directive to enforce HTTPS."),
            ("cookie", "Weak Cookie flags. Enforce Secure, HttpOnly, and SameSite (Lax/Strict) attributes on all application cookies."),
            ("redirect", "Potential Open Redirect. Implement strict domain whitelisting on all redirect destinations to prevent phishing redirection."),
            ("xss", "Cross-Site Scripting (XSS). Perform robust context-aware output encoding and input sanitization on all user-supplied data."),
            ("cors", "Insecure CORS configuration. Configure the Access-Control-Allow-Origin header to use a strict whitelist of origins rather than wildcard *."),
            ("csrf", "CSRF vulnerability. Implement unique anti-CSRF state tokens and leverage SameSite cookie properties.")
        ]

        # First, filter to active vulnerabilities (severity > Informational)
        active_vulns = [
            v for v in vulnerabilities 
            if v.severity.lower() in ("low", "medium", "high", "critical")
        ]

        # Gather recommendations from active vulnerabilities only
        findings_recommendations = []
        for vuln in active_vulns:
            title_lower = vuln.title.lower()
            desc_lower = vuln.description.lower()
            scanner_lower = vuln.scanner_name.lower()
            
            matched = False
            for key, rec in rules:
                if key in title_lower or key in desc_lower or key in scanner_lower:
                    findings_recommendations.append((vuln.severity.lower(), rec))
                    matched = True
                    
            if not matched:
                fallback_rec = vuln.recommendation or f"Remediate findings discovered by {vuln.scanner_name}."
                findings_recommendations.append((vuln.severity.lower(), fallback_rec))

        # Rank recommendations by severity of their source vulnerability (highest first)
        findings_recommendations.sort(key=lambda x: SEVERITY_RANK.get(x[0], 0), reverse=True)

        # Extract just the recommendation strings while maintaining order
        recs = [item[1] for item in findings_recommendations]

        # Deduplicate
        final_recs = deduplicate_recommendations(recs)

        # Baseline recommendation if no findings exist
        if not final_recs:
            final_recs.append("No active vulnerabilities detected. Continue executing periodic security checks and maintaining software patches.")

        logger.info(f"Recommendation Agent generated {len(final_recs)} recommendations.")
        return final_recs
