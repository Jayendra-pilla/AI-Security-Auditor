import logging
from typing import List
from app.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

class RecommendationAgent:
    """
    RecommendationAgent inspects the scan vulnerabilities and compiles
    a clean list of actionable recommendations/remediations.
    """

    def generate_recommendations(self, vulnerabilities: List[Vulnerability]) -> List[str]:
        """
        Scans vulnerabilities and maps them to deterministic recommendations.

        Args:
            vulnerabilities: List of Vulnerability database records.

        Returns:
            A clean list of distinct recommendation strings.
        """
        recommendations: List[str] = []
        
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

        for vuln in vulnerabilities:
            title_lower = vuln.title.lower()
            desc_lower = vuln.description.lower()
            scanner_lower = vuln.scanner_name.lower()
            
            matched = False
            for key, rec in rules:
                if key in title_lower or key in desc_lower or key in scanner_lower:
                    if rec not in recommendations:
                        recommendations.append(rec)
                    matched = True
                    
            # Fallback if no specific rule matched:
            if not matched:
                fallback_rec = vuln.recommendation or f"Remediate findings discovered by {vuln.scanner_name}."
                if fallback_rec not in recommendations:
                    recommendations.append(fallback_rec)

        # Baseline recommendation if no findings exist
        if not recommendations:
            recommendations.append("No active vulnerabilities detected. Continue executing periodic security checks and maintaining software patches.")

        logger.info(f"Recommendation Agent generated {len(recommendations)} recommendations.")
        return recommendations
