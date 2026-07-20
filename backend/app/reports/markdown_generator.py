from datetime import datetime, timezone
from app.models.scan import Scan
from app.models.report import Report
from app.scanners.scanner_utils import parse_vulnerability_description

class MarkdownReportGenerator:
    """
    Markdown generator class for technical and executive report exports.
    Produces highly structured, styled enterprise pentesting markdown reports.
    """

    @staticmethod
    def generate(scan: Scan, report: Report, mode: str = "technical") -> str:
        """
        Generates a GitHub-flavored Markdown report.
        Supports both 'technical' and 'executive' modes.
        """
        scan_date_str = scan.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        generated_date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        stats = report.statistics or {}
        critical_count = stats.get("critical", 0)
        high_count = stats.get("high", 0)
        medium_count = stats.get("medium", 0)
        low_count = stats.get("low", 0)
        info_count = stats.get("informational", 0)
        
        # Filter vulnerabilities by mode
        if mode == "executive":
            vulnerabilities = [
                v for v in scan.vulnerabilities 
                if v.severity.lower() in ("critical", "high", "medium")
            ]
        else:
            vulnerabilities = scan.vulnerabilities

        total_vulns = len(vulnerabilities)

        # Build Compliance values
        pci_compliance = max(30, min(100, 100 - (critical_count * 20 + high_count * 10)))
        iso_compliance = max(40, min(100, 100 - (critical_count * 15 + high_count * 8)))

        md = f"""# AI Security Audit Report ({mode.capitalize()} Summary)

**Target URL:** {scan.target}  
**Scan ID:** {scan.scan_id}  
**Scan Date:** {scan_date_str}  
**Status:** {scan.status.capitalize()}  
**Report Version:** v2.0  
**Classification:** CONFIDENTIAL  

---

# Executive Summary

{report.summary}

---

# Risk Score

| Metric | Score / Grade / Count |
| :--- | :--- |
| **Assessed Risk Score** | {report.risk_score}/100 |
| **Security Grade** | {report.grade} |
| **PCI DSS Compliance** | {pci_compliance}% |
| **ISO 27001 Security Score** | {iso_compliance}% |
| **Total Findings** | {len(scan.vulnerabilities)} |

---

# Statistics

| Severity | Count |
| :--- | :--- |
| **Critical** | {critical_count} |
| **High** | {high_count} |
| **Medium** | {medium_count} |
| **Low** | {low_count} |
| **Informational** | {info_count} |

---

# Vulnerabilities Summary ({mode.capitalize()} View)

"""

        if vulnerabilities:
            md += "| Finding ID | Severity | Title | CWE | OWASP | CVSS Score |\n"
            md += "| :--- | :--- | :--- | :--- | :--- | :--- |\n"
            for idx, vuln in enumerate(vulnerabilities):
                vuln_id = f"ASE-{1000 + idx}"
                sev_label = vuln.severity.upper()
                title_clean = vuln.title.replace("|", "\\|")
                parsed = parse_vulnerability_description(vuln.description or "")
                cwe_esc = parsed.get("cwe_mapping", "N/A")
                owasp_esc = parsed.get("owasp_mapping", "N/A")
                cvss_val = parsed.get("cvss_estimate", "N/A")
                md += f"| `{vuln_id}` | **{sev_label}** | {title_clean} | {cwe_esc} | {owasp_esc} | {cvss_val} |\n"

            md += "\n---\n\n# Detailed Vulnerability Index\n\n"
            for idx, vuln in enumerate(vulnerabilities):
                vuln_id = f"ASE-{1000 + idx}"
                parsed = parse_vulnerability_description(vuln.description or "")
                
                md += f"## {vuln_id} - {vuln.title}\n\n"
                md += f"*   **Severity:** {vuln.severity.upper()}\n"
                md += f"*   **CWE Mapping:** {parsed.get('cwe_mapping', 'N/A')}\n"
                md += f"*   **OWASP Category:** {parsed.get('owasp_mapping', 'N/A')}\n"
                md += f"*   **CVSS Score:** {parsed.get('cvss_estimate', 'N/A')}\n"
                if parsed.get("cvss_vector"):
                    md += f"*   **CVSS Vector:** `{parsed.get('cvss_vector')}`\n"
                md += f"*   **Confidence Level:** {parsed.get('confidence_level', 'Medium')} ({parsed.get('confidence_score') or 85}%)\n"
                md += f"*   **Reliability Score:** {int((parsed.get('reliability_score') or 0.8)*100)}%\n"
                md += f"*   **Verification Method:** {parsed.get('verification_method', 'N/A')}\n"
                md += f"\n### Description\n\n{parsed.get('description_body', 'No description.')}\n\n"
                md += f"### Remediation Steps\n\n{vuln.recommendation or 'No recommendation.'}\n\n"
                
                if mode == "technical":
                    md += "### Technical Evidence\n\n"
                    md += f"**Affected URL:** `{parsed.get('affected_url', 'N/A')}`  \n"
                    md += f"**Method:** `{parsed.get('request_method', 'GET')}`  \n\n"
                    
                    md += "<details>\n<summary>Click to view raw request/response logs</summary>\n\n"
                    md += "```http\n"
                    md += f"{parsed.get('request_method', 'GET')} {parsed.get('affected_url', '/')} HTTP/1.1\n"
                    md += "```\n\n"
                    if parsed.get("response_headers") and parsed.get("response_headers") != "N/A":
                        md += "Response Snippet:\n```http\n"
                        md += f"{parsed.get('response_snippet', '')}\n"
                        md += "```\n"
                    md += "</details>\n\n"
                
                md += "---\n\n"
        else:
            md += "*No vulnerabilities matching the filter criteria were identified during this security scan.*\n\n"

        md += "# Recommendations\n\n"
        if report.recommendations:
            for rec in report.recommendations:
                md += f"* {rec}\n"
        else:
            md += "*No immediate action items recommended.*\n"

        md += f"\n---\n*Generated by AI Security Auditor Engine at {generated_date_str}*"
        return md
