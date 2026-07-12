from datetime import datetime, timezone
import html
from app.models.scan import Scan
from app.models.report import Report

class HTMLReportGenerator:
    """
    HTML generator class for compiling dashboard reports.
    """

    @staticmethod
    def generate(scan: Scan, report: Report) -> str:
        """
        Generates a modern, professional, styled HTML report.
        """
        # Format dates
        scan_date_str = scan.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        generated_date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Format statistics
        stats = report.statistics or {}
        critical_count = stats.get("critical", 0)
        high_count = stats.get("high", 0)
        medium_count = stats.get("medium", 0)
        low_count = stats.get("low", 0)
        info_count = stats.get("informational", 0)
        total_vulns = len(scan.vulnerabilities)

        # Style colors based on risk grade/score
        risk_color = "#28a745"  # Green
        if report.risk_score >= 75:
            risk_color = "#dc3545"  # Red
        elif report.risk_score >= 40:
            risk_color = "#fd7e14"  # Orange
        elif report.risk_score >= 20:
            risk_color = "#ffc107"  # Yellow

        # Escape target and scan metadata
        target_esc = html.escape(scan.target)
        scan_id_esc = html.escape(scan.scan_id)
        summary_esc = html.escape(report.summary)

        # Render Vulnerability rows
        vuln_rows = ""
        if scan.vulnerabilities:
            for vuln in scan.vulnerabilities:
                sev_label = html.escape(vuln.severity.upper())
                sev_class = html.escape(vuln.severity.lower())
                title_esc = html.escape(vuln.title)
                desc_esc = html.escape(vuln.description)
                rec_esc = html.escape(vuln.recommendation)
                vuln_rows += f"""
                <tr class="vuln-row">
                    <td><span class="severity-badge sev-{sev_class}">{sev_label}</span></td>
                    <td class="vuln-title">{title_esc}</td>
                    <td>{desc_esc}</td>
                    <td>{rec_esc}</td>
                </tr>
                """
        else:
            vuln_rows = """
            <tr>
                <td colspan="4" class="no-vulns">No vulnerabilities detected in this scan.</td>
            </tr>
            """

        # Render Recommendations list
        recs_list = ""
        if report.recommendations:
            for rec in report.recommendations:
                rec_esc = html.escape(rec)
                recs_list += f"<li>{rec_esc}</li>"
        else:
            recs_list = "<li>No recommendations needed.</li>"

        # HTML template
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Security Audit Report - {target_esc}</title>
    <style>
        :root {{
            --primary: #1e293b;
            --primary-light: #334155;
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --text-main: #0f172a;
            --text-muted: #475569;
            --border: #e2e8f0;
            
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #22c55e;
            --info: #06b6d4;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            line-height: 1.5;
            padding: 2rem 1rem;
        }}

        .container {{
            max-width: 1000px;
            margin: 0 auto;
            background-color: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.05), 0 2px 4px -2px rgb(0 0 0 / 0.05);
            padding: 3rem;
        }}

        /* Header Layout */
        .header {{
            border-bottom: 2px solid var(--border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }}

        .header-title h1 {{
            font-size: 2.25rem;
            color: var(--primary);
            font-weight: 700;
            margin-bottom: 0.5rem;
        }}

        .header-title p {{
            font-size: 1.1rem;
            color: var(--text-muted);
        }}

        .badge-container {{
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: 0.5rem;
        }}

        .grade-badge {{
            font-size: 2.5rem;
            font-weight: 800;
            color: white;
            background-color: {risk_color};
            width: 80px;
            height: 80px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
        }}

        .risk-score-label {{
            font-size: 0.9rem;
            font-weight: 600;
            color: var(--text-muted);
        }}

        /* Metadata Grid */
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            background-color: #f1f5f9;
            padding: 1.5rem;
            border-radius: 6px;
            margin-bottom: 2.5rem;
        }}

        .meta-item .label {{
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            margin-bottom: 0.25rem;
        }}

        .meta-item .value {{
            font-size: 1rem;
            font-weight: 600;
            color: var(--primary-light);
            word-break: break-all;
        }}

        /* Section Layout */
        h2 {{
            font-size: 1.5rem;
            color: var(--primary);
            border-left: 4px solid var(--primary-light);
            padding-left: 0.75rem;
            margin-bottom: 1.25rem;
            margin-top: 2rem;
        }}

        p.summary-text {{
            color: var(--text-muted);
            font-size: 1.05rem;
            line-height: 1.7;
            margin-bottom: 2rem;
            text-align: justify;
        }}

        /* Severity Stats Cards */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 1rem;
            margin-bottom: 2.5rem;
        }}

        .stat-card {{
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 1rem;
            text-align: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.02);
        }}

        .stat-card.total {{
            background-color: #f8fafc;
            border-color: #cbd5e1;
        }}

        .stat-number {{
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 0.25rem;
        }}

        .stat-label {{
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
        }}

        /* Colors */
        .stat-card.critical {{ border-top: 4px solid var(--critical); }}
        .stat-card.critical .stat-number {{ color: var(--critical); }}
        .stat-card.high {{ border-top: 4px solid var(--high); }}
        .stat-card.high .stat-number {{ color: var(--high); }}
        .stat-card.medium {{ border-top: 4px solid var(--medium); }}
        .stat-card.medium .stat-number {{ color: var(--medium); }}
        .stat-card.low {{ border-top: 4px solid var(--low); }}
        .stat-card.low .stat-number {{ color: var(--low); }}
        .stat-card.info {{ border-top: 4px solid var(--info); }}
        .stat-card.info .stat-number {{ color: var(--info); }}

        /* Table styles */
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 2.5rem;
            font-size: 0.95rem;
        }}

        th {{
            background-color: #f1f5f9;
            color: var(--primary);
            font-weight: 600;
            text-align: left;
            padding: 0.75rem 1rem;
            border-bottom: 2px solid var(--border);
        }}

        td {{
            padding: 1rem;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }}

        .vuln-row:hover {{
            background-color: #f8fafc;
        }}

        .vuln-title {{
            font-weight: 600;
            color: var(--primary-light);
        }}

        .no-vulns {{
            text-align: center;
            color: var(--text-muted);
            padding: 2rem;
            font-style: italic;
        }}

        .severity-badge {{
            display: inline-block;
            padding: 0.25rem 0.5rem;
            font-size: 0.75rem;
            font-weight: 700;
            border-radius: 4px;
            color: white;
            text-align: center;
            min-width: 75px;
        }}

        .sev-critical {{ background-color: var(--critical); }}
        .sev-high {{ background-color: var(--high); }}
        .sev-medium {{ background-color: var(--medium); }}
        .sev-low {{ background-color: var(--low); }}
        .sev-informational {{ background-color: var(--info); }}

        /* Recommendations List */
        .recs-list {{
            margin-left: 1.5rem;
            margin-bottom: 2.5rem;
            color: var(--text-muted);
        }}

        .recs-list li {{
            margin-bottom: 0.75rem;
            line-height: 1.6;
        }}

        /* Footer */
        .footer {{
            border-top: 1px solid var(--border);
            padding-top: 1.5rem;
            margin-top: 3rem;
            display: flex;
            justify-content: space-between;
            font-size: 0.8rem;
            color: var(--text-muted);
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-title">
                <h1>AI Security Auditor</h1>
                <p>Vulnerability & Risk Assessment Report</p>
            </div>
            <div class="badge-container">
                <div class="grade-badge">{report.grade}</div>
                <div class="risk-score-label">Risk Score: {report.risk_score}/100</div>
            </div>
        </div>

        <!-- Metadata -->
        <div class="meta-grid">
            <div class="meta-item">
                <div class="label">Target URL</div>
                <div class="value">{target_esc}</div>
            </div>
            <div class="meta-item">
                <div class="label">Scan ID</div>
                <div class="value">{scan_id_esc}</div>
            </div>
            <div class="meta-item">
                <div class="label">Scan Date</div>
                <div class="value">{scan_date_str}</div>
            </div>
            <div class="meta-item">
                <div class="label">Scan Status</div>
                <div class="value" style="text-transform: capitalize;">{scan.status}</div>
            </div>
        </div>

        <!-- Executive Summary -->
        <h2>Executive Summary</h2>
        <p class="summary-text">{summary_esc}</p>

        <!-- Severity Statistics -->
        <h2>Severity Statistics</h2>
        <div class="stats-grid">
            <div class="stat-card total">
                <div class="stat-number">{total_vulns}</div>
                <div class="stat-label">Total</div>
            </div>
            <div class="stat-card critical">
                <div class="stat-number">{critical_count}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-number">{high_count}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-number">{medium_count}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-number">{low_count}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat-card info">
                <div class="stat-number">{info_count}</div>
                <div class="stat-label">Info</div>
            </div>
        </div>

        <!-- Vulnerability Details -->
        <h2>Vulnerability Details</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 120px;">Severity</th>
                    <th style="width: 200px;">Title</th>
                    <th>Description</th>
                    <th>Recommendation</th>
                </tr>
            </thead>
            <tbody>
                {vuln_rows}
            </tbody>
        </table>

        <!-- Actionable Recommendations -->
        <h2>AI Recommendations & Mitigations</h2>
        <ul class="recs-list">
            {recs_list}
        </ul>

        <!-- Footer -->
        <div class="footer">
            <div>Generated by AI Security Auditor Engine</div>
            <div>Timestamp: {generated_date_str}</div>
        </div>
    </div>
</body>
</html>
"""
        return html_content

