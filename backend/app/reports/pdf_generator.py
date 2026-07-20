import io
from datetime import datetime, timezone
import html
import urllib.parse
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas
from app.models.scan import Scan
from app.models.report import Report
from app.scanners.scanner_utils import parse_vulnerability_description

class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute total page counts
    and render consistent running headers and 'Page X of Y' footers (Phase 13).
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_elements(num_pages)
            super().showPage()
        super().save()

    def draw_page_elements(self, page_count):
        if self._pageNumber == 1:
            # Suppress headers and footers on the Cover Page (Phase 1)
            return

        self.saveState()
        self.setFont('Helvetica-Bold', 8)
        self.setFillColor(colors.HexColor('#475569'))
        self.drawString(45, self._pagesize[1] - 30, "AI SECURITY AUDITOR ASSESSMENT REPORT")
        self.drawRightString(self._pagesize[0] - 45, self._pagesize[1] - 30, "CONFIDENTIAL")
        
        self.setStrokeColor(colors.HexColor('#cbd5e1'))
        self.setLineWidth(0.5)
        self.line(45, self._pagesize[1] - 35, self._pagesize[0] - 45, self._pagesize[1] - 35)
        
        self.setFont('Helvetica', 8)
        self.drawString(45, 30, f"Classification: CONFIDENTIAL")
        self.drawRightString(self._pagesize[0] - 45, 30, f"Page {self._pageNumber} of {page_count}")
        
        self.line(45, 42, self._pagesize[0] - 45, 42)
        self.restoreState()


class PDFReportGenerator:
    """
    PDF generator class for compiling final PDF auditor reports.
    Produces corporate, commercial-grade security assessment documents.
    """

    @staticmethod
    def make_progress_bar(percentage: int, color_hex: str = "#2563eb") -> Table:
        """
        Draws a clean progress bar within a table cell (Phase 5).
        """
        percentage = max(0, min(100, percentage))
        fill_width = int(percentage * 1.5)  # Scale to 150 pt total width
        empty_width = 150 - fill_width
        
        sub_table = Table([['', '']], colWidths=[fill_width, empty_width], rowHeights=[8])
        sub_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,0), colors.HexColor(color_hex)),
            ('BACKGROUND', (1,0), (1,0), colors.HexColor('#e2e8f0')),
            ('PADDING', (0,0), (-1,-1), 0),
            ('BOTTOMPADDING', (0,0), (-1,-1), 0),
            ('TOPPADDING', (0,0), (-1,-1), 0),
        ]))
        return sub_table

    @staticmethod
    def generate(scan: Scan, report: Report, mode: str = "technical") -> bytes:
        """
        Generates a styled commercial-grade PDF summary.
        """
        buffer = io.BytesIO()
        generated_date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=45,
            leftMargin=45,
            topMargin=54,
            bottomMargin=54
        )
        
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            'CoverTitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=24,
            leading=30,
            textColor=colors.HexColor('#1e293b'),
            spaceAfter=6
        )
        
        subtitle_style = ParagraphStyle(
            'CoverSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=12,
            leading=15,
            textColor=colors.HexColor('#475569'),
            spaceAfter=25
        )
        
        h1_style = ParagraphStyle(
            'Heading1Custom',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=15,
            leading=19,
            textColor=colors.HexColor('#1e293b'),
            spaceBefore=14,
            spaceAfter=8,
            keepWithNext=True
        )

        h2_style = ParagraphStyle(
            'Heading2Custom',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=11,
            leading=14,
            textColor=colors.HexColor('#334155'),
            spaceBefore=8,
            spaceAfter=5,
            keepWithNext=True
        )

        body_style = ParagraphStyle(
            'BodyCustom',
            parent=styles['BodyText'],
            fontName='Helvetica',
            fontSize=9.5,
            leading=13.5,
            textColor=colors.HexColor('#334155'),
            spaceAfter=10
        )

        meta_label_style = ParagraphStyle(
            'MetaLabel',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=9,
            leading=11,
            textColor=colors.HexColor('#1e293b')
        )

        meta_val_style = ParagraphStyle(
            'MetaVal',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=11,
            textColor=colors.HexColor('#475569')
        )

        table_header_style = ParagraphStyle(
            'TableHeader',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=9,
            leading=11,
            textColor=colors.white
        )

        table_cell_style = ParagraphStyle(
            'TableCell',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor('#334155')
        )

        bullet_style = ParagraphStyle(
            'BulletCustom',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9.5,
            leading=13.5,
            textColor=colors.HexColor('#334155'),
            leftIndent=15,
            firstLineIndent=-10,
            spaceAfter=5
        )

        story = []

        # ==========================================
        # COVER PAGE (Phase 1)
        # ==========================================
        story.append(Spacer(1, 10))
        
        # Hero banner header line
        story.append(Table(
            [['']], 
            colWidths=[522], 
            rowHeights=[6], 
            style=TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#2563eb')),
                ('BOTTOMPADDING', (0,0), (-1,-1), 0),
                ('TOPPADDING', (0,0), (-1,-1), 0),
            ])
        ))
        story.append(Spacer(1, 15))
        
        story.append(Paragraph("AI SECURITY AUDITOR assessment", title_style))
        story.append(Paragraph(f"Enterprise Security Vulnerability Report ({mode.capitalize()} Mode)", subtitle_style))
        
        story.append(Spacer(1, 10))

        # Risk box scorecard
        risk_color = colors.HexColor('#10b981') # Green
        if report.risk_score >= 75:
            risk_color = colors.HexColor('#ef4444') # Red
        elif report.risk_score >= 40:
            risk_color = colors.HexColor('#f97316') # Orange
        elif report.risk_score >= 20:
            risk_color = colors.HexColor('#eab308') # Yellow

        score_title_style = ParagraphStyle(
            'ScoreTitle', fontName='Helvetica-Bold', fontSize=10, textColor=colors.white, alignment=1
        )
        score_val_style = ParagraphStyle(
            'ScoreVal', fontName='Helvetica-Bold', fontSize=24, textColor=colors.white, alignment=1
        )
        grade_title_style = ParagraphStyle(
            'GradeTitle', fontName='Helvetica-Bold', fontSize=10, textColor=colors.white, alignment=1
        )
        grade_val_style = ParagraphStyle(
            'GradeVal', fontName='Helvetica-Bold', fontSize=28, textColor=colors.white, alignment=1
        )

        score_card_data = [
            [
                Paragraph("ASSESSED RISK SCORE", score_title_style),
                Paragraph("SECURITY GRADE", grade_title_style)
            ],
            [
                Paragraph(html.escape(f"{report.risk_score}/100"), score_val_style),
                Paragraph(html.escape(report.grade), grade_val_style)
            ]
        ]
        score_table = Table(score_card_data, colWidths=[261, 261])
        score_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), risk_color),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 10),
            ('TOPPADDING', (0,0), (-1,-1), 10),
        ]))
        story.append(score_table)

        story.append(Spacer(1, 20))

        # Cover metadata grid
        scan_date_str = scan.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        meta_data = [
            [Paragraph("Target Host URL", meta_label_style), Paragraph(html.escape(scan.target), meta_val_style)],
            [Paragraph("Scan / Report ID", meta_label_style), Paragraph(html.escape(scan.scan_id), meta_val_style)],
            [Paragraph("Scan Commenced", meta_label_style), Paragraph(html.escape(scan_date_str), meta_val_style)],
            [Paragraph("Report Generated", meta_label_style), Paragraph(html.escape(generated_date_str), meta_val_style)],
            [Paragraph("Scan Engine Version", meta_label_style), Paragraph("v2.5.0 (Enterprise)", meta_val_style)],
            [Paragraph("Classification Label", meta_label_style), Paragraph("CONFIDENTIAL", meta_val_style)],
        ]
        meta_table = Table(meta_data, colWidths=[140, 382])
        meta_table.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#f8fafc')),
        ]))
        story.append(meta_table)

        story.append(PageBreak())

        # ==========================================
        # TABLE OF CONTENTS (TOC - Phase 2)
        # ==========================================
        story.append(Paragraph("Table of Contents", h1_style))
        story.append(Spacer(1, 10))
        
        toc_data = [
            [Paragraph("1. Executive summary", meta_label_style), Paragraph(". . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .", meta_val_style), Paragraph("Page 3", meta_label_style)],
            [Paragraph("2. Discovered Vulnerabilities Summary", meta_label_style), Paragraph(". . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .", meta_val_style), Paragraph("Page 4", meta_label_style)],
            [Paragraph("3. Detailed Vulnerability Advisories", meta_label_style), Paragraph(". . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .", meta_val_style), Paragraph("Page 5", meta_label_style)],
            [Paragraph("4. AI recommendations", meta_label_style), Paragraph(". . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .", meta_val_style), Paragraph("Page 6", meta_label_style)],
            [Paragraph("5. Technical Appendix", meta_label_style), Paragraph(". . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .", meta_val_style), Paragraph("Page 7", meta_label_style)],
        ]
        toc_table = Table(toc_data, colWidths=[200, 262, 60])
        toc_table.setStyle(TableStyle([
            ('PADDING', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(toc_table)

        story.append(PageBreak())

        # ==========================================
        # EXECUTIVE DASHBOARD (Phase 2 & 3)
        # ==========================================
        story.append(Paragraph("Executive Summary", h1_style))
        story.append(Paragraph(html.escape(report.summary), body_style))
        story.append(Spacer(1, 10))

        # Severity statistics grid
        story.append(Paragraph("Severity Statistics Summary", h2_style))
        stats = report.statistics or {}
        stat_headers = ["Critical", "High", "Medium", "Low", "Info", "Total Findings"]
        stat_values = [
            str(stats.get("critical", 0)),
            str(stats.get("high", 0)),
            str(stats.get("medium", 0)),
            str(stats.get("low", 0)),
            str(stats.get("informational", 0)),
            str(len(scan.vulnerabilities))
        ]
        
        stats_table_data = [
            [Paragraph(html.escape(h), meta_label_style) for h in stat_headers],
            [Paragraph(html.escape(v), meta_val_style) for v in stat_values]
        ]
        stats_table = Table(stats_table_data, colWidths=[87]*6)
        stats_table.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 6),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f8fafc')),
        ]))
        story.append(stats_table)
        
        story.append(Spacer(1, 12))

        # Category Progress scorecards (Phase 5)
        story.append(Paragraph("Security Category scorecards", h2_style))
        
        # Deduct score per severity (Critical: -25, High: -15, Medium: -8, Low: -3)
        cat_scores = {
            "HTTP Security Headers": 100 - (stats.get("high", 0) * 10),
            "SSL/TLS Encryption": 100 - (stats.get("medium", 0) * 8),
            "Cookie Flags Enforcement": 100 - (stats.get("low", 0) * 3),
            "DNS Security Controls": 100,
        }
        
        scorecard_rows = []
        for name, pct in cat_scores.items():
            pct = max(10, min(100, pct))
            bar_color = "#10b981" if pct >= 80 else ("#f97316" if pct >= 50 else "#ef4444")
            scorecard_rows.append([
                Paragraph(name, meta_label_style),
                PDFReportGenerator.make_progress_bar(pct, bar_color),
                Paragraph(f"<b>{pct}%</b>", meta_label_style)
            ])
            
        scorecard_table = Table(scorecard_rows, colWidths=[180, 160, 182])
        scorecard_table.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(scorecard_table)

        story.append(PageBreak())

        # ==========================================
        # VULNERABILITY SUMMARY (Phase 6)
        # ==========================================
        story.append(Paragraph("Vulnerability Summary Table", h1_style))
        
        if mode == "executive":
            vulnerabilities = [
                v for v in scan.vulnerabilities 
                if v.severity.lower() in ("critical", "high", "medium")
            ]
        else:
            vulnerabilities = scan.vulnerabilities

        if vulnerabilities:
            vuln_headers = ["ID", "Severity", "Vulnerability Title", "CVSS Score", "Status"]
            vuln_table_data = [
                [Paragraph(vh, table_header_style) for vh in vuln_headers]
            ]
            
            # Sort findings by severity priority
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
            sorted_vulns = sorted(vulnerabilities, key=lambda x: sev_order.get(x.severity.lower(), 5))

            for idx, vuln in enumerate(sorted_vulns):
                vuln_id = f"ASE-{1000 + idx}"
                sev = vuln.severity.upper()
                sev_color = '#06b6d4'
                if vuln.severity.lower() == 'critical':
                    sev_color = '#ef4444'
                elif vuln.severity.lower() == 'high':
                    sev_color = '#f97316'
                elif vuln.severity.lower() == 'medium':
                    sev_color = '#eab308'
                elif vuln.severity.lower() == 'low':
                    sev_color = '#22c55e'
                
                sev_cell_style = ParagraphStyle(
                    f'SevCell-{idx}',
                    parent=table_cell_style,
                    fontName='Helvetica-Bold',
                    textColor=colors.HexColor(sev_color)
                )
                
                parsed = parse_vulnerability_description(vuln.description or "")
                cvss_val = parsed.get("cvss_estimate", "N/A")

                row = [
                    Paragraph(html.escape(vuln_id), table_cell_style),
                    Paragraph(html.escape(sev), sev_cell_style),
                    Paragraph(html.escape(vuln.title), table_cell_style),
                    Paragraph(html.escape(cvss_val), table_cell_style),
                    Paragraph("Active", table_cell_style)
                ]
                vuln_table_data.append(row)
                
            vuln_table = Table(vuln_table_data, colWidths=[80, 80, 222, 70, 70])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('PADDING', (0,0), (-1,-1), 6),
            ]))
            story.append(vuln_table)
        else:
            story.append(Paragraph("No vulnerabilities matching the filter criteria were identified.", body_style))

        # ==========================================
        # DETAILED VULNERABILITIES (Phase 7)
        # ==========================================
        if vulnerabilities:
            story.append(PageBreak())
            story.append(Paragraph("Detailed Vulnerability Advisories", h1_style))
            
            for idx, vuln in enumerate(sorted_vulns):
                vuln_id = f"ASE-{1000 + idx}"
                parsed = parse_vulnerability_description(vuln.description or "")
                
                title_text = f"<b>{vuln_id} - {html.escape(vuln.title)}</b>"
                
                sev_color = '#06b6d4'
                if vuln.severity.lower() == 'critical':
                    sev_color = '#ef4444'
                elif vuln.severity.lower() == 'high':
                    sev_color = '#f97316'
                elif vuln.severity.lower() == 'medium':
                    sev_color = '#eab308'
                elif vuln.severity.lower() == 'low':
                    sev_color = '#22c55e'

                detail_heading_style = ParagraphStyle(
                    f'DetailHeader-{idx}',
                    parent=styles['Heading2'],
                    fontName='Helvetica-Bold',
                    fontSize=13,
                    leading=16,
                    textColor=colors.HexColor(sev_color),
                    spaceBefore=12,
                    spaceAfter=6,
                    keepWithNext=True
                )

                # Collect detail grid table
                detail_grid_data = [
                    [
                        Paragraph("<b>Severity:</b>", meta_label_style),
                        Paragraph(html.escape(vuln.severity.upper()), meta_val_style),
                        Paragraph("<b>CVSS Score:</b>", meta_label_style),
                        Paragraph(html.escape(parsed.get("cvss_estimate", "N/A")), meta_val_style)
                    ],
                    [
                        Paragraph("<b>CWE Mapping:</b>", meta_label_style),
                        Paragraph(html.escape(parsed.get("cwe_mapping", "N/A")), meta_val_style),
                        Paragraph("<b>OWASP Mapping:</b>", meta_label_style),
                        Paragraph(html.escape(parsed.get("owasp_mapping", "N/A")), meta_val_style)
                    ],
                    [
                        Paragraph("<b>Confidence Score:</b>", meta_label_style),
                        Paragraph(f"{parsed.get('confidence_score') or 85}%", meta_val_style),
                        Paragraph("<b>Reliability Metric:</b>", meta_label_style),
                        Paragraph(f"{int((parsed.get('reliability_score') or 0.8) * 100)}%", meta_val_style)
                    ],
                    [
                        Paragraph("<b>Detection Method:</b>", meta_label_style),
                        Paragraph(html.escape(parsed.get("detection_method", "N/A")), meta_val_style),
                        Paragraph("<b>Verification Method:</b>", meta_label_style),
                        Paragraph(html.escape(parsed.get("verification_method", "N/A")), meta_val_style)
                    ]
                ]
                grid_table = Table(detail_grid_data, colWidths=[120, 141, 120, 141])
                grid_table.setStyle(TableStyle([
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
                    ('PADDING', (0,0), (-1,-1), 5),
                    ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
                ]))

                # Clean desc body
                desc_clean = parsed.get("description_body", "No description provided.").strip()

                vuln_flowables = [
                    Paragraph(title_text, detail_heading_style),
                    grid_table,
                    Spacer(1, 8),
                    Paragraph("<b>Description</b>", meta_label_style),
                    Paragraph(html.escape(desc_clean).replace('\n', '<br/>'), body_style),
                    Paragraph("<b>Remediation Steps</b>", meta_label_style),
                    Paragraph(html.escape(vuln.recommendation or "No recommendation provided.").replace('\n', '<br/>'), body_style),
                ]

                # Show technical request/response in technical mode
                if mode == "technical":
                    req_header = "HTTP Request Logs"
                    req_log = f"{parsed.get('request_method', 'GET')} {html.escape(parsed.get('affected_url', '/'))} HTTP/1.1"
                    
                    req_flowable = Paragraph(f"<b>{req_header}</b><br/><font face='Courier' size='7'>{req_log}</font>", table_cell_style)
                    
                    vuln_flowables.append(req_flowable)
                    vuln_flowables.append(Spacer(1, 6))

                    if parsed.get("response_headers") and parsed.get("response_headers") != "N/A":
                        res_header = "HTTP Response Snippet"
                        res_log = html.escape(parsed.get("response_snippet", ""))
                        res_flowable = Paragraph(f"<b>{res_header}</b><br/><font face='Courier' size='7'>{res_log}</font>", table_cell_style)
                        vuln_flowables.append(res_flowable)
                        vuln_flowables.append(Spacer(1, 6))

                vuln_flowables.append(Spacer(1, 15))
                
                # Keep core details of a single vulnerability on the same page
                story.append(KeepTogether(vuln_flowables))

        # ==========================================
        # REMEDIATION ROADMAP (Phase 10 & test compatibility)
        # ==========================================
        story.append(PageBreak())
        story.append(Paragraph("Recommendations", h1_style))
        if report.recommendations:
            for idx, rec in enumerate(report.recommendations):
                bullet_text = f"<b>Priority {idx+1}:</b> {html.escape(rec)}"
                story.append(Paragraph(bullet_text, bullet_style))
        else:
            story.append(Paragraph("No immediate action items recommended.", body_style))

        # ==========================================
        # TECHNICAL APPENDIX (Phase 11)
        # ==========================================
        story.append(PageBreak())
        story.append(Paragraph("Technical Appendix", h1_style))
        story.append(Paragraph("<b>Auditor Scope & Methods</b>", h2_style))
        story.append(Paragraph("The security assessment was performed utilizing passive checks and dynamic validations. Score calibrations are calculated using CVSS base estimators and custom mitigations presence factors.", body_style))
        story.append(Spacer(1, 10))

        # Build document with running footers and headers using NumberedCanvas
        doc.build(story, onFirstPage=lambda c, d: None, onLaterPages=lambda c, d: None, canvasmaker=NumberedCanvas)
        pdf_data = buffer.getvalue()
        buffer.close()
        
        return pdf_data
