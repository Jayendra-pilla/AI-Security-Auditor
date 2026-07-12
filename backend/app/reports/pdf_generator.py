import io
from datetime import datetime, timezone
import html
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from app.models.scan import Scan
from app.models.report import Report

class PDFReportGenerator:
    """
    PDF generator class for compiling final PDF auditor reports.
    """

    @staticmethod
    def generate(scan: Scan, report: Report) -> bytes:
        """
        Generates a professional, branded executive summary PDF.
        """
        buffer = io.BytesIO()
        
        # Page size is letter (8.5 x 11 inches)
        # 54 points = 0.75 inch margins
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=54,
            leftMargin=54,
            topMargin=54,
            bottomMargin=54
        )
        
        styles = getSampleStyleSheet()
        
        # Define custom professional styles
        title_style = ParagraphStyle(
            'CoverTitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=28,
            leading=34,
            textColor=colors.HexColor('#1e293b'),
            spaceAfter=10
        )
        
        subtitle_style = ParagraphStyle(
            'CoverSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=14,
            leading=18,
            textColor=colors.HexColor('#475569'),
            spaceAfter=40
        )
        
        h1_style = ParagraphStyle(
            'Heading1Custom',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=18,
            leading=22,
            textColor=colors.HexColor('#1e293b'),
            spaceBefore=15,
            spaceAfter=10,
            keepWithNext=True
        )

        body_style = ParagraphStyle(
            'BodyCustom',
            parent=styles['BodyText'],
            fontName='Helvetica',
            fontSize=10,
            leading=14,
            textColor=colors.HexColor('#334155'),
            spaceAfter=12
        )

        meta_label_style = ParagraphStyle(
            'MetaLabel',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=10,
            leading=12,
            textColor=colors.HexColor('#1e293b')
        )

        meta_val_style = ParagraphStyle(
            'MetaVal',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            leading=12,
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
            fontSize=9,
            leading=12,
            textColor=colors.HexColor('#334155')
        )

        bullet_style = ParagraphStyle(
            'BulletCustom',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            leading=14,
            textColor=colors.HexColor('#334155'),
            leftIndent=20,
            firstLineIndent=-10,
            spaceAfter=6
        )

        story = []

        # ==========================================
        # COVER PAGE
        # ==========================================
        story.append(Spacer(1, 40))
        
        # Header accent bar
        story.append(Table(
            [['']], 
            colWidths=[504], 
            rowHeights=[6], 
            style=TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#1e293b')),
                ('BOTTOMPADDING', (0,0), (-1,-1), 0),
                ('TOPPADDING', (0,0), (-1,-1), 0),
            ])
        ))
        story.append(Spacer(1, 20))
        
        story.append(Paragraph("AI Security Audit Report", title_style))
        story.append(Paragraph("Automated Vulnerability & Risk Assessment", subtitle_style))
        
        story.append(Spacer(1, 30))

        # Metadata table
        scan_date_str = scan.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        meta_data = [
            [Paragraph("Target URL", meta_label_style), Paragraph(html.escape(scan.target), meta_val_style)],
            [Paragraph("Scan ID", meta_label_style), Paragraph(html.escape(scan.scan_id), meta_val_style)],
            [Paragraph("Scan Date", meta_label_style), Paragraph(html.escape(scan_date_str), meta_val_style)],
            [Paragraph("Status", meta_label_style), Paragraph(html.escape(scan.status.capitalize()), meta_val_style)],
        ]
        meta_table = Table(meta_data, colWidths=[120, 384])
        meta_table.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#f8fafc')),
        ]))
        story.append(meta_table)

        story.append(Spacer(1, 40))

        # Score box card on Cover page
        risk_color = colors.HexColor('#22c55e') # Green
        if report.risk_score >= 75:
            risk_color = colors.HexColor('#ef4444') # Red
        elif report.risk_score >= 40:
            risk_color = colors.HexColor('#f97316') # Orange
        elif report.risk_score >= 20:
            risk_color = colors.HexColor('#eab308') # Yellow

        score_title_style = ParagraphStyle(
            'ScoreTitle', fontName='Helvetica-Bold', fontSize=12, textColor=colors.white, alignment=1
        )
        score_val_style = ParagraphStyle(
            'ScoreVal', fontName='Helvetica-Bold', fontSize=32, textColor=colors.white, alignment=1
        )
        grade_title_style = ParagraphStyle(
            'GradeTitle', fontName='Helvetica-Bold', fontSize=12, textColor=colors.white, alignment=1
        )
        grade_val_style = ParagraphStyle(
            'GradeVal', fontName='Helvetica-Bold', fontSize=36, textColor=colors.white, alignment=1
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
        score_table = Table(score_card_data, colWidths=[252, 252])
        score_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), risk_color),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 15),
            ('TOPPADDING', (0,0), (-1,-1), 15),
        ]))
        story.append(score_table)

        story.append(PageBreak())

        # ==========================================
        # BODY PAGES
        # ==========================================
        
        # 1. Executive Summary
        story.append(Paragraph("Executive Summary", h1_style))
        story.append(Paragraph(html.escape(report.summary), body_style))
        story.append(Spacer(1, 10))

        # 2. Severity Statistics
        story.append(Paragraph("Severity Statistics", h1_style))
        stats = report.statistics or {}
        stat_headers = ["Total Scanned", "Critical", "High", "Medium", "Low", "Info"]
        stat_values = [
            str(len(scan.vulnerabilities)),
            str(stats.get("critical", 0)),
            str(stats.get("high", 0)),
            str(stats.get("medium", 0)),
            str(stats.get("low", 0)),
            str(stats.get("informational", 0))
        ]
        
        stats_table_data = [
            [Paragraph(html.escape(h), meta_label_style) for h in stat_headers],
            [Paragraph(html.escape(v), meta_val_style) for v in stat_values]
        ]
        stats_table = Table(stats_table_data, colWidths=[84]*6)
        stats_table.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 8),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f8fafc')),
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 15))

        # 3. Vulnerability Details
        story.append(Paragraph("Vulnerability Details", h1_style))
        
        if scan.vulnerabilities:
            vuln_headers = ["Severity", "Title / Description", "Remediation"]
            vuln_table_data = [
                [Paragraph(vh, table_header_style) for vh in vuln_headers]
            ]
            
            for vuln in scan.vulnerabilities:
                sev = vuln.severity.upper()
                sev_color = '#06b6d4' # Info
                if vuln.severity.lower() == 'critical':
                    sev_color = '#ef4444'
                elif vuln.severity.lower() == 'high':
                    sev_color = '#f97316'
                elif vuln.severity.lower() == 'medium':
                    sev_color = '#eab308'
                elif vuln.severity.lower() == 'low':
                    sev_color = '#22c55e'
                
                sev_cell_style = ParagraphStyle(
                    'SevCell',
                    parent=table_cell_style,
                    fontName='Helvetica-Bold',
                    textColor=colors.HexColor(sev_color)
                )
                
                title_desc = f"<b>{html.escape(vuln.title)}</b><br/><br/>{html.escape(vuln.description)}"
                
                row = [
                    Paragraph(html.escape(sev), sev_cell_style),
                    Paragraph(title_desc, table_cell_style),
                    Paragraph(html.escape(vuln.recommendation), table_cell_style)
                ]
                vuln_table_data.append(row)
                
            # Total width = 504 (letter width 612 - 108 margin)
            vuln_table = Table(vuln_table_data, colWidths=[80, 212, 212])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('PADDING', (0,0), (-1,-1), 8),
            ]))
            story.append(vuln_table)
        else:
            story.append(Paragraph("No vulnerabilities were identified during this security scan.", body_style))
            
        story.append(Spacer(1, 15))

        # 4. Actionable Recommendations
        story.append(Paragraph("Recommendations", h1_style))
        if report.recommendations:
            for rec in report.recommendations:
                bullet_text = f"&bull;&nbsp;&nbsp;{html.escape(rec)}"
                story.append(Paragraph(bullet_text, bullet_style))
        else:
            story.append(Paragraph("No immediate action items recommended.", body_style))

        # Build document with header and footer on later pages
        def on_later_pages(canvas, doc):
            # Draw header
            canvas.saveState()
            canvas.setFont('Helvetica-Bold', 8)
            canvas.setFillColor(colors.HexColor('#475569'))
            canvas.drawString(54, doc.pagesize[1] - 30, "AI SECURITY AUDITOR REPORT")
            canvas.drawRightString(doc.pagesize[0] - 54, doc.pagesize[1] - 30, "CONFIDENTIAL")
            
            # Header line
            canvas.setStrokeColor(colors.HexColor('#e2e8f0'))
            canvas.setLineWidth(0.75)
            canvas.line(54, doc.pagesize[1] - 35, doc.pagesize[0] - 54, doc.pagesize[1] - 35)
            
            # Draw footer
            canvas.setFont('Helvetica', 8)
            canvas.drawString(54, 30, f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
            canvas.drawRightString(doc.pagesize[0] - 54, 30, f"Page {canvas.getPageNumber()}")
            
            # Footer line
            canvas.line(54, 42, doc.pagesize[0] - 54, 42)
            canvas.restoreState()

        doc.build(story, onFirstPage=lambda c, d: None, onLaterPages=on_later_pages)
        pdf_data = buffer.getvalue()
        buffer.close()
        
        return pdf_data

