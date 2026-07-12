from sqlalchemy.orm import Session
from sqlalchemy import select, func, desc
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.models.report import Report
from typing import List, Dict, Any, Optional

class DashboardService:
    @staticmethod
    def get_overview(db: Session, user_id: int) -> Dict[str, Any]:
        # Count scans by status
        scan_status_stmt = (
            select(Scan.status, func.count(Scan.id))
            .where(Scan.user_id == user_id)
            .group_by(Scan.status)
        )
        status_counts = dict(db.execute(scan_status_stmt).all())
        
        total_scans = sum(status_counts.values())
        completed_scans = status_counts.get("completed", 0)
        running_scans = status_counts.get("running", 0)
        failed_scans = status_counts.get("failed", 0)

        # Count reports
        total_reports_stmt = (
            select(func.count(Report.id))
            .join(Scan, Scan.id == Report.scan_db_id)
            .where(Scan.user_id == user_id)
        )
        total_reports = db.execute(total_reports_stmt).scalar() or 0

        # Count vulnerabilities by severity
        vuln_severity_stmt = (
            select(Vulnerability.severity, func.count(Vulnerability.id))
            .join(Scan, Scan.id == Vulnerability.scan_id)
            .where(Scan.user_id == user_id)
            .group_by(Vulnerability.severity)
        )
        severity_results = db.execute(vuln_severity_stmt).all()

        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0
        }
        total_vulnerabilities = 0
        for sev, count in severity_results:
            if sev:
                sev_lower = sev.lower()
                if sev_lower in severity_counts:
                    severity_counts[sev_lower] += count
                else:
                    severity_counts["informational"] += count
                total_vulnerabilities += count

        # Average risk score
        avg_score_stmt = (
            select(func.avg(Report.risk_score))
            .join(Scan, Scan.id == Report.scan_db_id)
            .where(Scan.user_id == user_id)
        )
        avg_score = db.execute(avg_score_stmt).scalar()
        average_risk_score = float(avg_score) if avg_score is not None else 0.0

        # Latest grade
        latest_grade_stmt = (
            select(Report.grade)
            .join(Scan, Scan.id == Report.scan_db_id)
            .where(Scan.user_id == user_id)
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
        latest_grade = db.execute(latest_grade_stmt).scalar()

        return {
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "running_scans": running_scans,
            "failed_scans": failed_scans,
            "total_reports": total_reports,
            "total_vulnerabilities": total_vulnerabilities,
            "critical_findings": severity_counts["critical"],
            "high_findings": severity_counts["high"],
            "medium_findings": severity_counts["medium"],
            "low_findings": severity_counts["low"],
            "informational_findings": severity_counts["informational"],
            "average_risk_score": average_risk_score,
            "latest_grade": latest_grade
        }

    @staticmethod
    def get_recent_scans(db: Session, user_id: int, limit: int = 10) -> List[Dict[str, Any]]:
        stmt = (
            select(
                Scan.scan_id,
                Scan.target,
                Scan.scan_type,
                Scan.status,
                Report.risk_score,
                Report.grade,
                Scan.created_at
            )
            .outerjoin(Report, Scan.id == Report.scan_db_id)
            .where(Scan.user_id == user_id)
            .order_by(Scan.created_at.desc())
            .limit(limit)
        )
        results = db.execute(stmt).all()
        return [
            {
                "scan_id": r.scan_id,
                "target": r.target,
                "scan_type": r.scan_type,
                "status": r.status,
                "risk_score": r.risk_score,
                "grade": r.grade,
                "created_at": r.created_at
            }
            for r in results
        ]

    @staticmethod
    def get_risk_distribution(db: Session, user_id: int) -> Dict[str, int]:
        vuln_severity_stmt = (
            select(Vulnerability.severity, func.count(Vulnerability.id))
            .join(Scan, Scan.id == Vulnerability.scan_id)
            .where(Scan.user_id == user_id)
            .group_by(Vulnerability.severity)
        )
        severity_results = db.execute(vuln_severity_stmt).all()

        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0
        }
        for sev, count in severity_results:
            if sev:
                sev_lower = sev.lower()
                if sev_lower in severity_counts:
                    severity_counts[sev_lower] += count
                else:
                    severity_counts["informational"] += count
        total = sum(severity_counts.values())
        severity_counts["total"] = total
        return severity_counts

    @staticmethod
    def get_top_vulnerabilities(db: Session, user_id: int, limit: int = 10) -> List[Dict[str, Any]]:
        stmt = (
            select(
                Vulnerability.title,
                Vulnerability.severity,
                func.count(Vulnerability.id).label("count")
            )
            .join(Scan, Scan.id == Vulnerability.scan_id)
            .where(Scan.user_id == user_id)
            .group_by(Vulnerability.title, Vulnerability.severity)
            .order_by(desc("count"))
            .limit(limit)
        )
        results = db.execute(stmt).all()
        return [
            {
                "title": r.title,
                "severity": r.severity,
                "count": r.count
            }
            for r in results
        ]

    @staticmethod
    def get_history(db: Session, user_id: int) -> List[Dict[str, Any]]:
        stmt = (
            select(
                Scan.scan_id,
                Scan.target,
                Scan.status,
                Report.risk_score,
                Report.grade,
                Scan.created_at
            )
            .outerjoin(Report, Scan.id == Report.scan_db_id)
            .where(Scan.user_id == user_id)
            .order_by(Scan.created_at.desc())
        )
        results = db.execute(stmt).all()
        return [
            {
                "scan_id": r.scan_id,
                "target": r.target,
                "status": r.status,
                "risk_score": r.risk_score,
                "grade": r.grade,
                "created_at": r.created_at
            }
            for r in results
        ]

    @staticmethod
    def get_statistics(db: Session, user_id: int) -> Dict[str, Any]:
        # Average, highest, lowest risk scores
        stats_stmt = (
            select(
                func.avg(Report.risk_score).label("avg_score"),
                func.max(Report.risk_score).label("max_score"),
                func.min(Report.risk_score).label("min_score"),
                func.count(Report.id).label("total_reports")
            )
            .join(Scan, Scan.id == Report.scan_db_id)
            .where(Scan.user_id == user_id)
        )
        stats = db.execute(stats_stmt).first()

        total_reports = stats.total_reports if stats and stats.total_reports is not None else 0
        if total_reports > 0:
            average_risk_score = float(stats.avg_score)
            highest_risk_score = float(stats.max_score)
            lowest_risk_score = float(stats.min_score)
        else:
            average_risk_score = 0.0
            highest_risk_score = 0.0
            lowest_risk_score = 0.0

        # Total scans
        total_scans_stmt = select(func.count(Scan.id)).where(Scan.user_id == user_id)
        total_scans = db.execute(total_scans_stmt).scalar() or 0

        # Total findings
        total_findings_stmt = (
            select(func.count(Vulnerability.id))
            .join(Scan, Scan.id == Vulnerability.scan_id)
            .where(Scan.user_id == user_id)
        )
        total_findings = db.execute(total_findings_stmt).scalar() or 0

        average_findings_per_scan = float(total_findings) / float(total_scans) if total_scans > 0 else 0.0

        return {
            "average_risk_score": average_risk_score,
            "highest_risk_score": highest_risk_score,
            "lowest_risk_score": lowest_risk_score,
            "average_findings_per_scan": average_findings_per_scan,
            "total_reports": total_reports
        }

    @staticmethod
    def get_trends(db: Session, user_id: int) -> List[Dict[str, Any]]:
        stmt = (
            select(
                func.date(Report.completed_at).label("date"),
                func.avg(Report.risk_score).label("risk_score")
            )
            .join(Scan, Scan.id == Report.scan_db_id)
            .where(Scan.user_id == user_id)
            .group_by(func.date(Report.completed_at))
            .order_by(func.date(Report.completed_at).asc())
        )
        results = db.execute(stmt).all()
        trends = []
        for r in results:
            if r.date:
                date_str = r.date if isinstance(r.date, str) else r.date.strftime("%Y-%m-%d")
                trends.append({
                    "date": date_str,
                    "risk_score": float(r.risk_score) if r.risk_score is not None else 0.0
                })
        return trends
