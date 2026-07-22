from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from collections import Counter

from app.database import get_db
from app.models import Scan, Vulnerability, User, UserRole
from app.schemas import DashboardStats, SeverityBreakdown
from app.dependencies import get_current_user

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("/public")
def public_stats(db: Session = Depends(get_db)):
    """Statistiques globales agrégées, sans authentification — utilisées sur la
    page de connexion. Ne renvoie que des compteurs, aucune donnée personnelle
    ou détail de scan."""
    total_scans = db.query(Scan).count()
    total_vulns = db.query(Vulnerability).count()
    critical_vulns = db.query(Vulnerability).filter(Vulnerability.severity == "critical").count()
    done_scans = db.query(Scan).filter(Scan.status == "done").count()
    success_rate = round((done_scans / total_scans) * 100) if total_scans else 0

    return {
        "total_scans": total_scans,
        "critical_vulnerabilities": critical_vulns,
        "success_rate": success_rate,
    }


@router.get("/dashboard", response_model=DashboardStats)
def dashboard_stats(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Agrège les données nécessaires aux graphiques du tableau de bord.
    Respecte le même RBAC que les scans : un utilisateur standard ne voit
    que ses propres statistiques."""
    scan_query = db.query(Scan)
    vuln_query = db.query(Vulnerability).join(Scan)

    if current_user.role != UserRole.ADMIN:
        scan_query = scan_query.filter(Scan.user_id == current_user.id)
        vuln_query = vuln_query.filter(Scan.user_id == current_user.id)

    scans = scan_query.all()
    vulnerabilities = vuln_query.all()

    severity_counts = Counter(v.severity for v in vulnerabilities)
    name_counts = Counter(v.name for v in vulnerabilities)

    scans_by_day = Counter(s.date.strftime("%Y-%m-%d") for s in scans if s.date)
    scans_over_time = [{"date": d, "count": c} for d, c in sorted(scans_by_day.items())]

    # Répartition des sévérités par jour, pour le graphique de tendance
    severity_by_day: dict = {}
    for v in vulnerabilities:
        if not v.detected_at:
            continue
        day = v.detected_at.strftime("%Y-%m-%d")
        severity_by_day.setdefault(day, {"critical": 0, "high": 0, "medium": 0, "low": 0})
        if v.severity in severity_by_day[day]:
            severity_by_day[day][v.severity] += 1
    vulnerabilities_over_time = [
        {"date": d, **counts} for d, counts in sorted(severity_by_day.items())
    ]

    return DashboardStats(
        total_scans=len(scans),
        scans_in_progress=len([s for s in scans if s.status == "running"]),
        total_vulnerabilities=len(vulnerabilities),
        severity_breakdown=SeverityBreakdown(
            critical=severity_counts.get("critical", 0),
            high=severity_counts.get("high", 0),
            medium=severity_counts.get("medium", 0),
            low=severity_counts.get("low", 0),
        ),
        top_vulnerability_types=[
            {"name": name, "count": count} for name, count in name_counts.most_common(5)
        ],
        scans_over_time=scans_over_time,
        vulnerabilities_over_time=vulnerabilities_over_time,
    )
