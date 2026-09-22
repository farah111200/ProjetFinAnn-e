"""Planificateur de scans récurrents. Utilise APScheduler avec un jobstore
SQLAlchemy (même base Postgres que le reste de l'app) pour que les tâches
programmées survivent à un redémarrage du conteneur — pas besoin de Redis."""
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from app.core.config import settings
from app.database import SessionLocal
from app.models import Scan, ScheduledScan
from app.services.scanner import run_scan
from app.services.ai_analysis import analyze_findings, normalize_severity
from app.services.cve_lookup import enrich_with_cve
from app.services.audit import log_action
from app.models import Vulnerability, AttackSurfaceAsset
from datetime import datetime

jobstores = {"default": SQLAlchemyJobStore(url=settings.DATABASE_URL)}
scheduler = BackgroundScheduler(jobstores=jobstores, timezone="UTC")


def execute_scheduled_scan(scheduled_scan_id: int) -> None:
    """Exécuté par APScheduler à chaque déclenchement. Crée un nouveau Scan,
    lance l'outil, analyse les résultats avec l'IA, et journalise l'action."""
    db = SessionLocal()
    try:
        scheduled = db.query(ScheduledScan).filter(ScheduledScan.id == scheduled_scan_id).first()
        if scheduled is None or not scheduled.is_active:
            return

        scan = Scan(
            user_id=scheduled.user_id,
            url=scheduled.target,
            scanner=scheduled.scanner,
            status="running",
            current_step=f"Scan en cours ({scheduled.scanner})",
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        findings = run_scan(scheduled.scanner, scheduled.target)

        if scheduled.scanner == "recon":
            # Même logique que pour un scan lancé manuellement : inventaire
            # d'actifs stocké directement, pas d'analyse IA.
            assets = [f for f in findings if "error" not in f]
            for asset in assets:
                db.add(AttackSurfaceAsset(
                    scan_id=scan.id,
                    subdomain=asset.get("subdomain") or scheduled.target,
                    url=asset.get("url"),
                    ip_address=asset.get("ip_address"),
                    http_status=asset.get("http_status"),
                    title=asset.get("title"),
                    technologies=asset.get("technologies"),
                    source_tool=asset.get("source_tool", "recon"),
                ))
            scan.status = "done" if assets or not findings else "failed"
            scan.current_step = "Terminé" if scan.status == "done" else "Échec du scan"
        else:
            scan.current_step = "Analyse par l'IA"
            db.commit()

            vulnerabilities = analyze_findings(findings)
            vulnerabilities = enrich_with_cve(findings, vulnerabilities)

            for vuln in vulnerabilities:
                db.add(Vulnerability(
                    scan_id=scan.id,
                    name=vuln.get("name", "Vulnérabilité"),
                    severity=normalize_severity(vuln.get("severity", "medium")),
                    description=vuln.get("description"),
                    solution=vuln.get("solution"),
                    source_tool=vuln.get("source_tool"),
                    cve_id=vuln.get("cve_id"),
                    cwe_id=vuln.get("cwe_id"),
                    cvss_score=vuln.get("cvss_score"),
                ))
            scan.status = "done"
            scan.current_step = "Terminé"

        scan.finished_at = datetime.utcnow()
        scheduled.last_run_at = datetime.utcnow()

        # Un scan "once" ne se redéclenche jamais après son unique exécution
        if scheduled.frequency == "once":
            scheduled.is_active = False
            scheduled.next_run_at = None
        else:
            job = scheduler.get_job(f"scheduled_scan_{scheduled_scan_id}")
            scheduled.next_run_at = job.next_run_time if job else None

        db.commit()

        log_action(
            db, action="scheduled_scan_executed", user_id=scheduled.user_id,
            details=f"Scan automatique #{scan.id} sur {scheduled.target}",
        )
    finally:
        db.close()


def schedule_recurring_scan(scheduled_scan_id: int, frequency: str, scheduled_at: datetime = None) -> None:
    """Ajoute (ou remplace) une tâche APScheduler pour un ScheduledScan donné.

    - "once"   : se déclenche une seule fois, exactement à `scheduled_at`
    - "daily"/"weekly" : se répète à l'intervalle choisi, en démarrant à
      `scheduled_at` si fourni (sinon tout de suite, comme avant)
    """
    job_id = f"scheduled_scan_{scheduled_scan_id}"

    if frequency == "once":
        if scheduled_at is None:
            raise ValueError("scheduled_at est obligatoire pour une planification 'once'.")
        scheduler.add_job(
            execute_scheduled_scan,
            "date",
            run_date=scheduled_at,
            id=job_id,
            replace_existing=True,
            args=[scheduled_scan_id],
        )
        return

    trigger_kwargs = {"hours": 24} if frequency == "daily" else {"weeks": 1}
    if scheduled_at is not None:
        trigger_kwargs["start_date"] = scheduled_at

    scheduler.add_job(
        execute_scheduled_scan,
        "interval",
        id=job_id,
        replace_existing=True,
        args=[scheduled_scan_id],
        **trigger_kwargs,
    )


def unschedule_scan(scheduled_scan_id: int) -> None:
    job_id = f"scheduled_scan_{scheduled_scan_id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)


def start_scheduler() -> None:
    if not scheduler.running:
        scheduler.start()
