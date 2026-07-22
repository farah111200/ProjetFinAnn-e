import json
import logging
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request, Response
from app.services.pdf_report import generate_scan_report_pdf
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db
from app.models import Scan, Vulnerability, User, UserRole
from app.schemas import ScanCreate, ScanOut, ScanDetailOut
from app.dependencies import get_current_user
from app.services.scanner import run_scan
from app.services.ai_analysis import analyze_findings, normalize_severity
from app.services.cve_lookup import enrich_with_cve
from app.services.audit import log_action

logger = logging.getLogger("scans")
router = APIRouter(prefix="/scans", tags=["scans"])


def _execute_scan_background(scan_id: int, scanner: str, target: str) -> None:
    """Tourne dans un BackgroundTask FastAPI : suffisant pour ce projet
    (pas besoin de Celery/Redis pour un volume de scans étudiant)."""
    from app.database import SessionLocal

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan is None:
            return

        logger.info(f"[scan #{scan_id}] Démarrage — cible={target} outil={scanner}")
        scan.current_step = f"Scan en cours ({scanner})"
        db.commit()

        findings = run_scan(scanner, target)
        logger.info(f"[scan #{scan_id}] {scanner} terminé — {len(findings)} finding(s) brut(s)")
        scan.raw_output = json.dumps(findings, ensure_ascii=False)
        db.commit()

        scan.current_step = "Analyse par l'IA"
        db.commit()
        logger.info(f"[scan #{scan_id}] Envoi des findings à l'IA...")

        vulnerabilities = analyze_findings(findings)
        vulnerabilities = enrich_with_cve(findings, vulnerabilities)
        logger.info(f"[scan #{scan_id}] Analyse IA terminée — {len(vulnerabilities)} vulnérabilité(s) identifiée(s)")

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

        scan.status = "done" if vulnerabilities or not findings else "failed"
        scan.current_step = "Terminé" if scan.status == "done" else "Échec du scan"
        scan.finished_at = datetime.utcnow()
        db.commit()
        logger.info(f"[scan #{scan_id}] Statut final : {scan.status}")
    except Exception as e:
        logger.error(f"[scan #{scan_id}] Erreur inattendue : {e}")
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "failed"
            scan.current_step = "Échec du scan"
            scan.finished_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


@router.post("", response_model=ScanOut, status_code=201)
def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = Scan(user_id=current_user.id, url=payload.url, scanner=payload.scanner, status="running", current_step="Initialisation")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(_execute_scan_background, scan.id, payload.scanner, payload.url)

    log_action(
        db, action="scan_created", user_id=current_user.id,
        details=f"target={payload.url} scanner={payload.scanner}",
        ip_address=request.client.host if request.client else None,
    )
    return scan


@router.get("/vulnerabilities", response_model=List[dict])
def list_all_vulnerabilities(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Liste toutes les vulnérabilités trouvées, tous scans confondus (avec RBAC :
    un utilisateur standard ne voit que celles de ses propres scans)."""
    query = db.query(Vulnerability).join(Scan)
    if current_user.role != UserRole.ADMIN:
        query = query.filter(Scan.user_id == current_user.id)

    results = []
    for v in query.order_by(Vulnerability.detected_at.desc()).limit(200).all():
        results.append({
            "id": v.id,
            "name": v.name,
            "severity": v.severity,
            "description": v.description,
            "solution": v.solution,
            "source_tool": v.source_tool,
            "cve_id": v.cve_id,
            "cwe_id": v.cwe_id,
            "cvss_score": v.cvss_score,
            "detected_at": v.detected_at.isoformat() if v.detected_at else None,
            "scan_id": v.scan_id,
            "scan_target": v.scan.url,
        })
    return results


@router.get("", response_model=List[ScanOut])
def list_scans(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """RBAC : un admin voit tous les scans, un utilisateur standard ne voit que les siens."""
    query = db.query(Scan)
    if current_user.role != UserRole.ADMIN:
        query = query.filter(Scan.user_id == current_user.id)
    return query.order_by(Scan.date.desc()).all()


@router.get("/{scan_id}", response_model=ScanDetailOut)
def get_scan(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan introuvable.")
    if current_user.role != UserRole.ADMIN and scan.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Vous n'avez pas accès à ce scan.")
    return scan


@router.get("/{scan_id}/report")
def download_scan_report(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan introuvable.")
    if current_user.role != UserRole.ADMIN and scan.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Vous n'avez pas accès à ce scan.")
    if scan.status == "running":
        raise HTTPException(status_code=400, detail="Le scan est encore en cours — attends qu'il se termine pour générer le rapport.")

    pdf_bytes = generate_scan_report_pdf(scan, scan.vulnerabilities)
    filename = f"rapport_scan_{scan.id}.pdf"

    log_action(db, action="report_downloaded", user_id=current_user.id, details=f"scan_id={scan_id}")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.delete("/{scan_id}", status_code=204)
def delete_scan(
    scan_id: int, request: Request, db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan introuvable.")
    if current_user.role != UserRole.ADMIN and scan.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Vous n'avez pas accès à ce scan.")

    db.delete(scan)
    log_action(
        db, action="scan_deleted", user_id=current_user.id, details=f"scan_id={scan_id}",
        ip_address=request.client.host if request.client else None,
    )
    db.commit()
