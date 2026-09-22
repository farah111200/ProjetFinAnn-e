import json
import logging
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request, Response
from app.services.pdf_report import generate_scan_report_pdf
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db
from app.models import Scan, Vulnerability, User, UserRole, AttackSurfaceAsset
from app.schemas import ScanCreate, ScanOut, ScanDetailOut, VulnerabilityOut, VulnerabilityStatusUpdate, ScanComparisonOut
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

        if scanner == "recon":
            # Inventaire d'actifs, pas un jugement de vulnérabilité — pas
            # besoin d'IA ici, on enregistre directement ce que httpx a vu.
            assets = [f for f in findings if "error" not in f]
            for asset in assets:
                db.add(AttackSurfaceAsset(
                    scan_id=scan.id,
                    subdomain=asset.get("subdomain") or target,
                    url=asset.get("url"),
                    ip_address=asset.get("ip_address"),
                    http_status=asset.get("http_status"),
                    title=asset.get("title"),
                    technologies=asset.get("technologies"),
                    source_tool=asset.get("source_tool", "recon"),
                ))
            scan.status = "done" if assets or not findings else "failed"
            scan.current_step = "Terminé" if scan.status == "done" else "Échec du scan"
            scan.finished_at = datetime.utcnow()
            db.commit()
            logger.info(f"[scan #{scan_id}] Statut final : {scan.status} — {len(assets)} actif(s) découvert(s)")
            return

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
            "status": v.status,
            "detected_at": v.detected_at.isoformat() if v.detected_at else None,
            "scan_id": v.scan_id,
            "scan_target": v.scan.url,
        })
    return results


@router.patch("/vulnerabilities/{vuln_id}/status", response_model=VulnerabilityOut)
def update_vulnerability_status(
    vuln_id: int, payload: VulnerabilityStatusUpdate, request: Request,
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user),
):
    """Triage : fait passer une vulnérabilité par un cycle de vie
    (ouverte -> en cours -> corrigée / faux positif), au lieu de la laisser
    comme une simple ligne figée issue du scan."""
    vuln = db.query(Vulnerability).join(Scan).filter(Vulnerability.id == vuln_id).first()
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnérabilité introuvable.")
    if current_user.role != UserRole.ADMIN and vuln.scan.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Vous n'avez pas accès à cette vulnérabilité.")

    previous_status = vuln.status
    vuln.status = payload.status
    db.commit()
    db.refresh(vuln)

    log_action(
        db, action="vulnerability_status_updated", user_id=current_user.id,
        details=f"vuln_id={vuln_id} {previous_status} -> {payload.status}",
        ip_address=request.client.host if request.client else None,
    )
    return vuln


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


def _vuln_key(v: Vulnerability) -> str:
    """Identifie une vulnérabilité de façon stable d'un scan à l'autre : le
    CVE si on en a un (le plus fiable), sinon le nom normalisé."""
    return f"cve:{v.cve_id}" if v.cve_id else f"name:{v.name.strip().lower()}"


def _security_score(vulns: List[Vulnerability]) -> int:
    """Score sur 100, formule documentée (pas de boîte noire) :
    on part de 100 et on retire un poids par sévérité. Plafonné à 0."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        if v.severity in counts:
            counts[v.severity] += 1
    penalty = counts["critical"] * 15 + counts["high"] * 8 + counts["medium"] * 3 + counts["low"] * 1
    return max(0, 100 - penalty)


@router.get("/{scan_id}/compare", response_model=ScanComparisonOut)
def compare_scan(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Compare ce scan avec le précédent scan terminé sur la même cible
    (même URL, même scanner) : nouvelles vulnérabilités, corrigées, et
    évolution du score de sécurité."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan introuvable.")
    if current_user.role != UserRole.ADMIN and scan.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Vous n'avez pas accès à ce scan.")

    previous_scan = (
        db.query(Scan)
        .filter(
            Scan.user_id == scan.user_id,
            Scan.url == scan.url,
            Scan.scanner == scan.scanner,
            Scan.status == "done",
            Scan.id != scan.id,
            Scan.date < scan.date,
        )
        .order_by(Scan.date.desc())
        .first()
    )

    current_score = _security_score(scan.vulnerabilities)

    if previous_scan is None:
        return ScanComparisonOut(
            current_scan_id=scan.id,
            current_score=current_score,
            new_vulnerabilities=scan.vulnerabilities,
        )

    previous_map = {_vuln_key(v): v for v in previous_scan.vulnerabilities}
    current_map = {_vuln_key(v): v for v in scan.vulnerabilities}

    new_vulns = [v for k, v in current_map.items() if k not in previous_map]
    resolved_vulns = [v for k, v in previous_map.items() if k not in current_map]
    still_open_count = sum(1 for k in current_map if k in previous_map)
    previous_score = _security_score(previous_scan.vulnerabilities)

    return ScanComparisonOut(
        current_scan_id=scan.id,
        previous_scan_id=previous_scan.id,
        previous_scan_date=previous_scan.date,
        current_score=current_score,
        previous_score=previous_score,
        score_delta=current_score - previous_score,
        new_vulnerabilities=new_vulns,
        resolved_vulnerabilities=resolved_vulns,
        still_open_count=still_open_count,
    )


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
