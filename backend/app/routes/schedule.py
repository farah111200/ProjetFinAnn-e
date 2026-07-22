from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, timezone

from app.database import get_db
from app.models import ScheduledScan, User, UserRole
from app.schemas import ScheduledScanCreate, ScheduledScanOut
from app.dependencies import get_current_user
from app.services.scheduler import schedule_recurring_scan, unschedule_scan, scheduler
from app.services.audit import log_action

router = APIRouter(prefix="/schedule", tags=["schedule"])

VALID_FREQUENCIES = {"once", "daily", "weekly"}


@router.post("", response_model=ScheduledScanOut, status_code=201)
def create_scheduled_scan(
    payload: ScheduledScanCreate, db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if payload.frequency not in VALID_FREQUENCIES:
        raise HTTPException(status_code=400, detail="frequency doit être 'once', 'daily' ou 'weekly'.")

    if payload.frequency == "once":
        if payload.scheduled_at is None:
            raise HTTPException(status_code=400, detail="scheduled_at (date et heure) est obligatoire pour une planification unique.")
        target_time = payload.scheduled_at
        if target_time.tzinfo is None:
            target_time = target_time.replace(tzinfo=timezone.utc)
        if target_time <= datetime.now(timezone.utc):
            raise HTTPException(status_code=400, detail="La date/heure choisie doit être dans le futur.")

    scheduled = ScheduledScan(
        user_id=current_user.id,
        target=payload.target,
        frequency=payload.frequency,
        scheduled_at=payload.scheduled_at,
        scanner=payload.scanner,
    )
    db.add(scheduled)
    db.commit()
    db.refresh(scheduled)

    schedule_recurring_scan(scheduled.id, scheduled.frequency, scheduled.scheduled_at)

    job = scheduler.get_job(f"scheduled_scan_{scheduled.id}")
    scheduled.next_run_at = job.next_run_time if job else None
    db.commit()
    db.refresh(scheduled)

    log_action(
        db, action="schedule_created", user_id=current_user.id,
        details=f"target={payload.target} frequency={payload.frequency}",
    )
    return scheduled


@router.get("", response_model=List[ScheduledScanOut])
def list_scheduled_scans(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = db.query(ScheduledScan)
    if current_user.role != UserRole.ADMIN:
        query = query.filter(ScheduledScan.user_id == current_user.id)
    return query.order_by(ScheduledScan.created_at.desc()).all()


@router.delete("/{scheduled_id}", status_code=204)
def cancel_scheduled_scan(
    scheduled_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scheduled = db.query(ScheduledScan).filter(ScheduledScan.id == scheduled_id).first()
    if scheduled is None:
        raise HTTPException(status_code=404, detail="Planification introuvable.")
    if current_user.role != UserRole.ADMIN and scheduled.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Accès refusé.")

    unschedule_scan(scheduled.id)
    db.delete(scheduled)
    log_action(db, action="schedule_cancelled", user_id=current_user.id, details=f"scheduled_id={scheduled_id}")
    db.commit()
