from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db
from app.models import AuditLog, User
from app.schemas import AuditLogOut
from app.dependencies import require_admin

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=List[AuditLogOut])
def list_audit_logs(
    limit: int = Query(default=100, le=500),
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Réservé aux admins : historique de toutes les actions sensibles
    (connexions, scans créés/supprimés, planifications, etc.)."""
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
