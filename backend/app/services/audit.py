from typing import Optional
from sqlalchemy.orm import Session
from app.models import AuditLog


def log_action(
    db: Session,
    action: str,
    user_id: Optional[int] = None,
    details: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> None:
    """Enregistre une entrée dans le journal d'audit. Ne lève jamais d'exception
    pour ne pas casser le flux principal si le logging échoue."""
    try:
        entry = AuditLog(user_id=user_id, action=action, details=details, ip_address=ip_address)
        db.add(entry)
        db.commit()
    except Exception:
        db.rollback()
