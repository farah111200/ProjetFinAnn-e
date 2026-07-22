import enum
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Text, Enum, Boolean, Float
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    USER = "user"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    organization = Column(String, nullable=True)
    role = Column(Enum(UserRole), default=UserRole.USER, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scans = relationship("Scan", back_populates="owner")
    scheduled_scans = relationship("ScheduledScan", back_populates="owner")
    audit_logs = relationship("AuditLog", back_populates="user")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    url = Column(String, nullable=False)
    status = Column(String, default="pending")  # pending, running, done, failed
    current_step = Column(String, default="En attente")
    scanner = Column(String, default="zap")
    raw_output = Column(Text, nullable=True)  # findings bruts (JSON), pour l'onglet "Résultats bruts"
    date = Column(DateTime(timezone=True), server_default=func.now())
    finished_at = Column(DateTime(timezone=True), nullable=True)

    owner = relationship("User", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    name = Column(String, nullable=False)
    severity = Column(String, nullable=False)  # low, medium, high, critical
    description = Column(Text)
    solution = Column(Text)
    source_tool = Column(String, nullable=True)  # nmap, nuclei, zap
    cve_id = Column(String, nullable=True)  # ex: CVE-2024-6387, si identifié
    cwe_id = Column(String, nullable=True)  # ex: CWE-693, classification ZAP (config/bonnes pratiques)
    cvss_score = Column(Float, nullable=True)  # ex: 9.8, si trouvé via NVD
    detected_at = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="vulnerabilities")


class ScheduledScan(Base):
    """Définit un scan récurrent, exécuté automatiquement par APScheduler."""
    __tablename__ = "scheduled_scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    target = Column(String, nullable=False)
    frequency = Column(String, nullable=False)  # once, daily, weekly
    scheduled_at = Column(DateTime(timezone=True), nullable=True)  # date/heure exacte (obligatoire si "once", sinon = heure de départ des répétitions)
    scanner = Column(String, default="zap")
    is_active = Column(Boolean, default=True, nullable=False)
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    next_run_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    owner = relationship("User", back_populates="scheduled_scans")


class AuditLog(Base):
    """Journal d'audit : trace toute action sensible (connexion, scan lancé, etc.)."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String, nullable=False)  # ex: "scan_created", "login", "scan_deleted"
    details = Column(Text, nullable=True)
    ip_address = Column(String, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="audit_logs")
