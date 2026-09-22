from datetime import datetime
from typing import Optional, List
import re
import ipaddress
from pydantic import BaseModel, EmailStr, ConfigDict, field_validator
from app.models import UserRole

# Domaine valide : ex. "example.com", "scanme.nmap.org", "sub.domain.co"
DOMAIN_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def validate_target(value: str) -> str:
    """Accepte une IPv4/IPv6 valide, un nom de domaine valide, ou une URL
    http(s) valide. Rejette tout le reste (texte arbitraire, IP mal formée...)."""
    candidate = value.strip()
    stripped = re.sub(r"^https?://", "", candidate).split("/")[0].split(":")[0]

    try:
        ipaddress.ip_address(stripped)
        return candidate
    except ValueError:
        pass

    if DOMAIN_PATTERN.match(stripped) or stripped == "localhost":
        return candidate

    raise ValueError(
        "Cible invalide : entre une adresse IP valide (ex: 192.168.56.10) "
        "ou un nom de domaine/URL valide (ex: example.com ou https://example.com)."
    )


VALID_SCANNERS = {"zap", "nuclei", "nmap", "recon"}


def validate_scanner(value: str) -> str:
    if value not in VALID_SCANNERS:
        raise ValueError(f"Scanner invalide. Options : {sorted(VALID_SCANNERS)}.")
    return value


def validate_password_strength(value: str) -> str:
    if len(value) < 8:
        raise ValueError("Le mot de passe doit contenir au moins 8 caractères.")
    if not re.search(r"[A-Za-z]", value):
        raise ValueError("Le mot de passe doit contenir au moins une lettre.")
    if not re.search(r"[0-9]", value):
        raise ValueError("Le mot de passe doit contenir au moins un chiffre.")
    return value


# ---------- Users / Auth ----------

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    organization: Optional[str] = None

    @field_validator("username")
    @classmethod
    def username_valid(cls, v: str) -> str:
        if len(v.strip()) < 3:
            raise ValueError("Le nom d'utilisateur doit contenir au moins 3 caractères.")
        return v.strip()

    @field_validator("password")
    @classmethod
    def password_valid(cls, v: str) -> str:
        return validate_password_strength(v)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: EmailStr
    organization: Optional[str] = None
    role: UserRole
    is_active: bool
    created_at: datetime


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    user_id: Optional[int] = None


# ---------- Vulnerabilities ----------

class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    severity: str
    description: Optional[str] = None
    solution: Optional[str] = None
    source_tool: Optional[str] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    status: str = "open"
    detected_at: datetime


VALID_VULN_STATUSES = {"open", "in_progress", "fixed", "false_positive"}


class VulnerabilityStatusUpdate(BaseModel):
    status: str

    @field_validator("status")
    @classmethod
    def status_valid(cls, v: str) -> str:
        if v not in VALID_VULN_STATUSES:
            raise ValueError(f"Statut invalide. Options : {sorted(VALID_VULN_STATUSES)}.")
        return v


# ---------- Attack surface (scanner="recon") ----------

class AttackSurfaceAssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    subdomain: str
    url: Optional[str] = None
    ip_address: Optional[str] = None
    http_status: Optional[int] = None
    title: Optional[str] = None
    technologies: Optional[str] = None
    source_tool: Optional[str] = None
    detected_at: datetime


# ---------- Scans ----------

class ScanCreate(BaseModel):
    url: str
    scanner: str = "zap"  # zap (pentest web), nuclei, nmap (réseau), recon (surface d'attaque)

    @field_validator("url")
    @classmethod
    def url_valid(cls, v: str) -> str:
        return validate_target(v)

    @field_validator("scanner")
    @classmethod
    def scanner_valid(cls, v: str) -> str:
        return validate_scanner(v)


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    url: str
    status: str
    current_step: str
    scanner: str
    date: datetime
    finished_at: Optional[datetime] = None


class ScanDetailOut(ScanOut):
    vulnerabilities: List[VulnerabilityOut] = []
    attack_surface: List[AttackSurfaceAssetOut] = []
    raw_output: Optional[str] = None


class ScanComparisonOut(BaseModel):
    current_scan_id: int
    previous_scan_id: Optional[int] = None
    previous_scan_date: Optional[datetime] = None
    current_score: int
    previous_score: Optional[int] = None
    score_delta: Optional[int] = None
    new_vulnerabilities: List[VulnerabilityOut] = []
    resolved_vulnerabilities: List[VulnerabilityOut] = []
    still_open_count: int = 0


# ---------- Scheduled scans ----------

class ScheduledScanCreate(BaseModel):
    target: str
    frequency: str  # "once", "daily" ou "weekly"
    scheduled_at: Optional[datetime] = None  # obligatoire si "once", sinon heure de départ des répétitions
    scanner: str = "zap"

    @field_validator("target")
    @classmethod
    def target_valid(cls, v: str) -> str:
        return validate_target(v)

    @field_validator("scanner")
    @classmethod
    def scanner_valid(cls, v: str) -> str:
        return validate_scanner(v)


class ScheduledScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    target: str
    frequency: str
    scheduled_at: Optional[datetime] = None
    scanner: str
    is_active: bool
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None
    created_at: datetime


# ---------- Audit log ----------

class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: Optional[int] = None
    action: str
    details: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp: datetime


# ---------- Dashboard stats ----------

class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class DashboardStats(BaseModel):
    total_scans: int
    scans_in_progress: int
    total_vulnerabilities: int
    severity_breakdown: SeverityBreakdown
    top_vulnerability_types: List[dict]  # [{"name": "...", "count": N}]
    scans_over_time: List[dict]  # [{"date": "2026-07-01", "count": N}]
    vulnerabilities_over_time: List[dict] = []  # [{"date": "...", "critical": N, "high": N, "medium": N, "low": N}]
