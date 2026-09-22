"""Protection anti brute-force sur la connexion : après plusieurs tentatives
échouées pour un même nom d'utilisateur, on bloque temporairement les
nouvelles tentatives, même avec le bon mot de passe.

Stockage en mémoire (dict) — suffisant pour ce projet (un seul processus
backend). Se réinitialise si le conteneur redémarre, ce qui est acceptable
ici (pas un souci de sécurité, juste un détail d'implémentation à documenter).
"""
from datetime import datetime, timedelta
from typing import Optional

MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

# username -> {"count": int, "locked_until": datetime | None}
_attempts: dict = {}


def check_lock(username: str) -> Optional[datetime]:
    """Retourne la date/heure jusqu'à laquelle le compte est bloqué, ou None
    s'il n'est pas bloqué (et nettoie l'entrée si le blocage est expiré)."""
    entry = _attempts.get(username)
    if not entry or not entry.get("locked_until"):
        return None

    if datetime.utcnow() >= entry["locked_until"]:
        _attempts.pop(username, None)
        return None

    return entry["locked_until"]


def record_failure(username: str) -> Optional[datetime]:
    """Enregistre une tentative échouée. Retourne la date de déblocage si le
    compte vient d'être verrouillé suite à cet échec, sinon None."""
    entry = _attempts.setdefault(username, {"count": 0, "locked_until": None})
    entry["count"] += 1

    if entry["count"] >= MAX_ATTEMPTS:
        entry["locked_until"] = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
        return entry["locked_until"]

    return None


def remaining_attempts(username: str) -> int:
    entry = _attempts.get(username)
    if not entry:
        return MAX_ATTEMPTS
    return max(0, MAX_ATTEMPTS - entry["count"])


def reset(username: str) -> None:
    """Appelé après une connexion réussie — repart sur un compteur propre."""
    _attempts.pop(username, None)
