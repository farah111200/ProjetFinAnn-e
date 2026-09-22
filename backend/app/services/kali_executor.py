"""Exécute une commande sur la VM Kali via SSH, pour que ce soit Kali qui
lance réellement les outils de scan plutôt que le conteneur backend.
Utilisé uniquement quand SCAN_MODE=kali dans .env."""
import paramiko
from app.core.config import settings


def run_remote_command(command: list[str], timeout: int = 300, stdin_data: str | None = None) -> tuple[str, str]:
    """Se connecte en SSH à la VM Kali, exécute la commande, retourne (stdout, stderr).
    Lève une exception explicite si la connexion échoue (IP incorrecte, SSH
    désactivé sur Kali, mauvais identifiants...). `stdin_data`, si fourni, est
    écrit sur l'entrée standard distante avant de lire la sortie (ex: liste
    d'hôtes pour httpx)."""
    if not settings.KALI_HOST:
        raise RuntimeError(
            "KALI_HOST n'est pas configuré dans .env. "
            "Renseigne l'IP de ta VM Kali (visible avec `ip a` sur Kali)."
        )

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=settings.KALI_HOST,
            port=settings.KALI_SSH_PORT,
            username=settings.KALI_SSH_USER,
            password=settings.KALI_SSH_PASSWORD,
            timeout=10,
        )
        cmd_str = " ".join(command)
        stdin, stdout, stderr = client.exec_command(cmd_str, timeout=timeout)
        if stdin_data:
            stdin.write(stdin_data)
            stdin.channel.shutdown_write()
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        return out, err
    except paramiko.AuthenticationException:
        raise RuntimeError(
            "Authentification SSH refusée par Kali. Vérifie KALI_SSH_USER/KALI_SSH_PASSWORD dans .env."
        )
    except (paramiko.SSHException, OSError) as e:
        raise RuntimeError(f"Impossible de joindre la VM Kali ({settings.KALI_HOST}): {e}")
    finally:
        client.close()
