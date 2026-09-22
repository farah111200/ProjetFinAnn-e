"""Exécute les outils de scan (Nmap, Nuclei) et normalise leurs résultats
bruts en une liste de "findings" prête à être analysée par le module IA.

Deux modes d'exécution, contrôlés par SCAN_MODE dans .env :
- "local"  : les outils tournent directement dans le conteneur backend (subprocess)
- "kali"   : les commandes sont envoyées par SSH à une VM Kali qui exécute
             réellement les outils (voir kali_executor.py)

Le reste du code (parsing, format des findings) est identique dans les deux
cas — seul le point d'exécution de la commande change.
"""
import re
import subprocess
import time
import requests
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional
from app.core.config import settings
from app.services.kali_executor import run_remote_command


def _execute(command: List[str], timeout: int, stdin_data: Optional[str] = None) -> str:
    """Exécute la commande localement ou sur Kali selon SCAN_MODE, retourne
    la sortie standard (stdout) sous forme de texte. `stdin_data`, si fourni,
    est écrit sur l'entrée standard de la commande (ex: liste d'hôtes pour
    httpx) — géré dans les deux modes."""
    if settings.SCAN_MODE == "kali":
        stdout, stderr = run_remote_command(command, timeout=timeout, stdin_data=stdin_data)
        return stdout
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, input=stdin_data)
    return result.stdout


def run_nmap_scan(target: str) -> List[Dict]:
    """Lance un scan Nmap (ports + détection de service/version) et retourne
    une liste de findings bruts : [{"port": 22, "service": "ssh", "product": "...", ...}]
    """
    findings: List[Dict] = []
    try:
        stdout = _execute(["nmap", "-sV", "--open", "-oX", "-", target], timeout=300)
        root = ET.fromstring(stdout)
        for host in root.findall("host"):
            for port in host.findall("./ports/port"):
                port_id = port.get("portid")
                protocol = port.get("protocol")
                service_el = port.find("service")
                state_el = port.find("state")

                if state_el is None or state_el.get("state") != "open":
                    continue

                findings.append({
                    "port": port_id,
                    "protocol": protocol,
                    "service": service_el.get("name") if service_el is not None else "unknown",
                    "product": service_el.get("product") if service_el is not None else None,
                    "version": service_el.get("version") if service_el is not None else None,
                    "source_tool": "nmap" if settings.SCAN_MODE == "local" else "nmap (kali)",
                })
    except subprocess.TimeoutExpired:
        findings.append({"error": "Le scan Nmap a dépassé le délai imparti (5 min)."})
    except FileNotFoundError:
        findings.append({"error": "Nmap n'est pas installé dans ce conteneur."})
    except ET.ParseError:
        findings.append({"error": "Impossible de parser la sortie XML de Nmap (sortie vide ou erreur SSH)."})
    except RuntimeError as e:
        findings.append({"error": str(e)})

    return findings


def run_nuclei_scan(target: str) -> List[Dict]:
    """Lance Nuclei avec les templates par défaut (JSON lines en sortie)."""
    import json

    findings: List[Dict] = []
    try:
        stdout = _execute(["nuclei", "-target", target, "-jsonl", "-silent"], timeout=600)
        for line in stdout.strip().splitlines():
            if not line:
                continue
            try:
                data = json.loads(line)
                findings.append({
                    "name": data.get("info", {}).get("name"),
                    "severity": data.get("info", {}).get("severity"),
                    "description": data.get("info", {}).get("description"),
                    "matched_at": data.get("matched-at"),
                    "classification": data.get("info", {}).get("classification", {}),
                    "source_tool": "nuclei" if settings.SCAN_MODE == "local" else "nuclei (kali)",
                })
            except json.JSONDecodeError:
                continue
    except subprocess.TimeoutExpired:
        findings.append({"error": "Le scan Nuclei a dépassé le délai imparti (10 min)."})
    except FileNotFoundError:
        findings.append({"error": "Nuclei n'est pas installé dans ce conteneur."})
    except RuntimeError as e:
        findings.append({"error": str(e)})

    return findings


def run_zap_scan(target: str) -> List[Dict]:
    """Lance un scan OWASP ZAP complet contre une cible web : spider (cartographie
    du site) puis scan actif (tests d'injection, XSS, etc.), et récupère les alertes.
    Contacte le conteneur ZAP via son API REST (settings.ZAP_API_URL)."""
    base = settings.ZAP_API_URL
    findings: List[Dict] = []

    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    # ZAP met parfois 20-30s à finir son initialisation interne (règles de scan,
    # certificat CA), et jusqu'à 2 minutes la toute première fois s'il doit
    # télécharger ses plugins additionnels (ensuite mis en cache dans un volume
    # persistant). On retente pendant 2 minutes avant d'abandonner.
    zap_ready = False
    for attempt in range(24):
        try:
            requests.get(f"{base}/JSON/core/view/version/", timeout=5).raise_for_status()
            zap_ready = True
            break
        except requests.exceptions.RequestException:
            time.sleep(5)

    if not zap_ready:
        return [{"error": "ZAP n'a pas répondu après 2 minutes de tentatives. "
                           "Vérifie ses logs (`docker compose logs zap`) — il est peut-être "
                           "encore en train de télécharger ses plugins la première fois."}]

    try:
        # 1. Spider : cartographie le site pour trouver les pages/paramètres
        r = requests.get(f"{base}/JSON/spider/action/scan/", params={"url": target}, timeout=15)
        r.raise_for_status()
        scan_id = r.json().get("scan")

        for _ in range(60):  # jusqu'à ~5 min (60 x 5s)
            status = requests.get(f"{base}/JSON/spider/view/status/", params={"scanId": scan_id}, timeout=10)
            if int(status.json().get("status", 0)) >= 100:
                break
            time.sleep(5)

        # 2. Scan actif : envoie des payloads de test (injections, XSS...)
        r = requests.get(f"{base}/JSON/ascan/action/scan/", params={"url": target}, timeout=15)
        r.raise_for_status()
        ascan_id = r.json().get("scan")

        for _ in range(120):  # jusqu'à ~10 min (120 x 5s)
            status = requests.get(f"{base}/JSON/ascan/view/status/", params={"scanId": ascan_id}, timeout=10)
            if int(status.json().get("status", 0)) >= 100:
                break
            time.sleep(5)

        # 3. Récupère les alertes détectées
        alerts = requests.get(f"{base}/JSON/core/view/alerts/", params={"baseurl": target}, timeout=15)
        alerts.raise_for_status()

        risk_map = {"High": "high", "Medium": "medium", "Low": "low"}
        for alert in alerts.json().get("alerts", []):
            # Le niveau "Informational" de ZAP ne signale pas une faille de
            # sécurité — c'est un log de ce que ZAP a testé (ex: quel User-Agent
            # a été envoyé). On l'exclut pour ne garder que de vraies découvertes.
            if alert.get("risk") == "Informational":
                continue
            findings.append({
                "name": alert.get("alert", "Alerte ZAP"),
                "severity": risk_map.get(alert.get("risk"), "medium"),
                "description": alert.get("description", ""),
                "solution": alert.get("solution", ""),
                "matched_at": alert.get("url"),
                "cwe_id": f"CWE-{alert.get('cweid')}" if alert.get("cweid") and str(alert.get("cweid")) not in ("-1", "0") else None,
                "source_tool": "zap",
            })
    except requests.exceptions.ConnectionError:
        findings.append({"error": "Impossible de joindre le conteneur ZAP. Vérifie qu'il est bien démarré."})
    except requests.exceptions.Timeout:
        findings.append({"error": "ZAP n'a pas répondu à temps."})
    except Exception as e:
        findings.append({"error": f"Erreur ZAP : {e}"})

    return findings


def _clean_domain(target: str) -> str:
    """Extrait le nom d'hôte nu (sans schéma ni port ni chemin) d'une cible,
    ex: 'https://api.example.com:8080/path' -> 'api.example.com'."""
    stripped = re.sub(r"^https?://", "", target.strip())
    return stripped.split("/")[0].split(":")[0]


MAX_SUBDOMAINS_PROBED = 50  # borne le temps du scan (httpx sonde chaque hôte un par un)


def run_subfinder(domain: str) -> List[str]:
    """Énumère les sous-domaines connus via des sources passives (subfinder :
    certificate transparency, DNS public, etc. — aucune requête active sur la
    cible). Best-effort : si l'outil est absent ou échoue, on retombe sur le
    domaine racine seul plutôt que de faire échouer tout le scan."""
    try:
        stdout = _execute(["subfinder", "-d", domain, "-silent"], timeout=120)
        subs = sorted({line.strip() for line in stdout.splitlines() if line.strip()})
        if domain not in subs:
            subs.insert(0, domain)
        return subs
    except (subprocess.TimeoutExpired, FileNotFoundError, RuntimeError):
        return [domain]


def run_httpx_probe(hosts: List[str]) -> List[Dict]:
    """Sonde chaque hôte en HTTP(S) (httpx) : code de statut, titre de page,
    IP résolue et technologies détectées via empreintes (serveur web, CMS,
    framework...). Les hôtes sont envoyés sur l'entrée standard de httpx,
    un par ligne — c'est le mode d'utilisation normal de l'outil."""
    import json as _json

    if not hosts:
        return []
    hosts = hosts[:MAX_SUBDOMAINS_PROBED]
    stdin_data = "\n".join(
        host if host.startswith(("http://", "https://")) else f"https://{host}"
        for host in hosts
    ) + "\n"
    findings: List[Dict] = []

    try:
        stdout = _execute(
            ["httpx", "-silent", "-json", "-title", "-tech-detect", "-status-code", "-timeout", "8"],
            timeout=180,
            stdin_data=stdin_data,
        )
        for line in stdout.strip().splitlines():
            if not line:
                continue
            try:
                data = _json.loads(line)
            except _json.JSONDecodeError:
                continue
            a_records = data.get("a") or []
            findings.append({
                "subdomain": data.get("input") or data.get("host"),
                "url": data.get("url"),
                "ip_address": a_records[0] if a_records else None,
                "http_status": data.get("status_code"),
                "title": data.get("title"),
                "technologies": ", ".join(data.get("tech", [])) or None,
                "source_tool": "recon" if settings.SCAN_MODE == "local" else "recon (kali)",
            })
    except subprocess.TimeoutExpired:
        findings.append({"error": "La sonde HTTP (httpx) a dépassé le délai imparti (3 min)."})
    except FileNotFoundError:
        findings.append({"error": "httpx n'est pas installé dans ce conteneur."})
    except RuntimeError as e:
        findings.append({"error": str(e)})

    return findings


def run_recon_scan(target: str) -> List[Dict]:
    """Reconnaissance de la surface d'attaque : énumère les sous-domaines
    (subfinder) puis sonde chacun en HTTP (httpx) pour produire un inventaire
    d'actifs exposés (hôte, IP, statut, titre, technologies). Contrairement
    aux autres scanners, ce n'est pas un jugement de vulnérabilité — c'est de
    l'inventaire brut, stocké tel quel (voir AttackSurfaceAsset), qui peut
    ensuite nourrir un scan nmap/nuclei/zap ciblé ou une future couche de
    corrélation IA."""
    domain = _clean_domain(target)
    subdomains = run_subfinder(domain)
    return run_httpx_probe(subdomains)


SCANNERS = {
    "nmap": run_nmap_scan,
    "nuclei": run_nuclei_scan,
    "zap": run_zap_scan,
    "recon": run_recon_scan,
}


def run_scan(scanner: str, target: str) -> List[Dict]:
    scan_fn = SCANNERS.get(scanner)
    if scan_fn is None:
        return [{"error": f"Scanner '{scanner}' inconnu. Options: {list(SCANNERS.keys())}"}]
    return scan_fn(target)
