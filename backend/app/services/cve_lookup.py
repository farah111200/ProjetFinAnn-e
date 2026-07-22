"""Identifie un CVE réel et son score CVSS pour un service détecté, via l'API
publique du NVD (National Vulnerability Database, gouvernement américain).

Deux sources, par ordre de priorité :
1. CVE déjà taggé par Nuclei dans ses templates (le plus fiable, zéro appel réseau)
2. Recherche par mot-clé (produit + version) sur l'API NVD — utilisée seulement
   pour les findings Nmap, avec cache et limitation stricte pour respecter le
   rate limit public du NVD (5 requêtes / 30s sans clé API).

Si aucun CVE n'est trouvé, retourne (None, None) — jamais de valeur inventée.
"""
import time
import logging
import requests
from typing import Optional, Tuple

logger = logging.getLogger("cve_lookup")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_cache: dict = {}
_last_call_time = 0.0
_MIN_INTERVAL = 6.0  # secondes entre deux appels, pour rester sous 5 req/30s


def lookup_cve_by_keyword(product: str, version: Optional[str] = None) -> Tuple[Optional[str], Optional[float]]:
    """Cherche un CVE correspondant à un produit (+ version si connue) via l'API
    NVD. Retourne (cve_id, cvss_score) ou (None, None) si rien de fiable trouvé."""
    if not product:
        return None, None

    keyword = f"{product} {version}".strip() if version else product
    cache_key = keyword.lower()
    if cache_key in _cache:
        return _cache[cache_key]

    global _last_call_time
    elapsed = time.time() - _last_call_time
    if elapsed < _MIN_INTERVAL:
        time.sleep(_MIN_INTERVAL - elapsed)

    try:
        response = requests.get(
            NVD_API_URL,
            params={"keywordSearch": keyword, "resultsPerPage": 1},
            timeout=10,
        )
        _last_call_time = time.time()

        if response.status_code == 429:
            logger.warning("NVD rate limit atteint — recherche CVE ignorée pour ce finding.")
            _cache[cache_key] = (None, None)
            return None, None

        response.raise_for_status()
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            _cache[cache_key] = (None, None)
            return None, None

        cve = vulnerabilities[0].get("cve", {})
        cve_id = cve.get("id")

        cvss_score = None
        metrics = cve.get("metrics", {})
        for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if version_key in metrics and metrics[version_key]:
                cvss_score = metrics[version_key][0].get("cvssData", {}).get("baseScore")
                break

        result = (cve_id, cvss_score)
        _cache[cache_key] = result
        return result
    except (requests.RequestException, Exception) as e:
        logger.warning(f"Recherche CVE échouée pour '{keyword}' : {e}")
        _cache[cache_key] = (None, None)
        return None, None


def extract_cve_from_nuclei(raw_finding: dict) -> Tuple[Optional[str], Optional[float]]:
    """Beaucoup de templates Nuclei taguent directement le CVE concerné dans
    leurs métadonnées — zéro appel réseau nécessaire si c'est déjà là."""
    classification = raw_finding.get("classification") or {}
    cve_id = classification.get("cve-id")
    if isinstance(cve_id, list):
        cve_id = cve_id[0] if cve_id else None
    cvss_score = classification.get("cvss-score")
    return cve_id, cvss_score


MAX_NVD_LOOKUPS_PER_SCAN = 5  # borne le temps ajouté par le scan (rate limit NVD ~6s/appel)


def enrich_with_cve(raw_findings: list, vulnerabilities: list) -> list:
    """Associe à chaque vulnérabilité produite par l'IA un CVE réel si on peut
    en trouver un, à partir du finding brut correspondant. Best-effort : si les
    listes ne correspondent pas exactement (l'IA a pu réordonner/fusionner),
    on associe ce qu'on peut par position et on laisse le reste sans CVE plutôt
    que d'inventer une correspondance incertaine."""
    real_findings = [f for f in raw_findings if "error" not in f]
    nvd_lookups_used = 0

    for i, vuln in enumerate(vulnerabilities):
        vuln["cve_id"] = None
        vuln["cwe_id"] = None
        vuln["cvss_score"] = None

        if i >= len(real_findings):
            continue
        finding = real_findings[i]

        if finding.get("source_tool", "").startswith("nuclei"):
            cve_id, cvss = extract_cve_from_nuclei(finding)
            vuln["cve_id"], vuln["cvss_score"] = cve_id, cvss

        elif finding.get("source_tool", "").startswith("nmap") and finding.get("product"):
            if nvd_lookups_used >= MAX_NVD_LOOKUPS_PER_SCAN:
                continue
            cve_id, cvss = lookup_cve_by_keyword(finding.get("product"), finding.get("version"))
            vuln["cve_id"], vuln["cvss_score"] = cve_id, cvss
            nvd_lookups_used += 1

        elif finding.get("source_tool") == "zap":
            # ZAP détecte surtout des problèmes de configuration/bonnes pratiques,
            # rarement liés à un CVE précis — on expose son CWE (classification
            # de la nature du problème) plutôt que d'inventer un CVE inexistant.
            vuln["cwe_id"] = finding.get("cwe_id")

    return vulnerabilities
