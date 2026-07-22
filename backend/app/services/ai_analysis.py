"""Transforme les résultats bruts des outils de scan en vulnérabilités
compréhensibles (nom, sévérité, description, remédiation).

Deux fournisseurs IA supportés, contrôlés par AI_PROVIDER dans .env :
- "claude" : API Anthropic, payant mais meilleure qualité d'analyse
- "ollama" : modèle open-source tournant en local (gratuit, pas de clé API)

Dans les deux cas, si l'appel échoue (pas de clé, service injoignable...),
on retombe sur une version dégradée sans IA pour ne jamais bloquer le scan.
"""
import json
import logging
import requests
from typing import List, Dict
import anthropic
from app.core.config import settings

logger = logging.getLogger("ai_analysis")

VALID_SEVERITIES = {"critical", "high", "medium", "low"}
SEVERITY_TRANSLATIONS = {
    "critique": "critical",
    "élevée": "high",
    "elevee": "high",
    "haute": "high",
    "moyenne": "medium",
    "faible": "low",
}


def normalize_severity(value: str) -> str:
    """Ramène la sévérité renvoyée par l'IA à l'une des 4 valeurs attendues
    (critical/high/medium/low), quelle que soit la casse ou la langue utilisée
    par le modèle. Retombe sur 'medium' si la valeur est inconnue."""
    if not value:
        return "medium"
    cleaned = value.strip().lower()
    if cleaned in VALID_SEVERITIES:
        return cleaned
    return SEVERITY_TRANSLATIONS.get(cleaned, "medium")


SYSTEM_PROMPT = """Tu es un expert en cybersécurité qui analyse des résultats bruts
d'outils de scan (Nmap, Nuclei). Pour chaque finding fourni, produis une entrée
avec : name (titre court), severity (critical/high/medium/low), description
(explication claire en français, 2-3 phrases), solution (remédiation concrète).
Réponds UNIQUEMENT avec un tableau JSON valide, sans texte avant ou après,
sans balises markdown. Exemple de format :
[{"name": "...", "severity": "high", "description": "...", "solution": "..."}]
"""


def analyze_findings(findings: List[Dict]) -> List[Dict]:
    """Point d'entrée unique : dispatche vers le bon fournisseur IA selon
    AI_PROVIDER, avec fallback automatique en cas d'échec."""
    real_findings = [f for f in findings if "error" not in f]
    if not real_findings:
        return []

    if settings.AI_PROVIDER == "ollama":
        logger.info(f"Analyse via Ollama ({settings.OLLAMA_MODEL} @ {settings.OLLAMA_API_URL})")
        result = _analyze_with_ollama(real_findings)
    elif settings.AI_PROVIDER == "openrouter":
        logger.info(f"Analyse via OpenRouter ({settings.OPENROUTER_MODEL})")
        result = _analyze_with_openrouter(real_findings)
    else:
        logger.info("Analyse via Claude API")
        result = _analyze_with_claude(real_findings)

    if not result:
        logger.warning(
            f"Aucun résultat IA exploitable (provider={settings.AI_PROVIDER}) — "
            "bascule sur les descriptions génériques (fallback)."
        )
        return _fallback_without_ai(real_findings)
    return result


def _analyze_with_claude(findings: List[Dict]) -> List[Dict]:
    if not settings.ANTHROPIC_API_KEY:
        return []
    try:
        client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2000,
            system=SYSTEM_PROMPT,
            messages=[{
                "role": "user",
                "content": f"Findings bruts à analyser :\n{json.dumps(findings, ensure_ascii=False)}",
            }],
        )
        raw_text = "".join(block.text for block in response.content if block.type == "text")
        return _parse_json_response(raw_text)
    except (anthropic.APIError, Exception):
        return []


def _analyze_with_ollama(findings: List[Dict]) -> List[Dict]:
    """Appelle un serveur Ollama local (gratuit, aucune clé API requise).
    Nécessite qu'Ollama tourne (conteneur ou installation locale) avec le
    modèle configuré déjà téléchargé (ex: `ollama pull llama3.1`)."""
    try:
        response = requests.post(
            f"{settings.OLLAMA_API_URL}/api/generate",
            json={
                "model": settings.OLLAMA_MODEL,
                "prompt": f"{SYSTEM_PROMPT}\n\nFindings bruts à analyser :\n"
                          f"{json.dumps(findings, ensure_ascii=False)}",
                "stream": False,
            },
            timeout=120,
        )
        response.raise_for_status()
        raw_text = response.json().get("response", "")
        parsed = _parse_json_response(raw_text)
        if not parsed:
            logger.warning(f"Réponse Ollama reçue mais JSON illisible : {raw_text[:200]!r}")
        return parsed
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Impossible de joindre Ollama à {settings.OLLAMA_API_URL} : {e}")
        return []
    except requests.exceptions.Timeout:
        logger.error("Ollama n'a pas répondu à temps (120s) — le modèle est peut-être encore en train de charger.")
        return []
    except Exception as e:
        logger.error(f"Erreur inattendue avec Ollama : {e}")
        return []


def _analyze_with_openrouter(findings: List[Dict]) -> List[Dict]:
    """Appelle un modèle gratuit via OpenRouter (passerelle unifiée vers de
    nombreux modèles, API compatible OpenAI). Nécessite OPENROUTER_API_KEY.
    La liste des modèles :free change régulièrement côté OpenRouter — ajuste
    OPENROUTER_MODEL dans .env si le modèle configuré n'est plus disponible."""
    if not settings.OPENROUTER_API_KEY:
        return []
    try:
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {settings.OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": settings.OPENROUTER_MODEL,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": f"Findings bruts à analyser :\n{json.dumps(findings, ensure_ascii=False)}"},
                ],
            },
            timeout=60,
        )
        response.raise_for_status()
        raw_text = response.json()["choices"][0]["message"]["content"]
        parsed = _parse_json_response(raw_text)
        if not parsed:
            logger.warning(f"Réponse OpenRouter reçue mais JSON illisible : {raw_text[:200]!r}")
        return parsed
    except requests.exceptions.HTTPError as e:
        logger.error(f"Erreur HTTP OpenRouter (modèle '{settings.OPENROUTER_MODEL}' peut-être indisponible) : {e}")
        return []
    except (requests.RequestException, KeyError, IndexError) as e:
        logger.error(f"Erreur inattendue avec OpenRouter : {e}")
        return []


def _parse_json_response(raw_text: str) -> List[Dict]:
    cleaned = raw_text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    try:
        parsed = json.loads(cleaned)
        return parsed if isinstance(parsed, list) else []
    except json.JSONDecodeError:
        return []


def _fallback_without_ai(findings: List[Dict]) -> List[Dict]:
    """Génère des vulnérabilités basiques sans IA, pour que la plateforme reste
    fonctionnelle même sans IA configurée ou disponible (utile en démo/dev)."""
    results = []
    for f in findings:
        if f.get("source_tool", "").startswith("nmap"):
            results.append({
                "name": f"Port {f.get('port')} ouvert ({f.get('service', 'inconnu')})",
                "severity": "medium",
                "description": f"Le port {f.get('port')}/{f.get('protocol')} est ouvert, "
                                f"exécutant {f.get('product') or f.get('service')}.",
                "solution": "Vérifier si ce service doit être exposé publiquement, "
                            "sinon le fermer ou le restreindre par pare-feu.",
                "source_tool": f.get("source_tool", "nmap"),
            })
        else:
            results.append({
                "name": f.get("name", "Vulnérabilité détectée"),
                "severity": f.get("severity", "medium"),
                "description": f.get("description", ""),
                "solution": "Consulter la documentation de l'outil pour la remédiation.",
                "source_tool": f.get("source_tool", "inconnu"),
            })
    return results
