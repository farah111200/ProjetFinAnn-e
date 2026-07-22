"""Génère un rapport PDF pour un scan — synthèse, sévérités, détail de chaque
vulnérabilité (description IA, remédiation, CVE/CWE si identifiés).

Utilise WeasyPrint (HTML/CSS -> PDF), déjà présent dans les dépendances et
les libs système du Dockerfile (libpango, libgdk-pixbuf).
"""
from datetime import datetime
from weasyprint import HTML

SEVERITY_LABELS = {"critical": "Critique", "high": "Élevée", "medium": "Moyenne", "low": "Faible"}
SEVERITY_COLORS = {"critical": "#a32d2d", "high": "#854f0b", "medium": "#a08b3a", "low": "#185fa5"}


def _fmt_date(dt) -> str:
    if not dt:
        return "—"
    return dt.strftime("%d/%m/%Y à %H:%M")


def _duration(start, end) -> str:
    if not start or not end:
        return "—"
    seconds = int((end - start).total_seconds())
    if seconds < 60:
        return f"{seconds}s"
    return f"{seconds // 60}m {seconds % 60}s"


def build_scan_report_html(scan, vulnerabilities) -> str:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulnerabilities:
        if v.severity in counts:
            counts[v.severity] += 1

    severity_rows = "".join(
        f"""<tr>
            <td><span class="badge" style="background:{SEVERITY_COLORS[s]}22; color:{SEVERITY_COLORS[s]};">{SEVERITY_LABELS[s]}</span></td>
            <td class="num">{counts[s]}</td>
        </tr>"""
        for s in ["critical", "high", "medium", "low"]
    )

    vuln_blocks = ""
    for v in vulnerabilities:
        color = SEVERITY_COLORS.get(v.severity, "#666")
        identifiers = []
        if v.cve_id:
            identifiers.append(f"<span class='tag'>{v.cve_id}</span>")
        if v.cwe_id:
            identifiers.append(f"<span class='tag'>{v.cwe_id}</span>")
        if v.cvss_score is not None:
            identifiers.append(f"<span class='tag'>CVSS {v.cvss_score}</span>")
        identifiers_html = " ".join(identifiers) if identifiers else "<span class='tag muted'>Aucun identifiant CVE/CWE</span>"

        vuln_blocks += f"""
        <div class="vuln-block">
            <div class="vuln-header">
                <span class="badge" style="background:{color}22; color:{color};">{SEVERITY_LABELS.get(v.severity, v.severity)}</span>
                <span class="vuln-name">{v.name}</span>
            </div>
            <div class="identifiers">{identifiers_html}</div>
            <p class="label">Analyse</p>
            <p>{v.description or "Pas de description disponible."}</p>
            <p class="label">Remédiation recommandée</p>
            <p>{v.solution or "—"}</p>
            <p class="meta">Détecté via {v.source_tool or "—"} le {_fmt_date(v.detected_at)}</p>
        </div>
        """

    total = len(vulnerabilities)

    return f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
    <meta charset="utf-8">
    <style>
        @page {{
            size: A4;
            margin: 2.2cm 1.8cm;
            @bottom-center {{
                content: "AI Pentest Platform — Rapport confidentiel — Page " counter(page) " / " counter(pages);
                font-size: 9px; color: #888;
            }}
        }}
        * {{ box-sizing: border-box; }}
        body {{ font-family: 'DejaVu Sans', Arial, sans-serif; color: #1a1a1a; font-size: 11px; line-height: 1.5; }}

        .cover {{ text-align: center; padding-top: 4cm; }}
        .cover .eyebrow {{ font-size: 11px; letter-spacing: 2px; color: #7c3aed; text-transform: uppercase; margin-bottom: 12px; }}
        .cover h1 {{ font-size: 30px; margin: 0 0 8px; }}
        .cover .target {{ font-size: 16px; color: #444; margin-bottom: 40px; }}
        .cover-meta {{ display: inline-block; text-align: left; border: 1px solid #ddd; border-radius: 8px; padding: 20px 30px; margin-top: 20px; }}
        .cover-meta div {{ margin: 6px 0; font-size: 12px; }}
        .cover-meta b {{ display: inline-block; width: 140px; color: #666; font-weight: 600; }}
        .disclaimer {{ margin-top: 60px; font-size: 9px; color: #999; padding: 0 40px; }}

        h2 {{ font-size: 16px; border-bottom: 2px solid #7c3aed; padding-bottom: 6px; margin-top: 30px; page-break-after: avoid; }}

        table.summary {{ width: 60%; border-collapse: collapse; margin: 16px 0; }}
        table.summary td {{ padding: 8px 12px; border-bottom: 1px solid #eee; }}
        table.summary .num {{ text-align: right; font-weight: 700; font-family: monospace; }}

        .badge {{ display: inline-block; padding: 2px 10px; border-radius: 5px; font-size: 10px; font-weight: 700; }}
        .tag {{ display: inline-block; background: #f0f0f0; border-radius: 4px; padding: 2px 8px; font-size: 9px; font-family: monospace; margin-right: 4px; color: #555; }}
        .tag.muted {{ color: #aaa; font-style: italic; font-family: inherit; }}

        .vuln-block {{ border: 1px solid #e5e5e5; border-radius: 8px; padding: 14px 16px; margin-bottom: 12px; page-break-inside: avoid; }}
        .vuln-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
        .vuln-name {{ font-size: 13px; font-weight: 700; }}
        .identifiers {{ margin-bottom: 8px; }}
        .label {{ font-size: 9px; text-transform: uppercase; letter-spacing: 0.5px; color: #888; margin: 10px 0 2px; font-weight: 700; }}
        .meta {{ font-size: 9px; color: #999; margin-top: 8px; }}
    </style>
    </head>
    <body>

    <div class="cover">
        <div class="eyebrow">AI Pentest Platform — Rapport de Vulnerability Assessment</div>
        <h1>Rapport de scan de sécurité</h1>
        <div class="target">{scan.url}</div>

        <div class="cover-meta">
            <div><b>Outil utilisé</b> {scan.scanner}</div>
            <div><b>Date du scan</b> {_fmt_date(scan.date)}</div>
            <div><b>Durée</b> {_duration(scan.date, scan.finished_at)}</div>
            <div><b>Statut</b> {scan.status}</div>
            <div><b>Vulnérabilités trouvées</b> {total}</div>
            <div><b>Généré le</b> {_fmt_date(datetime.utcnow())}</div>
        </div>

        <p class="disclaimer">
            Ce rapport a été généré automatiquement par une plateforme de Vulnerability Assessment
            assistée par intelligence artificielle, dans le cadre d'un test effectué sur une cible
            autorisée. Il ne constitue pas un test d'intrusion (penetration test) avec exploitation
            active, mais une détection et une analyse automatisées des vulnérabilités potentielles.
            Confidentiel — à ne pas diffuser sans autorisation.
        </p>
    </div>

    <div style="page-break-before: always;">
        <h2>Synthèse par sévérité</h2>
        <table class="summary">
            <tbody>{severity_rows}</tbody>
        </table>

        <h2>Détail des vulnérabilités ({total})</h2>
        {vuln_blocks if vuln_blocks else "<p>Aucune vulnérabilité détectée lors de ce scan.</p>"}
    </div>

    </body>
    </html>
    """


def generate_scan_report_pdf(scan, vulnerabilities) -> bytes:
    html_content = build_scan_report_html(scan, vulnerabilities)
    return HTML(string=html_content).write_pdf()
