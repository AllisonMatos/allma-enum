#!/usr/bin/env python3
"""
Modern Report Generator (Material Design Style)
Generates: output/<target>/report/report.html + report.pdf
"""

from pathlib import Path
import datetime
import weasyprint
from ..output import info, success, warn, error


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def read_file_lines(path: Path):
    if not path.exists():
        return []
    return [l.strip() for l in path.read_text(errors="ignore").splitlines() if l.strip()]


def read_file_raw(path: Path):
    if not path.exists():
        return ""
    return path.read_text(errors="ignore")


def ensure_outdir(target: str):
    outdir = Path("output") / target / "report"
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir


# ------------------------------------------------------------
# HTML Template (Material Design)
# ------------------------------------------------------------
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Report - {target}</title>
<style>

    body {{
        font-family: "Roboto", Arial, sans-serif;
        background: #f5f7fa;
        margin: 0;
        padding: 0;
        color: #333;
    }}

    h1, h2 {{
        font-weight: 500;
        margin-bottom: 10px;
    }}

    .header {{
        background: linear-gradient(to right, #3f51b5, #5c6bc0);
        color: white;
        padding: 40px;
        text-align: center;
        border-bottom-left-radius: 20px;
        border-bottom-right-radius: 20px;
    }}

    .container {{
        width: 90%;
        max-width: 1200px;
        margin: auto;
        margin-top: 30px;
        margin-bottom: 50px;
    }}

    .card {{
        background: white;
        border-radius: 14px;
        padding: 25px;
        margin-bottom: 25px;
        box-shadow: 0 2px 12px rgba(0,0,0,0.10);
    }}

    .section-title {{
        font-size: 22px;
        margin-bottom: 15px;
        color: #3f51b5;
    }}

    /* Tables */
    table {{
        width: 100%;
        border-collapse: collapse;
        margin-top: 15px;
        font-size: 15px;
    }}

    table, th, td {{
        border: 1px solid #ddd;
    }}

    th {{
        background: #e8eaf6;
        padding: 12px;
        font-weight: 600;
        color: #303f9f;
    }}

    td {{
        padding: 10px;
        background: #ffffff;
    }}

    /* Accordion */
    details {{
        background: white;
        border-radius: 10px;
        margin-bottom: 5px;
        padding: 12px;
        box-shadow: 0 1px 6px rgba(0,0,0,0.1);
        cursor: pointer;
    }}

    details summary {{
        font-size: 17px;
        font-weight: 600;
        color: #3f51b5;
        outline: none;
    }}

    pre {{
        white-space: pre-wrap;
        background: #f0f0f5;
        padding: 15px;
        border-radius: 10px;
        font-size: 14px;
    }}

</style>
</head>

<body>
<div class="header">
    <h1>Relatório de Enumeração</h1>
    <h2>{target}</h2>
    <p>Gerado em {date}</p>
</div>

<div class="container">

    <!-- SUBDOMAINS -->
    <div class="card">
        <div class="section-title">🌐 Subdomínios Encontrados</div>
        <pre>{subdomains}</pre>
    </div>

    <!-- PORTS -->
    <div class="card">
        <div class="section-title">🔌 Portas Abertas</div>
        {ports_html}
    </div>

    <!-- URL 200 -->
    <div class="card">
        <div class="section-title">🔗 URLs Válidas (200/301/302)</div>
        {urls_table}
    </div>

    <!-- FILES -->
    <div class="card">
        <div class="section-title">📁 Arquivos por Extensão</div>
        <pre>{files}</pre>
    </div>

    <!-- SERVICES -->
    <div class="card">
        <div class="section-title">🛰️ Serviços Identificados via Nmap</div>
        {services_table}
    </div>

    <!-- JSSCANNER -->
    <div class="card">
        <div class="section-title">🧪 JSScanner — Suspeitas</div>
        <pre>{jsscanner}</pre>
    </div>

</div>

</body>
</html>
"""


# ------------------------------------------------------------
# Build HTML sections
# ------------------------------------------------------------
def build_ports_html(ports_txt: Path):
    if not ports_txt.exists():
        return "<p>Nenhuma porta encontrada.</p>"

    output = []
    current_host = ""
    lines = ports_txt.read_text().splitlines()

    for line in lines:
        if line.startswith("Host:"):
            host = line.replace("Host: ", "").strip()
            if current_host:
                output.append("</details>")
            output.append(f"<details><summary>{host}</summary><pre>")
            current_host = host
        else:
            output.append(line)

    if current_host:
        output.append("</pre></details>")

    return "\n".join(output)


def build_urls_table(urls):
    if not urls:
        return "<p>Nenhuma URL válida.</p>"

    rows = "\n".join(f"<tr><td>{u}</td></tr>" for u in urls)
    return f"""
    <table>
        <tr><th>URL</th></tr>
        {rows}
    </table>
    """


def build_services_table(files):
    if not files:
        return "<p>Nenhum serviço encontrado.</p>"

    rows = []
    for file in files:
        content = read_file_lines(file)
        for line in content:
            rows.append(f"<tr><td>{line}</td></tr>")

    return f"""
    <table>
        <tr><th>Serviço Identificado</th></tr>
        {' '.join(rows)}
    </table>
    """


# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------
def run(context):
    target = context.get("target")
    if not target:
        raise ValueError("context['target'] é obrigatório para report")

    info("Gerando relatório final (Material Design)...")

    outdir = ensure_outdir(target)
    html_file = outdir / "report.html"
    pdf_file = outdir / "report.pdf"

    # Paths de entrada
    base = Path("output") / target

    subdomains = read_file_raw(base / "domain" / "subdomains.txt")
    ports_html = build_ports_html(base / "domain" / "ports.txt")
    urls_200 = read_file_lines(base / "urls" / "urls_200.txt")
    urls_table = build_urls_table(urls_200)
    files_ext = read_file_raw(base / "files" / "files_by_extension.txt")

    # Nmap outputs
    services_files = list((base / "services").glob("scanFinal_*.txt"))
    services_table = build_services_table(services_files)

    # JSScanner
    jsscanner_report = read_file_raw(base / "jsscanner" / "jsscanner_report.txt")

    html = HTML_TEMPLATE.format(
        target=target,
        date=datetime.datetime.now().strftime("%d/%m/%Y %H:%M"),
        subdomains=subdomains or "Nenhum subdomínio.",
        ports_html=ports_html,
        urls_table=urls_table,
        files=files_ext or "Nenhum arquivo encontrado.",
        services_table=services_table,
        jsscanner=jsscanner_report or "Nenhuma suspeita.",
    )

    html_file.write_text(html, encoding="utf-8")

    try:
        weasyprint.HTML(string=html).write_pdf(str(pdf_file))
        success(f"Relatório PDF gerado com sucesso → {pdf_file}")
    except Exception as e:
        warn(f"Falha ao gerar PDF automaticamente ({e}). Relatório HTML está pronto → {html_file}")

    return [str(html_file), str(pdf_file)]
