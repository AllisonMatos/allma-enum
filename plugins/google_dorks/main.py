#!/usr/bin/env python3
"""
Google Dorks Generator — Gera dorks especializados para o target.
Não faz scraping — gera os dorks para uso manual.
"""
import json
from pathlib import Path
from urllib.parse import quote_plus

from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error


DORK_TEMPLATES = [
    # Files sensíveis
    ("Arquivos sensíveis", 'site:{target} (filetype:pdf OR filetype:doc OR filetype:xls OR filetype:csv)'),
    ("Backups", 'site:{target} (filetype:bak OR filetype:old OR filetype:sql OR filetype:zip OR filetype:tar.gz)'),
    ("Configs expostos", 'site:{target} (filetype:env OR filetype:cfg OR filetype:conf OR filetype:ini)'),
    ("Logs expostos", 'site:{target} (filetype:log OR filetype:txt) inurl:(error OR debug OR access)'),
    # Painéis
    ("Admin panels", 'site:{target} inurl:(admin OR login OR dashboard OR panel OR manage)'),
    ("phpMyAdmin etc", 'site:{target} inurl:(phpmyadmin OR adminer OR dbadmin OR wp-login)'),
    # API & Dev
    ("Swagger/API docs", 'site:{target} inurl:(swagger OR api-docs OR openapi OR graphql)'),
    ("Git expostos", 'site:{target} inurl:(.git OR .svn OR .env OR .htaccess)'),
    ("Debug mode", 'site:{target} intitle:("Django" OR "Traceback" OR "Debug" OR "phpinfo")'),
    # Dados
    ("Emails expostos", 'site:{target} intext:("@{target}" OR "email" OR "contact")'),
    ("Subdomínios indexados", 'site:*.{target} -www'),
    # Vulns
    ("Open Redirect", 'site:{target} inurl:(redirect OR redir OR url= OR next= OR return=)'),
    ("SQL errors", 'site:{target} intext:("mysql" OR "syntax error" OR "ORA-" OR "PostgreSQL")'),
    ("Directory listing", 'site:{target} intitle:"Index of /"'),
    # Third party leaks
    ("GitHub leaks", '"{target}" (password OR secret OR token OR api_key) site:github.com'),
    ("Pastebin leaks", '"{target}" site:pastebin.com'),
    ("Trello boards", '"{target}" site:trello.com'),
]


def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟩───────────────────────────────────────────────────────────🟩\n"
        f"   🔍 {C.BOLD}{C.CYAN}GOOGLE DORKS GENERATOR{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟩───────────────────────────────────────────────────────────🟩\n"
    )

    outdir = ensure_outdir(target, "google_dorks")

    # V10.5: Usar target diretamente — evita trocar acionista.com.br por com.br
    base_domain = target

    dorks = []
    for category, template in DORK_TEMPLATES:
        query = template.format(target=base_domain)
        google_url = f"https://www.google.com/search?q={quote_plus(query)}"
        dorks.append({
            "category": category,
            "query": query,
            "google_url": google_url,
        })

    # Salvar JSON
    output_file = outdir / "dorks_results.json"
    output_file.write_text(json.dumps(dorks, indent=2, ensure_ascii=False))

    # Salvar TXT para copiar rápido
    txt_file = outdir / "dorks_generated.txt"
    lines = []
    for d in dorks:
        lines.append(f"# {d['category']}")
        lines.append(d['query'])
        lines.append(d['google_url'])
        lines.append("")
    txt_file.write_text("\n".join(lines))

    info(f"   📋 {len(dorks)} dorks gerados para '{base_domain}'")
    for d in dorks[:5]:
        info(f"      🔎 [{d['category']}] {d['query'][:80]}")
    if len(dorks) > 5:
        info(f"      ... e mais {len(dorks) - 5} dorks")

    summary = {"dorks_generated": len(dorks), "status": "COMPLETED"}
    (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))

    success(f"   📂 Dorks salvos em {txt_file}")
    return dorks
