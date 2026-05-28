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
    ("StackOverflow leaks", '"{target}" (key OR token OR password OR secret) site:stackoverflow.com'),
    ("Jira / Confluence", '"{target}" site:atlassian.net'),
    # Cloud storage leaks
    ("AWS S3 Buckets", 'site:s3.amazonaws.com "{target}"'),
    ("Azure Blob Storage", 'site:blob.core.windows.net "{target}"'),
    ("GCP Storage", 'site:storage.googleapis.com "{target}"'),
    # Pro mode - aggressive but still relevant
    ("Env Leaks", 'site:{target} inurl:.env OR intext:"APP_KEY=" OR intext:"DB_PASSWORD="'),
    ("JWT/Token leaks", 'site:{target} (intext:"eyJ" OR intext:"Bearer " OR intext:"api_key")'),
    ("Backup keyword leaks", 'site:{target} (intitle:"index of" AND ("backup" OR "dump" OR "old"))'),
    ("Kibana/Elastic admin", 'site:{target} inurl:(kibana OR _cat/indices OR _search)'),
    ("Debug endpoints", 'site:{target} inurl:(actuator OR phpinfo OR debug OR whoops OR ignition)'),
    ("Public buckets references", '"{target}" ("s3.amazonaws.com" OR "blob.core.windows.net" OR "storage.googleapis.com")'),
]

TECH_DORKS = {
    "wordpress": [
        ("WordPress Exposed Plugins", 'site:{target} inurl:/wp-content/plugins/'),
        ("WordPress Config Leaks", 'site:{target} inurl:wp-config.php OR inurl:/wp-json/wp/v2/users'),
    ],
    "graphql": [
        ("GraphQL Operations", 'site:{target} ("query {" OR "mutation {" OR "__schema")'),
    ],
    "swagger": [
        ("Swagger Specs", 'site:{target} (inurl:swagger.json OR inurl:openapi.json OR inurl:v3/api-docs)'),
    ],
    "django": [
        ("Django Debug Leaks", 'site:{target} intitle:"Django" OR intext:"SECRET_KEY"'),
    ],
    "laravel": [
        ("Laravel Env Exposure", 'site:{target} intext:"APP_KEY=" OR inurl:.env'),
    ],
    "react": [
        ("React Source Maps", 'site:{target} inurl:.js.map'),
    ],
    "next.js": [
        ("Next.js Data Leaks", 'site:{target} inurl:/_next/data/ filetype:json'),
    ],
}


def _load_detected_technologies(base_out: Path) -> set[str]:
    tech_hits = set()
    candidate_files = [
        base_out / "domain" / "technologies.json",
        base_out / "fingerprint" / "wappalyzer.json",
    ]
    for f in candidate_files:
        if not f.exists():
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue

        if isinstance(data, dict):
            # technologies.json => {host: {"technologies":[{"name":"..."}]}}
            for val in data.values():
                if isinstance(val, dict) and isinstance(val.get("technologies"), list):
                    for t in val.get("technologies", []):
                        if isinstance(t, dict):
                            n = str(t.get("name", "")).strip().lower()
                            if n:
                                tech_hits.add(n)
                else:
                    # wappalyzer.json legacy map {tech: {...}}
                    k = str(val).strip().lower()
                    if k:
                        tech_hits.add(k)
            for k in data.keys():
                ks = str(k).strip().lower()
                if ks:
                    tech_hits.add(ks)
    return tech_hits


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

    mode = context.get("mode", "pro")
    detected_techs = _load_detected_technologies(Path("output") / target)
    dorks = []
    seen_queries = set()
    for category, template in DORK_TEMPLATES:
        query = template.format(target=base_domain)
        if query in seen_queries:
            continue
        seen_queries.add(query)
        google_url = f"https://www.google.com/search?q={quote_plus(query)}"
        dorks.append({
            "category": category,
            "query": query,
            "google_url": google_url,
            "mode": mode
        })

    # Adaptive expansion based on detected stack/fingerprint.
    for tech_key, templates in TECH_DORKS.items():
        if not any(tech_key in t for t in detected_techs):
            continue
        for category, template in templates:
            query = template.format(target=base_domain)
            if query in seen_queries:
                continue
            seen_queries.add(query)
            google_url = f"https://www.google.com/search?q={quote_plus(query)}"
            dorks.append({
                "category": f"{category} [tech:{tech_key}]",
                "query": query,
                "google_url": google_url,
                "mode": mode
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
    # V12: dorks são utilitários — não gerar findings normalizados (evita poluir score do report)
    return []
