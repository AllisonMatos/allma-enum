#!/usr/bin/env python3
"""
Wayback Machine JS Snapshot Diffing
Busca versões antigas de arquivos JS e compara as rotas com as versões atuais.
"""
import asyncio
import json
from pathlib import Path
import httpx
from urllib.parse import urlparse

from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from plugins.extractors.js_analyzer import extract_js_logic
from plugins.validation import finding

WAYBACK_CDX_URL = "https://web.archive.org/cdx/search/cdx"
WAYBACK_FILE_URL = "https://web.archive.org/web/{}id_/{}"

async def fetch_oldest_snapshot(client, url):
    """Obtém a versão mais antiga de um arquivo JS no Wayback Machine."""
    try:
        params = {
            "url": url,
            "output": "json",
            "limit": 1,
            "fl": "timestamp,original",
            "collapse": "urlkey",
            "filter": "statuscode:200"
        }
        r = await client.get(WAYBACK_CDX_URL, params=params, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if len(data) > 1: # data[0] is header
                timestamp = data[1][0]
                original = data[1][1]
                
                # Fetch content
                content_url = WAYBACK_FILE_URL.format(timestamp, original)
                res = await client.get(content_url, timeout=15)
                if res.status_code == 200:
                    return res.text
    except Exception:
        pass
    return None

async def run_diff_async(target, outdir):
    js_routes_file = Path("output") / target / "jsscanner" / "js_routes.json"
    if not js_routes_file.exists():
        warn("   ⚠️ js_routes.json não encontrado. Execute o jsscanner primeiro.")
        return []

    try:
        current_data = json.loads(js_routes_file.read_text())
    except Exception:
        warn("   ⚠️ Erro lendo js_routes.json.")
        return []
        
    current_routes = set()
    for item in current_data:
        current_routes.update(item.get("routes", []))
        
    if not current_routes:
        warn("   ⚠️ Nenhuma rota atual para comparar.")
        return []

    # Get the list of JS files to diff
    js_files_path = Path("output") / target / "domain" / "extracted_js.json"
    js_urls = []
    if js_files_path.exists():
        try:
            data = json.loads(js_files_path.read_text())
            for d in data:
                if isinstance(d, dict) and "url" in d:
                    js_urls.append(d["url"])
                elif isinstance(d, str):
                    js_urls.append(d)
        except Exception:
            pass
            
    # Limit to main bundles to avoid massive requests
    main_bundles = [u for u in js_urls if "main" in u or "app" in u or "bundle" in u][:5]
    if not main_bundles:
        main_bundles = js_urls[:5] # Fallback to first 5

    if not main_bundles:
        warn("   ⚠️ Nenhum JS encontrado para buscar histórico.")
        return []

    info(f"   ⏳ Buscando histórico no Wayback Machine para {len(main_bundles)} arquivos JS principais...")
    
    historical_routes = set()
    async with httpx.AsyncClient(verify=False) as client:
        tasks = [fetch_oldest_snapshot(client, u) for u in main_bundles]
        results = await asyncio.gather(*tasks)
        
        for url, old_js in zip(main_bundles, results):
            if old_js:
                try:
                    logic = extract_js_logic(old_js, url)
                    historical_routes.update(logic.get("routes", []))
                except Exception:
                    pass

    abandoned_routes = historical_routes - current_routes
    
    findings = []
    if abandoned_routes:
        success(f"   🚨 {len(abandoned_routes)} rotas antigas/abandonadas encontradas!")
        for route in abandoned_routes:
            findings.append(
                finding(
                    plugin="wayback_diff",
                    target=target,
                    title="Abandoned JS API Route",
                    issue_type="ABANDONED_API_ROUTE",
                    risk="MEDIUM",
                    confidence="HIGH",
                    description=f"Rota encontrada no histórico do Wayback Machine que não está presente na versão atual do frontend.",
                    url=f"https://{target}{route}",
                    detection={"route": route},
                    validation={"wayback_machine": True},
                    evidence={"observable_impact": "shadow_api"}
                )
            )
            
        out_file = outdir / "findings.json"
        out_file.write_text(json.dumps(findings, indent=2, ensure_ascii=False))
        
        diff_file = outdir / "abandoned_routes.txt"
        diff_file.write_text("\n".join(abandoned_routes))
        info(f"   📂 Rotas abandonadas salvas em {diff_file}")
    else:
        info("   ✅ Nenhuma rota abandonada encontrada no histórico.")
        
    return findings


def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟩───────────────────────────────────────────────────────────🟩\n"
        f"   🕒 {C.BOLD}{C.CYAN}WAYBACK SNAPSHOT DIFFING{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟩───────────────────────────────────────────────────────────🟩\n"
    )

    outdir = ensure_outdir(target, "wayback_diff")
    
    try:
        findings = asyncio.run(run_diff_async(target, outdir))
        return findings
    except Exception as e:
        warn(f"   ⚠️ Erro executando snapshot diffing: {e}")
        return []
