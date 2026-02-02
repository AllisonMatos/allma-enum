#!/usr/bin/env python3
"""
Plugin JSSCANNER — Optimized Async Version
"""

import asyncio
from pathlib import Path
import subprocess
import shutil
import tempfile
import re
import time
from urllib.parse import urljoin

from menu import C
from ..output import info, warn, error, success
from .utils import ensure_outdir
from core.utils import find_tool

# ============================================================
# REGEX CONFIG
# ============================================================
SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
RE_URL = re.compile(r"https?://[^\s'\"<>]+")
RE_KEY  = re.compile(r"(?i)(apikey|token|secret|bearer)[\s'\":=]{1,8}([A-Za-z0-9\-_]{8,128})")

CONCURRENCY_LIMIT = 10
DELAY = 0.5

# ============================================================
# ASYNC HELPERS
# ============================================================
async def extract_js_from_html_async(client, url, semaphore):
    """Baixa HTML e extrai <script src=""> (.js) de forma assíncrona com retry"""
    async with semaphore:
        await asyncio.sleep(DELAY)
        
        for attempt in range(3):
            try:
                r = await client.get(url, timeout=10)
                if r.status_code == 429:
                    await asyncio.sleep((attempt + 1) * 2)
                    continue
                    
                if r.status_code != 200 or "html" not in r.headers.get("content-type", ""):
                    return []
                
                html = r.text
                js_urls = []
                for src in SCRIPT_SRC_RE.findall(html):
                    full = urljoin(url, src)
                    if full.lower().split("?")[0].endswith(".js"):
                        js_urls.append(full)
                return js_urls
            except Exception:
                await asyncio.sleep(1)
        return []

async def analyze_js_file_async(client, url, semaphore):
    """Baixa e analisa um único arquivo JS"""
    async with semaphore:
        await asyncio.sleep(DELAY)
        try:
            r = await client.get(url, follow_redirects=True, timeout=15)
            if r.status_code != 200:
                return None
            
            text = r.text
            # Basic analysis
            found_urls = RE_URL.findall(text)
            found_keys = [m[1] for m in RE_KEY.findall(text)]
            
            return {
                "url": url,
                "text": text[:50000], # Limit size for raw log
                "urls": found_urls[:100],
                "keys": found_keys
            }
        except Exception:
            return None

# ============================================================
# SYNC HELPERS (Legacy/Utils)
# ============================================================
def gather_js_urls(target: str) -> list:
    """Coleta URLs de arquivos JS de múltiplas fontes"""
    import json
    
    base = Path("output") / target / "files"
    domain_base = Path("output") / target / "domain"
    urls = []

    # 1. Arquivos de texto tradicionais
    files_to_check = [
        base / "js.txt",
        domain_base / "extracted_js.txt"
    ]

    for f in files_to_check:
        if f.exists():
            urls.extend([l.strip() for l in f.read_text(errors="ignore").splitlines() if l.strip()])
    
    # 2. Check files_by_extension
    f2 = base / "files_by_extension.txt"
    if f2.exists():
        txt = f2.read_text(errors="ignore")
        m = re.search(r"===\s*\.js\s*===(.*?)(?:\n===|\Z)", txt, flags=re.S)
        if m:
            urls.extend([l.strip() for l in m.group(1).splitlines() if l.strip()])
    
    # 3. LER extracted_js.json do DOMAIN (fonte principal com 250+ arquivos)
    extracted_js_json = domain_base / "extracted_js.json"
    if extracted_js_json.exists():
        try:
            data = json.loads(extracted_js_json.read_text(errors="ignore"))
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and "url" in item:
                        urls.append(item["url"])
                    elif isinstance(item, str):
                        urls.append(item)
            info(f"   📄 Carregados {len(data)} JS de extracted_js.json")
        except Exception as e:
            warn(f"   ⚠️ Erro ao ler extracted_js.json: {e}")
    
    return sorted(set(urls))

def locate_jsscanner():
    return find_tool("JSScanner.py")

# ============================================================
# MAIN LOGIC
# ============================================================
async def run_async_scan(target, report_file, raw_file):
    import httpx
    
    info(f"{C.BOLD}{C.BLUE}🚀 Iniciando Scan Otimizado (Async)...{C.END}")
    
    # 1. Coletar JS conhecidos
    js_urls = gather_js_urls(target)
    info(f"   - {len(js_urls)} arquivos JS já conhecidos.")

    # 2. Extrair JS de páginas HTML (Urls 200)
    urls_200_path = Path("output") / target / "urls" / "urls_200.txt"
    if urls_200_path.exists():
        html_pages = [l.strip() for l in urls_200_path.read_text().splitlines() if l.strip()]
        if html_pages:
            info(f"   - Analisando {len(html_pages)} páginas HTML para descobrir novos JS...")
            
            sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
            async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
                tasks = [extract_js_from_html_async(client, u, sem) for u in html_pages]
                results = await asyncio.gather(*tasks)
                
                for res in results:
                    js_urls.extend(res)
            
            js_urls = sorted(set(js_urls))
            success(f"   - Total de JS para análise: {len(js_urls)}")

    if not js_urls:
        warn("⚠️ Nenhum arquivo JS encontrado para análise.")
        return

    # 3. Analisar conteúdo dos JS
    info(f"{C.BOLD}{C.BLUE}⚡ Baixando e analisando {len(js_urls)} arquivos JS em paralelo...{C.END}")
    
    results_data = []
    sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
    
    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        tasks = [analyze_js_file_async(client, u, sem) for u in js_urls]
        
        # Progress bar simple
        total = len(tasks)
        completed = 0
        
        for coro in asyncio.as_completed(tasks):
            res = await coro
            completed += 1
            if completed % 10 == 0:
                print(f"      Processados: {completed}/{total}", end="\r")
            
            if res:
                results_data.append(res)
                
    print("") # Newline after progress
    
    # 4. Save Results
    info("💾 Salvando relatório...")
    
    with raw_file.open("w") as f_raw, report_file.open("w") as f_rep:
        for item in results_data:
            # Raw
            f_raw.write(f"=== FILE: {item['url']} ===\n")
            f_raw.write(item['text'] + "\n\n")
            
            # Report
            if item['urls'] or item['keys']:
                f_rep.write(f"FILE: {item['url']}\n")
                if item['urls']:
                    f_rep.write("  URLs found:\n")
                    for u in item['urls']:
                        f_rep.write(f"    - {u}\n")
                if item['keys']:
                    f_rep.write("  KEYS found:\n")
                    for k in item['keys']:
                        f_rep.write(f"    - {k}\n")
                f_rep.write("\n")

    success(f"✔ Scan concluído! Relatório salvo em: {report_file}")


def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   ⚡ {C.BOLD}{C.CYAN}INICIANDO MÓDULO: JSSCANNER (ASYNC){C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    outdir = ensure_outdir(target)
    report_file = outdir / "jsscanner_report.txt"
    raw_file = outdir / "jsscanner_raw.txt"

    # Check for httpx
    try:
        import httpx
    except ImportError:
        error("Biblioteca 'httpx' não instalada. Instale com: pip install httpx")
        return []

    try:
        asyncio.run(run_async_scan(target, report_file, raw_file))
        return [str(report_file), str(raw_file)]
    except KeyboardInterrupt:
        warn("Scan interrompido pelo usuário.")
        return []
    except Exception as e:
        import traceback
        error(f"Erro no async scanner: {e}")
        traceback.print_exc()
        return []
