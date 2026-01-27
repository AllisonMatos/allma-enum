#!/usr/bin/env python3
"""
Plugin ENDPOINT — Async Version
"""

from pathlib import Path
import re
import json
import time
from urllib.parse import urljoin
import asyncio

from menu import C
from ..output import info, warn, success, error
from .utils import ensure_outdir

# === PATTERNS PARA EXTRAÇÃO ===
PATTERNS = [
    r'["\'](/api/[A-Za-z0-9_\-\/\.?=&%]+)["\']',
    r'["\'](/v[0-9]+/[A-Za-z0-9_\-\/\.?=&%]+)["\']',
    r'["\'](/graphql(?:[A-Za-z0-9_\-\/\.?=&%]*)?)["\']',
    r'["\'](/auth[A-Za-z0-9_\-\/\.?=&%]*)["\']',
    r'fetch\(\s*["\']([^"\']+)["\']',
    r'axios\.\w+\(\s*["\']([^"\']+)["\']',
    r'["\'](https?://[^\s"\']+/graphql[^"\']*)["\']',
    r'["\'](https?://[^\s"\']+/api[^\']*)["\']'
]

CONCURRENCY_LIMIT = 10
DELAY = 0.5

# === EXTRAÇÃO DE ENDPOINTS EM TEXTO (CPU Bound) ===
def extract_from_text(text, base_url=None):
    found = set()
    for p in PATTERNS:
        for m in re.findall(p, text or "", flags=re.I):
            if m.startswith("/"):
                if base_url:
                    found.add(urljoin(base_url, m))
                else:
                    found.add(m)
            else:
                found.add(m)
    return found

def read_list_file(path):
    if not path.exists():
        return []
    return [l.strip() for l in path.read_text(errors="ignore").splitlines() if l.strip()]

# === ASYNC CRAWLER ===
async def fetch_and_analyze(client, url, semaphore):
    async with semaphore:
        await asyncio.sleep(DELAY)
        
        for attempt in range(3):
            try:
                resp = await client.get(url)
                
                if resp.status_code == 429 or resp.status_code >= 500:
                    await asyncio.sleep((attempt + 1) * 2)
                    continue

                if resp.status_code == 200:
                    return extract_from_text(resp.text, base_url=url)
                return set()
            except:
                await asyncio.sleep(1)
                
    return set()

async def run_full_scan_async(target, pages):
    import httpx
    candidates = set()
    sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
    
    info(f"{C.BOLD}{C.BLUE}🌐 Analisando {len(pages)} páginas HTML (Async)...{C.END}")
    
    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as client:
        tasks = [fetch_and_analyze(client, p, sem) for p in pages]
        
        # Executar com barra de progresso simples
        total = len(tasks)
        completed = 0
        
        for coro in asyncio.as_completed(tasks):
            res = await coro
            completed += 1
            if completed % 10 == 0:
                print(f"   Processados: {completed}/{total}", end="\r")
            
            if res:
                candidates.update(res)
                
    print("") # Newline
    return candidates


# === MAIN ===
def run(context: dict):
    start = time.time()
    target = context.get("target")

    if not target:
        raise ValueError("context['target'] é obrigatório para plugin endpoint")

    # ==============================
    # 🎯 CABEÇALHO PREMIUM
    # ==============================
    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   🛰️  {C.BOLD}{C.CYAN}INICIANDO MÓDULO: ENDPOINT DISCOVERY (ASYNC){C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    # Criar diretórios
    outdir = ensure_outdir(target)
    endpoints_file = outdir / "endpoints.txt"
    graphql_file = outdir / "graphql.txt"
    raw_file = outdir / "raw_endpoints.json"

    candidates = set()

    # ==============================
    # 🌐 ETAPA 1 — ANALISAR URLS_200
    # ==============================
    
    urls_200 = Path("output") / target / "urls" / "urls_200.txt"
    if urls_200.exists():
        pages = read_list_file(urls_200)
        if pages:
            # Check httpx
            try:
                import httpx
                found = asyncio.run(run_full_scan_async(target, pages))
                candidates.update(found)
            except ImportError:
                error("Biblioteca 'httpx' não instalada de endpoints async.")
            except Exception as e:
                error(f"Erro no scan async: {e}")
    else:
        warn(f"⚠️ Nenhum arquivo urls_200 encontrado para {target}")

    # ==============================
    # ⚡ ETAPA 2 — ANALISAR JS E LISTAS (LOCAL)
    # ==============================
    info(f"\n{C.BOLD}{C.BLUE}⚡ Analisando arquivos JS e listas auxiliares...{C.END}")

    js_lists = [
        Path("output") / target / "jsscanner" / "jsscanner_list.txt",
        Path("output") / target / "files" / "files_by_extension.txt",
        Path("output") / target / "urls" / "url_completas.txt"
    ]

    for p in js_lists:
        if p.exists():
            info(f"   📄 lendo: {C.YELLOW}{p}{C.END}")
            txt = p.read_text(errors="ignore")
            found = extract_from_text(txt)
            candidates.update(found)

    # ==============================
    # 🔍 ORGANIZAR RESULTADOS
    # ==============================
    info(f"\n{C.BOLD}{C.BLUE}🔍 Organizandos endpoints...{C.END}")

    endpoints = sorted([e for e in candidates if "graphql" not in e.lower()])
    graphqls = sorted([e for e in candidates if "graphql" in e.lower()])

    # salvar endpoints
    if endpoints:
        endpoints_file.write_text("\n".join(endpoints) + "\n")
        info(f"   💾 Endpoints salvos em: {C.GREEN}{endpoints_file}{C.END}")
    else:
        info("   ❕ Nenhum endpoint REST encontrado.")

    # salvar graphql
    if graphqls:
        graphql_file.write_text("\n".join(graphqls) + "\n")
        info(f"   💾 GraphQLs salvos em: {C.GREEN}{graphql_file}{C.END}")
    else:
        info("   ❕ Nenhum endpoint GraphQL encontrado.")

    # salvar JSON bruto
    raw_file.write_text(
        json.dumps(
            {"endpoints": endpoints, "graphql": graphqls},
            indent=2,
            ensure_ascii=False
        )
    )

    # ==============================
    # 🎉 FINALIZAÇÃO
    # ==============================
    t = time.time() - start

    success(
        f"\n{C.GREEN}{C.BOLD}✔ ENDPOINT discovery finalizado!{C.END}\n"
        f"🔎 Endpoints REST: {C.YELLOW}{len(endpoints)}{C.END}\n"
        f"🧬 GraphQL: {C.YELLOW}{len(graphqls)}{C.END}\n"
        f"⏱️ Tempo total: {C.CYAN}{t:.1f}s{C.END}\n"
        f"📁 Output: {C.CYAN}{outdir}{C.END}\n"
    )

    return [
        str(endpoints_file) if endpoints else "",
        str(graphql_file) if graphqls else "",
        str(raw_file)
    ]
