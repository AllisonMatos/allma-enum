#!/usr/bin/env python3
from pathlib import Path
import re
import json
import time
from urllib.parse import urljoin

from menu import C

from ..output import info, warn, success
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


# === REQUEST REDUZIDO (httpx ou requests) ===
def http_get_text(url, timeout=6):
    try:
        import httpx
        try:
            with httpx.Client(follow_redirects=True, timeout=timeout) as c:
                r = c.get(url)
                return (r.status_code, r.text, dict(r.headers))
        except Exception:
            pass
    except Exception:
        pass

    try:
        import requests
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=True)
            return (r.status_code, r.text, dict(r.headers))
        except Exception:
            return (None, None, None)
    except Exception:
        return (None, None, None)


# === EXTRAÇÃO DE ENDPOINTS EM TEXTO ===
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
        f"   🛰️  {C.BOLD}{C.CYAN}INICIANDO MÓDULO: ENDPOINT DISCOVERY{C.END}\n"
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
    info(f"{C.BOLD}{C.BLUE}🌐 Analisando páginas HTML (urls_200)...{C.END}")

    urls_200 = Path("output") / target / "urls" / "urls_200.txt"
    if urls_200.exists():
        pages = read_list_file(urls_200)
        for p in pages:
            info(f"   🔎 lendo: {C.YELLOW}{p}{C.END}")
            status, text, headers = http_get_text(p)
            if text:
                found = extract_from_text(text, base_url=p)
                candidates.update(found)
    else:
        warn(f"⚠️ Nenhum arquivo urls_200 encontrado para {target}")

    # ==============================
    # ⚡ ETAPA 2 — ANALISAR JS E LISTAS
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
