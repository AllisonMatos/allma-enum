#!/usr/bin/env python3
"""
plugins/wordlist/main.py

Extrai wordlists passivas:
 - paths.txt
 - params.txt
 - js_words.txt
 - combined.txt
Fonte: urls_200, url_completas, files_by_extension, jsscanner_list
"""

from pathlib import Path
import re
import time
import json
from urllib.parse import urlparse, parse_qs

from menu import C

from ..output import info, warn, success
from .utils import ensure_outdir

# ---------------------------------------------------
# Tokenizadores simples
# ---------------------------------------------------
RE_WORD = re.compile(r"[A-Za-z0-9\-_]{3,60}")
RE_PATH_SEG = re.compile(r"/([A-Za-z0-9\-_]{2,80})")

def read_lines(p: Path):
    if not p.exists():
        return []
    return [l.strip() for l in p.read_text(errors="ignore").splitlines() if l.strip()]

def extract_from_url(url):
    path = urlparse(url).path or ""
    segs = RE_PATH_SEG.findall(path)
    qs = parse_qs(urlparse(url).query)
    params = list(qs.keys())
    return segs, params

def extract_tokens_from_js(text):
    tokens = set(RE_WORD.findall(text or ""))
    tokens = {t for t in tokens if len(t) > 3 and not t.isdigit()}
    return tokens


# ---------------------------------------------------
# MAIN
# ---------------------------------------------------
def run(context: dict):
    start = time.time()
    target = context.get("target")

    if not target:
        raise ValueError("context['target'] é obrigatório para plugin wordlist")

    # ============================================================
    # 🎯 CABEÇALHO PREMIUM
    # ============================================================
    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   🗂️  {C.BOLD}{C.CYAN}INICIANDO MÓDULO: WORDLIST{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    outdir = ensure_outdir(target)

    paths_file = outdir / "paths.txt"
    params_file = outdir / "params.txt"
    js_words_file = outdir / "js_words.txt"
    combined_file = outdir / "combined.txt"

    # Fontes da wordlist
    sources = [
        Path("output") / target / "urls" / "urls_200.txt",
        Path("output") / target / "urls" / "url_completas.txt",
        Path("output") / target / "files" / "files_by_extension.txt",
        Path("output") / target / "jsscanner" / "jsscanner_list.txt",
    ]

    path_terms = set()
    param_terms = set()
    js_terms = set()

    # ============================================================
    # ETAPA 1 — Processar arquivos principais
    # ============================================================
    info(f"{C.BOLD}{C.BLUE}📁 Processando fontes de URLs e arquivos JS...{C.END}")

    for src in sources:
        lines = read_lines(src)
        if not lines:
            continue

        info(f"   🔎 Lendo {C.YELLOW}{src}{C.END} ({len(lines)} linhas)")

        for l in lines:
            if l.startswith("http"):
                segs, params = extract_from_url(l)
                path_terms.update(segs)
                param_terms.update(params)
            else:
                js_terms.update(extract_tokens_from_js(l))

    # ============================================================
    # ETAPA 2 — Baixar arquivos JS da lista e extrair tokens
    # ============================================================
    js_list = Path("output") / target / "jsscanner" / "jsscanner_list.txt"

    if js_list.exists():
        info(f"\n{C.BOLD}{C.BLUE}🌐 Extraindo tokens dos arquivos .js remotos...{C.END}")

        for u in read_lines(js_list):
            try:
                import httpx
                with httpx.Client(timeout=6, follow_redirects=True) as c:
                    r = c.get(u)
                    if r.status_code == 200 and r.text:
                        js_terms.update(extract_tokens_from_js(r.text))
            except:
                try:
                    import requests
                    r = requests.get(u, timeout=6)
                    if r.status_code == 200 and r.text:
                        js_terms.update(extract_tokens_from_js(r.text))
                except:
                    continue

    # ============================================================
    # ETAPA 3 — Ordenar & salvar wordlists
    # ============================================================
    info(f"\n{C.BOLD}{C.BLUE}💾 Salvando arquivos de wordlist...{C.END}")

    paths_sorted = sorted({p for p in path_terms if p})
    params_sorted = sorted({p for p in param_terms if p})
    js_sorted = sorted({p for p in js_terms if p})

    paths_file.write_text("\n".join(paths_sorted) + ("\n" if paths_sorted else ""))
    params_file.write_text("\n".join(params_sorted) + ("\n" if params_sorted else ""))
    js_words_file.write_text("\n".join(js_sorted) + ("\n" if js_sorted else ""))

    combined = sorted(set(paths_sorted) | set(params_sorted) | set(js_sorted))
    combined_file.write_text("\n".join(combined) + ("\n" if combined else ""))

    # ============================================================
    # 🎉 FINALIZAÇÃO
    # ============================================================
    t = time.time() - start

    success(
        f"\n{C.GREEN}{C.BOLD}✔ WORDLIST concluído com sucesso!{C.END}\n"
        f"📁 Termos totais: {C.YELLOW}{len(combined)}{C.END}\n"
        f"   🔸 Paths: {len(paths_sorted)}\n"
        f"   🔸 Params: {len(params_sorted)}\n"
        f"   🔸 Tokens JS: {len(js_sorted)}\n"
        f"⏱️ Tempo total: {C.CYAN}{t:.1f}s{C.END}\n"
        f"📂 Wordlists geradas em: {C.CYAN}{outdir}{C.END}\n"
    )

    return [
        str(paths_file),
        str(params_file),
        str(js_words_file),
        str(combined_file)
    ]
