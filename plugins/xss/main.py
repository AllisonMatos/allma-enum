#!/usr/bin/env python3
"""
plugins/xss/main.py - XSS passive scanner (crawler + DOM + reflections)
Corrigido para:
 - nunca travar em redirects
 - nunca travar em timeouts
 - fail-fast
"""

from pathlib import Path
from urllib.parse import urlparse, parse_qsl, urljoin
import re
import time
import html
import collections

from menu import C

from ..output import info, warn, success
from .utils import ensure_outdir

# ============================================================
# FAIL-FAST HTTP CLIENT
# ============================================================
def http_get_text(url, timeout=6):
    """GET resiliente (fail-fast, sem travar nunca)."""
    try:
        import httpx
        try:
            with httpx.Client(follow_redirects=True, timeout=timeout) as c:
                r = c.get(url)
                return (r.status_code, r.text, r.headers)
        except Exception:
            pass
    except Exception:
        pass

    try:
        import requests
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=True)
            return (r.status_code, r.text, r.headers)
        except Exception:
            return (None, None, None)
    except Exception:
        return (None, None, None)

# ============================================================
# REGEX PATTERNS
# ============================================================
PARAM_MIN_LEN = 1

DOM_PATTERNS = [
    r"\binnerHTML\b", r"\bouterHTML\b", r"\bdocument\.write\b",
    r"\beval\s*\(", r"\bnew\s+Function\s*\(",
    r"\bsetTimeout\s*\(", r"\bsetInterval\s*\(",
    r"\blocation\s*=", r"\bwindow\.location\b",
    r"\bdocument\.location\b", r"\bwindow\.name\b",
    r"\bpostMessage\s*\(", r"\bunescape\s*\(",
    r"\bdocument\.cookie\b"
]

JS_PATTERNS = DOM_PATTERNS + [
    r"\bfetch\s*\(", r"\baxios\.", r"\bXMLHttpRequest\b",
    r"[A-Za-z0-9\-_]{20,}"
]

SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
INLINE_SCRIPT_RE = re.compile(r'<script\b[^>]*>(.*?)</script>', re.I | re.S)
LINK_RE = re.compile(r'href=["\']([^"\']+)["\']', re.I)

# ============================================================
# HELPERS
# ============================================================
def find_script_srcs(html, base_url):
    return [urljoin(base_url, m) for m in SCRIPT_SRC_RE.findall(html or "")]

def find_inline_scripts(html):
    return [m.strip() for m in INLINE_SCRIPT_RE.findall(html or "") if m.strip()]

def find_links(html, base_url):
    return [urljoin(base_url, m) for m in LINK_RE.findall(html or "")]

def search_patterns(text, patterns):
    hits = []
    for p in patterns:
        try:
            if re.search(p, text or "", flags=re.I):
                hits.append(p)
        except Exception:
            pass
    return hits

def is_same_origin(base, target):
    try:
        t = urlparse(target).netloc
        return t == base or t.endswith("." + base)
    except:
        return False

# ============================================================
# MAIN
# ============================================================
def run(context: dict):
    start = time.time()

    target = context.get("target")
    depth = int(context.get("depth", 1))
    max_pages = 200

    if not target:
        raise ValueError("context['target'] é obrigatório no plugin XSS")

    # ==========================================================================
    # 🎯 CABEÇALHO PREMIUM
    # ==========================================================================
    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   🎭 {C.BOLD}{C.CYAN}INICIANDO MÓDULO: XSS PASSIVE SCAN{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"   📏 Profundidade (depth): {C.YELLOW}{depth}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    outdir = ensure_outdir(target)

    # arquivos de saída
    params_txt       = outdir / "parameters.txt"
    reflections_txt  = outdir / "reflections.txt"
    dom_txt          = outdir / "dom_suspects.txt"
    js_txt           = outdir / "js_suspects.txt"
    final_txt        = outdir / "final_report.txt"

    # entrada
    urls200 = Path("output") / target / "urls" / "urls_200.txt"
    if not urls200.exists():
        warn(f"⚠️ Arquivo não encontrado: {urls200}")
        return []

    seed = [u.strip() for u in urls200.read_text().splitlines() if u.strip()]
    if not seed:
        warn("⚠️ Nenhuma URL disponível para XSS scan.")
        return []

    info(f"{C.BOLD}{C.BLUE}🌐 Preparando seed URLs ({len(seed)})...{C.END}")

    to_visit = collections.deque()
    visited = set()

    for u in seed:
        to_visit.append((u, 0))

    base_netloc = urlparse(seed[0]).netloc

    params_found = []
    reflections_found = []
    dom_found = []
    js_found = []

    pages = 0

    # ==========================================================================
    # 🕷️ ETAPA 1 — CRAWLING + ANÁLISE
    # ==========================================================================
    info(f"\n{C.BOLD}{C.BLUE}🕷️ Iniciando crawler XSS...{C.END}")

    while to_visit and pages < max_pages:
        url, d = to_visit.popleft()

        if url in visited:
            continue
        if d > depth:
            continue

        visited.add(url)
        pages += 1

        info(f"   🔎 Fetch: {C.YELLOW}{url}{C.END}")

        status, text, headers = http_get_text(url)
        if status is None:
            warn(f"   ⚠️ Falha ao buscar {url}")
            continue

        text = text or ""
        content_type = headers.get("content-type", "") if headers else ""

        # -------------------------------------------------------
        # PARAMETROS
        # -------------------------------------------------------
        parsed = urlparse(url)
        qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
        for k, v in qs.items():
            if v and len(v) >= PARAM_MIN_LEN:
                params_found.append((url, k, v))
                if v in text:
                    idx = text.find(v)
                    snip = text[max(0, idx-50):idx+50]
                    reflections_found.append((url, k, v, snip))

        # -------------------------------------------------------
        # HTML / JS ANALYSIS
        # -------------------------------------------------------
        is_html = "html" in content_type.lower() or "<html" in text[:200].lower()
        if not is_html:
            continue

        # DOM patterns
        dom_hits = search_patterns(text, DOM_PATTERNS)
        for p in dom_hits:
            dom_found.append((url, p, p))

        # INLINE JS
        inline = find_inline_scripts(text)
        for code in inline:
            hits = search_patterns(code, JS_PATTERNS)
            for h in hits:
                js_found.append((url, h, h))

        # SCRIPT SRC
        scripts = find_script_srcs(text, url)
        for s in scripts:
            sst, scode, _ = http_get_text(s)
            if sst and scode:
                hits = search_patterns(scode, JS_PATTERNS)
                for h in hits:
                    js_found.append((s, h, h))

        # LINKS — CRAWL
        links = find_links(text, url)
        for l in links:
            if l not in visited and is_same_origin(base_netloc, l):
                to_visit.append((l, d+1))

        time.sleep(0.05)

    # ==========================================================================
    # 📑 ETAPA 2 — RELATÓRIOS
    # ==========================================================================
    info(f"\n{C.BOLD}{C.BLUE}📑 Gerando relatórios XSS...{C.END}")

    params_txt.write_text("\n".join(f"{u}\t{k}\t{v}" for u,k,v in params_found))
    reflections_txt.write_text("\n".join(f"{u}\t{k}\t{v}\n{snip}\n---" for u,k,v,snip in reflections_found))
    dom_txt.write_text("\n".join(f"{u}\t{p}\n{snip}\n---" for u,p,snip in dom_found))
    js_txt.write_text("\n".join(f"{u}\t{p}\n{snip}\n---" for u,p,snip in js_found))

    summary = [
        f"XSS Passive Scan - {target}",
        f"Páginas visitadas: {len(visited)}",
        f"Parâmetros: {len(params_found)}",
        f"Reflexões: {len(reflections_found)}",
        f"DOM suspects: {len(dom_found)}",
        f"JS suspects: {len(js_found)}",
        ""
    ]
    final_txt.write_text("\n".join(summary))

    # ==========================================================================
    # 🎉 FINALIZAÇÃO
    # ==========================================================================
    success(
        f"\n{C.GREEN}{C.BOLD}✔ XSS PASSIVE SCAN CONCLUÍDO!{C.END}\n"
        f"🔎 Total de páginas analisadas: {C.YELLOW}{len(visited)}{C.END}\n"
        f"💡 Reflexões encontradas: {C.YELLOW}{len(reflections_found)}{C.END}\n"
        f"🧬 DOM Suspects: {C.YELLOW}{len(dom_found)}{C.END}\n"
        f"⚡ JS Suspects: {C.YELLOW}{len(js_found)}{C.END}\n"
        f"📄 Relatório final: {C.CYAN}{final_txt}{C.END}\n"
    )

    return [str(final_txt)]
