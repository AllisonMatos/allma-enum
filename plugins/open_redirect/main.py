#!/usr/bin/env python3
"""
Open Redirect Detection (V10 Pro) — Detecta redirecionamentos abertos com validação real.
Inclui bypasses modernos (@, path traversal, javascript:) e suporte a POST.
"""
import json
import time
import httpx
from pathlib import Path
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config import DEFAULT_USER_AGENT, REQUEST_DELAY, DEFAULT_TIMEOUT
from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from ..http_utils import format_http_request, format_http_response

# Parâmetros suspeitos de redirect
REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "next", "url", "return",
    "rurl", "dest", "destination", "redir", "return_url", "return_to",
    "checkout_url", "continue", "goto", "returl", "returnTo", "forward",
    "target", "out", "view", "to", "ref", "callback", "r",
]

EVIL_DOMAIN = "evil.com"

def _build_payloads(deep: bool = False):
    payloads = [
        f"https://{EVIL_DOMAIN}",
        f"//{EVIL_DOMAIN}",
        f"/\\{EVIL_DOMAIN}",
        f"https://{EVIL_DOMAIN}/%2f..",
        f"//{EVIL_DOMAIN}%2f%2e%2e%2f",
        "javascript:alert(1)", # XSS/Redirect combo
    ]
    
    if deep:
        payloads.extend([
            f"https://google.com@{EVIL_DOMAIN}", # @ bypass
            f"/%0d%0aLocation: https://{EVIL_DOMAIN}", # CRLF
            f"/%2f%2f{EVIL_DOMAIN}",
            f"http://{EVIL_DOMAIN}",
        ])
    return payloads


def _test_redirect(url: str, param: str, payload: str, method: str = "GET") -> dict | None:
    """Testa um payload de open redirect com validação real (follow_redirects)."""
    parsed = urlparse(url)
    
    test_url = url
    data = None
    
    if method == "GET":
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        new_query = urlencode(qs, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
    else:
        # POST: assume param no body
        data = {param: payload}

    try:
        # Usamos follow_redirects=True para ver se chegamos no destino do mal
        with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=True) as client:
            if method == "GET":
                resp = client.get(test_url, headers={"User-Agent": DEFAULT_USER_AGENT})
            else:
                resp = client.post(test_url, data=data, headers={"User-Agent": DEFAULT_USER_AGENT})

            # Critério de sucesso: a URL final (history) contém o domínio maligno
            final_url = str(resp.url).lower()
            
            # Verificar se algum redirecionamento na cadeia continha o evil domain
            is_confirmed = EVIL_DOMAIN.lower() in final_url
            for r in resp.history:
                if EVIL_DOMAIN.lower() in r.headers.get("location", "").lower():
                    is_confirmed = True
                    break
            
            # Caso especial: javascript:
            if payload.startswith("javascript:") and payload.lower() in resp.text.lower():
                is_confirmed = True

            if is_confirmed:
                return {
                    "url": url,
                    "test_url": test_url,
                    "method": method,
                    "parameter": param,
                    "payload": payload,
                    "status_history": [r.status_code for r in resp.history],
                    "final_url": final_url,
                    "risk": "HIGH",
                    "type": "OPEN_REDIRECT",
                    "details": f"Redirecionamento Aberto Confirmado ({method}) via '{param}': Destino final: {final_url}",
                    "request_raw": format_http_request(resp.request),
                    "response_raw": format_http_response(resp),
                }
    except Exception:
        pass
    return None


def run(context: dict):
    target = context.get("target")
    deep = context.get("deep", False)
    stealth = context.get("stealth", False)
    
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟧───────────────────────────────────────────────────────────🟧\n"
        f"   🔀 {C.BOLD}{C.CYAN}OPEN REDIRECT DETECTION (V10 PRO){C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END} | Deep: {deep} | POST: Habilitado\n"
        f"🟧───────────────────────────────────────────────────────────🟧\n"
    )

    outdir = ensure_outdir(target, "open_redirect")
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    
    if not urls_file.exists():
        warn("⚠️ urls_200.txt não encontrado.")
        summary = {"tests_run": 0, "urls_checked": 0, "findings": 0, "status": "NO_INPUT"}
        (outdir / "open_redirect_results.json").write_text(json.dumps([], indent=2))
        (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))
        return []

    all_urls = [l.strip() for l in urls_file.read_text(errors="ignore").splitlines() if l.strip()]
    payloads = _build_payloads(deep)

    # Filtrar candidatos
    candidates = []
    for url in all_urls:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        for p in REDIRECT_PARAMS:
            if p in qs or p.lower() in {k.lower() for k in qs}:
                candidates.append((url, p))

    # Adicionar base URLs se deep
    if deep:
        for p in REDIRECT_PARAMS[:5]:
            candidates.append((f"https://{target}/login", p))
            candidates.append((f"https://{target}/logout", p))

    candidates = list(set(candidates))[:80]
    max_workers = 3 if stealth else 10
    
    info(f"   📋 Testando {len(candidates)} vetores de redirecionamento com confirmação real")

    results = []
    tests_run = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for url, param in candidates:
            for payload in payloads:
                tests_run += 1
                futures.append(executor.submit(_test_redirect, url, param, payload, "GET"))
                if deep: # Testar POST no deep mode
                    futures.append(executor.submit(_test_redirect, url, param, payload, "POST"))

        for future in as_completed(futures):
            try:
                res = future.result()
                if res:
                    results.append(res)
                    info(f"   🔴 {C.RED}[HIGH]{C.END} {res['url']} — '{res['parameter']}' -> {res['final_url']}")
            except Exception:
                pass

    output_file = outdir / "open_redirect_results.json"
    output_file.write_text(json.dumps(results, indent=2, ensure_ascii=False))

    summary = {"tests_run": tests_run, "urls_checked": len(candidates), "findings": len(results), "status": "COMPLETED"}
    (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))

    if results:
        success(f"\n   🔀 {len(results)} Open Redirect(s) CONFIRMADO(s)!")
    else:
        info(f"   ✅ 0 Open Redirects em {len(candidates)} candidatos ({tests_run} requests).")

    success(f"   📂 Salvos em {output_file}")
    return results
