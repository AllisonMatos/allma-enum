#!/usr/bin/env python3
"""
Open Redirect Detection — Detecta redirecionamentos abertos em parâmetros de URL.
Testa payloads canônicos e valida via status 3xx + Location header.
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

# Payloads de teste
PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com/%2f..",
    "////evil.com",
    "https:evil.com",
    "/\\/evil.com",
    "/.evil.com",
]

EVIL_DOMAINS = ["evil.com"]


def _has_redirect_param(url: str) -> list:
    """Retorna lista de parâmetros de redirect encontrados na URL."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    found = []
    for p in REDIRECT_PARAMS:
        if p in qs or p.lower() in {k.lower() for k in qs}:
            found.append(p)
    return found


def _test_redirect(url: str, param: str, payload: str) -> dict | None:
    """Testa um payload de open redirect em um parâmetro."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    try:
        with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=False) as client:
            resp = client.get(test_url, headers={"User-Agent": DEFAULT_USER_AGENT})

            # Verificar redirect para domínio externo
            location = resp.headers.get("location", "")
            is_redirect = 300 <= resp.status_code < 400

            if is_redirect and any(evil in location.lower() for evil in EVIL_DOMAINS):
                return {
                    "url": url,
                    "test_url": test_url,
                    "parameter": param,
                    "payload": payload,
                    "status": resp.status_code,
                    "location": location,
                    "risk": "HIGH",
                    "type": "OPEN_REDIRECT",
                    "details": f"Redirect para domínio externo via parâmetro '{param}'",
                    "request_raw": format_http_request(resp.request),
                    "response_raw": format_http_response(resp),
                }
            # Verificar reflexão no body (meta refresh, JS redirect)
            if resp.status_code == 200:
                body = resp.text[:5000].lower()
                for evil in EVIL_DOMAINS:
                    if evil in body:
                        return {
                            "url": url,
                            "test_url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "status": resp.status_code,
                            "location": "",
                            "risk": "MEDIUM",
                            "type": "OPEN_REDIRECT_REFLECTED",
                            "details": f"Domínio externo refletido no body via '{param}' (possível JS/meta redirect)",
                            "request_raw": format_http_request(resp.request),
                            "response_raw": format_http_response(resp),
                        }
    except Exception:
        pass
    return None


def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟧───────────────────────────────────────────────────────────🟧\n"
        f"   🔀 {C.BOLD}{C.CYAN}OPEN REDIRECT DETECTION{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟧───────────────────────────────────────────────────────────🟧\n"
    )

    outdir = ensure_outdir(target, "open_redirect")

    # Ler URLs
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    if not urls_file.exists():
        warn("⚠️ urls_200.txt não encontrado. Execute o módulo URLs primeiro.")
        # Salvar resumo de testes
        summary = {"tests_run": 0, "urls_checked": 0, "findings": 0, "status": "NO_INPUT"}
        (outdir / "open_redirect_results.json").write_text(json.dumps([], indent=2))
        (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))
        return []

    all_urls = [l.strip() for l in urls_file.read_text(errors="ignore").splitlines() if l.strip()]

    # Filtrar URLs com parâmetros de redirect
    candidates = []
    for url in all_urls:
        params = _has_redirect_param(url)
        if params:
            candidates.append((url, params))

    # Também testar parâmetros genéricos em URLs com querystring
    for url in all_urls[:100]:  # Limitar para performance
        parsed = urlparse(url)
        if parsed.query:
            qs = parse_qs(parsed.query)
            for key, vals in qs.items():
                if any(v.startswith("http") or v.startswith("/") for v in vals):
                    if (url, [key]) not in candidates:
                        candidates.append((url, [key]))

    info(f"   📋 {len(candidates)} URLs com parâmetros de redirect detectados")

    if not candidates:
        info("   ✅ Nenhum parâmetro de redirect encontrado nas URLs.")
        summary = {"tests_run": 0, "urls_checked": len(all_urls), "findings": 0, "status": "NO_CANDIDATES"}
        (outdir / "open_redirect_results.json").write_text(json.dumps([], indent=2))
        (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))
        return []

    results = []
    tests_run = 0

    def _worker(url, param):
        nonlocal tests_run
        for payload in PAYLOADS:
            time.sleep(REQUEST_DELAY)
            tests_run += 1
            result = _test_redirect(url, param, payload)
            if result:
                return result
        return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for url, params in candidates[:50]:  # Limitar para não sobrecarregar
            for param in params:
                futures.append(executor.submit(_worker, url, param))

        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
                    info(f"   🔴 {C.RED}OPEN REDIRECT{C.END}: {result['url']} via '{result['parameter']}'")
            except Exception:
                pass

    # Salvar
    output_file = outdir / "open_redirect_results.json"
    output_file.write_text(json.dumps(results, indent=2, ensure_ascii=False))

    summary = {"tests_run": tests_run, "urls_checked": len(candidates), "findings": len(results), "status": "COMPLETED"}
    (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))

    if results:
        success(f"\n   🔀 {len(results)} Open Redirects detectados!")
    else:
        info(f"   ✅ 0 Open Redirects. Testados {len(candidates)} endpoints com {len(PAYLOADS)} payloads ({tests_run} requests).")

    success(f"   📂 Salvos em {output_file}")
    return results
