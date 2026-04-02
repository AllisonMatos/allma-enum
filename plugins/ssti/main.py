#!/usr/bin/env python3
"""
SSTI (V10 Pro) — Server-Side Template Injection detection.
Injeta payloads reais para Jinja2, Django, Mako, Twig e verifica execução.
"""
import json
import time
import httpx
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config import DEFAULT_USER_AGENT, REQUEST_DELAY, DEFAULT_TIMEOUT
from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from ..http_utils import format_http_request, format_http_response

def _build_payloads(deep: bool = False):
    payloads = [
        ("{{7*7}}", "49"),            # Jinja2, Twig
        ("${7*7}", "49"),             # Freemarker, Velocity
        ("<%= 7*7 %>", "49"),         # ERB (Ruby)
        ("#{7*7}", "49"),             # Slim, Pug
    ]
    if deep:
        payloads.extend([
            ("{{config}}", "Config"),    # Flask/Jinja leak
            ("{{settings.SECRET_KEY}}", "SECRET_KEY"), # Django leak hint
            ("${{7*7}}", "49"),          # Spring Expression Language
            ("{{7*'7'}}", "7777777"),    # Type testing
            ("@(7*7)", "49"),            # Razor
        ])
    return payloads


def _test_ssti(url: str, param: str, deep: bool = False) -> dict | None:
    """Testa payloads SSTI em um parâmetro específico com baseline check."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    
    # Baseline
    try:
        with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=True) as client:
            baseline_resp = client.get(url, headers={"User-Agent": DEFAULT_USER_AGENT})
            baseline_body = baseline_resp.text
    except Exception:
        return None

    payloads = _build_payloads(deep)

    for payload, expected in payloads:
        time.sleep(REQUEST_DELAY)
        qs[param] = [payload]
        new_query = urlencode(qs, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

        try:
            with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=True) as client:
                resp = client.get(test_url, headers={"User-Agent": DEFAULT_USER_AGENT})
                body = resp.text

                # Confirmação V10: Resultado esperado surge no body e NÃO estava no baseline
                if expected.lower() in body.lower() and expected.lower() not in baseline_body.lower():
                    return {
                        "url": url,
                        "test_url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "expected": expected,
                        "status": resp.status_code,
                        "risk": "CRITICAL",
                        "type": "SSTI",
                        "details": f"Vulnerabilidade Detectada: SSTI via '{param}' (Payload: {payload} -> {expected})",
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
        f"   🧪 {C.BOLD}{C.CYAN}SSTI (TEMPLATE INJECTION) SCANNER (V10 PRO){C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END} | Deep: {deep} | Stealth: {stealth}\n"
        f"🟧───────────────────────────────────────────────────────────🟧\n"
    )

    outdir = ensure_outdir(target, "ssti")
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    
    if not urls_file.exists():
        warn("⚠️ urls_200.txt não encontrado.")
        summary = {"tests_run": 0, "urls_checked": 0, "findings": 0, "status": "NO_INPUT"}
        (outdir / "ssti_results.json").write_text(json.dumps([], indent=2))
        (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))
        return []

    all_urls = [l.strip() for l in urls_file.read_text(errors="ignore").splitlines() if l.strip()]

    # Filtrar candidatos
    candidates = []
    for url in all_urls:
        if "?" in url:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for param in qs:
                candidates.append((url, param))

    candidates = list(set(candidates))[:80]
    max_workers = 3 if stealth else 10
    
    info(f"   📋 Testando {len(candidates)} parâmetros com payloads reais de engines")

    results = []
    tests_run = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_test_ssti, url, param, deep): (url, param) for url, param in candidates}

        for future in as_completed(futures):
            try:
                res = future.result()
                tests_run += 1
                if res:
                    results.append(res)
                    info(f"   🔴 {C.RED}[CRITICAL]{C.END} {res['url']} — '{res['parameter']}' -> {res['payload']}")
            except Exception:
                pass

    output_file = outdir / "ssti_results.json"
    output_file.write_text(json.dumps(results, indent=2, ensure_ascii=False))

    summary = {"tests_run": tests_run, "urls_checked": len(candidates), "findings": len(results), "status": "COMPLETED"}
    (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))

    if results:
        success(f"\n   🧪 {len(results)} SSTI Confirmado(s)!")
    else:
        info(f"   ✅ 0 SSTI em {len(candidates)} candidatos.")

    success(f"   📂 Salvos em {output_file}")
    return results
