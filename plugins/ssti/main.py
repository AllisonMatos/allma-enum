#!/usr/bin/env python3
"""
SSTI Hints — Server-Side Template Injection detection.
Injeta payloads canônicos em parâmetros refletidos e verifica se a engine avalia a expressão.
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

# Payloads e os resultados esperados
SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),            # Jinja2, Twig
    ("${7*7}", "49"),             # Freemarker, Velocity
    ("<%= 7*7 %>", "49"),         # ERB (Ruby)
    ("#{7*7}", "49"),             # Slim, Pug
    ("{{7*'7'}}", "7777777"),     # Jinja2 string repeat
    ("${7*7}", "49"),             # Mako, EL
    ("@(7*7)", "49"),             # Razor (C#)
]


def _test_ssti(url: str, param: str) -> dict | None:
    """Testa payloads SSTI em um parâmetro específico."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    original_val = qs.get(param, [""])[0]

    # Primeiro, obter baseline
    try:
        with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=True) as client:
            baseline_resp = client.get(url, headers={"User-Agent": DEFAULT_USER_AGENT})
            baseline_body = baseline_resp.text
    except Exception:
        return None

    for payload, expected in SSTI_PAYLOADS:
        time.sleep(REQUEST_DELAY)
        qs[param] = [payload]
        new_query = urlencode(qs, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

        try:
            with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=True) as client:
                resp = client.get(test_url, headers={"User-Agent": DEFAULT_USER_AGENT})
                body = resp.text

                # Verificar se o resultado avaliado aparece no body e NÃO estava no baseline
                if expected in body and expected not in baseline_body:
                    return {
                        "url": url,
                        "test_url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "expected": expected,
                        "status": resp.status_code,
                        "risk": "CRITICAL",
                        "type": "SSTI",
                        "details": f"Template injection via '{param}': payload '{payload}' avaliado como '{expected}'",
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
        f"   🧪 {C.BOLD}{C.CYAN}SSTI (Server-Side Template Injection) SCANNER{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟧───────────────────────────────────────────────────────────🟧\n"
    )

    outdir = ensure_outdir(target, "ssti")

    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    if not urls_file.exists():
        warn("⚠️ urls_200.txt não encontrado.")
        (outdir / "ssti_results.json").write_text(json.dumps([], indent=2))
        (outdir / "scan_summary.json").write_text(json.dumps({"tests_run": 0, "urls_checked": 0, "findings": 0, "status": "NO_INPUT"}, indent=2))
        return []

    all_urls = [l.strip() for l in urls_file.read_text(errors="ignore").splitlines() if l.strip()]

    # Filtrar URLs com parâmetros
    candidates = []
    for url in all_urls:
        parsed = urlparse(url)
        if parsed.query:
            qs = parse_qs(parsed.query)
            for param in qs:
                candidates.append((url, param))

    # Limitar para performance
    candidates = candidates[:200]
    info(f"   📋 {len(candidates)} pares URL/parâmetro para testar")

    if not candidates:
        info("   ✅ Nenhuma URL com parâmetros para testar.")
        (outdir / "ssti_results.json").write_text(json.dumps([], indent=2))
        (outdir / "scan_summary.json").write_text(json.dumps({"tests_run": 0, "urls_checked": len(all_urls), "findings": 0, "status": "NO_CANDIDATES"}, indent=2))
        return []

    results = []
    tests_run = 0

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(_test_ssti, url, param): (url, param) for url, param in candidates}

        for future in as_completed(futures):
            tests_run += len(SSTI_PAYLOADS)
            try:
                result = future.result()
                if result:
                    results.append(result)
                    info(f"   🔴 {C.RED}SSTI DETECTADO!{C.END} {result['url']} via '{result['parameter']}' → {result['payload']}={result['expected']}")
            except Exception:
                pass

    output_file = outdir / "ssti_results.json"
    output_file.write_text(json.dumps(results, indent=2, ensure_ascii=False))

    summary = {"tests_run": tests_run, "urls_checked": len(candidates), "findings": len(results), "status": "COMPLETED"}
    (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))

    if results:
        success(f"\n   🧪 {len(results)} SSTI encontrado(s)!")
    else:
        info(f"   ✅ 0 SSTI. Testados {len(candidates)} parâmetros com {len(SSTI_PAYLOADS)} payloads ({tests_run} requests).")

    success(f"   📂 Salvos em {output_file}")
    return results
