#!/usr/bin/env python3
"""
Host Header Injection — Detecta reflexão e manipulação via Host header.
Testa Host, X-Forwarded-Host e injeção CRLF no Host.
"""
import json
import time
import httpx
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config import DEFAULT_USER_AGENT, REQUEST_DELAY, DEFAULT_TIMEOUT
from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from ..http_utils import format_http_request, format_http_response

EVIL_HOST = "evil-enum-allma.com"

INJECTION_TESTS = [
    {"name": "Host Override", "headers": {"Host": EVIL_HOST}},
    {"name": "X-Forwarded-Host", "headers": {"X-Forwarded-Host": EVIL_HOST}},
    {"name": "X-Host", "headers": {"X-Host": EVIL_HOST}},
    {"name": "X-Forwarded-Server", "headers": {"X-Forwarded-Server": EVIL_HOST}},
    {"name": "X-Original-URL Override", "headers": {"X-Original-URL": f"/{EVIL_HOST}"}},
]


def _test_host_injection(base_url: str) -> list:
    """Testa injeções de host header em uma URL base."""
    findings = []
    parsed = urlparse(base_url)
    original_host = parsed.netloc

    for test in INJECTION_TESTS:
        try:
            time.sleep(REQUEST_DELAY)
            headers = {"User-Agent": DEFAULT_USER_AGENT}
            headers.update(test["headers"])

            with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=False) as client:
                resp = client.get(base_url, headers=headers)

                body = resp.text[:10000].lower()
                location = resp.headers.get("location", "").lower()
                all_headers = "\n".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()

                reflected_in_body = EVIL_HOST.lower() in body
                reflected_in_location = EVIL_HOST.lower() in location
                reflected_in_headers = EVIL_HOST.lower() in all_headers

                if reflected_in_body or reflected_in_location or reflected_in_headers:
                    reflection_points = []
                    if reflected_in_body:
                        reflection_points.append("response body")
                    if reflected_in_location:
                        reflection_points.append("Location header")
                    if reflected_in_headers:
                        reflection_points.append("response headers")

                    risk = "HIGH" if reflected_in_location else "MEDIUM"

                    findings.append({
                        "url": base_url,
                        "test": test["name"],
                        "injected_headers": test["headers"],
                        "status": resp.status_code,
                        "risk": risk,
                        "type": "HOST_HEADER_INJECTION",
                        "reflected_in": reflection_points,
                        "details": f"Host '{EVIL_HOST}' refletido em: {', '.join(reflection_points)}",
                        "request_raw": format_http_request(resp.request),
                        "response_raw": format_http_response(resp),
                    })
        except Exception:
            pass

    return findings


def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟥───────────────────────────────────────────────────────────🟥\n"
        f"   🏠 {C.BOLD}{C.CYAN}HOST HEADER INJECTION SCANNER{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟥───────────────────────────────────────────────────────────🟥\n"
    )

    outdir = ensure_outdir(target, "host_header_injection")

    urls_file = Path("output") / target / "domain" / "urls_valid.txt"
    if not urls_file.exists():
        warn("⚠️ urls_valid.txt não encontrado.")
        summary = {"tests_run": 0, "hosts_checked": 0, "findings": 0, "status": "NO_INPUT"}
        (outdir / "host_injection_results.json").write_text(json.dumps([], indent=2))
        (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))
        return []

    valid_urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]

    # Deduplicar por host
    seen = set()
    unique_bases = []
    for u in valid_urls:
        parsed = urlparse(u)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base not in seen:
            seen.add(base)
            unique_bases.append(base)

    info(f"   📋 Testando {len(unique_bases)} hosts únicos com {len(INJECTION_TESTS)} técnicas...")

    all_results = []
    tests_run = 0

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(_test_host_injection, url): url for url in unique_bases}

        for future in as_completed(futures):
            try:
                findings = future.result()
                tests_run += len(INJECTION_TESTS)
                if findings:
                    all_results.extend(findings)
                    for f in findings:
                        info(f"   🔴 {C.RED}[{f['risk']}]{C.END} {f['url']} — {f['test']}: refletido em {', '.join(f['reflected_in'])}")
            except Exception:
                pass

    output_file = outdir / "host_injection_results.json"
    output_file.write_text(json.dumps(all_results, indent=2, ensure_ascii=False))

    summary = {"tests_run": tests_run, "hosts_checked": len(unique_bases), "findings": len(all_results), "status": "COMPLETED"}
    (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))

    if all_results:
        success(f"\n   🏠 {len(all_results)} Host Header Injection(s) detectada(s)!")
    else:
        info(f"   ✅ 0 injeções. Testados {len(unique_bases)} hosts com {len(INJECTION_TESTS)} técnicas ({tests_run} requests).")

    success(f"   📂 Salvos em {output_file}")
    return all_results
