#!/usr/bin/env python3
"""
Host Header Injection (V10 Pro) — Detecta reflexão, manipulação e Cache Poisoning via Host header.
Inclui técnicas avançadas de CRLF, X-Forwarded-Host e bypass de portas administrativas.
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

# Blacklist de portas administrativas comuns onde reflexões são normais/esperadas
BLACKLIST_PORTS = [2082, 2083, 2086, 2087, 8443, 8080]

def _build_tests(target: str, deep: bool = False):
    tests = [
        {"name": "Host Override", "headers": {"Host": EVIL_HOST}},
        {"name": "X-Forwarded-Host", "headers": {"X-Forwarded-Host": EVIL_HOST}},
        {"name": "X-Host", "headers": {"X-Host": EVIL_HOST}},
        {"name": "X-Forwarded-Server", "headers": {"X-Forwarded-Server": EVIL_HOST}},
        {"name": "Duplicate Host", "headers": {"Host": f"{target}\r\nHost: {EVIL_HOST}"}}, # CRLF attempt
    ]
    
    if deep:
        # Payloads mais agressivos para modo --deep
        tests.extend([
            {"name": "Cache Poisoning (X-Forwarded-Proto)", "headers": {"X-Forwarded-Proto": "http", "Host": target, "X-Forwarded-Host": EVIL_HOST}},
            {"name": "Port Injection", "headers": {"Host": f"{target}:80@{EVIL_HOST}"}},
            {"name": "Absolute URI", "path_override": f"http://{EVIL_HOST}/"},
        ])
    
    return tests


def _test_host_injection(base_url: str, target: str, deep: bool = False) -> list:
    """Testa injeções de host header em uma URL base."""
    findings = []
    
    tests = _build_tests(target, deep)

    for test in tests:
        try:
            time.sleep(REQUEST_DELAY)
            headers = {"User-Agent": DEFAULT_USER_AGENT}
            headers.update(test.get("headers", {}))
            
            url = base_url
            if test.get("path_override"):
                parsed = urlparse(base_url)
                url = f"{parsed.scheme}://{parsed.netloc}{test['path_override']}"

            with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=False) as client:
                resp = client.get(url, headers=headers)

                body = resp.text[:10000].lower()
                location = resp.headers.get("location", "").lower()
                all_headers = "\n".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()

                reflected_in_body = EVIL_HOST.lower() in body
                reflected_in_location = EVIL_HOST.lower() in location
                reflected_in_headers = EVIL_HOST.lower() in all_headers

                # CRITÉRIO V10: Só reportar se status for 200 ou 3xx (impacto real)
                # Ignorar 4xx/5xx para evitar falsos positivos de páginas de erro cPanel/Cloudflare
                if resp.status_code < 400 and (reflected_in_body or reflected_in_location or reflected_in_headers):
                    reflection_points = []
                    if reflected_in_body: reflection_points.append("response body")
                    if reflected_in_location: reflection_points.append("Location header")
                    if reflected_in_headers: reflection_points.append("response headers")

                    # HIGH se for no Location (Redirect Hijack), MEDIUM se for no body
                    risk = "HIGH" if reflected_in_location else "MEDIUM"
                    
                    findings.append({
                        "url": url,
                        "test": test["name"],
                        "injected_headers": test.get("headers", {}),
                        "status": resp.status_code,
                        "risk": risk,
                        "type": "HOST_HEADER_INJECTION",
                        "reflected_in": reflection_points,
                        "details": f"Vulnerabilidade Detectada: Host '{EVIL_HOST}' refletido em {', '.join(reflection_points)} com status {resp.status_code}",
                        "request_raw": format_http_request(resp.request),
                        "response_raw": format_http_response(resp),
                    })
                    
                    # No deep mode, continuamos para achar todas as variações. Caso contrário, paramos no primeiro sucesso por host.
                    if not deep: break 
        except Exception:
            pass

    return findings


def run(context: dict):
    target = context.get("target")
    deep = context.get("deep", False)
    stealth = context.get("stealth", False)
    
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟥───────────────────────────────────────────────────────────🟥\n"
        f"   🏠 {C.BOLD}{C.CYAN}HOST HEADER INJECTION SCANNER (V10 PRO){C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END} | Modo: {'DEEP' if deep else 'Normal'} | Stealth: {'ON' if stealth else 'OFF'}\n"
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

    # Deduplicar por host e aplicar filtros (portas administrativas)
    seen = set()
    unique_bases = []
    for u in valid_urls:
        parsed = urlparse(u)
        
        # Filtro V10: Ignorar portas administrativas para reduzir FPs
        if parsed.port in BLACKLIST_PORTS:
            continue
            
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base not in seen:
            seen.add(base)
            unique_bases.append(base)

    # Modo Stealth reduz o número de workers
    max_workers = 3 if stealth else 8
    info(f"   📋 Analisando {len(unique_bases)} hosts (Blacklist de portas administrativas ATIVA)")

    all_results = []
    tests_run = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_test_host_injection, url, target, deep): url for url in unique_bases}

        for future in as_completed(futures):
            try:
                findings = future.result()
                tests_run += 1 # Contagem simplificada por host
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
        success(f"\n   🏠 {len(all_results)} Host Injection(s) CONFIRMADA(s) em status 200/3xx!")
    else:
        info(f"   ✅ 0 injeções válidas detectadas em {len(unique_bases)} hosts.")

    success(f"   📂 Resultados salvos em {output_file}")
    return all_results
