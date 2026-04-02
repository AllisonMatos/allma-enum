#!/usr/bin/env python3
"""
Host Header Injection (V10.1 Surgical) — Detecta manipulação do cabeçalho Host.
Filtra portas de painel e exige reflexão + status 2xx/3xx.
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

# Portas de painel administrativas (Blacklist cirúrgica V10.1)
PANEL_PORTS = ["2082", "2083", "2086", "2087", "8080", "8443"]

EVIL_DOMAIN = "evil-enum-allma.com"

def _test_host_injection(url: str) -> list:
    """Testa Host Header Injection com payloads cirúrgicos."""
    parsed = urlparse(url)
    if parsed.port and str(parsed.port) in PANEL_PORTS:
        return []

    findings = []
    
    # Payloads V10.1: Cache Poisoning, CRLF, X-Forwarded-Host
    payloads = [
        {"Host": EVIL_DOMAIN},
        {"X-Forwarded-Host": EVIL_DOMAIN},
        {"Host": f"localhost\r\nHost: {EVIL_DOMAIN}"}, # CRLF Injection
        {"X-Host": EVIL_DOMAIN},
        {"Forwarded": f"for=127.0.0.1;host={EVIL_DOMAIN}"},
    ]

    for headers in payloads:
        time.sleep(REQUEST_DELAY)
        try:
            with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=False) as client:
                resp = client.get(url, headers={**headers, "User-Agent": DEFAULT_USER_AGENT})
                
                # Validação Cirúrgica V10.1: Reflexão + Status 200/3xx
                # (Ignora 4xx/5xx pois podem ser erro genérico do cPanel/Plesk)
                if resp.status_code >= 400:
                    continue

                location = resp.headers.get("location", "").lower()
                body = resp.text.lower()
                
                is_vuln = False
                details = ""
                
                if EVIL_DOMAIN in location:
                    is_vuln = True
                    details = f"Domínio injetado refletido no header 'Location' ({resp.status_code})"
                elif EVIL_DOMAIN in body:
                    is_vuln = True
                    details = f"Domínio injetado refletido no corpo da resposta ({resp.status_code})"

                if is_vuln:
                    findings.append({
                        "url": url,
                        "type": "HOST_HEADER_INJECTION",
                        "risk": "HIGH" if resp.status_code < 400 else "MEDIUM",
                        "details": details,
                        "payload": str(headers),
                        "request_raw": format_http_request(resp.request),
                        "response_raw": format_http_response(resp),
                    })
                    break # Evita duplicar se múltiplos headers funcionarem
        except Exception:
            pass
    return findings

def run(context: dict):
    target = context.get("target")
    stealth = context.get("stealth", False)
    if not target:
        raise ValueError("Target required")

    info(f"🧪 {C.BOLD}{C.CYAN}HOST HEADER SCANNER (V10.1 SURGICAL){C.END}")
    outdir = ensure_outdir(target, "host_header_injection")

    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    candidates = []
    if urls_file.exists():
        candidates = urls_file.read_text().splitlines()
    
    candidates = list(set(candidates))[:80]
    max_workers = 5 if stealth else 15
    
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_test_host_injection, url): url for url in candidates}
        for future in as_completed(futures):
            res = future.result()
            if res:
                results.extend(res)
                for f in res:
                    info(f"   🔴 {C.RED}[{f['risk']}]{C.END} Host Injection em {f['url']}")

    output_file = outdir / "host_injection_results.json"
    output_file.write_text(json.dumps(results, indent=2))
    success(f"   📂 Resultados salvos em {output_file}")
    return results
