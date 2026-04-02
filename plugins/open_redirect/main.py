#!/usr/bin/env python3
"""
Open Redirect Detection (V10.1 Surgical) — Detecta redirecionamentos abertos.
Valida bypasses modernos e confirma o redirecionamento real com double-check.
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

EVIL_DOMAIN = "evil-enum-allma.com"

# Payloads Modernos V10.1
REDIRECT_PAYLOADS = [
    f"//{EVIL_DOMAIN}",
    f"https://{EVIL_DOMAIN}",
    f"@{EVIL_DOMAIN}", # @ bypass
    f"/\\{EVIL_DOMAIN}", # backslash bypass
    f"//google.com@{EVIL_DOMAIN}",
    f"javascript:alert(1)//@{EVIL_DOMAIN}",
    f"/%2f{EVIL_DOMAIN}",
    f"\\{EVIL_DOMAIN}",
]

def _test_redirect(url: str, param: str) -> list:
    """Testa Open Redirect com double-check de validação externa."""
    findings = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    for payload in REDIRECT_PAYLOADS:
        time.sleep(REQUEST_DELAY)
        test_qs = qs.copy()
        test_qs[param] = [payload]
        new_query = urlencode(test_qs, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

        try:
            with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=False) as client:
                resp = client.get(test_url, headers={"User-Agent": DEFAULT_USER_AGENT})
                location = resp.headers.get("location", "")
                
                # Fase 1: Detectar 3xx + Location contendo o payload
                if resp.status_code in [301, 302, 303, 307, 308] and (EVIL_DOMAIN in location or payload in location):
                    
                    # Fase 2: Double-Check Cirúrgico V10.1
                    # Faz um segundo request seguindo o Location para confirmar se cai em domínio externo
                    final_loc = location if location.startswith("http") else urlunparse((parsed.scheme, parsed.netloc, location, "", "", ""))
                    try:
                        resp2 = client.get(final_loc, headers={"User-Agent": DEFAULT_USER_AGENT}, follow_redirects=True)
                        final_url = str(resp2.url)
                        
                        if EVIL_DOMAIN in final_url:
                             findings.append({
                                "url": url,
                                "type": "OPEN_REDIRECT",
                                "risk": "HIGH",
                                "details": f"Redirecionamento Confirmado: Parâmetro '{param}' enviou o navegador para {final_url}",
                                "payload": payload,
                                "status": resp.status_code,
                                "request_raw": format_http_request(resp.request),
                                "response_raw": format_http_response(resp),
                            })
                             break # Um payload com sucesso basta por parâmetro
                    except: pass
        except Exception:
            pass
    return findings

def run(context: dict):
    target = context.get("target")
    stealth = context.get("stealth", False)
    if not target:
        raise ValueError("Target required")

    info(f"🧪 {C.BOLD}{C.CYAN}OPEN REDIRECT SCANNER (V10.1 SURGICAL){C.END}")
    outdir = ensure_outdir(target, "open_redirect")

    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    candidates = []
    if urls_file.exists():
        urls = urls_file.read_text().splitlines()
        for u in urls:
            if "?" in u:
                p = urlparse(u)
                qs = parse_qs(p.query)
                for param in qs:
                    candidates.append((u, param))
    
    candidates = list(set(candidates))[:80]
    max_workers = 5 if stealth else 15
    
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_test_redirect, url, param): (url, param) for url, param in candidates}
        for future in as_completed(futures):
            res = future.result()
            if res:
                results.extend(res)
                for f in res:
                    info(f"   🔴 {C.RED}[OPEN REDIRECT]{C.END} Confirmado em {f['url']} via '{f['payload']}'")

    output_file = outdir / "open_redirect_results.json"
    output_file.write_text(json.dumps(results, indent=2))
    success(f"   📂 Resultados salvos em {output_file}")
    return results
