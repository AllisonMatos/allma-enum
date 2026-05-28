#!/usr/bin/env python3
"""
Host Header Injection (V10.3 Precision) — Detecta manipulação do cabeçalho Host.
Filtra portas de painel e exige reflexão + status 2xx/3xx.
Inclui cache poisoning detection e payloads CRLF avançados.
V10.3: httpx.Client reuse, port=None handling, dedup.
"""
import json
import re
import time
import httpx
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config import DEFAULT_USER_AGENT, REQUEST_DELAY, DEFAULT_TIMEOUT, get_user_agent
from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from ..http_utils import format_http_request, format_http_response
from ..validation import finding

# Portas de painel administrativas (Blacklist cirúrgica V10.1)
PANEL_PORTS = {2082, 2083, 2086, 2087, 8080, 8443}

EVIL_DOMAIN = "evil-enum-allma.com"

# Headers indicativos de cache (V10.2 — Cache Poisoning Detection)
CACHE_HIT_HEADERS = ["x-cache", "x-cache-status", "cf-cache-status", "age", "x-varnish"]


def reflection_context(body: str, marker: str) -> str:
    idx = body.find(marker)
    if idx < 0:
        return "NONE"
    around = body[max(0, idx - 200): idx + 200]
    dangerous_patterns = [
        r'<form[^>]*action\s*=\s*["\']?[^"\'>]*' + re.escape(marker),
        r'<a[^>]*href\s*=\s*["\']?[^"\'>]*' + re.escape(marker),
        r'<script[^>]*src\s*=\s*["\']?[^"\'>]*' + re.escape(marker),
        r'<meta[^>]*content\s*=\s*["\']?\d+;\s*url\s*=\s*[^"\'>]*' + re.escape(marker),
        r'<iframe[^>]*src\s*=\s*["\']?[^"\'>]*' + re.escape(marker),
    ]
    safe_patterns = [
        r'<link[^>]*rel\s*=\s*["\']?canonical',
        r'property\s*=\s*["\']og:url["\']',
    ]
    if any(re.search(p, around, re.I) for p in dangerous_patterns):
        return "DANGEROUS"
    if any(re.search(p, around, re.I) for p in safe_patterns):
        return "SAFE"
    return "UNKNOWN"

def _test_host_injection(client: httpx.Client, url: str) -> list:
    """Testa Host Header Injection com payloads cirúrgicos. Reutiliza sessão."""
    parsed = urlparse(url)
    
    # V10.3: Tratar port=None graciosamente (portas padrão 80/443 retornam None)
    port = parsed.port
    if port is not None and port in PANEL_PORTS:
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

    # V10.2: Payloads adicionais para cache poisoning e bypass
    payloads_v10_2 = [
        {"X-Original-URL": f"/{EVIL_DOMAIN}"},                # X-Original-URL override
        {"X-Forwarded-Scheme": "nothttps", "Host": EVIL_DOMAIN},  # Cache key via scheme
        {"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Host": EVIL_DOMAIN},  # Combo forward
        {"X-Rewrite-URL": f"/{EVIL_DOMAIN}"},                 # URL rewrite
    ]
    payloads.extend(payloads_v10_2)

    for headers in payloads:
        time.sleep(REQUEST_DELAY)
        try:
            resp = client.get(url, headers={**headers, "User-Agent": DEFAULT_USER_AGENT})
            
            # Validação Cirúrgica V10.1: Reflexão + Status 200/3xx
            if resp.status_code >= 400:
                continue

            location = resp.headers.get("location", "").lower()
            body = resp.text.lower()
            
            is_vuln = False
            details = ""
            risk_context = "SAFE"
            
            if EVIL_DOMAIN in location:
                is_vuln = True
                risk_context = "DANGEROUS"
                details = f"Domínio injetado refletido no header 'Location' ({resp.status_code})"
            elif EVIL_DOMAIN in body:
                ctx = reflection_context(body, EVIL_DOMAIN)
                if ctx == "DANGEROUS":
                    is_vuln = True
                    risk_context = "DANGEROUS"
                    details = f"Domínio injetado refletido em contexto PERIGOSO no body ({resp.status_code})"
                elif ctx == "SAFE":
                    continue
                else:
                    continue

            # V10.2: Detectar cache poisoning
            cache_poisoned = False
            if is_vuln:
                for ch in CACHE_HIT_HEADERS:
                    cache_val = resp.headers.get(ch, "").lower()
                    if cache_val and ("hit" in cache_val or (ch == "age" and cache_val.isdigit() and int(cache_val) > 0)):
                        cache_poisoned = True
                        details += f" | Cache Poisoning detectado ({ch}: {cache_val})"
                        break

            if is_vuln:
                confidence = "CONFIRMED" if cache_poisoned else "HIGH"
                findings.append(finding(
                    plugin="host_header_injection",
                    target="",
                    title="Host Header Injection",
                    issue_type="HOST_HEADER_INJECTION",
                    risk="CRITICAL" if cache_poisoned else "HIGH",
                    confidence=confidence,
                    url=url,
                    description=details,
                    detection={"payload": headers, "status": resp.status_code, "reflection_context": risk_context},
                    validation={"cache_poisoned": cache_poisoned, "external_redirect": EVIL_DOMAIN in location},
                    evidence={
                        "request_raw": format_http_request(resp.request),
                        "response_raw": format_http_response(resp),
                        "observable_impact": "cache_hit_with_injected_host" if cache_poisoned else "injected_host_reflection"
                    },
                    metadata={"cache_poisoned": cache_poisoned}
                ))
                break # Evita duplicar se múltiplos headers funcionarem
        except Exception:
            pass
    return findings

def run(context: dict):
    target = context.get("target")
    stealth = context.get("stealth", False)
    if not target:
        raise ValueError("Target required")

    info(f"🧪 {C.BOLD}{C.CYAN}HOST HEADER SCANNER (V10.3 PRECISION){C.END}")
    outdir = ensure_outdir(target, "host_header_injection")

    from core.url_sources import primary_urls_txt_for_scan

    urls_file = primary_urls_txt_for_scan(target)
    candidates = []
    if urls_file.exists():
        candidates = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]
    
    # V10.3: Dedup URLs normalizadas
    seen = set()
    deduped = []
    for url in candidates:
        key = url.rstrip("/")
        if key not in seen:
            seen.add(key)
            deduped.append(url)
    
    candidates = deduped[:80]
    # V11: Reduzir workers para thread-safety com httpx.Client compartilhado
    max_workers = 3 if stealth else 5
    
    results = []
    
    # V10.3: Uma única sessão httpx para todos os testes
    with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=False) as client:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_test_host_injection, client, url): url for url in candidates}
            for future in as_completed(futures):
                res = future.result()
                if res:
                    results.extend(res)
                    for f in res:
                        f["target"] = target
                        info(f"   🔴 {C.RED}[{f['risk']}/{f['confidence']}]{C.END} Host Injection em {f['url']}")

    output_file = outdir / "host_injection_results.json"
    output_file.write_text(json.dumps(results, indent=2))
    
    # V10.3: Salvar summary
    summary = {"urls_tested": len(candidates), "findings": len(results), "status": "COMPLETED"}
    (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))
    
    success(f"   📂 Resultados salvos em {output_file}")
    return results
