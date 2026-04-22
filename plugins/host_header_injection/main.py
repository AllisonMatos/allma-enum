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

# Portas de painel administrativas (Blacklist cirúrgica V10.1)
PANEL_PORTS = {2082, 2083, 2086, 2087, 8080, 8443}

EVIL_DOMAIN = "evil-enum-allma.com"

# Headers indicativos de cache (V10.2 — Cache Poisoning Detection)
CACHE_HIT_HEADERS = ["x-cache", "x-cache-status", "cf-cache-status", "age", "x-varnish"]

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
            risk_context = "SAFE"  # V10.4: Contexto de reflexão
            
            if EVIL_DOMAIN in location:
                is_vuln = True
                risk_context = "DANGEROUS"
                details = f"Domínio injetado refletido no header 'Location' ({resp.status_code})"
            elif EVIL_DOMAIN in body:
                # V10.4: Verificar se a reflexão está em contexto perigoso vs inofensivo
                evil_idx = body.find(EVIL_DOMAIN)
                surrounding = body[max(0, evil_idx - 200):evil_idx + 200]
                
                # Contextos PERIGOSOS: form action, a href, script, meta refresh
                dangerous_patterns = [
                    r'<form[^>]*action\s*=\s*["\']?[^"\'>]*' + re.escape(EVIL_DOMAIN),
                    r'<a[^>]*href\s*=\s*["\']?[^"\'>]*' + re.escape(EVIL_DOMAIN),
                    r'<script[^>]*src\s*=\s*["\']?[^"\'>]*' + re.escape(EVIL_DOMAIN),
                    r'<meta[^>]*content\s*=\s*["\']?\d+;\s*url\s*=\s*[^"\'>]*' + re.escape(EVIL_DOMAIN),
                    r'<iframe[^>]*src\s*=\s*["\']?[^"\'>]*' + re.escape(EVIL_DOMAIN),
                ]
                # Contextos SEGUROS: link canonical, base href, og:url
                safe_patterns = [
                    r'<link[^>]*rel\s*=\s*["\']?canonical[^>]*' + re.escape(EVIL_DOMAIN),
                    r'<link[^>]*rel\s*=\s*["\']?alternate[^>]*' + re.escape(EVIL_DOMAIN),
                    r'<base[^>]*href\s*=\s*["\']?[^"\'>]*' + re.escape(EVIL_DOMAIN),
                    r'property\s*=\s*["\']og:url["\']',
                ]
                
                import re as _re
                is_dangerous = any(_re.search(p, surrounding, _re.I) for p in dangerous_patterns)
                is_safe_ctx = any(_re.search(p, surrounding, _re.I) for p in safe_patterns)
                
                if is_dangerous:
                    is_vuln = True
                    risk_context = "DANGEROUS"
                    details = f"Domínio injetado refletido em contexto PERIGOSO no body ({resp.status_code})"
                elif is_safe_ctx:
                    # V10.4: Reflexão em contexto seguro — NÃO reportar como vuln
                    continue
                else:
                    # V11: Contexto desconhecido — ignorar para evitar falsos positivos
                    # Sites frequentemente refletem Host em meta tags, og:url, canonical etc.
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
                risk = "CRITICAL" if cache_poisoned else ("HIGH" if resp.status_code < 400 else "MEDIUM")
                findings.append({
                    "url": url,
                    "type": "HOST_HEADER_INJECTION",
                    "risk": risk,
                    "details": details,
                    "payload": str(headers),
                    "cache_poisoned": cache_poisoned,
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

    info(f"🧪 {C.BOLD}{C.CYAN}HOST HEADER SCANNER (V10.3 PRECISION){C.END}")
    outdir = ensure_outdir(target, "host_header_injection")

    urls_file = Path("output") / target / "urls" / "urls_200.txt"
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
                        info(f"   🔴 {C.RED}[{f['risk']}]{C.END} Host Injection em {f['url']}")

    output_file = outdir / "host_injection_results.json"
    output_file.write_text(json.dumps(results, indent=2))
    
    # V10.3: Salvar summary
    summary = {"urls_tested": len(candidates), "findings": len(results), "status": "COMPLETED"}
    (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))
    
    success(f"   📂 Resultados salvos em {output_file}")
    return results
