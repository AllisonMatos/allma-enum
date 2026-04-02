#!/usr/bin/env python3
"""
OAuth Misconfiguration (V10.2 Precision) — Detecta falhas em implementações OAuth 2.0 / OpenID Connect.
Testa redirect_uri aberto (com bypass de subdomínio), Implicit Flow (response_type=token),
state/nonce ausente, e scope escalation.
"""
import json
import time
import re
import httpx
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config import DEFAULT_USER_AGENT, REQUEST_DELAY, DEFAULT_TIMEOUT
from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from ..http_utils import format_http_request, format_http_response

OAUTH_URL_PATTERNS = [
    r"/oauth", r"/auth/", r"/authorize", r"/callback", r"/login/oauth",
    r"/connect/", r"/sso/", r"redirect_uri=", r"client_id=",
]

EVIL_REDIRECT = "https://evil-enum-allma.com/callback"

# V10.2: Redirect URI bypass variants
REDIRECT_URI_BYPASSES = [
    "https://evil-enum-allma.com/callback",
    "https://evil-enum-allma.com%40legit.com/callback",  # @ encoding bypass
    "https://legit.com.evil-enum-allma.com/callback",    # Subdomain takeover style
    "https://legit.com@evil-enum-allma.com/callback",    # Credential-style bypass
]

def _test_oauth_vulnerabilities(url: str, deep: bool = False) -> list:
    """Testa múltiplas vulnerabilidades OAuth em um endpoint."""
    findings = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    # 1. Testar Redirect URI Aberto (V10.2: com múltiplos bypasses)
    param_to_test = "redirect_uri" if "redirect_uri" in qs else "redirect_url"
    
    for evil_uri in REDIRECT_URI_BYPASSES:
        test_params = qs.copy()
        test_params[param_to_test] = [evil_uri]
        
        # V10.2: Testar Implicit Flow independente de deep mode
        if "response_type" in test_params:
            test_params_implicit = test_params.copy()
            test_params_implicit["response_type"] = ["token"]
            test_url_implicit = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(test_params_implicit, doseq=True), parsed.fragment))
            
            try:
                time.sleep(REQUEST_DELAY)
                with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=False) as client:
                    resp = client.get(test_url_implicit, headers={"User-Agent": DEFAULT_USER_AGENT})
                    location = resp.headers.get("location", "").lower()
                    
                    # Se aceita response_type=token e redireciona (com ou sem token no fragment)
                    if resp.status_code in [301, 302, 303, 307, 308]:
                        if "access_token" in location or "#" in location:
                            findings.append({
                                "url": url,
                                "type": "IMPLICIT_FLOW_TOKEN_LEAK",
                                "risk": "CRITICAL",
                                "details": f"OAuth aceita response_type=token (Implicit Flow). Token pode vazar via redirect_uri. Location: {location[:200]}",
                                "request_raw": format_http_request(resp.request),
                                "response_raw": format_http_response(resp),
                            })
            except Exception:
                pass

        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(test_params, doseq=True), parsed.fragment))
        
        try:
            time.sleep(REQUEST_DELAY)
            with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=False) as client:
                resp = client.get(test_url, headers={"User-Agent": DEFAULT_USER_AGENT})
                location = resp.headers.get("location", "").lower()
                
                # Confirmação de Redirect URI Aberto
                if "evil-enum-allma.com" in location:
                    findings.append({
                        "url": url,
                        "type": "OPEN_REDIRECT_URI",
                        "risk": "CRITICAL",
                        "details": f"OAuth redirect_uri aceita domínio externo ({evil_uri}). Risco de vazamento de CODE/TOKEN.",
                        "bypass_variant": evil_uri,
                        "request_raw": format_http_request(resp.request),
                        "response_raw": format_http_response(resp),
                    })
                    break  # Um bypass confirmado basta
        except Exception:
            pass

    # 2. Verificar ausência de state/nonce
    try:
        time.sleep(REQUEST_DELAY)
        with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=False) as client:
            resp = client.get(url, headers={"User-Agent": DEFAULT_USER_AGENT})
            
            if "state" not in qs:
                findings.append({
                    "url": url,
                    "type": "STATE_MISSING",
                    "risk": "HIGH",
                    "details": "OAuth sem parâmetro 'state'. Vulnerável a CSRF no fluxo de autenticação.",
                    "request_raw": format_http_request(resp.request),
                    "response_raw": format_http_response(resp),
                })
            
            if "nonce" not in qs and "openid" in str(qs.get("scope", "")):
                findings.append({
                    "url": url,
                    "type": "NONCE_MISSING",
                    "risk": "MEDIUM",
                    "details": "OpenID Connect sem parâmetro 'nonce'. Risco de Replay Attack.",
                    "request_raw": format_http_request(resp.request),
                    "response_raw": format_http_response(resp),
                })
    except Exception:
        pass

    # V10.2: Scope escalation test (deep mode)
    if deep and "scope" in qs:
        escalated_scopes = ["openid profile email admin", "openid profile email write", "openid profile email offline_access"]
        for scope in escalated_scopes:
            test_params = qs.copy()
            test_params["scope"] = [scope]
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(test_params, doseq=True), parsed.fragment))
            
            try:
                time.sleep(REQUEST_DELAY)
                with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=False) as client:
                    resp = client.get(test_url, headers={"User-Agent": DEFAULT_USER_AGENT})
                    
                    # Se o servidor não rejeita escopos escalados (não retorna 400/error)
                    if resp.status_code in [200, 301, 302, 303, 307, 308]:
                        body = resp.text.lower()
                        if "invalid_scope" not in body and "error" not in body[:200]:
                            findings.append({
                                "url": url,
                                "type": "SCOPE_ESCALATION",
                                "risk": "HIGH",
                                "details": f"OAuth aceitou scope escalado: '{scope}'. Pode conceder permissões extras.",
                                "request_raw": format_http_request(resp.request),
                                "response_raw": format_http_response(resp),
                            })
                            break
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
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   🔐 {C.BOLD}{C.CYAN}OAUTH MISCONFIGURATION SCANNER (V10.2 PRECISION){C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END} | Implicit Flow: Testando | Deep: {deep}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    outdir = ensure_outdir(target, "oauth_misconfig")
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    
    if not urls_file.exists():
        warn("⚠️ urls_200.txt não encontrado.")
        return []

    all_urls = [l.strip() for l in urls_file.read_text(errors="ignore").splitlines() if l.strip()]
    
    # Heurística de busca de endpoints OAuth
    candidates = []
    for url in all_urls:
        for pattern in OAUTH_URL_PATTERNS:
            if re.search(pattern, url, re.I):
                candidates.append(url)
                break
    
    candidates = list(set(candidates))[:40]
    max_workers = 3 if stealth else 8
    
    info(f"   📋 Analisando {len(candidates)} potenciais endpoints OAuth")

    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_test_oauth_vulnerabilities, url, deep): url for url in candidates}
        for future in as_completed(futures):
            try:
                findings = future.result()
                if findings:
                    results.extend(findings)
                    for f in findings:
                        info(f"   🔴 {C.RED}[{f['risk']}]{C.END} {f['type']} em {f['url']}")
            except Exception:
                pass

    output_file = outdir / "oauth_misconfig_results.json"
    output_file.write_text(json.dumps(results, indent=2, ensure_ascii=False))

    summary = {"tests_run": len(candidates), "findings": len(results), "status": "COMPLETED"}
    (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))

    if results:
        success(f"\n   🔐 {len(results)} OAuth misconfigurations detectadas!")
    else:
        info(f"   ✅ 0 OAuth issues detectadas em {len(candidates)} endpoints.")

    success(f"   📂 Resultados salvos em {output_file}")
    return results
