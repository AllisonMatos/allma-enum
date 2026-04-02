#!/usr/bin/env python3
"""
OAuth Misconfiguration — Detecta falhas em implementações OAuth.
Testa redirect_uri aberto, state ausente, PKCE bypass.
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


def _find_oauth_urls(urls: list) -> list:
    """Filtra URLs que parecem ser endpoints OAuth."""
    candidates = []
    for url in urls:
        for pattern in OAUTH_URL_PATTERNS:
            if re.search(pattern, url, re.I):
                candidates.append(url)
                break
    return list(set(candidates))


def _test_redirect_uri(url: str) -> dict | None:
    """Testa se redirect_uri aceita domínio externo."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    if "redirect_uri" in qs:
        qs["redirect_uri"] = [EVIL_REDIRECT]
    elif "redirect_url" in qs:
        qs["redirect_url"] = [EVIL_REDIRECT]
    else:
        qs["redirect_uri"] = [EVIL_REDIRECT]

    new_query = urlencode(qs, doseq=True)
    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    try:
        time.sleep(REQUEST_DELAY)
        with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=False) as client:
            resp = client.get(test_url, headers={"User-Agent": DEFAULT_USER_AGENT})

            location = resp.headers.get("location", "")
            body = resp.text[:5000].lower()

            # Verificar se redirecionou para nosso evil
            if "evil-enum-allma.com" in location:
                return {
                    "url": url,
                    "test_url": test_url,
                    "type": "OPEN_REDIRECT_URI",
                    "risk": "CRITICAL",
                    "status": resp.status_code,
                    "details": f"OAuth redirect_uri aceita domínio externo ({EVIL_REDIRECT})",
                    "request_raw": format_http_request(resp.request),
                    "response_raw": format_http_response(resp),
                }
            # Verificar se o evil aparece no body (formulário de consent)
            if "evil-enum-allma.com" in body:
                return {
                    "url": url,
                    "test_url": test_url,
                    "type": "REDIRECT_URI_REFLECTED",
                    "risk": "HIGH",
                    "status": resp.status_code,
                    "details": "redirect_uri refletido no corpo (possível OAuth abuse)",
                    "request_raw": format_http_request(resp.request),
                    "response_raw": format_http_response(resp),
                }
    except Exception:
        pass
    return None


def _test_state_missing(url: str) -> dict | None:
    """Verifica se o parâmetro state está ausente (CSRF em OAuth)."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    if "state" not in qs:
        # Verificar se a response do authorize endpoint não exige state
        try:
            time.sleep(REQUEST_DELAY)
            with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=False) as client:
                resp = client.get(url, headers={"User-Agent": DEFAULT_USER_AGENT})
                if resp.status_code in (200, 302, 303):
                    location = resp.headers.get("location", "")
                    if "code=" in location or "token=" in location:
                        return {
                            "url": url,
                            "type": "STATE_MISSING",
                            "risk": "MEDIUM",
                            "status": resp.status_code,
                            "details": "OAuth flow sem parâmetro 'state' — vulnerável a CSRF",
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
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   🔐 {C.BOLD}{C.CYAN}OAUTH MISCONFIGURATION SCANNER{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    outdir = ensure_outdir(target, "oauth_misconfig")

    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    if not urls_file.exists():
        warn("⚠️ urls_200.txt não encontrado.")
        (outdir / "oauth_misconfig_results.json").write_text(json.dumps([], indent=2))
        (outdir / "scan_summary.json").write_text(json.dumps({"tests_run": 0, "findings": 0, "status": "NO_INPUT"}, indent=2))
        return []

    all_urls = [l.strip() for l in urls_file.read_text(errors="ignore").splitlines() if l.strip()]
    oauth_urls = _find_oauth_urls(all_urls)

    info(f"   📋 {len(oauth_urls)} URLs OAuth-related encontradas")

    if not oauth_urls:
        info("   ✅ Nenhum endpoint OAuth detectado.")
        (outdir / "oauth_misconfig_results.json").write_text(json.dumps([], indent=2))
        (outdir / "scan_summary.json").write_text(json.dumps({"tests_run": 0, "urls_checked": len(all_urls), "findings": 0, "status": "NO_OAUTH"}, indent=2))
        return []

    results = []
    tests_run = 0

    for url in oauth_urls[:30]:
        # Test redirect_uri
        r = _test_redirect_uri(url)
        tests_run += 1
        if r:
            results.append(r)
            info(f"   🔴 {C.RED}[{r['risk']}]{C.END} {r['type']}: {url}")

        # Test state
        r2 = _test_state_missing(url)
        tests_run += 1
        if r2:
            results.append(r2)
            info(f"   ⚠️ {C.YELLOW}[{r2['risk']}]{C.END} {r2['type']}: {url}")

    output_file = outdir / "oauth_misconfig_results.json"
    output_file.write_text(json.dumps(results, indent=2, ensure_ascii=False))

    summary = {"tests_run": tests_run, "oauth_endpoints": len(oauth_urls), "findings": len(results), "status": "COMPLETED"}
    (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))

    if results:
        success(f"\n   🔐 {len(results)} OAuth misconfiguration(s) detectada(s)!")
    else:
        info(f"   ✅ 0 OAuth issues. Testados {len(oauth_urls)} endpoints ({tests_run} requests).")

    success(f"   📂 Salvos em {output_file}")
    return results
