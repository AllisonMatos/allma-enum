"""
plugins/cookies/main.py — Cookie Security Analyzer
Analisa cookies de todas as URLs validadas do target.
Verifica: HttpOnly, Secure, SameSite, Expiration, Path, Domain scope.
Gera cookies_results.json para alimentar o report.
"""
from core.config import DEFAULT_USER_AGENT, REQUEST_DELAY
import json
import time
import re
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Any

from core.colors import C
from plugins import ensure_outdir
from plugins.validation import finding
from ..output import info, success, warn, error


# ============================================================
# COOKIE ANALYSIS
# ============================================================

def parse_set_cookie(header_value: str, url: str) -> Dict[str, Any]:
    """Parse a single Set-Cookie header into structured data."""
    parts = [p.strip() for p in header_value.split(";")]
    if not parts:
        return {}

    # First part is name=value
    name_val = parts[0]
    if "=" in name_val:
        name, value = name_val.split("=", 1)
    else:
        name, value = name_val, ""

    cookie = {
        "name": name.strip(),
        "value_preview": value[:8] + "***" if len(value) > 8 else value,
        "value_length": len(value),
        "httponly": False,
        "secure": False,
        "samesite": "Not Set",
        "expires": "Session",
        "path": "/",
        "domain": "",
        "issues": [],
        "severity": "INFO",
        "source_url": url,
    }

    for attr in parts[1:]:
        attr_lower = attr.lower().strip()

        if attr_lower == "httponly":
            cookie["httponly"] = True
        elif attr_lower == "secure":
            cookie["secure"] = True
        elif attr_lower.startswith("samesite="):
            cookie["samesite"] = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("expires="):
            cookie["expires"] = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("max-age="):
            try:
                max_age = int(attr.split("=", 1)[1].strip())
                if max_age <= 0:
                    cookie["expires"] = "Expired"
                else:
                    days = max_age // 86400
                    cookie["expires"] = f"{days}d ({max_age}s)"
            except ValueError:
                cookie["expires"] = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("path="):
            cookie["path"] = attr.split("=", 1)[1].strip()
        elif attr_lower.startswith("domain="):
            cookie["domain"] = attr.split("=", 1)[1].strip()

    # ── Classify Issues ──
    is_session = _is_session_cookie(cookie["name"])

    # CRITICAL: Session cookie without HttpOnly = XSS can steal it
    if not cookie["httponly"] and is_session:
        cookie["issues"].append("HttpOnly ausente — vulnerável a XSS stealing")
        cookie["severity"] = "CRITICAL" if cookie["name"].lower() in ("phpsessid","jsessionid","asp.net_sessionid","connect.sid","session","sessionid") else "HIGH"

    if not cookie["secure"]:
        parsed_url = urlparse(url)
        if parsed_url.scheme == "https":
            cookie["issues"].append("Secure ausente em HTTPS — cookie exposto em downgrade")
            if cookie["severity"] not in ("HIGH", "CRITICAL"):
                cookie["severity"] = "MEDIUM"
        else:
            cookie["issues"].append("Secure ausente — cookie enviado em HTTP")
            if cookie["severity"] not in ("HIGH", "CRITICAL"):
                cookie["severity"] = "MEDIUM"

    samesite_val = cookie["samesite"].lower()
    if samesite_val == "none":
        if not cookie["secure"]:
            cookie["issues"].append("SameSite=None SEM Secure — cookie será rejeitado pelos browsers modernos")
            if cookie["severity"] not in ("HIGH", "CRITICAL"):
                cookie["severity"] = "HIGH"
        else:
            cookie["issues"].append("SameSite=None — vulnerável a CSRF cross-site")
            if cookie["severity"] not in ("HIGH", "CRITICAL"):
                cookie["severity"] = "MEDIUM"
    elif samesite_val == "not set":
        cookie["issues"].append("SameSite não definido — browser default (Lax)")
        if cookie["severity"] == "INFO":
            cookie["severity"] = "LOW"

    # __Host- and __Secure- prefix checks
    if cookie["name"].startswith("__Host-"):
        if not cookie["secure"] or cookie["path"] != "/" or cookie["domain"]:
            cookie["issues"].append("__Host- prefix violado (requer Secure, Path=/, sem Domain)")
            if cookie["severity"] not in ("HIGH", "CRITICAL"):
                cookie["severity"] = "MEDIUM"
    elif cookie["name"].startswith("__Secure-"):
        if not cookie["secure"]:
            cookie["issues"].append("__Secure- prefix violado (requer flag Secure)")
            if cookie["severity"] not in ("HIGH", "CRITICAL"):
                cookie["severity"] = "MEDIUM"

    if cookie["expires"] == "Session" and is_session:
        pass  # Normal for session cookies
    elif cookie["expires"] != "Session" and cookie["expires"] != "Expired":
        try:
            match = re.match(r'(\d+)d', cookie["expires"])
            if match and int(match.group(1)) > 365:
                cookie["issues"].append(f"Expiração excessiva: {cookie['expires']}")
                if cookie["severity"] == "INFO":
                    cookie["severity"] = "LOW"
        except:
            pass

    if cookie["domain"] and cookie["domain"].startswith("."):
        cookie["issues"].append(f"Domain scope amplo: {cookie['domain']}")

    if not cookie["issues"]:
        cookie["issues"].append("Configuração adequada")

    return cookie


SESSION_COOKIE_PATTERNS = [
    "session", "sess", "sid", "token", "auth", "jwt",
    "access", "refresh", "login", "user", "csrf",
    "xsrf", "identity", "credential", "phpsessid",
    "jsessionid", "asp.net_sessionid", "connect.sid",
    "_session", "laravel_session", "ci_session",
]

def _is_session_cookie(name: str) -> bool:
    """Check if a cookie name suggests it's a session/auth cookie."""
    name_lower = name.lower()
    return any(pat in name_lower for pat in SESSION_COOKIE_PATTERNS)


def analyze_url_cookies(url: str) -> List[Dict[str, Any]]:
    """Fetch a URL and analyze all Set-Cookie headers."""
    import httpx

    cookies_found = []
    try:
        with httpx.Client(
            timeout=10,
            verify=False,
            follow_redirects=True,
            max_redirects=5,
        ) as client:
            resp = client.get(url, headers={
                "User-Agent": DEFAULT_USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            })

            # Collect all Set-Cookie headers
            set_cookie_headers = resp.headers.multi_raw(b"set-cookie") if hasattr(resp.headers, 'multi_raw') else []

            # Fallback: iterate response headers
            if not set_cookie_headers:
                for key, val in resp.headers.multi_items():
                    if key.lower() == "set-cookie":
                        cookie = parse_set_cookie(val, url)
                        if cookie and cookie.get("name"):
                            cookies_found.append(cookie)
            else:
                for raw_val in set_cookie_headers:
                    val = raw_val.decode("utf-8", errors="replace") if isinstance(raw_val, bytes) else str(raw_val)
                    cookie = parse_set_cookie(val, url)
                    if cookie and cookie.get("name"):
                        cookies_found.append(cookie)

    except Exception:
        pass

    return cookies_found


# ============================================================
# RUN
# ============================================================

def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("context['target'] is required")

    outdir = ensure_outdir(target, "cookies")
    base = Path("output") / target

    info(f"\n{C.BOLD}{C.CYAN}🍪 Cookie Security Analyzer{C.END}")
    info(f"   Target: {target}")

    # Collect unique root URLs from validated URLs (V12: prioriza 2xx)
    from core.url_sources import primary_urls_txt_for_scan

    urls_file = primary_urls_txt_for_scan(target)
    domain_urls = base / "domain" / "urls_200.txt"

    raw_urls = set()
    for src in [urls_file, domain_urls]:
        if src.exists():
            for line in src.read_text(errors="ignore").splitlines():
                u = line.strip()
                if u:
                    raw_urls.add(u)

    if not raw_urls:
        warn("   Nenhuma URL validada encontrada. Rode o módulo 'urls' primeiro.")
        return []

    # Deduplicate by unique host (only test root of each host)
    host_urls = {}
    for u in raw_urls:
        try:
            parsed = urlparse(u)
            host_key = f"{parsed.scheme}://{parsed.netloc}"
            if host_key not in host_urls:
                host_urls[host_key] = host_key + "/"
        except:
            pass

    # Also add some interesting URLs (login, auth endpoints)
    auth_patterns = ["login", "auth", "signin", "dashboard", "admin", "account", "api"]
    for u in raw_urls:
        path = urlparse(u).path.lower()
        if any(pat in path for pat in auth_patterns):
            try:
                host_key = f"{urlparse(u).scheme}://{urlparse(u).netloc}"
                host_urls[u] = u  # Add the specific URL too
            except:
                pass

    test_urls = list(host_urls.values())[:100]  # Max 100 URLs
    info(f"   Testando {len(test_urls)} URLs únicas...")

    # Parallel analysis
    all_cookies = []
    seen_names = set()

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(analyze_url_cookies, url): url for url in test_urls}
        done = 0
        for future in as_completed(futures):
            done += 1
            if done % 10 == 0:
                info(f"   Progresso: {done}/{len(test_urls)}")
            try:
                cookies = future.result()
                for c in cookies:
                    # Deduplicate by cookie name per host
                    key = f"{c['name']}:{urlparse(c['source_url']).netloc}"
                    if key not in seen_names:
                        seen_names.add(key)
                        all_cookies.append(c)
            except:
                pass
            time.sleep(REQUEST_DELAY * 0.1)

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_cookies.sort(key=lambda x: sev_order.get(x.get("severity", "INFO"), 5))

    # Stats
    n_total = len(all_cookies)
    n_high = sum(1 for c in all_cookies if c["severity"] in ("CRITICAL", "HIGH"))
    n_medium = sum(1 for c in all_cookies if c["severity"] == "MEDIUM")
    n_session = sum(1 for c in all_cookies if _is_session_cookie(c["name"]))
    n_no_httponly = sum(1 for c in all_cookies if not c["httponly"] and _is_session_cookie(c["name"]))
    n_no_secure = sum(1 for c in all_cookies if not c["secure"])

    # Save results
    results = {
        "target": target,
        "total_cookies": n_total,
        "stats": {
            "high_risk": n_high,
            "medium_risk": n_medium,
            "session_cookies": n_session,
            "missing_httponly": n_no_httponly,
            "missing_secure": n_no_secure,
        },
        "cookies": all_cookies,
    }

    results_file = outdir / "cookies_results.json"
    results_file.write_text(json.dumps(results, indent=2, ensure_ascii=False))
    normalized_findings = []
    sev_to_risk = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "INFO": "INFO"}
    sev_to_conf = {"CRITICAL": "HIGH", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "INFO": "LOW"}
    for c in all_cookies:
        sev = str(c.get("severity", "INFO")).upper()
        normalized_findings.append(
            finding(
                plugin="cookies",
                target=target,
                title=f"Insecure Cookie: {c.get('name', '')}",
                issue_type="INSECURE_COOKIE",
                risk=sev_to_risk.get(sev, "LOW"),
                confidence=sev_to_conf.get(sev, "LOW"),
                description=", ".join(c.get("issues", [])),
                url=c.get("source_url", ""),
                detection={
                    "name": c.get("name", ""),
                    "httponly": c.get("httponly", False),
                    "secure": c.get("secure", False),
                    "samesite": c.get("samesite", "Not Set"),
                },
                validation={"cookie_parsed": True},
                evidence={
                    "matched_snippet": c.get("name", ""),
                    "observable_impact": ", ".join(c.get("issues", [])),
                },
                metadata=c,
            )
        )
    (outdir / "findings.json").write_text(json.dumps(normalized_findings, indent=2, ensure_ascii=False))

    # Print summary
    success(f"\n{C.BOLD}{C.CYAN}🍪 COOKIE ANALYSIS COMPLETO{C.END}")
    success(f"   📊 Total Cookies: {C.BOLD}{n_total}{C.END}")
    if n_high > 0:
        warn(f"   🔴 HIGH Risk: {n_high}")
    if n_medium > 0:
        warn(f"   🟡 MEDIUM Risk: {n_medium}")
    info(f"   🔑 Session Cookies: {n_session}")
    if n_no_httponly > 0:
        warn(f"   ❌ Sem HttpOnly (session): {n_no_httponly}")
    if n_no_secure > 0:
        warn(f"   ❌ Sem Secure: {n_no_secure}")
    success(f"   Resultados: {results_file}")

    return normalized_findings
