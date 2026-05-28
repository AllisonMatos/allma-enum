#!/usr/bin/env python3
"""
403 Bypass Scanner — Tenta bypass de restrições de acesso em endpoints protegidos.

Testa múltiplas técnicas:
  1. Path manipulation: /admin → /Admin, /./admin, /admin;.js
  2. Header injection: X-Original-URL, X-Forwarded-For, X-Custom-IP-Authorization
  3. Method switching: GET → POST, PUT, PATCH
  4. URL encoding: %2f, double encoding
  5. HTTP version downgrade: HTTP/1.0
"""
import json
import re
from pathlib import Path
from urllib.parse import urlparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

from menu import C
from plugins import ensure_outdir
from plugins.validation import finding
from ..output import info, success, warn, error
from ..http_utils import format_http_request, format_http_response

# ============================================================
# BYPASS TECHNIQUES
# ============================================================

def _generate_path_mutations(path: str) -> list:
    """Gera variações de path para bypass."""
    clean = path.rstrip("/")
    if not clean:
        return []

    mutations = [
        # Case variations
        (clean.upper(), "Case: UPPERCASE"),
        (clean[0] + clean[1:].capitalize(), "Case: Capitalize"),

        # Trailing/leading characters
        (clean + "/", "Trailing slash"),
        (clean + "/.", "Trailing /."),
        (clean + "//", "Double trailing slash"),
        (clean + "/./", "Trailing /./"),
        (clean + "..;/", "Trailing ..;/"),
        ("/" + clean.lstrip("/"), "Clean path"),

        # Path traversal tricks
        ("/." + clean, "Prefix /."),
        ("/./" + clean.lstrip("/"), "Prefix /./"),
        (clean + "%20", "Trailing %20"),
        (clean + "%09", "Trailing tab"),
        (clean + "?", "Trailing ?"),
        (clean + "??", "Trailing ??"),
        (clean + "#", "Trailing #"),
        (clean + "/*", "Trailing /*"),

        # Semicolon/dot tricks (Tomcat/IIS/Spring)
        (clean + ";.css", "Semicolon .css (Tomcat)"),
        (clean + ";.js", "Semicolon .js (Tomcat)"),
        (clean + ";.html", "Semicolon .html"),
        (clean + ";a=b", "Semicolon param"),
        (clean + "..;/", "..;/ (Tomcat bypass)"),
        (clean + ";/", ";/ suffix"),

        # URL encoding
        (quote(clean, safe=""), "Full URL encode"),
        (clean.replace("/", "%2f"), "Slash → %2f"),
        (clean.replace("/", "%252f"), "Double encode slash"),

        # Backslash (IIS)
        (clean.replace("/", "\\"), "Slash → backslash (IIS)"),

        # Null byte
        (clean + "%00", "Null byte suffix"),
        (clean + ".json", ".json extension"),
        (clean + ".html", ".html extension"),
    ]

    return mutations


BYPASS_HEADERS = [
    # IP spoofing headers
    ({"X-Forwarded-For": "127.0.0.1"}, "X-Forwarded-For: 127.0.0.1"),
    ({"X-Forwarded-For": "10.0.0.1"}, "X-Forwarded-For: 10.0.0.1"),
    ({"X-Forwarded-For": "0.0.0.0"}, "X-Forwarded-For: 0.0.0.0"),
    ({"X-Real-IP": "127.0.0.1"}, "X-Real-IP: 127.0.0.1"),
    ({"X-Custom-IP-Authorization": "127.0.0.1"}, "X-Custom-IP-Authorization: 127.0.0.1"),
    ({"X-Originating-IP": "127.0.0.1"}, "X-Originating-IP: 127.0.0.1"),
    ({"X-Remote-IP": "127.0.0.1"}, "X-Remote-IP: 127.0.0.1"),
    ({"X-Client-IP": "127.0.0.1"}, "X-Client-IP: 127.0.0.1"),
    ({"X-Host": "127.0.0.1"}, "X-Host: 127.0.0.1"),
    ({"X-Forwarded-Host": "127.0.0.1"}, "X-Forwarded-Host: 127.0.0.1"),

    # URL rewrite headers (Nginx/IIS)
    ({"X-Original-URL": "/admin"}, "X-Original-URL: /admin"),  # Placeholder, replaced per URL
    ({"X-Rewrite-URL": "/admin"}, "X-Rewrite-URL: /admin"),  # Placeholder
    ({"Content-Length": "0"}, "Content-Length: 0"),
]

BYPASS_METHODS = ["GET", "POST", "PUT", "PATCH", "OPTIONS", "HEAD", "TRACE"]


def check_bypass(url: str, original_status: int = 403) -> list:
    """Testa múltiplas técnicas de bypass em uma URL que retornou 403."""
    import httpx
    from core.config import DEFAULT_USER_AGENT

    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path or "/"

    bypasses = []

    try:
        with httpx.Client(timeout=10, verify=False, follow_redirects=False) as client:
            base_headers = {"User-Agent": DEFAULT_USER_AGENT}

            # 1. PATH MUTATIONS
            for mutated_path, technique in _generate_path_mutations(path):
                try:
                    test_url = f"{base_url}{mutated_path}"
                    resp = client.get(test_url, headers=base_headers)

                    if resp.status_code == 200:
                        bypasses.append({
                            "url": url,
                            "bypass_url": test_url,
                            "technique": f"Path: {technique}",
                            "category": "PATH_MANIPULATION",
                            "original_status": original_status,
                            "bypass_status": resp.status_code,
                            "response_length": len(resp.text),
                            "title": _extract_title(resp.text),
                            "request_raw": format_http_request(resp.request),
                            "response_raw": format_http_response(resp),
                        })
                except Exception:
                    pass

            # 2. HEADER INJECTION
            for extra_headers, technique in BYPASS_HEADERS:
                try:
                    # Para X-Original-URL/X-Rewrite-URL, usar o path real
                    headers = {**base_headers, **extra_headers}
                    if "X-Original-URL" in extra_headers:
                        headers["X-Original-URL"] = path
                        # Fazer request para / com o header
                        test_url = f"{base_url}/"
                        technique = f"X-Original-URL: {path}"
                    elif "X-Rewrite-URL" in extra_headers:
                        headers["X-Rewrite-URL"] = path
                        test_url = f"{base_url}/"
                        technique = f"X-Rewrite-URL: {path}"
                    else:
                        test_url = url

                    resp = client.get(test_url, headers=headers)

                    if resp.status_code == 200:
                        bypasses.append({
                            "url": url,
                            "bypass_url": test_url,
                            "technique": f"Header: {technique}",
                            "category": "HEADER_INJECTION",
                            "original_status": original_status,
                            "bypass_status": resp.status_code,
                            "response_length": len(resp.text),
                            "title": _extract_title(resp.text),
                            "request_raw": format_http_request(resp.request),
                            "response_raw": format_http_response(resp),
                        })
                except Exception:
                    pass

            # 3. METHOD SWITCHING
            for method in BYPASS_METHODS:
                if method == "GET":
                    continue  # Já testamos
                try:
                    resp = client.request(method, url, headers=base_headers)

                    if resp.status_code == 200 and method not in ("OPTIONS", "HEAD"):
                        bypasses.append({
                            "url": url,
                            "bypass_url": url,
                            "technique": f"Method: {method}",
                            "category": "METHOD_SWITCH",
                            "original_status": original_status,
                            "bypass_status": resp.status_code,
                            "response_length": len(resp.text),
                            "title": _extract_title(resp.text),
                            "request_raw": format_http_request(resp.request),
                            "response_raw": format_http_response(resp),
                        })
                except Exception:
                    pass

    except Exception:
        pass

    # Deduplicar por técnica + hostname + status
    seen_techniques = set()
    unique_bypasses = []
    for b in bypasses:
        try:
            from urllib.parse import urlparse
            hostname = urlparse(b["url"]).netloc
        except Exception:
            hostname = "unknown"
            
        key = (hostname, b["technique"], b["bypass_status"])
        if key not in seen_techniques:
            seen_techniques.add(key)
            unique_bypasses.append(b)

    return unique_bypasses


def _extract_title(html: str) -> str:
    """Extrai título de uma página HTML."""
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return match.group(1).strip()[:100] if match else ""


def run(context: dict):
    """Executa 403 Bypass Scanner em endpoints protegidos."""
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🔓───────────────────────────────────────────────────────────🔓\n"
        f"   🛡️  {C.BOLD}{C.CYAN}403 BYPASS SCANNER{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🔓───────────────────────────────────────────────────────────🔓\n"
    )

    outdir = ensure_outdir(target, "bypass403")

    # Coletar URLs que retornaram 403
    urls_403 = set()

    # Fonte 1: Admin panels com 403
    admin_file = Path("output") / target / "admin" / "admin_panels.json"
    if admin_file.exists():
        try:
            panels = json.loads(admin_file.read_text())
            for p in panels:
                if p.get("status") == 403:
                    urls_403.add(p.get("url", ""))
        except Exception:
            pass

    # Fonte 2: URLs com 403 do httpx
    urls_protected_file = Path("output") / target / "urls" / "urls_protected.txt"
    if urls_protected_file.exists():
        for line in urls_protected_file.read_text().splitlines():
            url = line.strip()
            if url:
                urls_403.add(url)

    # Fonte 3: urls_403.txt genérico
    urls_403_file = Path("output") / target / "urls" / "urls_403.txt"
    if urls_403_file.exists():
        for line in urls_403_file.read_text().splitlines():
            url = line.strip()
            if url:
                urls_403.add(url)

    urls_403.discard("")
    urls_403 = list(urls_403)

    if not urls_403:
        info("   ✅ Nenhuma URL com status 403 encontrada para testar.")
        (outdir / "findings.json").write_text("[]")
        return []

    info(f"   🔒 {len(urls_403)} URLs com status 403 para testar bypass...")

    # Limitar para evitar excesso de requests
    if len(urls_403) > 50:
        info(f"   ⚠️ Limitando a 50 URLs prioritárias (de {len(urls_403)})")
        # Priorizar paths com admin/internal indicators
        priority = [u for u in urls_403 if any(
            k in u.lower() for k in ["admin", "panel", "console", "manage", "internal", "debug", "api", "config"]
        )]
        rest = [u for u in urls_403 if u not in priority]
        urls_403 = (priority + rest)[:50]

    # Executar
    all_bypasses = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(check_bypass, url): url for url in urls_403}
        for future in as_completed(futures):
            url = futures[future]
            try:
                results = future.result()
                if results:
                    all_bypasses.extend(results)
                    for b in results:
                        info(
                            f"   🔓 {C.RED}BYPASS!{C.END} {b['url']} → "
                            f"{C.GREEN}{b['bypass_status']}{C.END} via {b['technique']}"
                        )
            except Exception:
                pass

    # Salvar raw
    raw_file = outdir / "bypass403_results.json"
    raw_file.write_text(json.dumps(all_bypasses, indent=2, ensure_ascii=False))

    # Normalizar findings
    normalized = []
    for b in all_bypasses:
        normalized.append(
            finding(
                plugin="bypass403",
                target=target,
                title=f"403 Bypass: {b.get('technique', '')}",
                issue_type="ACCESS_CONTROL_BYPASS",
                risk="HIGH",
                confidence="HIGH",
                description=(
                    f"Endpoint {b['url']} retorna 403, mas pode ser acessado via "
                    f"{b['technique']}. Status bypass: {b['bypass_status']}. "
                    f"Título: {b.get('title', 'N/A')}"
                ),
                url=b.get("url", ""),
                detection={
                    "original_status": b.get("original_status"),
                    "bypass_status": b.get("bypass_status"),
                    "technique": b.get("technique"),
                    "category": b.get("category"),
                },
                validation={
                    "bypass_url": b.get("bypass_url"),
                    "response_length": b.get("response_length"),
                    "title": b.get("title", ""),
                },
                evidence={
                    "request_raw": b.get("request_raw", ""),
                    "response_raw": b.get("response_raw", ""),
                    "observable_impact": f"403→{b.get('bypass_status')} via {b.get('technique')}",
                },
                metadata=b,
            )
        )

    (outdir / "findings.json").write_text(json.dumps(normalized, indent=2, ensure_ascii=False))

    # Resumo
    if all_bypasses:
        success(f"\n   🔓 {C.RED}{len(all_bypasses)} BYPASSES ENCONTRADOS!{C.END}")
        by_category = {}
        for b in all_bypasses:
            cat = b.get("category", "UNKNOWN")
            by_category[cat] = by_category.get(cat, 0) + 1
        for cat, count in by_category.items():
            info(f"   📊 {cat}: {count}")
    else:
        info("   ✅ Nenhum bypass de 403 encontrado.")

    success(f"   📂 Resultados salvos em {outdir}/")
    return normalized
