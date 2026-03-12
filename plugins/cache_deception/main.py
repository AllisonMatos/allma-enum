#!/usr/bin/env python3
"""
Web Cache Deception Scanner — Detecção real de cache deception
Compara respostas com e sem path extension para detectar caching indevido
Captura raw request/response
"""
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from menu import C
from ..output import info, success, warn, error
from ..http_utils import format_raw_request, format_raw_response

try:
    import httpx
except ImportError:
    httpx = None


CACHE_EXTENSIONS = [
    ".css", ".js", ".jpg", ".png", ".gif", ".ico",
    ".svg", ".woff", ".woff2", ".ttf",
]

CACHE_HEADERS = [
    "x-cache", "cf-cache-status", "x-varnish", "age",
    "x-fastly-request-id", "x-served-by", "x-cache-hits",
]


def ensure_outdir(target):
    outdir = Path("output") / target / "scanners"
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir


def test_cache_deception(client, url):
    """Testa cache deception numa URL"""
    findings = []
    
    try:
        # Request 1: URL original
        resp_orig = client.get(url, timeout=10)
        body_orig = resp_orig.text
        
        if resp_orig.status_code != 200:
            return []
        
        # Para cada extensão estática
        for ext in CACHE_EXTENSIONS[:5]:  # Limitar para performance
            test_url = url.rstrip("/") + f"/nonexistent{ext}"
            
            try:
                resp_test = client.get(test_url, timeout=10)
                body_test = resp_test.text
                
                if resp_test.status_code != 200:
                    continue
                
                # Verificar se há headers de cache
                has_cache = False
                cache_info = ""
                for ch in CACHE_HEADERS:
                    val = resp_test.headers.get(ch, "")
                    if val:
                        has_cache = True
                        cache_info += f"{ch}: {val}; "
                
                # Verificar se o conteúdo dinâmico foi cacheado
                # (o conteúdo da URL com extensão é similar ao original)
                if has_cache and len(body_test) > 100:
                    # Calcular similaridade simples
                    similarity = 0
                    if len(body_orig) > 0:
                        # Usar ratio de tamanho + buscar conteúdo específico
                        size_ratio = min(len(body_test), len(body_orig)) / max(len(body_test), len(body_orig))
                        if size_ratio > 0.7:
                            similarity = size_ratio
                    
                    if similarity > 0.7:
                        raw_req = format_raw_request("GET", test_url, dict(resp_test.request.headers))
                        raw_res = format_raw_response(resp_test.status_code, dict(resp_test.headers), body_test[:2000])
                        findings.append({
                            "url": url,
                            "test_url": test_url,
                            "type": "CACHE_DECEPTION",
                            "extension": ext,
                            "risk": "HIGH",
                            "status": resp_test.status_code,
                            "cache_headers": cache_info,
                            "similarity": f"{similarity:.0%}",
                            "details": f"Conteúdo dinâmico cacheado com extensão '{ext}' ({cache_info.strip()})",
                            "request_raw": raw_req,
                            "response_raw": raw_res,
                        })
                        break  # Um finding por URL é suficiente
            except Exception:
                continue
                
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
        f"\n🟦───────────────────────────────────────────────────────────🟦\n"
        f"   🗃️  {C.BOLD}{C.CYAN}CACHE DECEPTION SCANNER{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟦───────────────────────────────────────────────────────────🟦\n"
    )

    outdir = ensure_outdir(target)
    results_file = outdir / "cache_deception.json"
    
    # Carregar URLs
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    if not urls_file.exists():
        urls_file = Path("output") / target / "domain" / "urls_valid.txt"
    
    if not urls_file.exists():
        warn("Nenhum arquivo de URLs encontrado")
        return []
    
    all_urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]
    
    # Filtrar: somente URLs dinâmicas (sem extensões estáticas)
    static_exts = {".js", ".css", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".woff2"}
    testable = []
    for url in all_urls:
        path = urlparse(url).path.lower()
        if not any(path.endswith(ext) for ext in static_exts):
            testable.append(url)
    
    testable = testable[:100]
    
    if not testable:
        info("Nenhuma URL dinâmica encontrada para testar")
        json.dump([], open(results_file, "w"))
        return [str(results_file)]
    
    info(f"   📊 Testando {len(testable)} URLs dinâmicas")
    
    all_findings = []
    
    with httpx.Client(verify=False, follow_redirects=True, timeout=15) as client:
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(test_cache_deception, client, url): url for url in testable}
            
            for future in as_completed(futures):
                try:
                    results = future.result()
                    if results:
                        all_findings.extend(results)
                        for r in results:
                            info(f"   🚨 {C.RED}Cache Deception: {r['url']}{C.END}")
                except Exception:
                    pass
    
    results_file.write_text(json.dumps(all_findings, indent=2, ensure_ascii=False))
    
    if all_findings:
        success(f"🗃️ {len(all_findings)} potenciais cache deception encontrados!")
    else:
        success("✅ Nenhum cache deception detectado")
    
    return [str(results_file)]
