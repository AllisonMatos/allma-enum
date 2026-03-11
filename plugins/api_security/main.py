#!/usr/bin/env python3
"""
API Security Scanner — Verifica vulnerabilidades comuns em endpoints de API.
"""
import requests
import time
from pathlib import Path
from urllib.parse import urlparse

from menu import C
from ..output import info, success, warn, error

def ensure_outdir(target: str) -> Path:
    outdir = Path("output") / target / "api_security"
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir

def check_api_vulnerabilities(base_url: str) -> list:
    """Verifica vulnerabilidades comuns em APIs."""
    checks = []
    
    try:
        # 1. Verificar se OPTIONS retorna métodos permitidos perigosos
        resp = requests.options(base_url, verify=False, timeout=5)
        allow = resp.headers.get('Allow', '')
        if 'DELETE' in allow or 'PUT' in allow or 'PATCH' in allow:
            warn(f"   🚩 [DANGEROUS METHODS] {C.YELLOW}{base_url}{C.END} (Metodos: {allow})")
            checks.append({"type": "DANGEROUS_METHODS", "methods": allow, "url": base_url})
        
        # 2. Verificar falta de rate limiting (10 requests rápidas)
        start = time.time()
        count = 0
        for _ in range(10):
            try:
                r = requests.get(base_url, verify=False, timeout=3)
                if r.status_code != 429:
                    count += 1
            except: break
        elapsed = time.time() - start
        if count >= 10 and elapsed < 2:  # 10 requests bem sucedidas em menos de 2 segundos
            # warn(f"   🟡 [POTENTIAL NO RATE LIMIT] {base_url} ({count} reqs em {elapsed:.2f}s)")
            checks.append({"type": "NO_RATE_LIMIT", "requests": count, "time": elapsed, "url": base_url})
        
        # 3. Verificar CORS em endpoints de API
        resp = requests.get(base_url, headers={"Origin": "https://evil-allma-scanner.com"}, verify=False, timeout=5)
        if "evil-allma-scanner.com" in resp.headers.get("Access-Control-Allow-Origin", ""):
            warn(f"   🚩 [CORS API] {C.RED}{base_url}{C.END} (Refletiu Origin malicioso!)")
            checks.append({"type": "CORS_API", "severity": "high", "url": base_url})
            
    except Exception:
        pass
    
    return checks

def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")
        
    info(
        f"\n🛠️───────────────────────────────────────────────────────────🛠️\n"
        f"   🛡️  {C.BOLD}{C.CYAN}INICIANDO MÓDULO: API SECURITY SCANNER{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🛠️───────────────────────────────────────────────────────────🛠️\n"
    )
    
    # 1. Carregar URLs e procurar por potenciais APIs
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    if not urls_file.exists():
        warn("⚠️ Arquivo de URLs não encontrado.")
        return []
        
    urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]
    
    api_endpoints = set()
    for u in urls:
        if "/api/" in u or "/v1/" in u or "/v2/" in u or u.endswith(".json"):
            api_endpoints.add(u)
            
    if not api_endpoints:
        # Tentar a base como fallback
        from urllib.parse import urlparse
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}/api" if parsed.scheme else f"https://{target}/api"
        api_endpoints.add(base)

    info(f"   📂 Testando {len(api_endpoints)} potenciais endpoints de API...")
    
    all_findings = []
    # Limitar para não demorar muito se houver centenas
    list_endpoints = list(api_endpoints)[:50] 
    
    for ep in list_endpoints:
        findings = check_api_vulnerabilities(ep)
        if findings:
            all_findings.extend(findings)
            
    # 3. Salvar Resultados
    outdir = ensure_outdir(target)
    out_file = outdir / "findings.json"
    
    import json
    with open(out_file, "w") as f:
        json.dump(all_findings, f, indent=4)
        
    if all_findings:
        success(f"\n   ✔ {len(all_findings)} potenciais problemas de segurança em API detectados!")
    else:
        info("\n   ✔ Nenhum problema óbvio de segurança em API detectado nas amostras.")
        
    return all_findings
