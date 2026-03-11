#!/usr/bin/env python3
"""
Web Cache Deception Detector — Identifica vulnerabilidades de envenenamento de cache.
"""
import requests
from pathlib import Path
from urllib.parse import urlparse

from menu import C
from ..output import info, success, warn, error

def ensure_outdir(target: str) -> Path:
    outdir = Path("output") / target / "cache_deception"
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir

def detect_cache_deception(url: str) -> dict | None:
    """Detecta se o cache armazena conteúdo privado ao adicionar extensão estática."""
    try:
        # Base URL sem a barra final
        base = url.rstrip('/')
        
        # 1. Request normal com cookie de teste
        # (Em um pentest real usaríamos um cookie real de sessão do usuário)
        session = {"session": "enum-allma-test-deception"}
        
        # 2. Request com extensão de arquivo estático (.js, .css, .jpg)
        suffixes = [".js", ".css", ".jpg", "/nonexistent.jpg"]
        
        for suffix in suffixes:
            test_url = f"{base}{suffix}"
            resp = requests.get(test_url, verify=False, timeout=8, cookies=session)
            
            # Se retornar 200 e o conteúdo for sensível (contém o cookie ou info do profile)
            # E tiver headers de cache
            if resp.status_code == 200:
                is_cached = any(h in resp.headers for h in ["CF-Cache-Status", "X-Cache", "X-Varnish", "Cache-Control"])
                
                # Heurística: se o conteúdo parece ser o da página principal mas servido como JS/outros
                if "session" in resp.text or "profile" in resp.text or "email" in resp.text:
                    if "javascript" in resp.headers.get("Content-Type", "").lower() or "css" in resp.headers.get("Content-Type", "").lower():
                        return {
                            "vulnerable": True,
                            "url": test_url,
                            "suffix": suffix,
                            "content_type": resp.headers.get("Content-Type"),
                            "cached_headers": is_cached
                        }
    except:
        pass
    return None

def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")
        
    info(
        f"\n🧊───────────────────────────────────────────────────────────🧊\n"
        f"   🕸️  {C.BOLD}{C.CYAN}INICIANDO MÓDULO: WEB CACHE DECEPTION DETECTOR{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🧊───────────────────────────────────────────────────────────🧊\n"
    )
    
    # 1. Carregar URLs de endpoints dinâmicos (como profile, settings, account)
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    if not urls_file.exists():
        warn("⚠️ Arquivo de URLs não encontrado.")
        return []
        
    urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]
    
    # Lista de páginas que costumam ter info sensível
    sensitive_paths = ["/profile", "/account", "/settings", "/user", "/me", "/api/v1/me"]
    
    targets = []
    for u in urls:
        if any(path in u for path in sensitive_paths):
            targets.append(u)
            
    # Se não encontrar nada, testar a raiz se parecer um app
    if not targets:
        from urllib.parse import urlparse
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else f"https://{target}"
        targets.append(base)

    info(f"   📂 Testando {len(targets)} potenciais alvos de Cache Deception...")
    
    all_findings = []
    for t in targets:
        result = detect_cache_deception(t)
        if result:
            warn(f"   🚩 [CACHE DECEPTION] {C.RED}{result['url']}{C.END} (Possivel vazamento via cache!)")
            all_findings.append(result)
            
    # 3. Salvar Resultados
    outdir = ensure_outdir(target)
    out_file = outdir / "findings.json"
    
    import json
    with open(out_file, "w") as f:
        json.dump(all_findings, f, indent=4)
        
    if all_findings:
        success(f"\n   ✔ {len(all_findings)} vulnerabilidades de Cache Deception detectadas!")
    else:
        info("\n   ✔ Nenhuma vulnerabilidade de Cache Deception detectada.")
        
    return all_findings
