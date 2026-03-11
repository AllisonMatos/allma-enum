#!/usr/bin/env python3
"""
Open Redirect Scanner — Detecta redirecionamentos inseguros.
"""
import requests
from urllib.parse import urlparse, parse_qsl, urlunparse, urlencode
from pathlib import Path

from menu import C
from ..output import info, success, warn, error

# Desabilitar avisos de SSL (opcional, já que o runner configurou globalmente mas aqui usamos requests direto)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "///evil.com",
    "/\\evil.com",
    "evil.com",
    "https://{target}.evil.com",
]

def ensure_outdir(target: str) -> Path:
    outdir = Path("output") / target / "open_redirect"
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir

def scan_open_redirect(urls: list, target: str) -> list:
    """Detecta vulnerabilidades de Open Redirect."""
    findings = []
    
    # Parâmetros comuns de redirecionamento
    redirect_params = {'redirect', 'url', 'next', 'return', 'dest', 'destination', 'goto', 'u', 'link', 'uri', 'path', 'continue', 'return_to'}

    for url in urls:
        try:
            parsed = urlparse(url)
            if not parsed.query:
                continue
                
            params = dict(parse_qsl(parsed.query))
            for param in params:
                if any(x in param.lower() for x in redirect_params):
                    for payload in PAYLOADS:
                        # Preparar payload dinâmico
                        current_payload = payload.format(target=target)
                        
                        # Criar nova URL com o payload
                        new_params = params.copy()
                        new_params[param] = current_payload
                        
                        new_query = urlencode(new_params)
                        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
                        
                        try:
                            resp = requests.get(test_url, allow_redirects=False, verify=False, timeout=8)
                            location = resp.headers.get('Location', '')
                            
                            # Validar se o redirecionamento foi para o evil.com
                            if resp.status_code in (301, 302, 303, 307, 308) and ('evil.com' in location or location.startswith('//evil.com')):
                                warn(f"   🚩 [OPEN REDIRECT] {C.YELLOW}{url}{C.END} (Param: {param}, Payload: {current_payload})")
                                findings.append({
                                    "url": url,
                                    "param": param,
                                    "payload": current_payload,
                                    "location": location,
                                    "status_code": resp.status_code
                                })
                                break # Encontrou um, pula para o próximo parâmetro/url
                        except:
                            continue
        except Exception as e:
            continue
            
    return findings

def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")
        
    info(
        f"\n🔄───────────────────────────────────────────────────────────🔄\n"
        f"   🌐 {C.BOLD}{C.CYAN}INICIANDO MÓDULO: OPEN REDIRECT SCANNER{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🔄───────────────────────────────────────────────────────────🔄\n"
    )
    
    # 1. Carregar URLs
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    if not urls_file.exists():
        warn("⚠️ Arquivo de URLs (urls_200.txt) não encontrado. Pule para extração de URLs primeiro.")
        return []
        
    urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]
    info(f"   📂 Analisando {len(urls)} URLs em busca de parâmetros de redirecionamento...")
    
    # 2. Executar Scan
    findings = scan_open_redirect(urls, target)
    
    # 3. Salvar Resultados
    outdir = ensure_outdir(target)
    out_file = outdir / "findings.json"
    
    import json
    with open(out_file, "w") as f:
        json.dump(findings, f, indent=4)
        
    if findings:
        success(f"\n   ✔ {len(findings)} vulnerabilidades de Open Redirect encontradas!")
        success(f"   📂 Arquivo salvo em: {out_file}")
    else:
        info("\n   ✔ Nenhum Open Redirect detectado.")
        
    return findings
