#!/usr/bin/env python3
"""
Plugin CLOUD RECON - Detecta buckets S3/Azure/GCP via DNS e HTTP
"""
import sys
import dns.resolver
import requests
import concurrent.futures
from pathlib import Path

from menu import C
from ..output import info, success, warn, error
from .utils import ensure_outdir

# ============================================================
# TEMPLATES DE BUCKETS
# ============================================================
PROVIDERS = {
    "aws": [
        "s3.amazonaws.com",
        "s3-external-1.amazonaws.com",
        "s3.us-east-1.amazonaws.com",
        "s3.us-west-1.amazonaws.com"
    ],
    "azure": [
        "blob.core.windows.net"
    ],
    "gcp": [
        "storage.googleapis.com"
    ]
}

# Permutações comuns
PERMUTATIONS = [
    "{target}",
    "{target}-assets",
    "{target}-static",
    "{target}-media",
    "{target}-backup",
    "{target}-dev",
    "{target}-staging",
    "{target}-prod",
    "{target}-public",
    "assets-{target}",
    "static-{target}",
    "media-{target}",
    "backup-{target}"
]

def generate_bucket_names(target_domain: str) -> list:
    """Gera lista de candidatos a buckets baseados no domínio"""
    base = target_domain.split(".")[0] # ex: grupovoz de grupovoz.com.br
    candidates = []
    
    for fmt in PERMUTATIONS:
        name = fmt.format(target=base)
        candidates.append(name)
        
    return list(set(candidates))

def check_bucket(name: str):
    """Verifica se o bucket existe via DNS ou HTTP"""
    results = []
    
    # 1. AWS S3 (DNS check is reliable for CNAMEs, but bucket direct access is better checked via HTTP)
    # AWS pattern: http://<name>.s3.amazonaws.com
    aws_url = f"http://{name}.s3.amazonaws.com"
    try:
        r = requests.head(aws_url, timeout=3)
        if r.status_code != 404: # 200 (Open), 403 (Auth Required) -> Both mean it exists
            status = "OPEN" if r.status_code == 200 else "PROTECTED"
            results.append({"provider": "AWS", "name": name, "status": status, "url": aws_url})
    except:
        pass

    # 2. Azure Blob
    # Azure pattern: https://<name>.blob.core.windows.net
    azure_url = f"https://{name}.blob.core.windows.net"
    try:
        # Azure often returns 404 if container missing within account, but if account missing, it's DNS error.
        # So we check DNS first.
        try:
             dns.resolver.resolve(f"{name}.blob.core.windows.net", 'A')
             # If DNS resolves, check HTTP
             r = requests.head(azure_url, timeout=3)
             # Usually 400 (Invalid Query) or 409 (Conflict) means it exists. 404 might mean container missing but account exists.
             # Simplification: If DNS resolves, it's a hit for the Account Name.
             results.append({"provider": "Azure", "name": name, "status": "EXIST", "url": azure_url})
        except:
             pass
    except:
        pass
        
    return results

def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")
        
    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   ☁️  {C.BOLD}{C.CYAN}INICIANDO MÓDULO: CLOUD RECON{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )
    
    outdir = ensure_outdir(target)
    out_file = outdir / "buckets.txt"
    
    # Gerar nomes
    bucket_names = generate_bucket_names(target)
    info(f"{C.BLUE}🧩 Gerados {len(bucket_names)} nomes potenciais de buckets.{C.END}")
    
    found_buckets = []
    
    # Verificar em paralelo
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_bucket = {executor.submit(check_bucket, name): name for name in bucket_names}
        for future in concurrent.futures.as_completed(future_to_bucket):
            try:
                data = future.result()
                if data:
                    found_buckets.extend(data)
                    for b in data:
                        status_color = C.GREEN if b['status'] == 'OPEN' else C.YELLOW
                        info(f"   ☁️  [{b['provider']}] {b['name']} -> {status_color}{b['status']}{C.END}")
            except Exception as e:
                pass
                
    if found_buckets:
        with open(out_file, "w") as f:
            for b in found_buckets:
                f.write(f"{b['provider']}\t{b['name']}\t{b['status']}\t{b['url']}\n")
        success(f"📂 {len(found_buckets)} buckets encontrados salvos em {out_file}")
    else:
        warn("⚠️ Nenhum bucket encontrado.")
        
    return found_buckets
