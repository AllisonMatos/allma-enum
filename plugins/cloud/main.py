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
        try:
             dns.resolver.resolve(f"{name}.blob.core.windows.net", 'A')
             r = requests.head(azure_url, timeout=3)
             results.append({"provider": "Azure", "name": name, "status": "EXIST", "url": azure_url})
        except:
             pass
    except:
        pass

    # 3. GCP / Google Cloud Storage
    # GCP pattern: https://storage.googleapis.com/<name>
    gcp_url = f"https://storage.googleapis.com/{name}"
    try:
        r = requests.head(gcp_url, timeout=3)
        if r.status_code != 404:
            status = "OPEN" if r.status_code == 200 else "PROTECTED"
            results.append({"provider": "GCP", "name": name, "status": status, "url": gcp_url})
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
        # Testar permissões dos buckets encontrados
        info(f"\n   🔐 Testando permissões dos buckets encontrados...")
        test_write = context.get("test_write", False)  # Opt-in para teste de escrita

        for bucket in found_buckets:
            perms = test_bucket_permissions(bucket["provider"], bucket["name"], bucket["url"], test_write)
            bucket["permissions"] = perms
            if perms:
                perm_str = ",".join(perms)
                perm_color = C.RED if "WRITE" in perms else (C.YELLOW if "LIST" in perms else C.GREEN)
                info(f"   🔓 [{bucket['provider']}] {bucket['name']} → {perm_color}{perm_str}{C.END}")

        with open(out_file, "w") as f:
            for b in found_buckets:
                perms_str = ",".join(b.get("permissions", []))
                f.write(f"{b['provider']}\t{b['name']}\t{b['status']}\t{b['url']}\t{perms_str}\n")
        success(f"📂 {len(found_buckets)} buckets encontrados salvos em {out_file}")

        # Salvar JSON detalhado
        import json
        json_file = outdir / "buckets.json"
        json_file.write_text(json.dumps(found_buckets, indent=2, ensure_ascii=False))
    else:
        warn("⚠️ Nenhum bucket encontrado.")
        
    return found_buckets


def test_bucket_permissions(provider: str, name: str, url: str, test_write: bool = False) -> list:
    """
    Testa permissões de um bucket descoberto.
    Retorna lista: ["LIST", "READ", "WRITE"] conforme aplicável.
    """
    permissions = []

    if provider == "AWS":
        # LIST: GET /?list-type=2
        try:
            r = requests.get(f"http://{name}.s3.amazonaws.com/?list-type=2", timeout=5)
            if r.status_code == 200 and "<Contents>" in r.text:
                permissions.append("LIST")
        except:
            pass

        # READ: GET /test - tentar ler qualquer objeto
        try:
            r = requests.get(f"http://{name}.s3.amazonaws.com/", timeout=5)
            if r.status_code == 200:
                permissions.append("READ")
        except:
            pass

        # WRITE: PUT (SOMENTE se opt-in)
        if test_write:
            try:
                r = requests.put(
                    f"http://{name}.s3.amazonaws.com/enum-allma-permission-test.txt",
                    data="permission_test",
                    timeout=5
                )
                if r.status_code in (200, 201):
                    permissions.append("WRITE")
                    # Limpar o arquivo de teste
                    try:
                        requests.delete(
                            f"http://{name}.s3.amazonaws.com/enum-allma-permission-test.txt",
                            timeout=5
                        )
                    except:
                        pass
            except:
                pass

    elif provider == "GCP":
        # LIST: GET /storage/v1/b/{name}/o
        try:
            r = requests.get(f"https://storage.googleapis.com/storage/v1/b/{name}/o", timeout=5)
            if r.status_code == 200:
                permissions.append("LIST")
        except:
            pass

        # READ
        try:
            r = requests.get(f"https://storage.googleapis.com/{name}/", timeout=5)
            if r.status_code == 200:
                permissions.append("READ")
        except:
            pass

    elif provider == "Azure":
        # LIST: GET ?restype=container&comp=list
        try:
            r = requests.get(f"{url}?restype=container&comp=list", timeout=5)
            if r.status_code == 200 and "<Blob>" in r.text:
                permissions.append("LIST")
        except:
            pass

    return permissions
