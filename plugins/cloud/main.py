#!/usr/bin/env python3
"""
Plugin CLOUD RECON - Detecta buckets S3/Azure/GCP via DNS e HTTP
"""
import sys
import dns.resolver
import requests
import concurrent.futures
from pathlib import Path

import subprocess
from menu import C
from ..output import info, success, warn, error
from ..http_utils import check_tool_installed
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

# Permutações para Bug Bounty
CLOUD_PERMUTATIONS = [
    "{target}", "{target}-prod", "{target}-dev", "{target}-staging",
    "{target}-backup", "{target}-media", "{target}-assets", "{target}-static",
    "{target}-public", "{target}-private", "{target}-internal",
    "{target}-uploads", "{target}-downloads", "{target}-files",
    "{target}-data", "{target}-db", "{target}-database",
    "{target}-logs", "{target}-archive", "{target}-temp",
    "{target}-test", "{target}-demo", "{target}-sandbox",
    "{target}-web", "{target}-app", "{target}-api",
    "{target}-cdn", "{target}-content", "{target}-storage",
    "{target}-images", "{target}-videos", "{target}-docs",
    "{target}-documents", "{target}-reports", "{target}-exports",
    "{target}-imports", "{target}-sync", "{target}-mirror",
    "{target}-old", "{target}-new", "{target}-v1", "{target}-v2",
    "{target}-2019", "{target}-2020", "{target}-2021", "{target}-2022",
    "{target}-jan", "{target}-feb", "{target}-mar",  # meses
    "{target}-q1", "{target}-q2", "{target}-q3", "{target}-q4",  # trimestres
    "com.{target}", "org.{target}", "net.{target}",  # TLD invertido
    "{target}com", "{target}org", "{target}net",  # sem ponto
]

def generate_bucket_names(target_domain: str) -> list:
    """Gera lista de candidatos a buckets baseados no domínio"""
    base = target_domain.split(".")[0] # ex: grupovoz de grupovoz.com.br
    candidates = []
    
    for fmt in CLOUD_PERMUTATIONS:
        name = fmt.format(target=base)
        candidates.append(name)
        
    return list(set(candidates))


def extract_buckets_from_js(js_content: str) -> list:
    """Extrai referências a buckets de código JavaScript."""
    import re
    patterns = [
        r'["\']([a-z0-9-]+)\.s3[\.-][a-z0-9-]*\.amazonaws\.com["\']',
        r's3://([a-z0-9-]+)',
        r'["\']([a-z0-9-]+)\.blob\.core\.windows\.net["\']',
        r'["\']([a-z0-9-]+)\.storage\.googleapis\.com["\']',
    ]
    buckets = []
    for pattern in patterns:
        buckets.extend(re.findall(pattern, js_content, re.I))
    return list(set(buckets))

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
    
    # Tentar extrair buckets de arquivos JS se existirem
    js_urls_file = Path("output") / target / "urls" / "js_files.txt"
    if js_urls_file.exists():
        info(f"{C.BLUE}🔍 Extraindo buckets de arquivos JS conhecidos...{C.END}")
        try:
            # Por enquanto, apenas o nome do bucket se estiver na URL, 
            # ou podemos ler o conteúdo dos arquivos baixados se o jsscanner os salvou.
            # Como o cloud roda depois, vamos assumir que podemos tentar ler se houver cache.
            # Como o cloud roda depois, vamos assumir que podemos tentar ler se houver cache.
            pass 
        except: pass

    # ===============================
    # 🌩️ Executar Cloud_enum (se disponível)
    # ===============================
    if check_tool_installed("cloud_enum"):
        info(f"\n{C.BLUE}🌩️ Executando cloud_enum... aguarde, isso pode demorar alguns minutos.{C.END}")
        base_keyword = target.split(".")[0]
        ce_out = outdir / "cloud_enum_results.json"
        
        cmd = [
             "cloud_enum", "-k", base_keyword,
             "-j", str(ce_out)
        ]
        try:
             subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)
             info(f"   [+] cloud_enum finalizado.")
        except subprocess.TimeoutExpired:
             warn(f"   [!] Timeout ao executar cloud_enum.")
        except Exception as e:
             warn(f"   [!] Erro com cloud_enum: {e}")
             
        # Tentar fazer parse do JSON do cloud_enum caso tenha salvo algo util
        # Formato cloud_enum.json costuma ter chaves por provedor
        # Vamos apenas informar que o log bruto foi salvo.
        if ce_out.exists():
             info(f"   [✔] Resultados adicionais do cloud_enum salvos em: {ce_out}")
             
    else:
        warn("Ferramenta 'cloud_enum' não encontrada. Usando apenas scanner interno rápido.")

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
