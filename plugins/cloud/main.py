#!/usr/bin/env python3
"""
Plugin CLOUD RECON - Detecta buckets S3/Azure/GCP via DNS e HTTP
"""
import sys
import dns.resolver
import httpx
import concurrent.futures
from pathlib import Path

import subprocess
from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from ..http_utils import check_tool_installed
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
    parts = target_domain.split(".")
    # Heurística: para domínios com 3+ partes (ex: api.example.com.br),
    # pegar o penúltimo segmento significativo como brand.
    # Para domínios com 2 partes (example.com), pegar o primeiro.
    if len(parts) >= 3 and parts[-1] in ("br", "uk", "au", "jp", "in", "za", "mx", "ar", "co"):
        # ccTLD composto (com.br, co.uk, etc.)
        base = parts[-3] if len(parts) >= 3 else parts[0]
    elif len(parts) >= 3:
        # Subdomínio (api.example.com) → pegar 'example'
        base = parts[-2]
    else:
        base = parts[0]
    
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
    
    # 1. AWS S3 (Path-style universal, suporta qualquer região)
    # AWS pattern: https://s3.amazonaws.com/<name>
    aws_url = f"https://s3.amazonaws.com/{name}"
    try:
        r = httpx.head(aws_url, timeout=3)
        # V11: Aceitar SOMENTE 200 (aberto) ou 403 (existe mas protegido)
        # Outros códigos (400, 500, etc) são ruído
        if r.status_code in (200, 403):
            status = "OPEN" if r.status_code == 200 else "PROTECTED"
            results.append({"provider": "AWS", "name": name, "status": status, "url": aws_url})
    except Exception:
        pass

    # 2. Azure Blob
    # Azure pattern: https://<name>.blob.core.windows.net
    azure_url = f"https://{name}.blob.core.windows.net"
    try:
        try:
             dns.resolver.resolve(f"{name}.blob.core.windows.net", 'A')
             r = httpx.head(azure_url, timeout=3)
             results.append({"provider": "Azure", "name": name, "status": "EXIST", "url": azure_url})
        except Exception:
             pass
    except:
        pass

    # 3. GCP / Google Cloud Storage
    # GCP pattern: https://storage.googleapis.com/<name>
    gcp_url = f"https://storage.googleapis.com/{name}"
    try:
        r = httpx.head(gcp_url, timeout=3)
        if r.status_code != 404:
            status = "OPEN" if r.status_code == 200 else "PROTECTED"
            results.append({"provider": "GCP", "name": name, "status": status, "url": gcp_url})
    except Exception:
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
    
    outdir = ensure_outdir(target, "cloud")
    out_file = outdir / "buckets.txt"
    
    # Gerar nomes
    bucket_names = generate_bucket_names(target)
    
    # V10.3: Extrair buckets de arquivos JS reais
    js_urls_file = Path("output") / target / "urls" / "js_files.txt"
    js_analysis_file = Path("output") / target / "jsscanner" / "js_analysis.json"
    
    # Método 1: Extrair de URLs de JS (nomes de buckets no path)
    if js_urls_file.exists():
        info(f"{C.BLUE}🔍 Extraindo buckets de URLs de JS conhecidos...{C.END}")
        try:
            js_urls_content = js_urls_file.read_text(errors="ignore")
            js_buckets = extract_buckets_from_js(js_urls_content)
            if js_buckets:
                info(f"   [+] {len(js_buckets)} nomes de buckets extraídos de URLs de JS")
                bucket_names.extend(js_buckets)
        except Exception:
            pass
    
    # Método 2: Extrair do conteúdo JS analisado pelo jsscanner
    if js_analysis_file.exists():
        info(f"{C.BLUE}🔍 Extraindo buckets do conteúdo JS analisado...{C.END}")
        try:
            import json as _json
            js_data = _json.loads(js_analysis_file.read_text(errors="ignore"))
            for js_url, js_content in js_data.items():
                content_str = str(js_content) if not isinstance(js_content, str) else js_content
                js_buckets = extract_buckets_from_js(content_str)
                if js_buckets:
                    info(f"   [+] {len(js_buckets)} buckets extraídos de {js_url[:80]}")
                    bucket_names.extend(js_buckets)
        except Exception:
            pass
    
    # Dedup bucket names após todas as fontes
    bucket_names = list(set(bucket_names))

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
            r = httpx.get(f"https://s3.amazonaws.com/{name}/?list-type=2", timeout=5)
            if r.status_code == 200 and "<Contents>" in r.text:
                permissions.append("LIST")
        except Exception:
            pass

        # READ: GET /test - tentar ler qualquer objeto
        try:
            r = httpx.get(f"https://s3.amazonaws.com/{name}/", timeout=5)
            if r.status_code == 200:
                permissions.append("READ")
        except Exception:
            pass

        # WRITE: PUT (SOMENTE se opt-in)
        if test_write:
            try:
                r = httpx.put(
                    f"https://s3.amazonaws.com/{name}/enum-allma-permission-test.txt",
                    data="permission_test",
                    timeout=5
                )
                if r.status_code in (200, 201):
                    permissions.append("WRITE")
                    # Limpar o arquivo de teste
                    try:
                        httpx.delete(
                            f"https://s3.amazonaws.com/{name}/enum-allma-permission-test.txt",
                            timeout=5
                        )
                    except Exception:
                        pass
            except Exception:
                pass

    elif provider == "GCP":
        # LIST: GET /storage/v1/b/{name}/o
        try:
            r = httpx.get(f"https://storage.googleapis.com/storage/v1/b/{name}/o", timeout=5)
            if r.status_code == 200:
                permissions.append("LIST")
        except Exception:
            pass

        # READ
        try:
            r = httpx.get(f"https://storage.googleapis.com/{name}/", timeout=5)
            if r.status_code == 200:
                permissions.append("READ")
        except Exception:
            pass

    elif provider == "Azure":
        # LIST: GET ?restype=container&comp=list
        try:
            r = httpx.get(f"{url}?restype=container&comp=list", timeout=5)
            if r.status_code == 200 and "<Blob>" in r.text:
                permissions.append("LIST")
        except Exception:
            pass

    return permissions
