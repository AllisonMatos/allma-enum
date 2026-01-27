#!/usr/bin/env python3
"""
plugins/fingerprint/main.py

Fingerprinting passivo (ASYNC):
 - headers HTTP (AsyncIO + httpx)
 - TLS/Certificado (AsyncIO + ssl)
"""

from pathlib import Path
from urllib.parse import urlparse
import socket
import ssl
import json
import time
import asyncio

from menu import C
from ..output import info, warn, success, error
from .utils import ensure_outdir

CONCURRENCY_LIMIT = 10
DELAY = 0.5

# ============================
# ASYNC HTTP HEADERS (with Retry)
# ============================
async def fetch_headers_async(client, url, semaphore):
    """Obtém headers de uma URL com retry."""
    async with semaphore:
        await asyncio.sleep(DELAY)
        
        for attempt in range(3):
            try:
                resp = await client.get(url)
                
                # Retry on 429 or 5xx
                if resp.status_code == 429 or resp.status_code >= 500:
                    wait = (attempt + 1) * 2
                    await asyncio.sleep(wait)
                    continue
                    
                return url, resp.status_code, dict(resp.headers)
            except Exception:
                if attempt < 2:
                    await asyncio.sleep(1)
                else:
                    return url, None, {}
        return url, None, {}

# ============================
# ASYNC TLS CERT
# ============================
async def get_cert_async(hostname, port=443, timeout=5):
    """Obtém certificado TLS de forma assíncrona."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        fut = asyncio.open_connection(hostname, port, ssl=ctx)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        
        try:
            # Pega o socket do writer para acessar dados SSL
            # No Python asyncio+ssl, o 'get_extra_info' retorna o peercert
            peercert = writer.get_extra_info('peercert')
            return hostname, peercert
        finally:
            writer.close()
            await writer.wait_closed()
            
    except Exception as e:
        return hostname, {"error": str(e)}

# ============================
# HELPER: Filtrar headers
# ============================
def summarize_headers(h):
    keys = [
        "server", "x-powered-by", "content-type", "content-security-policy",
        "strict-transport-security", "x-frame-options", "x-xss-protection",
        "x-content-type-options", "referrer-policy", "set-cookie"
    ]
    s = {}
    for k in keys:
        v = h.get(k) or h.get(k.title()) or h.get(k.upper())
        if v:
            s[k] = v
    return s


# ============================
# RUNNERS ASYNC
# ============================
async def run_headers_scan_async(urls):
    import httpx
    
    results = {}
    sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
    
    info(f"{C.BOLD}{C.BLUE}📥 Coletando headers HTTP de {len(urls)} URLs...{C.END}")
    
    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=8) as client:
        # Criar tasks
        tasks = [fetch_headers_async(client, u, sem) for u in urls]
        
        # Executar com progresso
        total = len(tasks)
        completed = 0
        
        for coro in asyncio.as_completed(tasks):
            url, status, headers = await coro
            completed += 1
            if completed % 5 == 0:
                print(f"   Processados: {completed}/{total}", end="\r")
            
            if headers:
                results[url] = headers
                
    print("") # Newline
    return results

async def run_certs_scan_async(hosts):
    info(f"{C.BOLD}{C.BLUE}🔐 Coletando certificados de {len(hosts)} hosts...{C.END}")
    
    results = {}
    # Sem semaforo explícito, mas asyncio.gather gerencia bem. 
    # Para ser seguro, podemos usar chucks ou semaforo se forem milhares.
    # Assumindo lista razoável (<500).
    
    tasks = []
    for h in hosts:
        tasks.append(get_cert_async(h))
        
    responses = await asyncio.gather(*tasks)
    
    for host, cert in responses:
        results[host] = cert
        
    return results


# ============================
# MAIN
# ============================
def run(context: dict):
    start = time.time()
    target = context.get("target")

    if not target:
        raise ValueError("context['target'] é obrigatório para plugin fingerprint")

    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   🔍 {C.BOLD}{C.CYAN}INICIANDO MÓDULO: FINGERPRINT (ASYNC){C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    outdir = ensure_outdir(target)
    headers_file = outdir / "headers.txt"
    summary_file = outdir / "fingerprint_summary.txt"
    cert_file = outdir / "cert_info.txt"

    urls_200 = Path("output") / target / "urls" / "urls_200.txt"

    # ==========================================================================
    # 🌐 ETAPA 1 — Ler URLs
    # ==========================================================================
    
    if not urls_200.exists():
        warn(f"⚠️ Arquivo não encontrado: {C.RED}{urls_200}{C.END}")
        return []

    urls = [l.strip() for l in urls_200.read_text(errors="ignore").splitlines() if l.strip()]

    if not urls:
        warn(f"⚠️ Nenhuma URL válida encontrada para fingerprint.")
        return []

    # ==========================================================================
    # 📥 ETAPA 2 — Coletar Headers (Async)
    # ==========================================================================
    try:
        import httpx
        all_headers = asyncio.run(run_headers_scan_async(urls))
    except ImportError:
        error("httpx não instalado.")
        return []
    except Exception as e:
        error(f"Erro no scan de headers: {e}")
        return []
        
    # Extrair hosts únicos das URLs processadas com sucesso
    hosts = set()
    for u in all_headers.keys():
        try:
            h = urlparse(u).netloc.split(":")[0]
            if h: hosts.add(h)
        except:
            pass

    # ==========================================================================
    # 📝 ETAPA 3 — Salvar headers
    # ==========================================================================
    info(f"\n{C.BOLD}{C.BLUE}📝 Salvando headers brutos...{C.END}")
    headers_file.write_text(json.dumps(all_headers, indent=2, ensure_ascii=False))
    
    # ==========================================================================
    # 📊 ETAPA 4 — Gerar sumário
    # ==========================================================================
    info(f"\n{C.BOLD}{C.BLUE}📊 Gerando sumário de segurança...{C.END}")
    summary_lines = []
    for u, h in all_headers.items():
        s = summarize_headers(h)
        summary_lines.append(f"URL: {u}")
        for k, v in s.items():
            summary_lines.append(f"  {k}: {v}")
        summary_lines.append("")

    summary_file.write_text("\n".join(summary_lines))

    # ==========================================================================
    # 🔐 ETAPA 5 — Certificados (Async)
    # ==========================================================================
    if hosts:
        try:
            certs = asyncio.run(run_certs_scan_async(sorted(hosts)))
            cert_file.write_text(json.dumps(certs, indent=2, ensure_ascii=False))
            info(f"   💾 Certificado salvo: {C.GREEN}{cert_file}{C.END}")
        except Exception as e:
            warn(f"Erro ao coletar certificados: {e}")
            certs = {}
    else:
        certs = {}

    # ==========================================================================
    # 🎉 FINALIZAÇÃO
    # ==========================================================================
    t = time.time() - start

    success(
        f"\n{C.GREEN}{C.BOLD}✔ FINGERPRINT concluído com sucesso!{C.END}\n"
        f"🔎 URLs processadas: {C.YELLOW}{len(all_headers)}{C.END}\n"
        f"🔐 Certificados coletados: {C.YELLOW}{len(certs)}{C.END}\n"
        f"⏱️ Tempo total: {C.CYAN}{t:.1f}s{C.END}\n"
        f"📁 Output salvo em: {C.CYAN}{outdir}{C.END}\n"
    )

    return [str(headers_file), str(summary_file), str(cert_file)]
