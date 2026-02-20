#!/usr/bin/env python3
import shutil
"""
plugins/urls/main.py - Coleta URLs a partir das URLs válidas do módulo domain
e valida novamente com httpx.

Saídas:
  output/<target>/urls/url_completas.txt
  output/<target>/urls/urls_200.txt
"""

from pathlib import Path
import subprocess

from menu import C

from ..output import info, success, warn, error
from .utils import ensure_outdir, require_binary

WANT_STATUS = "200,301,302,307,308,401,403,404,405,500"


# ============================================================
# Validação com httpx
# ============================================================
def httpx_validate(in_file: Path, out_file: Path, want_status: str = WANT_STATUS):
    info(f"{C.BOLD}{C.BLUE}🔎 Validando URLs com httpx (mc={want_status})...{C.END}")

    httpx = require_binary("httpx")

    cmd = [
        httpx,
        "-l", str(in_file),
        "-mc", want_status,
        "-threads", "100",
        "-retries", "2",
        "-timeout", "15",
        "-random-agent",

        "-follow-redirects",
        "-o", str(out_file),
        "-silent",
    ]

    subprocess.run(cmd)

    if not out_file.exists() or out_file.stat().st_size == 0:
        warn("⚠️ Nenhuma URL válida encontrada via httpx.")
        return []

    urls = sorted(
        set(
            l.strip()
            for l in out_file.read_text(errors="ignore").splitlines()
            if l.strip()
        )
    )

    out_file.write_text("\n".join(urls) + "\n")

    success(f"✨ {len(urls)} URLs válidas salvas em: {C.GREEN}{out_file}{C.END}")
    return urls


# ============================================================
# Coleta Histórica (gau / waybackurls)
# ============================================================
def run_historical_discovery(target: str, out_file: Path):
    """
    Executa gau ou waybackurls para encontrar URLs históricas.
    """
    info(f"{C.BOLD}{C.BLUE}🕰️ Iniciando descoberta de URLs históricas...{C.END}")
    
    gau = shutil.which("gau")
    waybackurls = shutil.which("waybackurls")
    tool = gau or waybackurls
    
    if not tool:
        warn("⚠️ Nem 'gau' nem 'waybackurls' encontrados. Pulando histórico.")
        return []
        
    tool_name = Path(tool).name
    info(f"   🛠️ Usando ferramenta: {C.YELLOW}{tool_name}{C.END}")
    
    cmd = [tool, target]
    if "gau" in tool:
        cmd.extend(["--threads", "10"])
        
    try:
        with out_file.open("w", encoding="utf-8", errors="ignore") as fout:
            subprocess.run(cmd, stdout=fout, stderr=subprocess.DEVNULL, timeout=300)
            
        if out_file.exists() and out_file.stat().st_size > 0:
            count = len(out_file.read_text(errors="ignore").splitlines())
            success(f"📜 {count} URLs históricas salvas em: {C.GREEN}{out_file.name}{C.END}")
            return [l.strip() for l in out_file.read_text(errors="ignore").splitlines() if l.strip()]
            
    except Exception as e:
        error(f"Erro na coleta histórica: {e}")
        
    return []


# ============================================================
# MAIN
# ============================================================
def run(context: dict):
    target = context.get("target")

    if not target:
        raise ValueError("context['target'] é obrigatório para o plugin urls")

    # ============================================================
    # 🎯 CABEÇALHO PREMIUM
    # ============================================================
    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   🔗 {C.BOLD}{C.CYAN}INICIANDO MÓDULO: URLS{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    outdir = ensure_outdir(target)
    url_completas = outdir / "url_completas.txt"
    urls_200 = outdir / "urls_200.txt"

    # ============================================================
    # ETAPA 1 — Coletar URLs de múltiplas fontes
    # ============================================================
    info(f"{C.BOLD}{C.BLUE}📄 Coletando URLs de múltiplas fontes do pipeline...{C.END}")

    # Fonte 1: URLs validadas do DOMAIN
    domain_200 = Path("output") / target / "domain" / "urls_valid.txt"
    
    # Fonte 2: URLs HTTP descobertas pelo SERVICES (Nmap)
    services_http = Path("output") / target / "services" / "http_urls.txt"
    
    # Fonte 3: URLs descobertas pelo Katana (crawling do DOMAIN)
    katana_valid = Path("output") / target / "domain" / "katana_valid.txt"
    
    # Fonte 4: URLs descobertas inline pelo DOMAIN
    discovered_urls = Path("output") / target / "domain" / "discovered_urls.txt"

    # Coletar todas as seeds
    seed_urls = set()
    sources_found = []
    
    for source_name, source_path in [
        ("domain/urls_valid.txt", domain_200),
        ("services/http_urls.txt", services_http),
        ("domain/katana_valid.txt", katana_valid),
        ("domain/discovered_urls.txt", discovered_urls),
    ]:
        if source_path.exists():
            urls = [l.strip() for l in source_path.read_text(errors="ignore").splitlines() if l.strip()]
            if urls:
                seed_urls.update(urls)
                sources_found.append(f"{source_name} ({len(urls)} URLs)")
                info(f"   ✅ {C.GREEN}{source_name}{C.END}: {len(urls)} URLs")
        else:
            info(f"   ⚠️ {C.YELLOW}{source_name}{C.END}: não encontrado (opcional)")

    if not seed_urls:
        error(f"❌ Nenhuma URL seed encontrada de nenhuma fonte!")
        return []
        
    info(f"   📊 {C.CYAN}Total de seeds coletadas: {len(seed_urls)}{C.END}")

    # limpar arquivo anterior
    if url_completas.exists():
        url_completas.unlink()

    # ============================================================
    # ETAPA 1.5 — Filtrar URLs estáticas (Otimização)
    # ============================================================
    info(f"{C.BOLD}{C.BLUE}🧹 Filtrando arquivos estáticos para otimizar urlfinder...{C.END}")
    
    # Extensões para ignorar no urlfinder (crawling)
    # O usuário pediu especificamente para ignorar JS, mas adicionamos outras estáticas
    ignored_exts = {
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", 
        ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf", ".zip", 
        ".rar", ".tar", ".gz", ".7z", ".xml", ".txt", ".json"
    }
    
    urls_to_scan = []
    skipped_count = 0
    
    for line in seed_urls:
        # Verificar extensão na URL (ignorando query params)
        path = line.split("?")[0].lower()
        if any(path.endswith(ext) for ext in ignored_exts):
            skipped_count += 1
            continue
            
        urls_to_scan.append(line)
            
    urls_filtered_file = outdir / "urls_for_urlfinder.txt"
    urls_filtered_file.write_text("\n".join(urls_to_scan))
    
    info(f"   URLs totais de seeds: {len(seed_urls)}")
    info(f"   URLs ignoradas: {skipped_count} (arquivos estáticos/js)")
    info(f"   URLs para scan: {len(urls_to_scan)}")

    # ============================================================
    # ETAPA 2 — Executar urlfinder
    # ============================================================
    
    # Deduplica por base URL (scheme+host) — urlfinder crawla a partir do domínio
    from urllib.parse import urlparse as _urlparse
    base_seeds = set()
    for u in urls_to_scan:
        try:
            p = _urlparse(u)
            base = f"{p.scheme}://{p.netloc}"
            base_seeds.add(base)
        except:
            pass
    
    urlfinder_seeds = sorted(base_seeds)
    info(f"{C.BOLD}{C.BLUE}🌐 Coletando URLs com urlfinder ({len(urlfinder_seeds)} hosts únicos, de {len(urls_to_scan)} seeds)...{C.END}")

    urlfinder = require_binary("urlfinder")
    
    import time as _time
    import tempfile as _tempfile
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import os

    # Parallelize urlfinder execution
    # Run 5 concurrent urlfinder instances, each handling a batch
    CONCURRENT_WORKERS = 5
    BATCH_SIZE = 50
    total_seeds = len(urlfinder_seeds)
    url_count = 0
    start_time = _time.time()
    
    def process_batch(batch_seeds):
        """Runs urlfinder for a batch of seeds and returns unique URLs found."""
        if not batch_seeds:
            return []
            
        found_lines = []
        try:
            # Input file for this batch
            fd_in, temp_in = _tempfile.mkstemp(suffix=".txt", text=True)
            with os.fdopen(fd_in, 'w') as f:
                f.write("\n".join(batch_seeds) + "\n")
            
            # Run urlfinder
            cmd = [urlfinder, "-list", temp_in, "-silent", "-timeout", "10"]
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=300
            )
            
            if proc.stdout:
                found_lines = [l for l in proc.stdout.splitlines() if l.strip()]
                
        except Exception as e:
            # Silently fail for batch? or log?
            pass
        finally:
            if os.path.exists(temp_in):
                os.unlink(temp_in)
                
        return found_lines

    try:
        # Generate batches
        batches = []
        for i in range(0, total_seeds, BATCH_SIZE):
            batches.append(urlfinder_seeds[i:i + BATCH_SIZE])
            
        info(f"   🚀 Iniciando {len(batches)} lotes com {CONCURRENT_WORKERS} workers paralelos...")

        with url_completas.open("w", encoding="utf-8", errors="ignore") as fout:
            with ThreadPoolExecutor(max_workers=CONCURRENT_WORKERS) as executor:
                futures = {executor.submit(process_batch, batch): idx for idx, batch in enumerate(batches)}
                
                completed = 0
                for future in as_completed(futures):
                    completed += 1
                    batch_idx = futures[future]
                    try:
                        results = future.result()
                        # Write immediately to file
                        for line in results:
                            fout.write(line + "\n")
                        
                        url_count += len(results)
                        
                        # Progress log
                        elapsed = _time.time() - start_time
                        pct = int(completed / len(batches) * 100)
                        
                         # Estimar tempo
                        if completed > 0:
                            avg_time_per_batch = elapsed / completed
                            remaining_batches = len(batches) - completed
                            eta_secs = avg_time_per_batch * remaining_batches
                            eta_mins = int(eta_secs // 60)
                            eta_s = int(eta_secs % 60)
                            eta_str = f" | ETA ~{eta_mins}m{eta_s:02d}s"
                        else:
                            eta_str = ""

                        # Log only every few batches to avoid clutter if fast, or always if slow
                        print(f"   ⏳ urlfinder: {completed}/{len(batches)} batches ({pct}%) | +{len(results)} URLs | Total: {url_count}{eta_str}", end="\r")
                        
                    except Exception as e:
                        error(f"Erro no batch {batch_idx}: {e}")

        print("") # Newline
        
        elapsed = _time.time() - start_time
        mins = int(elapsed // 60)
        secs = int(elapsed % 60)
        info(f"   ✅ urlfinder concluído: {url_count} URLs em {mins}m{secs:02d}s")

    except Exception as e:
        error(f"❌ Falha ao executar urlfinder: {e}")
        # Dont return here, continue to historical
        
    # ============================================================
    # ETAPA 2.5 — Coleta Histórica
    # ============================================================
    historical_file = outdir / "historical_raw.txt"
    run_historical_discovery(target, historical_file)
    
    # Merge files
    all_raw_urls = []
    
    if url_completas.exists():
         all_raw_urls.extend(url_completas.read_text(errors="ignore").splitlines())
         
    if historical_file.exists():
         all_raw_urls.extend(historical_file.read_text(errors="ignore").splitlines())

    if not all_raw_urls:
         warn("⚠️ Nenhuma URL encontrada (urlfinder + histórico).")
         return []
    
    # Write combined back to url_completas for deduplication
    url_completas.write_text("\n".join(all_raw_urls))

    # ============================================================
    # ETAPA 3 — Deduplicar URLs
    # ============================================================
    info(f"{C.BOLD}{C.BLUE}🧹 Deduplicando URLs encontradas...{C.END}")

    lines = [
        l.strip()
        for l in url_completas.read_text(errors="ignore").splitlines()
        if l.strip()
    ]

    unique = sorted(set(lines))
    url_completas.write_text("\n".join(unique) + "\n")

    success(f"📁 {len(unique)} URLs coletadas em: {C.GREEN}{url_completas}{C.END}")

    # ============================================================
    # ETAPA 4 — Validar URLs com httpx
    # ============================================================
    info(f"{C.BOLD}{C.BLUE}🔍 Validando URLs com HTTPX...{C.END}")

    valid_urls = httpx_validate(url_completas, urls_200)

    # ============================================================
    # 🎉 FINALIZAÇÃO
    # ============================================================
    success(
        f"\n{C.GREEN}{C.BOLD}✔ URLS concluído com sucesso!{C.END}\n"
        f"🔗 URLs válidas: {C.YELLOW}{len(valid_urls)}{C.END}\n"
        f"📂 Arquivo final salvo em:\n"
        f"   {C.CYAN}{urls_200}{C.END}\n"
    )

    return valid_urls
