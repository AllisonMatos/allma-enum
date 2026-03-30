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
from plugins import ensure_outdir

from ..output import info, success, warn, error
from .utils import require_binary
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
        "-threads", "50",
        "-retries", "2",
        "-timeout", "15",
        "-random-agent",
        "-no-color",
        "-follow-redirects",
        "-o", str(out_file),
        "-silent",
    ]

    info(f"   CMD: {' '.join(cmd)}")

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    
    if result.stderr:
        stderr_clean = result.stderr.strip()[:500]
        if stderr_clean:
            warn(f"httpx stderr: {stderr_clean}")

    if result.returncode != 0:
        warn(f"httpx exit code: {result.returncode}")

    # Verificar se output existe e tem dados
    if not out_file.exists() or out_file.stat().st_size == 0:
        # Fallback: tentar via pipe (sem -o)
        warn("⚠️ httpx -o produziu arquivo vazio. Tentando via pipe...")
        cmd_pipe = [
            httpx,
            "-l", str(in_file),
            "-mc", want_status,
            "-threads", "50",
            "-retries", "2",
            "-timeout", "15",
            "-random-agent",
            "-no-color",
            "-follow-redirects",
            "-silent",
        ]
        result2 = subprocess.run(cmd_pipe, capture_output=True, text=True, timeout=600)
        if result2.stdout and result2.stdout.strip():
            out_file.write_text(result2.stdout)
            info(f"   ✅ Fallback via pipe funcionou!")
        else:
            if result2.stderr:
                warn(f"httpx pipe stderr: {result2.stderr.strip()[:300]}")
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
# Coleta Histórica (gauplus / gau / waybackurls / waymore)
# ============================================================
def run_historical_discovery(target: str, out_file: Path):
    """
    Executa gauplus/gau/waybackurls e complementa com waymore se disponível.
    """
    info(f"{C.BOLD}{C.BLUE}🕰️ Iniciando descoberta de URLs históricas...{C.END}")
    
    gauplus = shutil.which("gauplus")
    gau = shutil.which("gau")
    waybackurls = shutil.which("waybackurls")
    tool = gauplus or gau or waybackurls
    
    if not tool:
        warn("⚠️ Nenhuma ferramenta base (gauplus/gau/waybackurls) encontrada. Tentando apenas waymore se existir.")
    else:
        tool_name = Path(tool).name
        info(f"   🛠️ Usando ferramenta: {C.YELLOW}{tool_name}{C.END}")
        
        cmd = [tool]
        if "gau" in tool_name:
            cmd.extend([target, "--threads", "10"])
            
        try:
            with out_file.open("w", encoding="utf-8", errors="ignore") as fout:
                if "waybackurls" in tool_name:
                    subprocess.run(cmd, input=target.encode(), stdout=fout, stderr=subprocess.DEVNULL, timeout=300)
                else:
                    subprocess.run(cmd, stdout=fout, stderr=subprocess.DEVNULL, timeout=300)
        except Exception as e:
            error(f"Erro na coleta histórica ({tool_name}): {e}")

    # Executar waymore como suplemento se existir
    waymore = shutil.which("waymore")
    if waymore:
        info(f"   🛠️ Coletando extras com: {C.YELLOW}waymore{C.END}")
        waymore_out = out_file.with_name("waymore_temp.txt")
        cmd_wm = [waymore, "-i", target, "-mode", "U", "-oU", str(waymore_out)]
        try:
            subprocess.run(cmd_wm, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600)
            if waymore_out.exists() and waymore_out.stat().st_size > 0:
                with out_file.open("a", encoding="utf-8", errors="ignore") as fout:
                    fout.write("\n" + waymore_out.read_text(errors="ignore"))
                waymore_out.unlink(missing_ok=True)
        except Exception as e:
            error(f"Erro no waymore: {e}")

    # Limpar duplicatas e retornar
    if out_file.exists() and out_file.stat().st_size > 0:
        urls = sorted(set([l.strip() for l in out_file.read_text(errors="ignore").splitlines() if l.strip()]))
        out_file.write_text("\n".join(urls) + "\n", encoding="utf-8")
        success(f"📜 {len(urls)} URLs históricas consolidadas salvas em: {C.GREEN}{out_file.name}{C.END}")
        return urls
        
    return []


# ============================================================
# Coleta Ativa (Katana Headless)
# ============================================================
def run_katana_discovery(target: str, out_file: Path):
    """
    Executa katana para crawling ativo profundo e headless mode.
    """
    info(f"{C.BOLD}{C.BLUE}🕷️ Iniciando crawling ativo extremo com Katana...{C.END}")
    katana = shutil.which("katana")
    if not katana:
        warn("⚠️ 'katana' não encontrado no sistema. Pulando crawling ativo.")
        return []
        
    cmd = [
        katana,
        "-u", f"https://{target}",
        "-jc", "-jsl",   # Parse JS
        "-hl",           # Headless browser
        "-d", "3",       # Max depth 3
        "-f", "qurl",
        "-silent",
        "-o", str(out_file)
    ]
    
    try:
        # Aumentado timeout para 1200 (20 min) como solicitado pelo usuário
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1200)
    except subprocess.TimeoutExpired:
        warn(f"   [!] Katana atingiu o timeout de 20 min. Processando o que foi encontrado até agora...")
    except Exception as e:
        error(f"Erro inesperado no Katana: {e}")
        
    # Mesmo com timeout ou erro, verificamos se o arquivo de output tem dados salvos parcialmentes
    if out_file.exists() and out_file.stat().st_size > 0:
        found = [l.strip() for l in out_file.read_text(errors="ignore").splitlines() if l.strip()]
        success(f"   🕷️  {len(found)} URLs recuperadas do Katana (crawling ativo).")
        return found
            
    return []

# ============================================================
# Coleta Parametrizada (ParamSpider)
# ============================================================
def run_paramspider_discovery(target: str, out_file: Path):
    """Executa ParamSpider para descobrir URLs ricas em parâmetros."""
    info(f"{C.BOLD}{C.BLUE}🕷️ Iniciando descoberta de parâmetros com ParamSpider...{C.END}")
    paramspider = shutil.which("paramspider") or shutil.which("ParamSpider")
    if not paramspider:
        warn("⚠️ 'paramspider' não encontrado. Pulando descoberta.")
        return []
        
    cmd = [paramspider, "-d", target]
    
    try:
        # A maioria das versões do paramspider redireciona a saída padrão ou possui flag -o
        # Vamos rodar no dirtório temp e salvar saída bruta
        with out_file.open("w", encoding="utf-8", errors="ignore") as fout:
            subprocess.run(cmd, stdout=fout, stderr=subprocess.DEVNULL, timeout=600)
    except subprocess.TimeoutExpired:
        warn(f"   [!] ParamSpider atingiu o timeout. Processando o que foi encontrado...")
    except Exception as e:
        error(f"Erro inesperado no ParamSpider: {e}")
        
    # Verificar caminhos comuns de output do paramspider que podem não ter ido pro stdout
    results_file = Path("results") / f"{target}.txt"
    if results_file.exists() and results_file.stat().st_size > 0:
        with out_file.open("a", encoding="utf-8") as fout:
            fout.write("\n" + results_file.read_text(errors="ignore"))
        results_file.unlink(missing_ok=True)
        
    if out_file.exists() and out_file.stat().st_size > 0:
        found = [l.strip() for l in out_file.read_text(errors="ignore").splitlines() if l.strip() and "http" in l]
        # Rewrite limpo
        out_file.write_text("\n".join(found))
        success(f"   🕷️  {len(found)} URLs com parâmetros recuperadas.")
        return found
            
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

    outdir = ensure_outdir(target, "urls")
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
    # ETAPA 2.5 — Coleta Histórica & Ativa
    # ============================================================
    historical_file = outdir / "historical_raw.txt"
    run_historical_discovery(target, historical_file)
    
    katana_file = outdir / "katana_urls_raw.txt"
    run_katana_discovery(target, katana_file)
    
    paramspider_file = outdir / "paramspider_urls_raw.txt"
    run_paramspider_discovery(target, paramspider_file)
    
    # Merge files
    all_raw_urls = []
    
    if url_completas.exists():
         all_raw_urls.extend(url_completas.read_text(errors="ignore").splitlines())
         
    if historical_file.exists():
         all_raw_urls.extend(historical_file.read_text(errors="ignore").splitlines())
         
    if katana_file.exists():
         all_raw_urls.extend(katana_file.read_text(errors="ignore").splitlines())

    if paramspider_file.exists():
         all_raw_urls.extend(paramspider_file.read_text(errors="ignore").splitlines())

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
        l.strip().rstrip("/")
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
    # ETAPA 5 — GF Patterns & Qsreplace Routing
    # ============================================================
    info(f"{C.BOLD}{C.BLUE}🔀 Roteando parâmetros vulneráveis (gf & qsreplace)...{C.END}")
    
    gf = shutil.which("gf")
    qsreplace = shutil.which("qsreplace")
    
    if gf and qsreplace:
        gf_patterns = ["xss", "ssrf", "sqli", "lfi", "redirect"]
        gf_dir = outdir / "patterns"
        gf_dir.mkdir(exist_ok=True)
        
        for pattern in gf_patterns:
            pattern_file = gf_dir / f"{pattern}_urls.txt"
            
            # Execute gf com pipe seguro (sem shell=True)
            try:
                with open(urls_200, "r") as infile:
                    proc_gf = subprocess.run(
                        [gf, pattern], stdin=infile,
                        capture_output=True, text=True, timeout=120
                    )
                if proc_gf.stdout.strip():
                    pattern_file.write_text(proc_gf.stdout)
                else:
                    continue
            except Exception:
                continue
            
            if pattern_file.exists() and pattern_file.stat().st_size > 0:
                payload_file = gf_dir / f"{pattern}_ready.txt"
                
                if pattern == "xss":
                    payload = '\\"\\><script>alert(1)</script>'
                elif pattern == "ssrf":
                    payload = "http://169.254.169.254/latest/meta-data/"
                elif pattern in ["sqli", "lfi"]:
                    payload = "FUZZ"
                else:
                    payload = "http://evil.com"
                    
                # qsreplace com pipe seguro
                try:
                    with open(pattern_file, "r") as infile:
                        proc_qs = subprocess.run(
                            [qsreplace, payload], stdin=infile,
                            capture_output=True, text=True, timeout=120
                        )
                    if proc_qs.stdout.strip():
                        payload_file.write_text(proc_qs.stdout)
                        count = len(proc_qs.stdout.strip().splitlines())
                        if count > 0:
                            success(f"   🎯 {count} URLs criadas para {pattern.upper()} ({payload_file.name})")
                except Exception:
                    continue
    else:
        warn("⚠️ 'gf' ou 'qsreplace' não encontrados. Pulando roteamento (instale via go install).")

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
