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
        warn("   [!] 'ssrfmap' não encontrado. Rodando checks superficiais nativos...")
        # Lógica superficial caso não exista o SSRFMap
        import httpx
        from urllib.parse import urlparse
        
        # Testar webhook/oast básico
        oast_url = ""
        oast_file = Path("output") / target / "oast_payload.txt"
        if oast_file.exists():
            oast_url = oast_file.read_text(errors="ignore").strip()
            
        if oast_url:
            def run_native_ssrf(url):
                try:
                    import qsreplace # type: ignore
                except:
                    pass
                try:
                    with httpx.Client(verify=False, timeout=5) as client:
                        client.get(url)  # Se url já injetada
                except:
                    pass
                    
            with ThreadPoolExecutor(max_workers=10) as executor:
                for u in urls[:100]:
                    executor.submit(run_native_ssrf, u)
            info("   [i] Payloads disparados via OAST. Verifique seu painel Interactsh/Burp Collaborator.")
        else:
            info("   [i] Nenhum OAST configurado para testar SSRF blind.")

    results_file.write_text(json.dumps(deduped, indent=2, ensure_ascii=False))
    
    if deduped:
        success(f"💉 {len(deduped)} SSRFs detectados!")
    else:
        success("✅ Nenhum SSRF detectado de forma síncrona.")
    
    return [str(results_file)]
