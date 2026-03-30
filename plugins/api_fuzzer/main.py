#!/usr/bin/env python3
"""
API Fuzzer (Kiterunner) — Descobre rotas e endpoints de API ocultos.
Executa o `kr scan` usando wordlists .kite se disponíveis.
"""
import os
import json
import subprocess
from pathlib import Path

from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from ..http_utils import check_tool_installed

def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🚀───────────────────────────────────────────────────────────🚀\n"
        f"   🪁  {C.BOLD}{C.CYAN}API FUZZER (Kiterunner){C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🚀───────────────────────────────────────────────────────────🚀\n"
    )

    if not check_tool_installed("kr"):
        warn("Kiterunner ('kr') não está instalado ou configurado no PATH. Pulando fuzzing de API.")
        # Retorna arquivo vazio
        out = ensure_outdir(target, "api_fuzzer")
        Path(out / "kiterunner_results.json").write_text("[]")
        return [str(out / "kiterunner_results.json")]

    outdir = ensure_outdir(target, "api_fuzzer")
    results_file = outdir / "kiterunner_results.json"

    # Procurar URLs/Hosts para testar
    target_urls = []
    
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    if urls_file.exists():
        urls = [u for u in urls_file.read_text().splitlines() if u.strip()]
        # Priorizar Base URLs e Paths de API
        for u in urls:
            if "/api" in u or "/v1" in u or "/v2" in u or "/graphql" in u or "/rest" in u:
                target_urls.append(u)
    
    if len(target_urls) < 5:
        # Fallback to general base subdomains if not enough API paths found
        subs_file = Path("output") / target / "domain" / "subdomains.txt"
        if subs_file.exists():
             more_urls = [f"https://{s}" for s in subs_file.read_text().splitlines() if s.strip()]
             target_urls.extend(more_urls)

    if not target_urls:
         warn("Nenhum alvo válido para o Kiterunner.")
         results_file.write_text("[]")
         return [str(results_file)]

    # Dedup and limit to top 20 API entry-points or domains to avoid infinite hangs
    target_urls = list(set(target_urls))[:20]

    # Kiterunner geralmente usa "routes-large.kite" ou "routes-small.kite".
    # O user pode não ter, vamos tentar um comando list se falhar.
    # Mas em geral, ele usa um dataset padrão.
    wordlist = "routes-large.kite"
    
    findings = []
    
    for url in target_urls:
        info(f"   [Kiterunner] Testando: {C.YELLOW}{url}{C.END}")
        
        cmd = [
            "kr", "scan", url,
            "-w", wordlist,
            "-A=apiroute",
            "-j", # Output JSON
            "--max-connection-per-host", "10"
        ]
        
        try:
             proc = subprocess.run(
                 cmd,
                 capture_output=True,
                 text=True,
                 timeout=90 # 1.5 min per target timeout limit
             )
             
             if proc.returncode != 0 and "could not open wordlist" in proc.stderr.lower():
                 warn(f"   [!] Wordlist '{wordlist}' não encontrada no ambiente.")
                 warn("   [!] Você precisa baixar o dataset (ex: wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz)")
                 break
             
             for line in proc.stdout.splitlines():
                 if not line.strip(): continue
                 try:
                     d = json.loads(line)
                     findings.append({
                         "url": d.get("URL"),
                         "method": d.get("Method"),
                         "status": d.get("Status"),
                         "words": d.get("Words"),
                         "lines": d.get("Lines")
                     })
                 except Exception: pass
                 
        except subprocess.TimeoutExpired:
             warn(f"   [!] Timeout ao fuzzer (Kiterunner limite de 90s atingido)")
             continue
        except Exception as e:
             error(f"Erro executando kr: {e}")
             break
             
    if findings:
         results_file.write_text(json.dumps(findings, indent=2, ensure_ascii=False))
         success(f"   🎉 {len(findings)} rotas de API/Endpoints ocultos encontrados!")
    else:
         warn("   Nenhuma rota extra descoberta pelo Kiterunner.")
         results_file.write_text("[]")
         
    return [str(results_file)]
