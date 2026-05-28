#!/usr/bin/env python3
"""
Virtual Host Discovery Scanner
Usa ffuf para bruteforce de vhosts em IPs usando o header Host: FUZZ.target.com
"""
import os
import json
import shutil
import subprocess
from pathlib import Path

from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from plugins.validation import finding

# Usa wordlist padrão de subdomínios/vhosts se não especificado
DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"

def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟩───────────────────────────────────────────────────────────🟩\n"
        f"   🌐 {C.BOLD}{C.CYAN}VIRTUAL HOST DISCOVERY (FFUF){C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟩───────────────────────────────────────────────────────────🟩\n"
    )

    outdir = ensure_outdir(target, "vhost")
    
    # Checar se ffuf está instalado
    ffuf_bin = shutil.which("ffuf")
    if not ffuf_bin:
        warn("   ⚠️ ffuf não instalado. Pulei o bruteforce de vhosts.")
        return []
        
    # Identificar IPs para testar (gerados pelo dns_resolver)
    ips_file = Path("output") / target / "domain" / "ips.txt"
    if not ips_file.exists():
        warn("   ⚠️ ips.txt não encontrado. Execute a fase de resolução DNS primeiro.")
        return []
        
    ips = [l.strip() for l in ips_file.read_text().splitlines() if l.strip()]
    if not ips:
        warn("   ⚠️ Nenhum IP encontrado para testar vhosts.")
        return []
        
    # Pegar wordlist
    wordlist = context.get("vhost_wordlist", DEFAULT_WORDLIST)
    if not Path(wordlist).exists():
        warn(f"   ⚠️ Wordlist {wordlist} não encontrada. Pulei o bruteforce de vhosts.")
        return []

    # Limitar a 5 IPs para não demorar demais
    ips_to_test = ips[:5]
    info(f"   📋 Testando VHOSTs em {len(ips_to_test)} IPs usando wordlist {Path(wordlist).name}...")

    all_findings = []
    
    for ip in ips_to_test:
        output_json = outdir / f"ffuf_{ip.replace('.', '_')}.json"
        
        cmd = [
            ffuf_bin,
            "-w", wordlist,
            "-u", f"http://{ip}",
            "-H", f"Host: FUZZ.{target}",
            "-mc", "200,204,301,302,307,401,403", # Aceitar vários códigos
            "-ac", # Auto calibrate filtering para ignorar a default vhost response
            "-t", "50",
            "-o", str(output_json),
            "-s" # Silent
        ]
        
        info(f"      ▶️ Testando IP: {ip}...")
        try:
            subprocess.run(cmd, capture_output=True, timeout=600)
            
            if output_json.exists():
                try:
                    data = json.loads(output_json.read_text())
                    results = data.get("results", [])
                    if results:
                        success(f"      🚨 {len(results)} vhosts encontrados no IP {ip}!")
                        for r in results:
                            vhost = f"{r.get('input', {}).get('FUZZ', '')}.{target}"
                            all_findings.append(
                                finding(
                                    plugin="vhost",
                                    target=target,
                                    title=f"Virtual Host Detected: {vhost}",
                                    issue_type="HIDDEN_VHOST",
                                    risk="MEDIUM",
                                    confidence="HIGH",
                                    description=f"Um virtual host oculto ({vhost}) foi descoberto rodando no IP {ip}.",
                                    url=f"http://{ip}",
                                    detection={"vhost": vhost, "status": r.get("status"), "words": r.get("words")},
                                    validation={"ffuf": True},
                                    evidence={"observable_impact": "internal_routing_exposure"}
                                )
                            )
                except Exception:
                    pass
        except subprocess.TimeoutExpired:
            warn(f"      ⚠️ Timeout executando ffuf para o IP {ip}.")
        except Exception as e:
            warn(f"      ⚠️ Erro executando ffuf: {e}")

    # Salvar resultados
    (outdir / "findings.json").write_text(json.dumps(all_findings, indent=2, ensure_ascii=False))
    
    if all_findings:
        success(f"   📂 Total de {len(all_findings)} vhosts ocultos encontrados! Salvos em findings.json.")
    else:
        info("   ✅ Nenhum vhost oculto identificado.")
        
    return all_findings
