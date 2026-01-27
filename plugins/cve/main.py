#!/usr/bin/env python3
"""
Plugin CVE PASSIVE - Correlaciona tecnologias detectadas com SearchSploit
"""
import json
import shutil
import subprocess
from pathlib import Path

from menu import C
from ..output import info, success, warn, error
from .utils import ensure_outdir

def run_searchsploit(term: str):
    """Executa searchsploit para um termo e retorna JSON"""
    searchsploit = shutil.which("searchsploit")
    if not searchsploit:
        return []

    cmd = [searchsploit, term, "--json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode == 0:
            data = json.loads(proc.stdout)
            return data.get("RESULTS_EXPLOIT", [])
    except:
        pass
    return []

def run(context: dict):
    target = context.get("target") # can be domain or just general
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   🛡️  {C.BOLD}{C.CYAN}INICIANDO MÓDULO: PASSIVE CVE{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    outdir = ensure_outdir(target)
    cve_file = outdir / "potential_vulns.json"
    report_file = outdir / "cve_report.txt"

    # Ler tecnologias detectadas
    tech_file = Path("output") / target / "domain" / "technologies.json"
    
    if not tech_file.exists():
        warn("⚠️ Arquivo technologies.json não encontrado. Rode o módulo DOMAIN primeiro.")
        return []

    try:
        tech_data = json.loads(tech_file.read_text())
    except:
        error("Erro ao ler technologies.json")
        return []

    vulns_found = {}
    
    info(f"{C.BLUE}🔍 Correlacionando tecnologias com ExploitDB...{C.END}")

    for subdomain, data in tech_data.items():
        if "technologies" not in data:
            continue
            
        for tech in data["technologies"]:
            name = tech.get("name")
            version = tech.get("version")
            
            if not name: continue
            
            # Construir termo de busca
            search_term = name
            if version:
                search_term += f" {version}"
            
            # Evitar buscar duplicatas
            cache_key = search_term.lower()
            if cache_key in vulns_found:
                # Já buscamos isso, só associar ao subdomínio se necessário
                continue
                
            info(f"   🔎 Buscando exploits para: {C.YELLOW}{search_term}{C.END}")
            exploits = run_searchsploit(search_term)
            
            if exploits:
                vulns_found[cache_key] = {
                    "tech": name,
                    "version": version,
                    "exploits": exploits
                }
                info(f"      🚨 {C.RED}{len(exploits)} exploits encontrados!{C.END}")

    # Salvar resultados
    if vulns_found:
        cve_file.write_text(json.dumps(vulns_found, indent=2))
        
        # Gerar relatório texto
        with open(report_file, "w") as f:
            for key, data in vulns_found.items():
                f.write(f"=== {data['tech']} {data['version'] or ''} ===\n")
                for exploit in data['exploits']:
                    f.write(f"- [{exploit.get('Title')}] (Path: {exploit.get('Path')})\n")
                f.write("\n")
                
        success(f"💣 Vulnerabilidades potenciais salvas em {cve_file}")
    else:
        success("✅ Nenhuma vulnerabilidade conhecida correlacionada automaticamente.")

    return [str(cve_file)]
