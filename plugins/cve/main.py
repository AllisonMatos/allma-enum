#!/usr/bin/env python3
"""
Plugin CVE PASSIVE - Correlaciona tecnologias detectadas com SearchSploit
"""
import json
import shutil
import subprocess
from pathlib import Path

from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
def run_searchsploit(term: str):
    """Executa searchsploit para um termo e retorna JSON"""
    searchsploit = shutil.which("searchsploit")
    if not searchsploit:
        return []

    cmd = [searchsploit, term, "--json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode == 0:
            data = json.loads(proc.stdout)
            return data.get("RESULTS_EXPLOIT", [])
    except Exception:
        pass
    return []

def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   🛡️  {C.BOLD}{C.CYAN}INICIANDO MÓDULO: PASSIVE CVE{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    outdir = ensure_outdir(target, "cve")
    cve_file = outdir / "potential_vulns.json"
    report_file = outdir / "cve_report.txt"

    # Ler tecnologias detectadas
    tech_file = Path("output") / target / "domain" / "technologies.json"
    
    if not tech_file.exists():
        warn("⚠️ Arquivo technologies.json não encontrado. Rode o módulo DOMAIN primeiro.")
        return []

    try:
        tech_data = json.loads(tech_file.read_text())
    except Exception:
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
            
            if not name:
                continue
            if not version or version.lower() in ["unknown", "n/a", ""]:
                continue
            
            # Construir termo de busca
            search_term = f"{name} {version}"
            
            # Evitar buscar duplicatas
            cache_key = search_term.lower()
            if cache_key in vulns_found:
                continue
                
            info(f"   🔎 Buscando exploits para: {C.YELLOW}{search_term}{C.END}")
            exploits = run_searchsploit(search_term)
            
            # Consultar NVD/NIST API
            nvd_results = query_nvd(name, version)
            
            if exploits or nvd_results:
                vulns_found[cache_key] = {
                    "tech": name,
                    "version": version,
                    "exploits": exploits,
                    "nvd_cves": nvd_results,
                }
                total = len(exploits) + len(nvd_results)
                info(f"      🚨 {C.RED}{total} vulnerabilidades encontradas!{C.END} (ExploitDB: {len(exploits)}, NVD: {len(nvd_results)})")

    # Salvar resultados
    if vulns_found:
        cve_file.write_text(json.dumps(vulns_found, indent=2))
        
        # Gerar relatório texto
        with open(report_file, "w") as f:
            for key, data in vulns_found.items():
                f.write(f"=== {data['tech']} {data['version'] or ''} ===\n")
                for exploit in data['exploits']:
                    f.write(f"- [ExploitDB] {exploit.get('Title')} (Path: {exploit.get('Path')})\n")
                for cve in data.get('nvd_cves', []):
                    f.write(f"- [NVD] {cve['id']} (CVSS: {cve.get('cvss', 'N/A')}) — {cve.get('description', '')[:120]}\n")
                f.write("\n")
                
        success(f"💣 Vulnerabilidades potenciais salvas em {cve_file}")
    else:
        success("✅ Nenhuma vulnerabilidade conhecida correlacionada automaticamente.")

    summary = {
        "techs_checked": len([t for d in tech_data.values() if "technologies" in d for t in d["technologies"]]),
        "findings": len(vulns_found),
        "status": "COMPLETED"
    }
    (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))

    return [str(cve_file)]


def query_nvd(tech_name: str, version: str) -> list:
    """Consulta a API pública do NVD/NIST para CVEs."""
    import httpx
    import time

    results = []
    keyword = f"{tech_name} {version}"
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=10"

    try:
        time.sleep(1)  # Rate limiting obrigatório do NVD (6 req/min sem API key)
        with httpx.Client(timeout=15, verify=True) as client:
            resp = client.get(url, headers={"User-Agent": "Enum-Allma/1.0 Security Scanner"})
            if resp.status_code == 200:
                data = resp.json()
                for vuln in data.get("vulnerabilities", [])[:5]:
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "")

                    # Extrair CVSS
                    cvss = "N/A"
                    metrics = cve.get("metrics", {})
                    if "cvssMetricV31" in metrics:
                        cvss = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", "N/A")
                    elif "cvssMetricV2" in metrics:
                        cvss = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", "N/A")

                    # Extrair descrição
                    desc = ""
                    for d in cve.get("descriptions", []):
                        if d.get("lang") == "en":
                            desc = d.get("value", "")
                            break

                    results.append({
                        "id": cve_id,
                        "cvss": cvss,
                        "description": desc[:300],
                        "source": "NVD/NIST",
                    })
    except Exception:
        pass

    return results

