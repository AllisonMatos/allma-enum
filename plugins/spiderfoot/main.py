#!/usr/bin/env python3
"""
SpiderFoot OSINT — Automação de OSINT via SpiderFoot (200+ fontes).
Coleta dados de WHOIS, DNS histórico, leaks, pastebins, breaches, certificados SSL, etc.
Se SpiderFoot não estiver instalado, avisa e pula sem erro.
"""
import json
import shutil
import subprocess
import time
import re
import signal
from pathlib import Path

from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error


# ============================================================
# MÓDULOS SPIDERFOOT SELECIONADOS (evitar scan completo)
# ============================================================
# Módulos rápidos e úteis para recon (evita scan "ALL" que demora 30+ min)
MODULES_FAST = [
    "sfp_dnsresolve",       # DNS resolution
    "sfp_dnsbrute",         # DNS brute force
    "sfp_dnsraw",           # Raw DNS records
    "sfp_whois",            # WHOIS lookup
    "sfp_certspotter",      # Certificate Transparency
    "sfp_crt",              # crt.sh Certificate Search
    "sfp_emailformat",      # Email format discovery
    "sfp_haveibeenpwned",   # Breach checking
    "sfp_hunter",           # Hunter.io email finder
    "sfp_pastebin",         # Pastebin search
    "sfp_pgp",              # PGP key servers
    "sfp_shodan",           # Shodan (basic)
    "sfp_threatcrowd",      # Threat intelligence
    "sfp_virustotal",       # VirusTotal
    "sfp_ipinfo",           # IP information
    "sfp_builtwith",        # Technology detection
    "sfp_social_general",   # Social media presence
]

# Módulos extras para modo --deep (demoram mais)
MODULES_DEEP = [
    "sfp_darknet",          # Dark web mentions
    "sfp_fullcontact",      # Full contact info
    "sfp_grep_app",         # grep.app code search
    "sfp_github",           # GitHub reconnaissance
    "sfp_gitlab",           # GitLab reconnaissance
    "sfp_stackoverflow",    # StackOverflow mentions
    "sfp_censys",           # Censys.io
    "sfp_binaryedge",       # BinaryEdge
    "sfp_securitytrails",   # SecurityTrails
    "sfp_waybackmachine",   # Wayback Machine
    "sfp_archiveorg",       # Archive.org
    "sfp_leakix",           # LeakIX
]


def _find_spiderfoot() -> str | None:
    """Localiza o executável do SpiderFoot no sistema."""
    # Opção 1: sf (pip install spiderfoot)
    sf = shutil.which("sf")
    if sf:
        return sf

    # Opção 2: sf.py (clone do GitHub)
    sf_py = shutil.which("sf.py")
    if sf_py:
        return sf_py

    # Opção 3: python3 -m spiderfoot
    try:
        result = subprocess.run(
            ["python3", "-m", "spiderfoot", "--help"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return "python3 -m spiderfoot"
    except Exception:
        pass

    # Opção 4: Procurar em locais comuns
    common_paths = [
        Path.home() / "spiderfoot" / "sf.py",
        Path("/opt/spiderfoot/sf.py"),
        Path("/usr/share/spiderfoot/sf.py"),
    ]
    for p in common_paths:
        if p.exists():
            return str(p)

    return None


def _find_spiderfoot_cli() -> str | None:
    """Localiza o CLI do SpiderFoot."""
    cli = shutil.which("sfcli.py")
    if cli:
        return cli

    common_paths = [
        Path.home() / "spiderfoot" / "sfcli.py",
        Path("/opt/spiderfoot/sfcli.py"),
        Path("/usr/share/spiderfoot/sfcli.py"),
    ]
    for p in common_paths:
        if p.exists():
            return str(p)

    return None


def _start_server(sf_bin: str, port: int = 5009) -> subprocess.Popen | None:
    """Inicia servidor SpiderFoot em background."""
    try:
        cmd = [sf_bin, "-l", f"0.0.0.0:{port}"]
        if sf_bin.startswith("python3"):
            cmd = ["python3", "-m", "spiderfoot", "-l", f"0.0.0.0:{port}"]
        elif sf_bin.endswith(".py"):
            cmd = ["python3", sf_bin, "-l", f"0.0.0.0:{port}"]

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_IGN),
        )

        # Aguardar servidor subir (máx 60s)
        info(f"   [⏳] Aguardando servidor SpiderFoot na porta {port}...")
        import httpx
        for i in range(60):
            try:
                r = httpx.get(f"http://127.0.0.1:{port}/", timeout=2)
                if r.status_code < 500:
                    success(f"   [+] Servidor SpiderFoot ativo na porta {port}")
                    return proc
            except Exception:
                pass
            time.sleep(1)

        warn("   [!] Servidor SpiderFoot não respondeu em 60s.")
        proc.terminate()
        return None

    except Exception as e:
        error(f"   [!] Erro ao iniciar servidor SpiderFoot: {e}")
        return None


def _run_scan_via_api(target: str, port: int, modules: list, outdir: Path, deep: bool = False) -> dict:
    """Executa scan via REST API do SpiderFoot."""
    import httpx

    base_url = f"http://127.0.0.1:{port}"
    results = {
        "target": target,
        "scan_type": "deep" if deep else "fast",
        "modules_used": modules,
        "findings": [],
    }

    try:
        # Iniciar scan
        scan_data = {
            "scanname": f"enum-allma-{target}",
            "scantarget": target,
            "usecase": "all",
            "modulelist": ",".join(modules),
        }

        r = httpx.post(f"{base_url}/startscan", data=scan_data, timeout=30, follow_redirects=True)

        if r.status_code not in (200, 301, 302):
            warn(f"   [!] Falha ao iniciar scan: HTTP {r.status_code}")
            return results

        # Extrair scan ID do redirect ou body
        scan_id = None
        if "scaninfo" in str(r.url):
            scan_id = str(r.url).split("scaninfo?id=")[-1].split("&")[0]
        elif "scaninfo" in r.text:
            match = re.search(r'scaninfo\?id=([a-f0-9]+)', r.text)
            if match:
                scan_id = match.group(1)

        if not scan_id:
            # Tentar pegar da lista de scans
            r2 = httpx.get(f"{base_url}/scanlist", timeout=10)
            try:
                scans = r2.json()
                if scans:
                    scan_id = scans[-1][0] if isinstance(scans[-1], list) else scans[-1].get("id")
            except Exception:
                pass

        if not scan_id:
            warn("   [!] Não foi possível obter ID do scan.")
            return results

        info(f"   [i] Scan ID: {scan_id}")

        # Monitorar progresso
        max_wait = 1800 if deep else 600  # 30min deep, 10min fast
        start = time.time()

        while time.time() - start < max_wait:
            try:
                r = httpx.get(f"{base_url}/scanstatus?id={scan_id}", timeout=10)
                status_data = r.json() if r.status_code == 200 else {}

                status = status_data.get("status", "UNKNOWN") if isinstance(status_data, dict) else "RUNNING"

                elapsed = int(time.time() - start)
                print(f"   [⏳] Scan em progresso... ({elapsed}s)", end="\r")

                if status in ("FINISHED", "COMPLETED", "ABORTED", "ERROR"):
                    break
            except Exception:
                pass

            time.sleep(10)

        print("")  # Newline
        info(f"   [i] Scan finalizado em {int(time.time() - start)}s")

        # Coletar resultados
        try:
            r = httpx.get(f"{base_url}/scaneventresults?id={scan_id}", timeout=30)
            if r.status_code == 200:
                events = r.json()
                if isinstance(events, list):
                    for event in events:
                        finding = {
                            "type": event[4] if len(event) > 4 else "UNKNOWN",
                            "data": event[1] if len(event) > 1 else "",
                            "module": event[3] if len(event) > 3 else "",
                            "source": event[2] if len(event) > 2 else "",
                        }
                        results["findings"].append(finding)
        except Exception as e:
            warn(f"   [!] Erro ao coletar resultados: {e}")

    except Exception as e:
        error(f"   [!] Erro durante scan SpiderFoot: {e}")

    return results


def _categorize_findings(findings: list) -> dict:
    """Categoriza findings do SpiderFoot por tipo."""
    categories = {
        "dns": [],
        "whois": [],
        "emails": [],
        "breaches": [],
        "social_media": [],
        "certificates": [],
        "technologies": [],
        "leaks": [],
        "network": [],
        "other": [],
    }

    type_map = {
        "DNS": "dns",
        "DOMAIN": "dns",
        "IP_ADDRESS": "network",
        "NETBLOCK": "network",
        "ASN": "network",
        "BGP": "network",
        "EMAILADDR": "emails",
        "EMAIL": "emails",
        "WHOIS": "whois",
        "DOMAIN_WHOIS": "whois",
        "SSL_CERTIFICATE": "certificates",
        "TCP_PORT": "network",
        "LEAK": "leaks",
        "PASTE": "leaks",
        "BREACH": "breaches",
        "SOCIAL_MEDIA": "social_media",
        "SOFTWARE": "technologies",
        "WEBSERVER": "technologies",
        "OPERATING_SYSTEM": "technologies",
    }

    for finding in findings:
        f_type = finding.get("type", "").upper()
        category = "other"
        for key, cat in type_map.items():
            if key in f_type:
                category = cat
                break
        categories[category].append(finding)

    return categories


def run(context: dict):
    """Executa OSINT via SpiderFoot."""
    target = context.get("target")
    deep = context.get("deep", False)
    stealth = context.get("stealth", False)

    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   🕷️  {C.BOLD}{C.CYAN}SPIDERFOOT OSINT (200+ FONTES){C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END} | Deep: {deep} | Stealth: {stealth}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    outdir = ensure_outdir(target, "spiderfoot")

    # Verificar se SpiderFoot está instalado
    sf_bin = _find_spiderfoot()

    if not sf_bin:
        warn(
            f"\n   ⚠️  SpiderFoot não encontrado no sistema.\n"
            f"   📦 Para instalar:\n"
            f"      pip install spiderfoot\n"
            f"      OU\n"
            f"      git clone https://github.com/smicallef/spiderfoot.git\n"
            f"      cd spiderfoot && pip install -r requirements.txt\n"
            f"\n   ⏩ Pulando módulo OSINT SpiderFoot...\n"
        )
        # Salvar resultado vazio
        empty_result = {
            "target": target,
            "status": "SKIPPED",
            "reason": "SpiderFoot not installed",
            "findings": [],
        }
        (outdir / "spiderfoot_results.json").write_text(json.dumps(empty_result, indent=2))
        summary = {"status": "SKIPPED", "findings": 0}
        (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))
        return []

    info(f"   [+] SpiderFoot encontrado: {C.GREEN}{sf_bin}{C.END}")

    # Selecionar módulos
    modules = list(MODULES_FAST)
    if deep:
        modules.extend(MODULES_DEEP)
        info(f"   [i] Modo DEEP ativado — {len(modules)} módulos selecionados")
    else:
        info(f"   [i] Modo FAST — {len(modules)} módulos selecionados")

    # Iniciar servidor SpiderFoot
    port = 5009
    server_proc = _start_server(sf_bin, port)

    if not server_proc:
        warn("   [!] Não foi possível iniciar o servidor SpiderFoot. Pulando...")
        empty_result = {
            "target": target,
            "status": "SERVER_FAILED",
            "reason": "Could not start SpiderFoot server",
            "findings": [],
        }
        (outdir / "spiderfoot_results.json").write_text(json.dumps(empty_result, indent=2))
        summary = {"status": "SERVER_FAILED", "findings": 0}
        (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))
        return []

    try:
        # Executar scan
        results = _run_scan_via_api(target, port, modules, outdir, deep)

        # Categorizar findings
        categories = _categorize_findings(results.get("findings", []))
        results["categories"] = {k: len(v) for k, v in categories.items()}

        # Salvar resultados completos
        output_file = outdir / "spiderfoot_results.json"
        output_file.write_text(json.dumps(results, indent=2, ensure_ascii=False))

        # Salvar categorias individuais para fácil consumo pelo report
        for cat_name, cat_findings in categories.items():
            if cat_findings:
                cat_file = outdir / f"sf_{cat_name}.json"
                cat_file.write_text(json.dumps(cat_findings, indent=2, ensure_ascii=False))

        total = len(results.get("findings", []))

        # Summary
        summary = {
            "status": "COMPLETED",
            "total_findings": total,
            "modules_used": len(modules),
            "categories": results.get("categories", {}),
        }
        (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))

        # Estatísticas no console
        if total > 0:
            success(f"\n   🕷️  SpiderFoot coletou {C.GREEN}{total}{C.END} dados OSINT!")
            info(f"   📊 Categorias:")
            for cat, count in sorted(results.get("categories", {}).items(), key=lambda x: -x[1]):
                if count > 0:
                    info(f"      {cat.upper():20s}: {C.YELLOW}{count}{C.END}")
        else:
            info("   ✅ Nenhum dado OSINT coletado (scan pode ter falhado ou alvo sem exposição).")

        success(f"   📂 Resultados salvos em {output_file}")

        return results.get("findings", [])

    finally:
        # Sempre encerrar o servidor
        if server_proc:
            info(f"   [i] Encerrando servidor SpiderFoot...")
            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_proc.kill()
