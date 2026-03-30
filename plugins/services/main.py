#!/usr/bin/env python3
"""
Plugin SERVICES – Realiza varredura com Nmap baseada nas portas encontradas no módulo DOMAIN.
"""

import re
import subprocess
from pathlib import Path
from collections import defaultdict

from menu import C
from plugins import ensure_outdir

from ..output import info, warn, success, error
# Regex para capturar host + porta
pattern = re.compile(
    r"(?P<host>(?:\d{1,3}(?:\.\d{1,3}){3})|(?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}))\s*:\s*(?P<port>\d+)"
)


def run(context):
    target = context.get("target")
    nmap_args = context.get("nmap_args", "-sV -Pn")

    if not target:
        raise ValueError("context['target'] é obrigatório no plugin services")

    # ============================================================
    # 🎯 CABEÇALHO PREMIUM
    # ============================================================
    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   🛠️  {C.BOLD}{C.CYAN}INICIANDO MÓDULO: SERVICES (NMAP){C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"   ⚙️  Args Nmap: {C.YELLOW}{nmap_args}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    # Diretório de saída
    outdir = ensure_outdir(target, "services")

    # Arquivo de entrada vindo do módulo DOMAIN
    ports_raw = Path("output") / target / "domain" / "ports_raw.txt"

    # ============================================================
    # ETAPA 1 — Validar entrada
    # ============================================================
    info(f"{C.BOLD}{C.BLUE}📄 Carregando portas encontradas no módulo DOMAIN...{C.END}")

    if not ports_raw.exists():
        error(f"❌ Arquivo não encontrado: {ports_raw}")
        return []

    # Map host → portas
    ports_by_host = defaultdict(list)

    for line in ports_raw.read_text().splitlines():
        m = pattern.search(line.strip())
        if m:
            host = m.group("host")
            port = m.group("port")
            ports_by_host[host].append(port)

    # ============================================================
    # ETAPA 1.5 — GARANTIR PORTAS HTTP (80/443) PARA TODOS OS HOSTS
    # ============================================================
    info(f"{C.BOLD}{C.BLUE}🔒 Garantindo portas HTTP (80/443) para todos os hosts...{C.END}")
    
    # Ler subdomínios do domain
    subs_file = Path("output") / target / "domain" / "subdomains.txt"
    all_hosts = set(ports_by_host.keys())
    
    if subs_file.exists():
        for line in subs_file.read_text(errors="ignore").splitlines():
            host = line.strip()
            if host:
                all_hosts.add(host)
    
    # Adicionar 80 e 443 para TODOS os hosts (se ainda não tiver)
    http_ports_added = 0
    for host in all_hosts:
        current_ports = set(ports_by_host[host])
        
        if "80" not in current_ports:
            ports_by_host[host].append("80")
            http_ports_added += 1
            
        if "443" not in current_ports:
            ports_by_host[host].append("443")
            http_ports_added += 1
    
    info(f"   ✅ {len(all_hosts)} hosts totais")
    info(f"   ➕ {http_ports_added} portas HTTP (80/443) adicionadas automaticamente")

    if not ports_by_host:
        warn("⚠️ Nenhuma porta encontrada. Nada para escanear.")
        return []

    # ============================================================
    # ETAPA 2 — Executar Nmap por host
    # ============================================================
    info(f"\n{C.BOLD}{C.BLUE}🛠️ Executando Nmap para cada host...{C.END}")

    results = []

    for host, ports in ports_by_host.items():
        ports_str = ",".join(sorted(set(ports), key=int))

        safe_host = host.replace(".", "_")
        outfile = outdir / f"scan_{safe_host}.txt"

        import shlex
        try:
            nmap_parts = shlex.split(nmap_args)
        except ValueError:
            nmap_parts = ["-sV", "-Pn"]
        
        # Adicionar timing default se nenhum -T flag for especificado
        if not any(p.startswith("-T") for p in nmap_parts):
            nmap_parts.append("-T3")

        cmd = [
            "nmap",
            *nmap_parts,
            "-p", ports_str,
            host,
            "-oN", str(outfile)
        ]

        info(f"   🔎 {C.CYAN}Nmap → {host}:{ports_str}{C.END}")
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        except subprocess.TimeoutExpired:
            warn(f"   ⚠️ Nmap timeout (30min) atingido para {host}. Pulando...")

        results.append(outfile)

    # ============================================================
    # ETAPA 3 — Consolidação final
    # ============================================================
    info(f"\n{C.BOLD}{C.BLUE}📦 Construindo arquivo consolidado final...{C.END}")

    consolidated = outdir / f"scanFinal_{target.replace('.', '_')}.txt"

    with open(consolidated, "w") as fout:
        for file in results:
            fout.write(f"\n====== OUTPUT {file.name} ======\n\n")
            fout.write(file.read_text(errors="ignore"))
            fout.write("\n\n")

    # ============================================================
    # ETAPA 4 — Extrair URLs HTTP e alimentar pipeline
    # ============================================================
    info(f"\n{C.BOLD}{C.BLUE}🔗 Extraindo URLs HTTP dos resultados Nmap...{C.END}")
    
    http_urls = set()
    http_pattern = re.compile(
        r"(\d+)/tcp\s+open\s+(ssl[/|]https?|https?|http-alt|https-alt|ssl-http)",
        re.IGNORECASE
    )
    
    # Padrão para capturar host do arquivo (linha "Nmap scan report for")
    host_pattern = re.compile(r"Nmap scan report for\s+(\S+)")
    
    for scan_file in results:
        content = scan_file.read_text(errors="ignore")
        
        # Encontrar o host deste scan
        host_match = host_pattern.search(content)
        if not host_match:
            continue
        
        host = host_match.group(1)
        # Limpar IPs entre parênteses se existir
        if "(" in host:
            host = host.split("(")[0].strip()
        
        # Encontrar portas HTTP
        for match in http_pattern.finditer(content):
            port = match.group(1)
            service = match.group(2).lower()
            
            # Determinar protocolo
            if "ssl" in service or "https" in service or port in ["443", "8443", "4443"]:
                protocol = "https"
            else:
                protocol = "http"
            
            # Gerar URL
            if port in ["80", "443"]:
                url = f"{protocol}://{host}"
            else:
                url = f"{protocol}://{host}:{port}"
            
            http_urls.add(url)
    
    # Salvar URLs HTTP descobertas
    http_urls_file = outdir / "http_urls.txt"
    if http_urls:
        http_urls_file.write_text("\n".join(sorted(http_urls)) + "\n")
        info(f"   💾 {len(http_urls)} URLs HTTP salvas em: {C.GREEN}{http_urls_file}{C.END}")
        
        # Alimentar de volta ao pipeline - append em domain/urls_valid.txt
        domain_urls_file = Path("output") / target / "domain" / "urls_valid.txt"
        if domain_urls_file.exists():
            existing = set(domain_urls_file.read_text().splitlines())
            new_urls = http_urls - existing
            if new_urls:
                with domain_urls_file.open("a") as f:
                    for url in sorted(new_urls):
                        f.write(f"{url}\n")
                success(f"   ✨ {len(new_urls)} novas URLs adicionadas ao pipeline!")
    else:
        warn("   ⚠️ Nenhum serviço HTTP detectado nos scans.")

    # ============================================================
    # 🎉 FINALIZAÇÃO
    # ============================================================
    success(
        f"\n{C.GREEN}{C.BOLD}✔ SERVICES concluído com sucesso!{C.END}\n"
        f"🛠️ Arquivo consolidado: {C.CYAN}{consolidated}{C.END}\n"
        f"📄 Arquivos individuais: {C.YELLOW}{len(results)} hosts escaneados{C.END}\n"
        f"🔗 URLs HTTP extraídas: {C.YELLOW}{len(http_urls)}{C.END}\n"
        f"📁 Output salvo em: {C.CYAN}{outdir}{C.END}\n"
    )

    return [str(consolidated), str(http_urls_file)] + [str(r) for r in results]
