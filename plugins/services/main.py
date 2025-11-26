#!/usr/bin/env python3
"""
Plugin SERVICES – Realiza varredura com Nmap baseada nas portas encontradas no módulo DOMAIN.
"""

import re
import subprocess
from pathlib import Path
from collections import defaultdict

from menu import C

from ..output import info, warn, success, error
from .utils import ensure_outdir

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
    outdir = ensure_outdir(target)

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

        cmd = [
            "nmap",
            *nmap_args.split(),
            "-p", ports_str,
            host,
            "-oN", str(outfile)
        ]

        info(f"   🔎 {C.CYAN}Nmap → {host}:{ports_str}{C.END}")
        subprocess.run(cmd)

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
    # 🎉 FINALIZAÇÃO
    # ============================================================
    success(
        f"\n{C.GREEN}{C.BOLD}✔ SERVICES concluído com sucesso!{C.END}\n"
        f"🛠️ Arquivo consolidado: {C.CYAN}{consolidated}{C.END}\n"
        f"📄 Arquivos individuais: {C.YELLOW}{len(results)} hosts escaneados{C.END}\n"
        f"📁 Output salvo em: {C.CYAN}{outdir}{C.END}\n"
    )

    return [str(consolidated)] + [str(r) for r in results]
