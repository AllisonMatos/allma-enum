from pathlib import Path

from menu import C
from ..output import info, success
from .utils import ensure_outdir
from .subfinder import run_subfinder
from .naabu import run_naabu
from .ports import organize_ports
from .urls import build_urls
from .validator import validate_urls


def run(context):
    """
    Fluxo principal do módulo DOMAIN.
    """

    target = context["target"]
    ports_mode = context["ports"]

    # 🎯 Cabeçalho Premium
    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   🚀 {C.BOLD}{C.CYAN}INICIANDO MÓDULO: DOMAIN{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"   🔌 Modo de portas: {C.YELLOW}{ports_mode}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    outdir = ensure_outdir(target)

    subs_file = outdir / "subdomains.txt"
    ports_raw = outdir / "ports_raw.txt"
    ports_final = outdir / "ports.txt"
    urls_file = outdir / "urls.txt"
    urls_ok = outdir / "urls_valid.txt"

    # ███ ETAPA 1: SUBFINDER
    info(f"{C.BOLD}{C.BLUE}🌐 Descobrindo subdomínios...{C.END}")
    run_subfinder(target, subs_file)

    # ███ ETAPA 2: NAABU (PORTAS)
    info(f"{C.BOLD}{C.BLUE}🔌 Executando varredura de portas (naabu)...{C.END}")
    run_naabu(subs_file, ports_raw, ports_mode)

    # ███ ETAPA 3: ORGANIZAR PORTAS
    info(f"{C.BOLD}{C.BLUE}📊 Organizando portas encontradas...{C.END}")
    organize_ports(ports_raw, ports_final)

    # ███ ETAPA 4: GERAR URLS
    info(f"{C.BOLD}{C.BLUE}🔗 Gerando URLs possíveis...{C.END}")
    build_urls(ports_raw, urls_file)

    # ███ ETAPA 5: VALIDAR URLS
    info(f"{C.BOLD}{C.BLUE}🧪 Validando URLs ativas...{C.END}")
    valid_urls = validate_urls(urls_file, urls_ok)

    # 🎉 Finalização
    success(
        f"\n{C.GREEN}{C.BOLD}✔ DOMAIN concluído com sucesso!{C.END}\n"
        f"🌍 Total de URLs válidas: {C.YELLOW}{len(valid_urls)}{C.END}\n"
        f"📁 Arquivos gerados em: {C.CYAN}{outdir}{C.END}\n"
    )

    return valid_urls
