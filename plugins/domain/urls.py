from pathlib import Path
from ..output import info, success, warn
from menu import C # para cores padronizadas


def build_urls(ports_raw: Path, out_file: Path):
    """
    Constrói URLs a partir das portas brutas.
    ports_raw: arquivo contendo linhas no formato host:porta/tcp
    out_file: arquivo onde as URLs serão salvas
    """

    # ============================================================
    # 📂 Verificação inicial
    # ============================================================
    if not ports_raw.exists():
        warn(
            f"{C.YELLOW}⚠️ Arquivo de portas não encontrado:{C.END} "
            f"{C.CYAN}{ports_raw}{C.END}"
        )
        out_file.write_text("")
        return []

    # ============================================================
    # 🟦 Cabeçalho Premium
    # ============================================================
    info(
        f"\n🟪──────────────────────────────────────────────────────────🟪\n"
        f"   🌐 {C.BOLD}{C.PURPLE}GERAÇÃO DE URLs A PARTIR DAS PORTAS{C.END}\n"
        f"   📄 Entrada: {C.CYAN}{ports_raw}{C.END}\n"
        f"🟪──────────────────────────────────────────────────────────🟪\n"
    )

    info(f"{C.BOLD}{C.BLUE}🔧 Processando portas e montando URLs...{C.END}")

    urls = []

    # ============================================================
    # 🔄 Processamento das portas
    # ============================================================
    for line in ports_raw.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue

        host, port = line.split(":", 1)
        port = port.split("/")[0].strip()

        if not port.isdigit():
            continue

        # --------------------------------------------------------
        # 🔗 Regras de construção das URLs
        # --------------------------------------------------------
        if port == "80":
            urls.append(f"http://{host}")
        elif port == "443":
            urls.append(f"https://{host}")
        else:
            urls.append(f"http://{host}:{port}")
            urls.append(f"https://{host}:{port}")

    # ============================================================
    # ✨ Finalização
    # ============================================================
    urls = sorted(set(urls))
    out_file.write_text("\n".join(urls) + "\n")

    success(
        f"\n{C.GREEN}{C.BOLD}✔ URLs geradas com sucesso!{C.END}\n"
        f"🔢 Total: {C.CYAN}{len(urls)} URLs{C.END}\n"
        f"📂 Salvo em: {C.YELLOW}{out_file}{C.END}\n"
    )

    return urls
