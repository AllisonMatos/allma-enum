from ..output import info, warn, success
from menu import C  # caso já esteja usando a classe C de cores

def organize_ports(raw_file, out_file):
    """
    Organiza portas encontradas pelo naabu em formato legível:
      Host: 1.2.3.4
       - 80/tcp
       - 443/tcp
    """

    # ============================================================
    # 🎯 Cabeçalho Premium
    # ============================================================
    info(
        f"\n🟩──────────────────────────────────────────────────────────🟩\n"
        f"   🔌 {C.BOLD}{C.CYAN}ORGANIZANDO PORTAS (POST-PROCESSAMENTO){C.END}\n"
        f"   📄 Arquivo bruto: {C.YELLOW}{raw_file}{C.END}\n"
        f"🟩──────────────────────────────────────────────────────────🟩\n"
    )

    # ============================================================
    # 📥 Leitura do arquivo bruto
    # ============================================================
    info(f"{C.BOLD}{C.BLUE}📥 Lendo portas brutas...{C.END}")

    data = raw_file.read_text().splitlines()

    if not data:
        warn("⚠️ Nenhum dado encontrado no arquivo de portas.")
        return

    hosts = {}

    # ============================================================
    # 🧩 Processamento das portas
    # ============================================================
    info(f"{C.BOLD}{C.BLUE}🧩 Processando host:porta...{C.END}")

    for line in data:
        if ":" not in line:
            continue

        host, port = line.split(":", 1)
        port = port.split("/")[0]  # remove "/tcp" e afins

        hosts.setdefault(host, set()).add(port)

    # ============================================================
    # 📝 Preparando saída organizada
    # ============================================================
    info(f"{C.BOLD}{C.BLUE}📝 Formatando saída final...{C.END}")

    out = []
    for host in sorted(hosts):
        out.append(f"Host: {host}")
        for p in sorted(hosts[host], key=lambda x: int(x)):
            out.append(f" - {p}/tcp")
        out.append("")

    out_file.write_text("\n".join(out))

    # ============================================================
    # 🎉 Finalização premium
    # ============================================================
    success(
        f"\n{C.GREEN}{C.BOLD}✔ Portas organizadas com sucesso!{C.END}\n"
        f"📂 Salvo em: {C.CYAN}{out_file}{C.END}\n"
    )
