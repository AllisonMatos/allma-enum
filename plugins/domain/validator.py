import subprocess
from pathlib import Path
from .utils import require_binary
from ..output import info, success, warn, error
from menu import C   # Classe de cores padrão

STATUS = "200,301,302,307,308"


# ============================================================
# 🔧 NORMALIZAÇÃO DE URLs
# ============================================================
def normalize_urls(in_file: Path) -> list:
    urls = []

    info(
        f"\n🟦──────────────────────────────────────────────────────────🟦\n"
        f"   🔗 {C.BOLD}{C.CYAN}NORMALIZANDO URLs PARA VALIDAÇÃO{C.END}\n"
        f"   📄 Entrada: {C.YELLOW}{in_file}{C.END}\n"
        f"🟦──────────────────────────────────────────────────────────🟦\n"
    )

    if not in_file.exists():
        warn(f"{C.YELLOW}Arquivo não encontrado:{C.END} {C.CYAN}{in_file}{C.END}")
        return []

    for line in in_file.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue

        # URL completa
        if line.startswith("http://") or line.startswith("https://"):
            urls.append(line)
            continue

        # host:port
        if ":" in line:
            host, port = line.split(":", 1)
            port = port.split("/")[0]

            urls.append(f"http://{host}:{port}")
            urls.append(f"https://{host}:{port}")
            continue

        # Apenas host
        urls.append(f"http://{line}")
        urls.append(f"https://{line}")

    info(f"{C.BLUE}🔧 Total normalizado: {len(urls)} URLs{C.END}")

    return urls


# ============================================================
# ✨ VALIDAR URLs COM HTTPX
# ============================================================
def validate_urls(in_file: Path, out_file: Path):
    httpx = require_binary("httpx")

    # Cabeçalho
    info(
        f"\n🟪──────────────────────────────────────────────────────────🟪\n"
        f"   🌐 {C.BOLD}{C.PURPLE}VALIDAÇÃO DE URLs COM HTTPX{C.END}\n"
        f"   📄 Origem: {C.CYAN}{in_file}{C.END}\n"
        f"   🎯 Códigos esperados: {C.GREEN}{STATUS}{C.END}\n"
        f"🟪──────────────────────────────────────────────────────────🟪\n"
    )

    # Normalização
    info(f"{C.BOLD}{C.BLUE}🔧 Normalizando URLs para o httpx...{C.END}")
    normalized = normalize_urls(in_file)

    if not normalized:
        warn("Nenhuma URL para validar.")
        out_file.write_text("")
        return []

    # Arquivo temporário
    temp_file = in_file.parent / "urls-normalized.txt"
    temp_file.write_text("\n".join(normalized))

    # Execução do httpx
    info(f"{C.BOLD}{C.BLUE}🚀 Executando httpx...{C.END}")

    cmd = [
        httpx,
        "-l", str(temp_file),
        "-mc", STATUS,
        "-silent",
        "-o", str(out_file)
    ]

    try:
        subprocess.run(cmd)
    except Exception as e:
        error(f"❌ Erro executando httpx: {e}")
        return []

    # Leitura dos resultados
    urls = [x.strip() for x in out_file.read_text().splitlines() if x.strip()]

    # Finalização
    success(
        f"\n{C.GREEN}{C.BOLD}✔ Validação concluída com sucesso!{C.END}\n"
        f"🔢 URLs válidas: {C.CYAN}{len(urls)}{C.END}\n"
        f"📂 Saída: {C.YELLOW}{out_file}{C.END}\n"
    )

    return urls
