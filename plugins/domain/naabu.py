import subprocess
from pathlib import Path

from menu import C
from .utils import require_binary
from ..output import info, success, error


def run_naabu(subs_file: Path, out_file: Path, mode: str):
    """
    Executa o Naabu para identificar portas abertas.

    subs_file : arquivo contendo subdomínios
    out_file  : saída bruta das portas
    mode      : "all" ou número de portas
    """

    naabu = require_binary("naabu")

    # ============================================================
    # 🎯 Cabeçalho Premium
    # ============================================================
    info(
        f"\n🟦──────────────────────────────────────────────────────────🟦\n"
        f"   🌐 {C.BOLD}{C.CYAN}INICIANDO NAABU (scan de portas){C.END}\n"
        f"   📄 Subdomínios: {C.GREEN}{subs_file}{C.END}\n"
        f"   🔍 Modo: {C.YELLOW}{mode}{C.END}\n"
        f"🟦──────────────────────────────────────────────────────────🟦\n"
    )

    # ============================================================
    # 🔧 Construção do comando
    # ============================================================
    info(f"{C.BOLD}{C.BLUE}🔧 Preparando comando Naabu...{C.END}")

    cmd = [naabu, "-list", str(subs_file), "-silent"]

    if mode == "all":
        cmd += ["-p", "-"]  # scan total
        info(f"➡️  {C.CYAN}Modo ALL — varrendo todas as portas.{C.END}")
    else:
        cmd += ["-top-ports", str(mode)]
        info(f"➡️  {C.CYAN}Top ports: {mode}{C.END}")

    # ============================================================
    # 🚀 Execução
    # ============================================================
    info(f"\n{C.BOLD}{C.BLUE}🚀 Executando Naabu...{C.END}")

    try:
        with open(out_file, "w") as f:
            result = subprocess.run(
                cmd,
                stdout=f,
                stderr=subprocess.PIPE,
                text=True
            )
    except Exception as e:
        error(f"❌ Falha ao executar Naabu: {e}")
        return False

    # ============================================================
    # 📊 Resultado
    # ============================================================
    if result.returncode != 0:
        error(
            f"{C.RED}{C.BOLD}❌ Naabu finalizou com código inesperado "
            f"({result.returncode}).{C.END}"
        )
    else:
        success(
            f"\n{C.GREEN}{C.BOLD}✔ NAABU concluído com sucesso!{C.END}\n"
            f"📂 Arquivo salvo em:\n"
            f"   {C.CYAN}{out_file}{C.END}\n"
        )

    return True
