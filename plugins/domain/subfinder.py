import subprocess
from .utils import require_binary
from ..output import info, success, error
from menu import C   # garante acesso às cores C.BLUE, C.CYAN etc.


def run_subfinder(target: str, out_file):
    """
    Executa o subfinder para coletar subdomínios do alvo.
    A saída é salva diretamente no arquivo `out_file`.
    """

    subfinder = require_binary("subfinder")

    # ============================================================
    # 🎯 Cabeçalho Premium
    # ============================================================
    info(
        f"\n🟦──────────────────────────────────────────────────────────🟦\n"
        f"   🌐 {C.BOLD}{C.CYAN}INICIANDO SUBFINDER{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟦──────────────────────────────────────────────────────────🟦\n"
    )

    # ============================================================
    # 🔧 Execução do Subfinder
    # ============================================================
    info(f"{C.BOLD}{C.BLUE}🚀 Executando subfinder...{C.END}")

    cmd = [
        subfinder,
        "-d", target,
        "-silent",
        "-all"
    ]

    try:
        with open(out_file, "w") as f:
            subprocess.run(cmd, stdout=f, text=True)
    except Exception as e:
        error(f"❌ Erro ao executar subfinder: {e}")
        return False

    # ============================================================
    # 🎉 Finalização premium
    # ============================================================
    success(
        f"\n{C.GREEN}{C.BOLD}✔ SUBFINDER concluído com sucesso!{C.END}\n"
        f"📂 Subdomínios salvos em:\n"
        f"   {C.CYAN}{out_file}{C.END}\n"
    )

    return True
