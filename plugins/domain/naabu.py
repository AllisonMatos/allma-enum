import subprocess
from pathlib import Path

from menu import C
from .utils import require_binary
from ..output import info, success, error, warn


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

    cmd = [naabu, "-list", str(subs_file), "-silent", "-Pn", "-rate", "3000"]

    # Portas HTTP comuns que devem sempre ser testadas
    # V11.6: Adicionadas portas de serviços internos com histórico de bounties
    # (Elasticsearch, Redis, MongoDB, Memcached, Node dev, Grafana, Jenkins, etc)
    http_extra_ports = "80,443,8080,8443,8000,8888,3000,4443,5000,5432,6379,9000,9090,9200,9443,11211,27017"

    if mode == "all":
        cmd += ["-p", "-"]  # scan total
        info(f"➡️  {C.CYAN}Modo ALL — varrendo todas as portas.{C.END}")
    else:
        # Combina top-ports com portas HTTP extras
        cmd += ["-top-ports", str(mode), "-p", http_extra_ports]
        info(f"➡️  {C.CYAN}Top ports: {mode} + portas HTTP extras ({http_extra_ports}){C.END}")

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
    
    # Mostrar avisos do naabu (stderr)
    if result.stderr:
        for line in result.stderr.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            if "[WRN]" in line or "non root" in line.lower():
                warn(f"   ⚠️ {line}")
            elif "[ERR]" in line:
                error(f"   ❌ {line}")
    
    # Contar portas encontradas
    port_count = 0
    if out_file.exists():
        port_count = sum(1 for l in out_file.read_text().splitlines() if l.strip())
    
    if result.returncode != 0:
        error(
            f"{C.RED}{C.BOLD}❌ Naabu finalizou com código inesperado "
            f"({result.returncode}).{C.END}"
        )
    else:
        if port_count == 0:
            warn(
                f"\n{C.YELLOW}{C.BOLD}⚠️ Naabu concluído mas NENHUMA porta encontrada!{C.END}\n"
                f"   Possíveis causas:\n"
                f"   - Rodando sem root (CONNECT scan menos confiável)\n"  
                f"   - Subdomínios não resolvem DNS\n"
                f"   - Rate limiting ou firewall bloqueando\n"
                f"   💡 Tente rodar com sudo para SYN scan\n"
            )
        else:
            success(
                f"\n{C.GREEN}{C.BOLD}✔ NAABU concluído! {port_count} portas encontradas.{C.END}\n"
                f"📂 Arquivo salvo em:\n"
                f"   {C.CYAN}{out_file}{C.END}\n"
            )

    return True
