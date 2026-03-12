#!/usr/bin/env python3
import sys
import time
from core import runner


class C:
    # Cores
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    ORANGE = "\033[38;5;214m"
    RED = "\033[91m"
    PURPLE = "\033[95m"
    GRAY = "\033[90m"
    END = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

    # Fundos
    BG_BLUE = "\033[44m"
    BG_GREEN = "\033[42m"
    BG_RED = "\033[41m"
    BG_YELLOW = "\033[43m"


# --------- MÓDULOS ---------
MODULES = {
    "1": "domain",
    "2": "urls",
    "3": "services",
    "4": "files",
    "5": "jsscanner",
    "6": "fingerprint",
    "7": "endpoint",
    "8": "wordlist",
    "9": "xss",
    "10": "sourcemaps",
    "11": "cve",
    "12": "admin",
    "13": "depconfusion",
    "14": "cors",
    "15": "takeover",
    "16": "headers",
    "17": "waf",
    "18": "emails",
    "19": "graphql",
    "20": "cache_deception",
    "21": "jwt_analyzer",
    "22": "crlf_injection",
    "23": "insecure_deserialization",
    "24": "all",
}

# --------- DEPENDÊNCIAS ---------
# Mapeia quais módulos o módulo X depende para rodar completo
DEPENDENCIES = {
    "1": ["1"],
    "2": ["1", "2"],
    "3": ["1", "2", "3"],
    "4": ["1", "2", "3", "4"],
    "5": ["1", "2", "3", "4", "5"],
    "6": ["1", "2", "3", "4", "5", "6"],
    "7": ["1", "2", "3", "4", "5", "6", "7"],
    "8": ["1", "2", "3", "4", "5", "6", "7", "8"],
    "9": ["1", "2", "3", "4", "5", "6", "7", "8", "9"],
    "10": ["1", "2", "5", "10"],
    "11": ["1", "2", "3", "6", "11"],
    "12": ["1", "2", "12"],
    "13": ["1", "2", "13"],
    "14": ["1", "2", "14"],
    "15": ["1", "2", "15"],
    "16": ["1", "2", "16"],
    "17": ["1", "2", "17"],
    "18": ["1", "2", "18"],
    "19": ["1", "2", "7", "19"],
    "20": ["1", "2", "20"],
    "21": ["1", "2", "21"],
    "22": ["1", "2", "22"],
    "23": ["1", "2", "23"],
    "24": [str(x) for x in range(1, 24)],
}


# ---------- BANNER ----------
def print_banner():
    banner = f"""
{C.BOLD}{C.PURPLE}
╔════════════════════════════════════════════════════════════════╗
║{C.CYAN}    ███████╗███╗   ██╗██╗   ██╗███╗   ███╗███████╗██████╗ {C.PURPLE}     ║
║{C.CYAN}    ██╔════╝████╗  ██║██║   ██║████╗ ████║██╔════╝██╔══██╗{C.PURPLE}     ║
║{C.CYAN}    █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║█████╗  ██████╔╝{C.PURPLE}     ║
║{C.CYAN}    ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║██╔══╝  ██╔══██╗{C.PURPLE}     ║
║{C.CYAN}    ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║███████╗██║  ██║{C.PURPLE}     ║
║{C.CYAN}    ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝{C.PURPLE}     ║
║                                                                  ║
║    {C.YELLOW}FERRAMENTA PROFISSIONAL DE ENUMERAÇÃO E RECONHECIMENTO{C.PURPLE}    ║
╚════════════════════════════════════════════════════════════════╝
{C.END}
    """
    print(banner)


# ---------- MENU ----------
def print_menu():
    print(f"\n{C.BOLD}{C.CYAN}📋 MÓDULOS DISPONÍVEIS{C.END}\n")

    modules = {
        "0": ("documentation", "Leia como a ferramenta funciona", "📖"),
        "1": ("domain", "Enumeração de subdomínios e portas", "🌐"),
        "2": ("urls", "Descoberta e validação de URLs", "🔗"),
        "3": ("services", "Identificação de serviços", "🛠️"),
        "4": ("files", "Busca por arquivos sensíveis", "📁"),
        "5": ("jsscanner", "Análise de JavaScript", "⚡"),
        "6": ("fingerprint", "Fingerprinting de tecnologias", "🖐️"),
        "7": ("endpoint", "Enumeração de endpoints API", "🎯"),
        "8": ("wordlist", "Força bruta em diretórios", "🗂️"),
        "9": ("xss", "Detecção de vulnerabilidades XSS", "🎭"),
        "10": ("sourcemaps", "Extração e Análise de Source Maps", "🗺️"),
        "11": ("cve", "Varredura de vulnerabilidades conhecidas", "🛡️"),
        "12": ("admin", "Busca por painéis administrativos", "🔑"),
        "13": ("depconfusion", "Dependency Confusion Scan", "📦"),
        "14": ("cors", "Misconfigurações de CORS", "🟧"),
        "15": ("takeover", "Subdomain Takeover Scan", "🏴‍☠️"),
        "16": ("headers", "Análise de Security Headers", "📜"),
        "17": ("waf", "Detecção de WAF", "🛡️"),
        "18": ("emails", "Extração de e-mails", "📧"),
        "19": ("graphql", "GraphQL Introspection", "🧬"),
        "20": ("cache_deception", "Web Cache Deception", "🧊"),
        "21": ("jwt_analyzer", "Análise de JWT Tokens", "🔑"),
        "22": ("crlf_injection", "CRLF Injection Scanner", "💉"),
        "23": ("insecure_deser", "Insecure Deserialization", "🧬"),
        "24": ("all", "Execução completa", "🚀")
    }

    for k, (name, desc, emoji) in modules.items():
        print(
            f"  {C.BOLD}{C.YELLOW}{k:>2}{C.END} {C.GREEN}▶{C.END} {emoji} "
            f"{C.BOLD}{name:<12}{C.END} {C.GRAY}─{C.END} {desc}"
        )


# ---------- CONFIG PORTAS (versão antiga) ----------
def ask_ports_mode():
    """Seleção de modo de portas usando opções numéricas."""
    print(f"\n{C.BOLD}{C.CYAN}🌐 CONFIGURAÇÃO DE PORTAS{C.END}")
    print(f"  {C.YELLOW}┌─ Modos disponíveis ───────────────────────────┐{C.END}")
    print(f"  {C.YELLOW}│{C.END} {C.GREEN}1{C.END} → TOP 100 portas                  {C.YELLOW}│{C.END}")
    print(f"  {C.YELLOW}│{C.END} {C.GREEN}2{C.END} → TOP 1000 portas                 {C.YELLOW}│{C.END}")
    print(f"  {C.YELLOW}│{C.END} {C.GREEN}3{C.END} → ALL (todas as portas)            {C.YELLOW}│{C.END}")
    print(f"  {C.YELLOW}└────────────────────────────────────────────────┘{C.END}")

    while True:
        val = input(f"\n{C.BOLD}{C.BLUE}Escolha o modo [3]: {C.END}").strip()

        if val == "":
            return "all"

        if val == "1":
            return "100"

        if val == "2":
            return "1000"

        if val == "3":
            return "all"

        print(f"{C.RED}❌ Opção inválida! Use: 1, 2 ou 3.{C.END}")


# ---------- NMAP ----------
def ask_nmap_args():
    import shlex
    print(f"\n{C.BOLD}{C.CYAN}🔧 CONFIGURAÇÃO DO NMAP{C.END}")
    print(f"{C.YELLOW}Padrão:{C.END} {C.GREEN}-sV -Pn{C.END}")
    val = input(f"{C.BOLD}{C.BLUE}Args: {C.END}").strip()
    raw = val if val else "-sV -Pn"
    # Sanitizar: usar shlex.split para parsing seguro
    try:
        parts = shlex.split(raw)
    except ValueError:
        print(f"{C.RED}❌ Argumentos inválidos, usando padrão -sV -Pn{C.END}")
        return "-sV -Pn"
    # Bloquear flags perigosas
    blocked = {"--script", "--exec", "--interactive", "-iL", "--script-args", "--script-updatedb"}
    for part in parts:
        flag = part.split("=")[0].lower()
        if flag in blocked:
            print(f"{C.RED}❌ Flag bloqueada: {flag}. Usando padrão -sV -Pn{C.END}")
            return "-sV -Pn"
    return raw


# ---------- VALIDAR TARGET ----------
def validate_target(target):
    return bool(target and len(target) >= 3)


# ---------- EXECUTION PLAN ----------
def print_execution_plan(chain, target):
    print(f"\n{C.BOLD}{C.CYAN}📊 PLANO DE EXECUÇÃO{C.END}")
    print(f"{C.YELLOW}Target:{C.END} {C.GREEN}{target}{C.END}")
    print(f"{C.YELLOW}Módulos:{C.END} {C.BLUE}{', '.join(MODULES[c] for c in chain)}{C.END}")
    print(f"{C.YELLOW}Total:{C.END} {len(chain)} fases\n")


# ---------- MAIN ----------
def main():
    print("\033c", end="")
    print_banner()
    print_menu()

    print(f"\n{C.BOLD}{C.CYAN}🎯 SELEÇÃO DO MÓDULO{C.END}")
    choice = input(f"\n{C.BOLD}{C.BLUE}Digite o número: {C.END}").strip()

    if choice == "0":
        print(f"\n{C.GREEN}📖 Iniciando Visualizador de Documentação...{C.END}")
        from plugins.documentation import main as docs_main
        docs_main.run_docs()
        # Se fechar, sai ou recarrega menu? Vamos apenas chamar o main de novo ou sair.
        sys.exit(0)

    if choice not in MODULES:
        print(f"{C.RED}❌ Opção inválida!{C.END}")
        sys.exit(1)

    # target
    print(f"\n{C.BOLD}{C.CYAN}🎯 DEFINIÇÃO DO ALVO{C.END}")
    target = input(f"{C.BOLD}{C.BLUE}Domínio: {C.END}").strip()

    if not validate_target(target):
        print(f"{C.RED}❌ Target inválido.{C.END}")
        sys.exit(1)

    # chain — "10" é meta-módulo (all), não deve entrar na chain de execução
    chain = list(dict.fromkeys(DEPENDENCIES[choice] + [choice]))
    chain = [c for c in chain if c != "10"]

    # parâmetros
    params = {name: {} for name in MODULES.values()}

    if "1" in chain:
        params["domain"]["ports"] = ask_ports_mode()

    if "3" in chain:
        params["services"]["nmap_args"] = ask_nmap_args()

    # plano
    print_execution_plan(chain, target)

    # iniciar?
    confirm = input(f"{C.BOLD}{C.BLUE}Iniciar varredura? [S/n]: {C.END}").strip().lower()

    if confirm in ["", "s", "sim", "y", "yes"]:
        print(f"{C.GREEN}\n🎬 Iniciando...\n{C.END}")
        time.sleep(1)
        runner.execute_chain(target, chain, params)
        print(f"{C.GREEN}{C.BOLD}✔ Concluído!{C.END}")
    else:
        print(f"{C.YELLOW}Operação cancelada.{C.END}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.RED}Interrompido pelo usuário.{C.END}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{C.RED}Erro inesperado: {e}{C.END}")
        sys.exit(1)
