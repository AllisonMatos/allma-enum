"""
Constantes de cores ANSI — Fonte única de verdade para toda a ferramenta.
Importar com: from core.colors import C
"""


class C:
    # Cores de texto
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
