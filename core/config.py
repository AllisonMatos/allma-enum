"""
Configuração centralizada da ferramenta Enum-allma.
Importar com: from core.config import DEFAULT_TIMEOUT, DEFAULT_MAX_WORKERS, ...
"""
import random

# Timeout padrão para requisições HTTP (segundos)
DEFAULT_TIMEOUT = 10

# Máximo de workers para ThreadPoolExecutor
DEFAULT_MAX_WORKERS = 15

# Pool de User-Agents modernos para rotação (evita fingerprinting por WAFs)
_USER_AGENT_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
]

# User-Agent padrão (fallback para compatibilidade)
DEFAULT_USER_AGENT = _USER_AGENT_POOL[0]

def get_user_agent() -> str:
    """Retorna um User-Agent aleatório do pool para rotação anti-fingerprinting."""
    return random.choice(_USER_AGENT_POOL)

# Atraso (Delay) em segundos entre as requisições paralelas nos plugins.
# Default: 0.6s (mais stealth conforme V10). Use 0.0 para velocidade máxima, 1.0+ para WAFs agressivos.
# Pode ser sobrescrito pelo prompt do menu na hora da execução.
REQUEST_DELAY = 0.6
DEFAULT_DELAY = 0.6

# Limites de URLs por scan
MAX_URLS_PER_SCAN = 150

# Timeout para processos subprocess (segundos)
SUBPROCESS_TIMEOUT = 120

# Limite de conexões por host para httpx
MAX_CONNECTIONS_PER_HOST = 50
MAX_CONNECTIONS_TOTAL = 100
