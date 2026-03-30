"""
Configuração centralizada da ferramenta Enum-allma.
Importar com: from core.config import DEFAULT_TIMEOUT, DEFAULT_MAX_WORKERS, ...
"""

# Timeout padrão para requisições HTTP (segundos)
DEFAULT_TIMEOUT = 10

# Máximo de workers para ThreadPoolExecutor
DEFAULT_MAX_WORKERS = 15

# User-Agent padrão
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# Limites de URLs por scan
MAX_URLS_PER_SCAN = 150

# Timeout para processos subprocess (segundos)
SUBPROCESS_TIMEOUT = 120

# Limite de conexões por host para httpx
MAX_CONNECTIONS_PER_HOST = 50
MAX_CONNECTIONS_TOTAL = 100
