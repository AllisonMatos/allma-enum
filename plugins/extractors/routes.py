import re
from urllib.parse import urljoin, urlparse

# Patterns para rotas de API
ROUTE_PATTERNS = [
    # Paths em strings
    r'["\'](\/?api\/[a-zA-Z0-9_\-\/\.]+)["\']',
    r'["\'](\/?v[0-9]+\/[a-zA-Z0-9_\-\/\.]+)["\']',
    r'["\'](\/[a-zA-Z0-9_\-]+\/[a-zA-Z0-9_\-\/\.]+)["\']',
    
    # Fetch/axios calls
    r'fetch\s*\(\s*["\']([^"\']+)["\']',
    r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
    r'\$\.(?:get|post|ajax|put|delete)\s*\(\s*["\']([^"\']+)["\']',
    
    # URL constructions
    r'url\s*[:=]\s*["\']([^"\']+)["\']',
    r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
    r'baseURL?\s*[:=]\s*["\']([^"\']+)["\']',
    r'path\s*[:=]\s*["\']([^"\']+)["\']',
    
    # GraphQL endpoints
    r'graphql["\']?\s*[:=]\s*["\']([^"\']+)["\']',
]

# Extensoes a ignorar
BAD_EXTENSIONS = (
    '.css', '.png', '.jpg', '.jpeg', '.svg', '.ico', '.woff', '.woff2', 
    '.ttf', '.eot', '.mp4', '.mp3', '.pdf', '.gif', '.webp', '.avif',
    '.map', '.scss', '.less', '.sass'
)

# Paths a ignorar (muito genericos ou falsos positivos comuns)
IGNORE_PATHS = {
    '/', '//', '#', 'javascript:', 'data:', 'mailto:', 'tel:',
    '/favicon.ico', '/robots.txt', '/sitemap.xml'
}

# HTTP methods
HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']


def extract_routes(content: str, base_url: str = None) -> list:
    """
    Extracts potential API routes/paths from content with detailed info.
    
    Args:
        content: Source code/HTML to analyze
        base_url: Base URL for context
        
    Returns:
        list of dicts with route info
    """
    found = []
    seen_paths = set()
    
    for pattern in ROUTE_PATTERNS:
        try:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            
            for m in matches:
                path = m.group(1).strip() if m.groups() else m.group(0).strip()
                
                # Filtros
                if not path or len(path) < 2:
                    continue
                if path.lower() in IGNORE_PATHS:
                    continue
                if path.lower().endswith(BAD_EXTENSIONS):
                    continue
                    
                # Normalizar path
                if not path.startswith('/') and not path.startswith('http'):
                    path = '/' + path
                    
                if path in seen_paths:
                    continue
                seen_paths.add(path)
                
                # Analisar rota
                route_info = analyze_route(path, content, m.start(), base_url)
                found.append(route_info)
                
        except re.error:
            continue
    
    # Ordenar por tipo (API primeiro) e depois alfabeticamente
    found.sort(key=lambda x: (0 if x['is_api'] else 1, x['path']))
    
    return found


def extract_routes_simple(content: str) -> list:
    """
    Versao simplificada que retorna apenas paths.
    Mantida para compatibilidade.
    """
    routes = extract_routes(content)
    return sorted([r['path'] for r in routes])


def analyze_route(path: str, content: str, match_pos: int, base_url: str = None) -> dict:
    """
    Analisa uma rota extraida para obter mais informacoes.
    """
    route_info = {
        "path": path,
        "full_url": None,
        "is_api": is_api_route(path),
        "method": detect_method(content, match_pos),
        "parameters": extract_parameters(path),
        "version": extract_api_version(path),
        "source_url": base_url,
        "category": categorize_route(path)
    }
    
    # Construir URL completa se tiver base
    if base_url and not path.startswith('http'):
        route_info["full_url"] = urljoin(base_url, path)
    elif path.startswith('http'):
        route_info["full_url"] = path
        
    return route_info


def is_api_route(path: str) -> bool:
    """
    Verifica se o path parece ser uma rota de API.
    """
    path_lower = path.lower()
    api_indicators = ['/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/', 
                      '/json/', '/data/', '/ajax/', '/ws/', '/webhook/']
    return any(ind in path_lower for ind in api_indicators)


def detect_method(content: str, match_pos: int) -> str:
    """
    Tenta detectar o metodo HTTP usado para a rota.
    """
    # Pegar contexto ao redor do match
    start = max(0, match_pos - 100)
    end = min(len(content), match_pos + 50)
    context = content[start:end].upper()
    
    # Patterns de metodos
    method_patterns = {
        'GET': ['.GET', 'GET(', 'method: "GET', "method: 'GET", 'method:"GET', "method:'GET"],
        'POST': ['.POST', 'POST(', 'method: "POST', "method: 'POST", 'method:"POST', "method:'POST"],
        'PUT': ['.PUT', 'PUT(', 'method: "PUT', "method: 'PUT", 'method:"PUT', "method:'PUT"],
        'DELETE': ['.DELETE', 'DELETE(', 'method: "DELETE', "method: 'DELETE"],
        'PATCH': ['.PATCH', 'PATCH(', 'method: "PATCH', "method: 'PATCH"]
    }
    
    for method, patterns in method_patterns.items():
        for pattern in patterns:
            if pattern.upper() in context:
                return method
                
    return 'UNKNOWN'


def extract_parameters(path: str) -> list:
    """
    Extrai parametros do path.
    """
    params = []
    
    # Path parameters (e.g., /users/:id, /users/{id}, /users/[id])
    path_param_patterns = [
        r':(\w+)',           # Express style :param
        r'\{(\w+)\}',        # OpenAPI style {param}
        r'\[(\w+)\]',        # Next.js style [param]
        r'<(\w+)>',          # Flask style <param>
    ]
    
    for pattern in path_param_patterns:
        matches = re.findall(pattern, path)
        for match in matches:
            params.append({
                "name": match,
                "type": "path",
                "in": "path"
            })
    
    # Query parameters (se tiver ? no path)
    if '?' in path:
        query_part = path.split('?', 1)[1]
        query_params = re.findall(r'(\w+)=', query_part)
        for param in query_params:
            params.append({
                "name": param,
                "type": "query",
                "in": "query"
            })
    
    return params


def extract_api_version(path: str) -> str:
    """
    Extrai versao da API do path.
    """
    version_match = re.search(r'/v(\d+(?:\.\d+)?)', path, re.I)
    if version_match:
        return f"v{version_match.group(1)}"
    return None


def categorize_route(path: str) -> str:
    """
    Categoriza o tipo de rota.
    """
    path_lower = path.lower()
    
    categories = {
        'auth': ['login', 'logout', 'signin', 'signout', 'register', 'auth', 'oauth', 'token', 'session'],
        'user': ['user', 'profile', 'account', 'member'],
        'admin': ['admin', 'dashboard', 'manage', 'control'],
        'data': ['data', 'export', 'import', 'download', 'upload', 'file'],
        'config': ['config', 'setting', 'preference', 'option'],
        'payment': ['payment', 'pay', 'checkout', 'order', 'cart', 'billing'],
        'search': ['search', 'query', 'find', 'lookup'],
        'notification': ['notify', 'notification', 'alert', 'message', 'email'],
        'webhook': ['webhook', 'callback', 'hook'],
        'graphql': ['graphql', 'graph'],
    }
    
    for category, keywords in categories.items():
        if any(kw in path_lower for kw in keywords):
            return category
            
    return 'general'
