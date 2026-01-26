import re
from urllib.parse import urljoin

# Patterns para encontrar arquivos JS
PATTERNS_JS = [
    # Script tags com src
    r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
    # Import statements
    r'import\s+.*?\s+from\s+["\']([^"\']+\.js)["\']',
    r'import\s*\(["\']([^"\']+\.js)["\']\)',
    # Require statements
    r'require\s*\(\s*["\']([^"\']+\.js)["\']\s*\)',
    # Dynamic imports
    r'loadScript\s*\(\s*["\']([^"\']+\.js)["\']',
    # Webpack chunks
    r'["\']([^"\']*chunk[^"\']*\.js)["\']',
    # Source maps (podem revelar arquivos originais)
    r'//[#@]\s*sourceMappingURL=([^\s]+\.map)',
]

# Patterns para inline scripts importantes
INLINE_PATTERNS = [
    r'<script[^>]*>([\s\S]*?)</script>',
]


def extract_js(content: str, base_url: str = None) -> list:
    """
    Extracts JS URLs from HTML content and resolves them to absolute URLs.
    
    Args:
        content: HTML content
        base_url: Base URL for resolving relative paths
        
    Returns:
        list of dicts with JS file info
    """
    found = []
    seen_urls = set()
    
    for pattern in PATTERNS_JS:
        try:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                    
                match = match.strip()
                if not match:
                    continue
                    
                # Ignorar data URIs e blobs
                if match.startswith('data:') or match.startswith('blob:'):
                    continue
                    
                # Resolver URL
                if base_url:
                    absolute_url = urljoin(base_url, match)
                else:
                    absolute_url = match
                    
                if absolute_url not in seen_urls:
                    seen_urls.add(absolute_url)
                    
                    js_info = {
                        "url": absolute_url,
                        "original": match,
                        "source_url": base_url,
                        "type": categorize_js(match),
                        "is_external": is_external_js(absolute_url, base_url)
                    }
                    found.append(js_info)
                    
        except re.error:
            continue
    
    return found


def extract_js_simple(content: str, base_url: str) -> list:
    """
    Versao simplificada que retorna apenas URLs.
    Mantida para compatibilidade.
    """
    js_files = extract_js(content, base_url)
    return sorted([js["url"] for js in js_files])


def extract_inline_scripts(content: str, base_url: str = None) -> list:
    """
    Extrai conteudo de scripts inline.
    Util para encontrar keys/configs hardcoded.
    """
    inline_scripts = []
    
    for pattern in INLINE_PATTERNS:
        matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
        for i, match in enumerate(matches):
            if len(match.strip()) > 50:  # Ignorar scripts muito pequenos
                inline_scripts.append({
                    "index": i + 1,
                    "content": match[:5000],  # Limitar tamanho
                    "length": len(match),
                    "source_url": base_url,
                    "has_api_calls": bool(re.search(r'fetch\(|axios\.|XMLHttpRequest|\$\.ajax', match)),
                    "has_config": bool(re.search(r'config|settings|API_|apiKey|baseURL', match, re.I))
                })
    
    return inline_scripts


def categorize_js(js_path: str) -> str:
    """
    Categoriza o tipo de arquivo JS baseado no nome/path.
    """
    path_lower = js_path.lower()
    
    if any(x in path_lower for x in ['chunk', 'bundle', 'webpack']):
        return 'bundle'
    elif any(x in path_lower for x in ['vendor', 'lib', 'node_modules']):
        return 'vendor'
    elif any(x in path_lower for x in ['min.js', '.min.']):
        return 'minified'
    elif any(x in path_lower for x in ['main', 'app', 'index']):
        return 'main'
    elif any(x in path_lower for x in ['config', 'settings', 'env']):
        return 'config'
    elif '.map' in path_lower:
        return 'sourcemap'
    else:
        return 'other'


def is_external_js(js_url: str, base_url: str) -> bool:
    """
    Verifica se o JS e de um dominio externo.
    """
    if not base_url or not js_url:
        return False
        
    from urllib.parse import urlparse
    
    try:
        base_domain = urlparse(base_url).netloc.split(':')[0]
        js_domain = urlparse(js_url).netloc.split(':')[0]
        
        # Comparar dominios base
        base_parts = base_domain.split('.')[-2:]
        js_parts = js_domain.split('.')[-2:]
        
        return base_parts != js_parts
    except:
        return False
