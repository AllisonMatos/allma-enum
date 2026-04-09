import re
import json
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse

# Regex patterns baseados no LinkFinder / Katana para APIs
ROUTE_PATTERNS = [
    # Absolute URLs, relative paths, API endpoints
    r'(?:"|\')(((?:[a-zA-Z]{1,10}://|//)[^"\'>/]+)?/[a-zA-Z0-9_/?=&.\-]*)(?:"|\')',
    # Rotas específicas de API
    r'(?:"|\')(api/v[0-9]/[a-zA-Z0-9_\-]+)(?:"|\')',
    # Extensões clássicas
    r'(?:"|\')([a-zA-Z0-9_\-/]+(?:\.php|\.asp|\.aspx|\.jsp|\.json|\.xml|\.action|\.do))(?:"|\')',
]

# Regex omitindo patterns genéricos que absorvem CSS classes do Bootstrap/React
PARAM_PATTERNS = [
    r'(?:\?|&)([a-zA-Z0-9_]+)=', # URL get params like ?token=
]

def extract_js_logic(content: str, full_url: str) -> Dict[str, Any]:
    """
    Analisa um conteúdo JavaScript bruto buscando por rotas de frontend/backend 
    e possíveis nomes de parâmetros de API.
    """
    routes = set()
    params = set()
    
    # 1. Extração de Rotas
    for pattern in ROUTE_PATTERNS:
        try:
            matches = re.finditer(pattern, content)
            for m in matches:
                # O grupo selecionado pelo regex
                matched_str = m.group(1).strip() if len(m.groups()) > 0 else m.group().strip("'\"")
                
                # Ignorar falsos positivos óbvios
                if not matched_str or matched_str in ['/', '.', '#']:
                    continue
                if any(ext in matched_str.lower() for ext in ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.css']):
                    continue
                if len(matched_str) < 4:
                    continue
                    
                # Reconstruir URL absoluta
                parsed_base = urlparse(full_url)
                base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
                
                if matched_str.startswith('/'):
                    absolute_url = urljoin(base_domain, matched_str)
                elif matched_str.startswith('api/') or matched_str.startswith('v1/') or matched_str.startswith('v2/'):
                    absolute_url = urljoin(base_domain, '/' + matched_str)
                else:
                    # Rota relativa, junta com o path atual
                    absolute_url = urljoin(full_url, matched_str)
                    
                routes.add(absolute_url)
        except Exception:
            pass

    # 2. Extração de Parâmetros
    # a) Params URL baseados em query string
    for pattern in PARAM_PATTERNS:
        try:
            matches = re.finditer(pattern, content)
            for m in matches:
                p = m.group(1).strip()
                if 2 < len(p) < 20 and not p.isdigit():
                    params.add(p)
        except Exception: pass
        
    # b) Params dentro de blocos de requisição Ajax / Axios / Fetch (ex: data: { param: value })
    try:
        ajax_block_re = re.compile(r'\b(?:data|params|headers|body)\s*:\s*\{([^}]+)\}')
        key_re = re.compile(r'(?:["\'])?([a-zA-Z0-9_]+)(?:["\'])?\s*:')
        for block_m in ajax_block_re.finditer(content):
            block = block_m.group(1)
            for key_m in key_re.finditer(block):
                p = key_m.group(1).strip()
                if 2 < len(p) < 20 and not p.isdigit() and p.lower() not in ['true', 'false', 'null']:
                    params.add(p)
    except Exception:
        pass

    return {
        "source_js": full_url,
        "routes": list(routes),
        "parameters": list(params)
    }

def analyze_js_files(js_files: Dict[str, str], base_target: str) -> List[Dict[str, Any]]:
    """
    Recebe um dict de URLs de JS e seus conteúdos de volta, 
    retorna lista de findings.
    """
    results = []
    for js_url, js_content in js_files.items():
        if not js_content:
            continue
        try:
            analysis = extract_js_logic(js_content, js_url)
            if analysis["routes"] or analysis["parameters"]:
                results.append(analysis)
        except Exception as e:
            print(f"[!] Error analyzing {js_url}: {e}")
            
    return results
