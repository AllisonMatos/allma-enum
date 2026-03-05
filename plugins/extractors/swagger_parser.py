import httpx
import json
import yaml
from typing import List, Dict, Any
from urllib.parse import urljoin

SWAGGER_PATHS = [
    "/swagger.json",
    "/api-docs",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/v3/swagger.json",
    "/api/swagger.json",
    "/openapi.json",
    "/api/openapi.json",
    "/docs/swagger.json",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/yml/swagger.yaml",
    "/swagger.yaml"
]

def parse_openapi(doc_content: str, source_url: str) -> List[Dict[str, Any]]:
    """
    Tenta parsear um documento OpenAPI/Swagger (JSON ou YAML).
    Extrai as rotas, os métodos suportados e parâmetros esperados.
    """
    try:
        data = json.loads(doc_content)
    except json.JSONDecodeError:
        try:
            data = yaml.safe_load(doc_content)
        except Exception:
            return []

    if not isinstance(data, dict):
        return []

    # Verificar se é formato reconhecido (Swagger 2.0 ou OpenAPI 3.x)
    is_swagger = "swagger" in data or "openapi" in data
    if not is_swagger:
        return []

    endpoints = []
    base_path = data.get("basePath", "")

    paths = data.get("paths", {})
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue

        for method_name, details in methods.items():
            # Ignorar definicoes que não sao metodos HTTP reais (ex: $ref)
            if method_name.lower() not in ["get", "post", "put", "delete", "patch", "options", "head"]:
                continue
            
            full_path = urljoin(source_url, f"{base_path}{path}".replace("//", "/"))
            
            params = []
            # Extrair parametros
            if isinstance(details, dict):
                for param in details.get("parameters", []):
                    if isinstance(param, dict) and "name" in param:
                        params.append({
                            "name": param["name"],
                            "in": param.get("in", "unknown"),
                            "required": param.get("required", False)
                        })

            endpoints.append({
                "method": method_name.upper(),
                "path": full_path,
                "summary": details.get("summary", ""),
                "parameters": params
            })

    return endpoints

def scan_for_swagger(base_url: str, timeout: int = 5) -> List[Dict[str, Any]]:
    """
    Faz fuzzing no base_url procurando pelos SWAGGER_PATHS.
    Se encontrar e parsear corretamente, retorna os endpoints.
    """
    extracted = []
    
    with httpx.Client(verify=False, follow_redirects=True, timeout=timeout) as client:
        for path in SWAGGER_PATHS:
            target_url = urljoin(base_url, path)
            try:
                resp = client.get(target_url)
                if resp.status_code == 200:
                    content_type = resp.headers.get('Content-Type', '').lower()
                    if 'application/json' in content_type or 'text/yaml' in content_type or 'application/yaml' in content_type:
                        findings = parse_openapi(resp.text, base_url)
                        if findings:
                            extracted.extend(findings)
                            break  # Se achou e parseou um com sucesso, não precisa tentar as outras variações
            except Exception:
                pass
                
    return extracted
