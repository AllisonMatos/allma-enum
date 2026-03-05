import httpx
from typing import List, Dict, Any
from urllib.parse import urljoin
from plugins.extractors.keys import extract_keys
from plugins.http_utils import format_http_request, format_http_response

# Caminhos críticos de repositório e CI/CD
CRITICAL_PATHS = [
    ("/.git/config", "Git Repository Configuration"),
    ("/.git/HEAD", "Git Repository HEAD"),
    ("/.git/logs/HEAD", "Git Commit History"),
    ("/.github/workflows/main.yml", "GitHub Actions Workflow"),
    ("/.gitlab-ci.yml", "GitLab CI Configuration"),
    ("/docker-compose.yml", "Docker Compose Configuration"),
    ("/Jenkinsfile", "Jenkins CI/CD Pipeline"),
    ("/.env.backup", "Environment Backup File"),
    ("/.env.dev", "Development Environment File"),
    ("/.env.example", "Environment Example Reference")
]

def scan_exposed_git_cicd(base_url: str, timeout: int = 5) -> List[Dict[str, Any]]:
    """
    Verifica se existem configurações de CI/CD ou repositórios Git expostos na raiz.
    Extrai chaves antigas do histórico do .git se disponível.
    """
    exposed = []
    
    with httpx.Client(verify=False, follow_redirects=True, timeout=timeout) as client:
        for path, description in CRITICAL_PATHS:
            target_url = urljoin(base_url, path)
            try:
                resp = client.get(target_url)
                if resp.status_code == 200:
                    text_content = resp.text
                    
                    # Verificação básica de falsos positivos
                    if "<html" in text_content[:100].lower() or "<body>" in text_content[:100].lower():
                        continue # Provavelmente um 404 fake
                        
                    is_valid = False
                    if "git" in path:
                         if "repositoryformatversion" in text_content or "ref:" in text_content or "commit" in text_content.lower():
                            is_valid = True
                    elif "yml" in path or "yaml" in path:
                         if "jobs:" in text_content or "services:" in text_content:
                             is_valid = True
                    else:
                         is_valid = True
                         
                    if is_valid:
                        # Achou arquivo sensível! Vamos escanear o histórico usando nosso módulo robusto de keys.py
                        found_keys = []
                        try:
                            # Chama a nova função de extração robusta
                            findings = extract_keys(text_content, source_file=path)
                            for k in findings:
                                found_keys.append({
                                    "match": k["match"],
                                    "type": k["type"],
                                    "risk": k.get("info", {}).get("risk", "MEDIUM")
                                })
                        except Exception:
                            pass
                            
                        exposed.append({
                            "url": target_url,
                            "type": description,
                            "size_bytes": len(text_content),
                            "secrets_found": found_keys,
                            "request_raw": format_http_request(resp.request),
                            "response_raw": format_http_response(resp)
                        })
                        
            except Exception:
                pass
                
    return exposed
