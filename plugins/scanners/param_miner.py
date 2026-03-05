import httpx
import re
from typing import List, Dict, Any
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

# Top 50 hidden parameters for bug bounty
HIDDEN_PARAMS = [
    "admin", "debug", "test", "role", "user_id", "id", "uid", "account_id", 
    "is_admin", "dev", "beta", "mode", "access", "permission", "dir", "file", 
    "path", "url", "redirect", "next", "return", "format", "type", "action", 
    "cmd", "exec", "query", "sql", "token", "key", "auth", "secret", "timestamp",
    "signature", "hash", "email", "username", "login", "password", "pass",
    "show_errors", "verbose", "trace", "dump", "env", "config", "profile", "user"
]

def analyze_response_diff(base_resp: httpx.Response, test_resp: httpx.Response) -> Dict[str, Any]:
    """
    Compara duas respostas HTTP e retorna a diferença caso seja significativa.
    Ignora pequenas mudanças dinâmicas tipo tokens CSRF aleatórios (+- 2% de diferença).
    """
    diff_data = {"is_different": False, "reason": ""}
    
    if base_resp.status_code != test_resp.status_code:
        diff_data["is_different"] = True
        diff_data["reason"] = f"Status changed from {base_resp.status_code} to {test_resp.status_code}"
        return diff_data
        
    base_len = len(base_resp.text)
    test_len = len(test_resp.text)
    
    # 0 length handling
    if base_len == 0 and test_len > 0:
         diff_data["is_different"] = True
         diff_data["reason"] = "Base response empty, test response has content"
         return diff_data
    if base_len == 0 and test_len == 0:
         return diff_data
         
    # Check for significant size change (mais de 2%)
    diff_percent = abs(base_len - test_len) / base_len
    if diff_percent > 0.02 and abs(base_len - test_len) > 50: # Pelo menos 50 bytes de dif
        diff_data["is_different"] = True
        diff_data["reason"] = f"Length changed by {diff_percent*100:.1f}% ({base_len} vs {test_len} bytes)"
        return diff_data

    # Check for new keywords indicating debug or admin
    if "admin" not in base_resp.text.lower() and "admin" in test_resp.text.lower():
        diff_data["is_different"] = True
        diff_data["reason"] = "'admin' keyword appeared in response"
    elif "debug" not in base_resp.text.lower() and "debug" in test_resp.text.lower():
        diff_data["is_different"] = True
        diff_data["reason"] = "'debug' keyword appeared in response"
        
    return diff_data

def mine_parameters(url: str, timeout: int = 5) -> List[Dict[str, Any]]:
    """
    Injeta a wordlist padrão de parâmetros na URL e avalia as mudanças de estado.
    """
    findings = []
    
    try:
        with httpx.Client(verify=False, follow_redirects=True, timeout=timeout) as client:
            # Baseline Request (without injection)
            base_resp = client.get(url)
            
            # Inject each parameter
            for param in HIDDEN_PARAMS:
                # Add parameter to URL query string
                parsed = urlparse(url)
                query_params = parse_qsl(parsed.query)
                query_params.append((param, "1")) # Testing with a truthy value like 1
                query_params.append((param, "true")) # or true
                
                # Fazer requisição apenas com um valor teste basico para velocidade
                test_parsed = parse_qsl(parsed.query)
                test_parsed.append((param, "true"))
                
                new_query = urlencode(test_parsed)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
                
                test_resp = client.get(test_url)
                
                diff = analyze_response_diff(base_resp, test_resp)
                
                if diff["is_different"]:
                    findings.append({
                        "url": url,
                        "parameter": param,
                        "test_value": "true",
                        "status_code": test_resp.status_code,
                        "original_status": base_resp.status_code,
                        "response_length": len(test_resp.text),
                        "original_length": len(base_resp.text),
                        "reason": diff["reason"]
                    })
                    
    except Exception as e:
        pass
        
    return findings
