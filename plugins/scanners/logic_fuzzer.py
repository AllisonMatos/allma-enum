import httpx
from typing import List, Dict, Any

def scan_cors(url: str, timeout: int = 5) -> Dict[str, Any]:
    """
    Testes avançados de CORS enviando um Origin falso.
    Se o servidor refletir o Origin falso no Access-Control-Allow-Origin,
    e permitir credentials, é crítico.
    """
    evil_origin = "https://evil-hacker.com"
    headers = {
        "Origin": evil_origin
    }
    
    finding = None
    try:
        with httpx.Client(verify=False, timeout=timeout) as client:
            resp = client.options(url, headers=headers)
            
            # Alguns servidores só respondem CORS num GET normal
            if "access-control-allow-origin" not in {k.lower(): v for k, v in resp.headers.items()}:
                resp = client.get(url, headers=headers)
            
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            
            if acao == evil_origin:
                risk = "HIGH" if acac == "true" else "MEDIUM"
                finding = {
                    "url": url,
                    "type": "CORS Misconfiguration",
                    "risk": risk,
                    "details": f"Reflected arbitrary origin '{evil_origin}'. Credentials allowed: {acac}",
                    "headers": dict(resp.headers)
                }
            elif acao == "*" and acac == "true":
                # Technically invalid in modern browsers, but still a misconfig sign
                finding = {
                    "url": url,
                    "type": "CORS Misconfiguration",
                    "risk": "LOW",
                    "details": "Wildcard origin with credentials allowed (Usually blocked by browsers)",
                    "headers": dict(resp.headers)
                }
    except Exception:
        pass
        
    return finding

def scan_cache_poisoning(url: str, timeout: int = 5) -> Dict[str, Any]:
    """
    Injeta cabeçalhos comuns que envenenam cache e checa a reflexão na resposta.
    """
    poison_host = "poisoned-host.evil.com"
    headers = {
        "X-Forwarded-Host": poison_host,
        "X-Host": poison_host,
        "X-Forwarded-Server": poison_host,
        "Host": poison_host # Algumas vezes injetar multiplos Host headers, mas httpx barra. Então usamos os extras.
    }
    
    finding = None
    try:
         with httpx.Client(verify=False, timeout=timeout) as client:
            resp = client.get(url, headers=headers)
            
            if poison_host in resp.text:
                # Checar se a página tem Cache vivo (headers)
                cache_control = resp.headers.get("Cache-Control", "")
                age = resp.headers.get("Age", "")
                cf_cache = resp.headers.get("CF-Cache-Status", "")
                x_cache = resp.headers.get("X-Cache", "")
                
                is_cached = any([
                    "public" in cache_control.lower(),
                    "max-age" in cache_control.lower(),
                    age != "",
                    cf_cache.lower() in ["hit", "miss"],
                    "hit" in x_cache.lower() or "miss" in x_cache.lower()
                ])
                
                risk = "HIGH" if is_cached else "MEDIUM"
                
                finding = {
                    "url": url,
                    "type": "Web Cache Poisoning",
                    "risk": risk,
                    "details": f"Reflected unkeyed header 'X-Forwarded-Host' into body. Cached: {is_cached}",
                    "headers": dict(resp.headers)
                }
    except Exception:
        pass
        
    return finding

def fuzz_logic_flaws(url: str, timeout: int = 5) -> List[Dict[str, Any]]:
    """
    Roda a suite inteira de falhas logicas nesa URL.
    """
    findings = []
    
    cors = scan_cors(url, timeout)
    if cors:
        findings.append(cors)
        
    cache = scan_cache_poisoning(url, timeout)
    if cache:
        findings.append(cache)
        
    return findings
