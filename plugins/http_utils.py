import httpx
import time
import core.config

# V11.6: Dynamic rate limiting state
_consecutive_429 = 0
_current_delay = core.config.REQUEST_DELAY

def throttle():
    """Aplica delay configurado globalmente para prevenir bans ou sobrecarga rate limit em paralelismo."""
    global _current_delay
    if _current_delay > 0:
        time.sleep(_current_delay)

def adapt_rate_limit(response: httpx.Response = None, status_code: int = None):
    """V11.6: Ajusta o delay dinamicamente se detectarmos WAF ou Rate Limit (429)"""
    global _consecutive_429, _current_delay
    
    code = status_code if status_code else (response.status_code if response else 200)
    
    if code == 429:
        _consecutive_429 += 1
        if _consecutive_429 >= 2:
            # Backoff exponencial até max 5s
            _current_delay = min(_current_delay * 1.5 + 0.5, 5.0)
            from plugins.output import warn
            warn(f"   ⚠️ Rate limit (429) detectado. Aumentando delay para {_current_delay:.2f}s")
            _consecutive_429 = 0
            time.sleep(_current_delay * 2) # Cool down imediato
    elif code < 400:
        # Se sucesso, tenta voltar devagar ao baseline
        _consecutive_429 = 0
        if _current_delay > core.config.REQUEST_DELAY:
            _current_delay = max(core.config.REQUEST_DELAY, _current_delay - 0.1)

def format_http_request(request: httpx.Request) -> str:
    """Formats an httpx.Request into a raw HTTP string."""
    headers = "\n".join(f"{k}: {v}" for k, v in request.headers.items())
    body = ""
    if request.content:
        try:
            body = "\n\n" + request.content.decode('utf-8', errors='replace')
        except Exception:
            body = "\n\n[Binary Content]"
            
    method = request.method
    path = request.url.raw_path.decode('utf-8')
    http_version = "HTTP/1.1" # httpx defaults to 1.1 unless http2=True
    
    return f"{method} {path} {http_version}\n{headers}{body}"

def format_http_response(response: httpx.Response) -> str:
    """Formats an httpx.Response into a raw HTTP string."""
    http_version = response.http_version
    status_code = response.status_code
    reason_phrase = response.reason_phrase
    
    headers = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
    
    body = ""
    if response.content:
        try:
            # Limit body size to avoid huge JSONs
            content = response.text
            if len(content) > 10000:
                content = content[:10000] + "\n... [Truncated]"
            body = "\n\n" + content
        except Exception:
            body = "\n\n[Binary Content]"

    return f"{http_version} {status_code} {reason_phrase}\n{headers}{body}"


def format_raw_request(method: str, url: str, headers: dict, body: str = "") -> str:
    """Formats a raw HTTP request string from individual components."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    
    host = parsed.netloc
    header_lines = f"Host: {host}\n"
    header_lines += "\n".join(f"{k}: {v}" for k, v in headers.items() if k.lower() != "host")
    
    result = f"{method} {path} HTTP/1.1\n{header_lines}"
    if body:
        result += f"\n\n{body}"
    return result


def format_raw_response(status_code: int, headers: dict, body: str = "") -> str:
    """Formats a raw HTTP response string from individual components."""
    header_lines = "\n".join(f"{k}: {v}" for k, v in headers.items())
    result = f"HTTP/1.1 {status_code}\n{header_lines}"
    if body:
        content = body[:10000]
        if len(body) > 10000:
            content += "\n... [Truncated]"
        result += f"\n\n{content}"
    return result


def check_tool_installed(name: str) -> bool:
    """Verifica se uma ferramenta (binário) está instalada no sistema."""
    import shutil
    return shutil.which(name) is not None
