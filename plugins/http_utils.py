
import httpx

def format_http_request(request: httpx.Request) -> str:
    """Formats an httpx.Request into a raw HTTP string."""
    headers = "\n".join(f"{k}: {v}" for k, v in request.headers.items())
    body = ""
    if request.content:
        try:
            body = "\n\n" + request.content.decode('utf-8', errors='replace')
        except:
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
        except:
            body = "\n\n[Binary Content]"

    return f"{http_version} {status_code} {reason_phrase}\n{headers}{body}"
