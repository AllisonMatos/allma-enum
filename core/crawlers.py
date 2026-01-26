import httpx
from random import choice
from .output import warn

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]

# Status codes que indicam que a pagina existe
VALID_STATUS_CODES = {200, 201, 204, 301, 302, 303, 307, 308, 401, 403, 405}


def get_headers():
    """Retorna headers com User-Agent aleatorio e headers comuns para bypass."""
    return {
        "User-Agent": choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,pt-BR;q=0.8,pt;q=0.7",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "max-age=0",
    }


def fetch_page(url: str, retries: int = 3, timeout: int = 15) -> str:
    """
    Fetches the content of a page with robust headers and retry mechanism.
    Returns the HTML content as string, or None if failed.
    
    Args:
        url: URL to fetch
        retries: Number of retry attempts (default 3)
        timeout: Timeout in seconds (default 15)
    """
    last_error = None
    
    for attempt in range(retries):
        headers = get_headers()  # Rotate User-Agent on each attempt
        current_timeout = timeout + (attempt * 5)  # Increase timeout on retries
        
        try:
            with httpx.Client(
                verify=False, 
                follow_redirects=True, 
                timeout=current_timeout,
                http2=True  # Enable HTTP/2 for better compatibility
            ) as client:
                resp = client.get(url, headers=headers)
                
                # Accept more status codes as valid
                if resp.status_code in VALID_STATUS_CODES:
                    return resp.text
                    
                # Log non-standard responses on last attempt
                if attempt == retries - 1:
                    warn(f"URL {url} returned status {resp.status_code}")
                    
        except httpx.TimeoutException:
            last_error = "timeout"
        except httpx.ConnectError:
            last_error = "connection_error"
        except Exception as e:
            last_error = str(e)
            
    return None


def fetch_page_with_info(url: str, retries: int = 3, timeout: int = 15) -> dict:
    """
    Fetches a page and returns detailed information about the response.
    
    Returns dict with:
        - success: bool
        - content: str or None
        - status_code: int or None
        - headers: dict or None
        - final_url: str (after redirects)
        - error: str or None
    """
    result = {
        "success": False,
        "content": None,
        "status_code": None,
        "headers": None,
        "final_url": url,
        "error": None
    }
    
    for attempt in range(retries):
        headers = get_headers()
        current_timeout = timeout + (attempt * 5)
        
        try:
            with httpx.Client(
                verify=False, 
                follow_redirects=True, 
                timeout=current_timeout,
                http2=True
            ) as client:
                resp = client.get(url, headers=headers)
                
                result["status_code"] = resp.status_code
                result["headers"] = dict(resp.headers)
                result["final_url"] = str(resp.url)
                
                if resp.status_code in VALID_STATUS_CODES:
                    result["success"] = True
                    result["content"] = resp.text
                    return result
                    
        except httpx.TimeoutException:
            result["error"] = "timeout"
        except httpx.ConnectError:
            result["error"] = "connection_error"
        except Exception as e:
            result["error"] = str(e)
            
    return result


def validate_url(url: str, timeout: int = 10) -> bool:
    """
    Quick validation to check if URL is accessible.
    Returns True if URL responds with a valid status code.
    """
    try:
        with httpx.Client(
            verify=False, 
            follow_redirects=True, 
            timeout=timeout
        ) as client:
            resp = client.head(url, headers=get_headers())
            if resp.status_code in VALID_STATUS_CODES:
                return True
            # Fallback to GET if HEAD fails
            resp = client.get(url, headers=get_headers())
            return resp.status_code in VALID_STATUS_CODES
    except:
        return False
