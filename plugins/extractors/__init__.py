from .keys import extract_keys_to_json, format_key_report
from .js import extract_js, extract_js_simple, extract_inline_scripts
from .routes import extract_routes, extract_routes_simple
from .wappalyzer import detect_technologies, analyze_page
from .secretfinder_wrapper import SecretFinderWrapper

# Instancia global do wrapper
_secret_finder = SecretFinderWrapper()

def extract_keys(content: str, source_url: str = None, source_file: str = None) -> list:
    """
    Funcao wrapper que usa a nova implementacao do SecretFinder
    mas mantem a assinatura da antiga extract_keys para compatibilidade.
    """
    # Adapta a chamada para o metodo scan do wrapper
    keys = _secret_finder.scan(content)
    
    # Adiciona metadados de origem que o scan puro nao conhece
    for key in keys:
        if "source" not in key:
            key["source"] = {}
        key["source"]["url"] = source_url
        key["source"]["file"] = source_file
        
        # Enriquecer com info padrao se nao tiver (pra nao quebrar report)
        if "info" not in key:
            key["info"] = {
                "risk": "HIGH" if "Key" in key["type"] or "Token" in key["type"] else "MEDIUM",
                "service": key["type"],
                "usage": "Detected by SecretFinder logic",
                "docs": "N/A"
            }
        if "context" not in key or not key["context"].get("full"):
             key["context"] = {"full": "Context analysis failed or not available"}
        
        # Se o scan retornou context.line, use-o como source line se nao tivermos um
        if key.get("context", {}).get("line") and (not key["source"].get("line") or key["source"]["line"] == "?"):
            key["source"]["line"] = key["context"]["line"]
            
    return keys
