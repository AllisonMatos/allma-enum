"""
Web Cache Vulnerabilities — Identifica rotas que fazem caching de respostas.
Rotas cacheadas são o alvo primário para Web Cache Poisoning e Cache Deception.
"""
from core.config import DEFAULT_USER_AGENT
import json
from pathlib import Path
from urllib.parse import urlparse
import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed

from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn
from ..validation import finding

CACHE_HEADERS = [
    "x-cache", "x-cache-hits", "x-cache-status", "age",
    "cf-cache-status", "x-drupal-cache", "x-varnish", "x-squid-error"
]

def check_cache_route(url: str) -> dict | None:
    """Verifica se uma rota responde com headers indicativos de Cache HIT."""
    import random
    
    # Cache buster to ensure we are hitting the edge fresh, 
    # then we hit it again to see if it cached it.
    cb = str(random.randint(100000, 999999))
    target_url = f"{url}?cb={cb}" if "?" not in url else f"{url}&cb={cb}"
    
    headers = {"User-Agent": DEFAULT_USER_AGENT}
    
    try:
        with httpx.Client(timeout=5, verify=False, follow_redirects=True) as client:
            # First request (Miss)
            client.get(target_url, headers=headers)
            
            # Second request (Hit)
            resp = client.get(target_url, headers=headers)
            
            matched_headers = {}
            for h in CACHE_HEADERS:
                if h in resp.headers:
                    val = resp.headers[h].upper()
                    if "HIT" in val or h == "age":
                        matched_headers[h] = resp.headers[h]
                        
            if matched_headers:
                # Cache is active on this route
                # Is it an API or user-specific route?
                risk = "INFO"
                if "/api/" in url.lower() or "/users/" in url.lower() or "/me" in url.lower():
                    risk = "MEDIUM" # High potential for Cache Deception
                    
                return finding(
                    plugin="cache",
                    target="",
                    title="Web Cache Detected",
                    issue_type="CACHE_ENABLED_ROUTE",
                    risk=risk,
                    confidence="HIGH",
                    url=url,
                    description=f"Route is cached by intermediate proxy/CDN. Potential target for Web Cache Poisoning/Deception.",
                    detection={"cache_headers": matched_headers, "status_code": resp.status_code},
                    validation={"status": "POTENTIAL"},
                    evidence={"observable_impact": "Allows manipulation of cached content or leakage of sensitive PII via cache deception"},
                    metadata={"headers": dict(resp.headers)}
                )
    except Exception:
        pass
        
    return None

def run(context: dict):
    """Executa descoberta de Web Cache."""
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟥───────────────────────────────────────────────────────────🟥\n"
        f"   ⚡ {C.BOLD}{C.CYAN}WEB CACHE DISCOVERY{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟥───────────────────────────────────────────────────────────🟥\n"
    )

    outdir = ensure_outdir(target, "cache")

    urls_file = Path("output") / target / "domain" / "urls_valid.txt"
    if not urls_file.exists():
        urls_file = Path("output") / target / "urls_valid.txt"

    if not urls_file.exists():
        warn("⚠️ Nenhuma URL encontrada para teste de cache.")
        return []

    valid_urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]
    
    # Deduplicate by base path to avoid hammering
    unique_paths = set()
    test_urls = []
    for u in valid_urls:
        parsed = urlparse(u)
        base_path = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if base_path not in unique_paths:
            unique_paths.add(base_path)
            test_urls.append(base_path)

    info(f"   📋 Testando {len(test_urls)} rotas únicas para Web Cache...")

    all_findings = []
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(check_cache_route, u): u for u in test_urls[:3000]} # Limit to 3000 to save time
        
        done = 0
        for future in as_completed(futures):
            done += 1
            if done % 50 == 0:
                print(f"   [{done}/{len(futures)}] Verificando...", end="\r")
                
            try:
                res = future.result()
                if res:
                    all_findings.append(res)
                    sev_color = C.YELLOW if res["risk"] == "MEDIUM" else C.CYAN
                    h_keys = ", ".join(res["detection"]["cache_headers"].keys())
                    info(f"   ⚡ {sev_color}[CACHE DETECTED]{C.END} {res['url']} (Headers: {h_keys})")
            except Exception:
                pass

    print("")
    
    results_file = outdir / "cache_results.json"
    if all_findings:
        results_file.write_text(json.dumps(all_findings, indent=2, ensure_ascii=False))
        success(f"\n   ⚡ {len(all_findings)} rotas cacheadas detectadas!")
        success(f"   📂 Salvos em {results_file}")
    else:
        success("✅ Nenhuma rota cacheada detectada de forma óbvia.")

    return all_findings
