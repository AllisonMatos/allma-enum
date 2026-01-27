from pathlib import Path
import json
import asyncio
import time
from urllib.parse import urlparse

from menu import C
from ..output import info, success, warn, error
from .utils import ensure_outdir
from .subfinder import run_subfinder
from .naabu import run_naabu
from .ports import organize_ports
from .urls import build_urls
from .validator import validate_urls, validate_urls_detailed
from plugins.extractors import (
    extract_keys, 
    extract_js, 
    extract_routes,
    extract_inline_scripts,
    analyze_page
)

CONCURRENCY_LIMIT = 10
DELAY_BETWEEN_REQUESTS = 0.5

# ============================================================
# ASYNC HELPERS
# ============================================================
async def fetch_page_with_info_async(client, url):
    """Fetches a page asynchronously with retry."""
    result = {
        "success": False,
        "content": None,
        "status_code": None,
        "headers": None,
        "final_url": url,
        "error": None
    }
    
    for attempt in range(3):
        try:
            resp = await client.get(url)
            
            if resp.status_code == 429 or resp.status_code >= 500:
                await asyncio.sleep((attempt + 1) * 2)
                continue

            result["status_code"] = resp.status_code
            result["headers"] = dict(resp.headers)
            result["final_url"] = str(resp.url)
            
            valid_codes = {200, 201, 204, 301, 302, 303, 307, 308, 401, 403, 405}
            if resp.status_code in valid_codes:
                result["success"] = True
                result["content"] = resp.text
            return result
            
        except Exception as e:
            result["error"] = str(e)
            await asyncio.sleep(1)
        
    return result

async def analyze_url_task(client, url, semaphore):
    """Task to analyze a single URL fully."""
    async with semaphore:
        # Rate limit
        await asyncio.sleep(DELAY_BETWEEN_REQUESTS)
        
        # 1. Fetch
        response = await fetch_page_with_info_async(client, url)
        if not response["success"]:
            return None
            
        content = response["content"]
        if not content:
            return None
            
        final_url = response["final_url"]
        headers = response["headers"]
        
        # 2. CPU-bound Extraction (Run in thread pool to avoid blocking loop if heavy)
        # For simplicity, we run inline as regex on small pages is fast. 
        # But to be robust against huge JS files, we could wrap in loop.run_in_executor
        
        # === DETECT LOGIN PAGES ===
        login_keywords = ["login", "signin", "auth", "logon", "sso"]
        url_lower = final_url.lower()
        content_lower = content[:3000].lower()
        
        is_login = False
        for kw in login_keywords:
            if kw in url_lower or (
                kw in content_lower and 
                ("password" in content_lower or "senha" in content_lower)
            ):
                is_login = True
                break
                
        # === EXTRACT DATA ===
        # These are synchronous calls from extractors module
        try:
            keys = extract_keys(content, source_url=final_url)
            js_files = extract_js(content, final_url)
            inline_scripts = extract_inline_scripts(content, final_url)
            
            # Inline JS keys
            for script in inline_scripts:
                if script.get("has_config"):
                    keys.extend(extract_keys(
                        script["content"], 
                        source_url=final_url,
                        source_file="inline_script"
                    ))
                    
            routes = extract_routes(content, final_url)
            tech_result = analyze_page(final_url, content, headers)
            
            return {
                "url": final_url,
                "is_login": is_login,
                "keys": keys,
                "js_files": js_files,
                "routes": routes,
                "technologies": tech_result["technologies"]
            }
            
        except Exception as e:
            # error(f"Error analyzing content of {url}: {e}")
            return None


async def run_deep_analysis_async(valid_urls):
    import httpx
    
    results = []
    sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
    
    info(f"{C.BOLD}{C.BLUE}[6/6] Deep Analysis Async (Keys, JS, Routes, Technologies)...{C.END}")
    
    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as client:
        tasks = [analyze_url_task(client, url, sem) for url in valid_urls]
        
        total = len(tasks)
        completed = 0
        
        for coro in asyncio.as_completed(tasks):
            res = await coro
            completed += 1
            if completed % 5 == 0:
                print(f"   [{completed}/{total}] Analyzed...", end="\r")
            
            if res:
                results.append(res)
                
    print("") # Newline
    return results

# ============================================================
# MAIN
# ============================================================
def run(context):
    """
    Fluxo principal do modulo DOMAIN.
    OTIMIZADO: Deep Analysis via AsyncIO.
    """

    target = context["target"]
    ports_mode = context["ports"]

    info(
        f"\n[DOMAIN] Iniciando modulo\n"
        f"   Alvo: {C.GREEN}{target}{C.END}\n"
        f"   Modo de portas: {C.YELLOW}{ports_mode}{C.END}\n"
    )

    outdir = ensure_outdir(target)

    subs_file = outdir / "subdomains.txt"
    ports_raw = outdir / "ports_raw.txt"
    ports_final = outdir / "ports.txt"
    urls_file = outdir / "urls.txt"
    urls_ok = outdir / "urls_valid.txt"

    # === ETAPA 1: SUBFINDER ===
    info(f"{C.BOLD}{C.BLUE}[1/6] Descobrindo subdominios...{C.END}")
    run_subfinder(target, subs_file)

    # === ETAPA 2: NAABU (PORTAS) ===
    info(f"{C.BOLD}{C.BLUE}[2/6] Varredura de portas (naabu)...{C.END}")
    run_naabu(subs_file, ports_raw, ports_mode)

    # === ETAPA 3: ORGANIZAR PORTAS ===
    info(f"{C.BOLD}{C.BLUE}[3/6] Organizando portas encontradas...{C.END}")
    organize_ports(ports_raw, ports_final)

    # === ETAPA 4: GERAR URLS ===
    info(f"{C.BOLD}{C.BLUE}[4/6] Gerando URLs possiveis...{C.END}")
    build_urls(ports_raw, urls_file, subs_file=subs_file)

    # === ETAPA 5: VALIDAR URLS ===
    info(f"{C.BOLD}{C.BLUE}[5/6] Validando URLs ativas...{C.END}")
    valid_urls = validate_urls(urls_file, urls_ok)

    # === ETAPA 5.5: ADVANCED CRAWLING (Recursivo) ===
    try:
        from ..crawlers import run_crawlers
        info(f"{C.BOLD}{C.BLUE}[5.5/6] Advanced Crawling (Katana/Gospider)...{C.END}")
        run_crawlers(urls_ok, outdir)
    except ImportError as e:
        warn(f"Modulo de crawlers nao encontrado: {e}")
    except Exception as e:
        error(f"Erro ao executar crawlers: {e}")

    # === ETAPA 6: DEEP ANALYSIS (ASYNC) ===
    
    # Arquivos de saida
    extracted_js_file = outdir / "extracted_js.json"
    extracted_keys_file = outdir / "extracted_keys.json"
    extracted_routes_file = outdir / "extracted_routes.json"
    technologies_file = outdir / "technologies.json"
    login_pages_file = outdir / "login_pages.txt"

    if not valid_urls:
         success(f"\n{C.GREEN}Sem URLs para analisar.{C.END}")
         return []

    # Executar Async Analysis
    try:
        # Check httpx
        import httpx
        results = asyncio.run(run_deep_analysis_async(valid_urls))
        
        # Processar resultados agregados
        all_js = []
        all_keys = []
        all_routes = []
        all_technologies = {}
        login_pages = []
        
        for res in results:
            url = res["url"]
            subdomain = get_subdomain(url)
            
            # Login
            if res["is_login"]:
                login_pages.append(url)
                
            # Keys
            for k in res["keys"]:
                k["subdomain"] = subdomain
            all_keys.extend(res["keys"])
            
            # JS
            for j in res["js_files"]:
                j["subdomain"] = subdomain
            all_js.extend(res["js_files"])
            
            # Routes
            for r in res["routes"]:
                r["subdomain"] = subdomain
            all_routes.extend(res["routes"])
            
            # Technologies
            if subdomain not in all_technologies:
                all_technologies[subdomain] = {"url": url, "technologies": []}
            
            existing_names = {t["name"] for t in all_technologies[subdomain]["technologies"]}
            for tech in res["technologies"]:
                if tech["name"] not in existing_names:
                    all_technologies[subdomain]["technologies"].append(tech)
                    existing_names.add(tech["name"])

        # === SALVAR RESULTADOS ===
        
        # JS
        if all_js:
            seen_urls = set()
            unique_js = []
            for js in all_js:
                if js["url"] not in seen_urls:
                    seen_urls.add(js["url"])
                    unique_js.append(js)
            
            with open(extracted_js_file, "w") as f:
                json.dump(unique_js, f, indent=2, ensure_ascii=False)
            info(f"   + {len(unique_js)} arquivos JS extraidos.")

        # KEYS
        if all_keys:
            with open(extracted_keys_file, "w") as f:
                json.dump(all_keys, f, indent=2, ensure_ascii=False)
            info(f"   + {len(all_keys)} keys/secrets encontradas!")
            
        # ROUTES
        if all_routes:
            seen_paths = set()
            unique_routes = []
            for route in all_routes:
                if route["path"] not in seen_paths:
                    seen_paths.add(route["path"])
                    unique_routes.append(route)
                    
            with open(extracted_routes_file, "w") as f:
                json.dump(unique_routes, f, indent=2, ensure_ascii=False)
            info(f"   + {len(unique_routes)} rotas de API extraidas.")

        # TECHNOLOGIES
        if all_technologies:
            with open(technologies_file, "w") as f:
                json.dump(all_technologies, f, indent=2, ensure_ascii=False)
            total_techs = sum(len(v["technologies"]) for v in all_technologies.values())
            info(f"   + {total_techs} tecnologias detectadas em {len(all_technologies)} subdominios.")

        # LOGIN PAGES
        if login_pages:
            with open(login_pages_file, "w") as f:
                f.write("\n".join(sorted(set(login_pages))) + "\n")
            info(f"   + {len(set(login_pages))} paginas de login encontradas!")

    except ImportError:
        error("Biblioteca 'httpx' não instalada. Instale com: pip install httpx")
    except Exception as e:
        import traceback
        error(f"Erro durante Deep Analysis: {e}")
        traceback.print_exc()

    # === FINALIZACAO ===
    success(
        f"\n{C.GREEN}{C.BOLD}DOMAIN concluido com sucesso!{C.END}\n"
        f"URLs validas: {C.YELLOW}{len(valid_urls)}{C.END}\n"
        f"Arquivos gerados em: {C.CYAN}{outdir}{C.END}\n"
    )

    return valid_urls


def get_subdomain(url: str) -> str:
    """Extrai o subdominio/host de uma URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc.split(":")[0]  # Remove porta se existir
    except:
        return url
