from pathlib import Path
import json
import asyncio
import time
import subprocess
from urllib.parse import urlparse

from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from .subfinder import run_subfinder
from .discovery import discover_subdomains
from .dns_resolver import resolve_and_filter
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
        
        # === DETECT LOGIN PAGES (V11: Enhanced) ===
        import re as _re
        url_lower = final_url.lower()
        content_lower = content[:5000].lower()
        
        is_login = False
        
        # Layer 1: URL path contains auth keywords
        url_auth_keywords = _re.compile(
            r'\b(login|signin|sign-in|sign_in|logon|sso|auth|authenticate|'
            r'account|access|entrar|conectar|acesso|portal|cas/login|'
            r'oauth|saml|adfs|idp|identity)\b', _re.I
        )
        url_has_auth = bool(url_auth_keywords.search(url_lower))
        
        # Layer 2: HTML has password input field (strongest signal)
        has_password_input = bool(_re.search(
            r'<input[^>]*type\s*=\s*["\']password["\']|'
            r'<input[^>]*name\s*=\s*["\'](password|passwd|pwd|pass|senha|contraseña)["\']',
            content_lower
        ))
        
        # Layer 3: HTML has login form patterns
        has_login_form = bool(_re.search(
            r'<form[^>]*(?:login|signin|auth|log-in|sign-in|entrar)[^>]*>|'
            r'<form[^>]*action\s*=\s*["\'][^"\']*(?:login|auth|signin|session|token)[^"\']*["\']',
            content_lower
        ))
        
        # Layer 4: Page title contains login keywords
        title_match = _re.search(r'<title[^>]*>(.*?)</title>', content_lower)
        has_login_title = False
        if title_match:
            title_text = title_match.group(1)
            has_login_title = bool(_re.search(
                r'login|sign\s*in|log\s*in|entrar|acesso|autenticação|authenticate|'
                r'iniciar\s*sessão|conectar|sign\s*on|portal', title_text
            ))
        
        # Decision: any strong signal OR combination of weaker signals
        if has_password_input:
            is_login = True  # Strongest: has password field
        elif url_has_auth and (has_login_form or has_login_title):
            is_login = True  # URL + form/title
        elif has_login_form and has_login_title:
            is_login = True  # Form + title
        elif url_has_auth and ("password" in content_lower or "senha" in content_lower):
            is_login = True  # URL + password text
                
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
    
    info(f"{C.BOLD}{C.BLUE}[8/8] Deep Analysis Async (Keys, JS, Routes, Technologies)...{C.END}")
    
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
    closed_scope = context.get("closed_scope", [])

    info(
        f"\n[DOMAIN] Iniciando modulo\n"
        f"   Alvo: {C.GREEN}{target}{C.END}\n"
        f"   Modo de portas: {C.YELLOW}{ports_mode}{C.END}\n"
    )

    outdir = ensure_outdir(target, "domain")

    subs_file = outdir / "subdomains.txt"
    ports_raw = outdir / "ports_raw.txt"
    ports_final = outdir / "ports.txt"
    urls_file = outdir / "urls.txt"
    urls_ok = outdir / "urls_valid.txt"

    if closed_scope:
        info(f"{C.BOLD}{C.BLUE}[1/8] Escopo fechado selecionado - escrevendo diretamente no arquivo...{C.END}")
        with open(subs_file, "w") as f:
            f.write("\n".join(closed_scope) + "\n")
        info(f"{C.BOLD}{C.BLUE}[2/8] Pulando Multi-source Discovery (crt.sh, haktrails, gau, etc)...{C.END}")
    else:
        # === ETAPA 1: SUBFINDER ===
        info(f"{C.BOLD}{C.BLUE}[1/8] Descobrindo subdominios (Subfinder)...{C.END}")
        run_subfinder(target, subs_file)

        # === ETAPA 2: MULTI-SOURCE DISCOVERY ===
        info(f"{C.BOLD}{C.BLUE}[2/8] Multi-source Discovery (crt.sh, haktrails, gau, waybackurls)...{C.END}")
        discover_subdomains(target, subs_file)
        
        # === ETAPA 2.2: HORIZONTAL DOMAIN DISCOVERY ===
        from .horizontal import discover_horizontal
        horizontal_domains = discover_horizontal(target, outdir)
        if horizontal_domains:
            with open(subs_file, "a") as f:
                f.write("\n" + "\n".join(horizontal_domains) + "\n")
                
        # === ETAPA 2.5: PERMUTATIONS ===
        from .permutations import run_permutations
        run_permutations(target, subs_file, outdir)

    # === ETAPA 3: DNS RESOLUTION + WILDCARD + CDN FILTER ===
    info(f"{C.BOLD}{C.BLUE}[3/8] DNS Resolution + Wildcard Detection + CDN Filter...{C.END}")
    resolve_and_filter(target, subs_file, outdir)

    # === ETAPA 4: NAABU (PORTAS) ===
    info(f"{C.BOLD}{C.BLUE}[4/8] Varredura de portas (naabu)...{C.END}")
    run_naabu(subs_file, ports_raw, ports_mode)

    # === ETAPA 5: ORGANIZAR PORTAS ===
    info(f"{C.BOLD}{C.BLUE}[5/8] Organizando portas encontradas...{C.END}")
    organize_ports(ports_raw, ports_final)

    # === ETAPA 6: GERAR URLS ===
    info(f"{C.BOLD}{C.BLUE}[6/8] Gerando URLs possiveis...{C.END}")
    build_urls(ports_raw, urls_file, subs_file=subs_file)

    # === ETAPA 7: VALIDAR URLS ===
    info(f"{C.BOLD}{C.BLUE}[7/8] Validando URLs ativas...{C.END}")
    valid_urls = validate_urls(urls_file, urls_ok)

    # === ETAPA 7.5: ADVANCED CRAWLING (Katana + GoSpider) ===
    import shutil as _shutil
    katana_bin = _shutil.which("katana")
    gospider_bin = _shutil.which("gospider")
    katana_out = outdir / "katana_valid.txt"
    discovered_file = outdir / "discovered_urls.txt"
    
    if (katana_bin or gospider_bin) and urls_ok.exists():
        info(f"{C.BOLD}{C.BLUE}[7.5/8] Advanced Crawling (Katana/GoSpider)...{C.END}")
        
        initial_urls = set(l.strip() for l in urls_ok.read_text().splitlines() if l.strip())
        all_discovered = set()
        all_valid = set(initial_urls)
        
        max_rounds = 2
        current_urls = initial_urls
        
        for round_num in range(1, max_rounds + 1):
            if not current_urls:
                break
            info(f"   Round {round_num}/{max_rounds} ({len(current_urls)} URLs)...")
            
            round_input = outdir / f"crawl_round_{round_num}.txt"
            round_input.write_text("\n".join(current_urls))
            round_discovered = set()
            
            # --- Katana ---
            if katana_bin:
                katana_raw = outdir / f"katana_raw_r{round_num}.txt"
                try:
                    katana_cmd = [
                        katana_bin,
                        "-list", str(round_input),
                        "-d", "2",
                        "-jc",                    # JS crawling
                        "-kf", "all",             # known files
                        "-ef", "css,png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot",
                        "-silent",
                        "-timeout", "20",
                        "-rate-limit", "50",
                        "-o", str(katana_raw),
                    ]
                    subprocess.run(katana_cmd, capture_output=True, text=True, timeout=10800)
                    if katana_raw.exists():
                        from core.config import is_in_scope
                        urls = set(l.strip() for l in katana_raw.read_text(errors="ignore").splitlines() if l.strip() and is_in_scope(l.strip(), target))
                        round_discovered.update(urls)
                        info(f"   Katana R{round_num}: {len(urls)} URLs brutas (In-Scope)")
                except subprocess.TimeoutExpired:
                    warn(f"   Katana R{round_num}: timeout atingido (3h)")
                except Exception as e:
                    warn(f"   Katana R{round_num}: {e}")
            
            # --- GoSpider (só no round 1) ---
            if gospider_bin and round_num == 1:
                gospider_dir = outdir / "gospider_out"
                gospider_dir.mkdir(exist_ok=True)
                try:
                    gs_cmd = [
                        gospider_bin,
                        "-S", str(round_input),
                        "-o", str(gospider_dir),
                        "-c", "10", "-d", "2",
                        "--other-source", "--include-subs", "-q",
                    ]
                    subprocess.run(gs_cmd, capture_output=True, text=True, timeout=10800)
                    import re as _gs_re
                    from core.config import is_in_scope
                    url_pattern = _gs_re.compile(r'https?://[^\s\]"\'><]+')
                    for out_file in gospider_dir.glob("*"):
                        if out_file.is_file():
                            try:
                                for line in out_file.read_text(errors="ignore").splitlines():
                                    for found_url in url_pattern.findall(line):
                                        if is_in_scope(found_url, target):
                                            round_discovered.add(found_url)
                            except Exception:
                                pass
                    info(f"   GoSpider: {len(round_discovered)} URLs combinadas (In-Scope)")
                except subprocess.TimeoutExpired:
                    warn(f"   GoSpider: timeout atingido (3h)")
                except Exception as e:
                    warn(f"   GoSpider: {e}")
            
            all_discovered.update(round_discovered)
            
            # Filtrar novas URLs do domínio alvo
            from urllib.parse import urlparse as _crawl_urlparse
            potential_new = round_discovered - all_valid
            domain_new = set()
            for u in potential_new:
                try:
                    h = _crawl_urlparse(u).netloc.split(":")[0]
                    if h.endswith(target) or target.endswith(h):
                        domain_new.add(u)
                except Exception:
                    pass
            
            if not domain_new:
                info(f"   Round {round_num}: sem URLs novas do domínio")
                break
            
            # Validar novas com httpx
            from .utils import require_binary
            httpx_bin = require_binary("httpx")
            validate_in = outdir / f"crawl_validate_r{round_num}.txt"
            validate_out = outdir / f"crawl_valid_r{round_num}.txt"
            validate_in.write_text("\n".join(domain_new))
            try:
                httpx_cmd = [
                    httpx_bin,
                    "-l", str(validate_in),
                    "-mc", "200,301,302,307,308,401,403",
                    "-threads", "30", "-timeout", "10",
                    "-silent", "-no-color", "-follow-redirects",
                    "-o", str(validate_out),
                ]
                subprocess.run(httpx_cmd, capture_output=True, text=True, timeout=120)
            except Exception:
                pass
            
            newly_valid = set()
            if validate_out.exists():
                newly_valid = set(l.strip() for l in validate_out.read_text().splitlines() if l.strip())
            
            if newly_valid:
                info(f"   ✅ Round {round_num}: +{len(newly_valid)} URLs válidas novas")
                all_valid.update(newly_valid)
                current_urls = newly_valid
            else:
                info(f"   Round {round_num}: 0 URLs novas validadas")
                break
        
        # Salvar katana_valid.txt (todas as URLs válidas do crawling)
        crawl_only = all_valid - initial_urls
        if crawl_only:
            katana_out.write_text("\n".join(sorted(crawl_only)) + "\n")
            success(f"   ✅ Crawling: {len(crawl_only)} URLs novas → katana_valid.txt")
        else:
            info(f"   Crawling: nenhuma URL nova além das iniciais")
        
        # Salvar discovered_urls.txt (tudo que foi encontrado, mesmo não validado)
        if all_discovered:
            discovered_file.write_text("\n".join(sorted(all_discovered)) + "\n")
            info(f"   📄 {len(all_discovered)} URLs brutas → discovered_urls.txt")
    else:
        if not katana_bin and not gospider_bin:
            warn(f"   ⚠️ Katana/GoSpider não instalados — crawling avançado desativado")

    # === ETAPA 6: DEEP ANALYSIS (ASYNC) ===
    
    # Arquivos de saida
    extracted_js_file = outdir / "extracted_js.json"
    extracted_keys_file = outdir / "extracted_keys.json"
    extracted_routes_file = outdir / "extracted_routes.json"
    technologies_file = outdir / "technologies.json"
    login_pages_file = outdir / "login_pages.txt"
    
    # Bug Bounty 2026 output files
    swagger_file = outdir / "swagger_docs.json"
    git_file = outdir / "git_exposed.json"
    hidden_params_file = outdir / "hidden_params.json" # Domain local copy
    logic_flaws_file = outdir / "logic_flaws.json" # Domain local copy

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
        
        all_swagger = []
        all_git = []
        all_hidden_params = []
        all_logic_flaws = []
        
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
                    
            # Bug Bounty 2026 data
            all_swagger.extend(res.get("swagger_docs", []))
            all_git.extend(res.get("git_exposed", []))
            all_hidden_params.extend(res.get("hidden_params", []))
            all_logic_flaws.extend(res.get("logic_flaws", []))

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
            
        # SWAGGER DOCS
        if all_swagger:
            with open(swagger_file, "w") as f:
                json.dump(all_swagger, f, indent=2, ensure_ascii=False)
            info(f"   + {len(all_swagger)} docs Swagger identificados.")
            
        # GIT TIME MACHINE
        if all_git:
            with open(git_file, "w") as f:
                json.dump(all_git, f, indent=2, ensure_ascii=False)
            info(f"   + {len(all_git)} diretorios de repositório CI/CD expostos encontrados!")
            
        # HIDDEN PARAMS e LOGIC
        if all_hidden_params:
            # Note: The paramfuzz module could also output this. We store it locally in domain first.
            # E garantimos diretório se ele salvar alhures.
            h_dir = Path("output") / target / "paramfuzz"
            h_dir.mkdir(parents=True, exist_ok=True)
            with open(h_dir / "hidden_params.json", "w") as f:
                json.dump(all_hidden_params, f, indent=2, ensure_ascii=False)
            info(f"   + {len(all_hidden_params)} parâmteros escondidos injetados com sucesso.")
            
        if all_logic_flaws:
            l_dir = Path("output") / target / "scanners"
            l_dir.mkdir(parents=True, exist_ok=True)
            with open(l_dir / "logic_flaws.json", "w") as f:
                json.dump(all_logic_flaws, f, indent=2, ensure_ascii=False)
            info(f"   + {len(all_logic_flaws)} falhas logicas achadas (CORS/Cache)!")

    except ImportError:
        error("Biblioteca 'httpx' não instalada. Instale com: pip install httpx")
    except Exception as e:
        import traceback
        error(f"Erro durante Deep Analysis: {e}")
        traceback.print_exc()

    # === ETAPA 8: FILTER INACTIVE SUBDOMAINS ===
    info(f"\\n{C.BOLD}{C.BLUE}[8/8] Filtrando subdominios inativos...{C.END}")
    active_hosts = set()
    for u in valid_urls:
        active_hosts.add(get_subdomain(u))
        
    if ports_final.exists():
        for line in ports_final.read_text(errors="ignore").splitlines():
            host = line.split(":")[0].strip()
            if host: active_hosts.add(host)
            
    if subs_file.exists():
        raw_subs = [s.strip() for s in subs_file.read_text(errors="ignore").splitlines() if s.strip()]
        
        # Save ALL subdomains so the report can show Inactive ones
        all_subs_file = outdir / "subdomains_all.txt"
        all_subs_file.write_text("\n".join(raw_subs) + "\n")
        
        alive_subs = [s for s in raw_subs if s in active_hosts]
        subs_file.write_text("\n".join(alive_subs) + "\n")
        info(f"   [!] Filtrado de {len(raw_subs)} para {len(alive_subs)} ativos (com ports/web). Backup salvo em subdomains_all.txt")

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
