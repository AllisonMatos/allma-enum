from pathlib import Path
import json

from menu import C
from ..output import info, success, warn, error
from .utils import ensure_outdir
from .subfinder import run_subfinder
from .naabu import run_naabu
from .ports import organize_ports
from .urls import build_urls
from .validator import validate_urls, validate_urls_detailed
from core.crawlers import fetch_page_with_info
from plugins.extractors import (
    extract_keys, 
    extract_js, 
    extract_routes,
    extract_inline_scripts,
    analyze_page
)


def run(context):
    """
    Fluxo principal do modulo DOMAIN.
    MELHORADO: Agora inclui Wappalyzer, extracao detalhada de keys/JS/routes com contexto.
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
    # Roda crawlers que descobrem novas URLs e as validam automaticamente
    try:
        from ..crawlers import run_crawlers
        info(f"{C.BOLD}{C.BLUE}[5.5/6] Advanced Crawling (Katana/Gospider)...{C.END}")
        # Passa arquivo de URLs válidas para crawling
        run_crawlers(urls_ok, outdir)
    except ImportError as e:
        warn(f"Modulo de crawlers nao encontrado: {e}")
    except Exception as e:
        error(f"Erro ao executar crawlers: {e}")

    # === ETAPA 6: DEEP ANALYSIS ===
    info(f"{C.BOLD}{C.BLUE}[6/6] Deep Analysis (Keys, JS, Routes, Technologies)...{C.END}")

    # Arquivos de saida
    extracted_js_file = outdir / "extracted_js.json"
    extracted_keys_file = outdir / "extracted_keys.json"
    extracted_routes_file = outdir / "extracted_routes.json"
    technologies_file = outdir / "technologies.json"
    login_pages_file = outdir / "login_pages.txt"

    all_js = []
    all_keys = []
    all_routes = []
    all_technologies = {}
    login_pages = []

    try:
        total = len(valid_urls)
        
        for idx, url in enumerate(valid_urls, 1):
            print(f"   [{idx}/{total}] Analyzing: {url[:60]}...", end="\r")
            
            # Fazer request com info detalhada
            response = fetch_page_with_info(url)
            
            if not response["success"]:
                continue
                
            content = response["content"]
            headers = response["headers"]
            final_url = response["final_url"]
            
            # === DETECT LOGIN PAGES ===
            login_keywords = ["login", "signin", "auth", "logon", "sso"]
            url_lower = final_url.lower()
            content_lower = content[:3000].lower() if content else ""
            
            is_login = False
            for kw in login_keywords:
                if kw in url_lower or (
                    kw in content_lower and 
                    ("password" in content_lower or "senha" in content_lower)
                ):
                    is_login = True
                    break
                    
            if is_login:
                login_pages.append(final_url)

            # === EXTRACT KEYS ===
            keys = extract_keys(content, source_url=final_url)
            for key in keys:
                key["subdomain"] = get_subdomain(final_url)
            all_keys.extend(keys)

            # === EXTRACT JS ===
            js_files = extract_js(content, final_url)
            for js in js_files:
                js["subdomain"] = get_subdomain(final_url)
            all_js.extend(js_files)
            
            # === EXTRACT INLINE SCRIPTS (for additional keys) ===
            inline_scripts = extract_inline_scripts(content, final_url)
            for script in inline_scripts:
                if script.get("has_config"):
                    inline_keys = extract_keys(
                        script["content"], 
                        source_url=final_url,
                        source_file="inline_script"
                    )
                    all_keys.extend(inline_keys)

            # === EXTRACT ROUTES ===
            routes = extract_routes(content, final_url)
            for route in routes:
                route["subdomain"] = get_subdomain(final_url)
            all_routes.extend(routes)

            # === DETECT TECHNOLOGIES ===
            tech_result = analyze_page(final_url, content, headers)
            subdomain = get_subdomain(final_url)
            
            if subdomain not in all_technologies:
                all_technologies[subdomain] = {
                    "url": final_url,
                    "technologies": []
                }
            
            # Merge technologies (evitar duplicatas)
            existing_names = {t["name"] for t in all_technologies[subdomain]["technologies"]}
            for tech in tech_result["technologies"]:
                if tech["name"] not in existing_names:
                    all_technologies[subdomain]["technologies"].append(tech)
                    existing_names.add(tech["name"])

        print("")  # Quebra de linha

        # === SALVAR RESULTADOS ===
        
        # JS
        if all_js:
            # Remover duplicatas por URL
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
            # Remover duplicatas por path
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
    """
    Extrai o subdominio/host de uma URL.
    """
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        return parsed.netloc.split(":")[0]  # Remove porta se existir
    except:
        return url
