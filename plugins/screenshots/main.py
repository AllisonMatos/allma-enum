#!/usr/bin/env python3
"""
plugins/screenshots/main.py — Screenshot automático de subdomínios (V2)
Usa Playwright assíncrono para renderizar SPAs, tirar screenshots, 
detectar tecnologias (Wappalyzer interno) e identificar páginas de login via DOM.
"""
import json
import asyncio
import re
from pathlib import Path

from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from core.config import is_in_scope

# Importamos a heurística de tech que agora tem Portainer
try:
    from plugins.extractors.wappalyzer import detect_technologies
except ImportError:
    detect_technologies = None

def get_subdomain(url: str) -> str:
    """Extrai o subdomínio/host de uma URL."""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        return parsed.netloc.split(":")[0]
    except:
        return url

# Tecnologias que SEMPRE indicam uma página/portal de autenticação
AUTH_TECH_NAMES = {"portainer", "keycloak", "verdaccio", "gitlab", "grafana", "jenkins", "sonarqube", "rancher", "harbor", "nexus"}

async def playwright_worker(url: str, screenshots_dir: Path, target: str, context_page):
    """
    Worker individual para analisar uma URL via Playwright.
    Retorna dict com url_original, url (final), screenshot, technologies, is_login, detected_app
    """
    original_url = url
    result = {
        "url": url,
        "url_original": original_url,
        "screenshot": None,
        "technologies": [],
        "is_login": False,
        "detected_app": None
    }
    
    try:
        # Navega para a página
        response = await context_page.goto(url, timeout=25000, wait_until="networkidle")
        if not response:
            return result

        # Espera extra para SPAs pesadas (Angular/React) renderizarem o DOM completo
        await context_page.wait_for_timeout(2500)
            
        # Pega a URL final real (pós-redirect)
        final_url = context_page.url
        result["url"] = final_url
        
        # Se houve redirect, preservar a original (importante para SSO como Keycloak)
        if final_url.rstrip("/") != original_url.rstrip("/"):
            result["url_original"] = original_url
        
        # Tirar screenshot full page
        safe_name = re.sub(r'[^a-zA-Z0-9_\-]', '_', original_url.replace("https://", "").replace("http://", ""))
        screenshot_path = screenshots_dir / f"{safe_name}.png"
        
        await context_page.screenshot(path=str(screenshot_path), full_page=True, timeout=15000)
        result["screenshot"] = str(screenshot_path)
        
        # Extrair DOM vivo
        html = await context_page.content()
        headers = response.headers
        
        # Detecção de Tecnologia no HTML vivo
        tech_names_lower = set()
        if detect_technologies:
            techs = detect_technologies(html=html, headers=headers, cookies=[], scripts=[], url=final_url)
            result["technologies"] = techs
            tech_names_lower = {t["name"].lower() for t in techs}
            
        # ── Forçar login se tecnologia é um portal de autenticação conhecido ──
        matched_auth_tech = AUTH_TECH_NAMES & tech_names_lower
        if matched_auth_tech:
            result["is_login"] = True
            result["detected_app"] = ", ".join(sorted(t.title() for t in matched_auth_tech))
            
        # ── Detecção Semântica de Login no DOM renderizado ──
        html_lower = html.lower()
        
        # 1. Input de senha visível
        has_password = bool(re.search(
            r'<input[^>]*type\s*=\s*["\']password["\']|'
            r'<input[^>]*name\s*=\s*["\'](password|passwd|pwd|pass|senha)["\']', 
            html_lower
        ))
        
        # 2. Formulário de autenticação
        has_auth_form = bool(re.search(
            r'<form[^>]*(?:login|signin|auth|log-in|sign-in|entrar)[^>]*>|'
            r'<form[^>]*action\s*=\s*["\'][^"\']*(?:login|auth|signin|session|token)[^"\']*["\']',
            html_lower
        ))
        
        # 3. URL contém keyword de autenticação
        url_lower = final_url.lower()
        url_has_auth = bool(re.search(r'\b(login|signin|sign-in|sso|auth|account|entrar|acesso)\b', url_lower))
        
        # 4. Buscar TODOS os botões e links com texto de login (não só o primeiro)
        has_login_button = False
        login_texts = {'login', 'sign in', 'entrar', 'acessar', 'log in', 'autenticar', 'iniciar sessão', 'conectar'}
        
        # Busca em <button>, <a>, <input type="submit">
        for tag_match in re.finditer(r'<(?:button|a)[^>]*>(.*?)</(?:button|a)>', html_lower, re.DOTALL):
            # Remove tags internas (ícones, spans) para pegar texto puro
            inner_text = re.sub(r'<[^>]+>', '', tag_match.group(1)).strip()
            # Normalizar whitespace multilinha
            inner_text = ' '.join(inner_text.split())
            if any(inner_text == lt or inner_text.startswith(lt + ' ') or inner_text.startswith(lt + '\n') for lt in login_texts):
                has_login_button = True
                break
        
        # 5. Título da página contém keyword de login
        title = (await context_page.title()).lower()
        title_has_auth = bool(re.search(r'\b(login|sign.?in|entrar|autenticar|acesso)\b', title))
        
        # 6. HTTP 401 (Basic Auth / WWW-Authenticate)
        is_401 = response.status == 401
                
        if has_password or (url_has_auth and has_auth_form) or (has_login_button and (has_auth_form or url_has_auth or title_has_auth)) or (title_has_auth and has_auth_form) or is_401:
            result["is_login"] = True
            if is_401:
                result["detected_app"] = result.get("detected_app") or "Basic Auth (401)"

    except Exception as e:
        # Apenas log debug ou ignorar silenciosamente timeouts
        pass
        
    return result

async def run_playwright_screenshots(urls: list, outdir: Path, target: str):
    """
    Inicia o Playwright, varre a lista de URLs (max 3 abas por vez) e gera relatórios.
    """
    from playwright.async_api import async_playwright
    screenshots_dir = outdir / "images"
    screenshots_dir.mkdir(exist_ok=True)
    
    results = []
    
    async with async_playwright() as p:
        # Tenta lançar o browser, se não der, cai fora graciosamente
        try:
            browser = await p.chromium.launch(headless=True, args=['--no-sandbox', '--disable-dev-shm-usage'])
            context = await browser.new_context(ignore_https_errors=True, bypass_csp=True)
        except Exception as e:
            warn(f"⚠️ Playwright falhou ao iniciar o chromium: {e}")
            return []
            
        info(f"   📸 Playwright chromium iniciado ({len(urls)} URLs na fila).")
        
        # Semáforo para rodar no máximo 5 abas simultâneas
        sem = asyncio.Semaphore(5)
        
        async def bound_worker(url):
            async with sem:
                page = await context.new_page()
                # Interceptar Basic Auth nativo
                # Quando uma URL pede basic auth, ela acusa como dialog ou joga HTTP 401
                # Mas para não ficar travado no prompt de Basic Auth, auto-rejeitamos dialogs.
                page.on("dialog", lambda dialog: asyncio.create_task(dialog.dismiss()))
                
                # Vamos registrar um listener de resposta para ver se foi 401. 
                # Se for 401 puro na raiz, sabemos que é gateway de auth. (Tratado no layer urls/report).
                
                res = await playwright_worker(url, screenshots_dir, target, page)
                await page.close()
                return res

        tasks = [bound_worker(u) for u in urls]
        total = len(tasks)
        completed = 0
        
        for coro in asyncio.as_completed(tasks):
            r = await coro
            results.append(r)
            completed += 1
            if completed % 5 == 0:
                print(f"   [{completed}/{total}] processadas...", end="\r")
        print("") # nova linha
        
        await context.close()
        await browser.close()
        
    return results

def merge_technologies(target: str, results: list):
    """
    Mescla as tecnologias descobertas via Playwright no arquivo principal (domain/technologies.json).
    """
    base_dir = Path("output") / target / "domain"
    tech_file = base_dir / "technologies.json"
    
    if not tech_file.exists():
        all_techs = {}
    else:
        try:
            all_techs = json.loads(tech_file.read_text())
        except Exception:
            all_techs = {}
            
    added_count = 0
    for res in results:
        if not res.get("technologies"):
            continue
        sub = get_subdomain(res["url"])
        
        if sub not in all_techs:
            all_techs[sub] = {"url": res["url"], "technologies": []}
            
        existing = {t["name"] for t in all_techs[sub]["technologies"]}
        
        for t in res["technologies"]:
            if t["name"] not in existing:
                all_techs[sub]["technologies"].append(t)
                existing.add(t["name"])
                added_count += 1
                
    if added_count > 0:
        tech_file.write_text(json.dumps(all_techs, indent=2, ensure_ascii=False))
        info(f"   + {added_count} tecnologias detectadas e injetadas via Headless Browser.")

def merge_login_pages(target: str, results: list):
    """
    Adiciona as páginas de login descobertas ao domain/login_pages.txt.
    Inclui tanto a URL final quanto a URL original (pré-redirect SSO).
    """
    base_dir = Path("output") / target / "domain"
    login_file = base_dir / "login_pages.txt"
    
    final_logins = {}
    if login_file.exists():
        for l in login_file.read_text(errors="ignore").splitlines():
            clean = l.strip()
            if not clean: continue
            key = clean.lower().rstrip("/").replace("https://", "").replace("http://", "")
            final_logins[key] = clean
            
    added_count = 0
    for res in results:
        if not res.get("is_login"):
            continue
            
        urls_to_add = []
        if res.get("url"): urls_to_add.append(res["url"])
        if res.get("url_original") and res.get("url_original") != res.get("url"):
            urls_to_add.append(res["url_original"])
            
        for url in urls_to_add:
            clean = url.strip()
            if not clean: continue
            key = clean.lower().rstrip("/").replace("https://", "").replace("http://", "")
            
            if key not in final_logins:
                final_logins[key] = clean
                added_count += 1
            else:
                if clean.startswith("https://") and final_logins[key].startswith("http://"):
                    final_logins[key] = clean
                    added_count += 1
            
    if added_count > 0:
        login_file.write_text("\n".join(sorted(final_logins.values())) + "\n")
        info(f"   + {added_count} páginas de login semânticas integradas/atualizadas via DOM.")

def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   📸 {C.BOLD}{C.CYAN}SCREENSHOT & SPA INSPECTION (Playwright){C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    outdir = ensure_outdir(target, "screenshots")
    base = Path("output") / target

    from core.url_sources import primary_urls_txt_for_scan
    from core.config import is_in_scope
    from urllib.parse import urlparse

    scope_root = (context.get("scope_root") or target).strip()
    urls_file = primary_urls_txt_for_scan(target)
    
    candidate_urls = []
    if urls_file.exists():
        candidate_urls.extend(urls_file.read_text(errors="ignore").splitlines())
    else:
        urls_valid = base / "domain" / "urls_valid.txt"
        if urls_valid.exists():
            candidate_urls.extend(urls_valid.read_text(errors="ignore").splitlines())
            
    # Adicionar domínios ativos raiz
    subs_active = base / "domain" / "subdomains_active.txt"
    if subs_active.exists():
        for sub in subs_active.read_text(errors="ignore").splitlines():
            if sub.strip():
                candidate_urls.append(f"https://{sub.strip()}")
                candidate_urls.append(f"http://{sub.strip()}")

    if not candidate_urls:
        warn("⚠️ Nenhuma URL encontrada para screenshot.")
        return []

    # Dedup by host — preferir URLs raiz (/) sobre paths profundos para SPAs
    host_to_url = {}
    for line in candidate_urls:
        url = line.strip()
        if not url:
            continue
        if not is_in_scope(url, target, scope_root):
            continue
        parsed = urlparse(url)
        host = parsed.netloc
        path = parsed.path.rstrip("/")
        
        if host not in host_to_url:
            host_to_url[host] = url
        elif path in ("", "/") and urlparse(host_to_url[host]).path.rstrip("/") not in ("", "/"):
            # Substituir deep path por URL raiz (melhor para detecção de SPAs)
            host_to_url[host] = url
    
    # Preferir HTTPS sobre HTTP para o mesmo host
    final_hosts = {}
    for host, url in host_to_url.items():
        clean_host = host.split(":")[0]
        if clean_host not in final_hosts:
            final_hosts[clean_host] = url
        elif url.startswith("https://"):
            final_hosts[clean_host] = url
    
    unique_urls = list(final_hosts.values())

    if not unique_urls:
        warn("⚠️ Nenhuma URL única para screenshot.")
        return []

    unique_urls = unique_urls[:200]
    info(f"   📋 {len(unique_urls)} URLs únicas na fila para processamento.")

    try:
        results = asyncio.run(run_playwright_screenshots(unique_urls, outdir, target))
    except Exception as e:
        error(f"❌ Erro na execução do Playwright: {e}")
        results = []
        
    if results:
        # Merge de inteligência
        merge_technologies(target, results)
        merge_login_pages(target, results)
        
        # Criar JSON Index final
        screenshots = []
        for r in results:
            if r.get("screenshot"):
                screenshots.append({
                    "filename": Path(r["screenshot"]).name,
                    "path": r["screenshot"],
                    "url": r["url"]
                })
                
        index_file = outdir / "screenshots_index.json"
        index_file.write_text(json.dumps(screenshots, indent=2))
        success(f"   📸 {len(screenshots)} screenshots capturados!")
        return [str(index_file)]
    else:
        warn("   ⚠️ Nenhuma ação registrada.")
        return []

