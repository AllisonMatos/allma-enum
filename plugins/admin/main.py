"""
Admin Panel Discovery — Descobre painéis administrativos expostos.
Testa 80+ paths comuns em URLs válidas + portas alternativas.
"""
import json
import re
import shutil
from pathlib import Path
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

from menu import C
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
    "/.DS_Store", "/robots.txt", "/sitemap.xml",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
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


def ensure_outdir(target: str) -> Path:
    outdir = Path("output") / target / "admin"
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir


def check_admin_path(base_url: str, path: str) -> dict:
    """
    Testa um path de admin em uma URL base.
    Retorna dict com resultado ou None se não encontrado.
    """
    import httpx

    url = base_url.rstrip("/") + path
    try:
        with httpx.Client(timeout=8, verify=False, follow_redirects=True) as client:
            resp = client.get(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            })

            # Ignorar 404, 500, 502, 503
            if resp.status_code in (404, 500, 502, 503, 504):
                return None

            # Verificar se é página real (não redirect genérico para home)
            final_url = str(resp.url)
            content = resp.text[:5000] if resp.text else ""
            content_lower = content.lower()

            # Detectar título
            title = ""
            title_match = re.search(r"<title>(.*?)</title>", content, re.I | re.S)
            if title_match:
                title = title_match.group(1).strip()[:100]

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
            # (tem título, ou tem form, ou é JSON, ou status code específico)
            is_interesting = (
                has_login or
                cms or
                resp.status_code in (200, 401, 403) or
                "login" in content_lower or
                "admin" in content_lower or
                "dashboard" in content_lower or
                resp.headers.get("content-type", "").startswith("application/json")
            )

            if is_interesting:
                return {
                    "url": final_url,
                    "path": path,
                    "status": resp.status_code,
                    "title": title,
                    "cms": cms,
                    "has_login_form": has_login,
                    "response_size": len(content),
                    "content_type": resp.headers.get("content-type", ""),
                }

    except Exception:
        pass

    return None


def run(context: dict):
    """Executa descoberta de admin panels."""
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟥───────────────────────────────────────────────────────────🟥\n"
        f"   🔐 {C.BOLD}{C.CYAN}ADMIN PANEL DISCOVERY{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟥───────────────────────────────────────────────────────────🟥\n"
    )

    outdir = ensure_outdir(target)

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
    info(f"   🔍 Testando {len(ADMIN_PATHS)} paths em {len(extended_bases)} bases...")
    info(f"   ⏱️  Total de testes: ~{len(extended_bases) * len(ADMIN_PATHS)}")

    # Executar testes em paralelo
    found_panels = []
    seen_urls = set()  # Deduplicar em tempo real
    total_tasks = 0

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {}
        for base in extended_bases:
            for path in ADMIN_PATHS:
                future = executor.submit(check_admin_path, base, path)
                futures[future] = (base, path)
                total_tasks += 1

        done_count = 0
        for future in as_completed(futures):
            done_count += 1
            if done_count % 200 == 0:
                print(f"   [{done_count}/{total_tasks}] Tested... ({len(found_panels)} found)", end="\r")

            try:
                result = future.result()
                if result:
                    # Deduplicar pela URL final (muitas bases redirecionam pro mesmo lugar)
                    norm_url = result["url"].rstrip("/").lower()
                    if norm_url in seen_urls:
                        continue
                    seen_urls.add(norm_url)
                    
                    found_panels.append(result)
                    status_color = C.RED if result["status"] == 200 else C.YELLOW
                    login_icon = "🔑" if result["has_login_form"] else "📄"
                    cms_str = f" [{result['cms']}]" if result.get("cms") else ""
                    info(f"   {login_icon} {status_color}[{result['status']}]{C.END} {result['url']}{cms_str}")
            except Exception:
                pass

    print("")  # Newline

    # Já está deduplicado (seen_urls durante execução)
    unique_panels = found_panels

    # Salvar resultados
    if unique_panels:
        output_file = outdir / "admin_panels.json"
        output_file.write_text(json.dumps(unique_panels, indent=2, ensure_ascii=False))
        success(f"\n   🔐 {len(unique_panels)} admin panels encontrados!")
        success(f"   📂 Salvos em {output_file}")

        # Stats
        with_login = sum(1 for p in unique_panels if p["has_login_form"])
        cms_count = sum(1 for p in unique_panels if p.get("cms"))
        open_200 = sum(1 for p in unique_panels if p["status"] == 200)
        auth_required = sum(1 for p in unique_panels if p["status"] in (401, 403))

        info(f"   📊 Stats:")
        info(f"      Abertos (200): {C.RED}{open_200}{C.END}")
        info(f"      Auth required (401/403): {C.YELLOW}{auth_required}{C.END}")
        info(f"      Com form de login: {with_login}")
        info(f"      CMS detectado: {cms_count}")
    else:
        warn("   ⚠️ Nenhum admin panel encontrado.")

    return unique_panels
