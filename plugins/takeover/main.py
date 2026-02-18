"""
Subdomain Takeover Detection — Detecta subdomínios vulneráveis a takeover.
Verifica CNAMEs apontando para serviços desativados (GitHub Pages, Heroku, S3, Azure, etc).
"""
import json
import re
import dns.resolver
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from menu import C
from ..output import info, success, warn, error

# ============================================================
# FINGERPRINTS DE SERVIÇOS VULNERÁVEIS A TAKEOVER
# ============================================================
TAKEOVER_FINGERPRINTS = [
    # (cname_pattern, service_name, response_fingerprint, severity)
    (r"\.github\.io$", "GitHub Pages", ["There isn't a GitHub Pages site here", "For root URLs"], "high"),
    (r"\.herokuapp\.com$", "Heroku", ["No such app", "no-such-app"], "high"),
    (r"\.s3\.amazonaws\.com$", "AWS S3", ["NoSuchBucket", "The specified bucket does not exist"], "critical"),
    (r"\.s3-website[.-].*\.amazonaws\.com$", "AWS S3 Website", ["NoSuchBucket"], "critical"),
    (r"\.azurewebsites\.net$", "Azure", ["Error 404 - Web app not found"], "high"),
    (r"\.cloudapp\.net$", "Azure CloudApp", ["not found", "404"], "high"),
    (r"\.azureedge\.net$", "Azure CDN", ["400 - Bad Request", "Our services aren"], "medium"),
    (r"\.trafficmanager\.net$", "Azure Traffic Manager", ["404 - Not found"], "high"),
    (r"\.blob\.core\.windows\.net$", "Azure Blob", ["BlobNotFound", "The specified blob does not exist"], "critical"),
    (r"\.shopify\.com$", "Shopify", ["Sorry, this shop is currently unavailable", "Only one step left"], "high"),
    (r"\.myshopify\.com$", "Shopify", ["Sorry, this shop is currently unavailable"], "high"),
    (r"\.ghost\.io$", "Ghost", ["The thing you were looking for is no longer here"], "high"),
    (r"\.pantheonsite\.io$", "Pantheon", ["The gods have no such site", "404 error unknown site"], "high"),
    (r"\.tumblr\.com$", "Tumblr", ["There's nothing here", "Whatever you were looking for"], "high"),
    (r"\.wordpress\.com$", "WordPress.com", ["Do you want to register"], "medium"),
    (r"\.wpengine\.com$", "WP Engine", ["The site you were looking for couldn't be found"], "high"),
    (r"\.zendesk\.com$", "Zendesk", ["Help Center Closed", "this help center no longer exists"], "high"),
    (r"\.helpscoutdocs\.com$", "HelpScout", ["No settings were found for this company"], "high"),
    (r"\.helpjuice\.com$", "Helpjuice", ["We could not find what you're looking for"], "high"),
    (r"\.freshdesk\.com$", "Freshdesk", ["is not found", "There is no helpdesk here"], "high"),
    (r"\.surge\.sh$", "Surge.sh", ["project not found"], "high"),
    (r"\.bitbucket\.io$", "Bitbucket", ["Repository not found"], "high"),
    (r"\.netlify\.app$", "Netlify", ["Not Found - Request ID"], "high"),
    (r"\.netlify\.com$", "Netlify", ["Not Found - Request ID"], "high"),
    (r"\.fly\.dev$", "Fly.io", ["404 Not Found"], "medium"),
    (r"\.vercel\.app$", "Vercel", ["NOT_FOUND"], "high"),
    (r"\.now\.sh$", "Vercel (Now)", ["NOT_FOUND"], "high"),
    (r"\.firebaseapp\.com$", "Firebase", ["not found", "404"], "medium"),
    (r"\.web\.app$", "Firebase", ["not found"], "medium"),
    (r"\.aha\.io$", "Aha!", ["There is no portal here"], "high"),
    (r"\.tictail\.com$", "Tictail", ["Building a brand of your own"], "high"),
    (r"\.cargocollective\.com$", "Cargo", ["404 Not Found"], "high"),
    (r"\.feedpress\.me$", "Feedpress", ["The feed has not been found"], "high"),
    (r"\.unbounce\.com$", "Unbounce", ["The requested URL was not found"], "high"),
    (r"\.launchrock\.com$", "LaunchRock", ["It looks like you may have taken a wrong turn"], "high"),
    (r"\.ngrok\.io$", "Ngrok", ["Tunnel.*not found", "ERR_NGROK"], "medium"),
    (r"\.readthedocs\.io$", "ReadTheDocs", ["is unknown to Read the Docs"], "high"),
    (r"\.kinsta\.cloud$", "Kinsta", ["No site with that domain", "404"], "high"),
    (r"\.amazonaws\.com$", "AWS (generic)", ["NoSuchBucket", "AccessDenied"], "medium"),
]


def ensure_outdir(target: str) -> Path:
    outdir = Path("output") / target / "takeover"
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir


def resolve_cname(subdomain: str) -> str | None:
    """Resolve CNAME de um subdomínio."""
    try:
        answers = dns.resolver.resolve(subdomain, "CNAME")
        for rdata in answers:
            return str(rdata.target).rstrip(".")
    except Exception:
        pass
    return None


def check_nxdomain(subdomain: str) -> bool:
    """Verifica se o subdomínio retorna NXDOMAIN (não resolve A/AAAA)."""
    try:
        dns.resolver.resolve(subdomain, "A")
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except Exception:
        return False


def check_http_fingerprint(subdomain: str, fingerprints: list[str]) -> bool:
    """Verifica se a resposta HTTP contém fingerprints de takeover."""
    import httpx

    for scheme in ["https", "http"]:
        try:
            with httpx.Client(timeout=8, verify=False, follow_redirects=True) as client:
                resp = client.get(f"{scheme}://{subdomain}", headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                })
                content = resp.text[:5000].lower()
                for fp in fingerprints:
                    if fp.lower() in content:
                        return True
        except Exception:
            pass
    return False


def check_subdomain(subdomain: str) -> dict | None:
    """Verifica se um subdomínio é vulnerável a takeover."""
    cname = resolve_cname(subdomain)
    if not cname:
        return None

    for pattern, service, fingerprints, severity in TAKEOVER_FINGERPRINTS:
        if re.search(pattern, cname, re.I):
            # Verificar NXDOMAIN ou fingerprint HTTP
            is_nxdomain = check_nxdomain(subdomain)
            has_fingerprint = check_http_fingerprint(subdomain, fingerprints)

            if is_nxdomain or has_fingerprint:
                return {
                    "subdomain": subdomain,
                    "cname": cname,
                    "service": service,
                    "severity": severity,
                    "nxdomain": is_nxdomain,
                    "http_fingerprint": has_fingerprint,
                    "status": "VULNERABLE" if is_nxdomain else "POTENTIAL",
                }

    return None


def run(context: dict):
    """Executa detecção de subdomain takeover."""
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟥───────────────────────────────────────────────────────────🟥\n"
        f"   🏴‍☠️ {C.BOLD}{C.CYAN}SUBDOMAIN TAKEOVER DETECTION{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟥───────────────────────────────────────────────────────────🟥\n"
    )

    outdir = ensure_outdir(target)

    # Ler subdomínios
    subs_file = Path("output") / target / "domain" / "subdomains.txt"
    if not subs_file.exists():
        warn("⚠️ Nenhum subdomínio encontrado. Execute o módulo domain primeiro.")
        return []

    subdomains = [l.strip() for l in subs_file.read_text().splitlines() if l.strip()]
    info(f"   📋 Verificando {len(subdomains)} subdomínios...")

    # Tentar usar CNAMEs já resolvidos
    dns_file = Path("output") / target / "domain" / "dns_resolved.json"
    known_cnames = {}
    if dns_file.exists():
        try:
            dns_data = json.loads(dns_file.read_text())
            if isinstance(dns_data, list):
                for entry in dns_data:
                    host = entry.get("host", "")
                    for cname in entry.get("cnames", []):
                        known_cnames[host] = cname
            info(f"   📂 {len(known_cnames)} CNAMEs carregados do DNS resolver")
        except Exception:
            pass

    # Executar em paralelo
    vulnerable = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_subdomain, sub): sub for sub in subdomains}

        done = 0
        for future in as_completed(futures):
            done += 1
            if done % 10 == 0:
                print(f"   [{done}/{len(subdomains)}] Checked...", end="\r")

            try:
                result = future.result()
                if result:
                    vulnerable.append(result)
                    sev_color = C.RED if result["severity"] == "critical" else C.YELLOW
                    status = "🔴 VULNERABLE" if result["status"] == "VULNERABLE" else "🟡 POTENTIAL"
                    info(
                        f"   {status} {sev_color}[{result['severity'].upper()}]{C.END} "
                        f"{result['subdomain']} → {result['cname']} ({result['service']})"
                    )
            except Exception:
                pass

    print("")

    # Salvar
    output_file = outdir / "takeover_results.json"
    output_file.write_text(json.dumps(vulnerable, indent=2, ensure_ascii=False))

    if vulnerable:
        confirmed = sum(1 for v in vulnerable if v["status"] == "VULNERABLE")
        potential = sum(1 for v in vulnerable if v["status"] == "POTENTIAL")
        success(f"\n   🏴‍☠️ {len(vulnerable)} subdomínios vulneráveis a takeover!")
        info(f"   📊 Confirmados: {C.RED}{confirmed}{C.END} | Potenciais: {C.YELLOW}{potential}{C.END}")
        success(f"   📂 Salvos em {output_file}")
    else:
        info("   ✅ Nenhum subdomain takeover detectado.")

    return vulnerable
