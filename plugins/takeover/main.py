"""
Subdomain Takeover Detection — Detecta subdomínios vulneráveis a takeover.
Verifica CNAMEs apontando para serviços desativados (GitHub Pages, Heroku, S3, Azure, etc).
"""
from core.config import DEFAULT_USER_AGENT, REQUEST_DELAY
import json
import re
import dns.resolver
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from menu import C
from plugins import ensure_outdir
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
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
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
                    "User-Agent": DEFAULT_USER_AGENT
                })
                content = resp.text[:5000].lower()
                for fp in fingerprints:
                    if fp.lower() in content:
                        return True
        except Exception:
            pass
    return False


def verify_service_available(cname: str, service: str, subdomain: str) -> dict:
    """Verify if the service is actually claimable/available for takeover."""
    import httpx
    
    verification = {"verified": False, "verification_detail": "Could not verify"}
    
    try:
        if service == "GitHub Pages":
            # Check if GitHub Pages returns the specific error page
            with httpx.Client(timeout=8, verify=False, follow_redirects=True) as client:
                resp = client.get(f"https://{subdomain}")
                if "There isn't a GitHub Pages site here" in resp.text:
                    verification["verified"] = True
                    verification["verification_detail"] = "GitHub Pages site not found — available for takeover via GitHub repository"
                elif resp.status_code == 404:
                    verification["verified"] = True
                    verification["verification_detail"] = "Returns 404 — likely available for claim"
        
        elif service in ("AWS S3", "AWS S3 Website"):
            with httpx.Client(timeout=8, verify=False, follow_redirects=True) as client:
                resp = client.get(f"https://{subdomain}")
                if "NoSuchBucket" in resp.text:
                    verification["verified"] = True
                    verification["verification_detail"] = f"S3 bucket does not exist — create bucket '{cname.split('.')[0]}' to takeover"
                elif "AccessDenied" in resp.text:
                    verification["verified"] = False
                    verification["verification_detail"] = "Bucket exists but access denied — not vulnerable"
        
        elif service == "Heroku":
            with httpx.Client(timeout=8, verify=False, follow_redirects=True) as client:
                resp = client.get(f"https://{subdomain}")
                if "No such app" in resp.text or "no-such-app" in resp.text:
                    app_name = cname.replace(".herokuapp.com", "")
                    verification["verified"] = True
                    verification["verification_detail"] = f"Heroku app '{app_name}' does not exist — create to takeover"
        
        elif service == "Shopify":
            with httpx.Client(timeout=8, verify=False, follow_redirects=True) as client:
                resp = client.get(f"https://{subdomain}")
                if "Sorry, this shop is currently unavailable" in resp.text:
                    verification["verified"] = True
                    verification["verification_detail"] = "Shopify store not claimed — register to takeover"
        
        elif service in ("Azure", "Azure CloudApp", "Azure CDN"):
            with httpx.Client(timeout=8, verify=False, follow_redirects=True) as client:
                resp = client.get(f"https://{subdomain}")
                if resp.status_code == 404 or "not found" in resp.text.lower():
                    verification["verified"] = True
                    verification["verification_detail"] = f"Azure resource not found — register '{cname}' to takeover"
        
        elif service in ("Netlify", "Vercel", "Surge.sh", "Fly.io"):
            with httpx.Client(timeout=8, verify=False, follow_redirects=True) as client:
                resp = client.get(f"https://{subdomain}")
                if resp.status_code == 404:
                    verification["verified"] = True
                    verification["verification_detail"] = f"{service} site not found — claim domain on {service}"
        
        else:
            # Generic: if NXDOMAIN + fingerprint match, consider verified
            verification["verification_detail"] = "Fingerprint matched but manual verification recommended"
    
    except Exception as e:
        verification["verification_detail"] = f"Verification check failed: {str(e)[:100]}"
    
    return verification


def check_subdomain(subdomain: str, known_cnames: dict = None) -> dict | None:
    """Verifica se um subdomínio é vulnerável a takeover.
    V10.3: Usa known_cnames como fallback quando resolução live falha."""
    cname = resolve_cname(subdomain)
    
    # V10.3: Fallback para CNAMEs pré-resolvidos se resolução live falhar
    if not cname and known_cnames:
        cname = known_cnames.get(subdomain)
    
    if not cname:
        return None

    for pattern, service, fingerprints, severity in TAKEOVER_FINGERPRINTS:
        if re.search(pattern, cname, re.I):
            # Verificar NXDOMAIN ou fingerprint HTTP
            is_nxdomain = check_nxdomain(subdomain)
            has_fingerprint = check_http_fingerprint(subdomain, fingerprints)

            if is_nxdomain or has_fingerprint:
                # Verify if the service is actually available for claiming
                verification = verify_service_available(cname, service, subdomain)
                
                status = "VULNERABLE"
                if verification["verified"]:
                    status = "CONFIRMED"
                elif is_nxdomain:
                    status = "VULNERABLE"
                else:
                    status = "POTENTIAL"
                
                return {
                    "subdomain": subdomain,
                    "cname": cname,
                    "service": service,
                    "severity": severity,
                    "nxdomain": is_nxdomain,
                    "http_fingerprint": has_fingerprint,
                    "status": status,
                    "verified": verification["verified"],
                    "verification_detail": verification["verification_detail"],
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

    outdir = ensure_outdir(target, "takeover")

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
        futures = {executor.submit(check_subdomain, sub, known_cnames): sub for sub in subdomains}

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
    results_file = outdir / "takeover_results.json"
    results_file.write_text(json.dumps(all_findings, indent=2, ensure_ascii=False))

    if all_findings:
        confirmed = sum(1 for v in all_findings if v["status"] == "VULNERABLE")
        potential = sum(1 for v in all_findings if v["status"] == "POTENTIAL")
        success(f"\n   🏴‍☠️ {len(all_findings)} subdomínios vulneráveis a takeover!")
        info(f"   📊 Confirmados: {C.RED}{confirmed}{C.END} | Potenciais: {C.YELLOW}{potential}{C.END}")
    
    if all_findings:
        success(f"🔥 {len(all_findings)} potenciais takeovers encontrados!")
    else:
        success("✅ Nenhum takeover detectado")
    
    # V10.4: NS Delegation Takeover + MX Takeover
    info(f"   🌐 {C.CYAN}[V10.4] Testando NS Delegation e MX Takeover...{C.END}")
    try:
        import dns.resolver
        
        # NS Delegation Takeover: verificar se NS do domínio aponta para serviço desativado
        try:
            ns_records = dns.resolver.resolve(target, 'NS')
            for ns in ns_records:
                ns_host = str(ns).rstrip('.')
                # Verificar se o NS resolve
                try:
                    dns.resolver.resolve(ns_host, 'A')
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    all_findings.append({
                        "subdomain": target,
                        "type": "NS_DELEGATION_TAKEOVER",
                        "risk": "CRITICAL",
                        "details": f"NS '{ns_host}' não resolve (NXDOMAIN) — controlando este NS, um atacante pode controlar TODO o domínio!",
                        "ns_server": ns_host,
                    })
                    info(f"   🔴 {C.RED}NS Takeover: {ns_host} → NXDOMAIN{C.END}")
                except Exception:
                    pass
        except Exception:
            pass
        
        # MX Takeover: verificar se MX do domínio aponta para serviço desativado
        try:
            mx_records = dns.resolver.resolve(target, 'MX')
            for mx in mx_records:
                mx_host = str(mx.exchange).rstrip('.')
                try:
                    dns.resolver.resolve(mx_host, 'A')
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    all_findings.append({
                        "subdomain": target,
                        "type": "MX_TAKEOVER",
                        "risk": "HIGH",
                        "details": f"MX '{mx_host}' não resolve — atacante pode registrar e interceptar emails de {target}",
                        "mx_server": mx_host,
                    })
                    info(f"   🔴 {C.RED}MX Takeover: {mx_host} → NXDOMAIN{C.END}")
                except Exception:
                    pass
        except Exception:
            pass
    except ImportError:
        warn("   ⚠️ dnspython não instalado — NS/MX takeover check ignorado")
    
    # Re-salvar com achados extras
    results_file.write_text(json.dumps(all_findings, indent=2, ensure_ascii=False))
    
    return [str(results_file)]
