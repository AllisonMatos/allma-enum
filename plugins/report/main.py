from plugins import ensure_outdir
#!/usr/bin/env python3
"""
Report Generator - SPA Dark Mode
Versao moderna com navegacao por abas e tema escuro profissional
"""

import re
import html
import json
import uuid
import base64
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
from ..output import info, success, warn, error


# ------------------------------------------------------------
# File Utilities
# ------------------------------------------------------------
def read_file_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    try:
        content = path.read_text(encoding='utf-8', errors='ignore')
        return [line.strip() for line in content.splitlines() if line.strip()]
    except Exception:
        return []


def read_file_raw(path: Path) -> str:
    if not path.exists():
        return ""
    try:
        return path.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return ""


def read_json_file(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding='utf-8', errors='ignore'))
    except Exception:
        return None


def find_file(base: Path, *relative_paths) -> Path:
    """
    Busca um arquivo em múltiplos locais relativos ao base path.
    Retorna o primeiro encontrado ou o último path se nenhum existir.
    
    Exemplo:
        find_file(base, "crawlers/file.json", "domain/crawlers/file.json", "domain/file.json")
    """
    for rel_path in relative_paths:
        full_path = base / rel_path
        if full_path.exists():
            return full_path
    # Retorna o primeiro path para manter compatibilidade com mensagens de erro
    return base / relative_paths[0] if relative_paths else base


# ------------------------------------------------------------
# Statistics Calculator
# ------------------------------------------------------------
def calculate_stats(target: str) -> Dict:
    base = Path("output") / target
    
    stats = {
        "subdomains": len(read_file_lines(base / "domain" / "subdomains.txt")),
        "urls_valid": len(read_file_lines(base / "domain" / "urls_valid.txt")),
        "ports_total": 0,
        "login_pages": len(read_file_lines(base / "domain" / "login_pages.txt")),
        "js_files": 0,
        "keys_found": 0,
        "routes_found": 0,
        "technologies": 0,
        "cloud_buckets": 0,
        "cve_vulns": 0,
        "endpoints_count": 0,
        "endpoints_count": 0,
        "xss_vulns": 0,
        "headers_count": 0,
        "takeover_count": 0,
        "waf_count": 0,
        "emails_count": 0,
        "js_routes_count": 0,
        "swagger_count": 0,
        "hidden_params_count": 0,
        "logic_flaws_count": 0,
        "git_exposed_count": 0,
        "cors_count": 0,
        "wordlist_count": 0
    }
    
    # Count ports
    ports_raw = read_file_lines(base / "domain" / "ports_raw.txt")
    stats["ports_total"] = len(ports_raw)
    
    # Count from JSON files
    js_data = read_json_file(base / "domain" / "extracted_js.json")
    if js_data:
        stats["js_files"] = len(js_data)
        
    keys_data = read_json_file(base / "domain" / "extracted_keys.json")
    if keys_data:
        stats["keys_found"] = len(keys_data)
        
    routes_data = read_json_file(base / "domain" / "extracted_routes.json")
    if routes_data:
        stats["routes_found"] = len(routes_data)
        
    tech_data = read_json_file(base / "domain" / "technologies.json")
    if tech_data:
        for host_data in tech_data.values():
            stats["technologies"] += len(host_data.get("technologies", []))
            
    # Cloud Buckets
    buckets_file = base / "cloud" / "buckets.txt"
    if buckets_file.exists():
        stats["cloud_buckets"] = len([l for l in buckets_file.read_text().splitlines() if l.strip()])

    # CVEs
    cve_file = base / "cve" / "potential_vulns.json"
    if cve_file.exists():
        try:
            cve_data = json.loads(cve_file.read_text())
            stats["cve_vulns"] = len(cve_data)
        except: pass
            
    # Endpoints (try JSON first, then txt fallback)
    endpoints_json = base / "endpoint" / "raw_endpoints.json"
    if endpoints_json.exists():
        try:
            stats["endpoints_count"] = len(json.loads(endpoints_json.read_text(errors="ignore")))
        except: pass
    
    endpoints_file = base / "endpoint" / "endpoints.txt"
    if endpoints_file.exists() and stats["endpoints_count"] == 0:
        stats["endpoints_count"] += len([l for l in endpoints_file.read_text(errors="ignore").splitlines() if l.strip()])
        
    kiterunner_json = base / "api_fuzzer" / "kiterunner_results.json"
    if kiterunner_json.exists():
        try:
            kdata = json.loads(kiterunner_json.read_text(errors="ignore"))
            stats["endpoints_count"] += len(kdata)
        except: pass
    
    # GraphQL
    graphql_json = base / "graphql" / "graphql.json"
    if graphql_json.exists():
        try:
            gql_data = json.loads(graphql_json.read_text(errors="ignore"))
            stats["graphql_count"] = len(gql_data)
        except: pass

    # XSS
    xss_file = base / "xss" / "final_report.txt"
    if xss_file.exists():
        content = xss_file.read_text(errors="ignore")
        # Parse Total findings line (e.g. 'Total findings: 10140')
        import re as _re
        m = _re.search(r'Total findings:\s*(\d+)', content)
        if m:
            stats["xss_vulns"] = int(m.group(1))
        elif "Vulnerable" in content or "[POC]" in content:
            stats["xss_vulns"] = content.count("[POC]") or 1
        elif content.strip():
            # File has content but no known markers, count non-empty lines as a rough heuristic
            stats["xss_vulns"] = len([l for l in content.splitlines() if l.strip()]) // 5 or 1
            
    # Headers (try JSON results first, then fingerprint fallback)
    headers_json = base / "headers" / "headers_results.json"
    if headers_json.exists():
        try:
            h_data = json.loads(headers_json.read_text(errors="ignore"))
            stats["headers_count"] = len(h_data)
        except: pass
    if stats["headers_count"] == 0:
        headers_file = base / "fingerprint" / "headers.txt"
        if headers_file.exists():
            try:
                 h_data = json.loads(headers_file.read_text(errors="ignore"))
                 stats["headers_count"] = len(h_data)
            except: pass

    # CRLF
    crlf_file = base / "crlf_injection" / "crlf_results.json"
    if crlf_file.exists():
        try:
            stats["crlf_count"] = len(json.loads(crlf_file.read_text()))
        except: pass

    # Deserialization
    deser_file = base / "insecure_deserialization" / "deser_results.json"
    if deser_file.exists():
        try:
            stats["deser_count"] = len(json.loads(deser_file.read_text()))
        except: pass

    # Takeover
    takeover_file = base / "takeover" / "takeover_results.json"
    if takeover_file.exists():
        try:
            stats["takeover_count"] = len(json.loads(takeover_file.read_text()))
        except: pass

    # WAF
    waf_file = base / "waf" / "waf_results.json"
    if waf_file.exists():
        try:
            stats["waf_count"] = len(json.loads(waf_file.read_text()))
        except: pass

    # Emails
    emails_file = base / "emails" / "emails.json"
    if emails_file.exists():
        try:
            stats["emails_count"] = json.loads(emails_file.read_text()).get("total", 0)
        except: pass

    # CORS
    cors_file = base / "cors" / "cors_results.json"
    if cors_file.exists():
        try:
            stats["cors_count"] = len(json.loads(cors_file.read_text()))
        except: pass


    # ParamFuzz
    paramfuzz_file = base / "paramfuzz" / "findings.json"
    if paramfuzz_file.exists():
        try:
            stats["paramfuzz_count"] = len(json.loads(paramfuzz_file.read_text()))
        except: pass

    # SourceMaps
    sourcemaps_file = base / "sourcemaps" / "secrets.json"
    if sourcemaps_file.exists():
        try:
            stats["sourcemaps_count"] = len(json.loads(sourcemaps_file.read_text()))
        except: pass

    # JS Routes (try multiple possible paths)
    for js_routes_path in [
        base / "domain" / "extracted_js_routes.json",
        base / "domain" / "extracted_routes.json",
    ]:
        if js_routes_path.exists() and stats.get("js_routes_count", 0) == 0:
            try:
                data = json.loads(js_routes_path.read_text())
                stats["js_routes_count"] = len(data) if isinstance(data, list) else sum(len(v) if isinstance(v, list) else 1 for v in data.values()) if isinstance(data, dict) else 0
            except: pass

    # URLs combined (count from multiple sources)
    urls_200 = base / "urls" / "urls_200.txt"
    if urls_200.exists():
        stats["urls_200_count"] = len([l for l in urls_200.read_text(errors="ignore").splitlines() if l.strip()])

    # Swagger
    swagger_file = base / "domain" / "swagger_docs.json"
    if swagger_file.exists():
        try:
            stats["swagger_count"] = len(json.loads(swagger_file.read_text()))
        except: pass

    # Hidden Params
    hidden_params_file = base / "paramfuzz" / "hidden_params.json"
    if hidden_params_file.exists():
        try:
            stats["hidden_params_count"] = len(json.loads(hidden_params_file.read_text()))
        except: pass

    # Logic Flaws
    logic_flaws_file = base / "scanners" / "logic_flaws.json"
    if logic_flaws_file.exists():
        try:
            stats["logic_flaws_count"] = len(json.loads(logic_flaws_file.read_text()))
        except: pass

    # Wordlists
    wordlist_file = base / "wordlist" / "combined.txt"
    if wordlist_file.exists():
        stats["wordlist_count"] = len([l for l in wordlist_file.read_text(errors="ignore").splitlines() if l.strip()])


    # Git Time Machine
    git_file = base / "domain" / "git_exposed.json"
    if git_file.exists():
        try:
            stats["git_exposed_count"] = len(json.loads(git_file.read_text()))
        except: pass

    # =============================================
    # V10.3: Contadores para plugins V10.2
    # =============================================
    v10_2_plugins = {
        "ssrf_count": ("ssrf", "ssrf_results.json"),
        "ssti_count": ("ssti", "ssti_results.json"),
        "xxe_count": ("xxe", "xxe_results.json"),
        "open_redirect_count": ("open_redirect", "open_redirect_results.json"),
        "host_injection_count": ("host_header_injection", "host_injection_results.json"),
        "proto_pollution_count": ("prototype_pollution", "prototype_pollution_results.json"),
        "oauth_count": ("oauth_misconfig", "oauth_misconfig_results.json"),
        "file_upload_count": ("file_upload", "file_upload_results.json"),
        "google_dorks_count": ("google_dorks", "dorks_results.json"),
        "api_versioning_count": ("api_versioning", "api_versioning_results.json"),
    }
    
    for stat_key, (plugin_dir, json_name) in v10_2_plugins.items():
        plugin_file = base / plugin_dir / json_name
        if plugin_file.exists():
            try:
                data = json.loads(plugin_file.read_text(errors="ignore"))
                stats[stat_key] = len(data) if isinstance(data, list) else 1
            except: pass
    
    # Email Security (dict, não lista)
    email_file = base / "email_security" / "email_security_results.json"
    if email_file.exists():
        try:
            data = json.loads(email_file.read_text(errors="ignore"))
            # Contar issues com risco alto ou crítico
            risks = [data.get(k, {}).get("risk", "INFO") for k in ["spf", "dmarc", "dkim", "bimi", "mta_sts", "tls_rpt"] if isinstance(data.get(k), dict)]
            stats["email_security_count"] = sum(1 for r in risks if r in ("HIGH", "CRITICAL", "MEDIUM"))
        except: pass

    return stats



# ------------------------------------------------------------
# Data Aggregators
# ------------------------------------------------------------
def aggregate_by_subdomain(target: str) -> Dict:
    """Agrupa todos os dados por subdominio."""
    base = Path("output") / target
    
    subdomains = {}
    
    # Load subdomains (trying to load subdomains_all.txt first to catch inactives, then fallback)
    subs_list_path = base / "domain" / "subdomains_all.txt"
    if not subs_list_path.exists():
        subs_list_path = base / "domain" / "subdomains.txt"
        
    for sub in read_file_lines(subs_list_path):
        subdomains[sub] = {
            "ports": [],
            "urls": [],
            "technologies": [],
            "is_login": False,
            "login_urls": set()
        }
    
    # Load ports
    for line in read_file_lines(base / "domain" / "ports_raw.txt"):
        if ":" in line:
            host, port = line.split(":", 1)
            port = port.split("/")[0]
            if host in subdomains:
                subdomains[host]["ports"].append(port)
            else:
                subdomains[host] = {"ports": [port], "urls": [], "technologies": [], "is_login": False, "login_urls": set()}
    
    # Load URLs
    for url in read_file_lines(base / "domain" / "urls_valid.txt"):
        try:
            from urllib.parse import urlparse
            host = urlparse(url).netloc.split(":")[0]
            if host in subdomains:
                subdomains[host]["urls"].append(url)
            else:
                subdomains[host] = {"ports": [], "urls": [url], "technologies": [], "is_login": False, "login_urls": set()}
        except:
            pass
    
    # Load technologies
    tech_data = read_json_file(base / "domain" / "technologies.json")
    if tech_data:
        for host, data in tech_data.items():
            if host in subdomains:
                subdomains[host]["technologies"] = data.get("technologies", [])
                
    # Load CVEs
    cve_data = read_json_file(base / "cve" / "potential_vulns.json")
    if cve_data:
        # CVE data is keyed by "tech version", not host directly. But we can match by tech name.
        # This is a simplification. Ideally, CVE plugin should output per-host or we cross-reference here.
        # Let's simple check if the host has the tech that has CVE.
        for host, host_data in subdomains.items():
            techs = host_data["technologies"]
            for tech in techs:
                name = tech["name"]
                version = tech.get("version")
                search_term = name + (f" {version}" if version else "")
                search_term_lower = search_term.lower()
                
                # Check exact match first
                tech["cve_exploits"] = []
                tech["cve_priority"] = "low"
                
                # Logic: prefer version match
                if version and search_term_lower in cve_data:
                    tech["cve_exploits"] = cve_data[search_term_lower]["exploits"]
                    tech["cve_priority"] = "high"
                # Fallback to generic name if no version match or no version
                elif name.lower() in cve_data:
                    tech["cve_exploits"] = cve_data[name.lower()]["exploits"]
                    # If we had a version but fell back, priority is ambiguous/medium? 
                    # If we had NO version, priority is low (generic).
                    if version:
                        tech["cve_priority"] = "medium" # Version present but partial match
                    else:
                        tech["cve_priority"] = "low" # Generic match

                tech["cve_count"] = len(tech["cve_exploits"])

    
    # Mark login pages (from explicit file OR heuristic)
    login_keywords = ["login", "signin", "auth", "portal", "admin", "entrar", "acesso"]
    
    # 1. From dedicated file
    for url in read_file_lines(base / "domain" / "login_pages.txt"):
        try:
            from urllib.parse import urlparse
            host = urlparse(url).netloc.split(":")[0]
            if host in subdomains:
                subdomains[host]["is_login"] = True
                subdomains[host]["login_urls"].add(url)
                if url not in subdomains[host]["urls"]:
                    subdomains[host]["urls"].append(url)
        except:
            pass
            
    # Load Intelligence Classifications
    intel_path = base / "intelligence" / "url_classification.json"
    intel_data = read_json_file(intel_path)
    url_tags = {}
    if intel_data:
        url_tags = {item["url"]: item["tags"] for item in intel_data}
        for host, host_data in subdomains.items():
            host_data["url_classifications"] = {}
            for url in host_data["urls"]:
                if url in url_tags:
                    host_data["url_classifications"][url] = url_tags[url]
    
    return subdomains


# ------------------------------------------------------------
# HTML Template - SPA Dark Mode
# ------------------------------------------------------------
HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enum-Allma Report: {target}</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --text-muted: #6e7681;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-red: #f85149;
            --accent-orange: #d29922;
            --accent-purple: #a371f7;
            --sidebar-width: 64px;
            --sidebar-width-expanded: 240px;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
            height: 100vh;
            display: flex;
            overflow: hidden;
        }}
        
        /* SIDEBAR */
        .sidebar {{
            width: var(--sidebar-width-expanded);
            background: var(--bg-secondary);
            border-right: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 12px 0;
            z-index: 1000;
            transition: width 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            overflow-x: hidden;
            overflow-y: auto;
            flex-shrink: 0;
        }}
        
        .sidebar {{
            align-items: stretch;
        }}
        
        .brand {{
            width: 50px;
            height: 50px;
            margin: 0 auto 20px;
            flex-shrink: 0;
            display: flex;
            align-items: center;
            justify-content: center;
        }}

        .brand svg {{
            width: 100%;
            height: 100%;
            transition: transform 0.3s ease;
            filter: drop-shadow(0 0 2px rgba(0,0,0,0.5));
        }}

        .brand:hover svg {{
            transform: scale(1.1) rotate(5deg);
        }}
        
        .nav-btn {{
            width: 100%;
            height: 48px;
            display: flex;
            align-items: center;
            background: transparent;
            border: none;
            color: var(--text-secondary);
            cursor: pointer;
            padding: 0;
            transition: all 0.2s;
            position: relative;
            text-decoration: none;
            white-space: nowrap;
        }}
        
        .nav-btn:hover, .nav-btn.active {{
            background: var(--bg-tertiary);
            color: var(--text-primary);
        }}
        
        .nav-btn.active:before {{
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 3px;
            background: var(--accent-blue);
        }}
        
        .nav-icon {{
            width: var(--sidebar-width);
            height: 48px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
            flex-shrink: 0;
        }}
        
        .nav-label {{
            padding-left: 10px;
            font-size: 14px;
            font-weight: 500;
            opacity: 1;
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex: 1;
            padding-right: 16px;
        }}
        
        
        
        .count {{
            background: var(--bg-primary);
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
            color: var(--text-muted);
            border: 1px solid var(--border-color);
        }}
        
        /* CONTENT AREA */
        .content-wrapper {{
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            position: relative;
        }}
        
        .top-bar {{
            height: 60px;
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 24px;
            flex-shrink: 0;
        }}
        
        .page-title h1 {{
            font-size: 18px;
            font-weight: 600;
            color: var(--text-primary);
            margin: 0;
        }}
        
        .page-title span {{
            color: var(--accent-blue);
        }}
        
        .meta-info {{
            font-size: 12px;
            color: var(--text-secondary);
            background: var(--bg-tertiary);
            padding: 4px 12px;
            border-radius: 20px;
            border: 1px solid var(--border-color);
        }}
        
        .main-content {{
            flex: 1;
            overflow-y: auto;
            padding: 24px;
            scroll-behavior: smooth;
        }}
        
        /* SECTIONS & CARDS */
        .section {{
            display: none;
            max-width: 1200px;
            margin: 0 auto;
            content-visibility: auto;
            contain-intrinsic-size: auto 500px;
        }}
        
        .section.active {{
            display: block;
            /* animation: fadeIn 0.3s ease; Removed for huge DOM performance */
        }}
        
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(10px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        
        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        
        .stat-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 16px;
            transition: transform 0.2s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-2px);
            border-color: var(--text-muted);
        }}
        
        .stat-card .value {{
            font-size: 28px;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 4px;
        }}
        
        .stat-card .label {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-secondary);
        }}
        
        /* TREE VIEW / SURFACE MAP */
        .tree {{
            list-style-type: none;
            padding-left: 10px;
        }}
        .tree ul {{
            list-style-type: none;
            padding-left: 20px;
            border-left: 1px dashed var(--border-color);
            margin-left: 5px;
        }}
        .tree li {{
            margin: 5px 0;
            position: relative;
        }}
        .tree li:before {{
            content: "";
            position: absolute;
            top: 12px;
            left: -20px;
            width: 15px;
            border-top: 1px dashed var(--border-color);
        }}
        .tree-folder {{
            font-weight: 600;
            color: var(--accent-blue);
            cursor: pointer;
        }}
        .tree-file {{
            color: var(--text-primary);
        }}
        .tree-tag {{
            font-size: 9px;
            background: var(--bg-tertiary);
            padding: 1px 4px;
            border-radius: 3px;
            margin-left: 5px;
            color: var(--text-muted);
        }}
        
        .stat-card.highlight {{ border-left: 3px solid var(--accent-blue); }}
        .stat-card.success {{ border-left: 3px solid var(--accent-green); }}
        .stat-card.warning {{ border-left: 3px solid var(--accent-orange); }}
        .stat-card.danger {{ border-left: 3px solid var(--accent-red); }}
        
        /* Cards */
        .card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            margin-bottom: 16px;
        }}
        
        .card-header {{
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            background: rgba(255,255,255,0.01);
        }}
        
        .card-header:hover {{
            background: var(--bg-tertiary);
        }}
        
        .card-title {{
            font-size: 14px;
            font-weight: 600;
            color: var(--text-primary);
        }}
        
        .section-title {{
            font-size: 16px;
            font-weight: 700;
            color: var(--text-primary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .card-badge {{
            font-size: 11px;
            padding: 2px 8px;
            border-radius: 10px;
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            border: 1px solid var(--border-color);
        }}
        
        .card-content {{
            padding: 16px;
            display: none;
            content-visibility: auto;
            contain-intrinsic-size: auto 200px;
        }}
        
        .card.open .card-content {{ display: block; }}
        
        .card-content pre {{
            background: var(--bg-primary);
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            font-size: 13px;
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            border: 1px solid var(--border-color);
        }}
        
        /* Tables */
        .table-wrapper {{ overflow-x: auto; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; table-layout: fixed; }}
        th {{
            text-align: left; padding: 12px;
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            font-weight: 600;
            border-bottom: 1px solid var(--border-color);
            white-space: nowrap;
        }}
        td {{ padding: 10px 12px; border-bottom: 1px solid var(--border-color); overflow-wrap: anywhere; word-break: break-word; }}
        tr:hover {{ background: rgba(255,255,255,0.03); }}
        a {{ color: var(--accent-blue); text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        
        /* Tags */
        .tag {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; margin-right: 4px; }}
        .tag-high {{ background: rgba(248, 81, 73, 0.15); color: #ff7b72; border: 1px solid rgba(248, 81, 73, 0.4); }}
        .tag-medium {{ background: rgba(210, 153, 34, 0.15); color: #d29922; border: 1px solid rgba(210, 153, 34, 0.4); }}
        .tag-low {{ background: rgba(63, 185, 80, 0.15); color: #3fb950; border: 1px solid rgba(63, 185, 80, 0.4); }}
        
        /* Scrollbar */
        ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
        ::-webkit-scrollbar-track {{ background: transparent; }}
        ::-webkit-scrollbar-thumb {{ background: var(--border-color); border-radius: 3px; }}
        ::-webkit-scrollbar-thumb:hover {{ background: var(--text-muted); }}
        
        .empty-state {{ text-align: center; padding: 40px; color: var(--text-muted); font-style: italic; }}
        /* Burp Modal */
        .burp-modal-overlay {{
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.7); z-index: 9999;
            display: none; align-items: center; justify-content: center;
            backdrop-filter: blur(2px);
        }}
        .burp-modal {{
            width: 90%; height: 85%; background: #1e1e1e;
            border: 1px solid #444; border-radius: 6px;
            display: flex; flex-direction: column;
            box-shadow: 0 20px 50px rgba(0,0,0,0.8);
            animation: slideIn 0.2s ease-out;
        }}
        @keyframes slideIn {{ from {{ transform: scale(0.95); opacity: 0; }} to {{ transform: scale(1); opacity: 1; }} }}
        
        .burp-header {{
            padding: 12px 15px; background: #323233; border-bottom: 1px solid #444;
            display: flex; justify-content: space-between; align-items: center;
        }}
        .burp-title {{
            color: #fff; font-weight: 600; font-family: system-ui, -apple-system, sans-serif;
            font-size: 14px; letter-spacing: 0.5px;
        }}
        .burp-title span {{ color: #858585; font-weight: normal; margin-left:10px; font-family: monospace;}}

        .burp-actions {{ display: flex; gap: 10px; }}
        .burp-btn {{
            background: #2d2d2d; border: 1px solid #444; color: #ccc;
            padding: 4px 10px; border-radius: 3px; cursor: pointer; font-size: 11px;
        }}
        .burp-btn:hover {{ background: #3e3e3e; color: #fff; }}
        .burp-close {{
            cursor: pointer; color: #aaa; font-size: 20px; line-height: 1; margin-left: 10px;
        }}
        .burp-close:hover {{ color: #fff; }}
        
        .burp-body {{
            flex: 1; display: flex; overflow: hidden;
        }}
        .burp-pane {{
            flex: 1; display: flex; flex-direction: column;
            border-right: 1px solid #444;
            min-width: 0;
        }}
        .burp-pane:last-child {{ border-right: none; }}
        .burp-pane-header {{
            background: #252526; padding: 6px 10px;
            color: #ccc; font-size: 11px; font-weight: 600; font-family: system-ui, sans-serif;
            border-bottom: 1px solid #444; text-transform: uppercase; letter-spacing: 0.5px;
            display: flex; justify-content: space-between;
        }}
        
        .burp-content {{
            flex: 1; padding: 15px; overflow: auto;
            background: #1e1e1e; color: #d4d4d4;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace; font-size: 12px;
            white-space: pre-wrap; word-break: break-all; line-height: 1.4;
        }}
        /* Syntax highlighting simulation */
        .http-method {{ color: #ebb626; font-weight: bold; }}
        .http-path {{ color: #a5d6ff; }}
        .http-version {{ color: #858585; }}
        .header-key {{ color: #9cdcfe; font-weight: bold; }}
        .header-val {{ color: #ce9178; }}
        .status-code {{ color: #b5cea8; font-weight: bold; }}
        
        /* Sidebar Categories */
        .sidebar-category {{
            padding: 15px 15px 5px 15px;
            color: #8b949e;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-family: system-ui, sans-serif;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            margin-bottom: 5px;
        }}
    </style>
    <script>const BURP_DATA = {{}};</script>
</head>
<body>
    <nav class="sidebar">
        <div class="brand">
            <!-- One Piece Inspired Straw Hat Skull - Monochrome -->
            <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
                <g fill="#e6edf3" stroke="#e6edf3" stroke-width="0">
                     <!-- Crossbones -->
                    <path d="M20,20 L80,80 L75,85 L15,25 Z" />
                    <path d="M80,20 L20,80 L25,85 L85,25 Z" />
                    <!-- Bone ends -->
                    <circle cx="18" cy="20" r="5" />
                    <circle cx="22" cy="16" r="5" />
                    <circle cx="82" cy="80" r="5" />
                    <circle cx="78" cy="84" r="5" />
                    
                    <circle cx="82" cy="20" r="5" />
                    <circle cx="78" cy="16" r="5" />
                    <circle cx="18" cy="80" r="5" />
                    <circle cx="22" cy="84" r="5" />
                </g>
                
                <!-- Skull Base -->
                <path d="M30 45 Q50 15 70 45 L70 65 Q70 75 50 75 Q30 75 30 65 Z" fill="#e6edf3"/>
                
                <!-- Hat -->
                <ellipse cx="50" cy="42" rx="35" ry="8" fill="#e6edf3" />
                <path d="M35 42 Q50 25 65 42" fill="#e6edf3" stroke="#161b22" stroke-width="2"/>
                
                <!-- Face Features (in background color to look like holes) -->
                <circle cx="42" cy="55" r="5" fill="#161b22"/>
                <circle cx="58" cy="55" r="5" fill="#161b22"/>
                <circle cx="50" cy="62" r="1.5" fill="#161b22"/>
                
                <!-- Teeth -->
                <path d="M40 70 L60 70 L60 75 L40 75 Z" fill="#161b22"/>
                <line x1="45" y1="70" x2="45" y2="75" stroke="#e6edf3" stroke-width="1"/>
                <line x1="50" y1="70" x2="50" y2="75" stroke="#e6edf3" stroke-width="1"/>
                <line x1="55" y1="70" x2="55" y2="75" stroke="#e6edf3" stroke-width="1"/>
            </svg>
        </div>
        
        <button class="nav-btn active" data-section="dashboard" data-always-show="true">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Dashboard</div>
        </button>
        <button class="nav-btn" data-section="quickwins_attack" data-always-show="true">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Quick Wins <span class="count">{stats_quickwins}</span></div>
        </button>

        <div class="sidebar-category">🌍 ASSETS & SURFACE</div>
        <button class="nav-btn" data-section="spiderfoot_sec" data-always-show="true">
            <div class="nav-icon">&#9679;</div><div class="nav-label">SpiderFoot <span class="count">{stats_spiderfoot}</span></div>
        </button>
        <button class="nav-btn" data-section="subdomains" data-always-show="true">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Subdomains <span class="count">{stats_subdomains}</span></div>
        </button>
        <button class="nav-btn" data-section="urls" data-always-show="true">
            <div class="nav-icon">&#9679;</div><div class="nav-label">URLs <span class="count">{stats_urls_combined}</span></div>
        </button>
        <button class="nav-btn" data-section="routes">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Endpoints <span class="count">{stats_endpoints}</span></div>
        </button>
        <button class="nav-btn" data-section="files">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Files</div>
        </button>
        <button class="nav-btn" data-section="params">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Params <span class="count">{stats_params}</span></div>
        </button>
        <button class="nav-btn" data-section="surfacemap">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Surface Map</div>
        </button>
        <button class="nav-btn" data-section="js">
            <div class="nav-icon">&#9679;</div><div class="nav-label">JS Files <span class="count">{stats_js}</span></div>
        </button>
        <button class="nav-btn" data-section="jsroutes">
            <div class="nav-icon">&#9679;</div><div class="nav-label">API & JS <span class="count">{stats_js_routes}</span></div>
        </button>
        <button class="nav-btn" data-section="sourcemaps">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Source Maps <span class="count">{stats_sourcemaps}</span></div>
        </button>

        <div class="sidebar-category">🔥 VULNERABILITIES</div>
        <button class="nav-btn" data-section="security">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Security <span class="count">{stats_xss}</span></div>
        </button>
        <button class="nav-btn" data-section="api_sec">
            <div class="nav-icon">&#9679;</div><div class="nav-label">API Security <span class="count">{stats_api_security}</span></div>
        </button>
        <button class="nav-btn" data-section="logic">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Logic & Smug. <span class="count">{stats_logic}</span></div>
        </button>
        <button class="nav-btn" data-section="takeover">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Takeover <span class="count">{stats_takeover}</span></div>
        </button>
        <button class="nav-btn" data-section="cve">
            <div class="nav-icon">&#9679;</div><div class="nav-label">CVEs <span class="count">{stats_cves}</span></div>
        </button>
        <button class="nav-btn" data-section="depconfusion">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Dep. Conf. <span class="count">{stats_depconfusion}</span></div>
        </button>
        <button class="nav-btn" data-section="ssrf_sec">
            <div class="nav-icon">&#9679;</div><div class="nav-label">SSRF <span class="count">{stats_ssrf}</span></div>
        </button>
        <button class="nav-btn" data-section="open_redirect_sec">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Open Redir <span class="count">{stats_open_redirect}</span></div>
        </button>
        <button class="nav-btn" data-section="crlf_sec">
            <div class="nav-icon">&#9679;</div><div class="nav-label">CRLF <span class="count">{stats_crlf}</span></div>
        </button>
        <button class="nav-btn" data-section="smuggling_sec">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Smuggling <span class="count">{stats_smuggling}</span></div>
        </button>
        <button class="nav-btn" data-section="deser_sec">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Deserial. <span class="count">{stats_deser}</span></div>
        </button>
        <button class="nav-btn" data-section="host_inj_sec">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Host Inj <span class="count">{stats_host_injection}</span></div>
        </button>
        <button class="nav-btn" data-section="ssti_sec">
            <div class="nav-icon">&#9679;</div><div class="nav-label">SSTI <span class="count">{stats_ssti}</span></div>
        </button>
        <button class="nav-btn" data-section="xxe_sec">
            <div class="nav-icon">&#9679;</div><div class="nav-label">XXE <span class="count">{stats_xxe}</span></div>
        </button>
        <button class="nav-btn" data-section="proto_sec">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Proto Poll <span class="count">{stats_proto_pollution}</span></div>
        </button>
        <button class="nav-btn" data-section="oauth_sec">
            <div class="nav-icon">&#9679;</div><div class="nav-label">OAuth <span class="count">{stats_oauth}</span></div>
        </button>
        <button class="nav-btn" data-section="api_ver_sec">
            <div class="nav-icon">&#9679;</div><div class="nav-label">API Ver <span class="count">{stats_api_versioning}</span></div>
        </button>
        <button class="nav-btn" data-section="file_upload_sec">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Upload <span class="count">{stats_file_upload}</span></div>
        </button>

        <div class="sidebar-category">⚙️ EXPOSURES</div>
        <button class="nav-btn" data-section="admin">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Admin Panels <span class="count">{stats_admin}</span></div>
        </button>
        <button class="nav-btn" data-section="keys">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Keys & Secrets <span class="count">{stats_keys}</span></div>
        </button>
        <button class="nav-btn" data-section="emails">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Emails <span class="count">{stats_emails}</span></div>
        </button>
        <button class="nav-btn" data-section="git">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Git Exposed <span class="count">{stats_git}</span></div>
        </button>
        <button class="nav-btn" data-section="cloud">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Cloud Storage <span class="count">{stats_buckets}</span></div>
        </button>
        <button class="nav-btn" data-section="graphql_scan">
            <div class="nav-icon">&#9679;</div><div class="nav-label">GraphQL <span class="count">{stats_graphql}</span></div>
        </button>
        <button class="nav-btn" data-section="swagger">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Swagger UI <span class="count">{stats_swagger}</span></div>
        </button>
        <button class="nav-btn" data-section="jwt_sec">
            <div class="nav-icon">&#9679;</div><div class="nav-label">JWT <span class="count">{stats_jwt}</span></div>
        </button>
        <button class="nav-btn" data-section="services">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Ports/Services <span class="count">{stats_ports}</span></div>
        </button>
        <button class="nav-btn" data-section="waf">
            <div class="nav-icon">&#9679;</div><div class="nav-label">WAF Detection <span class="count">{stats_waf}</span></div>
        </button>
        <button class="nav-btn" data-section="email_sec">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Email Sec</div>
        </button>
        <button class="nav-btn" data-section="oast_sec">
            <div class="nav-icon">&#9679;</div><div class="nav-label" style="color:#ff7b72">Blind Bugs <span class="count">{stats_oast}</span></div>
        </button>
        <button class="nav-btn" data-section="wordlist_sec">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Wordlists <span class="count">{stats_wordlist}</span></div>
        </button>
        <button class="nav-btn" data-section="dorks_sec">
            <div class="nav-icon">&#9679;</div><div class="nav-label">Dorks <span class="count">{stats_google_dorks}</span></div>
        </button>
    </nav>
    
    <div class="content-wrapper">
        <header class="top-bar">
            <div class="page-title">
                <h1>Enum-Allma: <span>{target}</span></h1>
            </div>
            <div class="meta-info">
                {date} &nbsp; {time}
            </div>
        </header>
        
        <main class="main-content">
            <!-- Dashboard -->
            <section class="section active" id="dashboard">
                <div class="stats-grid">
                    <div class="stat-card highlight">
                        <div class="value">{stats_subdomains}</div>
                        <div class="label">Subdomains</div>
                    </div>
                    <div class="stat-card success">
                        <div class="value">{stats_urls}</div>
                        <div class="label">Valid URLs</div>
                    </div>
                    <div class="stat-card danger">
                        <div class="value">{stats_xss}</div>
                        <div class="label">XSS Alerts</div>
                    </div>
                    <div class="stat-card warning">
                        <div class="value">{stats_login}</div>
                        <div class="label">Login Pages</div>
                    </div>
                    <div class="stat-card danger">
                        <div class="value">{stats_takeover}</div>
                        <div class="label">Takeover Risks</div>
                    </div>
                     <div class="stat-card danger">
                        <div class="value">{stats_keys}</div>
                        <div class="label">Keys Exposed</div>
                    </div>
                    <div class="stat-card warning">
                         <div class="value">{stats_waf}</div>
                        <div class="label">WAFs Detected</div>
                    </div>
                    <div class="stat-card">
                         <div class="value">{stats_emails}</div>
                        <div class="label">Emails</div>
                    </div>
                    <div class="stat-card orange" style="border-left: 3px solid var(--accent-orange);">
                         <div class="value">{stats_cors}</div>
                        <div class="label">CORS Issues</div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <span class="card-title section-title">Quick Summary</span>
                    </div>
                    <div class="card-content" style="display:block;">
                        <p>Scan completed for <strong>{target}</strong>. Found {stats_subdomains} subdomains with {stats_urls} valid URLs across {stats_ports} open ports.</p>
                        {login_warning}
                        {keys_warning}
                    </div>
                </div>

                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:20px; margin-top:20px;">
                    <div>{hvt_dashboard}</div>
                    <div class="card open" style="border-left: 4px solid var(--accent-blue);">
                         <div class="card-header">
                            <span class="card-title"> Dicas de Hacking (Recon Intelligence)</span>
                        </div>
                        <div class="card-content" style="display:block;">
                            <p style="margin-bottom:15px; color:#888;">Dicas práticas baseadas nas tecnologias detectadas no alvo.</p>
                            {knowledge_tips}
                        </div>
                    </div>
                </div>
            </section>


            
            <section class="section" id="subdomains">{subdomains_content}</section>
            <section class="section" id="security">{security_content}</section>

            <section class="section" id="services">{services_content}</section>
            <section class="section" id="urls">{urls_content}</section>
            <section class="section" id="keys">{keys_content}</section>
            <section class="section" id="routes">{routes_content}</section>
            <section class="section" id="js">{js_content}</section>
            <section class="section" id="params">{params_content}</section>

            <section class="section" id="jsroutes">{js_routes_content}</section>
            <section class="section" id="swagger">{swagger_content}</section>

            <section class="section" id="logic">{logic_content}</section>
            <section class="section" id="git">{git_content}</section>
            <section class="section" id="surfacemap">{surfacemap_content}</section>
            <section class="section" id="sourcemaps">{sourcemaps_content}</section>
            <section class="section" id="cloud">{cloud_content}</section>
            <section class="section" id="cve">{cve_content}</section>
            <section class="section" id="admin">{admin_content}</section>
            <section class="section" id="depconfusion">{depconfusion_content}</section>
            <section class="section" id="graphql_scan">{graphql_content}</section>
            <section class="section" id="api_sec">{api_security_content}</section>
            <section class="section" id="files">{files_content}</section>
            <section class="section" id="takeover">{takeover_content}</section>
            <section class="section" id="waf">{waf_content}</section>
            <section class="section" id="emails">{emails_content}</section>
            <section class="section" id="jwt_sec">{jwt_content}</section>
            <section class="section" id="crlf_sec">{crlf_content}</section>
            <section class="section" id="smuggling_sec">{smuggling_content}</section>
            <section class="section" id="deser_sec">{deser_content}</section>
            <section class="section" id="oast_sec">{oast_content}</section>
            <section class="section" id="wordlist_sec">{wordlist_content}</section>
            <section class="section" id="quickwins_attack">{quickwins_attack_content}</section>
            <section class="section" id="open_redirect_sec">{open_redirect_content}</section>
            <section class="section" id="host_inj_sec">{host_injection_content}</section>
            <section class="section" id="ssti_sec">{ssti_content}</section>
            <section class="section" id="xxe_sec">{xxe_content}</section>
            <section class="section" id="proto_sec">{proto_pollution_content}</section>
            <section class="section" id="oauth_sec">{oauth_content}</section>
            <section class="section" id="api_ver_sec">{api_versioning_content}</section>
            <section class="section" id="file_upload_sec">{file_upload_content}</section>
            <section class="section" id="email_sec">{email_security_content}</section>
            <section class="section" id="dorks_sec">{google_dorks_content}</section>
            <section class="section" id="spiderfoot_sec">{spiderfoot_content}</section>
            
             <footer style="text-align:center; color:var(--text-muted); font-size:12px; margin-top:40px; padding-bottom:20px;">
                Generated by Enum-Allma | {date} {time}
            </footer>
        </main>
    </div>

    <script>
        // Navigation Switcher
        document.querySelectorAll('.nav-btn').forEach(btn => {{
            btn.addEventListener('click', () => {{
                // Active state for buttons
                document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                
                // Show section
                const targetId = btn.dataset.section;
                document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
                const targetSection = document.getElementById(targetId);
                if (targetSection) targetSection.classList.add('active');
            }});
        }});
        
        // Card Expand/Collapse
        document.addEventListener('click', (e) => {{
            const header = e.target.closest('.card-header');
            if (header) {{
                header.parentElement.classList.toggle('open');
            }}
        }}, 0);
    </script>
    <!-- Burp Modal -->
    <div class="burp-modal-overlay" id="burpModal" onclick="if(event.target===this) closeBurp()">
        <div class="burp-modal">
            <div class="burp-header">
                <div class="burp-title">HTTP Request/Response <span id="burpUrl"></span></div>
                <div class="burp-actions">
                    <button class="burp-btn" onclick="copyReq()">Copy Request</button>
                    <button class="burp-btn" onclick="copyRes()">Copy Response</button>
                    <div class="burp-close" onclick="closeBurp()">×</div>
                </div>
            </div>
            <div id="burpInfo" style="display:none; padding:10px 15px; background:rgba(210,153,34,0.15); border-bottom:1px solid rgba(210,153,34,0.4); color:#d29922; font-size:13px; font-family:monospace; white-space:pre-wrap;"></div>
            <div class="burp-body">
                <div class="burp-pane">
                    <div class="burp-pane-header">Request</div>
                    <div class="burp-content" id="burpRequest"></div>
                </div>
                <div class="burp-pane">
                    <div class="burp-pane-header">Response</div>
                    <div class="burp-content" id="burpResponse"></div>
                </div>
            </div>
        </div>
    </div>

    <!-- Data Storage -->

    <script>

        
        function openBurp(id) {{
            const data = BURP_DATA[id];
            if (!data) return;
            
            document.getElementById('burpUrl').innerText = data.url;
            
            const infoEl = document.getElementById('burpInfo');
            if (data.info) {{
                infoEl.innerText = data.info;
                infoEl.style.display = 'block';
            }} else {{
                infoEl.style.display = 'none';
                infoEl.innerText = '';
            }}
            
            document.getElementById('burpRequest').innerHTML = highlightHttp(atob(data.req));
            document.getElementById('burpResponse').innerHTML = highlightHttp(atob(data.res));
            document.getElementById('burpModal').style.display = 'flex';
        }}
        
        function closeBurp() {{
            document.getElementById('burpModal').style.display = 'none';
        }}

        function highlightHttp(text) {{
            if (!text) return '<span style="color:#666">[No raw data captured]</span>';
            const parts = text.split('\\n\\n');
            let headers = parts[0];
            let body = parts.slice(1).join('\\n\\n');
            
            const lines = headers.split('\\n');
            let firstLine = lines.shift(); 
            
            if (firstLine.startsWith('HTTP/')) {{
                 firstLine = firstLine.replace(/^(HTTP\\/[\\d\\.]+)\\s+(\\d+)\\s+(.*)$/, 
                    '<span class="http-version">$1</span> <span class="status-code">$2</span> <span class="http-version">$3</span>');
            }} else {{
                 firstLine = firstLine.replace(/^([A-Z]+)\\s+(.*)\\s+(HTTP\\/[\\d\\.]+)$/,
                    '<span class="http-method">$1</span> <span class="http-path">$2</span> <span class="http-version">$3</span>');
            }}

            let coloredHeaders = lines.map(line => {{
                const idx = line.indexOf(':');
                if (idx > -1) {{
                    const key = line.substring(0, idx);
                    const val = line.substring(idx+1);
                    return `<span class="header-key">${{escapeHtml(key)}}</span>:<span class="header-val">${{escapeHtml(val)}}</span>`;
                }}
                return escapeHtml(line);
            }}).join('\\n');
            
            return `<div>${{firstLine}}\\n${{coloredHeaders}}</div>\\n\\n${{escapeHtml(body)}}`;
        }}
        
        function escapeHtml(text) {{
           if (!text) return '';
           return text
               .replace(/&/g, "&amp;")
               .replace(/</g, "&lt;")
               .replace(/>/g, "&gt;")
               .replace(/"/g, "&quot;")
               .replace(/'/g, "&#039;");
        }}
        
        function copyReq() {{
             const text = document.getElementById('burpRequest').innerText;
             navigator.clipboard.writeText(text);
        }}
         function copyRes() {{
             const text = document.getElementById('burpResponse').innerText;
             navigator.clipboard.writeText(text);
        }}

        document.addEventListener('keydown', function(event) {{
            if (event.key === "Escape") {{
                closeBurp();
            }}
        }});

        // --- Pagination Engine ---
        window.PAGINATION_DATA = {{}}; 
        
        function initPaginatedTable(tableId, data, cols, renderFn, pageSize=100) {{
            window.PAGINATION_DATA[tableId] = {{ data: data, cols: cols, page: 1, pageSize: pageSize, renderFn: renderFn }};
            renderPaginatedTable(tableId);
        }}

        function renderPaginatedTable(tableId) {{
            const tableData = window.PAGINATION_DATA[tableId];
            if (!tableData) return;
            
            const container = document.getElementById(tableId);
            if (!container) return;
            
            const data = tableData.data;
            const cols = tableData.cols;
            const page = tableData.page;
            const pageSize = tableData.pageSize;
            const renderFn = tableData.renderFn;
            
            const totalPages = Math.ceil(data.length / pageSize) || 1;
            const start = (page - 1) * pageSize;
            const end = start + pageSize;
            const pageData = data.slice(start, end);
            
            let tbodyRows = pageData.map(row => renderFn(row)).join('');
            
            let paginationHtml = '';
            if (totalPages > 1) {{
                paginationHtml = `
                <div style="margin-top: 15px; display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-color); padding-top: 10px;">
                    <div style="font-size: 12px; color: var(--text-secondary);">Showing ${{start + 1}} to ${{Math.min(end, data.length)}} of ${{data.length}} entries</div>
                    <div>
                        <button class="burp-btn" onclick="goToPage('${{tableId}}', ${{page - 1}})" ${{page === 1 ? 'disabled style="opacity:0.5;cursor:not-allowed;"' : ''}}>Previous</button>
                        <span style="margin: 0 10px; font-size: 13px;">Page ${{page}} of ${{totalPages}}</span>
                        <button class="burp-btn" onclick="goToPage('${{tableId}}', ${{page + 1}})" ${{page === totalPages ? 'disabled style="opacity:0.5;cursor:not-allowed;"' : ''}}>Next</button>
                    </div>
                </div>`;
            }}
            
            if (cols && cols.length > 0) {{
                let theadThs = cols.map(c => `<th>${{c}}</th>`).join('');
                container.innerHTML = `
                <div class="table-wrapper">
                    <table>
                        <thead><tr>${{theadThs}}</tr></thead>
                        <tbody>${{tbodyRows}}</tbody>
                    </table>
                </div>
                ${{paginationHtml}}
                `;
            }} else {{
                container.innerHTML = `
                ${{tbodyRows}}
                ${{paginationHtml}}
                `;
            }}
        }}

        function goToPage(tableId, newPage) {{
            const tableData = window.PAGINATION_DATA[tableId];
            if (!tableData) return;
            const totalPages = Math.ceil(tableData.data.length / tableData.pageSize) || 1;
            if (newPage >= 1 && newPage <= totalPages) {{
                tableData.page = newPage;
                renderPaginatedTable(tableId);
            }}
        }}
        function goToSubdomain(host) {{
            host = host.trim();
            // Switch to subdomains section
            document.querySelectorAll('.nav-btn').forEach(b => {{
                if(b.dataset.section === 'subdomains') b.click();
            }});
            
            // Search for the host
            const searchInput = document.getElementById('subdomainSearch');
            if(searchInput) {{
                searchInput.value = host;
                filterSubdomains(host);
            }}
            
            // Wait for pagination to render and scroll
            setTimeout(() => {{
                const cards = document.querySelectorAll('.card');
                for(let card of cards) {{
                    if(card.querySelector('.card-title') && card.querySelector('.card-title').innerText.trim() === host) {{
                        card.classList.add('open');
                        card.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
                        card.style.border = '2px solid var(--accent-blue)';
                        setTimeout(() => card.style.border = '', 3000);
                        break;
                    }}
                }}
            }}, 500);
        }}

        function filterSubdomains(query) {{
            query = query.toLowerCase().trim();
            const containerId = "subdomains_container";
            const tableData = window.PAGINATION_DATA[containerId];
            if (!tableData) return;
            
            if (!tableData.fullData) tableData.fullData = [...tableData.data];
            
            if (!query) {{
                tableData.data = [...tableData.fullData];
            }} else {{
                tableData.data = tableData.fullData.filter(html => {{
                    const temp = document.createElement('div');
                    temp.innerHTML = html;
                    return temp.textContent.toLowerCase().includes(query);
                }});
            }}
            tableData.page = 1;
            renderPaginatedTable(containerId);
        }}
        
        // ==========================================
        // AUTO-HIDE EMPTY SECTIONS IN SIDEBAR
        // ==========================================
        document.addEventListener('DOMContentLoaded', () => {{
            document.querySelectorAll('.nav-btn').forEach(btn => {{
                const countSpan = btn.querySelector('.count');
                if (countSpan && !btn.dataset.alwaysShow) {{
                    const count = parseInt(countSpan.textContent.trim(), 10);
                    if (!isNaN(count) && count === 0) {{
                        btn.style.display = 'none';
                    }}
                }}
            }});

            document.querySelectorAll('.sidebar-category').forEach(cat => {{
                let sibling = cat.nextElementSibling;
                let hasVisible = false;
                while (sibling && !sibling.classList.contains('sidebar-category')) {{
                    if (sibling.classList.contains('nav-btn') && getComputedStyle(sibling).display !== 'none') {{
                        hasVisible = true;
                        break;
                    }}
                    sibling = sibling.nextElementSibling;
                }}
                if (!hasVisible) {{
                    cat.style.display = 'none';
                }}
            }});
        }});
    </script>
</body>
</html>'''


# ------------------------------------------------------------
# HTML Builders
# ------------------------------------------------------------

# ------------------------------------------------------------
# New Plugin Builders (Open Redirect, SSRF, Cache Deception, GraphQL, API Security)
# ------------------------------------------------------------

def build_graphql_content(target: str) -> str:
    path = Path("output") / target / "graphql" / "graphql.json"
    data = read_json_file(path)
    if not data: return '<div class="empty-state"><p>No GraphQL instances found.</p></div>'
    
    rows = ""
    for item in data:
        # Extrair Request Body Style Burp
        req_b64 = base64.b64encode((item.get("request_raw") or "").encode("utf-8")).decode("utf-8")
        res_b64 = base64.b64encode((item.get("response_raw") or "").encode("utf-8")).decode("utf-8")
        row_id = f"gql_{uuid.uuid4().hex[:8]}"
        burp_script = f'<script>BURP_DATA["{row_id}"] = {{ "url": "{html.escape(item.get("url", ""))}", "req": "{req_b64}", "res": "{res_b64}" }};</script>'
        button_html = f'<button class="burp-btn" onclick="openBurp(\'{row_id}\')">View HTTP</button>{burp_script}' if req_b64 else '-'

        rows += f'''
        <tr>
            <td><a href="{html.escape(item.get("url", ""))}" target="_blank">{html.escape(item.get("url", ""))}</a></td>
            <td><span class="tag tag-medium">{item.get("status")}</span></td>
            <td><strong>{item.get("length")}</strong></td>
            <td>{"<span class='tag tag-high'>Introspection Enabled</span>" if item.get("introspection") else "-"}</td>
            <td style="text-align:right;">{button_html}</td>
        </tr>
        '''
    return f'''
    <div class="card open" style="border-left: 4px solid var(--accent-purple);">
        <div class="card-header">
            <span class="card-title"> GraphQL Instances</span>
            <span class="card-badge">{len(data)} endpoints</span>
        </div>
        <div class="card-content" style="display:block;">
            <div class="table-wrapper">
                <table>
                    <thead><tr><th>URL</th><th>Status</th><th>Length</th><th>Features</th><th>PoC</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>
    </div>
    '''

def build_api_security_content(target: str) -> str:
    path = Path("output") / target / "scanners" / "api_security.json"
    data = read_json_file(path)
    if not data: return '<div class="empty-state"><p>No API Security weaknesses found.</p></div>'
    
    rows = ""
    for item in data:
        risk = item.get("risk", "LOW")
        risk_class = f"tag-{risk.lower()}"
        
        # Burp data
        req_b64 = base64.b64encode((item.get("request_raw") or "").encode("utf-8")).decode("utf-8")
        res_b64 = base64.b64encode((item.get("response_raw") or "").encode("utf-8")).decode("utf-8")
        row_id = f"api_{uuid.uuid4().hex[:8]}"
        burp_script = f'<script>BURP_DATA["{row_id}"] = {{ "url": "{html.escape(item.get("url", ""))}", "req": "{req_b64}", "res": "{res_b64}" }};</script>'
        button_html = f'<button class="burp-btn" onclick="openBurp(\'{row_id}\')">View HTTP</button>{burp_script}' if req_b64 else ''
        
        rows += f'''
        <tr>
            <td><span class="tag {risk_class}">{risk}</span></td>
            <td><strong>{html.escape(item.get("type", ""))}</strong></td>
            <td><a href="{html.escape(item.get("url", ""))}" target="_blank">{html.escape(item.get("url", ""))}</a></td>
            <td style="font-size:12px;">{html.escape(item.get("details", ""))}</td>
            <td style="text-align:right;">{button_html}</td>
        </tr>
        '''
    return f'''
    <div class="card open" style="border-left: 4px solid var(--accent-red);">
        <div class="card-header">
            <span class="card-title"> API Security Flaws</span>
            <span class="card-badge">{len(data)} items</span>
        </div>
        <div class="card-content" style="display:block;">
            <div class="table-wrapper">
                <table>
                    <thead><tr><th>Risk</th><th>Type</th><th>URL</th><th>Details</th><th>Actions</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>
    </div>
    '''

def _build_generic_security_card(target: str, file_path: str, title: str, icon: str, border_color: str) -> str:
    path = Path("output") / target / file_path
    data = read_json_file(path)
    if not data: return ''
    
    rows = ""
    for item in data:
        # Check if Burp data exists
        req_b64 = item.get("request_raw", "")
        res_b64 = item.get("response_raw", "")
        
        button_html = ""
        if req_b64:
            if req_b64.startswith(('http', 'GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH')): # Needs base64 encoding
                try: 
                    import base64
                    req_b64 = base64.b64encode(req_b64.encode('utf-8', 'ignore')).decode('utf-8')
                    res_b64 = base64.b64encode(res_b64.encode('utf-8', 'ignore')).decode('utf-8')
                except: pass
            
            import uuid
            row_id = f"sec_{uuid.uuid4().hex[:8]}"
            burp_script_data = f'<script>BURP_DATA["{row_id}"] = {{ "url": "{html.escape(item.get("url", ""))}", "req": "{req_b64}", "res": "{res_b64}" }};</script>'
            button_html = f'<button class="burp-btn" onclick="openBurp(\'{row_id}\')">View HTTP</button>{burp_script_data}'
        
        # Details column (if dict, show key-value, if string, show string)
        details = item.get("details", "")
        if isinstance(details, dict):
            details = "<br>".join([f"<strong>{k}:</strong> {v}" for k,v in details.items()])
            
        rows += f'''
        <tr>
            <td><a href="{html.escape(item.get("url", ""))}" target="_blank">{html.escape(item.get("url", ""))}</a></td>
            <td><strong>{html.escape(item.get("parameter", item.get("type", "General")))}</strong></td>
            <td style="font-size:12px;">{html.escape(str(details))}</td>
            <td style="text-align:right;">{button_html}</td>
        </tr>
        '''
    
    explanation_html = ""
    if "cache_deception" in file_path:
        explanation_html = '''
        <div style="padding:15px; background:rgba(187,128,255,0.1); border:1px solid rgba(187,128,255,0.3); border-radius:6px; margin-bottom:15px;">
            <h4 style="color:var(--accent-purple); margin-bottom:8px; font-size:14px; font-weight:600;">What is Web Cache Deception?</h4>
            <p style="font-size:13px; color:var(--text-secondary); line-height:1.5;">
                <strong>Web Cache Deception (WCD)</strong> occurs when an attacker tricks a web cache into storing sensitive, user-specific information (like a profile page) as if it were a static asset (like a .css or .js file).
                <br><br>
                <strong>Impact:</strong> An attacker can then access the cached sensitive information by simply requesting the static asset URL.
                <br><br>
                <strong>What was tested:</strong> The analyzer appended fake static extensions (e.g., <code>/profile.php/test.css</code>) to sensitive endpoints and checked if the cache server (CDN/WAF) returned a <code>HIT</code> for those paths while still serving the underlying private content.
            </p>
        </div>
        '''

    return f'''
    <div class="card open" style="border-left: 3px solid var({border_color}); margin-top:20px;">
        <div class="card-header">
            <span class="card-title">{icon} {title}</span>
            <span class="card-badge">{len(data)} items</span>
        </div>
        <div class="card-content" style="display:block;">
            {explanation_html}
            <div class="table-wrapper">
                <table>
                    <thead><tr><th>URL</th><th>Type/Parameter</th><th>Details</th><th>Actions</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>
    </div>
    '''

def build_open_redirect_content(target: str) -> str:
    # Primeiro tentar a pasta nova, depois a pré-existente
    data = read_json_file(Path("output") / target / "open_redirect" / "open_redirect_results.json")
    if not data:
        data = read_json_file(Path("output") / target / "scanners" / "open_redirect.json")
    summary = read_json_file(Path("output") / target / "open_redirect" / "scan_summary.json") or {}
    if not data:
        s = summary.get("status", "NOT_RUN")
        detail = f"Testados {summary.get('urls_checked', 0)} URLs com {summary.get('tests_run', 0)} requests." if summary else ""
        return f'<div class="empty-state"><p> Nenhum Open Redirect encontrado. {detail}</p></div>'
    return _build_generic_security_card_from_data(data, "Open Redirect Vulnerabilities", "", "--accent-orange")

def build_host_injection_content(target: str) -> str:
    data = read_json_file(Path("output") / target / "host_header_injection" / "host_injection_results.json")
    summary = read_json_file(Path("output") / target / "host_header_injection" / "scan_summary.json") or {}
    if not data:
        detail = f"Testados {summary.get('hosts_checked', 0)} hosts com {summary.get('tests_run', 0)} requests." if summary else ""
        return f'<div class="empty-state"><p> Nenhum Host Header Injection encontrado. {detail}</p></div>'
    return _build_generic_security_card_from_data(data, "Host Header Injection", "", "--accent-red")

def build_ssti_content(target: str) -> str:
    data = read_json_file(Path("output") / target / "ssti" / "ssti_results.json")
    summary = read_json_file(Path("output") / target / "ssti" / "scan_summary.json") or {}
    if not data:
        detail = f"Testados {summary.get('urls_checked', 0)} parâmetros com {summary.get('tests_run', 0)} requests." if summary else ""
        return f'<div class="empty-state"><p> Nenhum SSTI encontrado. {detail}</p></div>'
    return _build_generic_security_card_from_data(data, "SSTI (Template Injection)", "", "--accent-red")

def build_xxe_content(target: str) -> str:
    data = read_json_file(Path("output") / target / "xxe" / "xxe_results.json")
    summary = read_json_file(Path("output") / target / "xxe" / "scan_summary.json") or {}
    if not data:
        detail = f"Testados {summary.get('endpoints_checked', 0)} endpoints." if summary else ""
        return f'<div class="empty-state"><p> Nenhum XXE encontrado. {detail}</p></div>'
    return _build_generic_security_card_from_data(data, "XXE (XML External Entity)", "", "--accent-red")

def build_proto_pollution_content(target: str) -> str:
    data = read_json_file(Path("output") / target / "prototype_pollution" / "prototype_pollution_results.json")
    summary = read_json_file(Path("output") / target / "prototype_pollution" / "scan_summary.json") or {}
    if not data:
        detail = f"Testados {summary.get('tests_run', 0)} requests. {summary.get('js_sinks', 0)} sinks JS analisados." if summary else ""
        return f'<div class="empty-state"><p> Nenhum Prototype Pollution encontrado. {detail}</p></div>'
    return _build_generic_security_card_from_data(data, "Prototype Pollution", "", "--accent-purple")

def build_oauth_content(target: str) -> str:
    data = read_json_file(Path("output") / target / "oauth_misconfig" / "oauth_misconfig_results.json")
    summary = read_json_file(Path("output") / target / "oauth_misconfig" / "scan_summary.json") or {}
    if not data:
        detail = f"Testados {summary.get('oauth_endpoints', 0)} endpoints OAuth." if summary else ""
        return f'<div class="empty-state"><p> Nenhuma misconfiguraçao OAuth encontrada. {detail}</p></div>'
    return _build_generic_security_card_from_data(data, "OAuth Misconfiguration", "", "--accent-orange")

def build_file_upload_content(target: str) -> str:
    data = read_json_file(Path("output") / target / "file_upload" / "file_upload_results.json")
    summary = read_json_file(Path("output") / target / "file_upload" / "scan_summary.json") or {}
    if not data:
        detail = f"Testados {summary.get('tests_run', 0)} endpoints de upload." if summary else ""
        return f'<div class="empty-state"><p> Nenhum upload inseguro encontrado. {detail}</p></div>'
    return _build_generic_security_card_from_data(data, "Insecure File Upload", "", "--accent-orange")

def build_api_versioning_content(target: str) -> str:
    data = read_json_file(Path("output") / target / "api_versioning" / "api_versioning_results.json")
    if not data:
        return '<div class="empty-state"><p> Nenhuma versão de API detectada.</p></div>'
    rows = ""
    for item in data:
        risk = item.get("risk", "INFO")
        risk_class = f"tag-{risk.lower()}" if risk != "INFO" else "tag-low"
        req_b64 = base64.b64encode((item.get("request_raw") or "").encode("utf-8")).decode("utf-8")
        res_b64 = base64.b64encode((item.get("response_raw") or "").encode("utf-8")).decode("utf-8")
        row_id = f"apiv_{uuid.uuid4().hex[:8]}"
        burp_script = f'<script>BURP_DATA["{row_id}"] = {{ "url": "{html.escape(item.get("url", ""))}", "req": "{req_b64}", "res": "{res_b64}" }};</script>'
        button_html = f'<button class="burp-btn" onclick="openBurp(\'{row_id}\')">View HTTP</button>{burp_script}' if req_b64 else '-'
        rows += f'''
        <tr>
            <td><a href="{html.escape(item.get("url", ""))}" target="_blank">{html.escape(item.get("url", ""))}</a></td>
            <td><span class="tag {risk_class}">{item.get("version", "")}</span></td>
            <td>{item.get("status", "")}</td>
            <td>{item.get("length", "")}</td>
            <td>{html.escape(item.get("details", ""))}</td>
            <td style="text-align:right;">{button_html}</td>
        </tr>'''
    return f'''
    <div class="card open" style="border-left: 4px solid var(--accent-blue);">
        <div class="card-header"><span class="card-title"> API Versioning</span><span class="card-badge">{len(data)} versions</span></div>
        <div class="card-content" style="display:block;"><div class="table-wrapper"><table>
            <thead><tr><th>URL</th><th>Version</th><th>Status</th><th>Length</th><th>Details</th><th>PoC</th></tr></thead>
            <tbody>{rows}</tbody>
        </table></div></div>
    </div>'''

def build_email_security_content(target: str) -> str:
    data = read_json_file(Path("output") / target / "email_security" / "email_security_results.json")
    if not data:
        return '<div class="empty-state"><p> Análise de email security não executada.</p></div>'
    spf = data.get("spf", {})
    dmarc = data.get("dmarc", {})
    dkim = data.get("dkim", {})
    def _risk_tag(r):
        cls = {"CRITICAL": "tag-critical", "HIGH": "tag-high", "MEDIUM": "tag-medium", "LOW": "tag-low"}.get(r, "tag-info")
        return f'<span class="tag {cls}">{r}</span>'
    return f'''
    <div class="card open" style="border-left: 4px solid var(--accent-blue);">
        <div class="card-header"><span class="card-title"> Email Security (SPF/DMARC/DKIM)</span>
        <span class="card-badge">{" SPOOFABLE" if data.get("spoofable") else " OK"}</span></div>
        <div class="card-content" style="display:block;"><div class="table-wrapper"><table>
            <thead><tr><th>Check</th><th>Status</th><th>Risk</th><th>Details</th><th>Record</th></tr></thead>
            <tbody>
                <tr><td><strong>SPF</strong></td><td>{" Present" if spf.get("present") else " Missing"}</td><td>{_risk_tag(spf.get("risk", ""))}</td><td>{html.escape(spf.get("issue", ""))}</td><td style="font-size:11px;max-width:300px;overflow:auto;">{html.escape(str(spf.get("record") or "-"))}</td></tr>
                <tr><td><strong>DMARC</strong></td><td>{" Present" if dmarc.get("present") else " Missing"}</td><td>{_risk_tag(dmarc.get("risk", ""))}</td><td>{html.escape(dmarc.get("issue", ""))}</td><td style="font-size:11px;max-width:300px;overflow:auto;">{html.escape(str(dmarc.get("record") or "-"))}</td></tr>
                <tr><td><strong>DKIM</strong></td><td>{" Present" if dkim.get("present") else " Missing"}</td><td>{_risk_tag(dkim.get("risk", ""))}</td><td>{html.escape(dkim.get("issue", ""))}</td><td style="font-size:11px;">-</td></tr>
            </tbody>
        </table></div></div>
    </div>'''

def build_google_dorks_content(target: str) -> str:
    data = read_json_file(Path("output") / target / "google_dorks" / "dorks_results.json")
    if not data:
        return '<div class="empty-state"><p>Google Dorks não gerados.</p></div>'
    rows = ""
    for item in data:
        rows += f'''<tr>
            <td><strong>{html.escape(item.get("category", ""))}</strong></td>
            <td style="font-size:12px;">{html.escape(item.get("query", ""))}</td>
            <td><a href="{html.escape(item.get("google_url", ""))}" target="_blank" class="burp-btn">Abrir no Google</a></td>
        </tr>'''
    return f'''
    <div class="card open" style="border-left: 4px solid var(--accent-green);">
        <div class="card-header"><span class="card-title"> Google Dorks</span><span class="card-badge">{len(data)} dorks</span></div>
        <div class="card-content" style="display:block;"><div class="table-wrapper"><table>
            <thead><tr><th>Categoria</th><th>Query</th><th>Link</th></tr></thead>
            <tbody>{rows}</tbody>
        </table></div></div>
    </div>'''

def build_spiderfoot_content(target: str) -> str:
    """Build SpiderFoot OSINT section for the report."""
    sf_path = Path("output") / target / "spiderfoot" / "spiderfoot_results.json"
    data = read_json_file(sf_path)
    if not data:
        return '<div class="empty-state"><p>SpiderFoot nao executado.</p></div>'

    status = data.get("status", "UNKNOWN")
    findings = data.get("findings", [])

    # Handle failure states
    if status in ("SERVER_FAILED", "SCAN_FAILED", "SKIPPED"):
        reason = html.escape(data.get("reason", "Erro desconhecido"))
        return f'''<div class="card" style="border-left: 4px solid var(--accent-orange);">
            <div class="card-header"><span class="card-title">SpiderFoot OSINT</span>
            <span class="card-badge">{status}</span></div>
            <div class="card-content" style="display:block;">
                <p style="color:var(--accent-orange);">Scan nao concluido: {reason}</p>
                <p style="color:var(--text-secondary); font-size:12px;">Verifique se o SpiderFoot esta instalado e acessivel no sistema.</p>
            </div>
        </div>'''

    if not findings:
        return '<div class="empty-state"><p>SpiderFoot executado mas sem findings.</p></div>'

    # Group by type
    by_type = {}
    for f in findings:
        t = f.get("type", "UNKNOWN")
        by_type.setdefault(t, []).append(f)

    cards = ""
    for ftype, items in sorted(by_type.items(), key=lambda x: -len(x[1])):
        rows = ""
        for item in items[:50]:  # Limit per category
            rows += f'''<tr>
                <td style="font-size:12px; max-width:400px; word-break:break-all;">{html.escape(str(item.get("data", ""))[:200])}</td>
                <td style="font-size:11px;">{html.escape(str(item.get("module", "")))}</td>
                <td style="font-size:11px;">{html.escape(str(item.get("source", ""))[:100])}</td>
            </tr>'''
        truncated = f' (mostrando 50 de {len(items)})' if len(items) > 50 else ''
        cards += f'''<div class="card">
            <div class="card-header" onclick="this.parentElement.classList.toggle('open')">
                <span class="card-title">{html.escape(ftype)}</span>
                <span class="card-badge">{len(items)}{truncated}</span>
            </div>
            <div class="card-content"><div class="table-wrapper"><table>
                <thead><tr><th>Data</th><th>Module</th><th>Source</th></tr></thead>
                <tbody>{rows}</tbody>
            </table></div></div>
        </div>'''

    return f'''<h2 class="section-title">SpiderFoot OSINT</h2>
    <p style="color:var(--text-secondary); margin-bottom:16px;">Resultados de reconhecimento OSINT via SpiderFoot. Total: {len(findings)} findings em {len(by_type)} categorias.</p>
    {cards}'''


def _build_generic_security_card_from_data(data: list, title: str, icon: str, border_color: str) -> str:
    """Constrói um card genérico de segurança a partir de dados já carregados."""
    if not data:
        return ''
    rows = ""
    for item in data:
        risk = item.get("risk", "LOW")
        risk_class = f"tag-{risk.lower()}"
        req_b64 = base64.b64encode((item.get("request_raw") or "").encode("utf-8")).decode("utf-8")
        res_b64 = base64.b64encode((item.get("response_raw") or "").encode("utf-8")).decode("utf-8")
        row_id = f"sec_{uuid.uuid4().hex[:8]}"
        burp_script = f'<script>BURP_DATA["{row_id}"] = {{ "url": "{html.escape(item.get("url", ""))}", "req": "{req_b64}", "res": "{res_b64}" }};</script>'
        button_html = f'<button class="burp-btn" onclick="openBurp(\'{row_id}\')">View HTTP</button>{burp_script}' if req_b64 else '-'
        rows += f'''<tr>
            <td><span class="tag {risk_class}">{risk}</span></td>
            <td><strong>{html.escape(item.get("type", ""))}</strong></td>
            <td><a href="{html.escape(item.get("url", ""))}" target="_blank">{html.escape(item.get("url", "")[:80])}</a></td>
            <td style="font-size:12px;">{html.escape(item.get("details", ""))}</td>
            <td style="text-align:right;">{button_html}</td>
        </tr>'''
    return f'''
    <div class="card open" style="border-left: 4px solid var({border_color});">
        <div class="card-header"><span class="card-title">{icon} {title}</span><span class="card-badge">{len(data)} items</span></div>
        <div class="card-content" style="display:block;"><div class="table-wrapper"><table>
            <thead><tr><th>Risk</th><th>Type</th><th>URL</th><th>Details</th><th>PoC</th></tr></thead>
            <tbody>{rows}</tbody>
        </table></div></div>
    </div>'''

def build_ssrf_content(target: str) -> str:
    return _build_generic_security_card(target, "scanners/ssrf.json", "Server-Side Request Forgery", "", "--accent-red")

def build_cache_deception_content(target: str) -> str:
    return _build_generic_security_card(target, "scanners/cache_deception.json", "Web Cache Deception", "", "--accent-purple")


def build_subdomains_content(subdomains: Dict, target: str) -> str:
    if not subdomains:
        return '<div class="empty-state"><p>No subdomains found</p></div>'
    
    # Load DNS Data
    from pathlib import Path
    base = Path("output") / target / "domain"
    
    dns_data = read_json_file(base / "dns_resolved.json") or {}
    
    cdn_file = base / "cdn_filtered.txt"
    cdn_subs = read_file_lines(cdn_file) if cdn_file.exists() else []
    cdn_set = set(s.strip() for s in cdn_subs if s.strip())
    
    ips_file = base / "ips.txt"
    ips_list = read_file_lines(ips_file) if ips_file.exists() else []
    ips_list = [ip.strip() for ip in ips_list if ip.strip()]
    
    html_parts = []
    
    def sort_key(item):
        host, data = item
        score = 0
        if data["ports"]: score += 100
        if data["urls"]: score += 50
        if data["technologies"]: score += 10
        if data["is_login"]: score += 500  # Login pages to top
        return (-score, host)

    for host, data in sorted(subdomains.items(), key=sort_key):
        ports_str = ", ".join(sorted(set(data["ports"]), key=int)) if data["ports"] else "None"
        urls_count = len(data["urls"])
        tech_count = len(data["technologies"])
        
        badge = ""
        is_cdn = host in cdn_set
        cdn_badge = '<span class="tag tag-medium" style="margin-left:8px;">CDN</span>' if is_cdn else ""
        
        is_active = len(data["urls"]) > 0 or len(data["ports"]) > 0
        active_badge = '<span class="tag tag-high" style="background:#23863630; color:#3fb950; margin-left:8px;">[+] Active</span>' if is_active else '<span class="tag tag-low" style="background:#f8514930; color:#f85149; margin-left:8px;"> Inactive</span>'
        
        if data["is_login"]:
            badge = '<span class="card-badge login"> LOGIN</span>'
        
        content_parts = []
        
        # === LOGIN PAGES (destaque no topo) ===
        if data["is_login"] and data.get("login_urls"):
            login_html = ""
            for login_url in sorted(data["login_urls"]):
                login_html += f'''
                <div style="display:flex; align-items:flex-start; gap:12px; margin-bottom:12px; padding:10px; background:#2d1f1f; border:1px solid #f8514930; border-radius:8px;">
                    <div style="flex:1;">
                        <p style="margin:0;">
                            <span class="tag tag-medium" style="font-size:10px;"> LOGIN</span>
                            <a href="{html.escape(login_url)}" target="_blank" style="color:var(--accent-orange); font-weight:bold; margin-left:8px;">{html.escape(login_url)}</a>
                        </p>
                    </div>
                </div>'''
            
            content_parts.append(f'''
            <div style="margin-bottom:16px; border-left:3px solid var(--accent-orange); padding-left:12px;">
                <p style="color:var(--accent-orange); font-weight:bold; margin-bottom:8px;"> Login Pages Detected ({len(data["login_urls"])})</p>
                {login_html}
            </div>''')
        

        host_ips = dns_data.get(host, [])
        if host_ips:
            ips_str = ", ".join(host_ips)
            content_parts.append(f'<p><strong>IPs ({len(host_ips)}):</strong> <code style="font-size:12px;">{html.escape(ips_str)}</code></p>')
            
        if data["ports"]:
            content_parts.append(f'<p><strong>Ports:</strong> {ports_str}</p>')
            
        # Technologies - Detailed table like original Technologies section
        if data["technologies"]:
            tech_rows = ""
            for tech in sorted(data["technologies"], key=lambda x: -x.get("confidence", 0)):
                conf = tech.get("confidence", 0)
                conf_class = "tag-high" if conf >= 70 else "tag-medium" if conf >= 40 else "tag-low"
                tech_rows += f'''
                <tr>
                    <td><strong>{html.escape(tech["name"])}</strong></td>
                    <td><span class="tag tag-low" style="background:#444; color:#fff">{html.escape(str(tech.get("version") or ""))}</span></td>
                    <td>{html.escape(tech.get("category", "Unknown"))}</td>
                    <td><span class="tag {conf_class}">{conf}%</span></td>
                    <td>{f'<span class="tag tag-high"> {tech["cve_count"]} CVEs</span>' if tech.get("cve_count") else '-'}</td>
                </tr>'''
            
            content_parts.append(f'''
            <div style="margin-bottom:12px;">
                <p><strong>Technologies ({tech_count}):</strong></p>
                <div class="table-wrapper">
                    <table>
                        <thead><tr><th>Technology</th><th>Version</th><th>Category</th><th>Confidence</th><th>Vulns</th></tr></thead>
                        <tbody>{tech_rows}</tbody>
                    </table>
                </div>
            </div>''')
            
        if data["urls"]:
            urls_list_items = []
            for u in data["urls"]:
                is_log = u in data.get("login_urls", set())
                style = "color:var(--accent-orange);font-weight:bold;" if is_log else "color:var(--accent-green);"
                url_badge = ' <span class="tag tag-medium" style="font-size:10px;">LOGIN</span>' if is_log else ""
                urls_list_items.append(f'<a href="{u}" target="_blank" style="{style}">{html.escape(u)}</a>{url_badge}')
            
            urls_list = "<br>".join(urls_list_items)
            content_parts.append(f'<p><strong>Validated URLs ({urls_count}):</strong><br>{urls_list}</p>')
        
        content = "".join(content_parts) if content_parts else "<p>No additional data</p>"
        
        html_parts.append(f'''
        <div class="card">
            <div class="card-header">
                <div>
                    <span class="card-title">{html.escape(host)}</span>
                    {active_badge}
                    {cdn_badge}
                </div>
                <div>
                    <span class="card-badge">{urls_count} URLs</span>
                    <span class="card-badge">{len(data["ports"])} ports</span>
                    <span class="card-badge">{tech_count} tech</span>
                    {badge}
                </div>
            </div>
            <div class="card-content">{content}</div>
        </div>
        ''')
        
    ips_card = ""
    if ips_list:
        ips_html = ", ".join(f"<code>{html.escape(ip)}</code>" for ip in ips_list[:100])
        ips_card = f'''
        <div class="card open" style="margin-top:20px; border-left: 4px solid var(--accent-blue);">
            <div class="card-header">
                <span class="card-title">Real IPs (Sem CDN)</span>
                <span class="card-badge">{len(ips_list)} IPs Resolvidos</span>
            </div>
            <div class="card-content">
                <p style="word-break:break-all;">{ips_html}</p>
                {"" if len(ips_list) <= 100 else "<p><small>Showing top 100 IPs.</small></p>"}
            </div>
        </div>'''
        
    import json
    json_data = json.dumps(html_parts).replace("</", "<\\/")
    
    return f'''
    <div style="margin-bottom:15px; display:flex; gap:10px;">
        <input type="text" id="subdomainSearch" placeholder=" Search subdomains..." style="flex:1; background:var(--bg-secondary); border:1px solid var(--border-color); border-radius:6px; padding:8px 12px; color:var(--text-primary); font-size:13px;" onkeyup="filterSubdomains(this.value)">
    </div>
    <div id="subdomains_container"></div>
    {ips_card}
    <script>
        setTimeout(function() {{
            initPaginatedTable("subdomains_container", {json_data}, [], function(row) {{ return row; }}, 100);
        }}, 0);
    </script>
    '''


def build_ports_content(target: str) -> str:
    base = Path("output") / target
    ports_file = base / "domain" / "ports.txt"
    
    content = read_file_raw(ports_file)
    if not content.strip():
        return '<div class="empty-state"><p>No ports found</p></div>'
    
    return f'''
    <div class="card open">
        <div class="card-header">
            <span class="card-title section-title">Open Ports by Host</span>
        </div>
        <div class="card-content">
            <pre>{html.escape(content)}</pre>
        </div>
    </div>
    '''


def build_urls_content(subdomains: Dict, target: str) -> str:
    from pathlib import Path
    import json
    
    # Load Crawled "Discovered" URLs from Katana
    base = Path("output") / target
    crawled_file = find_file(base, "crawlers/katana_valid.txt", "domain/crawlers/katana_valid.txt", "domain/katana_valid.txt", "katana_valid.txt")
    
    discovered_urls = []
    if crawled_file.exists():
        discovered_urls = read_file_lines(crawled_file)
        
    all_urls = []
    
    # Add Validated URLs from httpx (from subdomains obj)
    for host, data in subdomains.items():
        for url in data["urls"]:
            all_urls.append({
                "host": host, 
                "url": url, 
                "is_login": url in data.get("login_urls", set()),
                "type": "validated",
                "tags": data.get("url_classifications", {}).get(url, [])
            })
            
    # Add Discovered URLs from katana
    from urllib.parse import urlparse
    for d_url in discovered_urls:
        if not d_url.strip(): continue
        try:
            host = urlparse(d_url.strip()).netloc.split(":")[0]
            # avoid duplicates if already in validated
            if not any(u["url"] == d_url.strip() for u in all_urls):
                all_urls.append({
                    "host": host if host else "Unknown",
                    "url": d_url.strip(),
                    "is_login": False,
                    "type": "discovered",
                    "tags": []
                })
        except:
            pass
            
    if not all_urls:
        return '<div class="empty-state"><p>No URLs found</p></div>'
        
    all_urls = sorted(all_urls, key=lambda x: (x["host"], 0 if x["type"] == "validated" else 1, x["url"]))
    json_data = json.dumps(all_urls).replace("</", "<\\/")
    
    return f'''
    <div class="card open" style="margin-top:20px;">
        <div class="card-header">
            <span class="card-title"> All Found URLs</span>
            <span class="card-badge">{len(all_urls)} URLs</span>
        </div>
        <div class="card-content" id="urls_container" style="display:block;"></div>
    </div>
    <script>
        setTimeout(function() {{
            initPaginatedTable(
                "urls_container", 
                {json_data}, 
                ["Host", "URL", "Type", "Tags", "Login"], 
                function(row) {{
                    let style = row.type === "validated" ? "color:var(--text-primary);" : "color:var(--text-muted);";
                    let type_badge = row.type === "validated" ? '<span class="tag tag-high" style="background:#23863630; color:#3fb950; font-size:10px;"> Validated</span>' : '<span class="tag tag-low" style="background:#d2992230; color:#d29922; font-size:10px;"> Discovered</span>';
                    let login_badge = row.is_login ? '<span class="tag tag-medium"> LOGIN</span>' : "";
                    let tags_html = (row.tags || []).map(t => `<span class="tag tag-low" style="background:#333; color:#aaa; font-size:10px;">${{escapeHtml(t)}}</span>`).join(" ");
                    
                    return `<tr>
                        <td>${{escapeHtml(row.host)}}</td>
                        <td style="word-break: break-all; max-width: 500px;"><a href="${{escapeHtml(row.url)}}" target="_blank" style="${{style}}">${{escapeHtml(row.url)}}</a></td>
                        <td>${{type_badge}}</td>
                        <td>${{tags_html}}</td>
                        <td>${{login_badge}}</td>
                    </tr>`;
                }},
                100 // 100 per page layout
            );
        }}, 0);
    </script>
    '''



def build_technologies_content(target: str) -> str:
    base = Path("output") / target
    tech_data = read_json_file(base / "domain" / "technologies.json")
    
    if not tech_data:
        return '<div class="empty-state"><p>No technologies detected</p></div>'
    
    html_parts = []
    
    for host, data in sorted(tech_data.items()):
        techs = data.get("technologies", [])
        if not techs:
            continue
            
        tech_rows = ""
        for tech in sorted(techs, key=lambda x: -x.get("confidence", 0)):
            conf = tech.get("confidence", 0)
            conf_class = "tag-high" if conf >= 70 else "tag-medium" if conf >= 40 else "tag-low"
            tech_rows += f'''
            <tr>
                <td><strong>{html.escape(tech["name"])}</strong></td>
                <td>{html.escape(tech.get("category", "Unknown"))}</td>
                <td><span class="tag {conf_class}">{conf}%</span></td>
            </tr>
            '''
        
        html_parts.append(f'''
        <div class="card">
            <div class="card-header">
                <span class="card-title">{html.escape(host)}</span>
                <span class="card-badge">{len(techs)} technologies</span>
            </div>
            <div class="card-content">
                <div class="table-wrapper">
                    <table>
                        <thead><tr><th>Technology</th><th>Category</th><th>Confidence</th></tr></thead>
                        <tbody>{tech_rows}</tbody>
                    </table>
                </div>
            </div>
        </div>
        ''')
        
    
    return "".join(html_parts) if html_parts else '<div class="empty-state"><p>No technologies detected</p></div>'


def build_keys_content(target: str) -> str:
    base = Path("output") / target
    keys_data = read_json_file(base / "domain" / "extracted_keys.json")
    
    if not keys_data:
        return '<div class="empty-state"><p>No keys or secrets found</p></div>'
    
    html_parts = []
    
    for key in keys_data:
        risk = key.get("info", {}).get("risk", "UNKNOWN")
        risk_class = "tag-high" if risk == "CRITICAL" else "tag-medium" if risk == "HIGH" else "tag-low"
        
        # Validation badge
        validated = key.get("validated")
        val_info = key.get("validation_info", "")
        if validated is True:
            validated_badge = f'<span class="tag tag-high" style="margin-left:8px;" title="{html.escape(val_info)}"> VALIDATED</span>'
        elif validated is False:
            validated_badge = f'<span class="tag tag-low" style="margin-left:8px;" title="{html.escape(val_info)}"> INVALID</span>'
        else:
            validated_badge = f'<span class="tag" style="margin-left:8px;background:#30363d;" title="{html.escape(val_info)}">⊘ NOT TESTED</span>'
        
        # ── Confidence badge ──
        confidence = key.get("confidence", {})
        conf_score = confidence.get("total_score", 0)
        conf_level = confidence.get("level", "UNKNOWN")
        conf_entropy = confidence.get("entropy", 0)
        conf_context = confidence.get("context_type", "unknown")
        conf_placeholder = confidence.get("is_placeholder", False)
        conf_reasons = confidence.get("reasons", [])
        
        if conf_score >= 85:
            conf_color = "#f85149"  # red = very high confidence (critical finding)
            conf_bg = "rgba(248,81,73,0.15)"
        elif conf_score >= 70:
            conf_color = "#d29922"  # orange
            conf_bg = "rgba(210,153,34,0.15)"
        elif conf_score >= 50:
            conf_color = "#58a6ff"  # blue
            conf_bg = "rgba(88,166,255,0.15)"
        else:
            conf_color = "#8b949e"  # gray
            conf_bg = "rgba(139,148,158,0.15)"
        
        conf_badge = f'<span class="tag" style="margin-left:8px;background:{conf_bg};color:{conf_color};border:1px solid {conf_color}40;" title="Entropy: {conf_entropy} | Context: {conf_context}"> {conf_score}/100 {conf_level}</span>'
        
        placeholder_badge = '<span class="tag" style="margin-left:6px;background:rgba(210,153,34,0.15);color:#d29922;border:1px solid rgba(210,153,34,0.4);"> PLACEHOLDER</span>' if conf_placeholder else ''
        
        # Dados principais
        key_type = key.get("type", "Unknown")
        match_val = key.get("match", "")
        service = key.get("info", {}).get("service", "Unknown")
        
        # Source
        source_url = key.get("source", {}).get("url", "Unknown")
        source_line = key.get("source", {}).get("line", "?")
        source_file = key.get("source", {}).get("file", "")
        
        source_display = f'<a href="{source_url}" target="_blank">{html.escape(source_url[:60])}...</a>'
        if source_file:
             source_display += f' <span class="tag tag-low" style="margin-left:8px;">{html.escape(source_file)}</span>'
             
        # ── Context parsing ──
        context = key.get("context", {})
        
        before_lines = context.get("before", [])
        match_line = context.get("match_line", "")
        after_lines = context.get("after", [])
        
        if not match_line and context.get("full"):
            try:
                full_raw = str(context["full"])
                if "\\n" in full_raw:
                    lines = full_raw.replace("\\n", "\n").split("\n")
                else:
                    lines = full_raw.splitlines()
                
                lines = [l for l in lines]
                
                target_idx = -1
                for i, line in enumerate(lines):
                    if match_val in line or (len(match_val) > 10 and match_val[:10] in line):
                        target_idx = i
                        break
                
                if target_idx != -1:
                    start = max(0, target_idx - 2)
                    end = min(len(lines), target_idx + 3)
                    
                    before_lines = lines[start:target_idx]
                    match_line = lines[target_idx]
                    after_lines = lines[target_idx+1:end]
                else:
                    match_line = "\n".join(lines)
            except Exception:
                pass

        context_html = ""
        
        def truncate_line(l, max_len=1000):
            l_str = str(l)
            if len(l_str) > max_len:
                return l_str[:max_len] + " [TRUNCATED...]"
            return l_str

        current_line_num = 1
        if isinstance(source_line, int) and source_line > 0:
            current_line_num = max(1, source_line - len(before_lines))
        
        for line in before_lines:
            truncated = truncate_line(line)
            context_html += f'<span style="color:#6e7681;">{current_line_num:4d} │</span> {html.escape(truncated)}\n'
            current_line_num += 1
            
        if match_line:
            truncated = truncate_line(match_line)
            context_html += f'<span style="color:#f85149;">▶{current_line_num:4d} │</span> <span style="background:#3d1d1f;color:#ffa198;">{html.escape(truncated)}</span>\n'
            current_line_num += 1
        
        for line in after_lines:
            truncated = truncate_line(line)
            context_html += f'<span style="color:#6e7681;">{current_line_num:4d} │</span> {html.escape(truncated)}\n'
            current_line_num += 1
        
        if not context_html.strip():
             clean_full = str(context.get("full", "Context not available")).replace("\\n", "\n")
             context_html = html.escape(truncate_line(clean_full))
        
        # ── Confidence breakdown row ──
        breakdown = confidence.get("breakdown", {})
        conf_details_html = ""
        if breakdown:
            conf_details_html = f'''
                <div style="margin-top:8px; padding:8px 12px; background:#161b22; border-radius:6px; border:1px solid #30363d;">
                    <p style="font-size:11px; color:#8b949e; margin-bottom:6px;"><strong>Confidence Analysis:</strong></p>
                    <div style="display:flex; gap:12px; flex-wrap:wrap; font-size:11px;">
                        <span style="color:#58a6ff;">Entropy: {breakdown.get("entropy", 0)}/30</span>
                        <span style="color:#3fb950;">Context: {breakdown.get("context", 0)}/30</span>
                        <span style="color:#d29922;">Format: {breakdown.get("format", 0)}/20</span>
                        <span style="color:#a371f7;">Validation: {breakdown.get("validation", 0)}/20</span>
                        <span style="color:#f85149;">Placeholder: {breakdown.get("placeholder_penalty", 0)}</span>
                        <span style="color:#8b949e;">| Context: {conf_context}</span>
                        <span style="color:#8b949e;">| Shannon: {conf_entropy}</span>
                    </div>
                </div>'''
        
        html_parts.append(f'''
        <div class="card open" style="border-left: 4px solid var(--accent-{ 'red' if risk == 'CRITICAL' else 'orange' if risk == 'HIGH' else 'green' });">
            <div class="card-header" style="background:transparent; border-bottom:none; padding-bottom:0;">
                <span class="card-title" style="color:var(--accent-blue); font-size:16px;">{html.escape(key_type)}</span>
                <span class="tag {risk_class}">{risk}</span>
                <span class="tag tag-low" style="margin-left:8px;">{html.escape(service)}</span>
                {validated_badge}
                {conf_badge}
                {placeholder_badge}
            </div>
            <div class="card-content" style="display:block; padding-top:8px;">
                <p style="margin-bottom:8px;"><strong>Match:</strong> <code style="color:var(--accent-orange); background:#2d2d2d; padding:2px 6px; border-radius:4px;">{html.escape(match_val[:80])}</code></p>
                <p style="margin-bottom:12px; font-size:12px; color:var(--text-secondary);"><strong>Source:</strong> {source_display} <span class="tag tag-low">Line {source_line}</span></p>
                
                <p style="margin-bottom:4px; font-size:12px; color:var(--text-secondary);"><strong>Context:</strong></p>
                <pre style="background:#0d1117; color:#c9d1d9; padding:12px; border-radius:6px; font-size:11px; line-height:1.5; overflow-x:auto; white-space:pre-wrap; word-wrap:break-word;">{context_html}</pre>
                {conf_details_html}
            </div>
        </div>
        ''')
        
    
    return "".join(html_parts)


def build_files_content(target: str) -> str:
    base = Path("output") / target
    files_content = read_file_raw(base / "files" / "files_by_extension.txt")
    sensitive_files = read_json_file(base / "files" / "sensitive_files.json") or []
    
    if not files_content.strip() and not sensitive_files:
        return '<div class="empty-state"><p>No files categorized</p></div>'
        
    sensitive_html = ""
    if sensitive_files:
        items = "".join(f'<li><a href="{html.escape(f)}" target="_blank" style="color:var(--accent-red);">{html.escape(f)}</a></li>' for f in sensitive_files)
        sensitive_html = f'''
        <div class="card open" style="border-left: 4px solid var(--accent-red); margin-bottom: 20px;">
            <div class="card-header">
                <span class="card-title"> Sensitive Files Found (.git, .env, backups)</span>
                <span class="card-badge tag-critical">{len(sensitive_files)} files</span>
            </div>
            <div class="card-content" style="display:block;">
                <ul style="list-style-type:none; padding:10px;">
                    {items}
                </ul>
            </div>
        </div>
        '''
    
    return f'''
    {sensitive_html}
    <div class="card open">
        <div class="card-header">
            <span class="card-title">Files by Extension</span>
        </div>
        <div class="card-content">
            <pre>{html.escape(files_content)}</pre>
        </div>
    </div>
    '''


def build_services_content(target: str) -> str:
    base = Path("output") / target
    services_dir = base / "services"
    
    if not services_dir.exists():
        return '<div class="empty-state"><p>No services scanned</p></div>'
    
    html_parts = []
    
    for service_file in sorted(services_dir.glob("*.txt")):
        content = read_file_raw(service_file)
        if not content.strip():
            continue
        
        # Pular scans que falharam (DNS não resolveu ou 0 hosts)
        if "Failed to resolve" in content or "0 hosts scanned" in content:
            continue
            
        name = service_file.stem.replace("scan_", "").replace("scanFinal_", "").replace("_", ".")
        
        html_parts.append(f'''
        <div class="card">
            <div class="card-header">
                <span class="card-title">{html.escape(name)}</span>
            </div>
            <div class="card-content">
                <pre>{html.escape(content)}</pre>
            </div>
        </div>
        ''')
        
    
    return "".join(html_parts) if html_parts else '<div class="empty-state"><p>No services scanned</p></div>'


def build_routes_content(target: str) -> str:
    import json
    base = Path("output") / target
    routes_data = read_json_file(base / "domain" / "extracted_routes.json") or []
    
    # Load raw endpoints (formato JSON usado pelo plugin endpoint)
    raw_endpoints = []
    graphql = []
    
    raw_ep_json = base / "endpoint" / "raw_endpoints.json"
    if raw_ep_json.exists():
        ep_data = read_json_file(raw_ep_json) or {}
        raw_endpoints = ep_data.get("endpoints", [])
        graphql = ep_data.get("graphql", [])
    
    # Fallback para formato txt antigo
    if not raw_endpoints:
        ep_file = base / "endpoint" / "endpoints.txt"
        if ep_file.exists():
            raw_endpoints = [l.strip() for l in ep_file.read_text(errors="ignore").splitlines() if l.strip()]
    
    if not graphql:
        gql_file = base / "endpoint" / "graphql.txt"
        if gql_file.exists():
            graphql = [l.strip() for l in gql_file.read_text(errors="ignore").splitlines() if l.strip()]
    
    def is_in_scope(url_str: str, target_domain: str) -> bool:
        if url_str.startswith('/'): return True
        try:
            from urllib.parse import urlparse
            host = urlparse(url_str).netloc.split(':')[0].lower()
            if not host: return True
            return target_domain in host
        except:
            return False

    kiterunner_data = []
    kiterunner_json = base / "api_fuzzer" / "kiterunner_results.json"
    if kiterunner_json.exists():
        try:
            kit_raw = read_json_file(kiterunner_json) or []
            for item in kit_raw:
                u = item.get("url", "")
                if u and is_in_scope(u, target):
                    kiterunner_data.append(item)
        except: pass

    if not routes_data and not raw_endpoints and not graphql and not kiterunner_data:
        return '<div class="empty-state"><p>No API routes or endpoints found</p></div>'
        
    flat_routes = []
    for r in routes_data:
        url_val = r.get("url", "")
        # Filtragem de escopo rígida
        if not is_in_scope(url_val, target): continue
        
        flat_routes.append({
            "subdomain": r.get("subdomain", "Unknown"),
            "method": r.get("method", "GET"),
            "path": r.get("path", ""),
            "url": url_val,
            "source": r.get("source", "")
        })
        
    # Add raw endpoints as well if they don't overlap completely
    # Transform valid raw eps to flat_routes
    valid_raw_eps = [ep for ep in raw_endpoints if is_in_scope(ep, target)]
    for ep in valid_raw_eps:
        if not any(r["path"] == ep or r["url"] == ep for r in flat_routes):
            flat_routes.append({
                "subdomain": "Unknown",
                "method": "GET",
                "path": ep,
                "url": ep,
                "source": "raw"
            })
            
    # Add Kiterunner endpoints
    for item in kiterunner_data:
        u = item.get("url", "")
        if not any(r["path"] == u or r["url"] == u for r in flat_routes):
            subd = "Unknown"
            try: 
                from urllib.parse import urlparse
                subd = urlparse(u).netloc.split(':')[0]
            except: pass
            
            flat_routes.append({
                "subdomain": subd,
                "method": item.get("method", "GET"),
                "path": u,
                "url": u,
                "source": "kiterunner"
            })
            
    # Filtrar o GQL tambem
    graphql = [g for g in graphql if is_in_scope(g, target)]
            
    flat_routes = sorted(flat_routes, key=lambda x: (x["subdomain"], x["path"]))
    
    html_parts = []
    
    # 2. GraphQL
    if graphql:
        html_parts.append(f'''
        <div class="card" style="border-left: 4px solid var(--accent-purple);">
            <div class="card-header">
                <span class="card-title"> GraphQL Endpoints</span>
                <span class="card-badge">{len(graphql)} items</span>
            </div>
            <div class="card-content" style="display:block;">
                <pre>{html.escape(chr(10).join(graphql))}</pre>
            </div>
        </div>''')

    json_data = json.dumps(flat_routes).replace("</", "<\\/")
    
    html_parts.append(f'''
    <div class="card open" style="margin-top:20px;">
        <div class="card-header">
            <span class="card-title"> API Routes & Endpoints</span>
            <span class="card-badge">{len(flat_routes)} endpoints</span>
        </div>
        <div class="card-content" id="routes_container" style="display:block;"></div>
    </div>
    <script>
        setTimeout(function() {{
            initPaginatedTable(
                "routes_container", 
                {json_data}, 
                ["Subdomain", "Method", "Path", "Source"], 
                function(row) {{
                    let method_class = ["POST", "PUT", "DELETE"].includes(row.method) ? "tag-medium" : "tag-low";
                    return `<tr>
                        <td>${{escapeHtml(row.subdomain)}}</td>
                        <td><span class="tag ${{method_class}}">${{escapeHtml(row.method)}}</span></td>
                        <td style="word-break: break-all;"><a href="${{escapeHtml(row.url)}}" target="_blank">${{escapeHtml(row.path)}}</a></td>
                        <td>${{escapeHtml(row.source)}}</td>
                    </tr>`;
                }},
                100
            );
        }}, 0);
    </script>
    ''')
    
    return "".join(html_parts)


def build_js_content(target: str) -> str:
    import json
    base = Path("output") / target
    js_data = read_json_file(base / "domain" / "extracted_js.json")
    
    if not js_data:
        return '<div class="empty-state"><p>No JS files found</p></div>'
        
    def is_in_scope(url_str: str, target_domain: str) -> bool:
        if url_str.startswith('/'): return True
        try:
            from urllib.parse import urlparse
            host = urlparse(url_str).netloc.split(':')[0].lower()
            if not host: return True
            return target_domain in host
        except:
            return False

    flat_js = []
    for j in js_data:
        url_val = j.get("url", "")
        if not is_in_scope(url_val, target): continue
        
        flat_js.append({
            "subdomain": j.get("subdomain", "Unknown"),
            "url": url_val,
            "type": j.get("type", "external"),
            "size": j.get("size", 0)
        })
        
    json_data_str = json.dumps(flat_js).replace("</", "<\\/")
    
    html_parts = []
    html_parts.append(f'''
    <div class="card open" style="margin-top:20px;">
        <div class="card-header">
            <span class="card-title"> JavaScript Files</span>
            <span class="card-badge">{len(flat_js)} files</span>
        </div>
        <div class="card-content" id="js_container" style="display:block;"></div>
    </div>
    <script>
        setTimeout(function() {{
            initPaginatedTable(
                "js_container", 
                {json_data_str}, 
                ["Subdomain", "Filename", "Type", "Size", "Link"], 
                function(row) {{
                    let filename = row.url.split("/").pop() || row.url;
                    return `<tr>
                        <td>${{escapeHtml(row.subdomain)}}</td>
                        <td style="word-break: break-all;"><a href="${{escapeHtml(row.url)}}" target="_blank">${{escapeHtml(filename)}}</a></td>
                        <td><span class="tag tag-low">${{escapeHtml(row.type)}}</span></td>
                        <td>${{row.size}} bytes</td>
                        <td><a href="${{escapeHtml(row.url)}}" target="_blank" style="font-size:12px">View</a></td>
                    </tr>`;
                }},
                100
            );
        }}, 0);
    </script>
    ''')

    return "".join(html_parts)






def build_forms_content(target: str) -> str:
    """Mostra formulários descobertos pelo Katana"""
    base = Path("output") / target
    
    # Buscar em múltiplos locais possíveis
    forms_file = find_file(base,
        "crawlers/katana_forms_all.json",
        "domain/crawlers/katana_forms_all.json",
        "domain/katana_forms_all.json",
        "crawlers/katana_forms.json",
        "domain/crawlers/katana_forms.json"
    )
    
    if not forms_file.exists():
        return '<div class="empty-state"><p>No forms discovered. Run a scan with Katana to detect forms.</p></div>'
    
    try:
        forms = json.loads(forms_file.read_text())
    except:
        return '<div class="empty-state"><p>Error reading forms data</p></div>'
    
    if not forms:
        return '<div class="empty-state"><p>No forms found</p></div>'
    
    html_parts = []
    
    for form in forms:
        action = form.get("action", "Unknown")
        method = form.get("method", "GET")
        inputs = form.get("inputs", [])
        source = form.get("source_url", "")
        
        # Build inputs table
        inputs_html = ""
        if inputs:
            for inp in inputs[:10]:
                inp_name = inp.get("name", "unnamed")
                inp_type = inp.get("type", "text")
                inputs_html += f'<tr><td><code>{html.escape(inp_name)}</code></td><td><span class="tag tag-low">{html.escape(inp_type)}</span></td></tr>'
        
        # Method badge color
        method_class = "tag-high" if method.upper() == "POST" else "tag-low"
        
        html_parts.append(f'''
        <div class="card">
            <div class="card-header">
                <span class="card-title">{html.escape(action[:60])}</span>
                <span class="tag {method_class}">{method}</span>
            </div>
            <div class="card-content">
                <p><strong>Action:</strong> <a href="{action}" target="_blank">{html.escape(action)}</a></p>
                <p><strong>Found in:</strong> <a href="{source}" target="_blank">{html.escape(source[:50])}</a></p>
                {f'<p><strong>Inputs ({len(inputs)}):</strong></p><table><thead><tr><th>Name</th><th>Type</th></tr></thead><tbody>{inputs_html}</tbody></table>' if inputs_html else ''}
            </div>
        </div>
        ''')
    
    import json
    json_data = json.dumps(html_parts).replace("</", "<\\/")
    return f'''
    <div id="forms_container"></div>
    <script>
        setTimeout(function() {{
            initPaginatedTable("forms_container", {json_data}, [], function(row) {{ return row; }}, 100);
        }}, 0);
    </script>
    '''


def build_params_content(target: str) -> str:
    """Mostra parâmetros descobertos pelo Katana com suas URLs de origem"""
    base = Path("output") / target
    
    # Buscar em múltiplos locais possíveis
    params_file = find_file(base,
        "crawlers/katana_params_all.json",
        "domain/crawlers/katana_params_all.json",
        "domain/katana_params_all.json"
    )
    
    # Fallback para formato antigo txt
    if not params_file.exists():
        old_file = base / "crawlers" / "katana_params.txt"
        if not old_file.exists():
            old_file = base / "domain" / "crawlers" / "katana_params.txt"
        if old_file.exists():
            # Formato antigo - sem URLs
            params_list = read_file_lines(old_file)
            if params_list:
                return f'''
                <div class="card">
                    <div class="card-header"><span class="card-title">Parameters Found</span></div>
                    <div class="card-content">
                        <p style="color:var(--text-secondary);margin-bottom:12px;">(Run a new scan to see source URLs)</p>
                        <div style="display:flex;flex-wrap:wrap;gap:8px;">
                            {''.join([f'<span class="tag tag-low">{html.escape(p)}</span>' for p in params_list])}
                        </div>
                    </div>
                </div>'''
        return '<div class="empty-state"><p>No parameters discovered. Run a scan with Katana to detect params.</p></div>'
    
    # Ler JSON com param → [URLs]
    params_data = read_json_file(params_file) or {}
    
    # Adicionar hidden params da extração passiva
    hidden_params_file = base / "paramfuzz" / "hidden_params.json"
    hidden_params_data = read_json_file(hidden_params_file) or []
    
    # Mesclar hidden params no dicionário principal
    for hp in hidden_params_data:
        param_name = hp.get("param") or hp.get("name")
        url_context = hp.get("url") or hp.get("context", "Extracted passively")
        if param_name:
            if param_name not in params_data:
                params_data[param_name] = []
            if url_context not in params_data[param_name]:
                params_data[param_name].append(url_context)
    
    if not params_data:
        return '<div class="empty-state"><p>No parameters found</p></div>'
    
    # Padrões potencialmente sensíveis
    dangerous_patterns = ["id", "user", "pass", "token", "key", "auth", "admin", "file", "path", "url", "redirect", "callback", "next", "return", "query", "search", "cmd", "exec"]
    
    html_parts = []
    
    # Separar por sensibilidade
    dangerous = {}
    normal = {}
    
    for param, urls in params_data.items():
        if any(dp in param.lower() for dp in dangerous_patterns):
            dangerous[param] = urls
        else:
            normal[param] = urls
    
    # Params sensíveis primeiro (com detalhes)
    # Params sensíveis primeiro (com detalhes)
    dangerous_list = [{"param": p, "urls": urls} for p, urls in sorted(dangerous.items())]
    normal_list = [{"param": p, "urls": urls} for p, urls in sorted(normal.items())]
    
    import json
    dang_json = json.dumps(dangerous_list).replace("</", "<\\/")
    norm_json = json.dumps(normal_list).replace("</", "<\\/")
    
    if dangerous:
        html_parts.append(f'''
        <div class="card open" style="border-left:4px solid var(--accent-orange); margin-bottom: 20px;">
            <div class="card-header">
                <span class="card-title"> Potentially Sensitive Parameters</span>
                <span class="card-badge">{len(dangerous)} params</span>
            </div>
            <div class="card-content" id="params_dang_container" style="display:block;">
                <p style="color:var(--text-secondary);margin-bottom:12px;">These parameters may be interesting for testing (SQLi, auth bypass, IDOR, LFI, etc.)</p>
            </div>
        </div>
        <script>
            setTimeout(function() {{
                initPaginatedTable("params_dang_container", {dang_json}, ["Parameter", "Found In"], function(row) {{
                    let url_list = row.urls.map(u => `<a href="${{escapeHtml(u)}}" target="_blank" style="color:var(--accent-blue);font-size:11px;">${{escapeHtml(u.substring(0,60))}}</a>`).join("<br>");
                    return `<tr>
                        <td style="width:150px;"><code style="color:var(--accent-orange);background:#2d2d2d;padding:2px 6px;border-radius:4px;">${{escapeHtml(row.param)}}</code></td>
                        <td style="font-size:12px;">${{url_list}}</td>
                    </tr>`;
                }}, 50);
            }}, 0);
        </script>
        ''')
    
    # Params normais (resumidos)
    if normal:
        html_parts.append(f'''
        <div class="card">
            <div class="card-header">
                <span class="card-title">All Parameters</span>
                <span class="card-badge">{len(normal)} params</span>
            </div>
            <div class="card-content" id="params_norm_container" style="display:block;"></div>
        </div>
        <script>
            setTimeout(function() {{
                initPaginatedTable("params_norm_container", {norm_json}, ["Parameter", "Found In"], function(row) {{
                    let first_url = row.urls.length > 0 ? row.urls[0] : "Unknown";
                    let extra = row.urls.length > 1 ? ` (+${{row.urls.length - 1}} more)` : "";
                    return `<tr>
                        <td style="width:150px;"><code style="background:#2d2d2d;padding:2px 6px;border-radius:4px;">${{escapeHtml(row.param)}}</code></td>
                        <td><a href="${{escapeHtml(first_url)}}" target="_blank" style="color:var(--accent-blue);font-size:11px;">${{escapeHtml(first_url.substring(0,50))}}</a>${{extra}}</td>
                    </tr>`;
                }}, 100);
            }}, 0);
        </script>
        ''')
        
    return "".join(html_parts)
    
def build_cloud_content(target: str) -> str:
    base = Path("output") / target
    buckets_file = base / "cloud" / "buckets.txt"
    
    if not buckets_file.exists():
        return '<div class="empty-state"><p>No cloud buckets found</p></div>'
        
    lines = read_file_lines(buckets_file)
    if not lines:
        return '<div class="empty-state"><p>No cloud buckets found</p></div>'
        
    rows = ""
    for line in lines:
        # Format: Provider \t Name \t Status \t URL \t Permissions
        if not line.strip(): continue
        parts = line.split("\t")
        if len(parts) < 4: continue
        
        provider, name, status, url = parts[:4]
        perms = parts[4] if len(parts) > 4 else ""
        
        status_class = "tag-green" if status == "OPEN" else "tag-orange" if status == "PROTECTED" else "tag-low"
        
        perms_html = ""
        if perms:
            for p in perms.split(","):
                p = p.strip()
                p_class = "tag-high" if p == "WRITE" else "tag-medium" if p == "LIST" else "tag-low"
                perms_html += f'<span class="tag {p_class}" style="margin-right:4px;">{p}</span>'
        else:
            perms_html = '<span class="tag tag-low">N/A</span>'
        
        rows += f'''
        <tr>
            <td><strong>{html.escape(provider)}</strong></td>
            <td>{html.escape(name)}</td>
            <td><span class="tag {status_class}">{status}</span></td>
            <td><a href="{url}" target="_blank">{html.escape(url)}</a></td>
            <td>{perms_html}</td>
        </tr>'''
        
    cloud_enum_html = ""
    ce_file = base / "cloud" / "cloud_enum_results.json"
    if ce_file.exists():
        try:
            ce_data = read_json_file(ce_file)
            if ce_data:
                cloud_enum_html = f'''
                <div class="card open" style="margin-top: 20px; border-left: 4px solid var(--accent-blue);">
                    <div class="card-header"><span class="card-title">Cloud_enum Extra Findings</span></div>
                    <div class="card-content">
                        <pre style="background:var(--bg-primary); padding:10px; border-radius:4px; max-height:400px; overflow-y:auto; font-size:12px;">{html.escape(json.dumps(ce_data, indent=2))}</pre>
                    </div>
                </div>
                '''
        except:
            pass

    return f'''
    <div class="card open">
        <div class="card-header">
            <span class="card-title">Cloud Buckets</span>
            <span class="card-badge">{len(lines) if lines else 0} discovered</span>
        </div>
        <div class="card-content">
            <div class="table-wrapper">
                <table>
                    <thead><tr><th>Provider</th><th>Bucket Name</th><th>Status</th><th>URL</th><th>Permissions</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>
    </div>
    {cloud_enum_html}
    '''

def build_cve_content(subdomains: Dict) -> str:
    """Gera a aba de vulnerabilidades detalhada e priorizada"""
    
    # Coletar subdominios vulneraveis
    vuln_hosts = []
    
    for host, data in subdomains.items():
        vulnerable_techs = [t for t in data["technologies"] if t.get("cve_count", 0) > 0]
        if vulnerable_techs:
            vuln_hosts.append({
                "host": host,
                "techs": vulnerable_techs
            })
            
    if not vuln_hosts:
        return '<div class="empty-state"><p>No potential vulnerabilities correlated.</p></div>'
        
    html_parts = []
    
    # Contadores de resumo
    total_exploits_count = sum([sum([t.get("cve_count", 0) for t in h["techs"]]) for h in vuln_hosts])
    high_priority_count = sum([len([t for t in h["techs"] if t.get("cve_priority") == "high"]) for h in vuln_hosts])
    
    # Resumo
    html_parts.append(f'''
    <div class="stats-grid" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); margin-bottom: 20px;">
        <div class="stat-card danger">
            <div class="value">{total_exploits_count}</div>
            <div class="label">Total Potential Exploits</div>
        </div>
        <div class="stat-card" style="border-left: 3px solid var(--accent-red);">
            <div class="value">{high_priority_count}</div>
            <div class="label">High Priority (Version Match)</div>
        </div>
        <div class="stat-card warning">
            <div class="value">{len(vuln_hosts)}</div>
            <div class="label">Vulnerable Subdomains</div>
        </div>
    </div>
    ''')
    
    # Listar hosts (Priorizar os que tem High Priority techs)
    vuln_hosts.sort(key=lambda h: max([2 if t.get("cve_priority") == "high" else 1 for t in h["techs"]]), reverse=True)
    
    for item in vuln_hosts:
        host = item["host"]
        techs = item["techs"]
        
        # Order techs: High priority first
        techs.sort(key=lambda t: (t.get("cve_priority") != "high", -t.get("cve_count", 0)))
        
        tech_rows = ""
        for t in techs:
            prio = t.get("cve_priority", "low")
            if prio == "low": continue # Skip generic matches as requested by user
            
            prio_badge = '<span class="tag tag-high">HIGH PRIORITY</span>' if prio == "high" else '<span class="tag tag-medium">Medium</span>' if prio == "medium" else '<span class="tag tag-low">Generic Match</span>'
            prio_style = 'border-left: 3px solid var(--accent-red);' if prio == "high" else ''
            
            # Exploits list (collapsible details)
            exploits_html = ""
            for exp in t.get("cve_exploits", []):
                title = exp.get("Title", "Unknown")
                edb_id = exp.get("EDB-ID", "?")
                type_ = exp.get("Type", "remote")
                
                exploits_html += f'''
                <div style="padding: 4px 0; border-bottom: 1px solid var(--border-color); display:flex; justify-content:space-between; align-items:center;">
                    <span style="font-size:12px; color:var(--text-primary);">{html.escape(title)}</span>
                    <div>
                        <span class="tag tag-low">{type_}</span>
                        <a href="https://www.exploit-db.com/exploits/{edb_id}" target="_blank" style="font-size:11px; margin-left:8px;">EDB-{edb_id}</a>
                    </div>
                </div>
                '''
            
            details_id = f"exp-{host}-{t['name']}".replace(".", "-").replace(" ", "")
            
            tech_rows += f'''
            <div style="background:var(--bg-primary); border:1px solid var(--border-color); border-radius:4px; margin-bottom:8px; {prio_style}">
                <div style="padding:10px; display:flex; justify-content:space-between; align-items:center; cursor:pointer;" onclick="document.getElementById('{details_id}').style.display = document.getElementById('{details_id}').style.display === 'none' ? 'block' : 'none'">
                    <div>
                        <span style="font-weight:600; color:var(--text-primary); margin-right:8px;">{html.escape(t["name"])} {html.escape(str(t.get("version") or ""))}</span>
                        {prio_badge}
                    </div>
                    <div>
                        <span class="tag tag-high" style="background:#3d1d1f; color:#ffa198;">{t.get("cve_count")} Exploits ▼</span>
                    </div>
                </div>
                <div id="{details_id}" style="display:none; padding:10px; border-top:1px solid var(--border-color); background:var(--bg-secondary);">
                    {exploits_html}
                </div>
            </div>
            '''
            
        html_parts.append(f'''
        <div class="card">
            <div class="card-header">
                <span class="card-title">{html.escape(host)}</span>
                <span class="card-badge">{len(techs)} vulnerable technologies</span>
            </div>
            <div class="card-content" style="display:block;">
                {tech_rows}
            </div>
        </div>
        ''')
        
    return "".join(html_parts)



def build_security_content(target: str) -> str:
    """Consolida XSS, CORS, Headers e outros security checks."""
    base = Path("output") / target
    html_parts = []
    
    # -------------------------------------------------------------------------
    # 1. XSS Report
    # -------------------------------------------------------------------------
    xss_dir = base / "xss"
    if xss_dir.exists():
        xss_final = xss_dir / "final_report.txt"
        
        if xss_final.exists():
            content = xss_final.read_text(errors="ignore")
            # Filter out the TOP 10 FINDINGS section and everything after it if it's at the end
            if "=== TOP 10" in content:
                content = content.split("=== TOP 10")[0]
            
            if content.strip():
                formatted_content = html.escape(content.strip())
                formatted_content = formatted_content.replace("Vulnerable:", f'<span style="color:#f85149; font-weight:bold;">Vulnerable:</span>')
                formatted_content = formatted_content.replace("[POC]", f'<span style="background:#238636; color:#fff; padding:2px 6px; border-radius:4px; font-size:11px;">POC</span>')
                
                html_parts.append(f'''
                <div class="card" style="border-left: 3px solid var(--accent-red);">
                    <div class="card-header">
                        <span class="card-title"> Passive XSS Vulnerabilities</span>
                    </div>
                    <div class="card-content" style="display:block;">
                        <pre>{formatted_content}</pre>
                    </div>
                </div>''')

    # Dalfox Active Scan (V10.2 integration)
    dalfox_out = base / "xss" / "dalfox_results.txt"
    if dalfox_out.exists():
        content = dalfox_out.read_text(errors="ignore").strip()
        if content:
            formatted_content = html.escape(content)
            html_parts.append(f'''
            <div class="card" style="border-left: 3px solid #f85149; margin-top: 15px;">
                <div class="card-header">
                    <span class="card-title"> Dalfox Active XSS Scan</span>
                </div>
                <div class="card-content" style="display:block;">
                    <pre>{formatted_content}</pre>
                </div>
            </div>''')

    # -------------------------------------------------------------------------
    # 2. CORS Misconfigurations
    # -------------------------------------------------------------------------
    html_parts.append(build_cors_content(target))

    # -------------------------------------------------------------------------
    # 3. Security Headers
    # -------------------------------------------------------------------------
    html_parts.append(build_headers_content(target))

    # 4. New Plugins (Open Redirect, SSRF, Cache Deception)
    html_parts.append(build_open_redirect_content(target))
    html_parts.append(build_ssrf_content(target))
    html_parts.append(build_cache_deception_content(target))
    
    # 5. Hidden Plugins Prioritized (JWT, Kiterunner, Insecure Deserialization, GraphQL)
    html_parts.append(build_jwt_content(target))
    html_parts.append(build_kiterunner_content(target))
    html_parts.append(build_deser_content(target))
    html_parts.append(build_graphql_content(target))

    # Clean up empty strings
    html_parts = [p for p in html_parts if p]

    if not html_parts:
        return '<div class="empty-state"><p>No security issues found (XSS, CORS, Headers).</p></div>'
        
    return "".join(html_parts)


# ------------------------------------------------------------
# New Builders (CORS, Takeover, Headers, WAF, Emails)
# ------------------------------------------------------------
def build_kiterunner_content(target: str) -> str:
    path = Path("output") / target / "api_fuzzer" / "kiterunner_results.json"
    data = read_json_file(path)
    if not data:
        return ""
    
    rows = ""
    for item in data:
        status = item.get("status", 0)
        status_color = "var(--accent-green)" if 200 <= status < 300 else "var(--accent-orange)" if 300 <= status < 400 else "var(--accent-red)"
        
        rows += f'''
        <tr>
            <td><strong style="color:var(--accent-purple)">{html.escape(item.get("method", "GET"))}</strong></td>
            <td><code>{html.escape(item.get("url", ""))}</code></td>
            <td><span class="tag" style="background:{status_color}; color:#fff">{status}</span></td>
            <td style="font-size:12px;">{item.get("words", 0)} words, {item.get("lines", 0)} lines</td>
        </tr>
        '''
        
    return f'''
    <div class="card open" style="border-left: 4px solid var(--accent-purple); margin-top: 15px;">
        <div class="card-header">
            <span class="card-title"> Kiterunner (API Fuzzer) Hidden Endpoints</span>
            <span class="card-badge tag-high">{len(data)} routes</span>
        </div>
        <div class="card-content" style="display:block;">
            <p style="font-size:13px; color:var(--text-secondary); margin-bottom:10px;">
                Estas rotas de API não estavam visíveis nos crawlers ou links, mas foram descobertas via Fuzzing intensivo do Kiterunner.
            </p>
            <div class="table-wrapper">
                <table>
                    <thead><tr><th>Method</th><th>Endpoint URL</th><th>Status</th><th>Response Length</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>
    </div>
    '''
def build_cors_content(target: str) -> str:
    path = Path("output") / target / "cors" / "cors_results.json"
    data = read_json_file(path)
    if not data:
        return ""

    rows = ""
    for item in data:
        sev = item.get("severity", "info").lower()
        sev_class = "tag-high" if sev in ("critical", "high") else "tag-medium" if sev == "medium" else "tag-low"
        
        creds = '<span class="tag tag-high">Credentials</span>' if item.get("credentials") else ""
        
        # Prepare Burp Data
        req_b64 = base64.b64encode((item.get("request_raw") or "").encode("utf-8")).decode("utf-8")
        res_b64 = base64.b64encode((item.get("response_raw") or "").encode("utf-8")).decode("utf-8")
        row_id = f"cors_{uuid.uuid4().hex[:8]}"
        
        burp_script_data = f'<script>BURP_DATA["{row_id}"] = {{ "url": "{html.escape(item.get("url", ""))}", "req": "{req_b64}", "res": "{res_b64}" }};</script>'

        rows += f'''
        <tr>
            <td><span class="tag {sev_class}">{sev.upper()}</span></td>
            <td><a href="{html.escape(item.get("url", ""))}" target="_blank">{html.escape(item.get("url", ""))}</a></td>
            <td>
                {html.escape(item.get("issue", ""))}
                {creds}
            </td>
            <td style="text-align:right;">
                <button class="burp-btn" onclick="openBurp('{row_id}')">View HTTP</button>
                {burp_script_data}
            </td>
        </tr>
        '''

    return f'''
    <div class="card" style="border-left: 3px solid var(--accent-orange);">
        <div class="card-header">
            <span class="card-title"> CORS Misconfigurations</span>
            <span class="card-badge warning">{len(data)} issues</span>
        </div>
        <div class="card-content" style="display:block;">
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th width="80">Severity</th>
                            <th>URL</th>
                            <th>Issue</th>
                            <th width="100" style="text-align:right;">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    '''

    # Corsy Output Integration (V10.2)
    corsy_file = Path("output") / target / "cors" / "corsy_output.txt"
    if corsy_file.exists():
        content = corsy_file.read_text(errors="ignore").strip()
        if content:
            # Strip ANSI escape codes
            import re
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            clean_content = ansi_escape.sub('', content)
            
            output += f'''
            <div class="card" style="border-left: 3px solid #bf8700; margin-top: 15px;">
                <div class="card-header">
                    <span class="card-title"> Corsy Active Findings</span>
                </div>
                <div class="card-content" style="display:block;">
                    <pre>{html.escape(clean_content)}</pre>
                </div>
            </div>
            '''
    
    return output


def build_headers_content(target: str) -> str:
    path = Path("output") / target / "headers" / "headers_results.json"
    data = read_json_file(path)
    if not data:
        return ""

    rows = ""
    # Sort by grade (C, D, E, F first)
    data.sort(key=lambda x: x.get("score", 100))

    for item in data:
        grade = item.get("grade", "?")
        score = item.get("score", 0)
        grade_color = "#3fb950" if grade.startswith("A") else "#d29922" if grade in ("B", "C") else "#f85149"
        
        missing = item.get("missing", [])
        missing_badges = ""
        for m in missing[:5]: # Show top 5
             missing_badges += f'<span class="tag tag-high" title="{html.escape(m.get("desc", ""))}" style="margin-bottom:2px;">{m["header"]}</span> '
        if len(missing) > 5:
             missing_badges += f'<span class="tag tag-low">+{len(missing)-5} more</span>'

        warnings = item.get("warnings", [])
        warnings_html = ""
        if warnings:
            warnings_html = "<br>".join([f'<span style="color:#f85149; font-size:11px;"> {w}</span>' for w in warnings])
            if warnings_html:
                 warnings_html = f'<div style="margin-top:4px;">{warnings_html}</div>'

        present_count = item.get("present_count", 0)
        
        # Prepare Burp Data
        req_b64 = base64.b64encode((item.get("request_raw") or "").encode("utf-8")).decode("utf-8")
        res_b64 = base64.b64encode((item.get("response_raw") or "").encode("utf-8")).decode("utf-8")
        row_id = f"headers_{uuid.uuid4().hex[:8]}"
        
        burp_script_data = f'<script>BURP_DATA["{row_id}"] = {{ "url": "{html.escape(item.get("url", ""))}", "req": "{req_b64}", "res": "{res_b64}" }};</script>'

        rows += f'''
        <tr>
            <td style="text-align:center; vertical-align:top;">
                <div style="background:{grade_color}; color:#fff; border-radius:4px; padding:4px 8px; font-weight:700; font-size:14px; width:40px; margin:0 auto;">{grade}</div>
                <div style="font-size:10px; margin-top:4px; font-weight:600;">{score}%</div>
            </td>
            <td style="vertical-align:top;">
                <a href="{html.escape(item.get("url", ""))}" target="_blank" style="font-weight:600; font-size:13px; color:var(--text-primary);">{html.escape(item.get("url", ""))}</a>
                <div style="font-size:11px; color:var(--text-secondary); margin-top:2px;">Status: <span class="tag tag-medium">{item.get("status")}</span></div>
                {warnings_html}
            </td>
            <td style="vertical-align:top;">
                <div style="margin-bottom:6px;">
                    <span style="font-size:11px; font-weight:600; color:var(--text-secondary);">MISSING HEADERS:</span><br>
                    {missing_badges}
                </div>
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div style="font-size:11px; color:#3fb950;">
                         {present_count} security headers present
                    </div>
                    <div>
                        <button class="burp-btn" onclick="openBurp('{row_id}')">View HTTP</button>
                        {burp_script_data}
                    </div>
                </div>
            </td>
        </tr>
        '''
    
    avg_score = sum(d.get("score", 0) for d in data) / len(data) if data else 0
    
    #  Django Debug Mode Alerts
    django_debug_file = Path("output") / target / "fingerprint" / "django_debug_alerts.txt"
    django_html = ""
    if django_debug_file.exists():
        django_hosts = [l.strip() for l in django_debug_file.read_text(errors="ignore").splitlines() if l.strip()]
        if django_hosts:
            items = "".join([f'<li><a href="http://{h}" target="_blank" style="color:#ff7b72;">{h}</a></li>' for h in django_hosts])
            django_html = f'''
            <div class="card open" style="border-left: 4px solid var(--accent-red); margin-bottom: 20px;">
                <div class="card-header">
                    <span class="card-title"> HIGH RISK: Django Debug Mode Enabled</span>
                    <span class="card-badge tag-critical">{len(django_hosts)} hosts</span>
                </div>
                <div class="card-content" style="display:block;">
                    <p style="font-size:13px; color:var(--text-secondary); margin-bottom:10px;">
                        The following hosts have Django Debug Mode enabled, exposing sensitive configuration, code pathways, and environment variables via forced 404/500 errors.
                    </p>
                    <ul style="list-style-type:none; padding:10px;">
                        {items}
                    </ul>
                </div>
            </div>
            '''

    return f'''
    {django_html}
    <div class="card">
        <div class="card-header">
            <span class="card-title"> Security Headers Analysis</span>
            <span class="card-badge">Avg Score: {int(avg_score)}%</span>
        </div>
        <div class="card-content">
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th width="60" style="text-align:center;">Grade</th>
                            <th>URL & Warnings</th>
                            <th>Security Headers Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    '''


def build_takeover_content(target: str) -> str:
    path = Path("output") / target / "takeover" / "takeover_results.json"
    data = read_json_file(path)
    if not data:
        return '<div class="empty-state"><p>No subdomain takeovers detected.</p></div>'

    rows = ""
    for item in data:
        status = item.get("status", "POTENTIAL")
        style = "tag-high" if status == "VULNERABLE" else "tag-medium"
        
        rows += f'''
        <tr>
            <td><span class="tag {style}">{status}</span></td>
            <td><strong>{html.escape(item.get("subdomain", ""))}</strong></td>
            <td><code>{html.escape(item.get("cname", ""))}</code></td>
            <td>{html.escape(item.get("service", ""))}</td>
            <td>{item.get("severity", "").upper()}</td>
        </tr>
        '''

    return f'''
    <div class="card" style="border-left: 3px solid var(--accent-red);">
        <div class="card-header">
            <span class="card-title"> Subdomain Takeover Candidates</span>
            <span class="card-badge warning">{len(data)} found</span>
        </div>
        <div class="card-content" style="display:block;">
            <p style="margin-bottom:16px; color:var(--text-secondary);">
                Subdomains pointing to external services (CNAME) that may be unclaimed or expired.
                <strong>Verify manually before reporting.</strong>
            </p>
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>Status</th>
                            <th>Subdomain</th>
                            <th>CNAME / Target</th>
                            <th>Service</th>
                            <th>Severity</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    '''


def build_waf_content(target: str) -> str:
    path = Path("output") / target / "waf" / "waf_results.json"
    data = read_json_file(path)
    if not data:
        return '<div class="empty-state"><p>No WAF detected.</p></div>'

    # Statistics
    waf_counts = {}
    for item in data:
        name = item.get("primary_waf", "Unknown")
        waf_counts[name] = waf_counts.get(name, 0) + 1

    stats_html = '<div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:16px;">'
    for name, count in sorted(waf_counts.items(), key=lambda x: x[1], reverse=True):
        stats_html += f'<div style="background:var(--bg-tertiary); padding:6px 12px; border-radius:20px; font-size:13px; border:1px solid var(--border-color);"><strong>{name}</strong>: {count}</div>'
    stats_html += '</div>'

    rows = ""
    for item in data:
        matches = item.get("waf_detected", [{}])[0].get("matches", [])
        match_str = ", ".join(matches[:3])
        if len(matches) > 3: range_str = f" +{len(matches)-3} more"
        else: range_str = ""

        rows += f'''
        <tr>
            <td><span class="tag tag-port">{html.escape(item.get("primary_waf", ""))}</span></td>
            <td><a href="{html.escape(item.get("url", ""))}" target="_blank">{html.escape(item.get("url", ""))}</a></td>
            <td><span class="tag tag-medium">{item.get("status", "N/A")}</span></td>
            <td style="font-size:11px; color:var(--text-secondary);">{html.escape(match_str)}{range_str}</td>
        </tr>
        '''

    return f'''
    {stats_html}
    <div class="card">
        <div class="card-header">
            <span class="card-title"> Detected WAFs via Fingerprinting</span>
            <span class="card-badge">{len(data)} detected</span>
        </div>
        <div class="card-content" style="display:block;">
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>WAF Name</th>
                            <th>URL</th>
                            <th>Status</th>
                            <th>Evidence</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    '''


def build_emails_content(target: str) -> str:
    path = Path("output") / target / "emails" / "emails.json"
    data = read_json_file(path)
    if not data:
        return '<div class="empty-state"><p>No emails found.</p></div>'
    
    internal = data.get("internal", [])
    external = data.get("external", [])
    
    def render_table(email_list, title):
        if not email_list: return ""
        r_rows = ""
        for e in email_list:
            sources = ", ".join([str(s).split("/")[-1] for s in e.get("sources", [])[:2]])
            r_rows += f'<tr><td>{html.escape(e.get("email"))}</td><td>{html.escape(e.get("domain"))}</td><td style="color:var(--text-secondary);font-size:11px;">{html.escape(sources)}</td></tr>'
        
        return f'''
        <div class="card">
            <div class="card-header">
                <span class="card-title">{title}</span>
                <span class="card-badge">{len(email_list)}</span>
            </div>
            <div class="card-content" style="display:block;">
                <div class="table-wrapper">
                    <table>
                        <thead><tr><th>Email</th><th>Domain</th><th>Source Files</th></tr></thead>
                        <tbody>{r_rows}</tbody>
                    </table>
                </div>
            </div>
        </div>
        '''

    return f'''
    <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 16px;">
        <div>{render_table(internal, " Internal / Target Emails")}</div>
        <div>{render_table(external, " External / Third-party Emails")}</div>
    </div>
    '''


def build_admin_content(target: str) -> str:
    base = Path("output") / target
    admin_data = read_json_file(base / "admin" / "admin_panels.json")
    
    if not admin_data:
        return '<div class="empty-state"><p>No admin panels discovered</p></div>'
    
    # Ordenar: 200 primeiro, depois outros status
    # Sort logic with safe integer conversion for statuses that might be strings (e.g., "ERROR", "TIMEOUT")
    def safe_status(p):
        s = p.get("status")
        try:
            return int(s) if s is not None else 999
        except (ValueError, TypeError):
            return 999
            
    admin_data.sort(key=lambda p: (0 if safe_status(p) == 200 else 1, safe_status(p)))
    
    rows = ""
    for panel in admin_data:
        status = panel.get("status", 0)
        status_class = "tag-high" if status == 200 else "tag-medium" if status in (401, 403) or "BYPASS" in str(status) else "tag-low"
        title = panel.get("title", "")[:60]
        cms = panel.get("cms", "")
        login_icon = "" if panel.get("has_login_form") else ""
        url = panel.get("url", "")
        
        cms_html = f'<span class="tag tag-low" style="margin-left:4px;">{html.escape(cms)}</span>' if cms else ""
        
        # Prepare Burp Data if bypass found
        burp_html = ""
        if "BYPASS" in str(status) and panel.get("raw_request"):
            req_b64 = panel.get("raw_request", "")
            res_b64 = panel.get("raw_response", "")
            row_id = f"admin_{uuid.uuid4().hex[:8]}"
            
            bypass_methods = panel.get("bypass_methods", [])
            info_text = "Métodos de Bypass Encontrados:\\n" + "\\n".join(f"- {m}" for m in bypass_methods) if bypass_methods else ""
            import json
            info_json = json.dumps(info_text) if info_text else '""'
            
            burp_script = f'<script>BURP_DATA["{row_id}"] = {{ "url": "{html.escape(url)}", "req": "{req_b64}", "res": "{res_b64}", "info": {info_json} }};</script>'
            burp_html = f'''
            <div style="margin-top:5px; display:inline-flex; align-items:center;">
                <button class="burp-btn" onclick="openBurp('{row_id}')">View HTTP Bypass</button>
                {burp_script}
            </div>
            '''
        
        rows += f'''
        <tr>
            <td><a href="{html.escape(url)}" target="_blank">{html.escape(url[:80])}</a></td>
            <td><span class="tag {status_class}">{status}</span></td>
            <td>{html.escape(title)}</td>
            <td>
                {login_icon}{cms_html}
                {burp_html}
            </td>
        </tr>'''
    
    return f'''
    <div class="card open">
        <div class="card-header">
            <span class="card-title">Admin Panels Discovered</span>
            <span class="card-badge">{len(admin_data)} found</span>
        </div>
        <div class="card-content">
            <div class="table-wrapper">
                <table>
                    <thead><tr><th>URL</th><th>Status</th><th>Title</th><th>CMS / Login / Actions</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>
    </div>
    '''


def build_depconfusion_content(target: str) -> str:
    base = Path("output") / target
    dep_data = read_json_file(base / "depconfusion" / "depconfusion.json")
    
    if not dep_data:
        return '<div class="empty-state"><p>No dependency confusion risks found</p></div>'
    
    high_risk = [d for d in dep_data if d.get("risk") == "HIGH"]
    
    rows = ""
    for dep in dep_data:
        risk = dep.get("risk", "UNKNOWN")
        risk_class = "tag-high" if risk == "HIGH" else "tag-medium" if risk == "UNKNOWN" else "tag-low"
        npm_exists = dep.get("npm_exists")
        npm_badge = ' Exists' if npm_exists is True else ' NOT FOUND' if npm_exists is False else '? Unknown'
        npm_class = "tag-low" if npm_exists else "tag-high"
        
        rows += f'''
        <tr>
            <td><code style="color:var(--accent-orange);">{html.escape(dep.get("package", ""))}</code></td>
            <td><span class="tag {npm_class}">{npm_badge}</span></td>
            <td><span class="tag {risk_class}">{risk}</span></td>
            <td style="font-size:12px;">{html.escape(str(dep.get("found_in", ""))[:60])}</td>
            <td style="font-size:12px;">{html.escape(dep.get("note", "")[:80])}</td>
        </tr>'''
    
    alert_html = ""
    if high_risk:
        alert_html = f'<p style="color:var(--accent-red); margin-bottom:12px;"><strong> {len(high_risk)} packages NOT FOUND on npm — potential dependency confusion targets!</strong></p>'
    
    return f'''
    <div class="card open">
        <div class="card-header">
            <span class="card-title">Dependency Confusion Analysis</span>
            <span class="card-badge">{len(dep_data)} packages</span>
        </div>
        <div class="card-content">
            {alert_html}
            <div class="table-wrapper">
                <table>
                    <thead><tr><th>Package</th><th>npm Status</th><th>Risk</th><th>Found In</th><th>Note</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>
    </div>
    '''




# ------------------------------------------------------------

def build_js_routes_content(target: str) -> str:
    path = Path("output") / target / "jsscanner" / "js_routes.json"
    data = read_json_file(path)
    if not data: return '<div class="empty-state"><p>No API/JS routes found.</p></div>'
    
    def is_in_scope(url_str: str, target_domain: str) -> bool:
        if url_str.startswith('/'): return True
        try:
            from urllib.parse import urlparse
            host = urlparse(url_str).netloc.split(':')[0].lower()
            if not host: return True
            return target_domain in host
        except:
            return False

    html_content = ""
    for item in data:
        source = item.get("source", "")
        # Ignora se o arquivo JS origem estiver debulhando rotas externas
        if source and not is_in_scope(source, target):
            continue
            
        routes = item.get("routes", [])
        params = item.get("parameters", [])
        
        # Filtra rotas caso existam URLs absolutas de outros dominios mixadas
        routes = [r for r in routes if is_in_scope(r, target) or r.startswith('/')]
        
        # Se não tiver mais rotas nem params úteis, ignora
        if not routes and not params:
            continue
            
        routes_html = "".join([f'<li><code style="color:var(--accent-green);">{html.escape(r)}</code></li>' for r in routes])
        params_html = "".join([f'<li><code style="color:var(--accent-purple);">{html.escape(p)}</code></li>' for p in params])
        
        html_content += f'''
        <div class="card open">
            <div class="card-header">
                <span class="card-title"> <a href="{html.escape(source)}" target="_blank" style="color:inherit;text-decoration:none;">{html.escape(source[:70] + '...' if len(source) > 70 else source)}</a></span>
                <span class="card-badge">{len(routes)} routes, {len(params)} params</span>
            </div>
            <div class="card-content" style="display:flex; gap: 20px;">
                <div style="flex:1;">
                    <h4>API Routes</h4>
                    <ul style="list-style-type: none; padding: 0;">{routes_html or '<li>None</li>'}</ul>
                </div>
                <div style="flex:1;">
                    <h4>Parameters</h4>
                    <ul style="list-style-type: none; padding: 0;">{params_html or '<li>None</li>'}</ul>
                </div>
            </div>
        </div>
        '''
        
    if not html_content:
        return '<div class="empty-state"><p>No relevant in-scope API/JS routes found.</p></div>'
        
    return html_content

def build_swagger_content(target: str) -> str:
    path = Path("output") / target / "domain" / "swagger_docs.json"
    data = read_json_file(path)
    if not data: return '<div class="empty-state"><p>No Swagger/OpenAPI docs found.</p></div>'
    
    rows = ""
    for endpoint in data:
        method = endpoint.get("method", "GET")
        method_color = "var(--accent-green)" if method == "GET" else "var(--accent-blue)" if method == "POST" else "var(--accent-orange)"
        
        params = endpoint.get("parameters", [])
        params_str = ", ".join([f"{p.get('name')} ({p.get('in')})" for p in params])
        
        rows += f'''
        <tr>
            <td><strong style="color:{method_color}">{method}</strong></td>
            <td><code>{html.escape(endpoint.get("path", ""))}</code></td>
            <td>{html.escape(endpoint.get("summary", ""))}</td>
            <td style="font-size:12px;">{html.escape(params_str)}</td>
        </tr>
        '''
        
    return f'''
    <div class="card open" style="border-left: 4px solid var(--accent-blue);">
        <div class="card-header">
            <span class="card-title"> Swagger/OpenAPI Endpoints</span>
            <span class="card-badge">{len(data)} endpoints</span>
        </div>
        <div class="card-content">
            <div class="table-wrapper">
                <table>
                    <thead><tr><th>Method</th><th>Path</th><th>Summary</th><th>Parameters</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>
    </div>
    '''


def build_logic_content(target: str) -> str:
    from pathlib import Path
    import html
    import base64
    import uuid
    path = Path("output") / target / "scanners" / "logic_flaws.json"
    data = read_json_file(path)
    if not data: return '<div class="empty-state"><p>No logic or smuggling flaws detected.</p></div>'
    
    rows = ""
    for item in data:
        risk = item.get("risk", "LOW")
        risk_class = f"tag-{risk.lower()}"
        
        req_b64 = base64.b64encode((item.get("request_raw") or "").encode("utf-8")).decode("utf-8")
        res_b64 = base64.b64encode((item.get("response_raw") or "").encode("utf-8")).decode("utf-8")
        row_id = f"logic_{uuid.uuid4().hex[:8]}"
        burp_script_data = f'<script>BURP_DATA["{row_id}"] = {{ "url": "{html.escape(item.get("url", ""))}", "req": "{req_b64}", "res": "{res_b64}" }};</script>'
        
        button_html = f'<button class="burp-btn" onclick="openBurp(\'{row_id}\')">View HTTP</button>{burp_script_data}' if req_b64 else ''
        
        rows += f'''
        <tr>
            <td><span class="tag {risk_class}">{risk}</span></td>
            <td><strong>{html.escape(item.get("type", ""))}</strong></td>
            <td><a href="{html.escape(item.get("url", ""))}" target="_blank">{html.escape(item.get("url", ""))}</a></td>
            <td style="font-size:12px;">{html.escape(item.get("details", ""))}</td>
            <td style="text-align:right;">{button_html}</td>
        </tr>
        '''
    return f'''
    <div class="card open" style="border-left: 4px solid var(--accent-red);">
        <div class="card-header">
            <span class="card-title"> Logic & Smuggling Flaws</span>
            <span class="card-badge">{len(data)} flaws</span>
        </div>
        <div class="card-content" style="display:block;">
            <div class="table-wrapper">
                <table>
                    <thead><tr><th>Risk</th><th>Vulnerability Type</th><th>URL</th><th>Details</th><th>Request</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>
    </div>
    '''

def build_git_content(target: str) -> str:
    path = Path("output") / target / "domain" / "git_exposed.json"
    data = read_json_file(path)
    if not data: return '<div class="empty-state"><p>No exposed Git repositories or CI/CD files found.</p></div>'
    
    rows = ""
    for item in data:
        secrets = item.get("secrets_found", [])
        secrets_html = "<br>".join([f'&#8226; <span class="tag tag-high">{s.get("type")}</span> <code>{html.escape(s.get("match", ""))}</code>' for s in secrets])
        
        # Prepare Burp Data
        req_b64 = base64.b64encode((item.get("request_raw") or "").encode("utf-8")).decode("utf-8")
        res_b64 = base64.b64encode((item.get("response_raw") or "").encode("utf-8")).decode("utf-8")
        row_id = f"git_{uuid.uuid4().hex[:8]}"
        burp_script_data = f'<script>BURP_DATA["{row_id}"] = {{ "url": "{html.escape(item.get("url", ""))}", "req": "{req_b64}", "res": "{res_b64}" }};</script>'

        rows += f'''
        <tr>
            <td><strong>{html.escape(item.get("type", ""))}</strong></td>
            <td><a href="{html.escape(item.get("url", ""))}" target="_blank">{html.escape(item.get("url", ""))}</a></td>
            <td>{item.get("size_bytes")} bytes</td>
            <td style="font-size:11px;">{secrets_html or '<i>No secrets embedded</i>'}</td>
            <td style="text-align:right;">
                <button class="burp-btn" onclick="openBurp('{row_id}')">View HTTP</button>
                {burp_script_data}
            </td>
        </tr>
        '''
    return f'''
    <div class="card open" style="border-left: 4px solid var(--accent-orange);">
        <div class="card-header">
            <span class="card-title"> Git & CI/CD Time Machine</span>
            <span class="card-badge">{len(data)} exposures</span>
        </div>
        <div class="card-content">
            <div class="table-wrapper">
                <table>
                    <thead><tr><th>Configuration Type</th><th>URL Path</th><th>File Size</th><th>Extracted Secrets</th><th style="text-align:right;">Actions</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>
    </div>
    '''


def build_jwt_content(target: str) -> str:
    path = Path("output") / target / "jwt_analyzer" / "jwt_results.json"
    data = read_json_file(path)
    if not data: return '<div class="empty-state"><p>No JWT issues found.</p></div>'
    
    rows = ""
    for item in data:
        risk = item.get("risk", "LOW")
        risk_class = f"tag-{risk.lower()}"
        
        req_b64 = base64.b64encode((item.get("request_raw") or "").encode("utf-8")).decode("utf-8")
        res_b64 = base64.b64encode((item.get("response_raw") or "").encode("utf-8")).decode("utf-8")
        row_id = f"jwt_{uuid.uuid4().hex[:8]}"
        burp_script = f'<script>BURP_DATA["{row_id}"] = {{ "url": "{html.escape(item.get("url", "N/A"))}", "req": "{req_b64}", "res": "{res_b64}" }};</script>'
        button_html = f'<button class="burp-btn" onclick="openBurp(\'{row_id}\')">View HTTP</button>{burp_script}' if req_b64 else ''
        
        # Token preview
        token_preview = html.escape(item.get("token_preview", "")[:40])
        source = html.escape(str(item.get("source", "")))
        
        rows += f'''
        <tr>
            <td><span class="tag {risk_class}">{risk}</span></td>
            <td><strong>{html.escape(item.get("type", ""))}</strong></td>
            <td style="font-size:11px;"><code>{token_preview}...</code><br><span style="color:var(--text-muted);">{source}</span></td>
            <td style="font-size:12px;">{html.escape(item.get("details", ""))}</td>
            <td style="text-align:right;">{button_html}</td>
        </tr>
        '''
    return f'''
    <div class="card open" style="border-left: 4px solid var(--accent-orange);">
        <div class="card-header">
            <span class="card-title"> JWT Analysis</span>
            <span class="card-badge">{len(data)} issues</span>
        </div>
        <div class="card-content" style="display:block;">
            <div class="table-wrapper">
                <table>
                    <thead><tr><th>Risk</th><th>Type</th><th>Token / Source</th><th>Details</th><th>Actions</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>
    </div>
    '''


def build_crlf_content(target: str) -> str:
    path = Path("output") / target / "crlf_injection" / "crlf_results.json"
    data = read_json_file(path)
    if not data: return '<div class="empty-state"><p>No CRLF Injection vulnerabilities found.</p></div>'
    
    rows = ""
    for item in data:
        risk = item.get("risk", "LOW")
        risk_class = f"tag-{risk.lower()}"
        
        req_b64 = base64.b64encode((item.get("request_raw") or "").encode("utf-8")).decode("utf-8")
        res_b64 = base64.b64encode((item.get("response_raw") or "").encode("utf-8")).decode("utf-8")
        row_id = f"crlf_{uuid.uuid4().hex[:8]}"
        burp_script = f'<script>BURP_DATA["{row_id}"] = {{ "url": "{html.escape(item.get("url", ""))}", "req": "{req_b64}", "res": "{res_b64}" }};</script>'
        button_html = f'<button class="burp-btn" onclick="openBurp(\'{row_id}\')">View HTTP</button>{burp_script}' if req_b64 else ''
        
        rows += f'''
        <tr>
            <td><span class="tag {risk_class}">{risk}</span></td>
            <td><strong>{html.escape(item.get("type", ""))}</strong></td>
            <td><a href="{html.escape(item.get("url", ""))}" target="_blank">{html.escape(item.get("url", ""))}</a></td>
            <td><code>{html.escape(item.get("parameter", ""))}</code></td>
            <td style="font-size:12px;">{html.escape(item.get("details", ""))}</td>
            <td style="text-align:right;">{button_html}</td>
        </tr>
        '''
    return f'''
    <div class="card open" style="border-left: 4px solid var(--accent-red);">
        <div class="card-header">
            <span class="card-title"> CRLF Injection</span>
            <span class="card-badge warning">{len(data)} vulnerabilities</span>
        </div>
        <div class="card-content" style="display:block;">
            <div style="padding:15px; background:rgba(248,81,73,0.1); border:1px solid rgba(248,81,73,0.3); border-radius:6px; margin-bottom:15px;">
                <h4 style="color:var(--accent-red); margin-bottom:8px; font-size:14px; font-weight:600;">What is CRLF Injection?</h4>
                <p style="font-size:13px; color:var(--text-secondary); line-height:1.5;">
                    <strong>Carriage Return Line Feed (CRLF) Injection</strong> occurs when a user manages to inject <code>%0d%0a</code> into an application's input and it is reflected directly in the HTTP headers of the response without proper sanitization. 
                    <br><br>
                    <strong>Impact:</strong> This allows an attacker to manipulate the HTTP response, potentially leading to <strong>HTTP Response Splitting</strong>, <strong>XSS</strong>, creating malicious <code>Set-Cookie</code> headers, or bypassing security filters.
                    <br><br>
                    <strong>What was tested:</strong> The analyzer injected <code>%0d%0a</code> payloads into the URLs below to check if the server reflected the payload by creating a new header line or changing the response body structure unlawfully. Use the <strong style="color:var(--text-primary)">View HTTP</strong> button to inspect the raw request block that triggered the vulnerability.
                </p>
            </div>
            <div class="table-wrapper">
                <table>
                    <thead><tr><th>Risk</th><th>Type</th><th>URL</th><th>Parameter</th><th>Details</th><th>Actions</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>
    </div>
    '''


def build_smuggling_content(target: str) -> str:
    path = Path("output") / target / "http_smuggling" / "smuggling_results.json"
    data = read_json_file(path)
    if not data: return '<div class="empty-state"><p>No HTTP Smuggling vulnerabilities found.</p></div>'
    
    rows = ""
    for item in data:
        risk = item.get("risk", "LOW")
        risk_class = f"tag-{risk.lower()}"
        
        req_b64 = base64.b64encode((item.get("request_raw") or "").encode("utf-8")).decode("utf-8")
        res_b64 = base64.b64encode((item.get("response_raw") or "").encode("utf-8")).decode("utf-8")
        row_id = f"smug_{uuid.uuid4().hex[:8]}"
        burp_script = f'<script>BURP_DATA["{row_id}"] = {{ "url": "{html.escape(item.get("url", ""))}", "req": "{req_b64}", "res": "{res_b64}" }};</script>'
        button_html = f'<button class="burp-btn" onclick="openBurp(\'{row_id}\')">View HTTP</button>{burp_script}' if req_b64 else ''
        
        rows += f'''
        <tr>
            <td><span class="tag {risk_class}">{risk}</span></td>
            <td><strong>{html.escape(item.get("type", ""))}</strong></td>
            <td><a href="{html.escape(item.get("url", ""))}" target="_blank">{html.escape(item.get("url", ""))}</a></td>
            <td style="font-size:12px;">{html.escape(item.get("details", ""))}</td>
            <td style="text-align:right;">{button_html}</td>
        </tr>
        '''
    return f'''
    <div class="card open" style="border-left: 4px solid var(--accent-red);">
        <div class="card-header">
            <span class="card-title"> HTTP Request Smuggling</span>
            <span class="card-badge warning">{len(data)} findings</span>
        </div>
        <div class="card-content" style="display:block;">
            <div style="padding:15px; background:rgba(248,81,73,0.1); border:1px solid rgba(248,81,73,0.3); border-radius:6px; margin-bottom:15px;">
                <h4 style="color:var(--accent-red); margin-bottom:8px; font-size:14px; font-weight:600;">HTTP Smuggling Explanation</h4>
                <p style="font-size:13px; color:var(--text-secondary); line-height:1.5;">
                    This section focuses on <strong>HTTP Request Smuggling</strong> (CL.TE, TE.CL, TE.TE). It occurs when the load balancer and backend server have inconsistent parsing of the <code>Content-Length</code> and <code>Transfer-Encoding</code> headers.
                    <br><br>
                    <strong>What was tested:</strong> Timing-based and error-based smuggling techniques. If a finding is listed, the server was confirmed to be vulnerable to desynchronization. Use <strong>View HTTP</strong> to inspect the smuggling preamble.
                </p>
            </div>
            <div class="table-wrapper">
                <table>
                    <thead><tr><th>Risk</th><th>Type</th><th>URL</th><th>Details</th><th>Actions</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>
    </div>
    '''


def build_deser_content(target: str) -> str:
    path = Path("output") / target / "insecure_deserialization" / "deser_results.json"
    data = read_json_file(path)
    if not data: return '<div class="empty-state"><p>No Insecure Deserialization found.</p></div>'
    
    rows = ""
    for item in data:
        risk = item.get("risk", "LOW")
        risk_class = f"tag-{risk.lower()}"
        
        req_b64 = base64.b64encode((item.get("request_raw") or "").encode("utf-8")).decode("utf-8")
        res_b64 = base64.b64encode((item.get("response_raw") or "").encode("utf-8")).decode("utf-8")
        row_id = f"deser_{uuid.uuid4().hex[:8]}"
        burp_script = f'<script>BURP_DATA["{row_id}"] = {{ "url": "{html.escape(item.get("url", ""))}", "req": "{req_b64}", "res": "{res_b64}" }};</script>'
        button_html = f'<button class="burp-btn" onclick="openBurp(\'{row_id}\')">View HTTP</button>{burp_script}' if req_b64 else ''
        
        pattern = html.escape(item.get("pattern", ""))
        source_info = f'{html.escape(item.get("source_type", ""))}:{html.escape(item.get("source_name", ""))}'
        
        rows += f'''
        <tr>
            <td><span class="tag {risk_class}">{risk}</span></td>
            <td><strong>{pattern}</strong></td>
            <td><a href="{html.escape(item.get("url", ""))}" target="_blank">{html.escape(item.get("url", ""))}</a></td>
            <td><code>{source_info}</code></td>
            <td style="font-size:12px;">{html.escape(item.get("details", ""))}</td>
            <td style="text-align:right;">{button_html}</td>
        </tr>
        '''
    return f'''
    <div class="card open" style="border-left: 4px solid var(--accent-red);">
        <div class="card-header">
            <span class="card-title"> Insecure Deserialization</span>
            <span class="card-badge warning">{len(data)} findings</span>
        </div>
        <div class="card-content" style="display:block;">
            <div class="table-wrapper">
                <table>
                    <thead><tr><th>Risk</th><th>Pattern</th><th>URL</th><th>Source</th><th>Details</th><th>Actions</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>
    </div>
    '''


def build_oast_content(target: str) -> str:
    """Build OAST (Out-of-Band) interactions section."""
    from pathlib import Path
    import json
    path = Path("output") / target / "interactsh.json"
    if not path.exists(): return '<div class="empty-state"><p>No OAST interactions detected yet.</p></div>'
    
    try:
        lines = [l for l in path.read_text(errors="ignore").splitlines() if l.strip()]
        data = []
        for l in lines:
            try: data.append(json.loads(l))
            except: continue
    except:
        return '<div class="empty-state"><p>Error reading OAST data.</p></div>'

    if not data: return '<div class="empty-state"><p>No OAST interactions detected yet.</p></div>'
    
    rows = ""
    for item in data:
        proto = item.get("protocol", "unknown").upper()
        remote = item.get("remote-address", "unknown")
        timestamp = item.get("timestamp", "")
        if "T" in timestamp:
             timestamp = timestamp.split("T")[1].split(".")[0]
             
        rows += f'''
        <tr>
            <td><span class="tag tag-high">{proto}</span></td>
            <td><code>{html.escape(remote)}</code></td>
            <td>{html.escape(timestamp)}</td>
            <td style="font-size:11px;">{html.escape(item.get("unique-id", ""))} interaction on {html.escape(item.get("full-id", ""))}</td>
        </tr>
        '''
        
    return f'''
    <div class="card open" style="border-left: 4px solid var(--accent-purple);">
        <div class="card-header">
            <span class="card-title"> OAST / Blind Bugs (Interactsh)</span>
            <span class="card-badge warning">{len(data)} interactions</span>
        </div>
        <div class="card-content">
            <div style="padding:15px; background:rgba(137,87,229,0.1); border:1px solid rgba(137,87,229,0.3); border-radius:6px; margin-bottom:15px;">
                <h4 style="color:var(--accent-purple); margin-bottom:8px; font-size:14px; font-weight:600;">Out-of-Band Interaction</h4>
                <p style="font-size:13px; color:var(--text-secondary); line-height:1.5;">
                    These are <strong>critical</strong> findings. An interaction here means the target server made an external request to our OAST server. 
                    <br><br>
                    <strong>Impact:</strong> This confirms vulnerabilities like <strong>Blind SSRF</strong>, <strong>Blind XSS</strong>, or <strong>Blind RCE</strong> that would otherwise be invisible because they don't return data in the standard HTTP response.
                </p>
            </div>
            <div class="table-wrapper">
                <table>
                    <thead><tr><th>Proto</th><th>Remote IP</th><th>Time</th><th>Interaction ID</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>
    </div>
    '''

def build_surfacemap_content(subdomains: Dict) -> str:
    """Gera um mapa visual da superfície de ataque em formato de árvore."""
    from urllib.parse import urlparse
    if not subdomains:
        return '<div class="empty-state"><p>No domains to map.</p></div>'

    def add_to_tree(tree, path_parts, url, tags):
        current = tree
        for part in path_parts:
            if not part: continue
            if part not in current:
                current[part] = {"_children": {}, "_url": None, "_tags": []}
            current = current[part]["_children"]
        # Last part is the actual page/file
        # This is a bit simplified for URLs
        pass

    # Better tree builder
    tree_data = {}

    for host, host_data in subdomains.items():
        if host not in tree_data:
            tree_data[host] = {}
        
        urls = host_data.get("urls", [])
        classifs = host_data.get("url_classifications", {})

        for url in urls:
            try:
                parsed = urlparse(url)
                path = parsed.path
                if not path or path == "/":
                    continue
                
                parts = [p for p in path.split("/") if p]
                curr = tree_data[host]
                for i, part in enumerate(parts):
                    if part not in curr:
                        curr[part] = {}
                    curr = curr[part]
            except:
                continue

    def render_tree(node, depth=0):
        if not node: return ""
        html_out = "<ul>"
        for name, children in sorted(node.items()):
            icon = "" if children else ""
            html_out += f'<li><span class="{"tree-folder" if children else "tree-file"}">{icon} {html.escape(name)}</span>'
            if children:
                html_out += render_tree(children, depth + 1)
            html_out += "</li>"
        html_out += "</ul>"
        return html_out

    final_html = '<div class="card open"><div class="card-header"><span class="card-title"> Application Structure Map</span></div><div class="card-content"><div class="tree">'
    for host, structure in sorted(tree_data.items()):
        final_html += f'<div style="margin-bottom:20px;"><strong style="font-size:16px; color:var(--accent-green);"> {html.escape(host)}</strong>'
        if structure:
            final_html += render_tree(structure)
        else:
            final_html += '<p style="margin-left:25px; color:#666; font-size:12px;">No deep paths discovered</p>'
        final_html += '</div>'
    final_html += '</div></div></div>'
    
    return final_html

def build_sourcemaps_content(target: str) -> str:
    import html
    from pathlib import Path
    path = Path("output") / target / "sourcemaps" / "secrets.json"
    data = read_json_file(path)
    if not data:
        return '<div class="empty-state"><p>No secrets found in source maps.</p></div>'

    rows = ""
    for item in data:
        rows += f'''
        <tr>
            <td><span class="tag tag-high">{html.escape(item.get("type", ""))}</span></td>
            <td style="font-size:12px;">{html.escape(item.get("source_file", ""))} (line {item.get("line_num", "?")})<br><a href="{html.escape(item.get("map_url", ""))}" target="_blank" style="color:var(--text-muted);font-size:10px;">{html.escape(item.get("map_url", ""))}</a></td>
            <td><code style="color:var(--accent-orange);background:#2d2d2d;padding:2px 6px;border-radius:4px;">{html.escape(item.get("match", "")[:80])}</code></td>
            <td style="font-size:11px;color:var(--text-secondary);max-width:300px;word-wrap:break-word;">{html.escape(item.get("context", "")[:150])}</td>
        </tr>
        '''
    return f'''
    <div class="card open" style="border-left: 4px solid var(--accent-red);">
        <div class="card-header">
            <span class="card-title"> Source Maps Secrets</span>
            <span class="card-badge">{len(data)} secrets</span>
        </div>
        <div class="card-content">
            <div style="padding:15px; background:rgba(137,87,229,0.1); border:1px solid rgba(137,87,229,0.3); border-radius:6px; margin-bottom:15px;">
                <h4 style="color:var(--accent-purple); margin-bottom:8px; font-size:14px; font-weight:600;">Exposição de Source Maps</h4>
                <p style="font-size:13px; color:var(--text-secondary); line-height:1.5;">
                    <strong>Source Maps (<code>.map</code>)</strong> são arquivos que associam o código Javascript minificado/compilado de volta ao seu código-fonte original não minificado. São usados tipicamente para fins de depuração.
                    <br><br>
                    <strong>Impacto:</strong> Quando implementados em produção, os source maps expõem <strong>todo o código-fonte original</strong> da sua aplicação frontend a qualquer indivíduo. Isso torna trivial para atacantes aplicar engenharia reversa na lógica de negócios, descobrir comentários ocultos de desenvolvedores, caminhos de APIs e segredos confidenciais hardcoded.
                    <br><br>
                    <strong>O que foi encontrado:</strong> O analisador desempacotou os source maps expostos listados abaixo e executou padrões de Regex no código fonte original desminificado. A coluna <strong>Contexto</strong> mostra exatamente o fragmento ou linha de código extraído do source map original onde uma chave/segredo ou endpoint desautenticado foi isolado.
                </p>
            </div>
            <div class="table-wrapper">
                <table>
                    <thead><tr><th>Tipo</th><th>Arquivo Fonte & Map</th><th>Encontrado</th><th>Contexto</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>
    </div>
    '''

def build_attack_priority_content(target: str) -> str:
    """Build Attack Priority Engine section with weighted scores."""
    path = Path("output") / target / "intelligence" / "attack_priority.json"
    data = read_json_file(path)
    if not data:
        # Fallback to old risk_ranking
        path = Path("output") / target / "intelligence" / "risk_ranking.json"
        data = read_json_file(path)
    if not data: return ""
    
    rows = ""
    for item in data[:15]:  # Top 15
        score = item.get("score", 0)
        color = "var(--accent-red)" if score >= 7 else "var(--accent-orange)" if score >= 4 else "var(--accent-green)"
        bar_width = min(score * 10, 100)
        tags_html = " ".join([f'<span class="tag tag-low" style="background:#444; color:#eee;">{html.escape(str(t))}</span>' for t in item.get("tags", [])])
        
        factors = item.get("factors", item.get("reasons", []))
        factors_html = "<br>".join([f'<span style="font-size:11px; color:#aaa;">&#8226; {html.escape(str(r))}</span>' for r in factors[:5]])
        
        rows += f'''
        <div style="padding:12px; background:var(--bg-tertiary); border-left:4px solid {color}; border-radius:4px; margin-bottom:12px;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <div style="flex:1;">
                    <div style="display:flex; align-items:center; gap:10px;">
                        <a href="javascript:void(0)" onclick="goToSubdomain(\'{html.escape(str(item.get("subdomain", "")))} \')" style="font-size:15px; font-weight:bold; color:var(--accent-blue); text-decoration:none;">{html.escape(str(item.get("subdomain", "")))}</a>
                        <div style="font-size:22px; font-weight:800; color:{color};">{score}</div>
                    </div>
                    <div style="margin:6px 0; background:var(--bg-primary); border-radius:3px; height:6px; overflow:hidden;">
                        <div style="width:{bar_width}%; height:100%; background:{color}; border-radius:3px;"></div>
                    </div>
                    <div style="margin-top:4px;">{tags_html}</div>
                    <div style="margin-top:6px;">{factors_html}</div>
                </div>
            </div>
        </div>
        '''
    
    weight_table = '''
    <div style="margin-bottom:16px; padding:12px; background:var(--bg-tertiary); border-radius:6px; border:1px solid var(--border-color);">
        <span style="font-weight:bold; color:var(--text-primary); font-size:13px;"> Attack Priority Weights:</span>
        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:6px; margin-top:8px;">
            <span style="font-size:11px; color:#aaa;"> Login Page: +3</span>
            <span style="font-size:11px; color:#aaa;"> Admin Panel: +5</span>
            <span style="font-size:11px; color:#aaa;"> GraphQL: +6</span>
            <span style="font-size:11px; color:#aaa;"> Swagger: +5</span>
            <span style="font-size:11px; color:#aaa;"> JWT: +4</span>
            <span style="font-size:11px; color:#aaa;"> API Endpoint: +3</span>
            <span style="font-size:11px; color:#aaa;"> Upload: +6</span>
            <span style="font-size:11px; color:#aaa;"> Internal Host: +4</span>
            <span style="font-size:11px; color:#aaa;"> Dev/Staging: +4</span>
            <span style="font-size:11px; color:#aaa;"> JS Secrets: +5</span>
        </div>
    </div>
    '''
    
    return f'''
    <div class="card open" style="border-left: 4px solid var(--accent-red);">
        <div class="card-header">
            <span class="card-title"> Attack Priority Engine</span>
            <span class="card-badge">Top {min(len(data), 15)} Targets</span>
        </div>
        <div class="card-content">
            {weight_table}
            {rows}
        </div>
    </div>
    '''


def build_quick_wins_content(target: str) -> str:
    """Build Quick Wins section with high-impact, low-effort findings."""
    path = Path("output") / target / "intelligence" / "quick_wins.json"
    data = read_json_file(path)
    if not data: return '<div class="empty-state"><p>No quick wins identified.</p></div>'
    
    wins_html = ""
    for win in data:
        severity = win.get("severity", "MEDIUM")
        sev_class = "tag-high" if severity in ["HIGH", "CRITICAL"] else "tag-medium"
        icon = win.get("icon", "")
        
        bg_color = "rgba(248, 81, 73, 0.08)" if severity == "CRITICAL" else "rgba(210, 153, 34, 0.08)"
        border_color = "var(--accent-red)" if severity == "CRITICAL" else "var(--accent-orange)"
        
        wins_html += f'''
        <div style="padding:14px; background:{bg_color}; border-left:4px solid {border_color}; border-radius:4px; margin-bottom:12px;">
            <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;">
                <span style="font-size:20px;">{icon}</span>
                <strong style="color:var(--text-primary);">{html.escape(str(win.get("type", "")))}</strong>
                <span class="tag {sev_class}">{severity}</span>
            </div>
            <div style="font-size:13px; color:var(--text-secondary); margin-bottom:4px;">
                <a href="{html.escape(str(win.get('url', '')))}" target="_blank" style="color:var(--accent-blue);">{html.escape(str(win.get("url", "")))}</a>
            </div>
            <div style="font-size:12px; color:var(--text-secondary);">{html.escape(str(win.get("detail", "")))}</div>
            <div style="margin-top:6px; padding:6px 10px; background:var(--bg-tertiary); border-radius:4px; border:1px solid var(--border-color);">
                <span style="font-size:11px; color:var(--accent-green); font-weight:600;"> Action:</span>
                <span style="font-size:11px; color:var(--text-secondary);"> {html.escape(str(win.get("action", "")))}</span>
            </div>
        </div>
        '''
    
    return f'''
    <div class="card open" style="border-left: 4px solid var(--accent-orange);">
        <div class="card-header">
            <span class="card-title"> Quick Wins — Low-Effort, High-Impact</span>
            <span class="card-badge">{len(data)} wins</span>
        </div>
        <div class="card-content">
            {wins_html}
        </div>
    </div>
    '''


def build_vuln_patterns_content(target: str) -> str:
    path = Path("output") / target / "intelligence" / "vuln_patterns.json"
    data = read_json_file(path)
    if not data: return '<div class="empty-state"><p>No high-risk URL patterns identified.</p></div>'
    
    rows = ""
    for item in data:
        risk = item.get("risk_level", "MEDIUM")
        risk_class = "tag-high" if risk in ["HIGH", "CRITICAL"] else "tag-medium"
        params = ", ".join(item.get("matched_parameters", []))
        
        rows += f'''
        <tr>
            <td><span class="tag {risk_class}">{risk}</span></td>
            <td><strong>{html.escape(item.get("vulnerability"))}</strong></td>
            <td><a href="{html.escape(item.get("url"))}" target="_blank">{html.escape(item.get("url"))}</a></td>
            <td><code>{html.escape(params)}</code></td>
        </tr>
        '''
    return f'''
    <div class="card open" style="border-left: 4px solid var(--accent-orange);">
        <div class="card-header">
            <span class="card-title"> Vulnerability Pattern Detection</span>
            <span class="card-badge">{len(data)} suspicious URLs</span>
        </div>
        <div class="card-content">
            <div class="table-wrapper">
                <table>
                    <thead><tr><th>Risk</th><th>Potential Vuln</th><th>URL</th><th>Params</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>
    </div>
    '''

def build_knowledge_tips_content(target: str) -> str:
    path = Path("output") / target / "intelligence" / "knowledge_tips.json"
    data = read_json_file(path)
    if not data: return ""
    
    cards = ""
    for subdomain, info_kb in data.items():
        tips = info_kb.get("tips", [])
        tips_html = ""
        for t in tips:
            if isinstance(t, dict):
                tip_text = html.escape(str(t.get("tip", "")))
                payload = t.get("payload", "")
                category = t.get("category", "")
                cat_badge = f'<span class="tag tag-low" style="background:#333; color:#aaa; font-size:10px; margin-left:6px;">{html.escape(category)}</span>' if category else ""
                payload_html = f'<pre style="background:var(--bg-primary); padding:8px; border-radius:4px; font-size:11px; color:var(--accent-green); margin-top:4px; white-space:pre-wrap; border:1px solid var(--border-color);">{html.escape(str(payload))}</pre>' if payload else ""
                tips_html += f'<li style="margin-bottom:10px; color:#ddd;">{tip_text}{cat_badge}{payload_html}</li>'
            else:
                tips_html += f'<li style="margin-bottom:8px; color:#ddd;">{html.escape(str(t))}</li>'
        
        techs = ", ".join(info_kb.get("matched_technologies", []))
        
        cards += f'''
        <div style="background:var(--bg-tertiary); border:1px solid var(--border-color); border-radius:8px; padding:15px; margin-bottom:15px;">
            <div style="margin-bottom:10px; display:flex; justify-content:space-between; align-items:center;">
                <strong style="color:var(--accent-blue); font-size:15px;">{html.escape(subdomain)}</strong>
                <span style="font-size:11px; color:#666;">Techs: {html.escape(techs)}</span>
            </div>
            <ul style="padding-left:18px; margin:0;">
                {tips_html}
            </ul>
        </div>
        '''
    return cards

def build_wordlist_content(target: str) -> str:
    path = Path("output") / target / "wordlist" / "combined.txt"
    if not path.exists():
        return '<div class="empty-state"><p>No extracted wordlists found.</p></div>'
        
    lines = [l.strip() for l in path.read_text(errors="ignore").splitlines() if l.strip()]
    if not lines:
        return '<div class="empty-state"><p>No extracted wordlists found.</p></div>'
        
    json_data = json.dumps([{"word": w} for w in lines])
    
    return f'''
    <div class="card open">
        <div class="card-header">
            <span class="card-title"> Extracted Wordlist</span>
            <span class="card-badge">{{len(lines)}} words</span>
        </div>
        <div class="card-content">
            <div style="margin-bottom:15px; padding:12px; background:rgba(46,160,67,0.1); border:1px solid rgba(46,160,67,0.3); border-radius:6px;">
                <p style="font-size:13px; color:var(--text-secondary); margin:0; line-height: 1.5;">
                    Estas palavras foram passivamente extraídas do alvo (arquivos JS, parâmetros, diretórios). Elas são exclusivas do contexto da aplicação, perfeitas para <strong>Fuzzing focado</strong>.
                </p>
                <div style="margin-top:10px;">
                    <a href="output/{target}/wordlist/combined.txt" target="_blank" style="display:inline-block; padding:6px 10px; background:var(--bg-tertiary); border-radius:4px; border:1px solid var(--border-color); color:var(--accent-blue); text-decoration:none; font-size:12px; font-weight: bold;"> Baixar dicionário (combined.txt)</a>
                </div>
            </div>
            
            <div id="wordlists_container"></div>
            
            <script>
            (function() {{
                const data = {json_data};
                const cols = ["word"];
                const renderFn = function(row) {{
                    return `
                        <tr>
                            <td style="font-family:monospace; color:var(--accent-orange); font-size:13px;">${{row.word}}</td>
                        </tr>
                    `;
                }};
                
                document.addEventListener('DOMContentLoaded', function() {{
                    const tableContainer = document.getElementById("wordlists_container");
                    if(tableContainer) {{
                        tableContainer.innerHTML = `
                            <div class="table-wrapper">
                                <table>
                                    <thead><tr><th>Extracted Word</th></tr></thead>
                                    <tbody id="wordlists_container_tbody"></tbody>
                                </table>
                            </div>
                        `;
                    }}
                    
                    const initInterval = setInterval(() => {{
                        if (typeof initPaginatedTable === "function") {{
                            clearInterval(initInterval);
                            initPaginatedTable("wordlists_container", data, cols, renderFn, 200);
                        }}
                    }}, 100);
                }});
            }})();
            </script>
        </div>
    </div>
    '''

def run(context: Dict[str, Any]) -> List[str]:
    target = context.get("target")
    if not target:
        raise ValueError("context['target'] is required")
    
    info("Generating report (SPA Dark Mode)...")
    
    outdir = ensure_outdir(target, "report")
    html_file = outdir / "report.html"
    
    # Calculate statistics
    stats = calculate_stats(target)
    
    # Aggregate data by subdomain
    subdomains = aggregate_by_subdomain(target)
    
    # Build warnings
    login_warning = ""
    if stats["login_pages"] > 0:
        login_warning = f'<p style="color:var(--accent-orange);"><strong>Warning:</strong> Found {stats["login_pages"]} potential login pages.</p>'
    
    keys_warning = ""
    if stats["keys_found"] > 0:
        keys_warning = f'<p style="color:var(--accent-red);"><strong>Alert:</strong> Found {stats["keys_found"]} exposed keys/secrets. Review immediately!</p>'
    
    # Get datetime
    now = datetime.now()
    
    # Build template variables
    template_vars = {
        "target": html.escape(target),
        "date": now.strftime("%Y-%m-%d"),
        "time": now.strftime("%H:%M:%S"),
        "stats_subdomains": stats["subdomains"],
        "stats_urls": max(stats["urls_valid"], stats.get("urls_200_count", 0)),
        "stats_ports": stats["ports_total"],
        "stats_login": stats["login_pages"],
        "stats_keys": stats["keys_found"],
        "stats_technologies": stats["technologies"],
        "stats_js": stats["js_files"],
        "stats_routes": stats["routes_found"],
        "stats_cors": stats.get("cors_count", 0),
        "login_warning": login_warning,
        "keys_warning": keys_warning,
        "stats_buckets": stats.get("cloud_buckets", 0),
        "stats_cves": stats.get("cve_vulns", 0),
        "stats_endpoints": stats.get("endpoints_count", 0) + stats.get("routes_found", 0),
        "stats_xss": stats.get("xss_vulns", 0),
        "subdomains_content": build_subdomains_content(subdomains, target),
        "ports_content": build_ports_content(target),
        "urls_content": build_urls_content(subdomains, target),
        "technologies_content": build_technologies_content(target),
        "keys_content": build_keys_content(target),
        "routes_content": build_routes_content(target),
        "js_content": build_js_content(target),
        "files_content": build_files_content(target),
        "services_content": build_services_content(target),
        "stats_urls_combined": max(stats["urls_valid"], stats.get("urls_200_count", 0)) + len(read_file_lines(Path("output") / target / "crawlers" / "katana_valid.txt") or read_file_lines(Path("output") / target / "domain" / "crawlers" / "katana_valid.txt") or read_file_lines(Path("output") / target / "domain" / "katana_valid.txt")),
        "forms_content": build_forms_content(target),
        "stats_forms": len(read_json_file(Path("output") / target / "crawlers" / "katana_forms.json") or read_json_file(Path("output") / target / "domain" / "crawlers" / "katana_forms.json") or []),
        "params_content": build_params_content(target),
        "stats_params": len(read_json_file(Path("output") / target / "crawlers" / "katana_params_all.json") or read_json_file(Path("output") / target / "domain" / "crawlers" / "katana_params_all.json") or read_json_file(Path("output") / target / "domain" / "katana_params_all.json") or {}),
        "stats_sourcemaps": stats.get("sourcemaps_count", 0),
        "sourcemaps_content": build_sourcemaps_content(target),
        "stats_js_routes": stats.get("js_routes_count", 0),
        "js_routes_content": build_js_routes_content(target),
        "stats_swagger": stats.get("swagger_count", 0),
        "swagger_content": build_swagger_content(target),
        "stats_logic": stats.get("logic_flaws_count", 0),
        "logic_content": build_logic_content(target),
        "stats_git": stats.get("git_exposed_count", 0),
        "git_content": build_git_content(target),
        "cloud_content": build_cloud_content(target),
        "cve_content": build_cve_content(subdomains),
        "security_content": build_security_content(target),
        "newsincode_content": "",
        "stats_newsincode": len(read_json_file(Path("output") / target / "crawlers" / "katana_new_in_code_validated.json") or read_json_file(Path("output") / target / "domain" / "crawlers" / "katana_new_in_code_validated.json") or read_json_file(Path("output") / target / "crawlers" / "katana_new_in_code.json") or read_json_file(Path("output") / target / "domain" / "crawlers" / "katana_new_in_code.json") or []),
        "admin_content": build_admin_content(target),
        "stats_admin": len(read_json_file(Path("output") / target / "admin" / "admin_panels.json") or []),
        "depconfusion_content": build_depconfusion_content(target),
        "stats_depconfusion": len([d for d in (read_json_file(Path("output") / target / "depconfusion" / "depconfusion.json") or []) if d.get("risk") == "HIGH"]),
        "stats_graphql": stats.get("graphql_count", 0),
        "graphql_content": build_graphql_content(target),
        "stats_api_security": stats.get("api_security_count", 0),
        "api_security_content": build_api_security_content(target),
        "takeover_content": build_takeover_content(target),
        "stats_takeover": stats.get("takeover_count", 0),
        "waf_content": build_waf_content(target),
        "stats_waf": stats.get("waf_count", 0),
        "emails_content": build_emails_content(target),
        "stats_emails": stats.get("emails_count", 0),
        "hvt_dashboard": build_attack_priority_content(target),
        "vuln_patterns_content": build_vuln_patterns_content(target),
        "knowledge_tips": build_knowledge_tips_content(target),
        "surfacemap_content": build_surfacemap_content(subdomains),
        # New modules
        "stats_jwt": len(read_json_file(Path("output") / target / "jwt_analyzer" / "jwt_results.json") or []),
        "jwt_content": build_jwt_content(target),
        "stats_crlf": len(read_json_file(Path("output") / target / "crlf_injection" / "crlf_results.json") or []),
        "crlf_content": build_crlf_content(target),
        "stats_smuggling": len(read_json_file(Path("output") / target / "http_smuggling" / "smuggling_results.json") or []),
        "smuggling_content": build_smuggling_content(target),
        "stats_deser": len(read_json_file(Path("output") / target / "insecure_deserialization" / "deser_results.json") or []),
        "deser_content": build_deser_content(target),
        "quickwins_attack_content": build_quick_wins_content(target),
        "stats_quickwins": len(read_json_file(Path("output") / target / "intelligence" / "quick_wins.json") or []),
        "stats_oast": len(read_file_lines(Path("output") / target / "interactsh.json")),
        "oast_content": build_oast_content(target),
        "stats_wordlist": stats.get("wordlist_count", 0),
        "wordlist_content": build_wordlist_content(target),
        # V9: Novos módulos de segurança
        "open_redirect_content": build_open_redirect_content(target),
        "stats_open_redirect": len(read_json_file(Path("output") / target / "open_redirect" / "open_redirect_results.json") or []),
        "host_injection_content": build_host_injection_content(target),
        "stats_host_injection": len(read_json_file(Path("output") / target / "host_header_injection" / "host_injection_results.json") or []),
        "ssti_content": build_ssti_content(target),
        "stats_ssti": len(read_json_file(Path("output") / target / "ssti" / "ssti_results.json") or []),
        "xxe_content": build_xxe_content(target),
        "stats_xxe": len(read_json_file(Path("output") / target / "xxe" / "xxe_results.json") or []),
        "proto_pollution_content": build_proto_pollution_content(target),
        "stats_proto_pollution": len(read_json_file(Path("output") / target / "prototype_pollution" / "prototype_pollution_results.json") or []),
        "oauth_content": build_oauth_content(target),
        "stats_oauth": len(read_json_file(Path("output") / target / "oauth_misconfig" / "oauth_misconfig_results.json") or []),
        "api_versioning_content": build_api_versioning_content(target),
        "stats_api_versioning": len(read_json_file(Path("output") / target / "api_versioning" / "api_versioning_results.json") or []),
        "file_upload_content": build_file_upload_content(target),
        "stats_file_upload": len(read_json_file(Path("output") / target / "file_upload" / "file_upload_results.json") or []),
        "email_security_content": build_email_security_content(target),
        "google_dorks_content": build_google_dorks_content(target),
        "stats_google_dorks": len(read_json_file(Path("output") / target / "google_dorks" / "dorks_results.json") or []),
        "spiderfoot_content": build_spiderfoot_content(target),
        "stats_spiderfoot": len((read_json_file(Path("output") / target / "spiderfoot" / "spiderfoot_results.json") or {}).get("findings", [])),
    }
    

    # Generate HTML safely using regex replacement to avoid brace issues with .format()
    def safe_replace(match):
        key = match.group(1)
        return str(template_vars.get(key, match.group(0)))

    html_content = re.sub(r'\{([a-zA-Z0-9_]+)\}', safe_replace, HTML_TEMPLATE)
    
    # Second pass for double braces (if any were meant to be single after format)
    html_content = html_content.replace("{{", "{").replace("}}", "}")

    try:
        html_file.write_text(html_content, encoding='utf-8')

        success(f"Report HTML gerado: {html_file}")
    except Exception as e:
        error(f"Error generating HTML report: {e}")
        raise

    info(f"  Para visualizar no Web App: python3 core/webapp/server.py")
    info(f"  Depois acesse: http://127.0.0.1:5000")
    
    return [str(html_file)]