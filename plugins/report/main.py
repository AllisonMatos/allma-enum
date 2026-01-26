#!/usr/bin/env python3
"""
Report Generator - SPA Dark Mode
Versao moderna com navegacao por abas e tema escuro profissional
"""

import html
import json
from pathlib import Path
import datetime
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


def ensure_outdir(target: str) -> Path:
    outdir = Path("output") / target / "report"
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir


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
        "technologies": 0
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
    
    return stats


# ------------------------------------------------------------
# Data Aggregators
# ------------------------------------------------------------
def aggregate_by_subdomain(target: str) -> Dict:
    """Agrupa todos os dados por subdominio."""
    base = Path("output") / target
    
    subdomains = {}
    
    # Load subdomains
    for sub in read_file_lines(base / "domain" / "subdomains.txt"):
        subdomains[sub] = {
            "ports": [],
            "urls": [],
            "technologies": [],
            "is_login": False
        }
    
    # Load ports
    for line in read_file_lines(base / "domain" / "ports_raw.txt"):
        if ":" in line:
            host, port = line.split(":", 1)
            port = port.split("/")[0]
            if host in subdomains:
                subdomains[host]["ports"].append(port)
            else:
                subdomains[host] = {"ports": [port], "urls": [], "technologies": [], "is_login": False}
    
    # Load URLs
    for url in read_file_lines(base / "domain" / "urls_valid.txt"):
        try:
            from urllib.parse import urlparse
            host = urlparse(url).netloc.split(":")[0]
            if host in subdomains:
                subdomains[host]["urls"].append(url)
            else:
                subdomains[host] = {"ports": [], "urls": [url], "technologies": [], "is_login": False}
        except:
            pass
    
    # Load technologies
    tech_data = read_json_file(base / "domain" / "technologies.json")
    if tech_data:
        for host, data in tech_data.items():
            if host in subdomains:
                subdomains[host]["technologies"] = data.get("technologies", [])
    
    # Mark login pages (from explicit file OR heuristic)
    login_keywords = ["login", "signin", "auth", "portal", "admin", "entrar", "acesso"]
    
    # 1. From dedicated file
    for url in read_file_lines(base / "domain" / "login_pages.txt"):
        try:
            from urllib.parse import urlparse
            host = urlparse(url).netloc.split(":")[0]
            if host in subdomains:
                subdomains[host]["is_login"] = True
        except:
            pass
            
    # 2. Heuristic from urls_200.txt
    for url in read_file_lines(base / "urls" / "urls_200.txt"):
        try:
            if any(k in url.lower() for k in login_keywords):
                from urllib.parse import urlparse
                host = urlparse(url).netloc.split(":")[0]
                if host in subdomains:
                    subdomains[host]["is_login"] = True
        except:
            pass
    
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
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
            min-height: 100vh;
        }}
        
        /* Header */
        .header {{
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 20px 24px;
            position: sticky;
            top: 0;
            z-index: 100;
        }}
        
        .header-content {{
            max-width: 1400px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .header h1 {{
            font-size: 20px;
            font-weight: 600;
            color: var(--text-primary);
        }}
        
        .header h1 span {{
            color: var(--accent-blue);
        }}
        
        .header-meta {{
            font-size: 12px;
            color: var(--text-secondary);
        }}
        
        /* Navigation */
        .nav {{
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 0 24px;
            position: sticky;
            top: 60px;
            z-index: 99;
        }}
        
        .nav-content {{
            max-width: 1400px;
            margin: 0 auto;
            display: flex;
            gap: 4px;
            overflow-x: auto;
        }}
        
        .nav-btn {{
            padding: 12px 16px;
            background: none;
            border: none;
            color: var(--text-secondary);
            font-size: 14px;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            white-space: nowrap;
            transition: all 0.2s;
        }}
        
        .nav-btn:hover {{
            color: var(--text-primary);
            background: var(--bg-tertiary);
        }}
        
        .nav-btn.active {{
            color: var(--text-primary);
            border-bottom-color: var(--accent-orange);
        }}
        
        .nav-btn .count {{
            background: var(--bg-tertiary);
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 12px;
            margin-left: 6px;
        }}
        
        /* Main Content */
        .main {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 24px;
        }}
        
        .section {{
            display: none;
        }}
        
        .section.active {{
            display: block;
        }}
        
        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        
        .stat-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 16px;
        }}
        
        .stat-card .value {{
            font-size: 32px;
            font-weight: 600;
            color: var(--text-primary);
        }}
        
        .stat-card .label {{
            font-size: 12px;
            color: var(--text-secondary);
            margin-top: 4px;
        }}
        
        .stat-card.highlight {{
            border-left: 3px solid var(--accent-blue);
        }}
        
        .stat-card.warning {{
            border-left: 3px solid var(--accent-orange);
        }}
        
        .stat-card.danger {{
            border-left: 3px solid var(--accent-red);
        }}
        
        .stat-card.success {{
            border-left: 3px solid var(--accent-green);
        }}
        
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
        }}
        
        .card-header:hover {{
            background: var(--bg-tertiary);
        }}
        
        .card-title {{
            font-size: 14px;
            font-weight: 600;
            color: var(--text-primary);
        }}
        
        .card-badge {{
            font-size: 12px;
            padding: 2px 8px;
            border-radius: 10px;
            background: var(--bg-tertiary);
            color: var(--text-secondary);
        }}
        
        .card-badge.login {{
            background: var(--accent-orange);
            color: #000;
        }}
        
        .card-content {{
            padding: 16px;
            display: none;
        }}
        
        .card.open .card-content {{
            display: block;
        }}
        
        .card-content pre {{
            background: var(--bg-primary);
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            font-size: 13px;
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
        }}
        
        /* Tables */
        .table-wrapper {{
            overflow-x: auto;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        
        th {{
            text-align: left;
            padding: 12px;
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            font-weight: 500;
            border-bottom: 1px solid var(--border-color);
        }}
        
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid var(--border-color);
        }}
        
        tr:hover {{
            background: var(--bg-tertiary);
        }}
        
        a {{
            color: var(--accent-blue);
            text-decoration: none;
        }}
        
        a:hover {{
            text-decoration: underline;
        }}
        
        /* Tags */
        .tag {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 12px;
            margin-right: 4px;
            margin-bottom: 4px;
        }}
        
        .tag-tech {{
            background: var(--accent-purple);
            color: #fff;
        }}
        
        .tag-port {{
            background: var(--accent-blue);
            color: #fff;
        }}
        
        .tag-high {{
            background: var(--accent-red);
            color: #fff;
        }}
        
        .tag-medium {{
            background: var(--accent-orange);
            color: #000;
        }}
        
        .tag-low {{
            background: var(--accent-green);
            color: #000;
        }}
        
        /* Key Details */
        .key-detail {{
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 16px;
            margin-bottom: 12px;
        }}
        
        .key-detail-header {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 12px;
        }}
        
        .key-type {{
            font-weight: 600;
            color: var(--accent-blue);
        }}
        
        .key-context {{
            background: var(--bg-secondary);
            padding: 8px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 12px;
            overflow-x: auto;
            white-space: pre-wrap;
        }}
        
        /* Empty State */
        .empty-state {{
            text-align: center;
            padding: 48px 24px;
            color: var(--text-secondary);
        }}
        
        /* Footer */
        .footer {{
            text-align: center;
            padding: 24px;
            color: var(--text-muted);
            font-size: 12px;
            border-top: 1px solid var(--border-color);
            margin-top: 48px;
        }}
        
        /* Scrollbar */
        ::-webkit-scrollbar {{
            width: 8px;
            height: 8px;
        }}
        
        ::-webkit-scrollbar-track {{
            background: var(--bg-primary);
        }}
        
        ::-webkit-scrollbar-thumb {{
            background: var(--border-color);
            border-radius: 4px;
        }}
        
        ::-webkit-scrollbar-thumb:hover {{
            background: var(--text-muted);
        }}
    </style>
</head>
<body>
    <header class="header">
        <div class="header-content">
            <h1>Enum-Allma Report: <span>{target}</span></h1>
            <div class="header-meta">{date} - {time}</div>
        </div>
    </header>
    
    <nav class="nav">
        <div class="nav-content">
            <button class="nav-btn active" data-section="dashboard">Dashboard</button>
            <button class="nav-btn" data-section="subdomains">Subdomains<span class="count">{stats_subdomains}</span></button>
            <button class="nav-btn" data-section="services">Services<span class="count">{stats_ports}</span></button>
            <button class="nav-btn" data-section="urls">URLs & Discovered<span class="count">{stats_urls_combined}</span></button>
            <button class="nav-btn" data-section="keys">Keys<span class="count">{stats_keys}</span></button>
            <button class="nav-btn" data-section="routes">API Routes<span class="count">{stats_routes}</span></button>
            <button class="nav-btn" data-section="js">JS Files<span class="count">{stats_js}</span></button>
            <button class="nav-btn" data-section="params">Params<span class="count">{stats_params}</span></button>

            <button class="nav-btn" data-section="files">Files</button>
        </div>
    </nav>
    
    <main class="main">
        <!-- Dashboard -->
        <section class="section active" id="dashboard">
            <div class="stats-grid">
                <div class="stat-card highlight">
                    <div class="value">{stats_subdomains}</div>
                    <div class="label">Subdomains Found</div>
                </div>
                <div class="stat-card success">
                    <div class="value">{stats_urls}</div>
                    <div class="label">Valid URLs</div>
                </div>
                <div class="stat-card">
                    <div class="value">{stats_ports}</div>
                    <div class="label">Open Ports</div>
                </div>
                <div class="stat-card warning">
                    <div class="value">{stats_login}</div>
                    <div class="label">Login Pages</div>
                </div>
                <div class="stat-card danger">
                    <div class="value">{stats_keys}</div>
                    <div class="label">Keys Found</div>
                </div>
                <div class="stat-card">
                    <div class="value">{stats_technologies}</div>
                    <div class="label">Technologies</div>
                </div>
                <div class="stat-card">
                    <div class="value">{stats_js}</div>
                    <div class="label">JS Files</div>
                </div>
                <div class="stat-card">
                    <div class="value">{stats_routes}</div>
                    <div class="label">API Routes</div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <span class="card-title">Quick Summary</span>
                </div>
                <div class="card-content" style="display:block;">
                    <p>Scan completed for <strong>{target}</strong>. Found {stats_subdomains} subdomains with {stats_urls} valid URLs across {stats_ports} open ports.</p>
                    {login_warning}
                    {keys_warning}
                </div>
            </div>
        </section>
        
        <!-- Subdomains -->
        <section class="section" id="subdomains">
            {subdomains_content}
        </section>
        
        <!-- Services -->
        <section class="section" id="services">
            {services_content}
        </section>
        
        <!-- URLs & Discovered -->
        <section class="section" id="urls">
            <div style="margin-bottom: 24px;">
                <h3 style="margin-bottom: 16px; color: var(--accent-blue); border-bottom: 1px solid var(--border-color); padding-bottom: 8px;">Validated URLs</h3>
                {urls_content}
            </div>
            
            <div style="margin-top: 32px;">
                <h3 style="margin-bottom: 16px; color: var(--accent-purple); border-bottom: 1px solid var(--border-color); padding-bottom: 8px;">Discovered URLs (Crawling)</h3>
                {discovered_content}
            </div>
        </section>
        
        <!-- Keys -->
        <section class="section" id="keys">
            {keys_content}
        </section>
        
        <!-- API Routes -->
        <section class="section" id="routes">
            {routes_content}
        </section>
        
        <!-- JS Files -->
        <section class="section" id="js">
            {js_content}
        </section>
        
        <!-- Parameters (with source URLs) -->
        <section class="section" id="params">
            {params_content}
        </section>
        

        
        <!-- Files -->
        <section class="section" id="files">
            {files_content}
        </section>
    </main>
    
    <footer class="footer">
        Generated by Enum-Allma | {date} {time}
    </footer>
    
    <script>
        // Navigation
        document.querySelectorAll('.nav-btn').forEach(btn => {{
            btn.addEventListener('click', () => {{
                document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
                
                btn.classList.add('active');
                document.getElementById(btn.dataset.section).classList.add('active');
            }});
        }});
        
        // Expandable cards
        document.querySelectorAll('.card-header').forEach(header => {{
            header.addEventListener('click', () => {{
                header.parentElement.classList.toggle('open');
            }});
        }});
    </script>
</body>
</html>'''


# ------------------------------------------------------------
# HTML Builders
# ------------------------------------------------------------
def build_subdomains_content(subdomains: Dict) -> str:
    if not subdomains:
        return '<div class="empty-state"><p>No subdomains found</p></div>'
    
    html_parts = []
    
    for host, data in sorted(subdomains.items()):
        ports_str = ", ".join(sorted(set(data["ports"]), key=int)) if data["ports"] else "None"
        urls_count = len(data["urls"])
        tech_count = len(data["technologies"])
        
        badge = ""
        if data["is_login"]:
            badge = '<span class="card-badge login">LOGIN</span>'
        
        content_parts = []
        
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
                </tr>'''
            
            content_parts.append(f'''
            <div style="margin-bottom:12px;">
                <p><strong>Technologies ({tech_count}):</strong></p>
                <div class="table-wrapper">
                    <table>
                        <thead><tr><th>Technology</th><th>Version</th><th>Category</th><th>Confidence</th></tr></thead>
                        <tbody>{tech_rows}</tbody>
                    </table>
                </div>
            </div>''')
            
        if data["urls"]:
            urls_list_items = []
            for u in data["urls"]:
                urls_list_items.append(f'<a href="{u}" target="_blank" style="color:var(--accent-green);">{html.escape(u)}</a>')
            
            urls_list = "<br>".join(urls_list_items)
            content_parts.append(f'<p><strong>Validated URLs ({urls_count}):</strong><br>{urls_list}</p>')
        
        content = "".join(content_parts) if content_parts else "<p>No additional data</p>"
        
        html_parts.append(f'''
        <div class="card">
            <div class="card-header">
                <span class="card-title">{html.escape(host)}</span>
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
    
    return "".join(html_parts)


def build_ports_content(target: str) -> str:
    base = Path("output") / target
    ports_file = base / "domain" / "ports.txt"
    
    content = read_file_raw(ports_file)
    if not content.strip():
        return '<div class="empty-state"><p>No ports found</p></div>'
    
    return f'''
    <div class="card open">
        <div class="card-header">
            <span class="card-title">Open Ports by Host</span>
        </div>
        <div class="card-content">
            <pre>{html.escape(content)}</pre>
        </div>
    </div>
    '''


def build_urls_content(subdomains: Dict) -> str:
    all_urls = []
    for host, data in subdomains.items():
        for url in data["urls"]:
            all_urls.append({"host": host, "url": url})
    
    if not all_urls:
        return '<div class="empty-state"><p>No valid URLs found</p></div>'
    
    # Group by host
    html_parts = []
    current_host = None
    
    for item in sorted(all_urls, key=lambda x: x["host"]):
        if item["host"] != current_host:
            if current_host is not None:
                html_parts.append('</tbody></table></div></div></div>')
            current_host = item["host"]
            html_parts.append(f'''
            <div class="card">
                <div class="card-header">
                    <span class="card-title">{html.escape(current_host)}</span>
                    <span class="card-badge">{len([u for u in all_urls if u["host"] == current_host])} URLs</span>
                </div>
                <div class="card-content">
                    <div class="table-wrapper">
                        <table>
                            <thead><tr><th>URL</th></tr></thead>
                            <tbody>
            ''')
        
        html_parts.append(f'<tr><td><a href="{item["url"]}" target="_blank">{html.escape(item["url"])}</a></td></tr>')
    
    if current_host is not None:
        html_parts.append('</tbody></table></div></div></div>')
    
    return "".join(html_parts)


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
    
    for key in keys_data:  # Removed slicing
        risk = key.get("info", {}).get("risk", "UNKNOWN")
        risk_class = "tag-high" if risk == "CRITICAL" else "tag-medium" if risk == "HIGH" else "tag-low"
        
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
             
        # Context - melhorado com múltiplas linhas
        context = key.get("context", {})
        before_lines = context.get("before", [])
        match_line = context.get("match_line", "")
        after_lines = context.get("after", [])
        
        # Construir contexto formatado com destaque na linha do match
        context_html = ""
        line_num = max(1, source_line - len(before_lines)) if isinstance(source_line, int) else 1
        
        for line in before_lines:
            context_html += f'<span style="color:#6e7681;">{line_num:4d} │</span> {html.escape(str(line))}\n'
            line_num += 1
            
        # Linha do match destacada
        if match_line:
            context_html += f'<span style="color:#f85149;">▶{source_line:4d} │</span> <span style="background:#3d1d1f;color:#ffa198;">{html.escape(str(match_line))}</span>\n'
            line_num += 1
        
        for line in after_lines:
            context_html += f'<span style="color:#6e7681;">{line_num:4d} │</span> {html.escape(str(line))}\n'
            line_num += 1
        
        # Fallback se não tiver contexto estruturado
        if not context_html.strip():
            context_full = context.get("full", "Context not available")
            context_html = html.escape(str(context_full))
        
        html_parts.append(f'''
        <div class="card open" style="border-left: 4px solid var(--accent-{ 'red' if risk == 'CRITICAL' else 'orange' if risk == 'HIGH' else 'green' });">
            <div class="card-header" style="background:transparent; border-bottom:none; padding-bottom:0;">
                <span class="card-title" style="color:var(--accent-blue); font-size:16px;">{html.escape(key_type)}</span>
                <span class="tag {risk_class}">{risk}</span>
                <span class="tag tag-low" style="margin-left:8px;">{html.escape(service)}</span>
            </div>
            <div class="card-content" style="display:block; padding-top:8px;">
                <p style="margin-bottom:8px;"><strong>Match:</strong> <code style="color:var(--accent-orange); background:#2d2d2d; padding:2px 6px; border-radius:4px;">{html.escape(match_val[:80])}</code></p>
                <p style="margin-bottom:12px; font-size:12px; color:var(--text-secondary);"><strong>Source:</strong> {source_display} <span class="tag tag-low">Line {source_line}</span></p>
                
                <p style="margin-bottom:4px; font-size:12px; color:var(--text-secondary);"><strong>Context:</strong></p>
                <pre style="background:#0d1117; color:#c9d1d9; padding:12px; border-radius:6px; font-size:11px; line-height:1.5; overflow-x:auto; white-space:pre-wrap; word-wrap:break-word;">{context_html}</pre>
            </div>
        </div>
        ''')
    
    return "".join(html_parts)


def build_files_content(target: str) -> str:
    base = Path("output") / target
    files_content = read_file_raw(base / "files" / "files_by_extension.txt")
    
    if not files_content.strip():
        return '<div class="empty-state"><p>No files categorized</p></div>'
    
    return f'''
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
    base = Path("output") / target
    routes_data = read_json_file(base / "domain" / "extracted_routes.json")
    
    if not routes_data:
        return '<div class="empty-state"><p>No API routes found</p></div>'
        
    # Group by subdomain
    grouped = {}
    for r in routes_data:
        sub = r.get("subdomain", "Unknown")
        if sub not in grouped:
            grouped[sub] = []
        grouped[sub].append(r)
        
    html_parts = []
    
    for sub, routes in sorted(grouped.items()):
        route_rows = ""
        for r in routes:
            method = r.get("method", "GET")
            path = r.get("path", "")
            method_class = "tag-medium" if method in ["POST", "PUT", "DELETE"] else "tag-low"
            
            route_rows += f'''
            <tr>
                <td><span class="tag {method_class}">{method}</span></td>
                <td><a href="{r.get("url", "#")}" target="_blank">{html.escape(path)}</a></td>
                <td>{html.escape(r.get("source", ""))}</td>
            </tr>
            '''
            
        html_parts.append(f'''
        <div class="card">
            <div class="card-header">
                <span class="card-title">{html.escape(sub)}</span>
                <span class="card-badge">{len(routes)} routes</span>
            </div>
            <div class="card-content">
                <div class="table-wrapper">
                    <table>
                        <thead><tr><th>Method</th><th>Path</th><th>Source</th></tr></thead>
                        <tbody>{route_rows}</tbody>
                    </table>
                </div>
            </div>
        </div>
        ''')

    return "".join(html_parts)


def build_js_content(target: str) -> str:
    base = Path("output") / target
    js_data = read_json_file(base / "domain" / "extracted_js.json")
    
    if not js_data:
        return '<div class="empty-state"><p>No JS files found</p></div>'
        
    # Group by subdomain
    grouped = {}
    for j in js_data:
        sub = j.get("subdomain", "Unknown")
        if sub not in grouped:
            grouped[sub] = []
        grouped[sub].append(j)
        
    html_parts = []
    
    for sub, files in sorted(grouped.items()):
        file_rows = ""
        for j in files:
            js_url = j.get("url", "")
            js_type = j.get("type", "external")
            size = j.get("size", 0)
            
            file_rows += f'''
            <tr>
                <td><a href="{js_url}" target="_blank">{html.escape(js_url.split("/")[-1] or js_url)}</a></td>
                <td><span class="tag tag-low">{html.escape(js_type)}</span></td>
                <td>{size} bytes</td>
                <td><a href="{js_url}" target="_blank" style="font-size:12px">View</a></td>
            </tr>
            '''
            
        html_parts.append(f'''
        <div class="card">
            <div class="card-header">
                <span class="card-title">{html.escape(sub)}</span>
                <span class="card-badge">{len(files)} files</span>
            </div>
            <div class="card-content">
                <div class="table-wrapper">
                    <table>
                        <thead><tr><th>Filename</th><th>Type</th><th>Size</th><th>Link</th></tr></thead>
                        <tbody>{file_rows}</tbody>
                    </table>
                </div>
            </div>
        </div>
        ''')

    return "".join(html_parts)


def build_discovered_urls(target: str) -> str:
    """Mostra TODAS as URLs descobertas (Katana, URLFinder, News in Code) agrupadas por subdomínio"""
    base = Path("output") / target
    from urllib.parse import urlparse
    
    # ---------------------------------------------------------
    # 1. Coletar dados de multiplas fontes
    # ---------------------------------------------------------
    all_items = {} # URL -> Item Dict (para deduplicar)
    
    # helper
    def add_item(url, source_type, extra_data=None):
        if not url: return
        url = url.strip()
        if url not in all_items:
            all_items[url] = {
                "url": url,
                "status": 0,
                "sources": set(),
                "final_url": "",
                "error": "",
                "found_in": ""
            }
        
        all_items[url]["sources"].add(source_type)
        if extra_data:
            # Merge rich data (prefer non-empty/non-zero)
            if extra_data.get("status"): all_items[url]["status"] = extra_data["status"]
            if extra_data.get("final_url"): all_items[url]["final_url"] = extra_data["final_url"]
            if extra_data.get("error"): all_items[url]["error"] = extra_data["error"]
            if extra_data.get("found_in"): all_items[url]["found_in"] = extra_data["found_in"]

    # Source A: Katana Standard Validated
    katana_file = base / "crawlers" / "katana_valid.txt"
    if not katana_file.exists(): katana_file = base / "domain" / "crawlers" / "katana_valid.txt"
    if katana_file.exists():
        for u in read_file_lines(katana_file):
            add_item(u, "Katana")
            
    # Source B: URLFinder
    urlfinder_file = base / "urls" / "urls_200.txt"
    if urlfinder_file.exists():
        for u in read_file_lines(urlfinder_file):
            add_item(u, "URLFinder", {"status": 200})
            
    # Source C: Katana Deep/New in Code (Validated JSON)
    deep_file = base / "crawlers" / "katana_new_in_code_validated.json"
    if not deep_file.exists(): deep_file = base / "domain" / "crawlers" / "katana_new_in_code_validated.json"
    if deep_file.exists():
        start_data = read_json_file(deep_file)
        for item in start_data:
            u = item.get("url")
            # Converter formato JSON para nosso formato interno
            extra = {
                "status": item.get("status"),
                "final_url": item.get("final_url"),
                "error": item.get("error"),
                "found_in": item.get("found_in")
            }
            add_item(u, "DeepScan", extra)

    if not all_items:
        return '<div class="empty-state"><p>No discovered URLs found</p></div>'

    # ---------------------------------------------------------
    # 2. Agrupar por Subdomínio / Externo
    # ---------------------------------------------------------
    grouped = {} # host -> list of items
    external = []
    
    for u, item in all_items.items():
        try:
            domain = urlparse(u).netloc.split(":")[0]
            if target in domain or domain.endswith(target):
                if domain not in grouped:
                    grouped[domain] = []
                grouped[domain].append(item)
            else:
                external.append(item)
        except:
            external.append(item)

    html_parts = []
    
    # ---------------------------------------------------------
    # 3. Renderizar Tabelas
    # ---------------------------------------------------------
    
    def render_rows(items):
        # Sort: Valid/Status > URL
        sorted_list = sorted(items, key=lambda x: (x["status"] == 0, x["url"]))
        rows_html = ""
        for x in sorted_list:
            u = x["url"]
            st = x["status"]
            
            # Status Badge
            st_html = '<span class="tag tag-low">?</span>'
            if st:
                s_cls = "tag-green" if 200 <= st < 300 else "tag-blue" if 300 <= st < 400 else "tag-red" if st >= 500 else "tag-orange"
                st_html = f'<span class="tag {s_cls}">{st}</span>'
            elif x.get("error"):
                st_html = '<span class="tag tag-red">ERR</span>'
                
            # Details
            details = ""
            if x.get("final_url") and x["final_url"] != u:
                 details = f'<div style="font-size:10px;color:var(--text-muted);">→ {html.escape(x["final_url"][:50])}</div>'
            if x.get("error"):
                 details += f'<div style="font-size:10px;color:var(--accent-red);">{html.escape(x["error"][:30])}</div>'
                 
            # Found In (Source file context)
            found_in_html = ""
            if x.get("found_in"):
                 found_in_html = f'<div style="font-size:10px;color:var(--text-secondary);margin-top:2px;">Found in: <a href="{x["found_in"]}" target="_blank" style="color:var(--text-secondary);">{html.escape(x["found_in"].split("/")[-1])}</a></div>'
            
            rows_html += f'''
            <tr>
                <td style="width:60px;vertical-align:top;">{st_html}</td>
                <td>
                    <a href="{u}" target="_blank" style="color:var(--accent-blue);font-weight:500;">{html.escape(u)}</a>
                    {details}
                    {found_in_html}
                </td>
            </tr>
            '''
        return rows_html

    # A. Subdomínios (In-Scope)
    for host, items in sorted(grouped.items()):
        html_parts.append(f'''
        <div class="card">
            <div class="card-header">
                <span class="card-title">{html.escape(host)}</span>
                <span class="card-badge">{len(items)} URLs</span>
            </div>
            <div class="card-content">
                <div class="table-wrapper" style="max-height: 500px; overflow-y: auto;">
                    <table style="width:100%;">
                        <tbody>{render_rows(items)}</tbody>
                    </table>
                </div>
                <!-- <p style="margin-top:5px;font-size:11px;color:var(--text-secondary);">Showing all {len(items)} items</p> -->
            </div>
        </div>
        ''')
        
    # B. Externos
    if external:
        html_parts.append(f'''
        <div class="card">
            <div class="card-header">
                <span class="card-title">🌍 External / Third-Party</span>
                <span class="card-badge">{len(external)} URLs</span>
            </div>
            <div class="card-content">
                <div class="table-wrapper" style="max-height: 500px; overflow-y: auto;">
                    <table style="width:100%;">
                        <tbody>{render_rows(external)}</tbody>
                    </table>
                </div>
            </div>
        </div>
        ''')
        
    return "".join(html_parts)


def build_newsincode_content(target: str) -> str:
    # Deprecated / Merged into discovered_urls
    return ""


def build_forms_content(target: str) -> str:
    """Mostra formulários descobertos pelo Katana"""
    base = Path("output") / target
    forms_file = base / "crawlers" / "katana_forms.json"
    
    if not forms_file.exists():
        forms_file = base / "domain" / "crawlers" / "katana_forms.json"
    
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
    
    if len(forms) > 50:
        html_parts.append(f'<p style="text-align:center;color:var(--text-secondary);">Showing all {len(forms)} forms</p>')
    
    return "".join(html_parts)


def build_params_content(target: str) -> str:
    """Mostra parâmetros descobertos pelo Katana com suas URLs de origem"""
    base = Path("output") / target
    
    # Tenta ler o novo formato JSON
    params_file = base / "crawlers" / "katana_params.json"
    if not params_file.exists():
        params_file = base / "domain" / "crawlers" / "katana_params.json"
    
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
    params_data = read_json_file(params_file)
    
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
    if dangerous:
        danger_rows = ""
        for param, urls in sorted(dangerous.items()):
            url_list = "<br>".join([f'<a href="{u}" target="_blank" style="color:var(--accent-blue);font-size:11px;">{html.escape(u[:60])}</a>' for u in urls])
            if False:
                url_list += f'<br><span style="color:var(--text-secondary);font-size:11px;">...and {len(urls)-3} more URLs</span>'
            danger_rows += f'''
            <tr>
                <td><code style="color:var(--accent-orange);background:#2d2d2d;padding:2px 6px;border-radius:4px;">{html.escape(param)}</code></td>
                <td style="font-size:12px;">{url_list}</td>
            </tr>'''
        
        html_parts.append(f'''
        <div class="card open" style="border-left:4px solid var(--accent-orange);">
            <div class="card-header">
                <span class="card-title">⚠️ Potentially Sensitive Parameters</span>
                <span class="card-badge">{len(dangerous)} params</span>
            </div>
            <div class="card-content">
                <p style="color:var(--text-secondary);margin-bottom:12px;">These parameters may be interesting for testing (SQLi, auth bypass, IDOR, LFI, etc.)</p>
                <table style="width:100%;"><thead><tr><th style="width:150px;">Parameter</th><th>Found In</th></tr></thead><tbody>{danger_rows}</tbody></table>
            </div>
        </div>
        ''')
    
    # Params normais (resumidos)
    if normal:
        normal_rows = ""
        items = list(normal.items())
        for param, urls in sorted(items):
            first_url = urls[0] if urls else "Unknown"
            normal_rows += f'''
            <tr>
                <td><code style="background:#2d2d2d;padding:2px 6px;border-radius:4px;">{html.escape(param)}</code></td>
                <td><a href="{first_url}" target="_blank" style="color:var(--accent-blue);font-size:11px;">{html.escape(first_url[:50])}</a>{f' (+{len(urls)-1} more)' if len(urls) > 1 else ''}</td>
            </tr>'''
        
        html_parts.append(f'''
        <div class="card">
            <div class="card-header">
                <span class="card-title">All Parameters</span>
                <span class="card-badge">{len(normal)} params</span>
            </div>
            <div class="card-content">
                <table style="width:100%;"><thead><tr><th style="width:150px;">Parameter</th><th>Found In</th></tr></thead><tbody>{normal_rows}</tbody></table>
                {f'<p style="margin-top:12px;color:var(--text-secondary);">Showing all {len(normal)} parameters</p>' if len(normal) > 0 else ''}
            </div>
        </div>
        ''')
    
    return "".join(html_parts)
    return "".join(html_parts)
# Main Function
# ------------------------------------------------------------
def run(context: Dict[str, Any]) -> List[str]:
    target = context.get("target")
    if not target:
        raise ValueError("context['target'] is required")
    
    info("Generating report (SPA Dark Mode)...")
    
    outdir = ensure_outdir(target)
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
    now = datetime.datetime.now()
    
    # Build template variables
    template_vars = {
        "target": html.escape(target),
        "date": now.strftime("%Y-%m-%d"),
        "time": now.strftime("%H:%M:%S"),
        "stats_subdomains": stats["subdomains"],
        "stats_urls": stats["urls_valid"],
        "stats_ports": stats["ports_total"],
        "stats_login": stats["login_pages"],
        "stats_keys": stats["keys_found"],
        "stats_technologies": stats["technologies"],
        "stats_js": stats["js_files"],
        "stats_routes": stats["routes_found"],
        "login_warning": login_warning,
        "keys_warning": keys_warning,
        "subdomains_content": build_subdomains_content(subdomains),
        "ports_content": build_ports_content(target),
        "urls_content": build_urls_content(subdomains),
        "technologies_content": build_technologies_content(target),
        "keys_content": build_keys_content(target),
        "routes_content": build_routes_content(target),
        "js_content": build_js_content(target),
        "files_content": build_files_content(target),
        "services_content": build_services_content(target),
        "discovered_content": build_discovered_urls(target),
        "stats_discovered": len(read_file_lines(Path("output") / target / "crawlers" / "katana_valid.txt") or read_file_lines(Path("output") / target / "domain" / "crawlers" / "katana_valid.txt")),
        "stats_urls_combined": stats["urls_valid"] + len(read_file_lines(Path("output") / target / "crawlers" / "katana_valid.txt") or read_file_lines(Path("output") / target / "domain" / "crawlers" / "katana_valid.txt")),
        "forms_content": build_forms_content(target),
        "stats_forms": len(read_json_file(Path("output") / target / "crawlers" / "katana_forms.json") or read_json_file(Path("output") / target / "domain" / "crawlers" / "katana_forms.json") or []),
        "params_content": build_params_content(target),
        "stats_params": len(read_json_file(Path("output") / target / "crawlers" / "katana_params.json") or read_json_file(Path("output") / target / "domain" / "crawlers" / "katana_params.json") or {}),
        "newsincode_content": build_newsincode_content(target),
        "stats_newsincode": len(read_json_file(Path("output") / target / "crawlers" / "katana_new_in_code_validated.json") or read_json_file(Path("output") / target / "domain" / "crawlers" / "katana_new_in_code_validated.json") or read_json_file(Path("output") / target / "crawlers" / "katana_new_in_code.json") or read_json_file(Path("output") / target / "domain" / "crawlers" / "katana_new_in_code.json") or []),
    }
    
    # Generate HTML
    try:
        html_content = HTML_TEMPLATE.format(**template_vars)
        html_file.write_text(html_content, encoding='utf-8')
        success(f"Report generated: {html_file}")
    except Exception as e:
        error(f"Error generating report: {e}")
        raise
    
    return [str(html_file)]