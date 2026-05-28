"""
Enum-Allma Web Report Server — Ephemeral In-Memory Database
On startup: scans output/ and imports all targets using report builders.
On shutdown: DB is automatically destroyed (in-memory SQLite).
"""
import sys
import sqlite3
import json
import html
import traceback
from pathlib import Path
from datetime import datetime
from flask import Flask, jsonify, render_template, request, abort

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

app = Flask(__name__)

# ── In-Memory Database ──────────────────────────────────────────────
DB_CONN = None  # Global in-memory connection (kept alive for the entire process)


def get_db():
    """Return the shared in-memory connection."""
    global DB_CONN
    if DB_CONN is None:
        DB_CONN = sqlite3.connect(":memory:", check_same_thread=False)
        DB_CONN.row_factory = sqlite3.Row
        _create_tables(DB_CONN)
    return DB_CONN


def _create_tables(conn):
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS report_meta (
        target TEXT PRIMARY KEY,
        stats_json TEXT,
        dashboard_html TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS report_sections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        section_id TEXT,
        section_html TEXT,
        UNIQUE(target, section_id)
    )""")
    conn.commit()


# ── Target Import Logic ─────────────────────────────────────────────
def import_target(target: str):
    """Import a single target into the in-memory DB using report builders."""
    from plugins.report.main import (
        calculate_stats, aggregate_by_subdomain, read_file_lines, read_json_file,
        build_subdomains_content, build_ports_content, build_urls_content,
        build_technologies_content, build_keys_content, build_routes_content,
        build_js_content, build_files_content, build_services_content,
        build_forms_content, build_params_content, build_sourcemaps_content,
        build_js_routes_content, build_swagger_content, build_logic_content,
        build_git_content, build_cloud_content, build_cve_content,
        build_security_content, build_admin_content, build_depconfusion_content,
        build_graphql_content, build_api_security_content,
        build_takeover_content, build_waf_content, build_emails_content,
        build_quick_wins_content,
        build_vuln_patterns_content, build_knowledge_tips_content,
        build_surfacemap_content, build_attack_priority_content,
        build_jwt_content, build_oast_content,
        build_open_redirect_content, build_host_injection_content,
        build_email_security_content,
        build_google_dorks_content,
        build_login_pages_content, build_cookies_content,
        build_cors_content, build_headers_content, build_kiterunner_content,
        build_ssti_content, build_network_graph_content, build_dns_records_content,
        build_tls_certs_content, build_asn_content, build_response_headers_content,
        build_executive_summary_content, build_next_steps_content,
        build_screenshots_content, build_wordlist_content, build_wp_plugins_content
    )

    print(f"  [+] Importing: {target}")
    
    try:
        stats = calculate_stats(target)
        subdomains = aggregate_by_subdomain(target)
    except Exception as e:
        print(f"  [-] Failed to calculate stats for {target}: {e}")
        return

    # Build warnings
    login_warning = ""
    if stats["login_pages"] > 0:
        login_warning = f'<p style="color:var(--accent-orange);"><strong>Warning:</strong> Found {stats["login_pages"]} potential login pages.</p>'
    
    keys_warning = ""
    if stats["keys_found"] > 0:
        keys_warning = f'<p style="color:var(--accent-red);"><strong>Alert:</strong> Found {stats["keys_found"]} exposed keys/secrets. Review immediately!</p>'

    # Build dashboard HTML
    dashboard_attack_priority = build_attack_priority_content(target)
    dashboard_knowledge_tips = build_knowledge_tips_content(target)

    
    # Calculate Risk Score
    from pathlib import Path
    
    import html
    
    ap_path = Path("output") / target / "intelligence" / "attack_priority.json"
    ap_data = json.loads(ap_path.read_text()) if ap_path.exists() else []
    total_score = sum(item.get("score", 0) for item in ap_data)
    risk_score = min(100, int(total_score * 5))
    
    if risk_score >= 80:
        risk_label = "CRITICAL"
        risk_color = "#f85149"
    elif risk_score >= 50:
        risk_label = "HIGH"
        risk_color = "#ff7b72"
    elif risk_score >= 20:
        risk_label = "MEDIUM"
        risk_color = "#d29922"
    elif risk_score > 0:
        risk_label = "LOW"
        risk_color = "#3fb950"
    else:
        risk_label = "INFO"
        risk_color = "#8b949e"

    breakdown_rows = ""
    if ap_data:
        for item in ap_data[:6]:
            mod = item.get("module", "unknown")
            score_contrib = int(item.get("score", 0) * 5)
            breakdown_rows += f'<tr><td style="padding:4px 0;">{html.escape(mod)}</td><td style="text-align:right;color:var(--accent-red);padding:4px 0;font-weight:bold;">+{score_contrib}</td></tr>'

    risk_breakdown_html = ""
    if breakdown_rows:
        risk_breakdown_html = f'''
        <div style="border-top:1px solid var(--border-color);border-bottom:1px solid var(--border-color);margin:12px 0;padding:8px 0;">
            <div style="font-size:10px;font-weight:600;color:var(--text-muted);text-transform:uppercase;margin-bottom:6px;">Fatores Contribuintes</div>
            <table style="width:100%;font-size:11px;color:var(--text-secondary);">
                {breakdown_rows}
            </table>
        </div>
        '''
        
    # Tech chips
    tech_data = {}
    tech_path = Path("output") / target / "domain" / "technologies.json"
    if tech_path.exists():
        try:
            tech_json = json.loads(tech_path.read_text())
            for sub_data in tech_json.values():
                for tech in sub_data.get("technologies", []):
                    name = tech.get("name")
                    conf = tech.get("confidence", 0)
                    if name not in tech_data or conf > tech_data[name]:
                        tech_data[name] = conf
        except: pass
    
    # fallback to knowledge_tips if technologies.json empty
    if not tech_data:
        kb_path = Path("output") / target / "intelligence" / "knowledge_tips.json"
        kb_data = json.loads(kb_path.read_text()) if kb_path.exists() else {}
        for kb_info in kb_data.values():
            for name in kb_info.get("matched_technologies", []):
                tech_data[name] = 100
        
    tech_chips_html = ""
    for name, conf in sorted(tech_data.items(), key=lambda x: x[1], reverse=True)[:10]:
        if conf >= 80:
            badge_color = "var(--accent-green)"
            conf_str = f"Certeza Alta ({conf}%)"
        elif conf >= 50:
            badge_color = "var(--accent-blue)"
            conf_str = f"Provável ({conf}%)"
        else:
            badge_color = "var(--text-muted)"
            conf_str = f"Possível ({conf}%)"
            
        tech_chips_html += f'''
        <div style="display:inline-flex; align-items:center; border:1px solid rgba(139,148,158,0.2); background:rgba(139,148,158,0.05); border-radius:12px; padding:2px 8px; margin:0 6px 6px 0;">
            <span style="font-size:12px; font-weight:600; color:var(--text-primary); margin-right:6px;">{html.escape(name)}</span>
            <span style="font-size:10px; color:{badge_color};">{conf_str}</span>
        </div>
        '''
    if not tech_chips_html:
        tech_chips_html = '<span style="color:#666;font-size:12px;">Nenhuma stack detectada.</span>'

    executive_summary_html = build_executive_summary_content(target, stats, tech_data, risk_label, risk_color)
    next_steps_html = build_next_steps_content(target, stats, set(tech_data.keys()))
    wp_plugins_html = build_wp_plugins_content(target)
    stats_urls_display = max(stats["urls_valid"], stats.get("urls_200_count", 0))
    stats_urls_combined = len(read_json_file(Path("output") / target / "urls" / "urls_200.json") or [])

    dashboard_html = f'''
        {executive_summary_html}
        <div class="stats-grid">
            <div class="stat-card highlight"><div class="value">{stats["subdomains"]}</div><div class="label">Subdomains</div></div>
            <div class="stat-card success"><div class="value">{stats_urls_display}</div><div class="label">Valid URLs</div></div>
            <div class="stat-card danger"><div class="value">{stats.get("xss_vulns", 0)}</div><div class="label">XSS Alerts</div></div>
            <div class="stat-card warning"><div class="value">{stats["login_pages"]}</div><div class="label">Login Pages</div></div>
            <div class="stat-card danger"><div class="value">{stats.get("takeover_count", 0)}</div><div class="label">Takeover Risks</div></div>
            <div class="stat-card danger"><div class="value">{stats["keys_found"]}</div><div class="label">Keys Exposed</div><div class="badge-manual" style="margin-top:6px;display:inline-block;width:fit-content;">⚠ Validação manual</div></div>
            <div class="stat-card warning"><div class="value">{stats.get("waf_count", 0)}</div><div class="label">WAFs Detected</div></div>
            <div class="stat-card"><div class="value">{stats.get("emails_count", 0)}</div><div class="label">Emails</div></div>
            <div class="stat-card orange" style="border-left: 3px solid var(--accent-orange);"><div class="value">{stats.get("cors_count", 0)}</div><div class="label">CORS Issues</div><div class="badge-manual" style="margin-top:6px;display:inline-block;width:fit-content;">⚠ Validação manual</div></div>
        </div>
        
        <!-- RISK ASSESSMENT CARD -->
        <div class="card open" style="margin-bottom:16px;">
            <div class="card-header" style="cursor:default;">
                <span class="card-title section-title">📊 Risk Assessment</span>
                <span class="card-badge" id="riskLevelBadge" style="color:{risk_color};border-color:{risk_color};">{risk_label} RISK · Score <span id="riskScore">{risk_score}</span>/100</span>
            </div>
            <div class="card-content" style="display:block;">
                <div class="risk-gauge-wrap">
                    <div class="risk-gauge-block">
                        <div class="risk-gauge">
                            <div class="risk-gauge-arc"></div>
                            <div class="risk-needle" id="riskNeedle" style="transform: translateX(-50%) rotate(-90deg);"></div>
                        </div>
                        <div class="risk-gauge-score" style="color:{risk_color};">{risk_score}</div>
                        <div class="risk-gauge-sublabel">Risk Score /100</div>
                    </div>
                    <div style="flex:1;min-width:180px;">
                        {risk_breakdown_html}
                        <div style="font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:10px;">Stack Detectado</div>
                        <div class="tech-grid">
                            {tech_chips_html}
                        </div>
                        <div style="margin-top:14px;">
                            <div class="test-progress-label">
                                <span>Progresso dos Testes</span>
                                <span id="testProgressPct">100%</span>
                            </div>
                            <div class="test-progress-bar"><div class="test-progress-fill" id="testProgressFill" style="width:100%;"></div></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- PRIORITY QUEUE -->
        <div class="card open" style="margin-bottom:16px;">
            <div class="card-header" style="cursor:default;">
                <span class="card-title section-title">🎯 Priority Queue — Next Steps</span>
                <span class="card-badge">Auto-ranked by exploitability × impact</span>
            </div>
            <div class="card-content" style="display:block;">
                {dashboard_attack_priority or '<div class="priority-item"><div class="p-content"><div class="p-title">No priority items found.</div></div></div>'}
            </div>
        </div>

        {next_steps_html}

        {wp_plugins_html}

        <div style="margin-top:0;">
            <div class="card open" style="border-left: 4px solid var(--accent-blue);">
                 <div class="card-header">
                    <span class="card-title">💡 Playbook por Tecnologia</span>
                    <span class="card-badge">Dicas práticas baseadas na stack</span>
                </div>
                <div class="card-content" style="display:block;">
                    {dashboard_knowledge_tips or '<p style="color:#666;">Sem dicas disponíveis.</p>'}
                </div>
            </div>
        </div>
    '''

    # Calculate stats for sidebar badges  
    stats_for_db = {
        "stats_subdomains": stats["subdomains"],
        "stats_urls": stats_urls_display,
        "stats_ports": stats["ports_total"],
        "stats_login": stats["login_pages"],
        "stats_keys": stats["keys_found"],
        "stats_technologies": stats["technologies"],
        "stats_js": stats["js_files"],
        "stats_routes": stats["routes_found"],
        "stats_cors": stats.get("cors_count", 0),
        "stats_buckets": stats.get("cloud_buckets", 0),
        "stats_cves": stats.get("cve_vulns", 0),
        "stats_endpoints": stats.get("endpoints_count", 0) + stats.get("routes_found", 0),
        "stats_xss": stats.get("xss_vulns", 0),
        "stats_urls_combined": stats_urls_combined,
        "stats_forms": len(read_json_file(Path("output") / target / "crawlers" / "katana_forms.json") or read_json_file(Path("output") / target / "domain" / "crawlers" / "katana_forms.json") or []),
        "stats_params": len(read_json_file(Path("output") / target / "crawlers" / "katana_params_all.json") or read_json_file(Path("output") / target / "domain" / "crawlers" / "katana_params_all.json") or read_json_file(Path("output") / target / "domain" / "katana_params_all.json") or {}),
        "stats_sourcemaps": stats.get("sourcemaps_count", 0),
        "stats_js_routes": stats.get("js_routes_count", 0),
        "stats_swagger": stats.get("swagger_count", 0),
        "stats_logic": stats.get("logic_flaws_count", 0),
        "stats_git": stats.get("git_exposed_count", 0),
        "stats_takeover": stats.get("takeover_count", 0),
        "stats_waf": stats.get("waf_count", 0),
        "stats_emails": stats.get("emails_count", 0),
        "stats_admin": len(read_json_file(Path("output") / target / "admin" / "admin_panels.json") or []),
        "stats_depconfusion": len([d for d in (read_json_file(Path("output") / target / "depconfusion" / "depconfusion.json") or []) if d.get("risk") == "HIGH"]),
        "stats_graphql": stats.get("graphql_count", 0),
        "stats_api_security": stats.get("api_security_count", 0),
        "stats_jwt": len(read_json_file(Path("output") / target / "jwt_analyzer" / "jwt_results.json") or []),
        "stats_quickwins": len(read_json_file(Path("output") / target / "intelligence" / "quick_wins.json") or []),
        "stats_oast": len(read_file_lines(Path("output") / target / "interactsh.json") or read_json_file(Path("output") / target / "intelligence" / "oast_interactions.json") or []),
        "stats_open_redirect": len(read_json_file(Path("output") / target / "open_redirect" / "open_redirect_results.json") or []),
        "stats_host_injection": len(read_json_file(Path("output") / target / "host_header_injection" / "host_injection_results.json") or []),
        "stats_email_sec": 1 if (Path("output") / target / "email_security" / "email_security_results.json").exists() else 0,
        "stats_google_dorks": len(read_json_file(Path("output") / target / "google_dorks" / "dorks_results.json") or []),
        "stats_cookies": len(read_json_file(Path("output") / target / "cookies" / "cookies_results.json") or []),
        "stats_wordlist": stats.get("wordlist_count", 0),
    }

    # Build all section content using the same section IDs/order as the static report.
    section_content_map = {
        "subdomains": build_subdomains_content(subdomains, target),
        "cors": build_cors_content(target),
        "headers": build_headers_content(target),
        "services": build_services_content(target),
        "urls": build_urls_content(subdomains, target),
        "screenshots": build_screenshots_content(target),
        "login_pages": build_login_pages_content(subdomains, target),
        "keys": build_keys_content(target),
        "routes": build_routes_content(target),
        "js": build_js_content(target),
        "params": build_params_content(target),
        "jsroutes": build_js_routes_content(target),
        "swagger": build_swagger_content(target),
        "git": build_git_content(target),
        "surfacemap": build_surfacemap_content(subdomains, target),
        "sourcemaps": build_sourcemaps_content(target),
        "cloud": build_cloud_content(target),
        "cve": build_cve_content(subdomains),
        "admin": build_admin_content(target),
        "graphql_scan": build_graphql_content(target),
        "files": build_files_content(target),
        "forms": build_forms_content(target),
        "takeover": build_takeover_content(target),
        "waf": build_waf_content(target),
        "emails": build_emails_content(target),
        "jwt_sec": build_jwt_content(target),
        "oast_sec": build_oast_content(target),
        "wordlist_sec": build_wordlist_content(target),
        "quickwins_attack": build_quick_wins_content(target),
        "email_sec": build_email_security_content(target),
        "dorks_sec": build_google_dorks_content(target),
        "network_graph": build_network_graph_content(target),
        "dns_records": build_dns_records_content(target),
        "tls_certs": build_tls_certs_content(target),
        "asn_mapping": build_asn_content(target),
        "resp_headers": build_response_headers_content(target),
    }

    def _is_empty_section(section_html: str) -> bool:
        if not section_html or not section_html.strip():
            return True
        has_empty_state = "empty-state" in section_html
        has_content = any(marker in section_html for marker in (
            'class="card', "class='card", 'class="table-wrapper', "class='table-wrapper",
            'class="stats-grid', "class='stats-grid", "<pre", "<table"
        ))
        return has_empty_state and not has_content

    stats_for_db["empty_sections"] = {
        sec_id: _is_empty_section(sec_html)
        for sec_id, sec_html in section_content_map.items()
    }

    # Save to in-memory DB
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("INSERT OR REPLACE INTO report_meta (target, stats_json, dashboard_html) VALUES (?, ?, ?)",
                (target, json.dumps(stats_for_db), dashboard_html))
    
    cur.execute("DELETE FROM report_sections WHERE target=?", (target,))
    for sec_id, sec_html in section_content_map.items():
        cur.execute("INSERT INTO report_sections (target, section_id, section_html) VALUES (?, ?, ?)",
                    (target, sec_id, sec_html or ""))
    
    conn.commit()
    print(f"  [✔] {target} imported successfully")


def import_all_targets():
    """Scan output/ directory and import all targets."""
    import time as _time
    
    output_dir = Path("output")
    if not output_dir.exists():
        print("[!] No output/ directory found. Start scans to generate data.")
        _import_status["status"] = "done"
        return
    
    targets = [d.name for d in sorted(output_dir.iterdir()) 
               if d.is_dir() and not d.name.startswith(".") and d.name != "__pycache__"]
    
    if not targets:
        print("[!] No target directories found in output/")
        _import_status["status"] = "done"
        return
    
    _import_status["status"] = "running"
    _import_status["total"] = len(targets)
    _import_status["current"] = 0
    _import_status["current_target"] = ""
    _import_status["imported"] = []
    _import_status["errors"] = []
    
    print(f"\n{'='*60}")
    print(f"  Enum-Allma Web Report — Importing {len(targets)} targets")
    print(f"{'='*60}")
    
    for i, target in enumerate(targets):
        _import_status["current"] = i + 1
        _import_status["current_target"] = target
        t_start = _time.time()
        try:
            import_target(target)
            elapsed = _time.time() - t_start
            _import_status["imported"].append(target)
            print(f"  ⏱️  {target}: {elapsed:.1f}s")
        except Exception as e:
            elapsed = _time.time() - t_start
            _import_status["errors"].append(f"{target}: {str(e)[:100]}")
            print(f"  [-] Error importing {target} ({elapsed:.1f}s): {e}")
            traceback.print_exc()
    
    _import_status["status"] = "done"
    _import_status["current_target"] = ""
    
    print(f"{'='*60}")
    print(f"  Import complete! {len(_import_status['imported'])}/{len(targets)} targets loaded.")
    print(f"{'='*60}\n")


# ── Background Import State ──────────────────────────────────────────
_import_status = {
    "status": "idle",     # idle | running | done
    "total": 0,
    "current": 0,
    "current_target": "",
    "imported": [],
    "errors": [],
}


def _background_import():
    """Run import in a background thread so Flask starts instantly."""
    import time as _time
    _time.sleep(0.5)  # Let Flask bind the port first
    import_all_targets()


# ── Flask Routes ─────────────────────────────────────────────────────
@app.route("/")
def index():
    """Landing page - target selector."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT target FROM report_meta ORDER BY target ASC")
    targets = [row["target"] for row in cur.fetchall()]
    return render_template("index.html", targets=targets)


@app.route("/api/targets")
def get_targets():
    """Return JSON list of all imported targets."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT target FROM report_meta ORDER BY target ASC")
    targets = [row["target"] for row in cur.fetchall()]
    return jsonify(targets)


@app.route("/api/import_status")
def get_import_status():
    """Return the current status of background data import."""
    return jsonify(_import_status)


@app.route("/report/<target>")
def view_report(target):
    """Serve the report shell for a target (dashboard + empty sections)."""
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("SELECT stats_json, dashboard_html FROM report_meta WHERE target=?", (target,))
    row = cur.fetchone()
    
    if not row:
        # If import is still running, show a loading message instead of 404
        if _import_status["status"] == "running":
            return f"""<html><head><meta http-equiv="refresh" content="5">
            <style>body{{background:#0d1117;color:#c9d1d9;font-family:Inter,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}}
            .loader{{text-align:center;}}.spinner{{width:40px;height:40px;border:3px solid #21262d;border-top:3px solid #58a6ff;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 20px;}}
            @keyframes spin{{0%{{transform:rotate(0deg)}}100%{{transform:rotate(360deg)}}}}</style></head>
            <body><div class="loader"><div class="spinner"></div>
            <h2>⏳ Importando dados...</h2>
            <p>Target: <b>{html.escape(_import_status.get('current_target',''))}</b></p>
            <p>{_import_status['current']}/{_import_status['total']} targets processados</p>
            <p style="color:#8b949e;font-size:13px;">Esta página recarrega automaticamente a cada 5 segundos.</p>
            </div></body></html>"""
        abort(404, description=f"No report found for target: {target}")
    
    stats = json.loads(row["stats_json"])
    dashboard_html = row["dashboard_html"]
    
    cur.execute("SELECT target FROM report_meta ORDER BY target ASC")
    all_targets = [r["target"] for r in cur.fetchall()]
    
    return render_template("report.html",
                           target=target,
                           stats=stats,
                           dashboard_html=dashboard_html,
                           all_targets=all_targets,
                           date=datetime.now().strftime("%Y-%m-%d"),
                           time=datetime.now().strftime("%H:%M:%S"))


@app.route("/api/section/<target>/<section_id>")
def get_section(target, section_id):
    """Return the pre-rendered HTML for a specific section."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT section_html FROM report_sections WHERE target=? AND section_id=?",
                (target, section_id))
    row = cur.fetchone()
    
    if not row:
        return "<div class='empty-state'>No data found for this section.</div>"
    
    return row["section_html"] or "<div class='empty-state'>No data found for this section.</div>"


@app.route("/api/reload")
def reload_data():
    """Re-import all targets from output/ (no restart needed)."""
    global DB_CONN
    if DB_CONN:
        DB_CONN.close()
        DB_CONN = None
    import_all_targets()
    return jsonify({"status": "ok", "message": "All targets re-imported successfully"})


# ── Startup ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    import threading
    
    # Start import in background thread — Flask starts INSTANTLY
    import_thread = threading.Thread(target=_background_import, daemon=True)
    import_thread.start()
    
    print(f"\n  {'='*60}")
    print(f"  🚀 Server starting at: http://127.0.0.1:5000")
    print(f"  📊 Import status:      http://127.0.0.1:5000/api/import_status")
    print(f"  🔄 Reload data:        http://127.0.0.1:5000/api/reload")
    print(f"  {'='*60}\n")
    print(f"  ℹ️  Data is being imported in the background.")
    print(f"     Targets will appear as they are processed.\n")
    
    app.run(host="127.0.0.1", port=5000, debug=False)
