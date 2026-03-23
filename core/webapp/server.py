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
        build_jwt_content, build_crlf_content, build_smuggling_content,
        build_deser_content, build_oast_content
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

    dashboard_html = f'''
        <div class="stats-grid">
            <div class="stat-card highlight"><div class="value">{stats["subdomains"]}</div><div class="label">Subdomains</div></div>
            <div class="stat-card success"><div class="value">{stats["urls_valid"]}</div><div class="label">Valid URLs</div></div>
            <div class="stat-card danger"><div class="value">{stats.get("xss_vulns", 0)}</div><div class="label">XSS Alerts</div></div>
            <div class="stat-card warning"><div class="value">{stats["login_pages"]}</div><div class="label">Login Pages</div></div>
            <div class="stat-card danger"><div class="value">{stats.get("takeover_count", 0)}</div><div class="label">Takeover Risks</div></div>
            <div class="stat-card danger"><div class="value">{stats["keys_found"]}</div><div class="label">Keys Exposed</div></div>
            <div class="stat-card warning"><div class="value">{stats.get("waf_count", 0)}</div><div class="label">WAFs Detected</div></div>
            <div class="stat-card"><div class="value">{stats.get("emails_count", 0)}</div><div class="label">Emails</div></div>
            <div class="stat-card" style="border-left: 3px solid var(--accent-orange);"><div class="value">{stats.get("cors_count", 0)}</div><div class="label">CORS Issues</div></div>
        </div>
        <div class="card">
            <div class="card-header"><span class="card-title section-title">Quick Summary</span></div>
            <div class="card-content" style="display:block;">
                <p>Scan completed for <strong>{html.escape(target)}</strong>. Found {stats["subdomains"]} subdomains with {stats["urls_valid"]} valid URLs across {stats["ports_total"]} open ports.</p>
                {login_warning}
                {keys_warning}
            </div>
        </div>
    '''
    
    if dashboard_attack_priority:
        dashboard_html += dashboard_attack_priority
    
    if dashboard_knowledge_tips:
        dashboard_html += f'''
        <div class="card open" style="border-left: 4px solid var(--accent-blue); margin-top: 20px;">
            <div class="card-header"><span class="card-title">🧠 Dicas de Hacking (Recon Intelligence)</span></div>
            <div class="card-content" style="display:block;">
                {dashboard_knowledge_tips}
            </div>
        </div>
        '''

    # Calculate stats for sidebar badges  
    stats_for_db = {
        "stats_subdomains": stats["subdomains"],
        "stats_urls": stats["urls_valid"],
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
        "stats_urls_combined": stats["urls_valid"] + len(read_file_lines(Path("output") / target / "crawlers" / "katana_valid.txt") or read_file_lines(Path("output") / target / "domain" / "crawlers" / "katana_valid.txt")),
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
        "stats_crlf": len(read_json_file(Path("output") / target / "crlf_injection" / "crlf_results.json") or []),
        "stats_smuggling": len(read_json_file(Path("output") / target / "http_smuggling" / "smuggling_results.json") or []),
        "stats_deser": len(read_json_file(Path("output") / target / "insecure_deserialization" / "deser_results.json") or []),
        "stats_quickwins": len(read_json_file(Path("output") / target / "intelligence" / "quick_wins.json") or []),
        "stats_oast": len(read_file_lines(Path("output") / target / "interactsh.json")),
    }

    # Build all section content
    section_content_map = {
        "subdomains": build_subdomains_content(subdomains, target),
        "security": build_security_content(target),
        "services": build_services_content(target),
        "urls": build_urls_content(subdomains, target),
        "keys": build_keys_content(target),
        "routes": build_routes_content(target),
        "js": build_js_content(target),
        "params": build_params_content(target),
        "jsroutes": build_js_routes_content(target),
        "swagger": build_swagger_content(target),
        "logic": build_logic_content(target),
        "git": build_git_content(target),
        "surfacemap": build_surfacemap_content(subdomains),
        "sourcemaps": build_sourcemaps_content(target),
        "cloud": build_cloud_content(target),
        "cve": build_cve_content(subdomains),
        "admin": build_admin_content(target),
        "depconfusion": build_depconfusion_content(target),
        "graphql_scan": build_graphql_content(target),
        "api_sec": build_api_security_content(target),
        "files": build_files_content(target),
        "takeover": build_takeover_content(target),
        "waf": build_waf_content(target),
        "emails": build_emails_content(target),
        "jwt_sec": build_jwt_content(target),
        "crlf_sec": build_crlf_content(target),
        "smuggling_sec": build_smuggling_content(target),
        "deser_sec": build_deser_content(target),
        "quickwins_attack": build_quick_wins_content(target),
                "knowledge_tips": build_knowledge_tips_content(target),
        "oast_sec": build_oast_content(target),
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
    output_dir = Path("output")
    if not output_dir.exists():
        print("[!] No output/ directory found. Start scans to generate data.")
        return
    
    targets = [d.name for d in sorted(output_dir.iterdir()) 
               if d.is_dir() and not d.name.startswith(".") and d.name != "__pycache__"]
    
    if not targets:
        print("[!] No target directories found in output/")
        return
    
    print(f"\n{'='*60}")
    print(f"  Enum-Allma Web Report — Importing {len(targets)} targets")
    print(f"{'='*60}")
    
    for target in targets:
        try:
            import_target(target)
        except Exception as e:
            print(f"  [-] Error importing {target}: {e}")
            traceback.print_exc()
    
    print(f"{'='*60}")
    print(f"  Import complete! {len(targets)} targets loaded.")
    print(f"{'='*60}\n")


# ── Flask Routes ─────────────────────────────────────────────────────
@app.route("/")
def index():
    """Landing page - target selector."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT target FROM report_meta ORDER BY target ASC")
    targets = [row["target"] for row in cur.fetchall()]
    return render_template("index.html", targets=targets)


@app.route("/report/<target>")
def view_report(target):
    """Serve the report shell for a target (dashboard + empty sections)."""
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("SELECT stats_json, dashboard_html FROM report_meta WHERE target=?", (target,))
    row = cur.fetchone()
    
    if not row:
        abort(404, description=f"No report found for target: {target}")
    
    stats = json.loads(row["stats_json"])
    dashboard_html = row["dashboard_html"]
    
    cur.execute("SELECT target FROM report_meta ORDER BY target ASC")
    all_targets = [r["target"] for r in cur.fetchall()]
    
    return render_template("report.html",
                           target=target,
                           stats=stats,
                           dashboard_html=dashboard_html,
                           all_targets=all_targets)


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
    import_all_targets()
    print("  Server running at: http://127.0.0.1:5000")
    print("  Reload data without restart: http://127.0.0.1:5000/api/reload\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
