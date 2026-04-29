#!/usr/bin/env python3
"""
plugins/diff/main.py — Diff entre scans
Compara dois diretórios output/<target> e mostra diferenças.
Uso manual: python -m plugins.diff.main <dir_antigo> <dir_novo>
"""
import json
from pathlib import Path
from datetime import datetime

from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error


def _load_lines(path: Path) -> set:
    if not path.exists():
        return set()
    return set(l.strip() for l in path.read_text(errors="ignore").splitlines() if l.strip())


def _load_json_keys(path: Path) -> set:
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(errors="ignore"))
        if isinstance(data, list):
            return set(json.dumps(item, sort_keys=True) for item in data)
        elif isinstance(data, dict):
            return set(data.keys())
    except Exception:
        pass
    return set()


def compare_scans(old_dir: Path, new_dir: Path) -> dict:
    """Compare two scan output directories."""
    diff = {
        "timestamp": datetime.now().isoformat(),
        "old_dir": str(old_dir),
        "new_dir": str(new_dir),
        "changes": []
    }

    # Subdomains
    old_subs = _load_lines(old_dir / "domain" / "subdomains.txt")
    new_subs = _load_lines(new_dir / "domain" / "subdomains.txt")
    added = new_subs - old_subs
    removed = old_subs - new_subs
    if added or removed:
        diff["changes"].append({
            "section": "Subdomains",
            "added": sorted(added),
            "removed": sorted(removed),
            "added_count": len(added),
            "removed_count": len(removed),
        })

    # URLs
    old_urls = _load_lines(old_dir / "urls" / "urls_200.txt")
    new_urls = _load_lines(new_dir / "urls" / "urls_200.txt")
    added = new_urls - old_urls
    removed = old_urls - new_urls
    if added or removed:
        diff["changes"].append({
            "section": "URLs (200)",
            "added": sorted(list(added)[:100]),
            "removed": sorted(list(removed)[:100]),
            "added_count": len(added),
            "removed_count": len(removed),
        })

    # Technologies
    old_tech = _load_json_keys(old_dir / "domain" / "technologies.json")
    new_tech = _load_json_keys(new_dir / "domain" / "technologies.json")
    added = new_tech - old_tech
    removed = old_tech - new_tech
    if added or removed:
        diff["changes"].append({
            "section": "Technologies",
            "added": sorted(added),
            "removed": sorted(removed),
            "added_count": len(added),
            "removed_count": len(removed),
        })

    # Cookies
    old_cookies = _load_json_keys(old_dir / "cookies" / "cookies_results.json")
    new_cookies = _load_json_keys(new_dir / "cookies" / "cookies_results.json")
    added = new_cookies - old_cookies
    if added:
        diff["changes"].append({
            "section": "Cookies",
            "added": sorted(list(added)[:50]),
            "removed": [],
            "added_count": len(added),
            "removed_count": len(old_cookies - new_cookies),
        })

    # Ports
    old_ports = _load_lines(old_dir / "domain" / "ports_raw.txt")
    new_ports = _load_lines(new_dir / "domain" / "ports_raw.txt")
    added = new_ports - old_ports
    removed = old_ports - new_ports
    if added or removed:
        diff["changes"].append({
            "section": "Ports",
            "added": sorted(added),
            "removed": sorted(removed),
            "added_count": len(added),
            "removed_count": len(removed),
        })

    # CORS findings
    old_cors = _load_json_keys(old_dir / "cors" / "cors_results.json")
    new_cors = _load_json_keys(new_dir / "cors" / "cors_results.json")
    added = new_cors - old_cors
    if added:
        diff["changes"].append({
            "section": "CORS Findings",
            "added_count": len(added),
            "removed_count": len(old_cors - new_cors),
            "added": sorted(list(added)[:20]),
            "removed": [],
        })

    # Takeover
    old_tk = _load_json_keys(old_dir / "takeover" / "takeover_results.json")
    new_tk = _load_json_keys(new_dir / "takeover" / "takeover_results.json")
    added = new_tk - old_tk
    if added:
        diff["changes"].append({
            "section": "Takeover Findings",
            "added_count": len(added),
            "removed_count": 0,
            "added": sorted(list(added)[:20]),
            "removed": [],
        })

    # Summary
    diff["summary"] = {
        "total_sections_changed": len(diff["changes"]),
        "has_new_subdomains": any(c["section"] == "Subdomains" and c["added_count"] > 0 for c in diff["changes"]),
        "has_new_vulns": any(c["section"] in ("CORS Findings", "Takeover Findings") and c["added_count"] > 0 for c in diff["changes"]),
    }

    return diff


def run(context: dict):
    """Compare current scan with a previous scan directory."""
    target = context.get("target")
    old_dir_path = context.get("diff_old_dir")

    if not target:
        raise ValueError("Target required")

    if not old_dir_path:
        warn("⚠️ Nenhum diretório antigo especificado. Use diff_old_dir no context.")
        warn("   Exemplo: Renomeie output/<target> para output/<target>_old antes do novo scan.")
        return []

    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   🔄 {C.BOLD}{C.CYAN}SCAN DIFF COMPARATOR{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    old_dir = Path(old_dir_path)
    new_dir = Path("output") / target

    if not old_dir.exists():
        error(f"❌ Diretório antigo não encontrado: {old_dir}")
        return []

    if not new_dir.exists():
        error(f"❌ Diretório novo não encontrado: {new_dir}")
        return []

    diff = compare_scans(old_dir, new_dir)

    # Save
    outdir = ensure_outdir(target, "diff")
    diff_file = outdir / "scan_diff.json"
    diff_file.write_text(json.dumps(diff, indent=2, ensure_ascii=False))

    # Print summary
    if diff["changes"]:
        success(f"\n   🔄 {len(diff['changes'])} seções com mudanças:")
        for change in diff["changes"]:
            color = C.GREEN if change["added_count"] > 0 else C.RED
            info(f"      {change['section']}: {color}+{change['added_count']}{C.END} / {C.RED}-{change['removed_count']}{C.END}")
    else:
        info("   ✅ Nenhuma mudança detectada entre os scans.")

    success(f"   📂 Diff salvo em: {diff_file}")
    return [str(diff_file)]
