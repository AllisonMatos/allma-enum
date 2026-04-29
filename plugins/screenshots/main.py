#!/usr/bin/env python3
"""
plugins/screenshots/main.py — Screenshot automático de subdomínios
Usa gowitness (preferido) ou fallback para httpx screenshots.
"""
import json
import shutil
import subprocess
from pathlib import Path

from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error


def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   📸 {C.BOLD}{C.CYAN}SCREENSHOT CAPTURE{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    outdir = ensure_outdir(target, "screenshots")
    base = Path("output") / target

    # Collect URLs
    urls_file = base / "urls" / "urls_200.txt"
    if not urls_file.exists():
        urls_file = base / "domain" / "urls_valid.txt"
    if not urls_file.exists():
        warn("⚠️ Nenhuma URL encontrada. Rode o módulo urls primeiro.")
        return []

    # Deduplicate by host (one screenshot per host)
    from urllib.parse import urlparse
    seen_hosts = set()
    unique_urls = []
    for line in urls_file.read_text(errors="ignore").splitlines():
        url = line.strip()
        if not url:
            continue
        host = urlparse(url).netloc
        if host not in seen_hosts:
            seen_hosts.add(host)
            unique_urls.append(url)

    if not unique_urls:
        warn("⚠️ Nenhuma URL única para screenshot.")
        return []

    # Write temp file with unique URLs
    targets_file = outdir / "targets.txt"
    targets_file.write_text("\n".join(unique_urls[:200]) + "\n")  # Max 200
    info(f"   📋 {len(unique_urls[:200])} URLs únicas para screenshot")

    screenshots_dir = outdir / "images"
    screenshots_dir.mkdir(exist_ok=True)

    # Try gowitness first
    gowitness = shutil.which("gowitness")
    if gowitness:
        info(f"   📸 Usando {C.BOLD}gowitness{C.END}...")
        cmd = [
            gowitness, "scan", "file",
            "-f", str(targets_file),
            "--screenshot-path", str(screenshots_dir),
            "--timeout", "10",
            "--threads", "5",
        ]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            success(f"   ✅ Screenshots capturados em {screenshots_dir}")
        except subprocess.TimeoutExpired:
            warn("   ⚠️ gowitness timeout (10min)")
        except Exception as e:
            error(f"   ❌ Erro: {e}")
    else:
        # Fallback: use Python + httpx to at least get response info
        warn("   ⚠️ gowitness não encontrado. Instale com: go install github.com/sensepost/gowitness@latest")
        warn("   Gerando metadata de URLs como fallback...")

        import httpx
        metadata = []
        for url in unique_urls[:100]:
            try:
                with httpx.Client(timeout=8, verify=False, follow_redirects=True) as client:
                    resp = client.get(url)
                    title = ""
                    import re
                    m = re.search(r"<title>([^<]+)</title>", resp.text[:5000], re.I)
                    if m:
                        title = m.group(1).strip()
                    metadata.append({
                        "url": url,
                        "status": resp.status_code,
                        "title": title,
                        "content_length": len(resp.text),
                        "server": resp.headers.get("server", ""),
                    })
            except Exception:
                pass

        meta_file = outdir / "screenshots_metadata.json"
        meta_file.write_text(json.dumps(metadata, indent=2, ensure_ascii=False))
        info(f"   📄 Metadata de {len(metadata)} URLs salva em {meta_file}")

    # Generate index JSON for the report
    screenshots = []
    if screenshots_dir.exists():
        for img in sorted(screenshots_dir.glob("*.png")):
            screenshots.append({
                "filename": img.name,
                "path": str(img),
            })

    index_file = outdir / "screenshots_index.json"
    index_file.write_text(json.dumps(screenshots, indent=2))
    success(f"   📸 {len(screenshots)} screenshots capturados")

    # Cleanup
    targets_file.unlink(missing_ok=True)
    return [str(index_file)]
