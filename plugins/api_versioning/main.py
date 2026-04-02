#!/usr/bin/env python3
"""
API Versioning Recon — Descobre versões de API ativas/descontinuadas.
"""
import json
import time
import httpx
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config import DEFAULT_USER_AGENT, REQUEST_DELAY, DEFAULT_TIMEOUT
from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from ..http_utils import format_http_request, format_http_response

VERSION_PATHS = ["/v1/", "/v2/", "/v3/", "/v4/", "/v5/",
                 "/api/v1/", "/api/v2/", "/api/v3/", "/api/v4/",
                 "/api/1/", "/api/2/", "/api/3/"]


def _probe_versions(base_url: str) -> list:
    """Testa versões de API em um host."""
    results = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    for vpath in VERSION_PATHS:
        test_url = f"{origin}{vpath}"
        time.sleep(REQUEST_DELAY)
        try:
            with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=True) as client:
                resp = client.get(test_url, headers={"User-Agent": DEFAULT_USER_AGENT})
                if resp.status_code < 404:
                    results.append({
                        "url": test_url,
                        "version": vpath.strip("/"),
                        "status": resp.status_code,
                        "length": len(resp.text),
                        "content_type": resp.headers.get("content-type", ""),
                        "request_raw": format_http_request(resp.request),
                        "response_raw": format_http_response(resp),
                    })
        except Exception:
            pass

    return results


def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟦───────────────────────────────────────────────────────────🟦\n"
        f"   🔢 {C.BOLD}{C.CYAN}API VERSIONING RECON{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟦───────────────────────────────────────────────────────────🟦\n"
    )

    outdir = ensure_outdir(target, "api_versioning")

    urls_file = Path("output") / target / "domain" / "urls_valid.txt"
    if not urls_file.exists():
        warn("⚠️ urls_valid.txt não encontrado.")
        (outdir / "api_versioning_results.json").write_text(json.dumps([], indent=2))
        (outdir / "scan_summary.json").write_text(json.dumps({"tests_run": 0, "findings": 0, "status": "NO_INPUT"}, indent=2))
        return []

    valid_urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]

    # Dedup por host
    seen = set()
    unique = []
    for u in valid_urls:
        p = urlparse(u)
        h = f"{p.scheme}://{p.netloc}"
        if h not in seen:
            seen.add(h)
            unique.append(h)

    info(f"   📋 Testando {len(unique)} hosts com {len(VERSION_PATHS)} versões...")

    all_results = []
    tests_run = 0

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(_probe_versions, url): url for url in unique}
        for future in as_completed(futures):
            try:
                results = future.result()
                tests_run += len(VERSION_PATHS)
                all_results.extend(results)
                for r in results:
                    info(f"   ✅ {C.GREEN}[{r['status']}]{C.END} {r['url']} ({r['length']} bytes)")
            except Exception:
                pass

    # Agrupar por host
    by_host = {}
    for r in all_results:
        host = urlparse(r["url"]).netloc
        by_host.setdefault(host, []).append(r)

    # Detectar versões antigas (potencial risco)
    flagged = []
    for host, versions in by_host.items():
        if len(versions) > 1:
            versions.sort(key=lambda x: x["version"])
            for v in versions[:-1]:
                v["risk"] = "MEDIUM"
                v["type"] = "OLD_API_VERSION"
                v["details"] = f"Versão antiga '{v['version']}' ainda acessível — pode ter menos proteções"
                flagged.append(v)

    output_file = outdir / "api_versioning_results.json"
    output_file.write_text(json.dumps(all_results, indent=2, ensure_ascii=False))

    summary = {"tests_run": tests_run, "hosts_checked": len(unique), "versions_found": len(all_results), "old_versions": len(flagged), "status": "COMPLETED"}
    (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))

    if all_results:
        info(f"   🔢 {len(all_results)} versões de API encontradas em {len(by_host)} hosts")
        if flagged:
            warn(f"   ⚠️ {len(flagged)} versões antigas ainda ativas!")
    else:
        info(f"   ✅ Nenhuma versão de API detectada. Testados {tests_run} paths.")

    success(f"   📂 Salvos em {output_file}")
    return all_results
