#!/usr/bin/env python3
"""
Insecure File Upload Hints — Detecta endpoints de upload e verifica aceitação.
"""
import json
import time
import re
import httpx
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config import DEFAULT_USER_AGENT, REQUEST_DELAY, DEFAULT_TIMEOUT
from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from ..http_utils import format_http_request, format_http_response

UPLOAD_PATTERNS = [
    r"/upload", r"/import", r"/attach", r"/file", r"/media/upload",
    r"/api/upload", r"/api/file", r"/documents", r"/assets/upload",
]

DANGEROUS_EXTENSIONS = [".php", ".jsp", ".asp", ".aspx", ".exe", ".sh", ".py", ".pl", ".cgi", ".svg", ".html"]


def _test_upload_endpoint(url: str) -> dict | None:
    """Testa se um endpoint aceita uploads e quais métodos/tipos."""
    try:
        time.sleep(REQUEST_DELAY)
        with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False) as client:
            # OPTIONS
            resp_options = client.options(url, headers={"User-Agent": DEFAULT_USER_AGENT})
            allowed = resp_options.headers.get("allow", "").upper()
            accepts_post = "POST" in allowed or "PUT" in allowed

            # Tentar POST com multipart vazio
            resp_post = client.post(url, files={"file": ("test.txt", b"test", "text/plain")},
                                     headers={"User-Agent": DEFAULT_USER_AGENT})

            if resp_post.status_code < 405:
                body = resp_post.text[:3000].lower()
                details = f"Endpoint aceita POST (status {resp_post.status_code})"
                risk = "MEDIUM"

                if resp_post.status_code in (200, 201, 202):
                    risk = "HIGH"
                    details += " — upload possivelmente aceito"

                if any(ext in body for ext in [".php", ".jsp", ".asp"]):
                    risk = "CRITICAL"
                    details += " — extensões perigosas detectadas no response"

                return {
                    "url": url,
                    "status": resp_post.status_code,
                    "methods_allowed": allowed,
                    "risk": risk,
                    "type": "FILE_UPLOAD",
                    "details": details,
                    "request_raw": format_http_request(resp_post.request),
                    "response_raw": format_http_response(resp_post),
                }
    except Exception:
        pass
    return None


def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟧───────────────────────────────────────────────────────────🟧\n"
        f"   📤 {C.BOLD}{C.CYAN}INSECURE FILE UPLOAD SCANNER{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟧───────────────────────────────────────────────────────────🟧\n"
    )

    outdir = ensure_outdir(target, "file_upload")

    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    if not urls_file.exists():
        warn("⚠️ urls_200.txt não encontrado.")
        (outdir / "file_upload_results.json").write_text(json.dumps([], indent=2))
        (outdir / "scan_summary.json").write_text(json.dumps({"tests_run": 0, "findings": 0, "status": "NO_INPUT"}, indent=2))
        return []

    all_urls = [l.strip() for l in urls_file.read_text(errors="ignore").splitlines() if l.strip()]

    # Filtrar URLs com padrão de upload
    candidates = []
    for url in all_urls:
        path = urlparse(url).path.lower()
        if any(re.search(p, path, re.I) for p in UPLOAD_PATTERNS):
            candidates.append(url)

    candidates = list(set(candidates))[:30]
    info(f"   📋 {len(candidates)} endpoints de upload detectados")

    if not candidates:
        info("   ✅ Nenhum endpoint de upload detectado.")
        (outdir / "file_upload_results.json").write_text(json.dumps([], indent=2))
        (outdir / "scan_summary.json").write_text(json.dumps({"tests_run": 0, "urls_checked": len(all_urls), "findings": 0, "status": "NO_UPLOAD"}, indent=2))
        return []

    results = []

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(_test_upload_endpoint, url): url for url in candidates}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
                    color = C.RED if result["risk"] in ("HIGH", "CRITICAL") else C.YELLOW
                    info(f"   {color}[{result['risk']}]{C.END} {result['url']}")
            except Exception:
                pass

    output_file = outdir / "file_upload_results.json"
    output_file.write_text(json.dumps(results, indent=2, ensure_ascii=False))

    summary = {"tests_run": len(candidates), "findings": len(results), "status": "COMPLETED"}
    (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))

    if results:
        success(f"\n   📤 {len(results)} upload endpoint(s) com risco!")
    else:
        info(f"   ✅ 0 uploads vulneráveis. Testados {len(candidates)} endpoints.")

    success(f"   📂 Salvos em {output_file}")
    return results
