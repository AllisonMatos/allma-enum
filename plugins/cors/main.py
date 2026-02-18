"""
CORS Misconfiguration Scanner — Detecta configurações CORS inseguras.
Testa reflexão de Origin, wildcard, null origin em URLs válidas.
"""
import json
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from menu import C
from ..output import info, success, warn, error
from ..http_utils import format_http_request, format_http_response


# Origens maliciosas para testar
EVIL_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
]


def ensure_outdir(target: str) -> Path:
    outdir = Path("output") / target / "cors"
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir


def check_cors(url: str, target: str) -> dict | None:
    """Testa CORS misconfigs em uma URL."""
    import httpx

    results = []

    try:
        with httpx.Client(timeout=8, verify=False, follow_redirects=True) as client:
            # 1) Testar reflexão de origin arbitrário
            for origin in EVIL_ORIGINS:
                try:
                    resp = client.get(url, headers={
                        "Origin": origin,
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                    })

                    acao = resp.headers.get("access-control-allow-origin", "")
                    acac = resp.headers.get("access-control-allow-credentials", "")

                    if not acao:
                        continue

                    finding = {
                        "url": url,
                        "tested_origin": origin,
                        "acao": acao,
                        "credentials": acac.lower() == "true",
                        "severity": "info",
                        "issue": "",
                        "response_raw": format_http_response(resp),
                        "request_raw": format_http_request(resp.request)
                    }

                    # Classificar severidade
                    if acao == origin and origin != "null":
                        finding["severity"] = "critical" if acac.lower() == "true" else "high"
                        finding["issue"] = "Origin reflected (arbitrary)"
                    elif acao == "*":
                        finding["severity"] = "medium"
                        finding["issue"] = "Wildcard ACAO (*)"
                    elif acao == "null" and origin == "null":
                        finding["severity"] = "high" if acac.lower() == "true" else "medium"
                        finding["issue"] = "Null origin accepted"

                    if finding["issue"]:
                        results.append(finding)

                except Exception:
                    pass

            # 2) Testar subdomínio do target
            subdomain_origin = f"https://evil.{target}"
            try:
                resp = client.get(url, headers={
                    "Origin": subdomain_origin,
                    "User-Agent": "Mozilla/5.0"
                })
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")

                if acao == subdomain_origin:
                    results.append({
                        "url": url,
                        "tested_origin": subdomain_origin,
                        "acao": acao,
                        "credentials": acac.lower() == "true",
                        "severity": "high",
                        "issue": "Subdomain prefix accepted",
                        "response_raw": format_http_response(resp),
                        "request_raw": format_http_request(resp.request)
                    })
            except Exception:
                pass

    except Exception:
        pass

    return results if results else None


def run(context: dict):
    """Executa CORS scan em URLs válidas."""
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟧───────────────────────────────────────────────────────────🟧\n"
        f"   🌐 {C.BOLD}{C.CYAN}CORS MISCONFIGURATION SCANNER{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟧───────────────────────────────────────────────────────────🟧\n"
    )

    outdir = ensure_outdir(target)

    # Ler URLs válidas
    urls_file = Path("output") / target / "domain" / "urls_valid.txt"
    if not urls_file.exists():
        warn("⚠️ Nenhuma URL válida encontrada. Execute o módulo domain primeiro.")
        return []

    valid_urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]

    # Deduplicar por base URL
    from urllib.parse import urlparse
    seen = set()
    unique_urls = []
    for u in valid_urls:
        parsed = urlparse(u)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base not in seen:
            seen.add(base)
            unique_urls.append(base)

    info(f"   📋 Testando CORS em {len(unique_urls)} hosts únicos...")

    # Executar em paralelo
    all_findings = []

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(check_cors, url, target): url for url in unique_urls}

        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    all_findings.extend(result)
                    for f in result:
                        sev_color = C.RED if f["severity"] in ("critical", "high") else C.YELLOW
                        cred_str = " +credentials" if f["credentials"] else ""
                        info(f"   🚨 {sev_color}[{f['severity'].upper()}]{C.END} {f['url']} → {f['issue']}{cred_str}")
            except Exception:
                pass

    # Salvar
    output_file = outdir / "cors_results.json"
    output_file.write_text(json.dumps(all_findings, indent=2, ensure_ascii=False))

    if all_findings:
        critical = sum(1 for f in all_findings if f["severity"] == "critical")
        high = sum(1 for f in all_findings if f["severity"] == "high")
        medium = sum(1 for f in all_findings if f["severity"] == "medium")

        success(f"\n   🌐 {len(all_findings)} CORS misconfigurations encontradas!")
        info(f"   📊 Critical: {C.RED}{critical}{C.END} | High: {C.YELLOW}{high}{C.END} | Medium: {medium}")
        success(f"   📂 Salvos em {output_file}")
    else:
        info("   ✅ Nenhuma CORS misconfiguration encontrada.")

    return all_findings
