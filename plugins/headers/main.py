"""
HTTP Security Headers Check — Verifica headers de segurança em URLs válidas.
Classifica de A-F baseado na presença de headers recomendados.
"""
import json
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from menu import C
from ..output import info, success, warn, error
from ..http_utils import format_http_request, format_http_response

# Headers de segurança e suas descrições
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "desc": "Força HTTPS, previne downgrade attacks",
        "weight": 15,
    },
    "Content-Security-Policy": {
        "desc": "Previne XSS, data injection, clickjacking",
        "weight": 20,
    },
    "X-Frame-Options": {
        "desc": "Previne clickjacking (iframe embedding)",
        "weight": 10,
    },
    "X-Content-Type-Options": {
        "desc": "Previne MIME sniffing",
        "weight": 10,
    },
    "Referrer-Policy": {
        "desc": "Controla informação enviada no Referer header",
        "weight": 10,
    },
    "Permissions-Policy": {
        "desc": "Controla acesso a APIs do browser (camera, geo, etc)",
        "weight": 10,
    },
    "X-XSS-Protection": {
        "desc": "Filtro XSS do browser (legacy but still checked)",
        "weight": 5,
    },
    "Cross-Origin-Opener-Policy": {
        "desc": "Isola processo do browser (Spectre protection)",
        "weight": 5,
    },
    "Cross-Origin-Resource-Policy": {
        "desc": "Controla quem pode carregar recursos",
        "weight": 5,
    },
    "Cross-Origin-Embedder-Policy": {
        "desc": "Controla embedding cross-origin",
        "weight": 5,
    },
    "Cache-Control": {
        "desc": "Controla caching de conteúdo sensível",
        "weight": 5,
    },
}


def ensure_outdir(target: str) -> Path:
    outdir = Path("output") / target / "headers"
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir


def calculate_grade(score: int) -> str:
    """Calcula grade A-F baseado no score."""
    if score >= 90:
        return "A+"
    elif score >= 80:
        return "A"
    elif score >= 70:
        return "B"
    elif score >= 55:
        return "C"
    elif score >= 40:
        return "D"
    elif score >= 25:
        return "E"
    return "F"


def check_headers(url: str) -> dict | None:
    """Verifica headers de segurança de uma URL."""
    import httpx

    try:
        with httpx.Client(timeout=8, verify=False, follow_redirects=True) as client:
            resp = client.get(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            })

            if resp.status_code >= 500:
                return None

            headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            present = []
            missing = []
            score = 0
            total_weight = sum(h["weight"] for h in SECURITY_HEADERS.values())

            for header_name, config in SECURITY_HEADERS.items():
                header_val = headers_lower.get(header_name.lower(), "")
                if header_val:
                    present.append({
                        "header": header_name,
                        "value": header_val[:200],
                        "desc": config["desc"],
                    })
                    score += config["weight"]
                else:
                    missing.append({
                        "header": header_name,
                        "desc": config["desc"],
                        "weight": config["weight"],
                    })

            pct = int((score / total_weight) * 100)
            grade = calculate_grade(pct)

            # Verificar headers perigosos
            warnings = []
            server = headers_lower.get("server", "")
            if server:
                warnings.append(f"Server header exposed: {server}")
            x_powered = headers_lower.get("x-powered-by", "")
            if x_powered:
                warnings.append(f"X-Powered-By exposed: {x_powered}")

            return {
                "url": str(resp.url),
                "status": resp.status_code,
                "grade": grade,
                "score": pct,
                "present": present,
                "missing": missing,
                "warnings": warnings,
                "present_count": len(present),
                "missing_count": len(missing),
                "response_raw": format_http_response(resp),
                "request_raw": format_http_request(resp.request)
            }

    except Exception:
        pass
    return None


def run(context: dict):
    """Executa verificação de headers de segurança."""
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟦───────────────────────────────────────────────────────────🟦\n"
        f"   🛡️ {C.BOLD}{C.CYAN}HTTP SECURITY HEADERS CHECK{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟦───────────────────────────────────────────────────────────🟦\n"
    )

    outdir = ensure_outdir(target)

    urls_file = Path("output") / target / "domain" / "urls_valid.txt"
    if not urls_file.exists():
        warn("⚠️ Nenhuma URL válida encontrada.")
        return []

    valid_urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]

    # Deduplicar por base URL
    seen = set()
    unique_urls = []
    for u in valid_urls:
        parsed = urlparse(u)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base not in seen:
            seen.add(base)
            unique_urls.append(base)

    info(f"   📋 Verificando headers em {len(unique_urls)} hosts únicos...")

    results = []

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(check_headers, url): url for url in unique_urls}

        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
                    grade = result["grade"]
                    grade_color = C.GREEN if grade.startswith("A") else C.YELLOW if grade in ("B", "C") else C.RED
                    info(
                        f"   {grade_color}[{grade}]{C.END} {result['url']} — "
                        f"{result['present_count']} present, {result['missing_count']} missing"
                    )
            except Exception:
                pass

    # Ordenar por score (pior primeiro)
    results.sort(key=lambda r: r["score"])

    output_file = outdir / "headers_results.json"
    output_file.write_text(json.dumps(results, indent=2, ensure_ascii=False))

    if results:
        avg_score = sum(r["score"] for r in results) / len(results)
        avg_grade = calculate_grade(int(avg_score))
        grade_a = sum(1 for r in results if r["grade"].startswith("A"))
        grade_f = sum(1 for r in results if r["grade"] == "F")

        success(f"\n   🛡️ {len(results)} hosts verificados!")
        info(f"   📊 Score médio: {int(avg_score)}% ({avg_grade})")
        info(f"   ✅ Grade A: {C.GREEN}{grade_a}{C.END} | ❌ Grade F: {C.RED}{grade_f}{C.END}")
        success(f"   📂 Salvos em {output_file}")
    else:
        info("   ⚠️ Nenhum resultado obtido.")

    return results
