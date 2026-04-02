#!/usr/bin/env python3
"""
Prototype Pollution Hints — Detecta potencial poluição de protótipos JavaScript.
Combina análise de parâmetros com varredura estática de JS.
"""
import json
import time
import re
import httpx
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config import DEFAULT_USER_AGENT, REQUEST_DELAY, DEFAULT_TIMEOUT
from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from ..http_utils import format_http_request, format_http_response

POLLUTION_PAYLOADS = [
    ("__proto__[polluted]", "true"),
    ("__proto__.polluted", "true"),
    ("constructor[prototype][polluted]", "true"),
    ("constructor.prototype.polluted", "true"),
]

# Padrões em JS que indicam sinks vulneráveis
JS_SINK_PATTERNS = [
    (r"Object\.assign\s*\(", "Object.assign"),
    (r"_\.merge\s*\(", "lodash merge"),
    (r"_\.extend\s*\(", "lodash extend"),
    (r"\$\.extend\s*\(", "jQuery extend"),
    (r"\.defaultsDeep\s*\(", "lodash defaultsDeep"),
    (r"JSON\.parse\s*\(", "JSON.parse (potential sink)"),
    (r"__proto__", "__proto__ reference"),
    (r"Object\.create\s*\(null\)", "safe pattern (Object.create(null))"),
]


def _test_pollution(url: str) -> list:
    """Testa payloads de prototype pollution em parâmetros de URL."""
    findings = []
    parsed = urlparse(url)
    if not parsed.query:
        return findings

    for payload_key, payload_val in POLLUTION_PAYLOADS:
        time.sleep(REQUEST_DELAY)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[payload_key] = [payload_val]
        new_query = urlencode(qs, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

        try:
            with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=True) as client:
                resp = client.get(test_url, headers={"User-Agent": DEFAULT_USER_AGENT})
                body = resp.text[:10000]

                # Verificar reflexão do payload no body (possível PP client-side)
                if "polluted" in body.lower() and "true" in body.lower():
                    findings.append({
                        "url": url,
                        "test_url": test_url,
                        "payload": f"{payload_key}={payload_val}",
                        "status": resp.status_code,
                        "risk": "HIGH",
                        "type": "PROTOTYPE_POLLUTION",
                        "details": f"Payload '{payload_key}' refletido no response — possível prototype pollution",
                        "request_raw": format_http_request(resp.request),
                        "response_raw": format_http_response(resp),
                    })
                    break
        except Exception:
            pass

    return findings


def _scan_js_sinks(target: str) -> list:
    """Analisa arquivos JS coletados em busca de sinks vulneráveis."""
    js_dir = Path("output") / target / "jsscanner"
    js_urls_file = Path("output") / target / "jsscanner" / "js_urls.txt"
    hints = []

    # Ler conteúdo JS se disponível
    js_analysis_file = js_dir / "js_analysis.json"
    if js_analysis_file.exists():
        try:
            js_data = json.loads(js_analysis_file.read_text())
            if isinstance(js_data, dict):
                for url, content in js_data.items():
                    content_str = str(content)
                    for pattern, name in JS_SINK_PATTERNS:
                        if re.search(pattern, content_str):
                            hints.append({
                                "js_url": url,
                                "sink": name,
                                "type": "JS_SINK",
                                "risk": "MEDIUM",
                                "details": f"Sink '{name}' encontrado em {url}",
                            })
        except Exception:
            pass

    return hints


def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟨───────────────────────────────────────────────────────────🟨\n"
        f"   🧪 {C.BOLD}{C.CYAN}PROTOTYPE POLLUTION SCANNER{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟨───────────────────────────────────────────────────────────🟨\n"
    )

    outdir = ensure_outdir(target, "prototype_pollution")

    # 1. Análise estática de JS
    info(f"   📋 Fase 1: Analisando sinks em JavaScript...")
    js_hints = _scan_js_sinks(target)
    if js_hints:
        info(f"      ⚠️ {len(js_hints)} sinks potenciais encontrados em JS")

    # 2. Teste dinâmico de URLs
    info(f"   📋 Fase 2: Testando payloads em URLs com parâmetros...")
    urls_file = Path("output") / target / "urls" / "urls_200.txt"

    param_results = []
    tests_run = 0

    if urls_file.exists():
        all_urls = [l.strip() for l in urls_file.read_text(errors="ignore").splitlines() if l.strip()]
        candidates = [u for u in all_urls if "?" in u][:100]

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(_test_pollution, url): url for url in candidates}
            for future in as_completed(futures):
                tests_run += len(POLLUTION_PAYLOADS)
                try:
                    findings = future.result()
                    param_results.extend(findings)
                    for f in findings:
                        info(f"      🔴 {C.RED}POLLUTION{C.END} {f['url']}")
                except Exception:
                    pass

    all_results = param_results + js_hints

    output_file = outdir / "prototype_pollution_results.json"
    output_file.write_text(json.dumps(all_results, indent=2, ensure_ascii=False))

    summary = {"tests_run": tests_run, "js_sinks": len(js_hints), "dynamic_findings": len(param_results), "findings": len(all_results), "status": "COMPLETED"}
    (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))

    if param_results:
        success(f"\n   🧪 {len(param_results)} Prototype Pollution CONFIRMADO(s)!")
    elif js_hints:
        info(f"   ⚠️ {len(js_hints)} sinks JS potenciais (necessita validação manual).")
    else:
        info(f"   ✅ 0 Prototype Pollution. Testados {tests_run} requests.")

    success(f"   📂 Salvos em {output_file}")
    return all_results
