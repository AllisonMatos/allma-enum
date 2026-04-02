#!/usr/bin/env python3
"""
Prototype Pollution Detection (V10 Pro) — Detecta poluição de protótipos JavaScript.
Combina análise de sinks (lodash, defineProperty) com payloads avançados e confirmação.
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

def _build_payloads(deep: bool = False):
    payloads = [
        ("__proto__[polluted]", "allma_v10"),
        ("__proto__.polluted", "allma_v10"),
    ]
    if deep:
        payloads.extend([
            ("constructor[prototype][polluted]", "allma_v10"),
            ("constructor.prototype.polluted", "allma_v10"),
            ("__proto__[toString]", "allma_v10"), # toString override attempt
            ("__proto__[polluted]", "{\"allma\":\"v10\"}"), # JSON payload
        ])
    return payloads

# Padrões Pro (V10) que indicam sinks vulneráveis ou referências de poluição
JS_SINK_PATTERNS = [
    (r"Object\.assign\s*\(", "Object.assign"),
    (r"_\.merge\s*\(", "lodash.merge"),
    (r"_\.extend\s*\(", "lodash.extend"),
    (r"\$\.extend\s*\(", "jQuery.extend"),
    (r"\.defaultsDeep\s*\(", "lodash.defaultsDeep"),
    (r"Object\.defineProperty\s*\(", "Object.defineProperty"),
    (r"JSON\.parse\s*\(", "JSON.parse (potential sink)"),
    (r"__proto__", "__proto__ reference"),
]

def _test_pollution(url: str, deep: bool = False) -> list:
    """Testa payloads de prototype pollution com verificação de reflexão."""
    findings = []
    parsed = urlparse(url)
    if not parsed.query and not deep:
        return []

    payloads = _build_payloads(deep)

    for p_key, p_val in payloads:
        time.sleep(REQUEST_DELAY)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[p_key] = [p_val]
        new_query = urlencode(qs, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

        try:
            with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=True) as client:
                resp = client.get(test_url, headers={"User-Agent": DEFAULT_USER_AGENT})
                body = resp.text[:15000].lower()

                # Confirmação V10: Reflexão do valor poluído no body
                # Se "allma_v10" aparecer no body, há uma chance alta de que o objeto foi poluído e refletido via code/template.
                if "allma_v10" in body:
                    findings.append({
                        "url": url,
                        "test_url": test_url,
                        "payload": f"{p_key}={p_val}",
                        "status": resp.status_code,
                        "risk": "HIGH",
                        "type": "PROTOTYPE_POLLUTION",
                        "details": f"Vulnerabilidade Detectada: Payload '{p_key}' refletido no body — forte indício de Prototype Pollution no lado do cliente.",
                        "request_raw": format_http_request(resp.request),
                        "response_raw": format_http_response(resp),
                    })
                    if not deep: break
        except Exception:
            pass
    return findings


def _scan_js_sinks(target: str) -> list:
    """Analisa arquivos JS coletados em busca de sinks Pro (V10)."""
    js_dir = Path("output") / target / "jsscanner"
    hints = []

    # Analisar o arquivo consolidado de análise JS
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
                                "details": f"Sink detectado em JS: '{name}' encontrado em {url}. Este endpoint pode ser vulnerável a Prototype Pollution se receber dados não sanitizados.",
                            })
        except Exception:
            pass
    return hints


def run(context: dict):
    target = context.get("target")
    deep = context.get("deep", False)
    stealth = context.get("stealth", False)
    
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟨───────────────────────────────────────────────────────────🟨\n"
        f"   🧪 {C.BOLD}{C.CYAN}PROTOTYPE POLLUTION SCANNER (V10 PRO){C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END} | Sinks: Avançado | Deep: {deep}\n"
        f"🟨───────────────────────────────────────────────────────────🟨\n"
    )

    outdir = ensure_outdir(target, "prototype_pollution")

    # 1. Análise Estática de JS (Fase 1)
    info(f"   📋 Fase 1: Varredura de Sinks Avançados em JavaScript...")
    js_hints = _scan_js_sinks(target)
    if js_hints:
        info(f"      ⚠️ {len(js_hints)} sinks JS suspeitos mapeados.")

    # 2. Teste Dinâmico (Fase 2)
    info(f"   📋 Fase 2: Testando payloads Pro (Deep={deep})...")
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    
    param_results = []
    tests_run = 0

    if urls_file.exists():
        all_urls = [l.strip() for l in urls_file.read_text(errors="ignore").splitlines() if l.strip()]
        
        # Filtro de escopo (V10)
        scoped_urls = []
        for u in all_urls:
            try:
                if urlparse(u).netloc.endswith(target):
                    scoped_urls.append(u)
            except: continue

        candidates = [u for u in scoped_urls if "?" in u]
        if deep:
             candidates.extend(scoped_urls[:50]) # Tenta injetar mesmo sem ? no deep
        
        candidates = list(set(candidates))[:100]
        max_workers = 3 if stealth else 8

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_test_pollution, url, deep): url for url in candidates}
            for future in as_completed(futures):
                try:
                    findings = future.result()
                    tests_run += 1
                    if findings:
                        param_results.extend(findings)
                        for f in findings:
                            info(f"      🔴 {C.RED}[POLLUTION]{C.END} {f['url']} (Reflexão confirmada)")
                except Exception:
                    pass

    all_results = param_results + js_hints
    output_file = outdir / "prototype_pollution_results.json"
    output_file.write_text(json.dumps(all_results, indent=2, ensure_ascii=False))

    summary = {"tests_run": tests_run, "js_sinks": len(js_hints), "findings": len(all_results), "status": "COMPLETED"}
    (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))

    if param_results:
        success(f"\n   🧪 {len(param_results)} Prototype Pollution CONFIRMADO(s) via reflexão de payload!")
    else:
        info(f"   ✅ 0 confirmações dinâmicas em {len(candidates)} URLs ({tests_run} hosts).")

    success(f"   📂 Resultados salvos em {output_file}")
    return all_results
