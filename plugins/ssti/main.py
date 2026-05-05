#!/usr/bin/env python3
"""
SSTI Scanner — Server-Side Template Injection.
Detecta vulnerabilidades em engines como Jinja2, Twig, Freemarker, Velocity, etc.
"""
import json
import re
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx
from core.config import DEFAULT_USER_AGENT, DEFAULT_TIMEOUT
from menu import C
from plugins import ensure_outdir
from plugins.validation import finding
from plugins.http_utils import format_http_request, format_http_response, adapt_rate_limit, throttle

# Payloads de SSTI e as respostas matemáticas esperadas
SSTI_PAYLOADS = [
    # General / Jinja2 / Twig / Nunjucks
    {"payload": "{{7*7}}", "expected": "49", "engine": "Jinja2/Twig/Generic"},
    {"payload": "${7*7}", "expected": "49", "engine": "Freemarker/Velocity/EL"},
    {"payload": "<%= 7*7 %>", "expected": "49", "engine": "ERB/EJS"},
    {"payload": "#{7*7}", "expected": "49", "engine": "Spring/EL"},
    {"payload": "*{7*7}", "expected": "49", "engine": "Thymeleaf"},
    # Blind / Error based strings
    {"payload": "{{'a'*7}}", "expected": "aaaaaaa", "engine": "Jinja2/Twig"},
]

def check_ssti(url: str, params: dict, payload_data: dict) -> dict | None:
    """Testa um payload SSTI específico em uma URL com parâmetros."""
    payload = payload_data["payload"]
    expected = payload_data["expected"]
    
    # Injeta o payload em todos os parâmetros
    injected_params = {k: payload for k in params.keys()}
    query_string = urlencode(injected_params, doseq=True)
    base_url = url.split("?")[0]
    target_url = f"{base_url}?{query_string}"
    
    try:
        throttle()
        with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=True) as client:
            resp = client.get(target_url, headers={"User-Agent": DEFAULT_USER_AGENT})
            adapt_rate_limit(resp)
            
            # Verifica se o resultado da equação matemática foi renderizado na resposta
            if expected in resp.text and payload not in resp.text:
                # Confirmação dupla para evitar falso positivo (se '49' já existisse na página original)
                # Testa 7*8
                verify_payload = payload.replace("7*7", "7*8")
                verify_params = {k: verify_payload for k in params.keys()}
                verify_url = f"{base_url}?{urlencode(verify_params, doseq=True)}"
                
                resp2 = client.get(verify_url, headers={"User-Agent": DEFAULT_USER_AGENT})
                if "56" in resp2.text and verify_payload not in resp2.text:
                    return finding(
                        plugin="ssti",
                        target="",
                        title=f"Server-Side Template Injection ({payload_data['engine']})",
                        issue_type="SSTI",
                        risk="CRITICAL",
                        confidence="CONFIRMED",
                        url=target_url,
                        description=f"O template engine renderizou a equação matemática. Vulnerável a RCE.",
                        detection={"payload": payload, "engine": payload_data["engine"]},
                        validation={"math_evaluated": True},
                        evidence={
                            "request_raw": format_http_request(resp2.request),
                            "response_raw": format_http_response(resp2),
                            "matched_snippet": "56"
                        }
                    )
    except Exception:
        pass
    return None

def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    from core.output import info, success, warn
    info(
        f"\n🟥───────────────────────────────────────────────────────────🟥\n"
        f"   🔥 {C.BOLD}{C.CYAN}SSTI SCANNER (Template Injection){C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟥───────────────────────────────────────────────────────────🟥\n"
    )

    outdir = ensure_outdir(target, "ssti")
    
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    if not urls_file.exists():
        warn("⚠️ Nenhuma URL encontrada. Rode o módulo 'urls' primeiro.")
        return []

    valid_urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]
    
    # Filtra apenas URLs com parâmetros na querystring
    param_urls = {}
    for u in valid_urls:
        parsed = urlparse(u)
        if parsed.query:
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            params = parse_qs(parsed.query)
            if base not in param_urls:
                param_urls[base] = {"url": u, "params": params}
                
    if not param_urls:
        info("   ✅ Nenhuma URL com parâmetros de GET encontrada para testar SSTI.")
        return []
        
    info(f"   📋 Testando {len(param_urls)} rotas parametrizadas...")

    results = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for base, data in param_urls.items():
            for payload in SSTI_PAYLOADS:
                futures.append(executor.submit(check_ssti, data["url"], data["params"], payload))
                
        done = 0
        total = len(futures)
        for future in as_completed(futures):
            done += 1
            if done % 10 == 0:
                print(f"   [{done}/{total}] Testando payloads...", end="\r")
            try:
                res = future.result()
                if res:
                    results.append(res)
                    info(f"\n   🔥 {C.RED}[CRITICAL/CONFIRMED]{C.END} SSTI em {res['url']}")
            except Exception:
                pass

    print("")
    output_file = outdir / "findings.json"
    
    if results:
        output_file.write_text(json.dumps(results, indent=2, ensure_ascii=False))
        success(f"\n   🔥 {len(results)} vulnerabilidades SSTI encontradas!")
        success(f"   📂 Salvos em {output_file}")
    else:
        success("   ✅ Nenhuma injeção de template (SSTI) detectada.")

    return results
