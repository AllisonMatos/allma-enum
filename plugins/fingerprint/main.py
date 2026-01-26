#!/usr/bin/env python3
"""
plugins/fingerprint/main.py

Fingerprinting passivo:
 - consulta urls_200.txt (páginas válidas)
 - coleta headers HTTP, security headers, cookies
 - tenta obter info TLS/Certificado para o host
 - gera:
    output/<target>/fingerprint/headers.txt
    output/<target>/fingerprint/fingerprint_summary.txt
    output/<target>/fingerprint/cert_info.txt
"""

from pathlib import Path
from urllib.parse import urlparse
import socket
import ssl
import json
import time

from menu import C

from ..output import info, warn, success, error
from .utils import ensure_outdir


# ============================
# HTTP GET fail-fast
# ============================
def http_get_text_meta(url, timeout=6):
    try:
        import httpx # type: ignore
        try:
            with httpx.Client(follow_redirects=True, timeout=timeout) as c:
                r = c.get(url)
                return (r.status_code, r.text, dict(r.headers))
        except Exception:
            pass
    except Exception:
        pass

    try:
        import requests
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=True)
            return (r.status_code, r.text, dict(r.headers))
        except Exception:
            return (None, None, None)
    except Exception:
        return (None, None, None)


# ============================
# Obter certificado TLS
# ============================
def get_cert_info(hostname, port=443, timeout=6):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        return {"error": str(e)}


# ============================
# Filtrar headers importantes
# ============================
def summarize_headers(h):
    keys = [
        "server", "x-powered-by", "content-type", "content-security-policy",
        "strict-transport-security", "x-frame-options", "x-xss-protection",
        "x-content-type-options", "referrer-policy", "set-cookie"
    ]
    s = {}
    for k in keys:
        v = h.get(k) or h.get(k.title()) or h.get(k.upper())
        if v:
            s[k] = v
    return s


# ============================
# MAIN
# ============================
def run(context: dict):
    start = time.time()
    target = context.get("target")

    if not target:
        raise ValueError("context['target'] é obrigatório para plugin fingerprint")

    # ==========================================================================
    # 🎯 CABEÇALHO PREMIUM
    # ==========================================================================
    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   🔍 {C.BOLD}{C.CYAN}INICIANDO MÓDULO: FINGERPRINT{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    outdir = ensure_outdir(target)
    headers_file = outdir / "headers.txt"
    summary_file = outdir / "fingerprint_summary.txt"
    cert_file = outdir / "cert_info.txt"

    urls_200 = Path("output") / target / "urls" / "urls_200.txt"

    # ==========================================================================
    # 🌐 ETAPA 1 — Ler URLs
    # ==========================================================================
    info(f"{C.BOLD}{C.BLUE}🌐 Lendo URLs válidas (urls_200.txt)...{C.END}")

    if not urls_200.exists():
        warn(f"⚠️ Arquivo não encontrado: {C.RED}{urls_200}{C.END}")
        return []

    urls = [l.strip() for l in urls_200.read_text(errors="ignore").splitlines() if l.strip()]

    if not urls:
        warn(f"⚠️ Nenhuma URL válida encontrada para fingerprint.")
        return []

    all_headers = {}
    hosts = set()

    # ==========================================================================
    # 📥 ETAPA 2 — Coletar headers HTTP
    # ==========================================================================
    info(f"\n{C.BOLD}{C.BLUE}📥 Coletando headers HTTP...{C.END}")

    for u in urls:
        info(f"   🔎 {C.YELLOW}{u}{C.END}")
        status, _, headers = http_get_text_meta(u)

        if headers is None:
            headers = {}

        host = urlparse(u).netloc.split(":")[0]
        hosts.add(host)

        all_headers[u] = headers

    # ==========================================================================
    # 📝 ETAPA 3 — Salvar headers brutos
    # ==========================================================================
    info(f"\n{C.BOLD}{C.BLUE}📝 Salvando headers brutos...{C.END}")
    headers_file.write_text(json.dumps(all_headers, indent=2, ensure_ascii=False))
    info(f"   💾 Arquivo salvo: {C.GREEN}{headers_file}{C.END}")

    # ==========================================================================
    # 📊 ETAPA 4 — Gerar sumário de segurança
    # ==========================================================================
    info(f"\n{C.BOLD}{C.BLUE}📊 Gerando sumário de segurança...{C.END}")

    summary_lines = []
    for u, h in all_headers.items():
        s = summarize_headers(h)
        summary_lines.append(f"URL: {u}")
        for k, v in s.items():
            summary_lines.append(f"  {k}: {v}")
        summary_lines.append("")

    summary_file.write_text("\n".join(summary_lines))
    info(f"   💾 Sumário salvo: {C.GREEN}{summary_file}{C.END}")

    # ==========================================================================
    # 🔐 ETAPA 5 — Coletar Informações de Certificado TLS
    # ==========================================================================
    info(f"\n{C.BOLD}{C.BLUE}🔐 Coletando certificados TLS...{C.END}")

    certs = {}
    for host in sorted(hosts):
        info(f"   🔎 Certificado de {C.YELLOW}{host}{C.END}")
        cert = get_cert_info(host)
        certs[host] = cert

    cert_file.write_text(json.dumps(certs, indent=2, ensure_ascii=False))
    info(f"   💾 Certificado salvo: {C.GREEN}{cert_file}{C.END}")

    # ==========================================================================
    # 🎉 FINALIZAÇÃO
    # ==========================================================================
    t = time.time() - start

    success(
        f"\n{C.GREEN}{C.BOLD}✔ FINGERPRINT concluído com sucesso!{C.END}\n"
        f"🔎 URLs processadas: {C.YELLOW}{len(urls)}{C.END}\n"
        f"🔐 Certificados coletados: {C.YELLOW}{len(certs)}{C.END}\n"
        f"⏱️ Tempo total: {C.CYAN}{t:.1f}s{C.END}\n"
        f"📁 Output salvo em: {C.CYAN}{outdir}{C.END}\n"
    )

    return [str(headers_file), str(summary_file), str(cert_file)]
