#!/usr/bin/env python3
"""
plugins/urls/main.py - Coleta URLs a partir das URLs válidas do módulo domain
e valida novamente com httpx.

Saídas:
  output/<target>/urls/url_completas.txt
  output/<target>/urls/urls_200.txt
"""

from pathlib import Path
import subprocess

from menu import C

from ..output import info, success, warn, error
from .utils import ensure_outdir, require_binary

WANT_STATUS = "200,301,302,307,308"


# ============================================================
# Validação com httpx
# ============================================================
def httpx_validate(in_file: Path, out_file: Path, want_status: str = WANT_STATUS):
    info(f"{C.BOLD}{C.BLUE}🔎 Validando URLs com httpx (mc={want_status})...{C.END}")

    httpx = require_binary("httpx")

    cmd = [
        httpx,
        "-l", str(in_file),
        "-mc", want_status,
        "-o", str(out_file),
        "-silent",
    ]

    subprocess.run(cmd)

    if not out_file.exists() or out_file.stat().st_size == 0:
        warn("⚠️ Nenhuma URL válida encontrada via httpx.")
        return []

    urls = sorted(
        set(
            l.strip()
            for l in out_file.read_text(errors="ignore").splitlines()
            if l.strip()
        )
    )

    out_file.write_text("\n".join(urls) + "\n")

    success(f"✨ {len(urls)} URLs válidas salvas em: {C.GREEN}{out_file}{C.END}")
    return urls


# ============================================================
# MAIN
# ============================================================
def run(context: dict):
    target = context.get("target")

    if not target:
        raise ValueError("context['target'] é obrigatório para o plugin urls")

    # ============================================================
    # 🎯 CABEÇALHO PREMIUM
    # ============================================================
    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   🔗 {C.BOLD}{C.CYAN}INICIANDO MÓDULO: URLS{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    outdir = ensure_outdir(target)
    url_completas = outdir / "url_completas.txt"
    urls_200 = outdir / "urls_200.txt"

    # ============================================================
    # ETAPA 1 — Validar arquivo de entrada
    # ============================================================
    domain_200 = Path("output") / target / "domain" / "urls_valid.txt"

    info(f"{C.BOLD}{C.BLUE}📄 Verificando arquivo de entrada do módulo DOMAIN...{C.END}")

    if not domain_200.exists():
        error(f"❌ Arquivo de entrada não encontrado: {domain_200}")
        return []

    # limpar arquivo anterior
    if url_completas.exists():
        url_completas.unlink()

    # ============================================================
    # ETAPA 2 — Executar urlfinder
    # ============================================================
    info(f"{C.BOLD}{C.BLUE}🌐 Coletando URLs com urlfinder...{C.END}")

    urlfinder = require_binary("urlfinder")
    cmd = [urlfinder, "-list", str(domain_200), "-silent"]

    try:
        with url_completas.open("w", encoding="utf-8", errors="ignore") as fout:
            proc = subprocess.Popen(
                cmd,
                stdout=fout,
                stderr=subprocess.PIPE,
                text=True,
            )
            proc.wait()

    except Exception as e:
        error(f"❌ Falha ao executar urlfinder: {e}")
        return []

    if not url_completas.exists() or url_completas.stat().st_size == 0:
        warn("⚠️ urlfinder não retornou nenhuma URL.")
        return []

    # ============================================================
    # ETAPA 3 — Deduplicar URLs
    # ============================================================
    info(f"{C.BOLD}{C.BLUE}🧹 Deduplicando URLs encontradas...{C.END}")

    lines = [
        l.strip()
        for l in url_completas.read_text(errors="ignore").splitlines()
        if l.strip()
    ]

    unique = sorted(set(lines))
    url_completas.write_text("\n".join(unique) + "\n")

    success(f"📁 {len(unique)} URLs coletadas em: {C.GREEN}{url_completas}{C.END}")

    # ============================================================
    # ETAPA 4 — Validar URLs com httpx
    # ============================================================
    info(f"{C.BOLD}{C.BLUE}🔍 Validando URLs com HTTPX...{C.END}")

    valid_urls = httpx_validate(url_completas, urls_200)

    # ============================================================
    # 🎉 FINALIZAÇÃO
    # ============================================================
    success(
        f"\n{C.GREEN}{C.BOLD}✔ URLS concluído com sucesso!{C.END}\n"
        f"🔗 URLs válidas: {C.YELLOW}{len(valid_urls)}{C.END}\n"
        f"📂 Arquivo final salvo em:\n"
        f"   {C.CYAN}{urls_200}{C.END}\n"
    )

    return valid_urls
