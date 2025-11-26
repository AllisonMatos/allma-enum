#!/usr/bin/env python3
"""
Plugin FILES

Agrupa URLs por extensão encontradas em:
  output/<target>/urls/urls_200.txt

Saída:
  output/<target>/files/files_by_extension.txt
"""

from pathlib import Path
from urllib.parse import urlparse, unquote
import re

from menu import C

from ..output import info, success, warn, error
from .utils import ensure_outdir


# ----------------------------------------------
# Detecta a extensão baseada na URL
# ----------------------------------------------
def detect_extension_from_url(url: str) -> str:
    try:
        p = urlparse(url)
        path = unquote(p.path or "")

        # ex: file.zip, file.tar.gz
        m = re.search(r"\.([a-zA-Z0-9]{1,10})(?:\.([a-zA-Z0-9]{1,10}))?$", path)
        if m:
            if m.group(2):
                return f"{m.group(1).lower()}.{m.group(2).lower()}"
            return m.group(1).lower()

        # tenta achar extensão no querystring
        query = unquote(p.query or "")
        m2 = re.search(r"([a-zA-Z0-9_\-]+\.(?:[a-zA-Z0-9.]+))", query)
        if m2:
            return m2.group(1).split(".")[-1].lower()

    except:
        pass

    return "others"


# ----------------------------------------------
# Agrupa URLs por extensão
# ----------------------------------------------
def build_groups(urls: list) -> dict:
    groups = {}
    for u in urls:
        ext = detect_extension_from_url(u)
        groups.setdefault(ext, []).append(u)

    for k in groups:
        groups[k] = sorted(set(groups[k]))

    return groups


# ----------------------------------------------
# Escreve arquivo único final
# ----------------------------------------------
def write_single_by_extension(groups: dict, outdir: Path):
    outfile = outdir / "files_by_extension.txt"

    ordered = sorted([e for e in groups if e != "others"])
    if "others" in groups:
        ordered.append("others")

    lines = []
    for ext in ordered:
        header = f"=== .{ext} ===" if ext != "others" else "=== others ==="
        lines.append(header)
        lines.extend(groups[ext])
        lines.append("")

    outfile.write_text("\n".join(lines).strip() + "\n")
    return outfile


# ----------------------------------------------
# Plugin principal
# ----------------------------------------------
def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("context['target'] é obrigatório para plugin FILES")

    # ======================================================
    # 🎯 Cabeçalho Premium
    # ======================================================
    info(
        f"\n🟪──────────────────────────────────────────────────────────🟪\n"
        f"   📁 {C.BOLD}{C.CYAN}INICIANDO MÓDULO: FILES{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪──────────────────────────────────────────────────────────🟪\n"
    )

    outdir = ensure_outdir(target)
    input_file = Path("output") / target / "urls" / "urls_200.txt"

    # ======================================================
    # 📄 ETAPA 1 — Ler URLs
    # ======================================================
    info(f"{C.BOLD}{C.BLUE}📄 Lendo URLs a partir de urls_200.txt...{C.END}")

    if not input_file.exists():
        error(f"❌ Entrada não encontrada: {C.RED}{input_file}{C.END}")
        return []

    urls = [
        l.strip()
        for l in input_file.read_text(errors="ignore").splitlines()
        if l.strip()
    ]

    if not urls:
        warn(f"⚠️ Nenhuma URL válida encontrada em {input_file}")
        return []

    # ======================================================
    # 🧩 ETAPA 2 — Agrupar por extensão
    # ======================================================
    info(f"{C.BOLD}{C.BLUE}🧩 Agrupando URLs por extensão...{C.END}")
    groups = build_groups(urls)

    # ======================================================
    # 💾 ETAPA 3 — Salvar arquivo final
    # ======================================================
    info(f"{C.BOLD}{C.BLUE}💾 Salvando arquivo final...{C.END}")
    outfile = write_single_by_extension(groups, outdir)

    # ======================================================
    # 🎉 FINALIZAÇÃO
    # ======================================================
    success(
        f"\n{C.GREEN}{C.BOLD}✔ FILES concluído com sucesso!{C.END}\n"
        f"📂 Arquivo organizado por extensão salvo em:\n"
        f"   {C.CYAN}{outfile}{C.END}\n"
    )

    return [str(outfile)]
