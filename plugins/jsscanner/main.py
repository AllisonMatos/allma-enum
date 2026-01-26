#!/usr/bin/env python3
"""
Plugin JSSCANNER — versão final com análise HTML
"""

from pathlib import Path
import subprocess
import shutil
import tempfile
import re
import time
from urllib.parse import urljoin

from menu import C

from ..output import info, warn, error, success
from .utils import ensure_outdir
from core.utils import find_tool

# ============================================================
# EXPRESSÕES REGULARES
# ============================================================
SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
RE_URL = re.compile(r"https?://[^\s'\"<>]+")
RE_KEY  = re.compile(r"(?i)(apikey|token|secret|bearer)[\s'\":=]{1,8}([A-Za-z0-9\-_]{8,128})")


# ============================================================
# EXTRAÇÃO DE JS VIA HTML
# ============================================================
def extract_js_from_html(url):
    """Baixa HTML e extrai <script src=""> (.js)"""
    try:
        import httpx # type: ignore
        with httpx.Client(follow_redirects=True, timeout=8) as c:
            r = c.get(url)
            if r.status_code != 200:
                return []
            if "html" not in r.headers.get("content-type", ""):
                return []

            html = r.text
    except Exception:
        return []

    js_urls = []
    for src in SCRIPT_SRC_RE.findall(html):
        full = urljoin(url, src)
        if full.lower().endswith(".js"):
            js_urls.append(full)

    return js_urls


# ============================================================
# COLETAR .JS DOS MÓDULOS ANTERIORES
# ============================================================
def gather_js_urls(target: str) -> list:
    base = Path("output") / target / "files"

    f1 = base / "js.txt"
    if f1.exists():
        info(f"📄 Lendo URLs .js de {f1}")
        return [l.strip() for l in f1.read_text().splitlines() if l.strip()]

    f2 = base / "files_by_extension.txt"
    if f2.exists():
        info(f"📄 Buscando seção .js em {f2}")
        txt = f2.read_text(errors="ignore")
        m = re.search(r"===\s*\.js\s*===(.*?)(?:\n===|\Z)", txt, flags=re.S)
        if m:
            urls = [l.strip() for l in m.group(1).splitlines() if l.strip()]
            if urls:
                return urls

    f3 = Path("output") / target / "urls" / "url_completas.txt"
    if f3.exists():
        info(f"📄 Filtrando URLs .js em {f3}")
        return [
            l.strip() for l in f3.read_text().splitlines()
            if l.strip().lower().endswith(".js")
        ]

    f4 = Path("output") / target / "domain" / "extracted_js.txt"
    if f4.exists():
        info(f"📄 Lendo JS extraído pelo módulo DOMAIN em {f4}")
        return [l.strip() for l in f4.read_text().splitlines() if l.strip()]

    return []


# ============================================================
# LOCALIZAÇÃO DO SCRIPT EXTERNO JSScanner.py
# ============================================================
def locate_jsscanner():
    return find_tool("JSScanner.py")


# ============================================================
# EXECUTAR JSScanner.py EXTERNO
# ============================================================
def run_external_jsscanner(script: Path, list_file: Path, regex_file: Path, raw_file: Path, extra_args: str):
    cmd = ["python3", str(script)]
    if extra_args:
        cmd += extra_args.split()

    info(f"▶️ Executando JSScanner.py: {' '.join(cmd)}")

    try:
        proc = subprocess.run(
            cmd,
            input=f"{list_file}\n{regex_file}\n",
            text=True,
            capture_output=True
        )
        raw_file.write_text(proc.stdout + proc.stderr)
        return proc.returncode == 0

    except Exception as e:
        warn(f"⚠️ Erro ao executar JSScanner.py: {e}")
        return False


# ============================================================
# FALLBACK (caso não exista JSScanner.py)
# ============================================================
def download_js(url):
    try:
        import httpx # type: ignore
        r = httpx.get(url, follow_redirects=True, timeout=10)
        return r.text if r.status_code == 200 else None
    except:
        try:
            import requests
            r = requests.get(url, timeout=10)
            return r.text if r.status_code == 200 else None
        except:
            return None


def fallback_scan(js_urls, raw_path, report_path):
    info(f"{C.BLUE}{C.BOLD}🔄 Executando fallback do JSScanner...{C.END}")

    with raw_path.open("w") as fout_raw, report_path.open("w") as fout_rep:
        for url in js_urls:
            fout_raw.write(f"=== FILE: {url} ===\n")
            text = download_js(url)

            if not text:
                fout_raw.write("[DOWNLOAD FAILED]\n\n")
                continue

            fout_raw.write(text[:20000] + "\n\n")

            found_urls = RE_URL.findall(text)
            found_keys = [m[1] for m in RE_KEY.findall(text)]

            fout_rep.write(f"FILE: {url}\n")
            if found_urls:
                fout_rep.write("  URLs:\n")
                for u in found_urls[:100]:
                    fout_rep.write(f"    - {u}\n")

            if found_keys:
                fout_rep.write("  Keys:\n")
                for k in found_keys:
                    fout_rep.write(f"    - {k}\n")

            fout_rep.write("\n")


# ============================================================
# MAIN
# ============================================================
def run(context: dict):
    target = context.get("target")
    regex_file = context.get("regex_file")
    extra_args = context.get("extra_args", "")

    if not target:
        raise ValueError("context['target'] é obrigatório no plugin jsscanner")

    # ============================================================
    # 🎯 CABEÇALHO PREMIUM
    # ============================================================
    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   ⚡ {C.BOLD}{C.CYAN}INICIANDO MÓDULO: JSSCANNER{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    outdir = ensure_outdir(target)
    list_file = outdir / "jsscanner_list.txt"
    raw_file = outdir / "jsscanner_raw.txt"
    report_file = outdir / "jsscanner_report.txt"

    # ============================================================
    # ETAPA 1 — Coletar .js existentes
    # ============================================================
    info(f"{C.BOLD}{C.BLUE}📁 Coletando arquivos .js dos módulos anteriores...{C.END}")
    js_urls = gather_js_urls(target)

    # ============================================================
    # ETAPA 2 — Extra via HTML (script src)
    # ============================================================
    urls_200 = Path("output") / target / "urls" / "urls_200.txt"
    if urls_200.exists():
        html_pages = [l.strip() for l in urls_200.read_text().splitlines() if l.strip()]

        info(f"{C.BOLD}{C.BLUE}🌐 Analisando HTML para <script src>...{C.END}")
        extra_js = []
        for page in html_pages:
            extra_js.extend(extract_js_from_html(page))

        if extra_js:
            success(f"✨ {len(extra_js)} arquivos .js adicionais encontrados!")
            js_urls.extend(extra_js)

    # remover duplicados
    js_urls = sorted(set(js_urls))

    if not js_urls:
        warn("⚠️ Nenhum arquivo .js encontrado.")
        return []

    # salvar lista final
    list_file.write_text("\n".join(js_urls) + "\n")
    success(f"📄 Lista final de JS salva ({len(js_urls)} arquivos): {list_file}")

    # ============================================================
    # ETAPA 3 — REGEX
    # ============================================================
    regex_path = None

    # usuário passou regex
    if regex_file:
        regex_path = Path(regex_file)
        if not regex_path.exists():
            warn(f"⚠️ Regex informado não existe: {regex_path}")
            regex_path = None

    # regex padrão
    if regex_path is None:
        default_regex = Path("tools") / "JSScanner" / "regex.txt"
        if default_regex.exists():
            info(f"🔎 Usando regex padrão: {default_regex}")
            regex_path = default_regex

    # regex temporário
    if regex_path is None:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="w")
        tmp.write(r"https?://[^\s'\"<>]+" + "\n")
        tmp.write(r"/[A-Za-z0-9_\-/\.]+" + "\n")
        tmp.close()
        regex_path = Path(tmp.name)
        info(f"📄 Regex temporário criado: {regex_path}")

    # ============================================================
    # ETAPA 4 — Executar JSScanner.py externo
    # ============================================================
    script = locate_jsscanner()
    if script:
        info(f"{C.BOLD}{C.BLUE}⚙️ Executando JSScanner externo...{C.END}")
        ok = run_external_jsscanner(script, list_file, regex_path, raw_file, extra_args)
        if ok:
            report_file.write_text(raw_file.read_text()[:20000] + "\n")
            success(f"✔ JSScanner externo finalizado → {report_file}")
            return [str(report_file), str(raw_file)]
        else:
            warn("⚠️ JSScanner externo falhou — fallback ativado.")

    # ============================================================
    # ETAPA 5 — FALLBACK
    # ============================================================
    info(f"{C.BOLD}{C.BLUE}🔄 Executando fallback...{C.END}")
    fallback_scan(js_urls, raw_file, report_file)
    success(f"✔ Fallback concluído → {report_file}")

    return [str(report_file), str(raw_file)]
