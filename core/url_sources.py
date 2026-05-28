"""
Helpers for choosing URL list files produced by plugins/urls (V12 hygiene).

urls_200.txt = apenas respostas 2xx (superfície viva para crawlers).
urls_alive.txt = mesmo conteúdo quando o pipeline V12 rodou; fallback legacy.
"""
from __future__ import annotations

from pathlib import Path


def urls_dir(base: Path) -> Path:
    return base / "urls"


def primary_urls_txt_for_scan(target: str) -> Path:
    """
    Arquivo texto de URLs para plugins que precisam de HTML/JS real (jsscanner, endpoint crawl, etc.).
    Prefere urls_alive.txt (2xx) gerado pelo módulo urls V12.
    """
    b = Path("output") / target
    ud = urls_dir(b)
    alive = ud / "urls_alive.txt"
    if alive.exists() and alive.stat().st_size > 0:
        return alive
    legacy = ud / "urls_200.txt"
    return legacy


def urls_json_for_status_map(target: str) -> Path:
    """JSON com url + status_code (+ campos extras) para o report."""
    b = Path("output") / target / "urls"
    allj = b / "urls_all.json"
    if allj.exists() and allj.stat().st_size > 0:
        return allj
    return b / "urls_200.json"
