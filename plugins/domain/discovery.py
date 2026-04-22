"""
Multi-source Subdomain Discovery
Fontes: crt.sh, haktrails, gau, waybackurls
Complementa o subfinder para aumentar cobertura de subdomínios.
"""
import subprocess
import shutil
import json
import re
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..output import info, success, warn, error
from menu import C


def _extract_hostnames_from_urls(lines: list, target: str) -> set:
    """Extrai hostnames de uma lista de URLs que pertencem ao target."""
    subs = set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            parsed = urlparse(line)
            host = parsed.netloc.split(":")[0] if parsed.netloc else ""
            if host and host.endswith(target):
                subs.add(host.lower())
        except Exception:
            pass
    return subs


def discover_crtsh(target: str) -> set:
    """
    Consulta Certificate Transparency via crt.sh (API HTTP pública).
    Retorna subdomínios encontrados em certificados SSL com suporte a retry robusto.
    """
    import time
    subs = set()
    try:
        import httpx
        url = f"https://crt.sh/?q=%25.{target}&output=json"
        
        transport = httpx.HTTPTransport(retries=3)
        with httpx.Client(transport=transport, timeout=90, verify=False, follow_redirects=True) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name.startswith("*."):
                            name = name[2:]
                        if name.endswith(target) and name:
                            subs.add(name)
        info(f"   📜 crt.sh: {len(subs)} subdomínios de certificados")
    except ImportError:
        warn("   httpx não instalado — crt.sh requer httpx")
    except Exception as e:
        warn(f"   crt.sh: erro — {e} (A API do crt.sh frequentemente sofre sobrecarga)")
    return subs


def discover_haktrails(target: str) -> set:
    """
    Usa haktrails (SecurityTrails) para descoberta de subdomínios.
    Requer: go install github.com/hakluke/haktrails@latest
    """
    subs = set()
    haktrails_bin = shutil.which("haktrails")
    if not haktrails_bin:
        warn("   haktrails não instalado — pulando")
        return subs

    try:
        result = subprocess.run(
            [haktrails_bin, "subdomains", "-d", target],
            capture_output=True, text=True, timeout=120
        )
        for line in result.stdout.splitlines():
            host = line.strip().lower()
            if host and host.endswith(target):
                subs.add(host)
        info(f"   🔍 haktrails: {len(subs)} subdomínios")
    except subprocess.TimeoutExpired:
        warn("   haktrails: timeout (120s)")
    except Exception as e:
        warn(f"   haktrails: erro — {e}")
    return subs


def discover_gau(target: str) -> set:
    """
    Usa gau (GetAllUrls) para extrair hostnames de URLs históricas.
    Requer: go install github.com/lc/gau/v2/cmd/gau@latest
    """
    subs = set()
    gau_bin = shutil.which("gau")
    if not gau_bin:
        warn("   gau não instalado — pulando")
        return subs

    try:
        result = subprocess.run(
            [gau_bin, "--subs", target],
            capture_output=True, text=True, timeout=600  # V11: 10min (domínios grandes)
        )
        subs = _extract_hostnames_from_urls(result.stdout.splitlines(), target)
        info(f"   🌐 gau: {len(subs)} subdomínios de URLs históricas")
    except subprocess.TimeoutExpired:
        warn("   gau: timeout (600s)")
    except Exception as e:
        warn(f"   gau: erro — {e}")
    return subs


def discover_waybackurls(target: str) -> set:
    """
    Usa waybackurls para extrair hostnames do Wayback Machine.
    Requer: go install github.com/tomnomnom/waybackurls@latest
    """
    subs = set()
    wayback_bin = shutil.which("waybackurls")
    if not wayback_bin:
        warn("   waybackurls não instalado — pulando")
        return subs

    try:
        proc = subprocess.run(
            ["bash", "-c", f"echo {target} | {wayback_bin}"],
            capture_output=True, text=True, timeout=600  # V11: 10min (domínios grandes)
        )
        subs = _extract_hostnames_from_urls(proc.stdout.splitlines(), target)
        info(f"   📦 waybackurls: {len(subs)} subdomínios do Wayback Machine")
    except subprocess.TimeoutExpired:
        warn("   waybackurls: timeout (600s)")
    except Exception as e:
        warn(f"   waybackurls: erro — {e}")
    return subs


def discover_subdomains(target: str, existing_subs_file: Path) -> set:
    """
    Executa todas as fontes de descoberta em paralelo e faz merge
    dos resultados com os subdomínios já encontrados pelo subfinder.

    Args:
        target: Domínio alvo
        existing_subs_file: Arquivo com subdomínios do subfinder

    Returns:
        set com todos os subdomínios (merged)
    """
    info(
        f"\n🟩──────────────────────────────────────────────────────────🟩\n"
        f"   🌍 {C.BOLD}{C.CYAN}MULTI-SOURCE DISCOVERY{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟩──────────────────────────────────────────────────────────🟩\n"
    )

    # Carregar subdomínios existentes do subfinder
    existing = set()
    if existing_subs_file.exists():
        existing = {l.strip().lower() for l in existing_subs_file.read_text().splitlines() if l.strip()}
    info(f"   Subfinder trouxe: {len(existing)} subdomínios")

    # Executar fontes em paralelo
    all_new = set()
    sources = [
        ("crt.sh", discover_crtsh),
        ("haktrails", discover_haktrails),
        ("gau", discover_gau),
        ("waybackurls", discover_waybackurls),
    ]

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(fn, target): name for name, fn in sources}
        for future in as_completed(futures):
            try:
                result = future.result()
                all_new.update(result)
            except Exception as e:
                source_name = futures[future]
                warn(f"   {source_name}: erro inesperado — {e}")

    # Merge
    new_only = all_new - existing
    merged = existing | all_new

    if new_only:
        info(f"\n   ✨ {C.GREEN}{len(new_only)} NOVOS subdomínios{C.END} encontrados pelas fontes adicionais!")
    else:
        info(f"   Nenhum subdomínio novo (fontes adicionais não trouxeram extras).")

    info(f"   📊 Total: {len(existing)} (subfinder) + {len(new_only)} (novo) = {C.BOLD}{len(merged)}{C.END}")

    # Salvar merged
    existing_subs_file.write_text("\n".join(sorted(merged)) + "\n")

    success(f"   ✔ {existing_subs_file.name} atualizado com {len(merged)} subdomínios.\n")

    return merged
