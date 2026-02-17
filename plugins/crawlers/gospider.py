import shutil
import subprocess
import re
from pathlib import Path
from ..output import info, success, warn, error


def run_gospider(urls_file: Path, output_dir: Path) -> list:
    """
    Executa o GoSpider para crawling adicional.
    Retorna lista de URLs descobertas.
    """
    gospider_bin = shutil.which("gospider")
    if not gospider_bin:
        warn("GoSpider nao encontrado. Pulando etapa.")
        return []

    info(f"Executando GoSpider em: {urls_file}")

    cmd = [
        gospider_bin,
        "-S", str(urls_file),
        "-o", str(output_dir),
        "-c", "10",
        "-d", "2",
        "--other-source",
        "--include-subs",
        "-q",   # Quiet mode
    ]

    try:
        subprocess.run(cmd, timeout=300, check=False)
    except subprocess.TimeoutExpired:
        warn("GoSpider timeout (300s). Resultados parciais podem existir.")
    except Exception as e:
        error(f"Erro ao executar GoSpider: {e}")
        return []

    # Extrair URLs dos arquivos de output do GoSpider
    discovered = set()
    url_pattern = re.compile(r'https?://[^\s\]"\'><]+')

    for out_file in output_dir.glob("*"):
        if out_file.is_file():
            try:
                for line in out_file.read_text(errors="ignore").splitlines():
                    matches = url_pattern.findall(line)
                    discovered.update(matches)
            except Exception:
                pass

    if discovered:
        success(f"GoSpider encontrou {len(discovered)} URLs.")
    else:
        warn("GoSpider finalizado sem URLs descobertas.")

    return list(discovered)
