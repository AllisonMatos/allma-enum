import shutil
import subprocess
import re
from pathlib import Path
from urllib.parse import urlparse
from ..output import info, success, warn, error


def run_gospider(urls_file: Path, output_dir: Path, user_agent: str = None) -> list:
    """
    Executa o GoSpider para crawling adicional.
    Retorna lista de URLs descobertas.
    """
    gospider_bin = shutil.which("gospider")
    if not gospider_bin:
        warn("GoSpider nao encontrado. Pulando etapa.")
        return []

    info(f"Executando GoSpider em: {urls_file}")

    # V11: Limpar output_dir para evitar mistura com resultados anteriores
    if output_dir.exists():
        for old_file in output_dir.glob("*"):
            if old_file.is_file():
                try:
                    old_file.unlink()
                except Exception:
                    pass

    # V11: Importar UA padrão se não fornecido
    if not user_agent:
        try:
            from core.config import DEFAULT_USER_AGENT
            user_agent = DEFAULT_USER_AGENT
        except ImportError:
            user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    cmd = [
        gospider_bin,
        "-S", str(urls_file),
        "-o", str(output_dir),
        "-c", "10",
        "-d", "2",
        "--other-source",
        "--include-subs",
        "-q",   # Quiet mode
        "-u", user_agent,  # V11: User-Agent customizado
    ]

    try:
        result = subprocess.run(
            cmd,
            timeout=600,
            check=False,
            capture_output=True,
            text=True,
        )
        # V11: Verificar exit code e logar stderr
        if result.returncode != 0:
            warn(f"GoSpider saiu com código {result.returncode}")
            if result.stderr:
                stderr_lines = result.stderr.strip().splitlines()
                for line in stderr_lines[:5]:  # Primeiras 5 linhas de erro
                    warn(f"  [GoSpider stderr] {line[:200]}")
    except subprocess.TimeoutExpired:
        warn("GoSpider timeout (600s). Resultados parciais podem existir.")
    except Exception as e:
        error(f"Erro ao executar GoSpider: {e}")
        return []

    # Extrair URLs dos arquivos de output do GoSpider
    discovered = set()
    url_pattern = re.compile(r'https?://[^\s\]"\'>< ]+')

    for out_file in output_dir.glob("*"):
        if out_file.is_file():
            try:
                for line in out_file.read_text(errors="ignore").splitlines():
                    matches = url_pattern.findall(line)
                    for url in matches:
                        # V11: Validar que a URL extraída tem hostname válido
                        try:
                            parsed = urlparse(url)
                            if parsed.hostname and len(parsed.hostname) > 2 and "." in parsed.hostname:
                                discovered.add(url)
                        except Exception:
                            pass
            except Exception:
                pass

    if discovered:
        success(f"GoSpider encontrou {len(discovered)} URLs.")
    else:
        warn("GoSpider finalizado sem URLs descobertas.")

    return list(discovered)
