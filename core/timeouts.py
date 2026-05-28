"""
core/timeouts.py — Constantes de timeout centralizadas e smart process monitor.

Substituíram os timeouts de 3h (10800s) cegos que travavam a pipeline.
Lógica: monitorar output do processo e matar se estagnar (sem novas linhas).
"""

import time
import subprocess
from pathlib import Path
from core.output import info, warn


# ============================================================
# CONSTANTES DE TIMEOUT
# ============================================================

# Katana (crawling headless) — hard limit
KATANA_HARD_TIMEOUT = 2400       # 40 min (era 3h / 10800s)

# GoSpider — hard limit
GOSPIDER_HARD_TIMEOUT = 2400     # 40 min

# Stale detection: se o arquivo de output parar de crescer por N segundos → kill
STALE_TIMEOUT = 300              # 5 min sem URLs novas

# httpx validation — hard limit para subprocess.run()
HTTPX_TIMEOUT = 1800             # 30 min (era 3h)

# Ferramentas históricas (gau, waybackurls, waymore, paramspider)
HISTORICAL_TIMEOUT = 600         # 10 min


# ============================================================
# CONTADORES PADRÃO
# ============================================================
def _count_file_lines(output_file: Path) -> int:
    """Conta linhas de um arquivo usando wc -l."""
    if not output_file.exists():
        return 0
    try:
        wc_res = subprocess.run(
            ["wc", "-l", str(output_file)],
            capture_output=True, text=True, timeout=5
        )
        if wc_res.stdout:
            return int(wc_res.stdout.split()[0])
    except Exception:
        pass
    return 0


def count_dir_lines(directory: Path) -> int:
    """Conta linhas de todos os arquivos em um diretório (para GoSpider)."""
    if not directory.exists():
        return 0
    try:
        wc_res = subprocess.run(
            ["find", str(directory), "-type", "f", "-exec", "cat", "{}", "+"],
            capture_output=True, timeout=10
        )
        if wc_res.stdout:
            return wc_res.stdout.count(b'\n')
    except Exception:
        pass
    return 0


# ============================================================
# SMART WAIT: monitora processo + early-exit por estagnação
# ============================================================
def smart_wait_process(
    proc: subprocess.Popen,
    output_file: Path,
    hard_timeout: int = KATANA_HARD_TIMEOUT,
    stale_timeout: int = STALE_TIMEOUT,
    label: str = "Processo",
    poll_interval: float = 2.0,
    count_fn=None,
) -> float:
    """
    Monitora um subprocess.Popen e o mata se:
      1. Atingir o hard_timeout (tempo total), ou
      2. O arquivo de output não crescer por stale_timeout segundos.

    Exibe progresso no terminal com \\r (inline update).

    Args:
        proc: O processo Popen a monitorar.
        output_file: Caminho do arquivo/dir de output que o processo escreve.
        hard_timeout: Timeout máximo absoluto em segundos.
        stale_timeout: Segundos sem crescimento no output → kill.
        label: Label para exibir no progresso (ex: "Katana R1").
        poll_interval: Intervalo de polling em segundos.
        count_fn: Função customizada para contar itens no output.
                  Recebe output_file e retorna int. Se None, usa wc -l.

    Returns:
        Tempo total decorrido em segundos.
    """
    start_time = time.time()
    last_count = 0
    last_change_time = start_time
    _counter = count_fn or _count_file_lines

    while proc.poll() is None:
        elapsed = time.time() - start_time

        # 1. Hard timeout
        if elapsed > hard_timeout:
            warn(f"   {label}: hard timeout ({hard_timeout // 60}min) atingido. Finalizando...")
            proc.kill()
            break

        # 2. Contar itens no output
        current_count = _counter(output_file)

        # 3. Stale detection
        if current_count > last_count:
            last_count = current_count
            last_change_time = time.time()
        elif current_count > 0 and (time.time() - last_change_time) > stale_timeout:
            info(
                f"   {label}: estagnado há {stale_timeout // 60}min "
                f"({current_count} itens). Finalizando inteligentemente..."
            )
            proc.kill()
            break

        # 4. Progresso inline
        mins = int(elapsed // 60)
        secs = int(elapsed % 60)
        stale_secs = int(time.time() - last_change_time)
        print(
            f"   ⏳ {label}: {mins}m{secs:02d}s | "
            f"Itens: {current_count} | "
            f"Sem novos: {stale_secs}s    ",
            end="\r"
        )

        time.sleep(poll_interval)

    print("")  # Limpa o \r
    total_elapsed = time.time() - start_time
    return total_elapsed
