import shutil
import subprocess
from pathlib import Path
from ..output import info, success, warn, error, run_command

def run_gospider(urls_file: Path, output_dir: Path):
    """
    Executa o Gospider.
    Nota: Gospider gera multiplos arquivos, precisamos consolidar ou gerenciar o output dir.
    """
    gospider_bin = shutil.which("gospider")
    if not gospider_bin:
        warn("Gospider nao encontrado. Pulando etapa.")
        return

    info(f"Executando Gospider em: {urls_file}")
    
    # Gospider requer input site a site ou -S para lista
    cmd = [
        gospider_bin,
        "-S", str(urls_file),
        "-o", str(output_dir),
        "-c", "10",
        "-d", "2",
        "--other-source", # Include other sources like Wayback, etc.
        "--include-subs"
    ]
    
    run_command(cmd)
    
    success(f"Gospider finalizado. Verify output dir: {output_dir}")
