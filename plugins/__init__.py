from pathlib import Path

def ensure_outdir(target: str, module_name: str) -> Path:
    """Garante que o diretório de output do módulo exista e retorna o Path."""
    outdir = Path("output") / target / module_name
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir
