from pathlib import Path

def ensure_outdir(target: str) -> Path:
    """
    Cria o diretório output/<target>/files
    """
    outdir = Path("output") / target / "files"
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir
