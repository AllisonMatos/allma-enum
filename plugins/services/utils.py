from pathlib import Path

def ensure_outdir(target: str) -> Path:
    """
    Cria o diretório output/<target>/services
    """
    outdir = Path("output") / target / "services"
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir
