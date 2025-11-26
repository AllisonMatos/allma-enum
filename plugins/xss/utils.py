from pathlib import Path

def ensure_outdir(target: str):
    """
    Cria o diretório output/<target>/xss
    """
    outdir = Path("output") / target / "xss"
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir
