from pathlib import Path

def ensure_outdir(target: str) -> Path:
    """
    Cria: output/<target>/endpoint
    """
    out = Path("output") / target / "endpoint"
    out.mkdir(parents=True, exist_ok=True)
    return out
