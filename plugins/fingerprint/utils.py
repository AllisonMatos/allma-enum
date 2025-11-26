from pathlib import Path

def ensure_outdir(target: str) -> Path:
    """
    Cria: output/<target>/fingerprint
    """
    out = Path("output") / target / "fingerprint"
    out.mkdir(parents=True, exist_ok=True)
    return out
