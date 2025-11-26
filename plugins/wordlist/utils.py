from pathlib import Path

def ensure_outdir(target: str) -> Path:
    """
    Cria: output/<target>/wordlist
    """
    out = Path("output") / target / "wordlist"
    out.mkdir(parents=True, exist_ok=True)
    return out
