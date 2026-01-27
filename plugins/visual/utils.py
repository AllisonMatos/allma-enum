from pathlib import Path

def ensure_outdir(target: str) -> Path:
    outdir = Path("output") / target / "visual"
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir
