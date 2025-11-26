from pathlib import Path
import shutil


def ensure_outdir(target: str) -> Path:
    """
    Cria o diretório output/<target>/domain
    """
    outdir = Path("output") / target / "domain"
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir


def require_binary(name: str) -> str:
    """
    Verifica se o binário existe no sistema.
    """
    path = shutil.which(name)
    if not path:
        raise RuntimeError(f"O binário '{name}' não está instalado. Instale e tente novamente.")
    return path
