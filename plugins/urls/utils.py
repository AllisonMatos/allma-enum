from pathlib import Path
import shutil


def ensure_outdir(target: str) -> Path:
    """
    Cria o diretório outputs/<target>/urls
    """
    outdir = Path("output") / target / "urls"
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir


def require_binary(name: str) -> str:
    """
    Verifica se o binário existe no sistema e retorna o caminho completo.
    Lança RuntimeError se não encontrar.
    """
    path = shutil.which(name)
    if not path:
        raise RuntimeError(
            f"O binário '{name}' não está instalado ou não está no PATH. "
            f"Instale e tente novamente."
        )
    return path
