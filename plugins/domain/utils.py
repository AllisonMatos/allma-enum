from pathlib import Path
import shutil
import os


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
    Procura também em ~/go/bin e /usr/local/go/bin (útil com sudo).
    """
    path = shutil.which(name)
    if path:
        return path
    
    # Procurar em caminhos comuns do Go (sudo perde o PATH do user)
    home = os.environ.get("HOME") or os.path.expanduser("~")
    extra_paths = [
        os.path.join(home, "go", "bin"),
        "/usr/local/go/bin",
        os.path.join("/home", os.environ.get("SUDO_USER", ""), "go", "bin"),
    ]
    
    for d in extra_paths:
        candidate = os.path.join(d, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    
    raise RuntimeError(
        f"O binário '{name}' não está instalado ou não está no PATH. "
        f"Instale e tente novamente."
    )
