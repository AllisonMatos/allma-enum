from pathlib import Path

def find_tool(filename: str):
    """
    Procura ferramentas locais dentro do projeto.
    Exemplo: find_tool("JSScanner.py")
    """
    candidates = [
        Path("tools") / filename,
        Path("tools") / "jsscanner" / filename,
        Path(filename),
        Path.cwd() / filename,
    ]

    for c in candidates:
        if c.exists():
            return c

    return None
