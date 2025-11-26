class Color:
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    END = "\033[0m"


def info(msg: str):
    print(f"{Color.BLUE}[INFO]{Color.END} {msg}")


def success(msg: str):
    print(f"{Color.GREEN}[OK]{Color.END} {msg}")


def warn(msg: str):
    print(f"{Color.YELLOW}[WARN]{Color.END} {msg}")


def error(msg: str):
    print(f"{Color.RED}[ERRO]{Color.END} {msg}")
