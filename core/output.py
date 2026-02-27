import os
import re
from datetime import datetime

class Color:
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    END = "\033[0m"

ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

def _log(level: str, msg: str):
    try:
        os.makedirs("logs", exist_ok=True)
        clean_msg = ANSI_ESCAPE.sub('', msg)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open("logs/enum_allma.log", "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] [{level}] {clean_msg}\n")
    except Exception:
        pass

def info(msg: str):
    print(f"{Color.BLUE}[INFO]{Color.END} {msg}")
    _log("INFO", msg)

def success(msg: str):
    print(f"{Color.GREEN}[OK]{Color.END} {msg}")
    _log("OK", msg)

def warn(msg: str):
    print(f"{Color.YELLOW}[WARN]{Color.END} {msg}")
    _log("WARN", msg)

def error(msg: str):
    print(f"{Color.RED}[ERRO]{Color.END} {msg}")
    _log("ERRO", msg)
