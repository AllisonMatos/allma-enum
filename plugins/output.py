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

_GLOBAL_LOGFILE = "logs/enum_allma.log"

def set_target_logfile(target: str):
    global _GLOBAL_LOGFILE
    _GLOBAL_LOGFILE = f"output/{target}/pipeline.log"
    os.makedirs(f"output/{target}", exist_ok=True)

def _log(level: str, msg: str):
    try:
        if _GLOBAL_LOGFILE.startswith("logs/"):
            os.makedirs("logs", exist_ok=True)
            
        clean_msg = ANSI_ESCAPE.sub('', msg)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(_GLOBAL_LOGFILE, "a", encoding="utf-8") as f:
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
