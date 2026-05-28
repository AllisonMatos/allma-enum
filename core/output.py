import os
import re
import threading
from datetime import datetime
from core.colors import C as Color

ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

_GLOBAL_LOGFILE = "logs/enum_allma.log"
_LOG_LOCK = threading.Lock()

# Multi-target: prefixo por processo (setado pelo multi_runner)
_MULTI_TARGET_PREFIX = ""

def set_target_logfile(target: str):
    global _GLOBAL_LOGFILE
    _GLOBAL_LOGFILE = f"output/{target}/execution.log"
    os.makedirs(f"output/{target}", exist_ok=True)

def _log(level: str, msg: str):
    # V11: Lock para thread-safety (múltiplos plugins usam ThreadPoolExecutor)
    with _LOG_LOCK:
        try:
            if _GLOBAL_LOGFILE.startswith("logs/"):
                os.makedirs("logs", exist_ok=True)

            clean_msg = ANSI_ESCAPE.sub('', msg)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            prefix = f"[{_MULTI_TARGET_PREFIX}] " if _MULTI_TARGET_PREFIX else ""
            with open(_GLOBAL_LOGFILE, "a", encoding="utf-8") as f:
                f.write(f"[{timestamp}] [{level}] {prefix}{clean_msg}\n")
        except Exception:
            pass

def _fmt_prefix():
    """Retorna prefixo formatado para modo multi-target."""
    if _MULTI_TARGET_PREFIX:
        return f"{Color.PURPLE}[{_MULTI_TARGET_PREFIX}]{Color.END} "
    return ""

def info(msg: str):
    print(f"{Color.BLUE}[INFO]{Color.END} {_fmt_prefix()}{msg}")
    _log("INFO", msg)

def success(msg: str):
    print(f"{Color.GREEN}[OK]{Color.END} {_fmt_prefix()}{msg}")
    _log("OK", msg)

def warn(msg: str):
    print(f"{Color.YELLOW}[WARN]{Color.END} {_fmt_prefix()}{msg}")
    _log("WARN", msg)

def error(msg: str):
    print(f"{Color.RED}[ERRO]{Color.END} {_fmt_prefix()}{msg}")
    _log("ERRO", msg)
