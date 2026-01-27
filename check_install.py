
import sys
import shutil
import importlib
from pkg_resources import working_set

# Define required python packages
REQUIRED_PYTHON = [
    "httpx",
    "requests",
    "bs4", # beautifulsoup4
    "lxml",
    "reportlab",
    "matplotlib",
    "weasyprint",
    "dns" # dnspython
]

# Define required system tools
REQUIRED_TOOLS = [
    "git",
    "curl",
    "wget",
    "nmap", 
    "naabu",
    "katana",
    "httpx", # Project discovery httpx
    "gowitness",
    "searchsploit"
]

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def check_python_modules():
    print(f"\n{YELLOW}[*] Checking Python Dependencies...{RESET}")
    all_ok = True
    for package in REQUIRED_PYTHON:
        try:
            importlib.import_module(package)
            print(f"{GREEN}[OK]{RESET} {package}")
        except ImportError:
            print(f"{RED}[MISSING]{RESET} {package}")
            all_ok = False
    return all_ok

def check_system_tools():
    print(f"\n{YELLOW}[*] Checking System Tools...{RESET}")
    all_ok = True
    for tool in REQUIRED_TOOLS:
        if shutil.which(tool):
            print(f"{GREEN}[OK]{RESET} {tool}")
        else:
            print(f"{RED}[MISSING]{RESET} {tool}")
            # Non-critical tools warning instead of error can be handled here
            if tool in ["naabu", "katana"]: 
               print(f"    {YELLOW}-> Required for full crawling/scanning capabilities{RESET}")
            all_ok = False
    return all_ok

def main():
    print(f"{YELLOW}=== Enum-Allma Environment Check ==={RESET}")
    
    py_ok = check_python_modules()
    sys_ok = check_system_tools()
    
    print("-" * 40)
    if py_ok and sys_ok:
        print(f"{GREEN}✓ All checks passed! You are ready to run.{RESET}")
        sys.exit(0)
    else:
        print(f"{RED}✗ Missing dependencies found.{RESET}")
        print(f"Install python deps: pip install -r requirements.txt")
        print(f"Install tools: sudo apt install ... or go install ...")
        sys.exit(1)

if __name__ == "__main__":
    main()
