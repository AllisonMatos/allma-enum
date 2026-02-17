
import sys
import shutil
import importlib

# Define required python packages
REQUIRED_PYTHON = [
    "httpx",
    "requests",
    "bs4", # beautifulsoup4
    "lxml",
    "reportlab",
    "matplotlib",
    "weasyprint",
    "dns", # dnspython
    "aiohttp",
    "aiofiles",
]

# Define required system tools
REQUIRED_TOOLS = [
    "git",
    "curl",
    "wget",
    "nmap", 
    "naabu",
    "subfinder",
    "katana",
    "gospider",
    "httpx", # Project discovery httpx
    "gowitness",
    "searchsploit",
]

# Ferramentas opcionais (melhoram cobertura mas não são obrigatórias)
OPTIONAL_TOOLS = [
    "gau",
    "waybackurls",
    "haktrails",
    "masscan",
]

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
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
    print(f"\n{YELLOW}[*] Checking Required System Tools...{RESET}")
    all_ok = True
    for tool in REQUIRED_TOOLS:
        if shutil.which(tool):
            print(f"{GREEN}[OK]{RESET} {tool}")
        else:
            print(f"{RED}[MISSING]{RESET} {tool}")
            if tool in ["naabu", "katana", "subfinder", "gospider"]: 
               print(f"    {YELLOW}-> Required for full crawling/scanning capabilities{RESET}")
            all_ok = False

    print(f"\n{YELLOW}[*] Checking Optional Tools (improve coverage)...{RESET}")
    for tool in OPTIONAL_TOOLS:
        if shutil.which(tool):
            print(f"{GREEN}[OK]{RESET} {tool}")
        else:
            print(f"{CYAN}[OPTIONAL]{RESET} {tool} — not installed (will be skipped)")

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
