
import sys
import shutil
import importlib

# Define required python packages
REQUIRED_PYTHON = [
    "httpx",
    "requests",
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
    "httpx",
    "searchsploit",
    "kr",
    "trufflehog",
    "cloud_enum",
    "interactsh-client",
    "gf",
    "qsreplace",
]

# Ferramentas opcionais (melhoram cobertura mas não são obrigatórias)
OPTIONAL_TOOLS = [
    "crlfuzz",
    "corsy",
    "ssrfmap",
    "gitleaks",
    "git-dumper",
    "dalfox",
    "gau",
    "gauplus",
    "waybackurls",
    "waymore",
    "haktrails",
    "masscan",
    "spiderfoot",
]

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

INSTALL_CMDS = {
    "naabu": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "katana": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "interactsh-client": "go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
    "crlfuzz": "go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest",
    "qsreplace": "go install github.com/tomnomnom/qsreplace@latest",
    "gf": "go install github.com/tomnomnom/gf@latest",
    "gospider": "go install github.com/jaeles-project/gospider@latest",
    "gau": "go install github.com/lc/gau/v2/cmd/gau@latest",
    "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
    "dalfox": "go install github.com/hahwul/dalfox/v2@latest",
    "nmap": "sudo apt install -y nmap",
    "curl": "sudo apt install -y curl",
    "wget": "sudo apt install -y wget",
    "git": "sudo apt install -y git",
    "searchsploit": "sudo apt install -y exploitdb",
    "spiderfoot": "git clone https://github.com/smicallef/spiderfoot.git ~/spiderfoot && sudo apt install -y libxml2-dev libxslt1-dev && pip install --break-system-packages -r ~/spiderfoot/requirements.txt -U cryptography pyOpenSSL",
}

def check_python_modules():
    print(f"\n{YELLOW}[*] Checking Python Dependencies...{RESET}")
    missing = []
    for package in REQUIRED_PYTHON:
        try:
            importlib.import_module(package)
            print(f"{GREEN}[OK]{RESET} {package}")
        except ImportError:
            print(f"{RED}[MISSING]{RESET} {package}")
            missing.append(package)
    return missing

def check_system_tools():
    print(f"\n{YELLOW}[*] Checking Required System Tools...{RESET}")
    missing_req = []
    for tool in REQUIRED_TOOLS:
        if shutil.which(tool):
            print(f"{GREEN}[OK]{RESET} {tool}")
        else:
            print(f"{RED}[MISSING]{RESET} {tool}")
            missing_req.append(tool)

    print(f"\n{YELLOW}[*] Checking Optional Tools...{RESET}")
    missing_opt = []
    for tool in OPTIONAL_TOOLS:
        if shutil.which(tool):
            print(f"{GREEN}[OK]{RESET} {tool}")
        else:
            print(f"{CYAN}[OPTIONAL MISSING]{RESET} {tool}")
            missing_opt.append(tool)

    return missing_req, missing_opt

def main():
    print(f"{YELLOW}=== Enum-Allma Environment Check ==={RESET}")
    
    missing_py = check_python_modules()
    missing_sys, missing_opt = check_system_tools()
    
    print("-" * 40)
    if not missing_py and not missing_sys:
        print(f"{GREEN}✓ All required checks passed! You are ready to run.{RESET}")
    else:
        print(f"{RED}✗ Missing dependencies found.{RESET}\n")
    
    if missing_py:
        print(f"{YELLOW}[!] Run the following command to install Python dependencies:{RESET}")
        print(f"    pip install -r requirements.txt")
        print(f"    (Ou especificamente: pip install {' '.join(missing_py)})\n")
        
    all_missing_tools = missing_sys + missing_opt
    if all_missing_tools:
        print(f"{YELLOW}[!] Comandos recomendados para instalar ferramentas ausentes:{RESET}")
        to_install = []
        for t in all_missing_tools:
            if t in INSTALL_CMDS:
                cmd = INSTALL_CMDS[t]
                print(f"    {GREEN}{t}:{RESET} {cmd}")
                to_install.append(cmd)
            else:
                if t == "cloud_enum":
                    print(f"    {GREEN}{t}:{RESET} git clone https://github.com/initstring/cloud_enum.git ~/cloud_enum")
                elif t == "trufflehog":
                    print(f"    {GREEN}{t}:{RESET} curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin")
                elif t == "kr":
                    print(f"    {GREEN}{t}:{RESET} wget https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_amd64.tar.gz && tar -xvzf kiterunner* && sudo mv kr /usr/local/bin/")
                else:
                    print(f"    {GREEN}{t}:{RESET} Consulte os passos de instalação no repositório oficial.")
        
        # Opcional: auto-install
        if to_install:
            print(f"\n{CYAN}[?] Deseja tentar instalar as ferramentas do GO/APT automaticamente agora? [s/N]{RESET}")
            resp = input().strip().lower()
            if resp == 's':
                import os
                for cmd in to_install:
                    print(f"\n{YELLOW}=> Executando: {cmd}{RESET}")
                    os.system(cmd)
                print(f"\n{GREEN}[+] Instalação finalizada! Execute o check_install.py novamente para confirmar.{RESET}")
                
    if missing_py or missing_sys:
        sys.exit(1)

if __name__ == "__main__":
    main()
