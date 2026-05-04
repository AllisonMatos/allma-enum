import shutil
from pathlib import Path
import subprocess
from menu import C
from plugins.output import info, warn

# Top-tier permutation words for bug bounty (Expanded with horizontal focus)
PERMUTATION_WORDS = [
    "api", "dev", "test", "staging", "stg", "prod", "uat", "qa", 
    "internal", "admin", "secure", "sso", "auth", "vpn", "corp",
    "portal", "beta", "demo", "sandbox", "v1", "v2", "v3",
    "grafana", "kibana", "jira", "jenkins", "gitlab", "wiki",
    "mail", "webmail", "exchange", "gw", "gateway",
    "student", "education", "shop", "store", "blog", "help",
    "support", "cloud", "app", "my", "cdn", "pay"
]

def run_permutations(target: str, subs_file: Path, outdir: Path):
    """
    Gera permutações de subdomínios (estilo gotator/altdns) e domínios raiz horizontais.
    Resolve-os ativamente via dnsx.
    Adiciona os resultados válidos de volta ao subs_file.
    """
    if not subs_file.exists():
        return
        
    dnsx = shutil.which("dnsx")
    if not dnsx:
        warn("   ⚠️ 'dnsx' não encontrado. Pulando permutações ativas.")
        return
        
    info(f"{C.BOLD}{C.BLUE}[2.5/8] Gerando permutações e resolvendo (Active Alterations & Horizontal)...{C.END}")
    
    current_subs = set(l.strip() for l in subs_file.read_text().splitlines() if l.strip())
    mutations = set()
    
    # 1. Horizontal Root Domain Permutations
    target_name = target.split('.')[0] if '.' in target else target
    tld = ".".join(target.split('.')[1:]) if '.' in target else ""
    
    if target_name and tld:
        for word in PERMUTATION_WORDS:
            mutations.add(f"{word}-{target}")            # student-sky.de
            mutations.add(f"{target_name}-{word}.{tld}") # sky-student.de
            mutations.add(f"{word}{target}")             # studentsky.de
            mutations.add(f"{target_name}{word}.{tld}")  # skystudent.de

    # 2. Vertical Subdomain Permutations
    for sub in current_subs:
        parts = sub.split('.')
        if len(parts) >= 2:
            # ex: api.target.com -> prefix=api, rest=target.com
            prefix = parts[0]
            rest = ".".join(parts[1:])
            if rest == target or rest.endswith("." + target):
                for word in PERMUTATION_WORDS:
                    mutations.add(f"{word}-{prefix}.{rest}")
                    mutations.add(f"{prefix}-{word}.{rest}")
                    mutations.add(f"{word}.{rest}")
        # Always add standard prefixes to the full subdomain
        for word in PERMUTATION_WORDS:
            mutations.add(f"{word}.{sub}")
            
    # Filter out ones we already know
    mutations = mutations - current_subs
    if not mutations:
        return
        
    mutations_file = outdir / "mutations_raw.txt"
    mutations_file.write_text("\n".join(mutations))
    
    info(f"   🌀 Geradas {len(mutations)} permutações. Resolvendo via dnsx...")
    
    resolved_file = outdir / "mutations_resolved.txt"
    
    cmd = [
        dnsx,
        "-l", str(mutations_file),
        "-silent",
        "-stats",
        "-t", "50",          # Limita threads para não sobrecarregar
        "-rl", "100",        # Rate-limit (100 req/s) para evitar block do provedor
        "-timeout", "1",     # Fail-fast timeout de 1s
        "-o", str(resolved_file)
    ]
    
    # Remove stderr=DEVNULL to allow dnsx progress stats to show on screen
    subprocess.run(cmd, stdout=subprocess.DEVNULL)
    
    if resolved_file.exists():
        valid_mutations = set()
        for line in resolved_file.read_text().splitlines():
            domain = line.split()[0].strip()
            if domain.endswith(target):
                valid_mutations.add(domain)
                
        new_valid = valid_mutations - current_subs
        if new_valid:
            info(f"   🎯 {C.GREEN}{len(new_valid)}{C.END} novos subdomínios ocultos encontrados via permutações!")
            with open(subs_file, "a") as f:
                f.write("\n" + "\n".join(new_valid) + "\n")
        else:
            info("   🤷 Nenhuma permutação nova retornou IPs vivos.")
