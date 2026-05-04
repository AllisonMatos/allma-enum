import httpx
import socket
import dns.resolver
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from menu import C
from plugins.output import info, warn

def get_asn_for_ip(ip: str) -> str:
    """Resolve IP to ASN via Team Cymru DNS"""
    try:
        octets = ip.split(".")
        if len(octets) != 4:
            return ""
        reversed_ip = ".".join(reversed(octets))
        origin_query = f"{reversed_ip}.origin.asn.cymru.com"
        answers = dns.resolver.resolve(origin_query, "TXT")
        for rdata in answers:
            txt = str(rdata).strip('"')
            parts = [p.strip() for p in txt.split("|")]
            if len(parts) >= 3:
                return f"AS{parts[0]}"
    except Exception:
        pass
    return ""

def reverse_asn(asn: str, target_name: str) -> set:
    """Fetch domains hosted on the ASN via HackerTarget API"""
    domains = set()
    try:
        url = f"https://api.hackertarget.com/asndns/?q={asn}"
        with httpx.Client(timeout=30, verify=False) as client:
            resp = client.get(url)
            if resp.status_code == 200 and "API count exceeded" not in resp.text:
                for line in resp.text.splitlines():
                    if "," in line:
                        domain = line.split(",")[0].strip().lower()
                        # Filter to only domains that contain the target name to avoid massive noise
                        if target_name in domain:
                            domains.add(domain)
    except Exception as e:
        warn(f"   Reverse ASN: error — {e}")
    return domains

def reverse_whois_crtsh(target_name: str) -> set:
    """Fetch domains registered under the same organization via crt.sh"""
    domains = set()
    try:
        # Search by Organization Name
        url = f"https://crt.sh/?O={target_name}&output=json"
        with httpx.Client(timeout=45, verify=False) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name.startswith("*."):
                            name = name[2:]
                        if name and target_name in name:
                            domains.add(name)
    except Exception as e:
        warn(f"   Reverse WHOIS (crt.sh): error — {e}")
    return domains

def discover_horizontal(target: str, outdir: Path) -> set:
    """
    Executa enumeração horizontal (Reverse ASN e Reverse WHOIS)
    para encontrar domínios raiz relacionados à marca.
    """
    info(
        f"\n🟩──────────────────────────────────────────────────────────🟩\n"
        f"   🏢 {C.BOLD}{C.CYAN}HORIZONTAL DISCOVERY (ASN & WHOIS){C.END}\n"
        f"   🎯 Alvo Base: {C.GREEN}{target}{C.END}\n"
        f"🟩──────────────────────────────────────────────────────────🟩\n"
    )

    horizontal_domains = set()
    target_name = target.split('.')[0] if '.' in target else target

    # 1. Obter ASN via IP do alvo principal
    asn = ""
    try:
        ip = socket.gethostbyname(target)
        asn = get_asn_for_ip(ip)
        if asn:
            info(f"   📍 IP Principal: {ip} | ASN: {asn}")
    except Exception:
        warn(f"   ⚠️ Não foi possível resolver IP/ASN para {target}")

    # 2. Executar Reverse ASN e Reverse WHOIS em paralelo
    info(f"   🔍 Buscando domínios relacionados à marca '{target_name}'...")
    
    with ThreadPoolExecutor(max_workers=2) as executor:
        f_asn = executor.submit(reverse_asn, asn, target_name) if asn else None
        f_whois = executor.submit(reverse_whois_crtsh, target_name)

        if f_asn:
            res_asn = f_asn.result()
            horizontal_domains.update(res_asn)
            info(f"   📡 Reverse ASN ({asn}): {len(res_asn)} domínios encontrados")

        res_whois = f_whois.result()
        horizontal_domains.update(res_whois)
        info(f"   📜 Reverse WHOIS (crt.sh): {len(res_whois)} domínios encontrados")

    if horizontal_domains:
        # Remover o target base se ele já estiver na lista para não duplicar
        horizontal_domains.discard(target)
        
        horiz_file = outdir / "horizontal_domains.txt"
        horiz_file.write_text("\n".join(sorted(horizontal_domains)) + "\n")
        info(f"\n   ✨ {C.GREEN}{len(horizontal_domains)} Domínios Horizontais{C.END} encontrados!")
        info(f"   📂 Salvos em: {horiz_file.name}")
    else:
        info("   🤷 Nenhum domínio horizontal novo encontrado.")

    return horizontal_domains
