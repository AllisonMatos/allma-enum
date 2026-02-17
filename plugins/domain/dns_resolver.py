"""
DNS Resolver + Wildcard Detection + CDN Filtering
Resolve subdomínios para IPs reais, detecta wildcard DNS,
e filtra IPs de CDN conhecidas.
"""
import json
import uuid
import socket
import ipaddress
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..output import info, success, warn, error
from menu import C

# CIDRs conhecidas de CDNs (principais)
CDN_RANGES = [
    # Cloudflare
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    # Akamai (principais)
    "23.32.0.0/11", "23.192.0.0/11", "23.72.0.0/13",
    "104.64.0.0/10",
    # Fastly
    "151.101.0.0/16", "199.232.0.0/16",
    # Amazon CloudFront
    "13.32.0.0/15", "13.35.0.0/16", "13.224.0.0/14",
    "52.84.0.0/15", "54.182.0.0/16", "54.192.0.0/16",
    "54.230.0.0/16", "54.239.128.0/18", "54.239.192.0/19",
    "99.84.0.0/16", "143.204.0.0/16", "205.251.192.0/19",
    # Incapsula / Imperva
    "199.83.128.0/21", "198.143.32.0/19",
    # Sucuri
    "192.124.249.0/24",
]

# Pré-compilar redes CDN
_cdn_networks = None

def _get_cdn_networks():
    global _cdn_networks
    if _cdn_networks is None:
        _cdn_networks = [ipaddress.ip_network(cidr) for cidr in CDN_RANGES]
    return _cdn_networks


def is_cdn_ip(ip_str: str) -> bool:
    """Verifica se um IP pertence a uma CDN conhecida."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for net in _get_cdn_networks():
            if ip in net:
                return True
    except ValueError:
        pass
    return False


def resolve_host(hostname: str) -> list:
    """Resolve um hostname para lista de IPs (A records)."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(hostname, 'A')
        return [str(rdata) for rdata in answers]
    except Exception:
        pass
    
    # Fallback para socket
    try:
        result = socket.getaddrinfo(hostname, None, socket.AF_INET)
        return list({addr[4][0] for addr in result})
    except Exception:
        return []


def detect_wildcard(target: str) -> bool:
    """
    Detecta wildcard DNS testando resolução de subdomínio inexistente.
    Se resolve, o domínio usa wildcard DNS.
    """
    random_sub = f"enum-allma-test-{uuid.uuid4().hex[:12]}.{target}"
    ips = resolve_host(random_sub)
    return len(ips) > 0


def resolve_and_filter(target: str, subs_file: Path, outdir: Path) -> dict:
    """
    Resolve subdomínios para IPs, detecta wildcard, e filtra CDN.

    Generates:
        - dns_resolved.json: {subdomain: [ips]}
        - ips.txt: IPs únicos (sem CDN)
        - cdn_filtered.txt: Subdomínios atrás de CDN (informativo)

    Returns:
        dict com resultados
    """
    info(
        f"\n🟧──────────────────────────────────────────────────────────🟧\n"
        f"   🔍 {C.BOLD}{C.CYAN}DNS RESOLUTION & FILTERING{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟧──────────────────────────────────────────────────────────🟧\n"
    )

    dns_dir = outdir
    dns_resolved_file = dns_dir / "dns_resolved.json"
    ips_file = dns_dir / "ips.txt"
    cdn_file = dns_dir / "cdn_filtered.txt"

    # 1. Wildcard Detection
    info(f"   🎲 Testando wildcard DNS...")
    is_wildcard = detect_wildcard(target)
    if is_wildcard:
        warn(f"   ⚠️  WILDCARD DNS detectado para {target}!")
        warn(f"   ⚠️  Subdomínios podem não ser reais — cuidado com falsos positivos.")
        (dns_dir / "wildcard.txt").write_text(
            f"WILDCARD DNS DETECTED for {target}\n"
            f"Random subdomains resolve to IPs. Results may contain false positives.\n"
        )
    else:
        info(f"   ✔ Sem wildcard DNS detectado.")

    # 2. Carregar subdomínios
    if not subs_file.exists():
        warn("   Arquivo de subdomínios não encontrado.")
        return {}

    subdomains = [l.strip() for l in subs_file.read_text().splitlines() if l.strip()]
    info(f"   📋 Resolvendo {len(subdomains)} subdomínios...")

    # 3. Resolver em paralelo
    resolved = {}
    all_ips = set()
    cdn_subs = []
    real_subs = []

    def resolve_one(sub):
        ips = resolve_host(sub)
        return sub, ips

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(resolve_one, sub): sub for sub in subdomains}
        done = 0
        for future in as_completed(futures):
            try:
                sub, ips = future.result()
                done += 1
                if done % 50 == 0:
                    print(f"   [{done}/{len(subdomains)}] Resolved...", end="\r")

                if ips:
                    resolved[sub] = ips
                    # Verificar CDN
                    is_cdn = all(is_cdn_ip(ip) for ip in ips)
                    if is_cdn:
                        cdn_subs.append(sub)
                    else:
                        real_subs.append(sub)
                        all_ips.update(ip for ip in ips if not is_cdn_ip(ip))
            except Exception:
                pass

    print("")  # Newline

    # 4. Salvar resultados
    # DNS Resolved
    dns_resolved_file.write_text(json.dumps(resolved, indent=2, ensure_ascii=False))

    # IPs únicos (sem CDN)
    sorted_ips = sorted(all_ips, key=lambda x: tuple(int(p) for p in x.split(".")))
    ips_file.write_text("\n".join(sorted_ips) + "\n" if sorted_ips else "")

    # CDN filtered
    if cdn_subs:
        cdn_file.write_text("\n".join(sorted(cdn_subs)) + "\n")

    # Stats
    no_resolve = len(subdomains) - len(resolved)
    info(f"\n   📊 Resultados DNS:")
    info(f"      Total subdomínios: {len(subdomains)}")
    info(f"      Resolvidos: {C.GREEN}{len(resolved)}{C.END}")
    info(f"      Sem resolução: {C.YELLOW}{no_resolve}{C.END}")
    info(f"      Atrás de CDN: {C.YELLOW}{len(cdn_subs)}{C.END}")
    info(f"      IPs reais (sem CDN): {C.GREEN}{len(all_ips)}{C.END}")

    if is_wildcard:
        warn(f"      ⚠️  WILDCARD DNS ativo — considere filtrar resultados")

    success(f"   ✔ DNS resolution concluído. {len(all_ips)} IPs salvos em {ips_file.name}\n")

    return {
        "resolved": resolved,
        "ips": sorted_ips,
        "cdn_subs": cdn_subs,
        "wildcard": is_wildcard
    }
