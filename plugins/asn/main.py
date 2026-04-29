#!/usr/bin/env python3
"""
plugins/asn/main.py — CIDR/ASN Mapping via Team Cymru DNS
Mapeia todos os IPs encontrados para seus ASNs, organizações e blocos CIDR.
"""
import json
import socket
import dns.resolver
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error


def resolve_host_to_ip(host: str) -> str | None:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def query_cymru_asn(ip: str) -> dict | None:
    """Query Team Cymru DNS for ASN info. No rate limit."""
    try:
        # Reverse IP for DNS query
        octets = ip.split(".")
        if len(octets) != 4:
            return None
        reversed_ip = ".".join(reversed(octets))

        # Step 1: Get ASN + CIDR
        origin_query = f"{reversed_ip}.origin.asn.cymru.com"
        answers = dns.resolver.resolve(origin_query, "TXT")
        for rdata in answers:
            txt = str(rdata).strip('"')
            parts = [p.strip() for p in txt.split("|")]
            if len(parts) >= 3:
                asn = parts[0]
                cidr = parts[1]
                country = parts[2] if len(parts) > 2 else ""

                # Step 2: Get ASN name/org
                org_name = ""
                try:
                    asn_query = f"AS{asn}.asn.cymru.com"
                    org_answers = dns.resolver.resolve(asn_query, "TXT")
                    for org_rdata in org_answers:
                        org_txt = str(org_rdata).strip('"')
                        org_parts = [p.strip() for p in org_txt.split("|")]
                        if len(org_parts) >= 5:
                            org_name = org_parts[4]
                except Exception:
                    pass

                return {
                    "ip": ip,
                    "asn": f"AS{asn}",
                    "cidr": cidr,
                    "country": country,
                    "org": org_name,
                }
    except Exception:
        pass
    return None


def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   🌐 {C.BOLD}{C.CYAN}CIDR/ASN MAPPING (Team Cymru DNS){C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    outdir = ensure_outdir(target, "asn")
    base = Path("output") / target

    # Collect all hosts from subdomains
    subs_file = base / "domain" / "subdomains.txt"
    if not subs_file.exists():
        warn("⚠️ Nenhum subdomínio encontrado. Rode o módulo domain primeiro.")
        return []

    hosts = [l.strip() for l in subs_file.read_text(errors="ignore").splitlines() if l.strip()]
    info(f"   📋 Resolvendo {len(hosts)} hosts...")

    # Resolve hosts to IPs in parallel
    ip_to_hosts = defaultdict(list)
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(resolve_host_to_ip, h): h for h in hosts}
        for future in as_completed(futures):
            host = futures[future]
            try:
                ip = future.result()
                if ip:
                    ip_to_hosts[ip].append(host)
            except Exception:
                pass

    unique_ips = list(ip_to_hosts.keys())
    info(f"   🔢 {len(unique_ips)} IPs únicos resolvidos")

    if not unique_ips:
        warn("⚠️ Nenhum IP resolvido.")
        return []

    # Query ASN for each IP
    info(f"   🌐 Consultando Team Cymru para {len(unique_ips)} IPs...")
    asn_results = []
    cidr_groups = defaultdict(lambda: {"asn": "", "org": "", "country": "", "hosts": [], "ips": []})

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(query_cymru_asn, ip): ip for ip in unique_ips}
        done = 0
        for future in as_completed(futures):
            done += 1
            if done % 10 == 0:
                print(f"   [{done}/{len(unique_ips)}] Queried...", end="\r")
            try:
                result = future.result()
                if result:
                    ip = result["ip"]
                    result["hosts"] = ip_to_hosts.get(ip, [])
                    asn_results.append(result)

                    # Group by CIDR
                    cidr = result["cidr"]
                    cidr_groups[cidr]["asn"] = result["asn"]
                    cidr_groups[cidr]["org"] = result["org"]
                    cidr_groups[cidr]["country"] = result["country"]
                    cidr_groups[cidr]["ips"].append(ip)
                    cidr_groups[cidr]["hosts"].extend(result["hosts"])
            except Exception:
                pass

    print("")  # Newline

    # Sort by number of hosts per CIDR
    cidr_summary = []
    for cidr, data in sorted(cidr_groups.items(), key=lambda x: len(x[1]["ips"]), reverse=True):
        cidr_summary.append({
            "cidr": cidr,
            "asn": data["asn"],
            "org": data["org"],
            "country": data["country"],
            "ip_count": len(set(data["ips"])),
            "host_count": len(set(data["hosts"])),
            "ips": sorted(set(data["ips"])),
            "hosts": sorted(set(data["hosts"])),
        })

    # Save
    output = {
        "target": target,
        "total_ips": len(unique_ips),
        "total_asns": len(set(r["asn"] for r in asn_results)),
        "total_cidrs": len(cidr_summary),
        "cidr_blocks": cidr_summary,
        "ip_details": asn_results,
    }

    results_file = outdir / "asn_mapping.json"
    results_file.write_text(json.dumps(output, indent=2, ensure_ascii=False))

    # Print summary
    success(f"\n   🌐 {C.BOLD}ASN MAPPING COMPLETO{C.END}")
    info(f"   📊 IPs únicos: {len(unique_ips)}")
    info(f"   🏢 ASNs: {output['total_asns']}")
    info(f"   📦 Blocos CIDR: {len(cidr_summary)}")

    for block in cidr_summary[:10]:
        info(f"      {block['cidr']} → {block['asn']} {block['org'][:40]} ({block['ip_count']} IPs, {block['host_count']} hosts)")

    success(f"   📂 Resultados: {results_file}")
    return [str(results_file)]
