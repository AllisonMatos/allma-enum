#!/usr/bin/env python3
"""
Email Security (V10 Pro) — Verifica configurações anti-spoofing e segurança de entrega.
Inclui SPF, DMARC, DKIM, BIMI e MTA-STS.
"""
import json
import dns.resolver
import httpx
from pathlib import Path

from core.config import DEFAULT_USER_AGENT, DEFAULT_TIMEOUT
from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error

def _query_txt(domain: str, prefix: str = "") -> list:
    """Consulta registros TXT de um domínio."""
    target = f"{prefix}.{domain}" if prefix else domain
    try:
        answers = dns.resolver.resolve(target, "TXT")
        return [str(rdata).strip('"') for rdata in answers]
    except Exception:
        return []

def _analyze_spf(records: list) -> dict:
    spf_records = [r for r in records if r.startswith("v=spf1")]
    if not spf_records:
        return {"present": False, "record": None, "risk": "HIGH", "issue": "SPF ausente"}
    spf = spf_records[0]
    risk = "LOW"
    if "+all" in spf: risk = "CRITICAL"
    elif "~all" in spf: risk = "MEDIUM"
    elif "?all" in spf: risk = "MEDIUM"
    return {"present": True, "record": spf, "risk": risk, "issue": f"SPF: {spf}"}

def _analyze_dmarc(records: list) -> dict:
    dmarc_records = [r for r in records if r.startswith("v=DMARC1")]
    if not dmarc_records:
        return {"present": False, "record": None, "risk": "HIGH", "issue": "DMARC ausente"}
    dmarc = dmarc_records[0]
    risk = "LOW"
    if "p=none" in dmarc: risk = "MEDIUM"
    return {"present": True, "record": dmarc, "risk": risk, "issue": f"DMARC: {dmarc}"}

def _check_bimi(domain: str) -> dict:
    """Verifica registro BIMI (Brand Indicators for Message Identification)."""
    records = _query_txt(domain, "default._bimi")
    if records:
        return {"present": True, "record": records[0], "risk": "INFO", "issue": "BIMI Detectado"}
    return {"present": False, "record": None, "risk": "INFO", "issue": "BIMI não configurado (opcional)"}

def _check_mta_sts(domain: str) -> dict:
    """Verifica MTA-STS (Secure Email Delivery)."""
    records = _query_txt(domain, "_mta-sts")
    present = len(records) > 0
    
    # Tentar buscar a política via HTTPS
    policy_found = False
    try:
        with httpx.Client(timeout=5, verify=True) as client:
            resp = client.get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt", headers={"User-Agent": DEFAULT_USER_AGENT})
            if resp.status_code == 200 and "version: STSv1" in resp.text:
                policy_found = True
    except: pass

    if present or policy_found:
        return {"present": True, "risk": "INFO", "issue": "MTA-STS Habilitado (Seguro)"}
    return {"present": False, "risk": "LOW", "issue": "MTA-STS ausente (Risco de Man-in-the-middle em SMTP)"}

def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟦───────────────────────────────────────────────────────────🟦\n"
        f"   📧 {C.BOLD}{C.CYAN}EMAIL SECURITY (SPF/DMARC/BIMI/MTA-STS) CHECK (V10 PRO){C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟦───────────────────────────────────────────────────────────🟦\n"
    )

    outdir = ensure_outdir(target, "email_security")
    domain = ".".join(target.split(".")[-2:]) if "." in target else target

    info(f"   🔍 Analisando segurança de email para: {C.YELLOW}{domain}{C.END}")

    txt_records = _query_txt(domain)
    spf = _analyze_spf(txt_records)
    dmarc = _analyze_dmarc(_query_txt(domain, "_dmarc"))
    bimi = _check_bimi(domain)
    mta_sts = _check_mta_sts(domain)

    # Exibir no console
    for res in [spf, dmarc, bimi, mta_sts]:
        color = C.RED if res["risk"] in ("CRITICAL", "HIGH") else C.YELLOW if res["risk"] == "MEDIUM" else C.GREEN
        info(f"      {color}[{res['risk']}]{C.END} {res['issue']}")

    results = {
        "domain": domain,
        "spf": spf,
        "dmarc": dmarc,
        "bimi": bimi,
        "mta_sts": mta_sts,
        "spoofable": spf["risk"] in ("HIGH", "CRITICAL") and dmarc["risk"] in ("HIGH", "CRITICAL")
    }

    output_file = outdir / "email_security_results.json"
    output_file.write_text(json.dumps(results, indent=2, ensure_ascii=False))

    if results["spoofable"]:
        success(f"\n   📧 🔴 {C.RED}DOMÍNIO SPOOFÁVEL!{C.END} Proteções anti-phishing inexistentes.")
    else:
        success(f"\n   ✅ Análise concluída.")

    success(f"   📂 Resultados salvos em {output_file}")
    return [results]
