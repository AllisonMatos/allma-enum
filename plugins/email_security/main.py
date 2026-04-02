#!/usr/bin/env python3
"""
Email Security (SPF/DMARC/DKIM) — Verifica configurações anti-spoofing via DNS.
"""
import json
import dns.resolver
from pathlib import Path

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
    """Analisa registros SPF."""
    spf_records = [r for r in records if r.startswith("v=spf1")]
    if not spf_records:
        return {"present": False, "record": None, "risk": "HIGH", "issue": "SPF ausente — domínio pode ser spoofed livremente"}

    spf = spf_records[0]
    risk = "LOW"
    issue = "SPF configurado corretamente"

    if "+all" in spf:
        risk = "CRITICAL"
        issue = "SPF com '+all' — qualquer servidor pode enviar emails como este domínio"
    elif "~all" in spf:
        risk = "MEDIUM"
        issue = "SPF com '~all' (softfail) — emails spoofed passam em muitos servidores"
    elif "?all" in spf:
        risk = "MEDIUM"
        issue = "SPF com '?all' (neutral) — não bloqueia spoofing"
    elif "-all" not in spf:
        risk = "MEDIUM"
        issue = "SPF sem mecanismo '-all' — proteção incompleta"

    return {"present": True, "record": spf, "risk": risk, "issue": issue}


def _analyze_dmarc(records: list) -> dict:
    """Analisa registros DMARC."""
    dmarc_records = [r for r in records if r.startswith("v=DMARC1")]
    if not dmarc_records:
        return {"present": False, "record": None, "risk": "HIGH", "issue": "DMARC ausente — sem politica de rejeição de spoofing"}

    dmarc = dmarc_records[0]
    risk = "LOW"
    issue = "DMARC configurado"

    if "p=none" in dmarc:
        risk = "MEDIUM"
        issue = "DMARC com 'p=none' — apenas monitora, não bloqueia spoofing"
    elif "p=quarantine" in dmarc:
        risk = "LOW"
        issue = "DMARC com 'p=quarantine' — emails spoofed vão para spam"
    elif "p=reject" in dmarc:
        risk = "INFO"
        issue = "DMARC com 'p=reject' — configuração ideal"

    return {"present": True, "record": dmarc, "risk": risk, "issue": issue}


def _analyze_dkim(records: list) -> dict:
    """Analisa registros DKIM."""
    if not records:
        return {"present": False, "record": None, "risk": "MEDIUM", "issue": "DKIM não detectado (selector 'default' testado)"}

    dkim = records[0]
    return {"present": True, "record": dkim[:200], "risk": "INFO", "issue": "DKIM configurado"}


def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟦───────────────────────────────────────────────────────────🟦\n"
        f"   📧 {C.BOLD}{C.CYAN}EMAIL SECURITY (SPF/DMARC/DKIM) CHECK{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟦───────────────────────────────────────────────────────────🟦\n"
    )

    outdir = ensure_outdir(target, "email_security")

    # Extrair domínio raiz (sem subdomínios)
    parts = target.split(".")
    if len(parts) > 2:
        domain = ".".join(parts[-2:])
    else:
        domain = target

    info(f"   🔍 Consultando registros DNS para: {C.YELLOW}{domain}{C.END}")

    # SPF
    info(f"   📋 Verificando SPF...")
    txt_records = _query_txt(domain)
    spf_result = _analyze_spf(txt_records)
    spf_color = C.RED if spf_result["risk"] in ("HIGH", "CRITICAL") else C.YELLOW if spf_result["risk"] == "MEDIUM" else C.GREEN
    info(f"      {spf_color}[{spf_result['risk']}]{C.END} {spf_result['issue']}")

    # DMARC
    info(f"   📋 Verificando DMARC...")
    dmarc_records = _query_txt(domain, "_dmarc")
    dmarc_result = _analyze_dmarc(dmarc_records)
    dmarc_color = C.RED if dmarc_result["risk"] in ("HIGH", "CRITICAL") else C.YELLOW if dmarc_result["risk"] == "MEDIUM" else C.GREEN
    info(f"      {dmarc_color}[{dmarc_result['risk']}]{C.END} {dmarc_result['issue']}")

    # DKIM (testar selectors comuns)
    info(f"   📋 Verificando DKIM...")
    dkim_result = {"present": False, "record": None, "risk": "MEDIUM", "issue": "DKIM não detectado"}
    selectors = ["default", "google", "selector1", "selector2", "k1", "dkim", "mail"]
    for selector in selectors:
        dkim_records = _query_txt(domain, f"{selector}._domainkey")
        if dkim_records:
            dkim_result = _analyze_dkim(dkim_records)
            dkim_result["selector"] = selector
            info(f"      {C.GREEN}[OK]{C.END} DKIM encontrado (selector: {selector})")
            break

    if not dkim_result["present"]:
        info(f"      {C.YELLOW}[MEDIUM]{C.END} {dkim_result['issue']}")

    # Resultado consolidado
    results = {
        "domain": domain,
        "spf": spf_result,
        "dmarc": dmarc_result,
        "dkim": dkim_result,
        "overall_risk": max(
            [spf_result["risk"], dmarc_result["risk"], dkim_result["risk"]],
            key=lambda r: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(r, 0)
        ),
        "spoofable": spf_result["risk"] in ("HIGH", "CRITICAL") and dmarc_result["risk"] in ("HIGH", "CRITICAL"),
    }

    output_file = outdir / "email_security_results.json"
    output_file.write_text(json.dumps(results, indent=2, ensure_ascii=False))

    summary = {"tests_run": 3, "findings": sum(1 for r in [spf_result, dmarc_result, dkim_result] if r["risk"] in ("HIGH", "CRITICAL", "MEDIUM")), "status": "COMPLETED"}
    (outdir / "scan_summary.json").write_text(json.dumps(summary, indent=2))

    if results["spoofable"]:
        success(f"\n   📧 🔴 {C.RED}DOMÍNIO SPOOFÁVEL!{C.END} SPF e DMARC ausentes/fracos — phishing possível.")
    else:
        info(f"   ✅ Análise completa. Risco geral: {results['overall_risk']}")

    success(f"   📂 Salvos em {output_file}")
    return [results]
