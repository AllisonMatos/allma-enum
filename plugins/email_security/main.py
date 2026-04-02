#!/usr/bin/env python3
"""
Email Security (V10.3 Precision) — Verifica configurações anti-spoofing e segurança de entrega.
Inclui SPF, DMARC, DKIM (múltiplos seletores), BIMI, MTA-STS e TLS-RPT.
V10.3: Fix extração de domínio para ccTLDs compostos (.com.br, .co.uk, etc.)
"""
import json
import re
import dns.resolver
import httpx
from pathlib import Path

from core.config import DEFAULT_USER_AGENT, DEFAULT_TIMEOUT
from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error

# V10.3: ccTLDs compostos conhecidos (2-letter + gTLD)
COMPOUND_TLDS = {
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "mil.br",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk",
    "com.au", "net.au", "org.au", "gov.au", "edu.au",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "co.in", "net.in", "org.in", "gov.in", "ac.in",
    "co.za", "org.za", "net.za", "gov.za",
    "com.mx", "net.mx", "org.mx", "gob.mx",
    "com.ar", "net.ar", "org.ar", "gov.ar",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.kr", "or.kr", "go.kr", "ne.kr",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.tw", "net.tw", "org.tw", "gov.tw",
    "com.sg", "net.sg", "org.sg", "gov.sg",
    "co.id", "or.id", "go.id", "web.id",
    "com.my", "net.my", "org.my", "gov.my",
    "co.th", "or.th", "go.th", "in.th",
    "com.ph", "net.ph", "org.ph", "gov.ph",
    "com.vn", "net.vn", "org.vn", "gov.vn",
    "com.tr", "net.tr", "org.tr", "gov.tr",
    "com.pt", "net.pt", "org.pt", "gov.pt",
    "co.il", "org.il", "net.il", "gov.il",
    "com.eg", "net.eg", "org.eg", "gov.eg",
    "co.ke", "or.ke", "go.ke", "ne.ke",
    "ind.br",  # ccTLD especial brasileiro
}


def _extract_root_domain(target: str) -> str:
    """V10.3: Extrai domínio raiz corretamente para ccTLDs compostos."""
    parts = target.lower().strip(".").split(".")
    if len(parts) <= 2:
        return target
    
    # Verificar se os últimos 2 segmentos são um ccTLD composto
    last_two = ".".join(parts[-2:])
    if last_two in COMPOUND_TLDS:
        # ex: "api.example.com.br" -> parts = [api, example, com, br]
        # retornar "example.com.br" (3 últimos)
        if len(parts) >= 3:
            return ".".join(parts[-3:])
        return target
    
    # Padrão: retornar os últimos 2 segmentos
    return ".".join(parts[-2:])


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


def _check_dkim(domain: str) -> dict:
    """V10.2: Verifica DKIM com múltiplos seletores comuns."""
    selectors = ["google", "default", "selector1", "selector2", "k1", "k2", "s1", "s2", "dkim", "mail"]
    found_selectors = []
    
    for selector in selectors:
        records = _query_txt(domain, f"{selector}._domainkey")
        if records:
            for rec in records:
                if "v=DKIM1" in rec or "p=" in rec:
                    found_selectors.append({"selector": selector, "record": rec[:200]})
    
    if found_selectors:
        return {
            "present": True,
            "selectors": found_selectors,
            "risk": "LOW",
            "issue": f"DKIM Detectado ({len(found_selectors)} seletor(es): {', '.join(s['selector'] for s in found_selectors)})"
        }
    return {
        "present": False,
        "selectors": [],
        "risk": "MEDIUM",
        "issue": "DKIM não detectado (nenhum seletor comum encontrado)"
    }


def _check_tls_rpt(domain: str) -> dict:
    """V10.2: Verifica TLS-RPT (SMTP TLS Reporting)."""
    records = _query_txt(domain, "_smtp._tls")
    if records:
        for rec in records:
            if "v=TLSRPTv1" in rec:
                return {"present": True, "record": rec, "risk": "INFO", "issue": f"TLS-RPT Habilitado: {rec[:150]}"}
        return {"present": True, "record": records[0], "risk": "INFO", "issue": "TLS-RPT registro encontrado"}
    return {"present": False, "record": None, "risk": "LOW", "issue": "TLS-RPT ausente (sem relatórios de falha TLS em SMTP)"}


def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟦───────────────────────────────────────────────────────────🟦\n"
        f"   📧 {C.BOLD}{C.CYAN}EMAIL SECURITY (SPF/DMARC/DKIM/BIMI/MTA-STS/TLS-RPT) CHECK (V10.3){C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟦───────────────────────────────────────────────────────────🟦\n"
    )

    outdir = ensure_outdir(target, "email_security")
    
    # V10.3: Usar extração de domínio correta para ccTLD
    domain = _extract_root_domain(target)

    info(f"   🔍 Analisando segurança de email para: {C.YELLOW}{domain}{C.END}")

    txt_records = _query_txt(domain)
    spf = _analyze_spf(txt_records)
    dmarc = _analyze_dmarc(_query_txt(domain, "_dmarc"))
    dkim = _check_dkim(domain)
    bimi = _check_bimi(domain)
    mta_sts = _check_mta_sts(domain)
    tls_rpt = _check_tls_rpt(domain)

    # Exibir no console
    for res in [spf, dmarc, dkim, bimi, mta_sts, tls_rpt]:
        color = C.RED if res["risk"] in ("CRITICAL", "HIGH") else C.YELLOW if res["risk"] == "MEDIUM" else C.GREEN
        info(f"      {color}[{res['risk']}]{C.END} {res['issue']}")

    results = {
        "domain": domain,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "bimi": bimi,
        "mta_sts": mta_sts,
        "tls_rpt": tls_rpt,
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
