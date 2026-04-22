#!/usr/bin/env python3
"""
Insecure Deserialization Scanner — Detecta objetos serializados em cookies/headers
Identifica Java, PHP, Python pickle, .NET serialization
Captura raw request/response para Burp modal
"""
import json
import re
import base64
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from ..http_utils import format_raw_request, format_raw_response

try:
    import httpx
except ImportError:
    httpx = None


# Padrões de objetos serializados
SERIALIZATION_PATTERNS = {
    "Java ObjectStream": {
        "regex": re.compile(r'rO0AB[A-Za-z0-9+/=]', re.I),
        "b64_prefix": "rO0AB",
        "hex_prefix": "aced0005",
        "risk": "HIGH",
        "desc": "Java ObjectInputStream — vulnerável a RCE via gadget chains",
    },
    "PHP Serialized": {
        # V11: Regex mais precisa — requer marcador + conteúdo substancial + terminador
        # Evita FPs de strings curtas como 'a:0:' que aparecem em cookies/HTML
        "regex": re.compile(r'(?:[OaCsi]:\d+:(?:"[^"]{2,}"|{[^}]+}|\d+;)){2,}', re.I),
        "risk": "HIGH",
        "desc": "PHP serialize() — vulnerável a property injection e RCE",
    },
    "Python Pickle": {
        "regex": re.compile(r'gASV[A-Za-z0-9+/=]', re.I),
        "b64_prefix": "gASV",
        "hex_prefix": "80049",
        "risk": "HIGH",
        "desc": "Python pickle — vulnerável a RCE via __reduce__",
    },
    ".NET ViewState": {
        "regex": re.compile(r'__VIEWSTATE', re.I),
        "risk": "MEDIUM",
        "desc": ".NET ViewState — pode ser vulnerável se MAC validation desabilitada",
    },
    ".NET BinaryFormatter": {
        "regex": re.compile(r'AAEAAAD[A-Za-z0-9+/=]', re.I),
        "b64_prefix": "AAEAAAD",
        "risk": "HIGH",
        "desc": ".NET BinaryFormatter — vulnerável a RCE",
    },
    "Java Base64 Serialized": {
        "regex": re.compile(r'[A-Za-z0-9+/]{50,}={0,2}', re.I),
        "b64_check": True,
        "risk": "MEDIUM",
        "desc": "Possível objeto Java serializado em base64",
    },
}


def check_value_for_serialization(value, source_type, source_name):
    """Verifica se um valor contém objeto serializado"""
    findings = []
    
    if not value or len(value) < 10:
        return []
    
    for pattern_name, pattern_info in SERIALIZATION_PATTERNS.items():
        if pattern_name == "Java Base64 Serialized":
            continue  # Muito genérico, tratar separadamente
        
        if pattern_info["regex"].search(value):
            findings.append({
                "pattern": pattern_name,
                "risk": pattern_info["risk"],
                "source_type": source_type,
                "source_name": source_name,
                "value_preview": value[:100],
                "description": pattern_info["desc"],
            })
    
    # Tentar decodificar base64 para buscar magic bytes
    if len(value) > 20:
        try:
            # V11: Calcular padding base64 correto em vez de adicionar '==' cegamente
            padded = value + '=' * (-len(value) % 4)
            decoded = base64.b64decode(padded)
            hex_str = decoded[:5].hex()
            
            # Java
            if hex_str.startswith("aced0005"):
                findings.append({
                    "pattern": "Java ObjectStream (decoded)",
                    "risk": "HIGH",
                    "source_type": source_type,
                    "source_name": source_name,
                    "value_preview": value[:100],
                    "description": "Java serialized object detectado após decodificação base64",
                })
            
            # Python pickle
            if hex_str.startswith("80049") or hex_str.startswith("80039"):
                findings.append({
                    "pattern": "Python Pickle (decoded)",
                    "risk": "HIGH",
                    "source_type": source_type,
                    "source_name": source_name,
                    "value_preview": value[:100],
                    "description": "Python pickle object detectado após decodificação base64",
                })
        except Exception:
            pass
    
    return findings


def scan_url(client, url):
    """Escaneia uma URL para objetos serializados em cookies, headers e body"""
    all_findings = []
    
    try:
        resp = client.get(url, timeout=10, follow_redirects=True)
        
        # 1) Verificar cookies
        for name, value in resp.cookies.items():
            findings = check_value_for_serialization(value, "cookie", name)
            for f in findings:
                f["url"] = url
                raw_req = format_raw_request("GET", url, dict(resp.request.headers))
                raw_res = format_raw_response(resp.status_code, dict(resp.headers), resp.text[:2000])
                f["request_raw"] = raw_req
                f["response_raw"] = raw_res
                f["type"] = f"DESER_{f['pattern'].replace(' ', '_').upper()}"
                f["details"] = f"{f['description']} (em cookie '{name}')"
                all_findings.append(f)
        
        # 2) Verificar Set-Cookie headers
        set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [resp.headers.get("set-cookie", "")]
        for sc in set_cookies:
            if sc:
                findings = check_value_for_serialization(sc, "set-cookie", "Set-Cookie")
                for f in findings:
                    f["url"] = url
                    raw_req = format_raw_request("GET", url, dict(resp.request.headers))
                    raw_res = format_raw_response(resp.status_code, dict(resp.headers), resp.text[:2000])
                    f["request_raw"] = raw_req
                    f["response_raw"] = raw_res
                    f["type"] = f"DESER_{f['pattern'].replace(' ', '_').upper()}"
                    f["details"] = f"{f['description']} (em Set-Cookie header)"
                    all_findings.append(f)
        
        # 3) Verificar custom headers suspeitos
        suspicious_headers = ["x-token", "x-session", "x-auth", "x-data", "x-state"]
        for h_name in suspicious_headers:
            h_value = resp.headers.get(h_name, "")
            if h_value:
                findings = check_value_for_serialization(h_value, "header", h_name)
                for f in findings:
                    f["url"] = url
                    raw_req = format_raw_request("GET", url, dict(resp.request.headers))
                    raw_res = format_raw_response(resp.status_code, dict(resp.headers), resp.text[:2000])
                    f["request_raw"] = raw_req
                    f["response_raw"] = raw_res
                    f["type"] = f"DESER_{f['pattern'].replace(' ', '_').upper()}"
                    f["details"] = f"{f['description']} (em header '{h_name}')"
                    all_findings.append(f)
        
        # 4) Verificar body para ViewState
        body = resp.text[:10000]
        viewstate_match = re.search(r'name="__VIEWSTATE"[^>]*value="([^"]+)"', body, re.I)
        if viewstate_match:
            vs_value = viewstate_match.group(1)
            raw_req = format_raw_request("GET", url, dict(resp.request.headers))
            raw_res = format_raw_response(resp.status_code, dict(resp.headers), body[:2000])
            
            # Verificar se MAC está presente
            mac_match = re.search(r'name="__VIEWSTATEGENERATOR"[^>]*value="([^"]+)"', body, re.I)
            
            # V11: Verificar __EVENTVALIDATION (complemento do ViewState)
            event_validation = re.search(r'name="__EVENTVALIDATION"[^>]*value="([^"]+)"', body, re.I)

            all_findings.append({
                "url": url,
                "pattern": ".NET ViewState",
                "type": "DESER_VIEWSTATE",
                "risk": "MEDIUM" if mac_match else "HIGH",
                "source_type": "form_field",
                "source_name": "__VIEWSTATE",
                "value_preview": vs_value[:100],
                "has_mac": bool(mac_match),
                "has_event_validation": bool(event_validation),
                "details": f".NET ViewState encontrado — {'MAC present (verificar se pode ser bypassed)' if mac_match else 'Sem MAC validation — possível RCE'}{' | EventValidation: presente' if event_validation else ''}",
                "request_raw": raw_req,
                "response_raw": raw_res,
            })
    
    except Exception:
        pass
    
    return all_findings


def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")
    
    if not httpx:
        error("httpx não instalado")
        return []

    info(
        f"\n🟧───────────────────────────────────────────────────────────🟧\n"
        f"   🧬  {C.BOLD}{C.CYAN}INSECURE DESERIALIZATION SCANNER{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟧───────────────────────────────────────────────────────────🟧\n"
    )

    outdir = ensure_outdir(target, "insecure_deserialization")
    results_file = outdir / "deser_results.json"
    
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    if not urls_file.exists():
        urls_file = Path("output") / target / "domain" / "urls_valid.txt"
    
    if not urls_file.exists():
        warn("Nenhum arquivo de URLs encontrado")
        return []
    
    all_urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()][:150]
    
    if not all_urls:
        info("Nenhuma URL encontrada")
        results_file.write_text("[]")
        return [str(results_file)]
    
    info(f"   📊 Verificando {len(all_urls)} URLs para objetos serializados")
    
    all_findings = []
    
    # V11: Thread-safe — scan_url cria seu próprio client internamente
    def scan_url_safe(url):
        with httpx.Client(verify=False, follow_redirects=True, timeout=15) as client:
            return scan_url(client, url)
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(scan_url_safe, url): url for url in all_urls}
        
        for future in as_completed(futures):
            try:
                results = future.result()
                if results:
                    all_findings.extend(results)
                    url = futures[future]
                    for r in results:
                        info(f"   🚨 {C.RED}{r.get('pattern', 'DESER')}: {url}{C.END}")
            except Exception:
                pass
    
    results_file.write_text(json.dumps(all_findings, indent=2, ensure_ascii=False))
    
    if all_findings:
        success(f"🧬 {len(all_findings)} objetos serializados encontrados!")
    else:
        success("✅ Nenhum objeto serializado detectado")
    
    return [str(results_file)]
