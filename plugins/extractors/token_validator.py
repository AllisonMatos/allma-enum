"""
Token Validator — Valida tokens/secrets encontrados contra APIs reais.
Determina se um secret é ATIVO, INVÁLIDO, ou NÃO TESTADO.
Enhanced: Suporte a Vercel, Discord, Telegram, NPM, Supabase, além dos originais.
"""
import json
import base64
import re
from datetime import datetime

from ..output import info, warn

# Timeout curto para validações (não queremos bloquear)
VALIDATION_TIMEOUT = 8


def validate_token(key_type: str, token_value: str) -> dict:
    """
    Valida um token contra a API correspondente.

    Returns:
        {
            "validated": True/False/None,
            "validation_info": "Descrição do resultado",
            "validation_type": "api_check" / "format_check" / "not_supported"
        }
    """
    validators = {
        # API validation (real HTTP requests)
        "GitHub PAT (Classic)": _validate_github,
        "GitHub PAT (Fine-grained)": _validate_github,
        "GitHub OAuth Token": _validate_github,
        "GitHub App Token": _validate_github,
        "GitHub Token (Legacy)": _validate_github,
        "Google API Key": _validate_google,
        "Slack Token": _validate_slack,
        "Slack Webhook": _validate_slack_webhook,
        "Stripe Secret Key": _validate_stripe,
        "Stripe Restricted Key": _validate_stripe,
        "SendGrid API Key": _validate_sendgrid,
        "Vercel Token": _validate_vercel,
        "Telegram Bot Token": _validate_telegram,

        # Format validation (no HTTP)
        "AWS Access Key": _validate_aws,
        "Twilio API Key": _validate_twilio,
        "Twilio Account SID": _validate_twilio_sid,
        "Twitter Bearer Token": _validate_twitter_bearer,
        "Discord Token": _validate_discord_format,
        "NPM Token": _validate_npm_format,
        "PyPI Token": _validate_pypi_format,
        "Supabase Anon Key": _validate_supabase_format,
        "New Relic Key": _validate_newrelic_format,
        "Sentry Auth Token": _validate_sentry_format,
    }

    validator = validators.get(key_type)
    if validator:
        try:
            return validator(token_value)
        except Exception as e:
            return {
                "validated": None,
                "validation_info": f"Erro na validação: {str(e)[:100]}",
                "validation_type": "error",
            }

    # JWT decode
    if key_type == "JWT Token":
        return _validate_jwt(token_value)

    # Tipo não suportado para validação
    return {
        "validated": None,
        "validation_info": "Tipo de token sem validação automática",
        "validation_type": "not_supported",
    }


def _get_httpx_client():
    import httpx
    return httpx.Client(timeout=VALIDATION_TIMEOUT, verify=True, follow_redirects=True)


# ═══════════════════════════════════════════════════════════════
# API VALIDATORS (fazem requests HTTP reais)
# ═══════════════════════════════════════════════════════════════

def _validate_github(token: str) -> dict:
    """Valida GitHub token via /user endpoint."""
    clean = re.search(r'(gh[pours]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,})', token)
    if clean:
        token = clean.group(1)

    try:
        with _get_httpx_client() as client:
            resp = client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"token {token}", "User-Agent": "EnumAllma"},
            )
            if resp.status_code == 200:
                data = resp.json()
                username = data.get("login", "unknown")
                scopes = resp.headers.get("x-oauth-scopes", "")
                scope_info = f" | Scopes: {scopes}" if scopes else ""
                return {
                    "validated": True,
                    "validation_info": f"TOKEN ATIVO — Usuário: {username}{scope_info}",
                    "validation_type": "api_check",
                }
            elif resp.status_code == 401:
                return {
                    "validated": False,
                    "validation_info": "Token inválido ou expirado",
                    "validation_type": "api_check",
                }
            else:
                return {
                    "validated": None,
                    "validation_info": f"Resposta inesperada: HTTP {resp.status_code}",
                    "validation_type": "api_check",
                }
    except Exception as e:
        return {"validated": None, "validation_info": f"Erro de conexão: {e}", "validation_type": "error"}


def _validate_aws(token: str) -> dict:
    """Valida AWS Access Key pelo formato."""
    clean = re.search(r'((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})', token)
    if clean:
        return {
            "validated": None,
            "validation_info": "Formato válido de AWS Access Key (precisa da Secret Key para validar completamente)",
            "validation_type": "format_check",
        }
    return {
        "validated": False,
        "validation_info": "Formato inválido de AWS Access Key",
        "validation_type": "format_check",
    }


def _validate_google(token: str) -> dict:
    """Valida Google API Key via tokeninfo e Maps API."""
    clean = re.search(r'(AIza[0-9A-Za-z\-_]{35})', token)
    if not clean:
        return {"validated": False, "validation_info": "Formato inválido", "validation_type": "format_check"}

    key = clean.group(1)
    try:
        with _get_httpx_client() as client:
            # Google API Keys não são validadas em /tokeninfo (que é para OAuth)
            # Testamos em serviços comuns que costumam estar habilitados
            
            # 1. Maps Geocode API
            resp = client.get(f"https://maps.googleapis.com/maps/api/geocode/json?address=1600+Amphitheatre+Parkway,+Mountain+View,+CA&key={key}")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") in ["OK", "ZERO_RESULTS"]:
                    return {
                        "validated": True,
                        "validation_info": "Google API Key ATIVA (Maps API)",
                        "validation_type": "api_check",
                    }
                elif data.get("status") == "OVER_QUERY_LIMIT":
                     return {
                        "validated": True,
                        "validation_info": "Google API Key ATIVA (Quota Exceeded)",
                        "validation_type": "api_check",
                    }

            # 2. Custom Search API (outro alvo comum)
            resp2 = client.get(f"https://www.googleapis.com/customsearch/v1?q=test&key={key}")
            if resp2.status_code == 200:
                 return {
                    "validated": True,
                    "validation_info": "Google API Key ATIVA (Custom Search API)",
                    "validation_type": "api_check",
                }

            return {
                "validated": False,
                "validation_info": "Google API Key inválida ou todas as APIs restritas",
                "validation_type": "api_check",
            }
    except Exception as e:
        return {"validated": None, "validation_info": f"Erro: {e}", "validation_type": "error"}


def _validate_slack(token: str) -> dict:
    """Valida Slack token via auth.test."""
    clean = re.search(r'(xox[baprs]-[0-9a-zA-Z\-]{10,})', token)
    if not clean:
        return {"validated": False, "validation_info": "Formato inválido", "validation_type": "format_check"}

    tok = clean.group(1)
    try:
        with _get_httpx_client() as client:
            resp = client.post(
                "https://slack.com/api/auth.test",
                headers={"Authorization": f"Bearer {tok}"},
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("ok"):
                    team = data.get("team", "unknown")
                    user = data.get("user", "unknown")
                    return {
                        "validated": True,
                        "validation_info": f"Slack Token ATIVO — Team: {team}, User: {user}",
                        "validation_type": "api_check",
                    }
                else:
                    return {
                        "validated": False,
                        "validation_info": f"Token inválido: {data.get('error', 'unknown')}",
                        "validation_type": "api_check",
                    }
    except Exception as e:
        return {"validated": None, "validation_info": f"Erro: {e}", "validation_type": "error"}

    return {"validated": None, "validation_info": "Não foi possível validar", "validation_type": "error"}


def _validate_slack_webhook(token: str) -> dict:
    """Verifica se Slack webhook URL é acessível (sem enviar mensagem)."""
    return {
        "validated": None,
        "validation_info": "Webhook URL encontrada (não testada para evitar envio de mensagem)",
        "validation_type": "format_check",
    }


def _validate_stripe(token: str) -> dict:
    """Valida Stripe Key."""
    clean = re.search(r'(sk_live_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,})', token)
    if not clean:
        if "sk_test_" in token or "rk_test_" in token:
            return {
                "validated": True,
                "validation_info": "Stripe TEST Key (não é produção)",
                "validation_type": "format_check",
            }
        return {"validated": False, "validation_info": "Formato inválido", "validation_type": "format_check"}

    key = clean.group(1)
    try:
        with _get_httpx_client() as client:
            resp = client.get(
                "https://api.stripe.com/v1/balance",
                headers={"Authorization": f"Bearer {key}"},
            )
            if resp.status_code == 200:
                return {
                    "validated": True,
                    "validation_info": "Stripe LIVE Key ATIVA!",
                    "validation_type": "api_check",
                }
            elif resp.status_code == 401:
                return {
                    "validated": False,
                    "validation_info": "Stripe Key inválida",
                    "validation_type": "api_check",
                }
    except Exception as e:
        return {"validated": None, "validation_info": f"Erro: {e}", "validation_type": "error"}

    return {"validated": None, "validation_info": "Não foi possível validar", "validation_type": "error"}


def _validate_twilio(token: str) -> dict:
    """Valida Twilio API Key pelo formato."""
    clean = re.search(r'(SK[0-9a-fA-F]{32})', token)
    if clean:
        return {
            "validated": None,
            "validation_info": "Formato válido de Twilio API Key (precisa do Account SID para validação completa)",
            "validation_type": "format_check",
        }
    return {"validated": False, "validation_info": "Formato inválido", "validation_type": "format_check"}


def _validate_twilio_sid(token: str) -> dict:
    """Valida formato de Twilio Account SID (AC + 32 hex chars)."""
    clean = re.search(r'(AC[a-fA-F0-9]{32})', token)
    if clean:
        return {
            "validated": None,
            "validation_info": "Formato válido de Twilio Account SID (Strict HEX)",
            "validation_type": "format_check",
        }
    return {"validated": False, "validation_info": "Formato inválido (deve ser AC + 32 hex chars)", "validation_type": "format_check"}


def _validate_twitter_bearer(token: str) -> dict:
    """Valida formato de Twitter Bearer Token."""
    if token.startswith('AAAA') and len(token) > 100 and '%' not in token:
        return {
            "validated": None,
            "validation_info": "Formato provável de Twitter Bearer Token (Length/Prefix OK)",
            "validation_type": "format_check",
        }
    return {"validated": False, "validation_info": "Falso positivo provável (Prefix/Length/Chars inválidos)", "validation_type": "format_check"}


def _validate_sendgrid(token: str) -> dict:
    """Valida SendGrid API Key."""
    clean = re.search(r'(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})', token)
    if not clean:
        return {"validated": False, "validation_info": "Formato inválido", "validation_type": "format_check"}

    key = clean.group(1)
    try:
        with _get_httpx_client() as client:
            resp = client.get(
                "https://api.sendgrid.com/v3/scopes",
                headers={"Authorization": f"Bearer {key}"},
            )
            if resp.status_code == 200:
                return {
                    "validated": True,
                    "validation_info": "SendGrid API Key ATIVA!",
                    "validation_type": "api_check",
                }
            elif resp.status_code in (401, 403):
                return {
                    "validated": False,
                    "validation_info": "SendGrid Key inválida ou sem permissão",
                    "validation_type": "api_check",
                }
    except Exception as e:
        return {"validated": None, "validation_info": f"Erro: {e}", "validation_type": "error"}

    return {"validated": None, "validation_info": "Não foi possível validar", "validation_type": "error"}


def _validate_vercel(token: str) -> dict:
    """Valida Vercel token via /v2/user."""
    clean = re.search(r'((?:vcel_|vc_)[a-zA-Z0-9]{32,})', token)
    if not clean:
        return {"validated": False, "validation_info": "Formato inválido", "validation_type": "format_check"}

    tok = clean.group(1)
    try:
        with _get_httpx_client() as client:
            resp = client.get(
                "https://api.vercel.com/v2/user",
                headers={"Authorization": f"Bearer {tok}"},
            )
            if resp.status_code == 200:
                data = resp.json()
                username = data.get("user", {}).get("username", "unknown")
                return {
                    "validated": True,
                    "validation_info": f"Vercel Token ATIVO — Usuário: {username}",
                    "validation_type": "api_check",
                }
            elif resp.status_code in (401, 403):
                return {
                    "validated": False,
                    "validation_info": "Vercel Token inválido ou expirado",
                    "validation_type": "api_check",
                }
            else:
                return {
                    "validated": None,
                    "validation_info": f"Resposta inesperada: HTTP {resp.status_code}",
                    "validation_type": "api_check",
                }
    except Exception as e:
        return {"validated": None, "validation_info": f"Erro: {e}", "validation_type": "error"}


def _validate_telegram(token: str) -> dict:
    """Valida Telegram Bot token via getMe."""
    clean = re.search(r'([0-9]+:AA[0-9A-Za-z_-]{33})', token)
    if not clean:
        return {"validated": False, "validation_info": "Formato inválido", "validation_type": "format_check"}

    tok = clean.group(1)
    try:
        with _get_httpx_client() as client:
            resp = client.get(f"https://api.telegram.org/bot{tok}/getMe")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("ok"):
                    bot_name = data.get("result", {}).get("username", "unknown")
                    return {
                        "validated": True,
                        "validation_info": f"Telegram Bot ATIVO — @{bot_name}",
                        "validation_type": "api_check",
                    }
                else:
                    return {
                        "validated": False,
                        "validation_info": "Bot token inválido",
                        "validation_type": "api_check",
                    }
            elif resp.status_code == 401:
                return {
                    "validated": False,
                    "validation_info": "Bot token inválido ou revogado",
                    "validation_type": "api_check",
                }
    except Exception as e:
        return {"validated": None, "validation_info": f"Erro: {e}", "validation_type": "error"}

    return {"validated": None, "validation_info": "Não foi possível validar", "validation_type": "error"}


# ═══════════════════════════════════════════════════════════════
# FORMAT VALIDATORS (sem HTTP, apenas verificação de formato)
# ═══════════════════════════════════════════════════════════════

def _validate_discord_format(token: str) -> dict:
    """Verifica formato de Discord token."""
    if re.search(r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}', token):
        return {
            "validated": None,
            "validation_info": "Formato válido de Discord Token (não testado contra API para evitar ban)",
            "validation_type": "format_check",
        }
    return {"validated": False, "validation_info": "Formato inválido", "validation_type": "format_check"}


def _validate_npm_format(token: str) -> dict:
    """Verifica formato de NPM token."""
    if re.search(r'npm_[A-Za-z0-9]{36}', token):
        return {
            "validated": None,
            "validation_info": "Formato válido de NPM Token",
            "validation_type": "format_check",
        }
    return {"validated": False, "validation_info": "Formato inválido", "validation_type": "format_check"}


def _validate_pypi_format(token: str) -> dict:
    """Verifica formato de PyPI token."""
    if re.search(r'pypi-[A-Za-z0-9_-]{50,}', token):
        return {
            "validated": None,
            "validation_info": "Formato válido de PyPI Token",
            "validation_type": "format_check",
        }
    return {"validated": False, "validation_info": "Formato inválido", "validation_type": "format_check"}


def _validate_supabase_format(token: str) -> dict:
    """Verifica formato de Supabase key (é um JWT)."""
    if "eyJ" in token:
        return _validate_jwt(token)
    return {"validated": None, "validation_info": "Formato de Supabase key", "validation_type": "format_check"}


def _validate_newrelic_format(token: str) -> dict:
    """Verifica formato de New Relic key."""
    if re.search(r'NRAK-[A-Z0-9]{27}', token):
        return {
            "validated": None,
            "validation_info": "Formato válido de New Relic Key",
            "validation_type": "format_check",
        }
    return {"validated": False, "validation_info": "Formato inválido", "validation_type": "format_check"}


def _validate_sentry_format(token: str) -> dict:
    """Verifica formato de Sentry Auth Token."""
    if re.search(r'sntrys_[a-zA-Z0-9]{64}', token):
        return {
            "validated": None,
            "validation_info": "Formato válido de Sentry Auth Token",
            "validation_type": "format_check",
        }
    return {"validated": False, "validation_info": "Formato inválido", "validation_type": "format_check"}


# ═══════════════════════════════════════════════════════════════
# JWT VALIDATOR
# ═══════════════════════════════════════════════════════════════

def _validate_jwt(token: str) -> dict:
    """Decodifica JWT para verificar expiração e valida tamanho das partes."""
    parts = token.split(".")
    if len(parts) != 3:
        return {"validated": None, "validation_info": "Não é formato JWT válido", "validation_type": "format_check"}

    # Validação rigorosa: cada parte deve ter um tamanho mínimo razoável (evita lixo com pontos)
    if any(len(p) < 10 for p in parts):
        return {"validated": False, "validation_info": "JWT inválido (partes muito curtas)", "validation_type": "format_check"}

    try:
        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding

        payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        exp = payload.get("exp")
        if exp:
            exp_date = datetime.fromtimestamp(exp)
            if exp_date < datetime.now():
                return {
                    "validated": False,
                    "validation_info": f"JWT EXPIRADO em {exp_date.strftime('%Y-%m-%d %H:%M')}",
                    "validation_type": "format_check",
                }
            else:
                return {
                    "validated": True,
                    "validation_info": f"JWT válido até {exp_date.strftime('%Y-%m-%d %H:%M')}",
                    "validation_type": "format_check",
                }

        iss = payload.get("iss", "unknown")
        sub = payload.get("sub", "unknown")
        return {
            "validated": None,
            "validation_info": f"JWT sem expiração. Issuer: {iss}, Subject: {sub}",
            "validation_type": "format_check",
        }
    except Exception:
        return {"validated": None, "validation_info": "JWT mal-formado", "validation_type": "format_check"}
