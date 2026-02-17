"""
Token Validator — Valida tokens/secrets encontrados contra APIs reais.
Determina se um secret é ATIVO, INVÁLIDO, ou NÃO TESTADO.
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
        "GitHub Token": _validate_github,
        "GitHub OAuth": _validate_github,
        "AWS Access Key": _validate_aws,
        "Google API Key": _validate_google,
        "Slack Token": _validate_slack,
        "Slack Webhook": _validate_slack_webhook,
        "Stripe Key": _validate_stripe,
        "Twilio API Key": _validate_twilio,
        "SendGrid API Key": _validate_sendgrid,
    }

    validator = validators.get(key_type)
    if validator:
        try:
            return validator(token_value)
        except Exception as e:
            return {
                "validated": None,
                "validation_info": f"Erro na validação: {str(e)[:100]}",
                "validation_type": "error"
            }

    # Verificações genéricas por formato
    if key_type == "JWT Token":
        return _validate_jwt(token_value)

    # Tipo não suportado para validação
    return {
        "validated": None,
        "validation_info": "Tipo de token sem validação automática",
        "validation_type": "not_supported"
    }


def _get_httpx_client():
    import httpx
    return httpx.Client(timeout=VALIDATION_TIMEOUT, verify=False, follow_redirects=True)


def _validate_github(token: str) -> dict:
    """Valida GitHub token via /user endpoint."""
    # Limpar token (pode ter prefixes)
    clean = re.search(r'(gh[ps]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,})', token)
    if clean:
        token = clean.group(1)

    try:
        with _get_httpx_client() as client:
            resp = client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"token {token}", "User-Agent": "EnumAllma"}
            )
            if resp.status_code == 200:
                data = resp.json()
                username = data.get("login", "unknown")
                return {
                    "validated": True,
                    "validation_info": f"TOKEN ATIVO — Usuário: {username}",
                    "validation_type": "api_check"
                }
            elif resp.status_code == 401:
                return {
                    "validated": False,
                    "validation_info": "Token inválido ou expirado",
                    "validation_type": "api_check"
                }
            else:
                return {
                    "validated": None,
                    "validation_info": f"Resposta inesperada: HTTP {resp.status_code}",
                    "validation_type": "api_check"
                }
    except Exception as e:
        return {"validated": None, "validation_info": f"Erro de conexão: {e}", "validation_type": "error"}


def _validate_aws(token: str) -> dict:
    """Valida AWS Access Key pelo formato (validação completa requer Secret Key)."""
    # AWS Access Keys sempre começam com AKIA e têm 20 chars
    clean = re.search(r'(AKIA[0-9A-Z]{16})', token)
    if clean:
        return {
            "validated": None,
            "validation_info": "Formato válido de AWS Access Key (precisa da Secret Key para validar completamente)",
            "validation_type": "format_check"
        }
    return {
        "validated": False,
        "validation_info": "Formato inválido de AWS Access Key",
        "validation_type": "format_check"
    }


def _validate_google(token: str) -> dict:
    """Valida Google API Key via tokeninfo."""
    clean = re.search(r'(AIza[0-9A-Za-z\-_]{35})', token)
    if not clean:
        return {"validated": False, "validation_info": "Formato inválido", "validation_type": "format_check"}

    key = clean.group(1)
    try:
        with _get_httpx_client() as client:
            # Tentar usar a key para acessar a API do Maps (simples e grátis)
            resp = client.get(f"https://www.googleapis.com/oauth2/v3/tokeninfo?access_token={key}")
            if resp.status_code == 200:
                return {
                    "validated": True,
                    "validation_info": "Google API Key ATIVA",
                    "validation_type": "api_check"
                }
            # Tentar outra API
            resp2 = client.get(f"https://maps.googleapis.com/maps/api/geocode/json?address=test&key={key}")
            if resp2.status_code == 200:
                data = resp2.json()
                if data.get("status") != "REQUEST_DENIED":
                    return {
                        "validated": True,
                        "validation_info": f"Google API Key ATIVA (Maps API: {data.get('status')})",
                        "validation_type": "api_check"
                    }
            return {
                "validated": False,
                "validation_info": "Google API Key inválida ou restrita",
                "validation_type": "api_check"
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
                headers={"Authorization": f"Bearer {tok}"}
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("ok"):
                    team = data.get("team", "unknown")
                    user = data.get("user", "unknown")
                    return {
                        "validated": True,
                        "validation_info": f"Slack Token ATIVO — Team: {team}, User: {user}",
                        "validation_type": "api_check"
                    }
                else:
                    return {
                        "validated": False,
                        "validation_info": f"Token inválido: {data.get('error', 'unknown')}",
                        "validation_type": "api_check"
                    }
    except Exception as e:
        return {"validated": None, "validation_info": f"Erro: {e}", "validation_type": "error"}

    return {"validated": None, "validation_info": "Não foi possível validar", "validation_type": "error"}


def _validate_slack_webhook(token: str) -> dict:
    """Verifica se Slack webhook URL é acessível (sem enviar mensagem)."""
    return {
        "validated": None,
        "validation_info": "Webhook URL encontrada (não testada para evitar envio de mensagem)",
        "validation_type": "format_check"
    }


def _validate_stripe(token: str) -> dict:
    """Valida Stripe Key."""
    clean = re.search(r'(sk_live_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,})', token)
    if not clean:
        # Pode ser test key
        if "sk_test_" in token or "rk_test_" in token:
            return {
                "validated": True,
                "validation_info": "Stripe TEST Key (não é produção)",
                "validation_type": "format_check"
            }
        return {"validated": False, "validation_info": "Formato inválido", "validation_type": "format_check"}

    key = clean.group(1)
    try:
        with _get_httpx_client() as client:
            resp = client.get(
                "https://api.stripe.com/v1/balance",
                headers={"Authorization": f"Bearer {key}"}
            )
            if resp.status_code == 200:
                return {
                    "validated": True,
                    "validation_info": "Stripe LIVE Key ATIVA!",
                    "validation_type": "api_check"
                }
            elif resp.status_code == 401:
                return {
                    "validated": False,
                    "validation_info": "Stripe Key inválida",
                    "validation_type": "api_check"
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
            "validation_type": "format_check"
        }
    return {"validated": False, "validation_info": "Formato inválido", "validation_type": "format_check"}


def _validate_sendgrid(token: str) -> dict:
    """Valida SendGrid API Key."""
    clean = re.search(r'(SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43})', token)
    if not clean:
        return {"validated": False, "validation_info": "Formato inválido", "validation_type": "format_check"}

    key = clean.group(1)
    try:
        with _get_httpx_client() as client:
            resp = client.get(
                "https://api.sendgrid.com/v3/scopes",
                headers={"Authorization": f"Bearer {key}"}
            )
            if resp.status_code == 200:
                return {
                    "validated": True,
                    "validation_info": "SendGrid API Key ATIVA!",
                    "validation_type": "api_check"
                }
            elif resp.status_code in (401, 403):
                return {
                    "validated": False,
                    "validation_info": "SendGrid Key inválida ou sem permissão",
                    "validation_type": "api_check"
                }
    except Exception as e:
        return {"validated": None, "validation_info": f"Erro: {e}", "validation_type": "error"}

    return {"validated": None, "validation_info": "Não foi possível validar", "validation_type": "error"}


def _validate_jwt(token: str) -> dict:
    """Decodifica JWT para verificar expiração."""
    parts = token.split(".")
    if len(parts) != 3:
        return {"validated": None, "validation_info": "Não é formato JWT válido", "validation_type": "format_check"}

    try:
        # Decodificar payload (parte 2)
        payload_b64 = parts[1]
        # Adicionar padding
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
                    "validation_type": "format_check"
                }
            else:
                return {
                    "validated": True,
                    "validation_info": f"JWT válido até {exp_date.strftime('%Y-%m-%d %H:%M')}",
                    "validation_type": "format_check"
                }

        iss = payload.get("iss", "unknown")
        sub = payload.get("sub", "unknown")
        return {
            "validated": None,
            "validation_info": f"JWT sem expiração. Issuer: {iss}, Subject: {sub}",
            "validation_type": "format_check"
        }
    except Exception:
        return {"validated": None, "validation_info": "JWT mal-formado", "validation_type": "format_check"}
