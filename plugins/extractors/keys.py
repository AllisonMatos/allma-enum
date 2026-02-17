import re
import json

# Patterns expandidos para mais tipos de secrets
REGEX_PATTERNS = {
    # Cloud Providers
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
    "Amazon MWS Auth Token": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "Azure Storage Key": r"(?i)azure[_\-]?storage[_\-]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{88})['\"]?",
    "GCP Service Account": r"\"type\":\s*\"service_account\"",
    
    # Social/OAuth
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Facebook App Secret": r"(?i)facebook[_\-]?(?:app[_\-]?)?secret['\"]?\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?",
    "Twitter Bearer Token": r"AAAAAAAAA[A-Za-z0-9%]+",
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
    "GitHub OAuth": r"(?i)github[_\-]?(?:oauth|token|secret)['\"]?\s*[:=]\s*['\"]?([a-f0-9]{40})['\"]?",
    
    # Payment
    "Stripe Publishable Key": r"pk_(?:live|test)_[0-9a-zA-Z]{24,}",
    "Stripe Secret Key": r"sk_(?:live|test)_[0-9a-zA-Z]{24,}",
    "PayPal Braintree": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\-_]{43}",
    
    # Communication
    "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Twilio Account SID": r"AC[a-zA-Z0-9_\-]{32}",
    "SendGrid API Key": r"SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}",
    "Mailchimp API Key": r"[a-f0-9]{32}-us[0-9]{1,2}",
    
    # Firebase
    "Firebase URL": r"https://[a-z0-9-]+\.firebaseio\.com",
    "Firebase API Key": r"(?i)firebase[_\-]?api[_\-]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_-]{39})['\"]?",
    
    # JWT/Auth
    "JWT Token": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/]*",
    "Bearer Token": r"(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}",
    "Basic Auth": r"(?i)basic\s+[a-zA-Z0-9+/=]{20,}",
    
    # Database
    "MongoDB Connection": r"mongodb(?:\+srv)?://[^\s\"'<>]+",
    "PostgreSQL Connection": r"postgres(?:ql)?://[^\s\"'<>]+",
    "MySQL Connection": r"mysql://[^\s\"'<>]+",
    "Redis URL": r"redis://[^\s\"'<>]+",
    
    # Private Keys
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "SSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "PGP Private Key": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "EC Private Key": r"-----BEGIN EC PRIVATE KEY-----",
    
    # Generic Patterns
    "Generic API Key": r"(?i)(?:api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|secret[_\-]?key)\s*[:=]\s*['\"]([0-9a-zA-Z\-_]{16,64})['\"]",
    "Generic Secret": r"(?i)(?:secret|password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{8,64})['\"]",
    "Private Key in Var": r"(?i)(?:private[_\-]?key|priv[_\-]?key)\s*[:=]\s*['\"]([^'\"]{20,})['\"]",
}

# Informacoes sobre cada tipo de key
KEY_INFO = {
    "Google API Key": {
        "service": "Google Cloud / Maps / Firebase",
        "risk": "HIGH",
        "usage": "Pode ser usado para acessar APIs do Google, cobrar custos na conta",
        "docs": "https://cloud.google.com/docs/authentication/api-keys"
    },
    "AWS Access Key": {
        "service": "Amazon Web Services",
        "risk": "CRITICAL",
        "usage": "Acesso a recursos AWS, pode ter permissoes amplas",
        "docs": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
    },
    "Stripe Secret Key": {
        "service": "Stripe Payments",
        "risk": "CRITICAL",
        "usage": "Pode processar pagamentos, acessar dados de clientes",
        "docs": "https://stripe.com/docs/keys"
    },
    "JWT Token": {
        "service": "Authentication",
        "risk": "HIGH",
        "usage": "Token de sessao/autenticacao, pode impersonar usuarios",
        "docs": "https://jwt.io/introduction"
    },
    "MongoDB Connection": {
        "service": "MongoDB Database",
        "risk": "CRITICAL",
        "usage": "Acesso direto ao banco de dados",
        "docs": "https://www.mongodb.com/docs/manual/reference/connection-string/"
    },
    "GitHub Token": {
        "service": "GitHub",
        "risk": "HIGH",
        "usage": "Acesso a repositorios, pode ter permissoes de escrita",
        "docs": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"
    },
    "Slack Token": {
        "service": "Slack",
        "risk": "MEDIUM",
        "usage": "Enviar mensagens, acessar canais e arquivos",
        "docs": "https://api.slack.com/authentication/token-types"
    },
    "Firebase URL": {
        "service": "Firebase Realtime Database",
        "risk": "MEDIUM",
        "usage": "Pode indicar database exposto sem autenticacao",
        "docs": "https://firebase.google.com/docs/database/security"
    },
    "RSA Private Key": {
        "service": "Cryptography",
        "risk": "CRITICAL",
        "usage": "Chave privada, pode descriptografar dados ou assinar como o dono",
        "docs": "N/A"
    }
}


def get_context_lines(content: str, match_start: int, context_size: int = 5) -> dict:
    """
    Retorna linhas de contexto ao redor do match.
    """
    lines = content.splitlines()
    
    # Encontrar linha do match
    chars_counted = 0
    line_idx = 0
    for i, line in enumerate(lines):
        chars_counted += len(line) + 1  # +1 for newline
        if chars_counted > match_start:
            line_idx = i
            break
    
    start_line = max(0, line_idx - context_size)
    end_line = min(len(lines), line_idx + context_size + 1)
    
    context_lines = lines[start_line:end_line]
    
    return {
        "line_number": line_idx + 1,
        "start_line": start_line + 1,
        "end_line": end_line,
        "lines": context_lines,
        "full_context": "\n".join(context_lines)
    }


def analyze_key_usage(content: str, match_start: int, key_type: str) -> dict:
    """
    Analisa como a key esta sendo usada no codigo.
    """
    lines = content.splitlines()
    
    # Encontrar linha do match
    chars_counted = 0
    line_idx = 0
    for i, line in enumerate(lines):
        chars_counted += len(line) + 1
        if chars_counted > match_start:
            line_idx = i
            break
    
    current_line = lines[line_idx] if line_idx < len(lines) else ""
    
    usage_info = {
        "variable_name": None,
        "assignment_type": None,
        "in_function": None,
        "possible_hardcoded": False
    }
    
    # Detectar nome da variavel
    var_patterns = [
        r"(?:const|let|var)\s+(\w+)\s*=",
        r"(\w+)\s*[:=]",
        r"\"(\w+)\"\s*:",
        r"'(\w+)'\s*:",
    ]
    
    for pattern in var_patterns:
        m = re.search(pattern, current_line)
        if m:
            usage_info["variable_name"] = m.group(1)
            break
    
    # Detectar tipo de atribuicao
    if "const " in current_line or "final " in current_line:
        usage_info["assignment_type"] = "constant"
    elif "let " in current_line or "var " in current_line:
        usage_info["assignment_type"] = "variable"
    elif "process.env" in current_line or "os.environ" in current_line:
        usage_info["assignment_type"] = "environment"
    else:
        usage_info["assignment_type"] = "unknown"
    
    # Verificar se parece hardcoded
    env_indicators = ["process.env", "os.environ", "getenv", "ENV[", "${"]
    if not any(ind in current_line for ind in env_indicators):
        usage_info["possible_hardcoded"] = True
    
    return usage_info


def extract_keys(content: str, source_url: str = None, source_file: str = None) -> list:
    """
    Scans content for secrets and returns a list of found items with full context.
    
    Args:
        content: Codigo/HTML para analisar
        source_url: URL de onde o conteudo foi obtido
        source_file: Caminho do arquivo local (se aplicavel)
        
    Returns: 
        list of dicts com informacoes completas de cada key encontrada
    """
    from .token_validator import validate_token
    
    found = []
    
    for key_type, pattern in REGEX_PATTERNS.items():
        try:
            matches = list(re.finditer(pattern, content))
        except re.error:
            continue
            
        for m in matches:
            match_str = m.group(0)
            
            # Obter contexto
            context = get_context_lines(content, m.start())
            
            # Analisar uso
            usage = analyze_key_usage(content, m.start(), key_type)
            
            # Obter info do tipo de key
            key_info = KEY_INFO.get(key_type, {
                "service": "Unknown",
                "risk": "UNKNOWN",
                "usage": "Verifique manualmente",
                "docs": "N/A"
            })
            
            # Validar token contra API
            validation = validate_token(key_type, match_str)
            
            found.append({
                "type": key_type,
                "match": match_str[:100] + "..." if len(match_str) > 100 else match_str,
                "full_match": match_str,
                "source": {
                    "url": source_url,
                    "file": source_file,
                    "line": context["line_number"]
                },
                "context": {
                    "lines": context["lines"],
                    "full": context["full_context"],
                    "start_line": context["start_line"],
                    "end_line": context["end_line"]
                },
                "usage": usage,
                "info": key_info,
                "validated": validation.get("validated"),
                "validation_info": validation.get("validation_info", ""),
                "validation_type": validation.get("validation_type", "not_supported"),
            })
    
    return found


def extract_keys_to_json(content: str, source_url: str = None, source_file: str = None) -> str:
    """
    Extrai keys e retorna como JSON formatado.
    """
    keys = extract_keys(content, source_url, source_file)
    return json.dumps(keys, indent=2, ensure_ascii=False)


def format_key_report(key: dict) -> str:
    """
    Formata uma key encontrada para output texto.
    """
    lines = [
        f"={'=' * 60}",
        f"TYPE: {key['type']}",
        f"RISK: {key['info'].get('risk', 'UNKNOWN')}",
        f"SERVICE: {key['info'].get('service', 'Unknown')}",
        f"",
        f"MATCH: {key['match']}",
        f"",
        f"SOURCE:",
        f"  URL: {key['source'].get('url', 'N/A')}",
        f"  File: {key['source'].get('file', 'N/A')}",
        f"  Line: {key['source'].get('line', 'N/A')}",
        f"",
        f"VARIABLE: {key['usage'].get('variable_name', 'N/A')}",
        f"HARDCODED: {'YES - VERIFY!' if key['usage'].get('possible_hardcoded') else 'Possibly from env'}",
        f"",
        f"CONTEXT:",
    ]
    
    for line in key['context'].get('lines', []):
        lines.append(f"  {line}")
    
    lines.append(f"")
    lines.append(f"USAGE INFO: {key['info'].get('usage', 'N/A')}")
    lines.append(f"DOCS: {key['info'].get('docs', 'N/A')}")
    lines.append(f"={'=' * 60}")
    lines.append("")
    
    return "\n".join(lines)
