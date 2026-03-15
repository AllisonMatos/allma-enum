import re
import json
import math
from collections import Counter

# ════════════════════════════════════════════════════════════════
# REGEX PATTERNS — 70+ patterns para detecção de secrets
# ════════════════════════════════════════════════════════════════
REGEX_PATTERNS = {
    # ── Cloud Providers ──────────────────────────────────────
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "AWS Access Key": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "AWS Secret Key": r"(?i)aws[_\s]*(?:secret[_\s]*)?(?:access[_\s]*)?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
    "AWS Session Token": r"(?i)aws[_\s]*session[_\s]*token[_\s]*[:=]['\"]?([A-Za-z0-9/+=]{100,})['\"]?",
    "Amazon MWS Auth Token": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "Azure Storage Key": r"(?i)azure[_\-]?storage[_\-]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{88})['\"]?",
    "Azure Client Secret": r"(?i)(?:azure|client)[_\s]*secret[_\s]*[:=]['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?",
    "Azure Connection String": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88};EndpointSuffix=",
    "Azure SAS Token": r"[?&]sig=[A-Za-z0-9%]+",
    "GCP Service Account": r"\"type\":\s*\"service_account\"",
    "Google OAuth ID": r"[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com",

    # ── GitHub ───────────────────────────────────────────────
    "GitHub PAT (Fine-grained)": r"github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}",
    "GitHub PAT (Classic)": r"ghp_[a-zA-Z0-9]{36}",
    "GitHub OAuth Token": r"gho_[a-zA-Z0-9]{36}",
    "GitHub App Token": r"(?:ghu|ghs)_[a-zA-Z0-9]{36}",
    "GitHub Refresh Token": r"ghr_[a-zA-Z0-9]{36}",
    "GitHub Token (Legacy)": r"(?i)github[_\-]?(?:oauth|token|secret)['\"]?\s*[:=]\s*['\"]?([a-f0-9]{40})['\"]?",

    # ── Vercel ───────────────────────────────────────────────
    "Vercel Token": r"(?:vcel_|vc_)[a-zA-Z0-9]{32,}",

    # ── Supabase ─────────────────────────────────────────────
    "Supabase URL": r"https://[a-z0-9]+\.supabase\.co",
    "Supabase Anon Key": r"(?i)(?:supabase[_\s]*)?(?:anon[_\s]*)?key[_\s]*[:=].*?(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)",

    # ── Social/OAuth ─────────────────────────────────────────
    "Facebook Access Token": r"EAA[a-zA-Z0-9]+",
    "Facebook App Secret": r"(?i)facebook[_\-]?(?:app[_\-]?)?secret['\"]?\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?",
    "Twitter Bearer Token": r"AAAA[A-Za-z0-9]{96,}",
    "Twitter API Secret": r"(?i)twitter[_\s]*(?:api[_\s]*)?secret[_\s]*[:=]['\"]([a-zA-Z0-9]{35,50})['\"]",
    "LinkedIn Client Secret": r"(?i)linkedin[_\s]*(?:client[_\s]*)?secret[_\s]*[:=]['\"]([a-zA-Z0-9]{16})['\"]",
    "OAuth Client Secret": r"(?i)(?:oauth[_\s]*)?client[_\s]*secret[_\s]*[:=]['\"]([a-zA-Z0-9_\-]{16,})['\"]",

    # ── Payment ──────────────────────────────────────────────
    "Stripe Publishable Key": r"pk_(?:live|test)_[0-9a-zA-Z]{24,}",
    "Stripe Secret Key": r"sk_(?:live|test)_[0-9a-zA-Z]{24,}",
    "Stripe Restricted Key": r"rk_(?:live|test)_[0-9a-zA-Z]{24,}",
    "Stripe Webhook Secret": r"whsec_[a-zA-Z0-9]{32,}",
    "PayPal Braintree": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "PayPal Client Secret": r"(?i)paypal[_\s]*(?:client[_\s]*)?secret[_\s]*[:=]['\"]([a-zA-Z0-9_\-]{32,})['\"]",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\-_]{43}",

    # ── Communication ────────────────────────────────────────
    "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}",
    "Discord Token": r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}",
    "Discord Webhook": r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
    "Telegram Bot Token": r"[0-9]+:AA[0-9A-Za-z_-]{33}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Twilio Account SID": r"AC[0-9a-fA-F]{32}",
    "Twilio Auth Token": r"(?i)twilio[_\s]*(?:auth[_\s]*)?token[_\s]*[:=]['\"]([a-f0-9]{32})['\"]",
    "SendGrid API Key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
    "Mailchimp API Key": r"[a-f0-9]{32}-us[0-9]{1,2}",
    "Mailgun API Key": r"key-[a-zA-Z0-9]{32}",

    # ── Firebase ─────────────────────────────────────────────
    "Firebase URL": r"https://[a-z0-9-]+\.firebaseio\.com",
    "Firebase Database URL": r"(?i)(?:firebase[_\s]*)?database[_\s]*url[_\s]*[:=]['\"]?(https://[a-z0-9-]+\.firebaseio\.com)['\"]?",
    "Firebase API Key": r"(?i)firebase[_\-]?api[_\-]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_-]{39})['\"]?",

    # ── Monitoring / DevOps ──────────────────────────────────
    "Sentry DSN": r"https://[a-f0-9]{32}@(?:o[0-9]+\.)?(?:sentry\.io|[a-z0-9-]+\.sentry\.io)/[0-9]+",
    "Sentry Auth Token": r"sntrys_[a-zA-Z0-9]{64}",
    "Algolia API Key": r"(?i)algolia[_\s]*(?:api[_\s]*)?key[_\s]*[:=]['\"]?([a-f0-9]{32})['\"]?",
    "Algolia Admin Key": r"(?i)algolia[_\s]*admin[_\s]*key[_\s]*[:=]['\"]?([a-f0-9]{32})['\"]?",
    "Datadog API Key": r"(?i)datadog[_\s]*(?:api[_\s]*)?key[_\s]*[:=]['\"]?([a-f0-9]{32})['\"]?",
    "New Relic Key": r"NRAK-[A-Z0-9]{27}",
    "Heroku API Key": r"(?i)heroku[_\s]*(?:api[_\s]*)?key[_\s]*[:=]['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?",

    # ── Package Registries ───────────────────────────────────
    "NPM Token": r"npm_[A-Za-z0-9]{36}",
    "PyPI Token": r"pypi-[A-Za-z0-9_-]{50,}",

    # ── JWT / Auth ───────────────────────────────────────────
    "JWT Token": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+",
    "JWT Secret": r"(?i)jwt[_\s]*secret[_\s]*[:=]['\"]?([a-zA-Z0-9_\-]{16,})['\"]?",
    "Bearer Token": r"(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}",
    "Basic Auth": r"(?i)basic\s+[a-zA-Z0-9+/=]{20,}",
    "Refresh Token": r"(?i)refresh[_\s]*token[_\s]*[:=]['\"]?([a-zA-Z0-9_\-.]{20,})['\"]?",

    # ── Database ─────────────────────────────────────────────
    "MongoDB Connection": r"mongodb(?:\+srv)?://[^\s\"'<>]+",
    "PostgreSQL Connection": r"postgres(?:ql)?://[^\s\"'<>]+",
    "MySQL Connection": r"mysql://[^\s\"'<>]+",
    "Redis URL": r"rediss?://[^\s\"'<>]+",
    "Database Password": r"(?i)(?:db|database)[_\s]*password[_\s]*[:=]['\"]?([^\"'\s]{8,})['\"]?",

    # ── Private Keys ─────────────────────────────────────────
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "SSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "PGP Private Key": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "EC Private Key": r"-----BEGIN EC PRIVATE KEY-----",
    "DSA Private Key": r"-----BEGIN DSA PRIVATE KEY-----",

    # ── Hardcoded Credentials ────────────────────────────────
    "Password Hardcoded": r'(?i)(?:password|passwd|pwd|pass)[_\s]*[:=]\s*["\']([^"\']{8,64})["\']',
    "Admin Password": r'(?i)admin[_\s]*(?:password|passwd|pwd)[_\s]*[:=]["\']([^"\']{6,})["\']',
    "Root Password": r'(?i)root[_\s]*password[_\s]*[:=]["\']([^"\']{6,})["\']',
    "Master Key": r'(?i)master[_\s]*key[_\s]*[:=]["\']([^"\']{16,})["\']',
    "Encryption Key": r'(?i)(?:encryption|cipher|aes|des)[_\s]*key[_\s]*[:=]["\']([^"\']{16,})["\']',
    "Salt Value": r'(?i)(?:password[_\s]*)?salt[_\s]*[:=]["\']([^"\']{8,})["\']',

    # ── Cloud Storage URLs ───────────────────────────────────
    "S3 Bucket URL": r"https?://[a-z0-9\-]{3,63}\.s3[\.\-][a-z0-9\-]*\.amazonaws\.com",
    "S3 Path Style URL": r"https?://s3[\.\-][a-z0-9\-]*\.amazonaws\.com/[a-z0-9\-]{3,63}",
    "GCS Bucket URL": r"https?://storage\.googleapis\.com/[a-z0-9\-_.]{3,63}",
    "Azure Blob URL": r"https?://[a-z0-9\-]{3,24}\.blob\.core\.windows\.net",
    "DigitalOcean Spaces URL": r"https?://[a-z0-9\-]{3,63}\.(?:[a-z0-9\-]+\.)?digitaloceanspaces\.com",
    "Cloudinary URL": r"cloudinary://[0-9]+:[a-zA-Z0-9_-]+@[a-z0-9-]+",

    # ── Webhooks & Internal URLs ─────────────────────────────
    "Webhook URL": r"https://[a-z0-9.-]+\.[a-z]{2,}/(?:webhook|hook|callback|notify)[a-zA-Z0-9/_\-?=&]*",
    "Internal URL": r"https?://(?:localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+)(?::\d+)?",
    "Debug Endpoint": r'(?i)(?:debug|test|staging|dev)[_\s]*(?:url|endpoint|api)[_\s]*[:=]["\']((https?://[^"\']+))["\']',

    # ── Generic Patterns ─────────────────────────────────────
    "Generic API Key": r"(?i)(?:api[_\s]*key|apikey|x-api-key|access[_\s]*token|auth[_\s]*token|secret[_\s]*key)\s*[:=]\s*['\"]([0-9a-zA-Z\-_]{16,64})['\"]",
    "Generic Secret": r"(?i)(?:secret|password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{8,64})['\"]",
    "Private Key in Var": r"(?i)(?:private[_\-]?key|priv[_\-]?key)\s*[:=]\s*['\"]([^'\"]{20,})['\"]",

    # ── Miscellaneous Sensitive Data ─────────────────────────
    "Credit Card Number": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
    "Private IP Address": r"\b(?:10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})\b",
}

# ════════════════════════════════════════════════════════════════
# KEY INFO — metadata por tipo de secret
# ════════════════════════════════════════════════════════════════
KEY_INFO = {
    # Cloud
    "Google API Key": {"service": "Google Cloud / Maps / Firebase", "risk": "HIGH", "usage": "Pode acessar APIs do Google, cobrar custos na conta", "docs": "https://cloud.google.com/docs/authentication/api-keys"},
    "AWS Access Key": {"service": "Amazon Web Services", "risk": "CRITICAL", "usage": "Acesso a recursos AWS com permissoes potencialmente amplas", "docs": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"},
    "AWS Secret Key": {"service": "Amazon Web Services", "risk": "CRITICAL", "usage": "Secret key AWS, acesso total quando combinada com Access Key", "docs": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"},
    "AWS Session Token": {"service": "Amazon Web Services", "risk": "HIGH", "usage": "Token de sessão temporário AWS", "docs": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html"},
    "Amazon MWS Auth Token": {"service": "Amazon Marketplace", "risk": "HIGH", "usage": "Acesso ao marketplace da Amazon", "docs": "https://developer-docs.amazon.com/sp-api/"},
    "Azure Storage Key": {"service": "Azure Storage", "risk": "CRITICAL", "usage": "Acesso total a Azure Storage Account", "docs": "https://docs.microsoft.com/azure/storage/"},
    "Azure Client Secret": {"service": "Azure AD", "risk": "CRITICAL", "usage": "Autenticação de aplicativo Azure AD", "docs": "https://docs.microsoft.com/azure/active-directory/"},
    "Azure Connection String": {"service": "Azure Storage", "risk": "CRITICAL", "usage": "Acesso direto a conta de armazenamento Azure", "docs": "https://docs.microsoft.com/azure/storage/common/storage-configure-connection-string"},
    "GCP Service Account": {"service": "Google Cloud", "risk": "CRITICAL", "usage": "Service account JSON com acesso a GCP", "docs": "https://cloud.google.com/iam/docs/service-accounts"},

    # GitHub
    "GitHub PAT (Fine-grained)": {"service": "GitHub", "risk": "HIGH", "usage": "Personal Access Token com escopo específico", "docs": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"},
    "GitHub PAT (Classic)": {"service": "GitHub", "risk": "HIGH", "usage": "Token pessoal clássico, pode ter permissões amplas", "docs": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"},
    "GitHub OAuth Token": {"service": "GitHub", "risk": "HIGH", "usage": "Token OAuth, acesso à conta do usuário", "docs": "https://docs.github.com/en/apps/oauth-apps/"},
    "GitHub App Token": {"service": "GitHub", "risk": "HIGH", "usage": "Token de GitHub App (installation ou user-to-server)", "docs": "https://docs.github.com/en/apps/creating-github-apps/"},
    "GitHub Refresh Token": {"service": "GitHub", "risk": "MEDIUM", "usage": "Refresh token, pode gerar novos access tokens", "docs": "https://docs.github.com/en/apps/creating-github-apps/"},
    "GitHub Token (Legacy)": {"service": "GitHub", "risk": "HIGH", "usage": "Token legacy, verificar permissões", "docs": "https://docs.github.com/en/authentication/"},

    # Vercel / Supabase
    "Vercel Token": {"service": "Vercel", "risk": "HIGH", "usage": "Acesso à conta Vercel, deploy de aplicações", "docs": "https://vercel.com/docs/rest-api#authentication"},
    "Supabase URL": {"service": "Supabase", "risk": "LOW", "usage": "URL do projeto Supabase (não é secret em si)", "docs": "https://supabase.com/docs"},
    "Supabase Anon Key": {"service": "Supabase", "risk": "MEDIUM", "usage": "Anon key, acesso public. Verificar RLS policies", "docs": "https://supabase.com/docs/guides/api/keys"},

    # Social
    "Facebook Access Token": {"service": "Facebook/Meta", "risk": "HIGH", "usage": "Acesso a dados de usuário Facebook", "docs": "https://developers.facebook.com/docs/facebook-login/access-tokens/"},
    "Facebook App Secret": {"service": "Facebook/Meta", "risk": "CRITICAL", "usage": "Secret do app, pode gerar tokens", "docs": "https://developers.facebook.com/docs/"},
    "Twitter Bearer Token": {"service": "Twitter/X", "risk": "HIGH", "usage": "Acesso à API do Twitter", "docs": "https://developer.twitter.com/en/docs/authentication/"},
    "Discord Token": {"service": "Discord", "risk": "CRITICAL", "usage": "Acesso total à conta/bot Discord", "docs": "https://discord.com/developers/docs/"},
    "Discord Webhook": {"service": "Discord", "risk": "MEDIUM", "usage": "Enviar mensagens em canal Discord", "docs": "https://discord.com/developers/docs/resources/webhook"},
    "Telegram Bot Token": {"service": "Telegram", "risk": "HIGH", "usage": "Controle total do bot Telegram", "docs": "https://core.telegram.org/bots/api"},

    # Payment
    "Stripe Secret Key": {"service": "Stripe Payments", "risk": "CRITICAL", "usage": "Pode processar pagamentos, acessar dados de clientes", "docs": "https://stripe.com/docs/keys"},
    "Stripe Publishable Key": {"service": "Stripe Payments", "risk": "LOW", "usage": "Chave pública, uso esperado no frontend", "docs": "https://stripe.com/docs/keys"},
    "Stripe Restricted Key": {"service": "Stripe Payments", "risk": "HIGH", "usage": "Chave com permissões restritas", "docs": "https://stripe.com/docs/keys#limit-access"},
    "Stripe Webhook Secret": {"service": "Stripe Payments", "risk": "HIGH", "usage": "Validação de webhooks Stripe", "docs": "https://stripe.com/docs/webhooks/signatures"},
    "Square Access Token": {"service": "Square Payments", "risk": "CRITICAL", "usage": "Acesso a APIs de pagamento Square", "docs": "https://developer.squareup.com/docs/"},

    # Communication
    "Slack Token": {"service": "Slack", "risk": "HIGH", "usage": "Enviar mensagens, acessar canais e arquivos", "docs": "https://api.slack.com/authentication/token-types"},
    "Slack Webhook": {"service": "Slack", "risk": "MEDIUM", "usage": "Enviar mensagens para canal Slack", "docs": "https://api.slack.com/messaging/webhooks"},
    "Twilio API Key": {"service": "Twilio", "risk": "HIGH", "usage": "Enviar SMS, fazer chamadas", "docs": "https://www.twilio.com/docs/iam/keys/api-key"},
    "SendGrid API Key": {"service": "SendGrid", "risk": "HIGH", "usage": "Enviar emails em nome da conta", "docs": "https://docs.sendgrid.com/ui/account-and-settings/api-keys"},
    "Mailchimp API Key": {"service": "Mailchimp", "risk": "MEDIUM", "usage": "Gerenciar campanhas e contatos", "docs": "https://mailchimp.com/developer/marketing/guides/quick-start/"},
    "Mailgun API Key": {"service": "Mailgun", "risk": "HIGH", "usage": "Enviar emails via Mailgun", "docs": "https://documentation.mailgun.com/en/latest/api-intro.html"},

    # Firebase
    "Firebase URL": {"service": "Firebase Realtime Database", "risk": "MEDIUM", "usage": "Pode indicar database exposto sem autenticação", "docs": "https://firebase.google.com/docs/database/security"},
    "Firebase API Key": {"service": "Firebase", "risk": "MEDIUM", "usage": "API key do Firebase, verificar regras de segurança", "docs": "https://firebase.google.com/docs/projects/api-keys"},

    # Monitoring
    "Sentry DSN": {"service": "Sentry", "risk": "LOW", "usage": "DSN de error tracking (geralmente não-sensível)", "docs": "https://docs.sentry.io/product/sentry-basics/dsn-explainer/"},
    "Sentry Auth Token": {"service": "Sentry", "risk": "HIGH", "usage": "Token de autenticação Sentry com permissões amplas", "docs": "https://docs.sentry.io/api/auth/"},
    "Algolia API Key": {"service": "Algolia Search", "risk": "MEDIUM", "usage": "Acesso à API de busca Algolia", "docs": "https://www.algolia.com/doc/guides/security/api-keys/"},
    "Datadog API Key": {"service": "Datadog", "risk": "HIGH", "usage": "Enviar métricas/logs ao Datadog", "docs": "https://docs.datadoghq.com/account_management/api-app-keys/"},
    "New Relic Key": {"service": "New Relic", "risk": "HIGH", "usage": "Acesso à API New Relic", "docs": "https://docs.newrelic.com/docs/apis/intro-apis/new-relic-api-keys/"},
    "Heroku API Key": {"service": "Heroku", "risk": "HIGH", "usage": "Gerenciar apps Heroku", "docs": "https://devcenter.heroku.com/articles/platform-api-quickstart"},

    # Package Registries
    "NPM Token": {"service": "NPM Registry", "risk": "HIGH", "usage": "Publicar pacotes NPM", "docs": "https://docs.npmjs.com/about-access-tokens"},
    "PyPI Token": {"service": "PyPI", "risk": "HIGH", "usage": "Publicar pacotes Python", "docs": "https://pypi.org/help/#apitoken"},

    # JWT / Auth
    "JWT Token": {"service": "Authentication", "risk": "HIGH", "usage": "Token de sessão/autenticação, pode impersonar usuários", "docs": "https://jwt.io/introduction"},
    "Bearer Token": {"service": "Authentication", "risk": "HIGH", "usage": "Token de acesso em header Authorization", "docs": "N/A"},

    # Database
    "MongoDB Connection": {"service": "MongoDB Database", "risk": "CRITICAL", "usage": "Acesso direto ao banco de dados com credenciais", "docs": "https://www.mongodb.com/docs/manual/reference/connection-string/"},
    "PostgreSQL Connection": {"service": "PostgreSQL Database", "risk": "CRITICAL", "usage": "Acesso direto ao banco PostgreSQL", "docs": "https://www.postgresql.org/docs/current/libpq-connect.html"},
    "MySQL Connection": {"service": "MySQL Database", "risk": "CRITICAL", "usage": "Acesso direto ao banco MySQL", "docs": "https://dev.mysql.com/doc/refman/en/connecting.html"},
    "Redis URL": {"service": "Redis", "risk": "HIGH", "usage": "Acesso direto ao Redis", "docs": "https://redis.io/docs/connect/"},
    "Database Password": {"service": "Database", "risk": "CRITICAL", "usage": "Senha de banco de dados hardcoded", "docs": "N/A"},

    # Private Keys
    "RSA Private Key": {"service": "Cryptography", "risk": "CRITICAL", "usage": "Chave privada RSA, pode descriptografar dados ou assinar", "docs": "N/A"},
    "SSH Private Key": {"service": "Cryptography", "risk": "CRITICAL", "usage": "Chave privada SSH, acesso a servidores", "docs": "N/A"},
    "PGP Private Key": {"service": "Cryptography", "risk": "CRITICAL", "usage": "Chave privada PGP", "docs": "N/A"},
    "EC Private Key": {"service": "Cryptography", "risk": "CRITICAL", "usage": "Chave privada EC (Elliptic Curve)", "docs": "N/A"},

    # Hardcoded Credentials
    "Password Hardcoded": {"service": "Authentication", "risk": "HIGH", "usage": "Senha hardcoded em código", "docs": "N/A"},
    "Admin Password": {"service": "Authentication", "risk": "CRITICAL", "usage": "Senha de admin hardcoded", "docs": "N/A"},
    "Root Password": {"service": "Authentication", "risk": "CRITICAL", "usage": "Senha root hardcoded", "docs": "N/A"},
    "Master Key": {"service": "Cryptography", "risk": "CRITICAL", "usage": "Master key de criptografia hardcoded", "docs": "N/A"},
    "Encryption Key": {"service": "Cryptography", "risk": "CRITICAL", "usage": "Chave de criptografia hardcoded", "docs": "N/A"},

    # Cloud Storage
    "S3 Bucket URL": {"service": "AWS S3", "risk": "MEDIUM", "usage": "URL de bucket S3, pode ter permissões abertas", "docs": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/"},
    "GCS Bucket URL": {"service": "Google Cloud Storage", "risk": "MEDIUM", "usage": "URL de bucket GCS", "docs": "https://cloud.google.com/storage/docs"},
    "Azure Blob URL": {"service": "Azure Blob Storage", "risk": "MEDIUM", "usage": "URL de Azure Blob Storage", "docs": "https://docs.microsoft.com/azure/storage/blobs/"},
    "Cloudinary URL": {"service": "Cloudinary", "risk": "HIGH", "usage": "Acesso à conta Cloudinary com credenciais", "docs": "https://cloudinary.com/documentation"},

    # Webhooks
    "Webhook URL": {"service": "Webhook", "risk": "MEDIUM", "usage": "URL de callback/webhook, pode receber dados sensíveis", "docs": "N/A"},
    "Internal URL": {"service": "Internal Network", "risk": "MEDIUM", "usage": "URL interna exposta, pode revelar infra", "docs": "N/A"},

    # Generic & Misc
    "Generic API Key": {"service": "Unknown", "risk": "MEDIUM", "usage": "Chave genérica, verificar serviço manualmente", "docs": "N/A"},
    "Generic Secret": {"service": "Unknown", "risk": "MEDIUM", "usage": "Secret genérico, verificar manualmente", "docs": "N/A"},
    "Credit Card Number": {"service": "PII/Financial", "risk": "CRITICAL", "usage": "Número de cartão de crédito exposto", "docs": "N/A"},
    "Private IP Address": {"service": "Internal Network", "risk": "LOW", "usage": "IP privado exposto, pode revelar topologia interna", "docs": "N/A"},
}


# ════════════════════════════════════════════════════════════════
# SHANNON ENTROPY — medir aleatoriedade do secret
# ════════════════════════════════════════════════════════════════
def calculate_entropy(s: str) -> float:
    """
    Calcula Shannon entropy de uma string.
    Maior entropy = mais aleatoriedade = mais provável de ser um secret real.
    
    Exemplos:
     - "aaaaaaaaaa" → 0.0
     - "example123" → ~2.8
     - "xK9$mP2&vQ" → ~4.2
    """
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def is_high_entropy(value: str, min_entropy: float = 3.5) -> bool:
    """Verifica se o secret tem entropia alta o suficiente para ser real."""
    if len(value) < 12:
        return False
    return calculate_entropy(value) >= min_entropy


# ════════════════════════════════════════════════════════════════
# PLACEHOLDER DETECTION — filtrar exemplos/testes
# ════════════════════════════════════════════════════════════════
PLACEHOLDER_WORDS = [
    "example", "test", "demo", "sample", "placeholder",
    "your-", "my-", "our-", "todo", "change-me", "replace",
    "xxx", "yyy", "zzz", "aaa", "bbb",
    "secret-here", "insert-", "add-your", "put-your",
    "12345", "abcde", "qwerty",
    "<change", "<replace", "<insert",
    "fakefakefake", "dummydummy",
]


def _has_repetitive_pattern(s: str) -> bool:
    """Detecta padrões repetitivos (aaaa, abcabc, 123123)."""
    if len(s) < 4:
        return False
    first_char = s[0]
    same_count = sum(1 for c in s if c == first_char)
    if same_count > len(s) * 2 / 3:
        return True
    for chunk_size in range(2, len(s) // 2 + 1):
        if len(s) % chunk_size == 0:
            chunk = s[:chunk_size]
            if chunk * (len(s) // chunk_size) == s:
                return True
    return False


def is_placeholder(value: str) -> bool:
    """Verifica se o valor é um placeholder/exemplo."""
    lower = value.lower()
    if any(p in lower for p in PLACEHOLDER_WORDS):
        return True
    if _has_repetitive_pattern(value):
        return True
    if "{{" in lower or "${" in lower or "<%" in lower:
        return True
    return False


def is_media_false_positive(content: str, position: int) -> bool:
    """Detecta se o contexto ao redor indica que o match é lixo de arquivo de mídia/binário."""
    start = max(0, position - 200)
    end = min(len(content), position + 200)
    nearby = content[start:end].lower()
    
    media_indicators = [
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.woff', '.ttf',
        'data:image', 'base64', 'favicon', 'icon', 'binary', 'octet-stream',
        'content-type: image', 'attachment; filename='
    ]
    
    if any(ind in nearby for ind in media_indicators):
        return True
    return False


# ════════════════════════════════════════════════════════════════
# CODE CONTEXT DETECTION — comentário, teste, exemplo, produção
# ════════════════════════════════════════════════════════════════
def _is_in_comment(content: str, position: int) -> bool:
    """Verifica se a posição está dentro de um comentário."""
    if position >= len(content):
        return False
    before = content[:position]
    line_start = before.rfind('\n')
    line_start = line_start + 1 if line_start != -1 else 0
    current_line = content[line_start:position].lstrip()
    if current_line.startswith("//") or current_line.startswith("#") or current_line.startswith("*"):
        return True
    last_open_block = before.rfind("/*")
    if last_open_block != -1:
        last_close_block = before.rfind("*/")
        if last_close_block < last_open_block:
            return True
    last_open_html = before.rfind("<!--")
    if last_open_html != -1:
        last_close_html = before.rfind("-->")
        if last_close_html < last_open_html:
            return True
    return False


TEST_INDICATORS = [
    "describe(", "it(", "test(", "expect(",
    "jest.mock", "sinon.stub", "chai.",
    "beforeEach", "afterEach", "beforeAll", "afterAll",
    "// Test", "// Example", "// Demo",
    "__tests__", ".test.js", ".spec.js",
    "mocha", "jasmine", "qunit", "vitest",
    "TestCase", "unittest", "pytest",
]

EXAMPLE_INDICATORS = [
    "example", "sample", "demo", "placeholder",
    "TODO:", "FIXME:", "NOTE:", "HACK:",
    "Replace with", "Change this", "Insert your",
    "your-", "my-", "our-",
    "documentation", "README",
]


def detect_code_context(content: str, position: int) -> str:
    """
    Classifica o contexto do match:
    - 'comment': dentro de comentário
    - 'test': código de teste
    - 'example': documentação/exemplo
    - 'production': código de produção (real)
    """
    if _is_in_comment(content, position):
        return "comment"
    start = max(0, position - 500)
    end = min(len(content), position + 100)
    nearby = content[start:end]
    if any(ind in nearby for ind in TEST_INDICATORS):
        return "test"
    if any(ind.lower() in nearby.lower() for ind in EXAMPLE_INDICATORS):
        return "example"
    return "production"


# ════════════════════════════════════════════════════════════════
# CONFIDENCE SCORING SYSTEM — pontuar confiança do finding
# ════════════════════════════════════════════════════════════════
CONFIDENCE_LEVELS = {
    "VERY_HIGH": 85,
    "HIGH": 70,
    "MEDIUM": 50,
    "LOW": 30,
    "VERY_LOW": 0,
}


def calculate_confidence(secret_value: str, key_type: str, content: str,
                           match_position: int, validated: bool = False) -> dict:
    """
    Sistema de pontuação de confiança (0-100) para um secret encontrado.

    Score = Entropy(30) + Context(30) + Format(20) + Validation(20) - Placeholder(-40)

    Returns:
        dict com total_score, level, breakdown, reasons
    """
    reasons = []
    
    # 1. ENTROPY SCORE (max 30 pontos)
    entropy = calculate_entropy(secret_value)
    if entropy >= 4.5:
        entropy_score = 30.0
        reasons.append(f"Entropia muito alta ({entropy:.2f})")
    elif entropy >= 4.0:
        entropy_score = 25.0
        reasons.append(f"Entropia alta ({entropy:.2f})")
    elif entropy >= 3.5:
        entropy_score = 18.0
        reasons.append(f"Entropia moderada ({entropy:.2f})")
    elif entropy >= 3.0:
        entropy_score = 10.0
        reasons.append(f"Entropia baixa ({entropy:.2f})")
    else:
        entropy_score = 0.0
        reasons.append(f"Entropia muito baixa ({entropy:.2f})")

    # 2. CONTEXT SCORE (max 30 pontos)
    context_type = detect_code_context(content, match_position)
    if context_type == "comment":
        context_score = 0.0
        reasons.append("Encontrado em comentário")
    elif context_type == "test":
        context_score = 8.0
        reasons.append("Encontrado em código de teste")
    elif context_type == "example":
        context_score = 0.0
        reasons.append("Encontrado em exemplo/documentação")
    else:
        context_score = 30.0
        reasons.append("Encontrado em código de produção")

    # 3. FORMAT SCORE (max 20 pontos)
    has_known_prefix = any(
        secret_value.startswith(p)
        for p in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
                   "sk_live_", "pk_live_", "rk_live_", "whsec_",
                   "AKIA", "vcel_", "vc_", "SG.", "xox",
                   "npm_", "pypi-", "NRAK-", "sntrys_", "key-",
                   "sq0atp-", "sq0csp-", "SK", "AC", "-----BEGIN"]
    )
    if has_known_prefix:
        format_score = 20.0
        reasons.append(f"Formato reconhecido ({key_type})")
    elif len(secret_value) >= 32:
        format_score = 10.0
        reasons.append("Chave longa (≥32 chars)")
    else:
        format_score = 5.0
        reasons.append("Formato genérico")

    # 4. PLACEHOLDER PENALTY (-40 pontos)
    if is_placeholder(secret_value):
        placeholder_penalty = -40.0
        reasons.append("⚠ Placeholder/exemplo detectado")
    else:
        placeholder_penalty = 0.0

    # 5. VALIDATION SCORE (max 20 pontos)
    if validated is True:
        validation_score = 20.0
        reasons.append("✓ Token validado com sucesso")
    elif validated is False:
        validation_score = 0.0
        reasons.append("✗ Token inválido/expirado")
    else:
        validation_score = 0.0

    total = max(0, min(100, entropy_score + context_score + format_score + placeholder_penalty + validation_score))

    if total >= 85:
        level = "VERY_HIGH"
    elif total >= 70:
        level = "HIGH"
    elif total >= 50:
        level = "MEDIUM"
    elif total >= 30:
        level = "LOW"
    else:
        level = "VERY_LOW"

    return {
        "total_score": round(total, 1),
        "level": level,
        "entropy": round(entropy, 2),
        "breakdown": {
            "entropy": round(entropy_score, 1),
            "context": round(context_score, 1),
            "format": round(format_score, 1),
            "placeholder_penalty": round(placeholder_penalty, 1),
            "validation": round(validation_score, 1),
        },
        "context_type": context_type,
        "is_placeholder": placeholder_penalty < 0,
        "reasons": reasons,
    }


# ════════════════════════════════════════════════════════════════
# CONTEXT & USAGE ANALYSIS — extrair contexto e uso
# ════════════════════════════════════════════════════════════════
def get_context_lines(content: str, match_start: int, context_size: int = 5) -> dict:
    """Retorna linhas de contexto ao redor do match."""
    lines = content.splitlines()
    chars_counted = 0
    line_idx = 0
    for i, line in enumerate(lines):
        chars_counted += len(line) + 1
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
        "full_context": "\n".join(context_lines),
    }


def analyze_key_usage(content: str, match_start: int, key_type: str) -> dict:
    """Analisa como a key está sendo usada no código."""
    lines = content.splitlines()
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
        "possible_hardcoded": False,
    }

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

    if "const " in current_line or "final " in current_line:
        usage_info["assignment_type"] = "constant"
    elif "let " in current_line or "var " in current_line:
        usage_info["assignment_type"] = "variable"
    elif "process.env" in current_line or "os.environ" in current_line:
        usage_info["assignment_type"] = "environment"
    else:
        usage_info["assignment_type"] = "unknown"

    env_indicators = ["process.env", "os.environ", "getenv", "ENV[", "${"]
    if not any(ind in current_line for ind in env_indicators):
        usage_info["possible_hardcoded"] = True

    return usage_info


# ════════════════════════════════════════════════════════════════
# MAIN EXTRACTION — função principal
# ════════════════════════════════════════════════════════════════
def extract_keys(content: str, source_url: str = None, source_file: str = None) -> list:
    """
    Scans content for secrets and returns a list of found items with
    full context, usage analysis, validation, and confidence scoring.
    """
    from .token_validator import validate_token

    found = []
    seen_values = set()

    for key_type, pattern in REGEX_PATTERNS.items():
        try:
            matches = list(re.finditer(pattern, content))
        except re.error:
            continue

        for m in matches:
            match_str = m.group(0)

            # Deduplicate
            if match_str in seen_values:
                continue
            
            # Rigorous validation: check if it's a media/binary false positive
            if is_media_false_positive(content, m.start()):
                continue

            seen_values.add(match_str)

            # Context
            ctx = get_context_lines(content, m.start())

            # Usage analysis
            usage = analyze_key_usage(content, m.start(), key_type)

            # Key info
            key_info = KEY_INFO.get(key_type, {
                "service": "Unknown",
                "risk": "UNKNOWN",
                "usage": "Verifique manualmente",
                "docs": "N/A",
            })

            # Validate token against API
            validation = validate_token(key_type, match_str)

            # Confidence scoring
            confidence = calculate_confidence(
                secret_value=match_str,
                key_type=key_type,
                content=content,
                match_position=m.start(),
                validated=validation.get("validated"),
            )

            found.append({
                "type": key_type,
                "match": match_str[:100] + "..." if len(match_str) > 100 else match_str,
                "full_match": match_str,
                "source": {
                    "url": source_url,
                    "file": source_file,
                    "line": ctx["line_number"],
                },
                "context": {
                    "lines": ctx["lines"],
                    "full": ctx["full_context"],
                    "start_line": ctx["start_line"],
                    "end_line": ctx["end_line"],
                },
                "usage": usage,
                "info": key_info,
                "validated": validation.get("validated"),
                "validation_info": validation.get("validation_info", ""),
                "validation_type": validation.get("validation_type", "not_supported"),
                "confidence": confidence,
            })

    # Sort by confidence score descending
    found.sort(key=lambda x: x["confidence"]["total_score"], reverse=True)

    return found


def extract_keys_to_json(content: str, source_url: str = None, source_file: str = None) -> str:
    """Extrai keys e retorna como JSON formatado."""
    keys = extract_keys(content, source_url, source_file)
    return json.dumps(keys, indent=2, ensure_ascii=False)


def format_key_report(key: dict) -> str:
    """Formata uma key encontrada para output texto."""
    conf = key.get("confidence", {})
    lines = [
        f"{'=' * 60}",
        f"TYPE: {key['type']}",
        f"RISK: {key['info'].get('risk', 'UNKNOWN')}",
        f"SERVICE: {key['info'].get('service', 'Unknown')}",
        f"CONFIDENCE: {conf.get('total_score', '?')}/100 ({conf.get('level', '?')})",
        f"ENTROPY: {conf.get('entropy', '?')}",
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
        f"CONTEXT TYPE: {conf.get('context_type', 'unknown')}",
        f"PLACEHOLDER: {'YES ⚠' if conf.get('is_placeholder') else 'No'}",
        f"",
        f"CONTEXT:",
    ]

    for line in key["context"].get("lines", []):
        lines.append(f"  {line}")

    lines.append(f"")
    lines.append(f"USAGE INFO: {key['info'].get('usage', 'N/A')}")
    lines.append(f"DOCS: {key['info'].get('docs', 'N/A')}")

    if conf.get("reasons"):
        lines.append(f"")
        lines.append(f"SCORING REASONS:")
        for reason in conf["reasons"]:
            lines.append(f"  • {reason}")

    lines.append(f"{'=' * 60}")
    lines.append("")

    return "\n".join(lines)
