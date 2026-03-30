import re
import json
import hashlib
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from collections import defaultdict
from typing import List, Dict, Any

from menu import C
from plugins import ensure_outdir
from ..output import info, warn, success, error

# ====================================================================
# CONFIGS & RULES
# ====================================================================

# Rule sets for URL Classification
ClassificationRules = {
    "LOGIN": r"(?i)(/login|/signin|/auth|/oauth|/sso|/logon)",
    "API": r"(?i)(/api/|/graphql|/v[0-9]+/|/rest)",
    "ADMIN": r"(?i)(/admin|/administrator|/manage|/dashboard|/panel|/wp-admin)",
    "UPLOAD": r"(?i)(/upload|/import|/media|/file|/attachment)",
    "DEBUG": r"(?i)(/debug|/test|/dev|/trace|/console|phpinfo)",
    "DOCS": r"(?i)(/swagger|/docs|/openapi|/api-docs)"
}

# Rule sets for Vulnerability Pattern Detection
VulnPatterns = {
    "LFI_RFI": {
        "params": ["file", "path", "dir", "document", "folder", "root", "pg", "style", "pdf", "template", "include", "page", "read", "cat", "doc", "filename"],
        "name": "Local/Remote File Inclusion",
        "risk": "HIGH"
    },
    "SQLI_IDOR": {
        "params": ["id", "user", "account", "number", "order", "query", "search", "q", "pwd", "email", "user_id", "uid", "pid", "item", "no"],
        "name": "SQLi / IDOR",
        "risk": "HIGH"
    },
    "SSRF": {
        "params": ["url", "uri", "src", "source", "dest", "redirect", "next", "target", "rurl", "return", "callback", "webhook", "proxy", "fetch"],
        "name": "SSRF / Open Redirect",
        "risk": "HIGH"
    },
    "RCE": {
        "params": ["cmd", "exec", "command", "execute", "ping", "process", "run", "daemon", "upload"],
        "name": "Remote Code Execution",
        "risk": "CRITICAL"
    },
    "XSS": {
        "params": ["q", "search", "keyword", "query", "name", "title", "content", "body", "message", "comment", "text", "value", "input", "data"],
        "name": "Cross-Site Scripting",
        "risk": "MEDIUM"
    }
}

# Attack Priority Weights
ATTACK_WEIGHTS = {
    "login_page": 3,
    "admin_panel": 5,
    "graphql_endpoint": 6,
    "swagger_exposed": 5,
    "jwt_detected": 4,
    "api_endpoint": 3,
    "upload_endpoint": 6,
    "internal_hostname": 4,
    "dev_staging_env": 4,
    "js_secrets": 5,
    "cors_credentials": 4,
    "git_exposed": 6,
    "takeover_vulnerable": 7,
    "open_admin_no_auth": 8,
    "crlf_vulnerable": 5,
    "cache_deception_vulnerable": 7,
    "insecure_headers": 2,
    "deserialization_vulnerable": 8,
}

# Patterns to detect dev/staging/internal hosts
DEV_STAGING_PATTERNS = re.compile(
    r"(?i)(dev\.|staging\.|stage\.|test\.|qa\.|uat\.|sandbox\.|demo\.|internal\.|"
    r"pre-prod\.|preprod\.|beta\.|alpha\.|local\.)", re.I
)

INTERNAL_HOSTNAME_PATTERNS = re.compile(
    r"(?i)(intranet\.|vpn\.|corp\.|private\.|backoffice\.|management\.|"
    r"sysadmin\.|monitoring\.|grafana\.|kibana\.|jenkins\.|gitlab\.|"
    r"portainer\.|zabbix\.|nagios\.|prometheus\.)", re.I
)

# IDOR/Privilege Escalation parameter patterns
IDOR_PARAMS = {"role", "admin", "user_id", "uid", "account_id", "is_admin", "privilege", "permission", "group", "level", "access"}

# Upload-related path patterns
UPLOAD_PATTERNS = re.compile(r"(?i)(/upload|/import|/attach|/file|/media|/image|/asset|/document)", re.I)

# Knowledge Base — Expanded with real payloads and categories
KnowledgeBase = {
    "Spring Boot": [
        {"tip": "Busque por actuators expostos", "payload": "GET /actuator/env\nGET /actuator/heapdump\nGET /actuator/mappings\nGET /actuator/configprops\nGET /actuator/beans", "category": "config_leak"},
        {"tip": "Teste Spring4Shell (CVE-2022-22965)", "payload": "class.module.classLoader.URLs%5B0%5D=0", "category": "rce"},
        {"tip": "Whitelabel Error Page pode expor stack traces", "payload": "GET /error", "category": "info_disclosure"},
    ],
    "Cloudflare": [
        {"tip": "Bypasse o WAF encontrando o IP de origem", "payload": "Ferramentas: Censys, Shodan, SecurityTrails\nBuscar por headers como X-Forwarded-For no histórico DNS", "category": "waf_bypass"},
        {"tip": "Web Cache Poisoning via headers", "payload": "X-Forwarded-Host: attacker.com\nX-Original-URL: /admin", "category": "cache_poison"},
    ],
    "Amazon S3": [
        {"tip": "Teste se o bucket permite leitura/escrita anônima", "payload": "aws s3 ls s3://BUCKET_NAME --no-sign-request\naws s3 cp test.txt s3://BUCKET_NAME --no-sign-request", "category": "misconfiguration"},
        {"tip": "Verifique subdomain takeover se retornar 404", "payload": "Registre o bucket com o mesmo nome no S3", "category": "takeover"},
    ],
    "GraphQL": [
        {"tip": "Execute query de introspecção completa", "payload": "query IntrospectionQuery {\n  __schema {\n    queryType { name }\n    mutationType { name }\n    types {\n      name\n      fields { name args { name type { name } } }\n    }\n  }\n}", "category": "introspection"},
        {"tip": "Teste ataque de batch query para bypass Rate Limiting", "payload": "[{\"query\":\"{ user(id:1) { email } }\"},{\"query\":\"{ user(id:2) { email } }\"}]", "category": "abuse"},
        {"tip": "Teste IDORs em queries/mutations customizadas", "payload": "mutation { updateUser(id: OTHER_USER_ID, role: \"admin\") { id } }", "category": "idor"},
        {"tip": "Field Suggestions para enumerar campos", "payload": "{ __type(name: \"User\") { fields { name type { name } } } }", "category": "enum"},
    ],
    "Swagger": [
        {"tip": "Buscar documentação de API exposta", "payload": "GET /swagger/v1/swagger.json\nGET /swagger.json\nGET /api-docs\nGET /openapi.json\nGET /v2/api-docs\nGET /v3/api-docs\nGET /swagger-resources", "category": "api_docs"},
        {"tip": "Testar endpoints administrativos sem autenticação", "payload": "Buscar endpoints com /admin/, /users/, /delete/, /create/ na spec", "category": "broken_access"},
    ],
    "JWT": [
        {"tip": "Teste alg:none bypass", "payload": "Trocar header para {\"alg\":\"none\"} e remover assinatura\nToken: eyJhbGciOiJub25lIn0.PAYLOAD.", "category": "auth_bypass"},
        {"tip": "Teste JWT Confusion (RS256→HS256)", "payload": "Trocar algoritmo de RS256 para HS256 e assinar com a chave pública", "category": "auth_bypass"},
        {"tip": "Teste kid injection", "payload": "kid: ../../dev/null\nkid: ' UNION SELECT 'secret' --", "category": "injection"},
        {"tip": "Teste jku/x5u header injection", "payload": "Apontar jku/x5u para servidor atacante com JWKS próprio", "category": "auth_bypass"},
    ],
    "WordPress": [
        {"tip": "Enumere usuários via REST API", "payload": "GET /wp-json/wp/v2/users\nGET /?author=1", "category": "user_enum"},
        {"tip": "Escaneie plugins vulneráveis", "payload": "wpscan --url TARGET --enumerate p,t,u\nGET /wp-content/plugins/", "category": "vuln_scan"},
        {"tip": "XML-RPC para brute-force", "payload": "POST /xmlrpc.php\n<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>password</value></param></params></methodCall>", "category": "brute_force"},
    ],
    "PHP": [
        {"tip": "Procure por phpinfo() exposto", "payload": "GET /phpinfo.php\nGET /info.php\nGET /php_info.php\nGET /test.php", "category": "info_disclosure"},
        {"tip": "Type Juggling em comparações", "payload": "password=0 (quando comparado com == em vez de ===)\npassword[]='' (Array bypass)", "category": "auth_bypass"},
    ],
    "React": [
        {"tip": "Verifique Source Maps por secrets expostos", "payload": "GET /static/js/main.js.map\nBuscar por: apiKey, secret, token, password", "category": "secret_leak"},
        {"tip": "XSS via dangerouslySetInnerHTML", "payload": "Injetar em campos que usam dangerouslySetInnerHTML", "category": "xss"},
    ],
    "Firebase": [
        {"tip": "Verifique DB aberto para leitura/escrita", "payload": "GET https://PROJECT-ID.firebaseio.com/.json\nPUT https://PROJECT-ID.firebaseio.com/test.json -d '{\"exploit\":true}'", "category": "misconfiguration"},
        {"tip": "Extraia configuração do Firebase dos bundles JS", "payload": "Buscar por: apiKey, authDomain, projectId, storageBucket", "category": "secret_leak"},
    ],
    "Upload": [
        {"tip": "Teste upload de extensões perigosas", "payload": "Extensões: .php, .php5, .phtml, .asp, .aspx, .jsp\nBypass: .php.jpg, .php%00.jpg, .pHp\nContent-Type: image/jpeg (com conteúdo PHP)", "category": "rce"},
        {"tip": "Stored XSS via SVG upload", "payload": "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\"/>", "category": "xss"},
        {"tip": "Path Traversal no filename", "payload": "filename=\"../../../etc/passwd\"\nfilename=\"..\\..\\..\\windows\\win.ini\"", "category": "lfi"},
    ],
    "CORS": [
        {"tip": "Teste CORS com credenciais + wildcard", "payload": "Origin: https://attacker.com\nVerificar: Access-Control-Allow-Credentials: true\nCom: Access-Control-Allow-Origin: *", "category": "cors_bypass"},
        {"tip": "Teste origin reflection", "payload": "Origin: https://evil.com\nVerificar se o valor é refletido no ACAO header", "category": "cors_bypass"},
    ],
    "Node.js": [
        {"tip": "Prototype Pollution", "payload": "__proto__[isAdmin]=true\nconstructor.prototype.isAdmin=true", "category": "injection"},
        {"tip": "SSRF via request libraries", "payload": "url=http://169.254.169.254/latest/meta-data/", "category": "ssrf"},
    ],
    "Nginx": [
        {"tip": "Teste path traversal via alias misconfiguration", "payload": "GET /assets../etc/passwd\nGET /static../app/config.py", "category": "lfi"},
        {"tip": "Off-by-slash", "payload": "location /api { proxy_pass http://backend; }\nGET /api../internal/", "category": "access_bypass"},
    ],
    "Apache": [
        {"tip": "Teste .htaccess bypass e mod_status", "payload": "GET /server-status\nGET /.htaccess\nGET /server-info", "category": "info_disclosure"},
    ],
    "Flask": [
        {"tip": "SSTI (Server-Side Template Injection) via Jinja2", "payload": "{{7*7}}\n{{config.items()}}", "category": "rce"},
        {"tip": "Session Forging", "payload": "Se a secret_key for vazada, forje o cookie de sessão via flask-unsign", "category": "auth_bypass"},
    ],
    "Django": [
        {"tip": "Django Debug Mode Enabled", "payload": "Forçar um erro 404/500 acesse rota inválida para obter config settings completas", "category": "info_disclosure"},
        {"tip": "Django Admin URL Discovery", "payload": "GET /admin/\nGET /django-admin/", "category": "admin_panel"},
    ],
    "Laravel": [
        {"tip": "Laravel Debug Mode (Ignition/Whoops)", "payload": "Gere uma exception para expor environment variables (APP_KEY, DB_PASSWORD)", "category": "info_disclosure"},
        {"tip": "CVE-2021-3129 Ignition RCE", "payload": "Explorar o log file clearing via phar:// deserialization", "category": "rce"},
    ],
    "Ruby on Rails": [
        {"tip": "Secret Token Leak", "payload": "Buscar secret_key_base exposta e testar RCE via Cookie Deserialization (CVE-2015-3226)", "category": "rce"},
        {"tip": "Rails Mass Assignment", "payload": "Testar parâmetros como user[admin]=1", "category": "privesc"},
    ],
    "Express": [
        {"tip": "Express Body-Parser Pollution", "payload": "Passar arrays `user[]=admin` em vez de strings", "category": "injection"},
    ],
    "Next.js": [
        {"tip": "Next.js Pre-rendering data leak", "payload": "Inspecionar arquivos _next/data/**/*.json em busca de credenciais embutidas do getStaticProps", "category": "info_disclosure"},
    ],
    "Vue.js": [
        {"tip": "SSTI/Vue Template Injection", "payload": "{{_vue.constructor.super.options.template}}", "category": "xss"},
    ],
    "Angular": [
        {"tip": "AngularJS Template Injection", "payload": "{{constructor.constructor('alert(1)')()}}", "category": "xss"},
    ],
    "Tomcat": [
        {"tip": "Tomcat Manager Default Creds", "payload": "GET /manager/html\ntomcat:tomcat\nboth:tomcat", "category": "bruteforce"},
        {"tip": "RCE via WAR Upload", "payload": "Se autenticado no manager, suba uma webshell em formato .war", "category": "rce"},
    ],
    "IIS": [
        {"tip": "IIS Short Name Enumeration", "payload": "GET /~1****.ext/ - enumere o path para descobrir secrets", "category": "enum"},
        {"tip": "Execute ASP/ASPX via path confusion", "payload": "test.aspx;.jpg", "category": "rce"},
    ],
    "Docker": [
        {"tip": "Docker API Socket Aberto", "payload": "GET /v1.24/containers/json HTTP/1.1", "category": "rce"},
        {"tip": "Privilege Escalation em containers", "payload": "Procurar capabilities '--privileged' para realizar escape pro host", "category": "privesc"},
    ],
    "Kubernetes": [
        {"tip": "Kubelet API Aberta", "payload": "GET /pods - Sem autenticação na porta 10250", "category": "rce"},
        {"tip": "Extração de Service Account Tokens", "payload": "Ler /var/run/secrets/kubernetes.io/serviceaccount/token", "category": "privesc"},
    ],
    "Redis": [
        {"tip": "Redis sem Autenticação", "payload": "redis-cli -h TARGET - port 6379\nCONFIG SET dir /root/.ssh\nCONFIG SET dbfilename authorized_keys", "category": "rce"},
    ],
    "Elasticsearch": [
        {"tip": "Cluster Aberto (sem auth)", "payload": "GET /_cat/indices\nGET /_search\nGET /_cluster/health", "category": "info_disclosure"},
    ],
    "MongoDB": [
        {"tip": "NoSQL Injection via JSON Params", "payload": "POST {\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}", "category": "auth_bypass"},
    ],
}



# ====================================================================
# ENGINE CLASS
# ====================================================================

class IntelligenceEngine:
    def __init__(self, target: str):
        self.target = target
        self.base_dir = Path("output") / target
        self.outdir = self.base_dir / "intelligence"
        self.outdir.mkdir(parents=True, exist_ok=True)
        
        # Load Raw Data
        self.urls = self._load_urls()
        self.technologies = self._load_technologies()
        self.js_files = self._load_json("domain/extracted_js_routes.json")
        if not self.js_files:
            self.js_files = self._load_json("jsscanner/js_routes.json")
        
        # Load cross-reference data
        self.admin_panels = self._load_json("admin/admin_panels.json") or []
        self.swagger_docs = self._load_json("domain/swagger_docs.json") or []
        self.graphql_data = self._load_json("scanners/graphql.json") or []
        self.jwt_data = self._load_json("jwt_analyzer/jwt_results.json") or []
        self.keys_data = self._load_json("domain/extracted_keys.json") or []
        self.cors_data = self._load_json("cors/cors_results.json") or []
        self.takeover_data = self._load_json("takeover/takeover_results.json") or []
        self.js_routes = self._load_json("jsscanner/js_routes.json") or []
        self.params_data = self._load_json("domain/katana_params_all.json") or {}
        self.endpoints_data = self._load_json("endpoint/raw_endpoints.json") or []
        self.extracted_routes = self._load_json("domain/extracted_routes.json") or []
        self.crlf_data = self._load_json("crlf_injection/crlf_results.json") or []
        self.cache_deception_data = self._load_json("cache_deception/cache_deception_results.json") or []
        self.headers_data = self._load_json("headers/headers_results.json") or []
        self.deserialization_data = self._load_json("insecure_deserialization/deserialization_results.json") or []
        
        # Load subdomains
        subs_file = self.base_dir / "domain" / "subdomains.txt"
        self.subdomains = []
        if subs_file.exists():
            self.subdomains = [l.strip() for l in subs_file.read_text().splitlines() if l.strip()]
        
        # Output artifacts
        self.classified_urls = []
        self.vuln_patterns = []
        self.risk_ranking = defaultdict(lambda: {"score": 0.0, "reasons": [], "tags": set()})
        self.knowledge_tips = {}

    def _load_urls(self) -> List[str]:
        f = self.base_dir / "urls" / "urls_valid.txt"
        if f.exists():
            return [line.strip() for line in f.read_text().splitlines() if line.strip()]
        return []
        
    def _load_technologies(self) -> Dict:
        f = self.base_dir / "domain" / "technologies.json"
        if f.exists():
            try: return json.loads(f.read_text())
            except: pass
        return {}

    def _load_json(self, relative_path: str) -> Any:
        f = self.base_dir / relative_path
        if f.exists():
            try: return json.loads(f.read_text())
            except: pass
        return []

    # ================================================================
    # FEATURE 1: Attack Priority Engine
    # ================================================================
    def calculate_attack_priority(self):
        """Calculate attack priority score per subdomain using weighted factors."""
        
        priority_data = defaultdict(lambda: {"score": 0, "factors": [], "tags": []})
        
        # Login pages from URL classification
        for url in self.urls:
            subdomain = urlparse(url).netloc
            url_lower = url.lower()
            
            if re.search(r"(?i)(/login|/signin|/auth|/sso)", url_lower):
                priority_data[subdomain]["score"] += ATTACK_WEIGHTS["login_page"]
                priority_data[subdomain]["factors"].append("Login Page detected")
                priority_data[subdomain]["tags"].append("LOGIN")
            
            if UPLOAD_PATTERNS.search(url_lower):
                priority_data[subdomain]["score"] += ATTACK_WEIGHTS["upload_endpoint"]
                priority_data[subdomain]["factors"].append(f"Upload endpoint: {urlparse(url).path}")
                priority_data[subdomain]["tags"].append("UPLOAD")
            
            if re.search(r"(?i)(/api/|/v[0-9]+/|/rest/)", url_lower):
                if "API" not in priority_data[subdomain]["tags"]:
                    priority_data[subdomain]["score"] += ATTACK_WEIGHTS["api_endpoint"]
                    priority_data[subdomain]["factors"].append("API endpoint detected")
                    priority_data[subdomain]["tags"].append("API")
        
        # Admin panels
        for panel in self.admin_panels:
            host = urlparse(panel.get("url", "")).netloc
            if panel.get("status") == 200 and not panel.get("has_login_form"):
                priority_data[host]["score"] += ATTACK_WEIGHTS["open_admin_no_auth"]
                priority_data[host]["factors"].append(f"Open Admin Panel (no auth!): {panel.get('url')}")
                priority_data[host]["tags"].append("ADMIN_OPEN")
            elif panel.get("status") in (200, 401, 403):
                priority_data[host]["score"] += ATTACK_WEIGHTS["admin_panel"]
                priority_data[host]["factors"].append(f"Admin Panel: {panel.get('url')}")
                priority_data[host]["tags"].append("ADMIN")
        
        # GraphQL endpoints
        for gql in self.graphql_data:
            host = urlparse(gql.get("url", "")).netloc
            priority_data[host]["score"] += ATTACK_WEIGHTS["graphql_endpoint"]
            introspection = " (Introspection Enabled!)" if gql.get("introspection") else ""
            priority_data[host]["factors"].append(f"GraphQL endpoint{introspection}")
            priority_data[host]["tags"].append("GRAPHQL")
        
        # Swagger
        for swagger in self.swagger_docs:
            url = swagger if isinstance(swagger, str) else swagger.get("url", "")
            host = urlparse(url).netloc
            if host:
                priority_data[host]["score"] += ATTACK_WEIGHTS["swagger_exposed"]
                priority_data[host]["factors"].append(f"Swagger exposed: {url}")
                priority_data[host]["tags"].append("SWAGGER")
        
        # JWT
        for jwt in self.jwt_data:
            host = urlparse(jwt.get("url", "")).netloc
            priority_data[host]["score"] += ATTACK_WEIGHTS["jwt_detected"]
            alg = jwt.get("algorithm", "unknown")
            priority_data[host]["factors"].append(f"JWT detected (alg: {alg})")
            priority_data[host]["tags"].append("JWT")
        
        # JS Secrets
        for key in self.keys_data:
            if not isinstance(key, dict):
                continue
            src = key.get("source", {})
            if isinstance(src, dict):
                host = src.get("url", "")
                host = urlparse(host).netloc if host else ""
            else:
                host = urlparse(str(src)).netloc if src else ""
            if not host:
                host = key.get("subdomain", "")
            if host:
                priority_data[host]["score"] += ATTACK_WEIGHTS["js_secrets"]
                priority_data[host]["factors"].append(f"Secret/Key in JS: {key.get('type', 'unknown')}")
                priority_data[host]["tags"].append("JS_SECRET")
        
        # Dev/Staging environments
        for sub in self.subdomains:
            if DEV_STAGING_PATTERNS.search(sub):
                priority_data[sub]["score"] += ATTACK_WEIGHTS["dev_staging_env"]
                priority_data[sub]["factors"].append("Dev/Staging environment")
                priority_data[sub]["tags"].append("DEV_STAGING")
            
            if INTERNAL_HOSTNAME_PATTERNS.search(sub):
                priority_data[sub]["score"] += ATTACK_WEIGHTS["internal_hostname"]
                priority_data[sub]["factors"].append("Internal/Management hostname")
                priority_data[sub]["tags"].append("INTERNAL")
        
        # CORS with credentials
        for cors in self.cors_data:
            host = urlparse(cors.get("url", "")).netloc
            if cors.get("credentials") or "credentials" in str(cors.get("issue", "")).lower():
                priority_data[host]["score"] += ATTACK_WEIGHTS["cors_credentials"]
                priority_data[host]["factors"].append("CORS with credentials")
                priority_data[host]["tags"].append("CORS_CREDS")
        
        # Takeover
        for tk in self.takeover_data:
            sub = tk.get("subdomain", "")
            if tk.get("status") == "VULNERABLE":
                priority_data[sub]["score"] += ATTACK_WEIGHTS["takeover_vulnerable"]
                priority_data[sub]["factors"].append(f"Subdomain Takeover CONFIRMED ({tk.get('service')})")
                priority_data[sub]["tags"].append("TAKEOVER")
                
        # CRLF Injection
        for crlf in self.crlf_data:
            host = urlparse(crlf.get("url", "")).netloc
            priority_data[host]["score"] += ATTACK_WEIGHTS["crlf_vulnerable"]
            priority_data[host]["factors"].append(f"CRLF Injection Susceptible")
            priority_data[host]["tags"].append("CRLF")

        # Cache Deception
        for cache in self.cache_deception_data:
            if cache.get("vulnerable"):
                host = urlparse(cache.get("url", "")).netloc
                priority_data[host]["score"] += ATTACK_WEIGHTS["cache_deception_vulnerable"]
                priority_data[host]["factors"].append(f"Web Cache Deception Vulnerable: {cache.get('url')}")
                priority_data[host]["tags"].append("CACHE_DECEPTION")

        # Insecure Headers
        for h in self.headers_data:
            host = urlparse(h.get("url", "")).netloc
            if h.get("issues"):
                priority_data[host]["score"] += ATTACK_WEIGHTS["insecure_headers"]
                priority_data[host]["factors"].append(f"Missing security headers detected")
                priority_data[host]["tags"].append("HEADERS")

        # Insecure Deserialization
        for deser in self.deserialization_data:
            host = urlparse(deser.get("url", "")).netloc
            priority_data[host]["score"] += ATTACK_WEIGHTS["deserialization_vulnerable"]
            priority_data[host]["factors"].append(f"Insecure Deserialization Susceptible: {deser.get('payload_type')}")
            priority_data[host]["tags"].append("DESERIALIZATION")
        
        # Build final sorted list
        result = []
        for subdomain, data in priority_data.items():
            if not subdomain:
                continue
                
            # SINCRONIZAÇÃO: Mesclar Priority Metrics com Risk Ranking
            # Isso impede que os pontuações divirgam no Painel de Admin
            self.risk_ranking[subdomain]["score"] += data["score"]
            self.risk_ranking[subdomain]["reasons"].extend(data["factors"])
            for t in data["tags"]: self.risk_ranking[subdomain]["tags"].add(t)
            
            # Rebalancear Priority para que reflita o Risk Ranking unificado
            unified_score = min(self.risk_ranking[subdomain]["score"], 10.0)
            
            result.append({
                "subdomain": subdomain,
                "score": round(unified_score, 1),
                "factors": list(set(data["factors"])),
                "tags": list(set(data["tags"]))
            })
        
        result.sort(key=lambda x: x["score"], reverse=True)
        
        with open(self.outdir / "attack_priority.json", "w") as f:
            json.dump(result, f, indent=2)
        
        return result

    # ================================================================
    # FEATURE 5: Quick Wins
    # ================================================================
    def detect_quick_wins(self):
        """Identify high-impact, low-effort findings."""
        quick_wins = []
        
        # CORS with credentials
        for cors in self.cors_data:
            issue = str(cors.get("issue", "")).lower()
            if "credentials" in issue or cors.get("credentials"):
                quick_wins.append({
                    "type": "CORS with Credentials",
                    "severity": "HIGH",
                    "url": cors.get("url", ""),
                    "detail": cors.get("issue", ""),
                    "action": "Teste com Origin: https://attacker.com — pode roubar dados autenticados",
                    "icon": "🎯"
                })
        
        # Admin panels without auth (status 200, no login form)
        for panel in self.admin_panels:
            if panel.get("status") == 200 and not panel.get("has_login_form"):
                quick_wins.append({
                    "type": "Admin Panel Aberto (Sem Auth Detectado)",
                    "severity": "HIGH",
                    "url": panel.get("url", ""),
                    "detail": f"Painel exposto: {panel.get('title', 'N/A')}",
                    "action": "Acesse e verifique se permite operações administrativas sem login.",
                    "icon": "👑"
                })
        
        # Confirmed takeovers
        for tk in self.takeover_data:
            if tk.get("status") == "VULNERABLE":
                quick_wins.append({
                    "type": "Subdomain Takeover Confirmado",
                    "severity": "CRITICAL",
                    "url": tk.get("subdomain", ""),
                    "detail": f"CNAME: {tk.get('cname', '')} → {tk.get('service', '')}",
                    "action": f"Registre o serviço {tk.get('service', '')} para assumir o subdomínio",
                    "icon": "🏴‍☠️"
                })
        
        # Git exposed
        for panel in self.admin_panels:
            url_str = panel.get("url", "")
            status = panel.get("status")
            
            # Repositório Base Exposto
            if "/.git/" in url_str and status == 200:
                quick_wins.append({
                    "type": "Git Repository Exposto",
                    "severity": "CRITICAL",
                    "url": url_str,
                    "detail": "Repositório Git acessível (200 OK)",
                    "action": "Use git-dumper para extrair código-fonte completo (já deve ter sido disparado no módulo Enum-Admin)",
                    "icon": "🕰️"
                })
                
            # Extração Ativa do GitLeaks
            if panel.get("cms") == "GitLeaks Exfiltration":
                quick_wins.append({
                    "type": "GitLeaks: Secret Hackeada",
                    "severity": "CRITICAL",
                    "url": url_str,
                    "detail": panel.get("title", "Key"),
                    "action": f"Secret/Chave Vazada Diretamente no Commit! Valor/Hash: {panel.get('content_hash', '')[:20]}...",
                    "icon": "🩸"
                })
        
        # Secrets in JS
        for key in self.keys_data:
            if not isinstance(key, dict):
                continue
            key_type = key.get("type", "").lower()
            if any(kw in key_type for kw in ["aws", "api_key", "secret", "token", "password", "private"]):
                src = key.get("source", {})
                if isinstance(src, dict):
                    src_url = src.get("url", "")
                else:
                    src_url = str(src) if src else ""
                if not src_url:
                    src_url = key.get("subdomain", "")
                quick_wins.append({
                    "type": "Secret Exposto em JavaScript",
                    "severity": "HIGH",
                    "url": src_url,
                    "detail": f"Tipo: {key.get('type', 'unknown')} — Value: {str(key.get('match', key.get('value', '')))[:30]}...",
                    "action": "Valide se a chave/token ainda está ativa e pode ser abusada",
                    "icon": "🔑"
                })
        
        # GraphQL with introspection
        for gql in self.graphql_data:
            if gql.get("introspection"):
                quick_wins.append({
                    "type": "GraphQL Introspection Habilitada",
                    "severity": "HIGH",
                    "url": gql.get("url", ""),
                    "detail": "Schema completo pode ser extraído",
                    "action": "Execute introspection query para mapear toda a API",
                    "icon": "🧬"
                })
                
        # CRLF Injection
        for crlf in self.crlf_data:
            quick_wins.append({
                "type": "CRLF Injection (Header Splitting)",
                "severity": "MEDIUM",
                "url": crlf.get("url", ""),
                "detail": f"Injeção bem sucedida: {crlf.get('payload', '')}",
                "action": "Teste de escalonamento para XSS ou Cache Poisoning",
                "icon": "🎭"
            })
            
        # Cache Deception
        for cache in self.cache_deception_data:
            if cache.get("vulnerable"):
                quick_wins.append({
                    "type": "Web Cache Deception",
                    "severity": "HIGH",
                    "url": cache.get("url", ""),
                    "detail": "Resposta dinâmica sendo indexada em cache CDN",
                    "action": "Verifique vazamento de informações de sessão em navegação real",
                    "icon": "👻"
                })
                
        # Insecure Deserialization
        for deser in self.deserialization_data:
            quick_wins.append({
                "type": "Insecure Deserialization Potencial",
                "severity": "CRITICAL",
                "url": deser.get("url", ""),
                "detail": f"Anomalia detectada com objeto: {deser.get('payload_type', '')}",
                "action": "Escalone para Execução de Comandos (RCE) via ysoserial, etc",
                "icon": "💣"
            })
        
        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        quick_wins.sort(key=lambda x: severity_order.get(x.get("severity", "LOW"), 3))
        
        with open(self.outdir / "quick_wins.json", "w") as f:
            json.dump(quick_wins, f, indent=2)
        
        return quick_wins

    # ================================================================
    # Original methods (updated)
    # ================================================================
    def classify_urls(self):
        """Analyzes all URLs and assigns tags (LOGIN, API, etc.)"""
        for url in self.urls:
            tags = []
            for tag_name, regex in ClassificationRules.items():
                if re.search(regex, url):
                    tags.append(tag_name)
                    
            if tags:
                self.classified_urls.append({
                    "url": url,
                    "tags": tags
                })
                
                subdomain = urlparse(url).netloc
                for tag in tags:
                    self.risk_ranking[subdomain]["tags"].add(tag)
                    if tag == "ADMIN":
                        self.risk_ranking[subdomain]["score"] += 3.0
                        self.risk_ranking[subdomain]["reasons"].append("Exposed Admin Panel/Path")
                    elif tag == "API" or tag == "DEBUG":
                        self.risk_ranking[subdomain]["score"] += 1.5
                    elif tag == "LOGIN":
                        self.risk_ranking[subdomain]["score"] += 1.0

    def detect_vulnerabilities(self):
        """Detect risk patterns based on URL parameters"""
        for url in self.urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query).keys()
            
            if not params:
                 continue
                 
            for vuln_key, vuln_info in VulnPatterns.items():
                 matched_params = [p for p in params if p.lower() in vuln_info["params"]]
                 if matched_params:
                      self.vuln_patterns.append({
                           "url": url,
                           "vulnerability": vuln_info["name"],
                           "risk_level": vuln_info["risk"],
                           "matched_parameters": matched_params
                      })
                      
                      subdomain = parsed.netloc
                      self.risk_ranking[subdomain]["score"] += 2.0
                      self.risk_ranking[subdomain]["reasons"].append(f"Suspicious params for {vuln_info['name']}")

    def generate_knowledge(self):
        """Map discovered technologies to actionable Hacking Tips with real payloads."""
        for subdomain, data in self.technologies.items():
            tips = []
            matched_techs = []
            
            tech_list = data.get("technologies", [])
            for tech in tech_list:
                t_name = tech.get("name", "")
                
                for kb_name, kb_tips in KnowledgeBase.items():
                    if kb_name.lower() in t_name.lower():
                        tips.extend(kb_tips)
                        matched_techs.append(t_name)
            
            # Also check for Swagger, JWT, etc. from cross-referenced data
            for swagger in self.swagger_docs:
                url = swagger if isinstance(swagger, str) else swagger.get("url", "")
                if subdomain in url:
                    tips.extend(KnowledgeBase.get("Swagger", []))
                    matched_techs.append("Swagger")
            
            for gql in self.graphql_data:
                if subdomain in gql.get("url", ""):
                    tips.extend(KnowledgeBase.get("GraphQL", []))
                    matched_techs.append("GraphQL")

            for jwt in self.jwt_data:
                if subdomain in jwt.get("url", ""):
                    tips.extend(KnowledgeBase.get("JWT", []))
                    matched_techs.append("JWT")

            for url in self.urls:
                if subdomain in url and UPLOAD_PATTERNS.search(url):
                    tips.extend(KnowledgeBase.get("Upload", []))
                    matched_techs.append("Upload")
                    break

            # Dedupe tips
            seen = set()
            unique_tips = []
            for tip in tips:
                tip_key = tip["tip"] if isinstance(tip, dict) else tip
                if tip_key not in seen:
                    seen.add(tip_key)
                    unique_tips.append(tip)
            
            if unique_tips:
                self.knowledge_tips[subdomain] = {
                    "matched_technologies": list(set(matched_techs)),
                    "tips": unique_tips
                }
                
                self.risk_ranking[subdomain]["score"] += 0.5 * len(unique_tips)

    def process_js_risk(self):
         """Increases risk score if APIs or logic flaws exist in JavaScript"""
         if not self.js_files:
              return
              
         for js_data in self.js_files:
              src = js_data.get("source", "")
              num_routes = len(js_data.get("routes", []))
              
              if num_routes > 0:
                   subdomain = urlparse(src).netloc
                   self.risk_ranking[subdomain]["score"] += min(num_routes * 0.2, 3.0)
                   self.risk_ranking[subdomain]["reasons"].append(f"Exposed {num_routes} API routes in JavaScript")

    def run_all(self):
        info(f"{C.BOLD}{C.BLUE}[*] Running Intelligence Engine Analysis...{C.END}")
        
        info("   - Classifying URLs...")
        self.classify_urls()
        
        info("   - Finding Vulnerability Patterns...")
        self.detect_vulnerabilities()
        
        info("   - Analyzing JS Risk factors...")
        self.process_js_risk()
        
        info("   - Querying Knowledge Base against Core Technologies...")
        self.generate_knowledge()
        
        info("   - Calculating Attack Priority Scores...")
        priority = self.calculate_attack_priority()        
        info("   - Detecting Quick Wins...")
        quick_wins = self.detect_quick_wins()
        
        # Cleanup and sort Risk Ranking
        final_ranking = []
        for subdomain, metrics in self.risk_ranking.items():
            final_score = round(min(metrics["score"], 10.0), 1)
            reasons = list(set(metrics["reasons"]))
            
            final_ranking.append({
                "subdomain": subdomain,
                "score": final_score,
                "tags": list(metrics["tags"]),
                "reasons": reasons
            })
            
        final_ranking = sorted(final_ranking, key=lambda x: x["score"], reverse=True)
        
        # Save artifacts
        with open(self.outdir / "risk_ranking.json", "w") as f:
            json.dump(final_ranking, f, indent=2)
            
        with open(self.outdir / "url_classification.json", "w") as f:
            json.dump(self.classified_urls, f, indent=2)
            
        with open(self.outdir / "vuln_patterns.json", "w") as f:
            json.dump(self.vuln_patterns, f, indent=2)
            
        with open(self.outdir / "knowledge_tips.json", "w") as f:
            json.dump(self.knowledge_tips, f, indent=2)
            
        success(f"   + Top Target: {priority[0]['subdomain']} (Score: {priority[0]['score']})" if priority else "   + No high value targets generated.")
        success(f"   + {len(quick_wins)} quick wins identified.")
        success(f"   + {len(self.vuln_patterns)} suspicious vulnerability patterns detected.")
        success(f"   + {len(self.classified_urls)} URLs automatically classified.")
        
        return {
            "risk_ranking": final_ranking,
            "classified_urls": self.classified_urls,
            "vuln_patterns": self.vuln_patterns,
            "knowledge_tips": self.knowledge_tips,
            "attack_priority": priority,
            "quick_wins": quick_wins,
        }

def run(context: dict):
    target = context.get("target")
    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   🧠 {C.BOLD}{C.CYAN}INICIANDO MÓDULO: ATTACK SURFACE INTELLIGENCE{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )
    
    engine = IntelligenceEngine(target)
    engine.run_all()
    
    success(f"✔ Inteligência gerada salva em: {engine.outdir}\n")
    return True
