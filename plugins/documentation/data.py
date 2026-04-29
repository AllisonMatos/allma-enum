# Dicionário central de documentação da ferramenta (Enum-allma V11)
# Contém detalhes técnicos de todos os plugins ativos.

DOCS = {
    "domain": {
        "nome": "domain",
        "resumo": "Módulo Inicial. Responsável por iniciar a cadeia descobrindo todos os subdomínios do Alvo, além de testar ativamente quais respondem na web (HTTP) e mapear suas portas.",
        "comandos": "subfinder -d ALVO -silent -all\n\nnaabu -list <subs> -silent -Pn -rate 3000\n\nhttpx -l urls-normalized.txt -mc 200,201,204,301,302,303,307,308,401,403,405 -retries 3 -timeout 20 -random-agent -follow-redirects -silent -threads 50\n\ncrt.sh API, haktrails, gau, waybackurls\n\nPython: dns.resolver.resolve(sub, 'A'), socket, regex keys/rotas.",
        "rationale": "Usa Subfinder + APIs passivas em ThreadPoolExecutor. httpx valida vida web com 401/403. V11: Detecção de login pages em 4 camadas (password input, URL keywords, login form, title).",
        "esperado": "Subdomínios, urls_valid.txt, login_pages.txt com detecção forte.",
        "exploracao": "Subdomínios dev/staging são portas de entrada para exploração."
    },
    "urls": {
        "nome": "urls",
        "resumo": "Motor de Crawler e Wayback. Coleta URLs de múltiplas fontes e valida com httpx.",
        "comandos": "urlfinder, gau, waybackurls -> httpx validação -> urls_200.txt",
        "rationale": "V11: Aplica scope filter para remover URLs de domínios externos (SSO, CDN, analytics).",
        "esperado": "URLs válidas in-scope com status 200+.",
        "exploracao": "Endpoints antigos podem ter parâmetros vulneráveis."
    },
    "services": {
        "nome": "services",
        "resumo": "Escaneador de Serviços e Portas com nmap -sV.",
        "comandos": "nmap -sV -Pn -T3 -p [PORTAS] ALVO -oN <outfile>",
        "rationale": "Flag -sV caça versão (crucial pro CVE), -Pn evita drop em firewalls cloud.",
        "esperado": "Versões de software e portas HTTP extras.",
        "exploracao": "Redis sem senha na 6379, Tomcat manager na 8080."
    },
    "files": {
        "nome": "files",
        "resumo": "Caçador de Arquivos Sensíveis por extensão (.env, .sql, .bak, .zip).",
        "comandos": "Python urllib.parse + regex de extensões, sem requests extras.",
        "rationale": "Filtro offline instantâneo. Separa por extensão em pastas.",
        "esperado": "Backups (.zip), dumps (.sql), chaves (.pem), configs (.env).",
        "exploracao": "Download de .sql revela base inteira, .env revela secrets cloud."
    },
    "jsscanner": {
        "nome": "jsscanner",
        "resumo": "Análise massiva de JS files. Extrai segredos e rotas de API.",
        "comandos": "httpx.AsyncClient com Semaphore de 10 concorrências. Regex para keys, tokens, rotas.",
        "rationale": "Assíncrono com retry 429. Extração focada de secrets.",
        "esperado": "js_routes.json com rotas API e secrets expostos.",
        "exploracao": "Tokens vazados dão acesso a APIs inteiras."
    },
    "fingerprint": {
        "nome": "fingerprint",
        "resumo": "Impressão Digital Web. Stack de tecnologias + certificados TLS.",
        "comandos": "httpx.AsyncClient -> headers server/x-powered-by + ssl.create_default_context() -> peercert.",
        "rationale": "Identifica stack completo (Nginx + PHP + Joomla + Cloudflare). V11: TLS certs e DNS records exibidos no report.",
        "esperado": "Stack tecnológico, certificados SSL, SANs.",
        "exploracao": "Versão específica revela CVEs conhecidos."
    },
    "endpoint": {
        "nome": "endpoint",
        "resumo": "Extrator de Endpoints API. V11: Filtra extensões estáticas (.css, .png, .woff, .svg).",
        "comandos": "Regex multi-padrão em urls_200.txt via httpx.AsyncClient.",
        "rationale": "Caça rotas ao vivo dos arquivos servidos, não do Wayback.",
        "esperado": "endpoints.txt limpo, sem lixo estático.",
        "exploracao": "Endpoints API sem autenticação."
    },
    "wordlist": {
        "nome": "wordlist",
        "resumo": "Gerador de dicionários customizados do alvo para brute force.",
        "comandos": "parse_qs + regex de tokens em JS via ThreadPoolExecutor.",
        "rationale": "Palavras internas da empresa são mais eficazes que wordlists públicas.",
        "esperado": "custom_wordlist.txt com ~5000 termos orgânicos.",
        "exploracao": "Ffuf com wordlist customizada contra IPs internos."
    },
    "cve": {
        "nome": "cve",
        "resumo": "Lookup passivo de CVEs via Searchsploit + NVD API.",
        "comandos": "searchsploit \"<Tech> <Version>\" --json",
        "rationale": "Cache de queries. Timeout de 30s. Consolidado com NVD.",
        "esperado": "potential_vulns.json agrupado por tech/versão.",
        "exploracao": "Copiar exploit retornado e executar."
    },
    "admin": {
        "nome": "admin",
        "resumo": "Buscador de Painéis Admin (~80 paths) com bypass 403. V11: Tags de categoria, strict validation.",
        "comandos": "httpx ThreadPoolExecutor(35) + 403 Bypass Headers/Paths.",
        "rationale": "Deduplica por SHA256. V11: Status 200 sem form precisa keyword admin real ou <form>.",
        "esperado": "Painéis com tags: ADMIN PANEL, ARQUIVO SENSÍVEL, CONFIG EXPOSURE, PATH API, DEBUG/TOOL.",
        "exploracao": "Credenciais padrão nos dashboards descobertos."
    },
    "cors": {
        "nome": "cors",
        "resumo": "CORS Misconfiguration Scanner passivo.",
        "comandos": "HTTPX injetando Origin: evil.com/null. Verifica ACAO + ACAC.",
        "rationale": "Checagem de bypass Wildcards, Suffix/Prefix.",
        "esperado": "ACAO: evil.com + ACAC: true = Crítico.",
        "exploracao": "Extração silenciosa de dados da API via link malicioso."
    },
    "takeover": {
        "nome": "takeover",
        "resumo": "Detector Subdomain Takeover via CNAME/A records.",
        "comandos": "dns.resolver CNAME -> Fallback NXDOMAIN -> HTTP Fingerprint provedor.",
        "rationale": "Fingerprint 404 do provedor reduz falsos positivos.",
        "esperado": "Subdomínios vulneráveis com provedor identificado.",
        "exploracao": "Criar recurso no provedor abandonado para takeover."
    },
    "headers": {
        "nome": "headers",
        "resumo": "Avaliador de HTTP Security Headers (Grade A-F).",
        "comandos": "HTTPX extração de headers. Score: HSTS=15, CSP=20, etc.",
        "rationale": "Detecta Information Disclosure e falta de proteções.",
        "esperado": "Grade de segurança + headers ausentes.",
        "exploracao": "Sem X-Frame-Options = Clickjacking possível."
    },
    "waf": {
        "nome": "waf",
        "resumo": "WAF Detection passivo via fingerprinting.",
        "comandos": "HTTPX passivo + regex em headers/cookies/body contra DB WAF.",
        "rationale": "Fingerprinting sem gerar alerta no WAF.",
        "esperado": "WAF identificado + endpoints sem proteção.",
        "exploracao": "Adaptar payloads ao WAF. Focar em endpoints desprotegidos."
    },
    "emails": {
        "nome": "emails",
        "resumo": "Email Harvester passivo via regex nos dados coletados.",
        "comandos": "Regex email nos outputs de 5+ módulos.",
        "rationale": "Zero requests extras. Limpeza e dedup automática.",
        "esperado": "Lista de emails com classificação internal/external.",
        "exploracao": "Password Spray nos logins corporativos."
    },
    "sourcemaps": {
        "nome": "sourcemaps",
        "resumo": "Caça Source Maps (.map) esquecidos. V11: httpx.AsyncClient (migrado de aiohttp).",
        "comandos": "httpx.AsyncClient -> Regex sourceMappingURL -> json.loads sourcesContent -> Regex secrets.",
        "rationale": "Source maps expõem código fonte original desminificado.",
        "esperado": "Secrets e keys expostos nos source maps.",
        "exploracao": "Acesso cloud via secrets expostos."
    },
    "graphql": {
        "nome": "graphql",
        "resumo": "Analítico GraphQL: Introspection, Batch, Mutations.",
        "comandos": "HTTPX POST: Introspection, Batch Queries, Mutations, Field Suggestions.",
        "rationale": "GraphQL condensa mil queries numa rota. Schema raramente protegido em prod.",
        "esperado": "DANGEROUS_MUTATIONS + Schema completo.",
        "exploracao": "Mutations admin via Postman (IDOR Avançado)."
    },
    "jwt_analyzer": {
        "nome": "jwt_analyzer",
        "resumo": "JWT Token Decoder + bypass alg:none.",
        "comandos": "Regex eyJ... -> base64 decode -> teste alg:none.",
        "rationale": "JWTs carregam status do usuário. alg:none = bypass total.",
        "esperado": "Claims sensíveis + ALG_NONE bypass confirmado.",
        "exploracao": "Forjar token admin manipulando claims."
    },
    "api_fuzzer": {
        "nome": "api_fuzzer",
        "resumo": "Fuzzer de API com Kiterunner.",
        "comandos": "kr scan <hosts> -w <wordlists> -x 5 --fail-status-codes 400,404,502",
        "rationale": "Templates de API reais são mais eficazes que wordlists genéricas.",
        "esperado": "Endpoints API ocultos com status 200/201.",
        "exploracao": "Endpoints sem auth permitem CRUD direto."
    },
    "host_header_injection": {
        "nome": "host_header_injection",
        "resumo": "Teste passivo de Host Header Injection.",
        "comandos": "HTTPX com Host: evil.com, X-Forwarded-Host: evil.com. Verifica reflexão.",
        "rationale": "Pode levar a Cache Poisoning e Password Reset Hijack.",
        "esperado": "Reflexão do host injetado em headers/body.",
        "exploracao": "Password reset hijack via Host header."
    },
    "cookies": {
        "nome": "cookies",
        "resumo": "V11: Análise de Segurança de Cookies (HttpOnly, Secure, SameSite).",
        "comandos": "httpx.AsyncClient -> Set-Cookie headers -> Classificação HIGH/MEDIUM/LOW.",
        "rationale": "Cookies mal configurados = session hijacking. HttpOnly previne XSS theft.",
        "esperado": "Cookies com flags de segurança e severidade.",
        "exploracao": "Session sem HttpOnly = roubo via XSS. Sem Secure = interceptação MITM."
    },
    "asn": {
        "nome": "asn",
        "resumo": "V11: CIDR/ASN Mapping via Team Cymru DNS.",
        "comandos": "dns.resolver IPs -> origin.asn.cymru.com -> Agrupamento por CIDR/ASN/Org/País.",
        "rationale": "Identificar infra real, distinguir CDN vs servidores próprios.",
        "esperado": "Mapa CIDR com ASN, organização, país, IPs.",
        "exploracao": "Hosts no mesmo CIDR com segurança fraca. Pivoting lateral."
    },
    "screenshots": {
        "nome": "screenshots",
        "resumo": "V11: Captura visual via gowitness (fallback httpx).",
        "comandos": "gowitness file -f urls_valid.txt -P <outdir>/screenshots --timeout 15",
        "rationale": "Triagem visual rápida sem abrir cada URL.",
        "esperado": "Screenshots + metadata JSON.",
        "exploracao": "Identificar visualmente painéis admin e páginas de debug."
    },
    "email_security": {
        "nome": "email_security",
        "resumo": "SPF/DMARC/DKIM Check do domínio.",
        "comandos": "dns.resolver para SPF (TXT), DMARC (_dmarc.domain), DKIM.",
        "rationale": "Configuração incorreta permite email spoofing.",
        "esperado": "Status SPF, DMARC, DKIM com análise de permissividade.",
        "exploracao": "SPF com ~all permite phishing como email legítimo."
    },
    "google_dorks": {
        "nome": "google_dorks",
        "resumo": "Gerador de Google Dorks customizados.",
        "comandos": "Gera queries: site:target ext:sql, inurl:admin, intitle:index of.",
        "rationale": "Google indexa arquivos que crawlers não alcançam.",
        "esperado": "Dorks prontos para copiar/colar.",
        "exploracao": "Encontrar dumps SQL e configs indexados pelo Google."
    },
    "cloud": {
        "nome": "cloud",
        "resumo": "Cloud Storage Scanner (S3, Azure Blobs, GCP).",
        "comandos": "cloud_enum -k target -l <outfile>",
        "rationale": "Buckets mal configurados = vazamento massivo.",
        "esperado": "Buckets públicos do alvo.",
        "exploracao": "Download de backups, logs, dados de clientes."
    },
    "diff": {
        "nome": "diff",
        "resumo": "V11: Comparação entre scans para tracking.",
        "comandos": "Python nativo: compara subdomains, urls, techs, cookies, ports, CORS, takeover.",
        "rationale": "Monitoramento contínuo detecta novas superfícies de ataque.",
        "esperado": "JSON com added/removed/summary por categoria.",
        "exploracao": "Novos subdomínios/techs indicam expansão do alvo."
    },
}
