# Dicionário central de documentação da ferramenta (Enum-allma)
# Contém detalhes técnicos de todos os 27 plugins.

DOCS = {
    "domain": {
        "nome": "domain",
        "resumo": "Módulo Inicial. Responsável por iniciar a cadeia descobrindo todos os subdomínios do Alvo, além de testar ativamente quais respondem na web (HTTP) e mapear suas portas.",
        "comandos": "subfinder -d ALVO -silent -all\n\nnaabu -list <subs> -silent -Pn -rate 3000 [MODO ALL: -p - | MODO TOP: -top-ports <n> -p 80,443,...]\n\nhttpx -l urls-normalized.txt -mc 200,201,204,301,302,303,307,308,401,403,405 -retries 3 -timeout 20 -random-agent -no-color -follow-redirects -silent -threads 50 -o <out_file>\n\ncrt.sh API: httpx.get('https://crt.sh/?q=%25.ALVO&output=json')\nhaktrails subdomains -d ALVO\ngau --subs ALVO\necho ALVO | waybackurls\n\nPython APIs: dns.resolver.resolve(sub, 'A') (DNS), socket (IPs), requisições HTTP para extrair RegExp (chaves e rotas).",
        "rationale": "Usa Subfinder para queries passivas velozes, além de outras apis (crt.sh, haktrails, gau, waybackurls) rodando em ThreadPoolExecutor. Usa httpx otimizado com dezenas de status code aceitos (incluindo 401/403) para validar vida web perfeitamente, poupando a máquina de timeouts nos próximos plugins.",
        "esperado": "Achar subdomínios (admin.alvo.com, dev.alvo.com) e montar o arquivo 'urls_valid.txt' que servirá de Bife pros próximos plugins. Ignora IPs que não respondem HTTP.",
        "exploracao": "Não é um plugin de vulnerabilidade direta, mas os subdomínios descobertos (especialmente os dev e staging) são portas de entrada para Injections e Takeovers."
    },
    "urls": {
        "nome": "urls",
        "resumo": "Motor de Crawler e Wayback. Pesca todas as URLs, rotas e páginas HTML já vistas na história do Domínio ou que estão mapeadas no servidor neste exato minuto.",
        "comandos": "urlfinder -list urls_for_urlfinder.txt -silent -timeout 10\n\ngau ALVO --threads 10\nwaybackurls ALVO\n\nhttpx -l <temp_file> -mc 200,301,302,307,308,401,403,404,405,500 -threads 50 -retries 2 -timeout 15 -random-agent -no-color -follow-redirects -silent",
        "rationale": "Usa o veloz urlfinder com paralelização (ThreadPoolExecutor de 5 lotes de 50) ignorando lixo estático (.png, .css) via regex rápida. Depois bate no Wayback (gau/waybackurls) pra pegar endpoints obsoletos. Por fim limpa todos os lixos com httpx.",
        "esperado": "Achar links antigos (ex: /api/v1/user/delete) e novos URLs que estão vivos (retornam 200 a 500). Ignora subdomínios mortos, e descarta extensões inúteis.",
        "exploracao": "Arquivos antigos descobertos podem conter parâmetros vulneráveis a injeção SQL, ou serem Endpoints sem autenticação."
    },
    "services": {
        "nome": "services",
        "resumo": "Escaneador de Serviços e Portas. Roda em cima dos IPs e domínios encontrados verificando que versões exatas de software estão rodando por trás (Ex: nginx 1.14.0).",
        "comandos": "nmap -sV -Pn -T3 -p [PORTAS_CONSOLIDADAS] ALVO -oN <outfile>\n\nRegex em Python: re.compile(r\"(\\d+)/tcp\\s+open\\s+(ssl[/|]https?|https?|http-alt...)\")",
        "rationale": "Adiciona inteligentemente as portas 80/443 se não estiverem na lista e roda o Nmap pegando banner real. A flag `-sV` caça a versão (crucial pro CVE plugin) e `-Pn` faz ele não dropar scans em firewalls cloud que bloqueiam Ping (ICMP).",
        "esperado": "Descobrir as versões dos softwares de Borda. E através da regex `(\\d+)/tcp\\s+open\\s+(ssl|http)\\b` ele repassa qualquer porta maluca HTTP (ex: 8443) de volta pra fila do validador (urls_valid.txt).",
        "exploracao": "Você identifica serviços exóticos como Redis sem senha na porta 6379, Tomcat com painel manager padrão na 8080."
    },
    "files": {
        "nome": "files",
        "resumo": "Caçador de Arquivos Sensíveis. Pega todo o pântano de milhões de URLs criadas anteriormente e agrupa filtrando arquivos com extensões perigosas (ex: pdf, zip, env, bak, sql).",
        "comandos": "Python nativo via `urllib.parse.urlparse` e Regex de Path/Query:\n\n`re.search(r\"\\.([a-zA-Z0-9]{1,10})(?:\\.([a-zA-Z0-9]{1,10}))?$\", path)`\n\nSeparação dinâmica baseada em string (sem requisições web repetidas).",
        "rationale": "Filtrar por regex offline em Python é instantâneo e não trava a máquina (diferente de fazer 'grep' em arquivos de 10GB). Separa tudo bonitinho em Pastas para o PenTester ver só o ouro.",
        "esperado": "Arquivos de Backup de código (.zip), Dumps de Base de dados (.sql), chaves SSH soltas (.pem). Retorna dicionários de extensão. Ignora html puro.",
        "exploracao": "Baixar um arquivo '.sql' te dá literalmente a base inteira, revelando hashes de senhas de administradores. Arquivos '.env' revelam os Segredos de Banco de Dados da Nuvem."
    },
    "jsscanner": {
        "nome": "jsscanner",
        "resumo": "Análise focada e massiva de Arquivos Javascript. Ele raspa as páginas em HTML baixando cada script `.js` importado nelas e aplica Regex destrutivo para encontrar segredos de backend colados ali e Rotas de API que não tem links no HTML.",
        "comandos": "HTML Scrape: `httpx.get(url)` -> Regex `<script[^>]+src=[\"']([^\"']+)[\"']`\n\nJS Analyzer: Regex `https?://[^\\s'\"<>]+` e `(?i)(apikey|token|secret|bearer)[\\s'\":=]{1,8}([A-Za-z0-9\\-_]{8,128})`\nExtração de lógica AST/Regex avançada via `extract_js_logic()` para rotas de API.",
        "rationale": "Totalmente Assíncrono (asyncio + httpx.AsyncClient) com Semaphore de limitação a 10 concorrências. Lida com retry de limites abusivos (Code 429). Processamento pesado focado em não crashar no regex de extração.",
        "esperado": "Lista Json `js_routes.json` estruturada para injetar perfeitamente parâmetros em rotas APIs fantasmas recém descobertas pela CLI. Extração de Secret Keys de nuvem e APIs vazadas nos scripts de frontend.",
        "exploracao": "Token solto dá acesso irrestrito às contas de e-mail transacionais (Stripe) da empresa. Rotas escondidas revelam Endpoints de API que esqueceram de implementar autenticação."
    },
    "fingerprint": {
        "nome": "fingerprint",
        "resumo": "Impressão Digital Baseada em Web. O Nmap analisa a porta, mas este plugin analisa o Framework! Descobre se o site roda Wordpress, React.js, Express, WAFs e pega informações do Certificado Digital TLS.",
        "comandos": "HTTP Headers Async: `httpx.AsyncClient()` -> Extrator de Header `server`, `x-powered-by`, `content-security-policy`.\n\nTLS Certificados Async: `ssl.create_default_context()` -> `writer.get_extra_info('peercert')`",
        "rationale": "Um Nmap diria 'Porta 443 Nginx'. O Fingerprint varre o cabeçalho e diz 'Nginx + PHP 5.4 + Joomla 1.5 + Cloudflare'. Ele junta O stack inteiro numa folha só.",
        "esperado": "Stack de tecnologia (Node.js, Vue, Apache, versões), Certificados SSL expondo outros subdomínios internos. Ignora erros de SSL (Insecure).",
        "exploracao": "Se bater que é 'Wordpress 4.7.1', o pentester já sabe que é vulnerável a Injeção na Rota REST nativa daquela versão."
    },
    "endpoint": {
        "nome": "endpoint",
        "resumo": "Extrator Cirúrgico de Endpoints API de códigos densos (Javascripts lidos e HTMLs). Varre códigos soltos extraindo URIs de APIs que possam ser invocadas (AJAX calls).",
        "comandos": "Regex patterns cruas multi-passo: \n`r'[\"\\'](/api/[A-Za-z0-9_\\-\\/.?=&%]+)[\"\\']'` \n`r'[\"\\'](/v[0-9]+/[A-Za-z0-9_\\-\\/.?=&%]+)[\"\\']'` \n`r'fetch\\(\\s*[\"\\']([^\"\\']+)[\"\\']'`\nAsync `httpx.AsyncClient` na lista `urls_200.txt`.",
        "rationale": "Diferente do URLs que caça do 'WaybackMachine', esse plugin caça das 'Entranhas' ao vivo dos arquivos servidos agora no domíno raiz, extraindo URIs como '/v1/users/list'.",
        "esperado": "Devolver o 'endpoints.txt' purinho e separar o GraphQL pra ser atacado depois. Ignora URLs absolutas para imagens estáticas (svg, jpg).",
        "exploracao": "Ficar caçando Endpoints cegamente demora séculos. Achar a API pura permite jogar no Fuzzer e bater de ombro no CRUD inteiro dos dados web."
    },
    "wordlist": {
        "nome": "wordlist",
        "resumo": "Gerador Personalizado de Dicionários. Ele roda todo o seu alvo destilando palavras específicas da empresa alvo pra criar um dicionário cirúrgico pra Brute Force.",
        "comandos": "Quebra de URLs: `parse_qs` e Regex de Params `r\"/([A-Za-z0-9\\-_]{2,80})\"`\n\nExtração JS Remoto: Download JS vivo via `ThreadPoolExecutor` c/ `httpx`.\nRegex de Tokens em JS puro: `r\"[A-Za-z0-9\\-_]{3,60}\"`",
        "rationale": "Tentar adivinhar painéis escondidos com Wordlists públicas ('admin', 'test') é ruim. A empresa usa siglas internas próprias ('projeto_omega_2024'). Se o plugin tirar essas strings das variáveis no JS ou do Footer do HTML, a chance do Bruteforce dar Hit é de 90%.",
        "esperado": "Lista 'custom_wordlist.txt' com 5.000 variáveis e pedaços de palavras achadas organicamente nos sites do alvo.",
        "exploracao": "Joga o arquivo `custom_wordlist.txt` no Ffuf contra um IP de Nuvem privado pra revelar o Painel de Controle secreto contendo o mesmo jargão técnico."
    },
    "xss": {
        "nome": "xss",
        "resumo": "Análise Passiva de Reflexão XSS (Cross Site Scripting). Lê as páginas para verificar se inserções na URL são refletidas nativamente no HTML ou se a lógica DOM usa funções perigosas (innerHTML).",
        "comandos": "Crawler Async: `aiohttp.ClientSession` c/ Batch Fetch Limits.\n\nDOM XSS: Regex multi-padrão `re.compile(r'\\binnerHTML\\b', re.I)` e `\\bsetTimeout\\s*\\(`\n\nReflexões: Mapeio das Tags adjascentes em blocos como HTML (`>...<`), Atributos (`<tag attr=...`), Javascript `<script>...</script>`.",
        "rationale": "Mandar códigos `><script>alert(1)</script>` suja a máquina, engatilha WAF e bane seu IP, resultando em Ban. A análise passiva envia parâmetros benignos (`?q=ENUMALLMATST`) e checa se o servidor devolve esse jargão no HTML fora de aspas ou sem encoding.",
        "esperado": "Reportar `XSS REFLECTED` se o parâmetro bater na página limpo. Reportar `DOM SINK_FOUND` caso tenha sinks perigosos. Ignora páginas seguras com Content-Type Json ou encoding nativo.",
        "exploracao": "Se for classificado Crítico, o hacker formata o Payload Real XSS (enviando stealers de Cookies), monta o link curto, joga pro Administrador Clicar, roubando a sessão do Banco sem senhas."
    },
    "cve": {
        "nome": "cve",
        "resumo": "Ligação Passiva com Banco de Vulnerabilidades Públicas. Pega o relatório de Tecnologias (do módulo Fingerprint e Services) e cruza com a database aberta mundial do ExploitDB (Searchsploit) instalada na máquina do Hacker.",
        "comandos": "searchsploit \"<TechName> <TechVersion>\" --json\n\n(Ex: searchsploit \"nginx 1.14.0\" --json)",
        "rationale": "Pula requests duplicadas mantendo cache (ex: não checar Nginx 1.14x 20 vezes). Execução subprocess cru com timeout severo limitante de 30s. Não quebra a CLI e salva apenas se tiver JSON result válido 'RESULTS_EXPLOIT'.",
        "esperado": "Gera `potential_vulns.json` agrupando CVEs por tecnologia/versão. Mostra o título e o path (arquivo ruby/python locado na máquina) do exploit publicamente letal.",
        "exploracao": "Basta copiar o `Exploit.py` retornado, configurar IP de reverso, dar Enter na CLI e ganhar Root no servidor oficial pela falha não patcheada."
    },
    "admin": {
        "nome": "admin",
        "resumo": "Buscador Oculto de Painéis (Admin Discovery). Roda as URLs válidas testando dicionários agressivos voltados somente para Endpoints de Administração. Ele também usa técnicas semi-ativas para burlar acessos proibidos (Erro 403).",
        "comandos": "Python httpx com ThreadPoolExecutor(35 workers) contra dicionário de ~80 caminhos mortais (/admin, /wp-admin, /actuator).\n\n403 Bypass Passivo Headers: `X-Forwarded-For: 127.0.0.1`, `X-Original-URL`, `X-Rewrite-URL`, `X-Host: localhost`\n\n403 Bypass Fuzzing Paths: `/admin/./`, `/admin..;/`, `//admin`, `/%20admin`, `/admin?`",
        "rationale": "Deduplica as respostas baseando-se no SHA256 do HTML stripado (remover timestamp, CSRF). Isso impede que 80 paths listem falsos 200 pro mesmo redirect da Home Page. Verifica 'CMS fingerprints' no SourceCode pra validar qual tecnologia abriu as pernas nas restrições originais.",
        "esperado": "Painel de Admin Genuínos abertos ou com form de login `<input type=\"password\">`. Buraços no WAF indicando que Path Mutation (ex: `..;/`) burlou a proteção de ingressos Tomcat/Spring.",
        "exploracao": "Usar credenciais padrões (`admin:admin`, `root:root`) nos Dashboards novos descobertos ou jogar a requisição de bypass crua no Burp Repeater."
    },
    "depconfusion": {
        "nome": "depconfusion",
        "resumo": "Escaneador de Confusão de Dependências (Supply Chain). Avalia os arquivos Frontend/Backend coletados para ver se existem Pacotes Privados citados que esqueceram de ser registrados na Fonte Pública (Como as lojas e nuvens do NPM/PyPi).",
        "comandos": "Regex Multi-padrão: `require\\(\\s*['\"]([a-z@][a-z0-9\\-_./@]*)['\"]\\s*\\)`\n\nVerificador NPM: `httpx.get(f'https://registry.npmjs.org/{pkg}')` -> `resp.status_code == 404` (Pacote Inexistente/Vulnerável).",
        "rationale": "Ao compilar em Nuvem, os desenvolvedores de React usam `import 'modulo-interno-banco'`. Se alguém no mundo nunca registrou publicamente um pacote chamado `modulo-interno-banco` no NPM Oficial da web... qualquer hacker poderá criar ele na base do NPM mundial. Ao dar deploy na empresa, a rede interna do banco vai baixar a versão oficial Hackeada via Internet cega e compilar junto do frontend da empresa automaticamente em vez da local.",
        "esperado": "Listar se pacotes citados pelo codigo deram NPM_VULNERABLE (Pacote não existe e o hacker poderá roubar hoje no NPM e envenenar a empresa).",
        "exploracao": "Entrar no repositório Global real do npmjs, dar push numa biblioteca com vírus feita por você com o mesmo nome. O pipeline GitHub Actions/Jenkins da empresa vai atualizar a versão dela pro seu VÍRUS, RCE completo pelo Supply Chain."
    },
    "cors": {
        "nome": "cors",
        "resumo": "CORS Misconfiguration Scanner. Testa a Política de Mesma Origem (SOP) p/ verificar se o site alvo permite que páginas maliciosas de terceiros realizem requisições ativas.",
        "comandos": "Python HTTPX ThreadPools injetando Headers:\n`Origin: https://evil.com`\n`Origin: https://evil.alvo.com`\n`Origin: null`\nVerificação `access-control-allow-origin` e `access-control-allow-credentials`",
        "rationale": "Checagem de bypass (Wildcards, Suffix/Prefix) porque os programadores usam Regex equivocadas. E testa se o Credencials envia as respostas p/ as sessões logadas do hacker.",
        "esperado": "Achado Crítico: Server retornar `Access-Control-Allow-Origin: https://evil.com` JUNTO de `Access-Control-Allow-Credentials: true`.",
        "exploracao": "Hacker envia link pra vítima, e extrai o saldo bancário da API num painel HTML falso sem a Vítima perceber, via conexão silenciosa."
    },
    "takeover": {
        "nome": "takeover",
        "resumo": "Detector Subdomain Takeover. Acha apontamentos órfãos em provedores de Cloud na qual a hospedagem originária não existe mais.",
        "comandos": "DNS Lookup via `dns.resolver.resolve(subdomain, 'CNAME')` ou `A` -> Fallback pra NotFound (`NXDOMAIN`).\n\nHTTP Fingerprint Otimizado: \nAzure `Error 404 - Web app not found`, S3 `NoSuchBucket`, Github Pages.",
        "rationale": "Busca na página de erro 404 pelo fingerprint (exemplo, site AWS). Isso reduz falso positivos e diz quando é de fato possível o takeover ao invés de ser apenas DNS estragado.",
        "esperado": "Listar se Subdomínio Alvo X e Y estão vulneráveis reportando o Provedor (`AWS_S3`, `Vercel`, `GithubPages`).",
        "exploracao": "Criar ou alugar instantaneamente a conta e o nome de recurso do Provedor esquecido, roubando imediatamente a fachada e dominância daquele domínio oficial alvo."
    },
    "headers": {
        "nome": "headers",
        "resumo": "Avaliador Passivo de HTTP Security. Calcula um Grade (Nota Escolar: A, B, C... F) do quão modernizado na proteção das conexões Web o domínio está.",
        "comandos": "Python HTTPX: `Client()` com extração dict `{k.lower(): v for k, v in resp.headers.items()}`.\nCruza contra as chaves dicionário (HSTS vale 15, CSP vale 20).",
        "rationale": "Evita Information Disclosure de backend informando via print (ex: PHP 5.6 exposto no Header) e agiliza compliance contra Clickjacking, sniffing, ataques básicos XSS/XFS.",
        "esperado": "Headers inseguros (ausência HSTS, CSP), apontando warnings da versão da tecnologia do Server em resposta HTTP.",
        "exploracao": "Sem X-Frame-Options, o hacker embute o alvo no Iframe invisível (Clickjacking / UI Redressing), atraindo roubos e botnets com o log da navegação da Vítima."
    },
    "waf": {
        "nome": "waf",
        "resumo": "Web Application Firewall Detection. Passa silenciosamente pra descobrir a camada defensiva que o alvo tem, e lista exatamente quais hosts não possuem escudo defensivo (desprotegidos ao ar livre).",
        "comandos": "Python HTTPX Request Passivo.\nRegex matching dinâmico nos dicts `resp.headers`, `resp.cookies.jar` e `resp.text`.\nValida chaves da DB json de WAF (ex: `header:server=cloudflare`).",
        "rationale": "Um scanner fuzzer seria instantaneamente barrado batendo num IP com WAF, então se usar fuzzed de 1.000 requests as cegas pode te dar ban da corporação. Ele usa Waf Fingerprinting Seguro (sem gerar o alerta na firewall).",
        "esperado": "Lista o WAF primário (Cloudflare, Akamai) que segura as portas, para que o pentester adapte os Payloads. Lista endpoints nus para brute-force imediato.",
        "exploracao": "Não explora; diz a estratégia para evitar punição de IPs limitadores do alvo real, mirando as armas pesadas de DB Attack em domínios que o firewall cloud abandonou (endpoints crus)."
    },
    "emails": {
        "nome": "emails",
        "resumo": "Email Harvester Passivo. Extração gigantesca que cata centenas de milhares de linhas das respostas já guardadas usando Busca Regex Sem Custos Adicionais.",
        "comandos": "Iteração de Cursor Find('@') linear.\nRegex final `re.compile(r'[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9\\-]+(?:\\.[a-zA-Z0-9\\-]+)*\\.[a-zA-Z]{2,}', re.I)` iterando os outputs `.txt, .json, .xml`.",
        "rationale": "Fazer request extra atrasa e aumenta tráfego. Esse Script só limpa o lixo e agrupa com regex o acúmulo das coletas de 5 módulos p/ frente de todo email validável.",
        "esperado": "Retornar Lista Extensa Limpa por Email de Pessoas Reais e classificar magicamente se é funcionário corporativo local (`internal_list`) pra Phishing de Intranet.",
        "exploracao": "Password Spray Account. Enviar senha padrao `Senhaworld1!` em logins Webmails com os endereços Internos, buscando Entrar em Intranets de diretores, Vpn Cisco, Office365 e Slack via Vazamento ou CredStuffing."
    },
    "sourcemaps": {
        "nome": "sourcemaps",
        "resumo": "Caça a Código Desminificado Front. Fuzza/Busca por arquivos '.map' (Webpack, JS) esquecidos e baixados reconstrói o fonte legível no servidor do hacker pra rastrear Keys API e Vazamento Crítico.",
        "comandos": "Async `aiohttp.ClientSession` -> Regex `//# sourceMappingURL=(.*?\\.map)` -> `json.loads()` em `sourcesContent` e `sources` -> Match `PATTERNS` compiladas de AWS Keys, GraphQL, Tokens.",
        "rationale": "Frontends usam Webpack q esmaga arquivos em 1 bloco de códigos insanos. Ao usar os Múltiplos Arquivos Maps q vazaram do prod, o Analista lê código como se estivesse com Github Real na mão, identificando lógicas secretas fáceis sem obfuscamento.",
        "esperado": "Achados pesados como Secret API Credentials e Access Keys que dev front não apaga por desleixo, acreditando a Nuvem iria esconder.",
        "exploracao": "Sequestro da Stripe Account, Controle AWS Nuvem pelo backend API e manipulação administrativa na cloud via Secrets esquecidos Expostos publicamente no site web."
    },
    "graphql": {
        "nome": "graphql",
        "resumo": "Ferramenta Analítica Crítica GraphQL API. Engole a Introspection Query inteira forçando Mutações Ocultas passivas e Testando Bypass Limites da API Batch.",
        "comandos": "HTTPX POST request injetando:\n1. Introspection `{__schema...}`\n2. Batch Queries `[{__typename}, {__typename}]`\n3. Mutations `{__schema{mutationType...}}` (buscando 'delete', 'admin')\n4. Field Suggestions `{__typ}`.",
        "rationale": "Endpoints estáticos `/api/` falham muito; Diferente deles GraphQL condensa 10 mil queries web web/crud em Única Rota End web aberta e desenvolvedor raramente esconde a Árvore Central (Esquema/Planos). Desabilita-se pouco em prod o Modo Debuggers GQL.",
        "esperado": "Vulnerável DANGEROUS_MUTATIONS reportável em Alto e Schema exposta na Totalidade, dando caminho do mapa pra deletar BD Inteiros e Ler Segredos Ocultos no Grafo, enumerando Admin Roles e Acessos restritos não Listados.",
        "exploracao": "Importar Schema Exportada Num Postman na Sessão Invasora. Muta IDs Ocultos via chamadas Administrativas descobrindo rotas cegas que Front Web Normal do Client não disponibilizou nativamente no navegador normal de usuários comuns (IDOR Avançado)."
    },
    "cache_deception": {
        "nome": "cache_deception",
        "resumo": "Detector Lógico Avançado Web Cache Deception. Falsifica o Processamento CDN/Proxy p/ Extratos de Clientes dinâmicos fiquem Retidos p/ Sempre no Repositório Global como Ficheiros Públicos Estáticos.",
        "comandos": "HTTPX GET na URL dinâmica.\nAdere sufixos estáticos (ex: `/nonexistent.css`) e envia GET denovo.\nProcura Headers `x-cache/cf-cache-status` e avalia se similarity de body length original/falso é >0.7 (70%).",
        "rationale": "Sistemas WAF/CDN evitam armazenar Info Dinamica Auth. Mas a Regra Crua Base Engine os faz Ignorar Segurança Guardando Arquivos Design na Memoria Limpa P/ Download Mundo/População. Se Hack Modifica Sufixo pra CSS Falso a Regra os Faz Exportar Extrato Logado da vitima num Espaço Compartilhante pra População Mundial.",
        "esperado": "Exceção Dinâmica Salva e Exposta Confirmada HIT Header; Retornando Dados Sigilosos Autenticados como HTML Público Exato. Vulnerabilidade de Status Risco Máximo para Vaza Info Bancária/Hospitalar Indiscriminada via Link Trivial do Proxy de Cache Público.",
        "exploracao": "O Malfeitor espalha Link Vítima Falso Logado com Extensão. Vitima clica ao Vivo em Sessão Valida. O Extrato da Vitima trava no Arquivo CDN Global. O Invasor Sem Log Nenhum Usa Modo Anonimo Pra Baixar Esse Mesma Url Minutos Depois Retirando PDF e Confidenciais Perfeitos na íntegra de Outro User Inconcientemente."
    },
    "jwt_analyzer": {
        "nome": "jwt_analyzer",
        "resumo": "Assassino JWT Token Engine Decoder. Puxa tokens Json Web nas respostas armazenado Local, Descriptando Silenciosamente Informações Pessoais Criptografadas no Core, Engenhando Testes Exóticos Alg:None Sem Triggers nas Proteções.",
        "comandos": "Regex `eyJ...` coletando de todo o output.\nDecoda b64 header/payload.\nAvalia assinatura (HS256/512).\nAvalia claims (`password`, `private_key`).\nTenta bypass Modificando header pra `alg:none` e testa request viva autenticada no alvo.",
        "rationale": "As Autenticações JWT carregam todo O Cargo/Status Usuário. Hackers n tem acesso banco central Entao o Modificador Local Forja Um Privilegio Admin Nulo Sem Assinaturas (Algo=None). E envia de Volta. Os Codificadores Backends q Desativaram Conferências Devem Dar Ok (Bypass Genuíno Brutalidade Em Fronts Despreparados de Segurança Tokenizada).",
        "esperado": "Informação 'ROLE_CLAIM' contendo senhas expostas sem proteção B64 no Cookie de Rede Pública Limpo. E Constatações Grave de 'ALG_NONE' indicando Que Sistema Aceita Manipular Sem A Chave Privada Local Criptografando Tokens de Acesso Falsos Como Master Root Accounts Live.",
        "exploracao": "Bypassar 100% Criptografia BackEnd Altrando O JWT Local No Burps. Remetendo Token Onde Está 'Role: user' e Submetendo 'Role: admin'. Tendo Autorizações Garantidas do Servidor Sincronizado Com Banco Nuvem Falso Aceito pela Key de FallBack 'None' Habilitação. Sucesso no Escalonamento Local Imediato em APIs."
    },
    "crlf_injection": {
        "nome": "crlf_injection",
        "resumo": "Identificador Injeção Header Break CRLF. Tenta Burlar Protocolo Web Injetando Resposta Falsa `\\r\\n` Nos Dados Recebidos Envenenando o HTML e a Rede com Elementos Falsos Fantasmas Modificados.",
        "comandos": "HTTPX + ThreadPoolExecutor.\nInjeta payloads `%0d%0aX-CRLF-Test:%20injected` em Parâmetros e no Path da URL (via `parse_qs` e `quote_via`).\nVerifica se `x-crlf-test` reflete nos Headers ou Cookies de resposta.",
        "rationale": "Os Bibliotecas Frameworks Cortam Payload CRLF Antigos, Bypasses Hex/Unicode Python Nativo Fuzza P/ Despistar Proteções Frontend/Nuvem pra Ver Se o DB de Trás Falha Renderizando Novas Linhas Fictícias na Interface Criando Cookies Set-Cookie e X-Headers Malcriados Controlados Pelo Hacker Invasor Diretamente Da Url.",
        "esperado": "Confirmação Do Server Acusando Cabeçalho Injection e Disparo em Resposta Crua Real No Raw Request Com Header Fabricado Confirmando Enfraquecimento no Protocolos Críticos Front End Roteando Modificações Abertas De Forma Involuntária. Detalhando Injection de Headers e Cookies Puros Criados Espúrios Injetados.",
        "exploracao": "Ao Quebrar HTTP com Carriage Returns em Respostas de Server Pode Redirecionar URL p/ Local Host Phising ou Ocultar Script Html Xss e Forjar Cookie Sessão Inteira Da Vitima Enganando Servidor e Cliente Num Refletido Inviável De Defesa Externa Pelo Modo Estrutural TCP Quebrado do Engine Backwards Compromised."
    },
    "insecure_deserialization": {
        "nome": "insecure_deserialization",
        "resumo": "Identificador Insegurança Desserializer. Escaneador Busca Nas Requisições Headers E Cookies Objetos Serializados Nativos Do Programador Expostos Para Analisar Se Ha Controle De Hash ou Criptografia Nula Nesses Valores Primos Da Programação Server Side C#, Python, PHP e JS Node.",
        "comandos": "HTTPX varrendo Cookies, Set-Cookie, Headers custom (`x-token`) e HTML body.\nRegex base64 (`rO0AB`, `gASV`) convertendo pra Hexadecimal e buscando Magic Bytes (`aced0005`, `80049`).\nRegex no body HTML para `__VIEWSTATE` identificando MAC Validation nativo do .NET.",
        "rationale": "Módulos Oficiais Não Devem Passar Objetos Backend Em Base64 Pela Rede Internet e Sim Id De Sessões No DB. Eviar String Hash Java E Pickle E PHP pra Rede E O Usuario Permitir Decodificar A Volta Num Server Libera Para Fuzzer Montar Uma String Equivalente De Ataque Destrutivo Usando Ferramentas Criadores De Objetos Ex (YsoSerial App). Transformadores Identificam Somente Os Genuínos Magic Bytes Assinados E Reportam a Despiste Da Falha Lógica Na Criação Da App Cloud Baseada No View/State Formato.",
        "esperado": "Localização de Objetos Puros Ou Descriptografados Serializado Hexadecimal Confirmando `HIGH` Ocorrencia De Base Oculta Vulneráveis Transposta Por Cookie Set/Custom Header. Ou Identificar NET Forms Desatualizados Identificando Com ou Se Ausencia De Codigo MAC Validation Protector Que Forçará Falha RCE Exploração Remota Garantida Via C# Payload Form Web App Engine Crtico Reportado JSON Evidence Crú.",
        "exploracao": "Encontrado O Base64 Magic Objeto Crú O Atacante Joga Ele De Volta Num Injetor Ferramenta Falsificando Um Script C# Java Criando Payload de Execucao Shell Remote Command Cmd Root E Bota Como Valor De Cookie. Quando Pagina Reloda o Script Original Roda O Payload Dentro E Fogo O Server Lhe Retorna Um Terminal Na Rede Da Vitima Ou Conexao Reversa Direta Pra Tela Do Hacker E Tomada Da Maquina Virtual Integrada Inteira Total Cloud Infrastructure Ownage Do DB AWS/Locals."
    }
}
