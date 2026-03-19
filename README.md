# Enum-Allma ⚡

> **Ferramenta Profissional de Enumeração e Reconhecimento**
> *Enumeration, Reconnaissance, and Deep Analysis Tool*

Allma-Enum é uma suíte completa para pentest e bug bounty, focada em automação de reconhecimento, descoberta de ativos, análise de vulnerabilidades e geração de relatórios profissionais dinâmicos.

![Banner](https://img.shields.io/badge/Status-Active-success)
![Python](https://img.shields.io/badge/Python-3.9+-blue)

## 🚀 Funcionalidades (Features)

### 🌐 Reconhecimento de Domínio & Crawling
- **Multi-source Discovery**: Enumeração passiva e ativa com `Subfinder`, `crt.sh`, `haktrails`, `gau` e `waybackurls`.
- **🆕 Katana Crawler**: Motor de crawling Headless (Chromium) da ProjectDiscovery para renderização de JS e discovery profundo.
- **Portas**: Scan rápido com `Naabu` (Top 100, 1000 ou Full) com rate limiting configurável.
- **DNS Resolver**: Resolução DNS concorrente com detecção de wildcard e filtragem de CDN.
- **Fingerprinting**: Identificação de tecnologias e serviços com Wappalyzer-like detection.
- **Forms & Params**: Extração automática de formulários e parâmetros GET/POST para análise.
- **JS Discovery**: Busca profunda por URLs dentro de arquivos JS e scripts inline.

### 🔍 Análise de Segurança Avançada
- **🆕 Attack Engine (Inteligência)**: Motor de priorização de ataques que pontua ativos vulneráveis.
- **🆕 OAST (Blind Bugs)**: Integração com `Interactsh` para detecção de vulnerabilidades "blind" (XSS, SSRF, CRLF) via Out-of-Band testing.
- **🆕 Secret Finder (TruffleHog)**: Busca robusta por segredos usando entropia de Shannon e regex (reemplaza scanners básicos).
- **🆕 API Security (Kiterunner)**: Fuzzing de rotas de API moderno (`kr scan`) para descoberta de endpoints ocultos.
- **🆕 Cloud Recon (Cloud_enum)**: Descoberta de ativos em nuvem (S3, Azure Blobs, GCP Buckets) vinculados ao domínio alvo.
- **JWT Analyzer**: Desmonta, verifica algoritmos fracos (None, HS256) e quebra tokens JWT.
- **GraphQL Introspection**: Descobre mutations ocultas em APIs GraphQL.
- **🗺️ Source Maps**: Extrai o código-fonte original desempacotando arquivos `.map`.
- **🧬 Insecure Deserialization**: Rastreia assinaturas conhecidas de dados serializados.
- **🎭 XSS Scanner**: Busca passiva por reflexões e sinks perigosos de Cross-Site Scripting.
- **💉 CRLF Injection**: Busca reativa contra divisões de pacotes (HTTP Response Splitting).

### 🔑 Admin Panel Discovery
- **80+ paths comuns** testados (/admin, /wp-admin, /actuator, etc.).
- **Bypass de 403**: Técnicas semi-ativas e headers customizados para burlar restrições de acesso.

### ☁️ Cloud Security
- **Takeover detection**: Verificação de subdomínios órfãos apontando para serviços de nuvem (AWS, Azure, Vercel, etc.).

### 📦 Dependency Confusion
- **Package Extraction**: Extrai nomes de pacotes em arquivos JS e compara na internet.
- **Risk Classification**: Pacotes não encontrados = HIGH risk (potencial supply chain attack).

### 📊 Relatório e Web App Server
O novo painel é servido por **FastAPI** e **SQLite (In-memory)**. Ele permite gestão robusta dos relatórios de forma local.
- **Dashboard Web Dinâmico**: Interface completa gerida em React/HTML moderno.
- **Interactive Reports**: Agora com busca de subdomínios, cliques de navegação e explicações técnicas para vulnerabilidades.
- Pressione `View HTTP` para ver as provas das requisições brutas em tempo real!

---

## 🛠️ Instalação

### Pré-requisitos
- Python 3.9+
- Go (para ferramentas externas)

### Setup

```bash
# Clone o repositório
git clone https://github.com/AllisonMatos/allma-enum.git
cd allma-enum

# Instale as dependências Python
pip install -r requirements.txt

# Configure a string de acesso para o WebApp no .env da pasta core/webapp/
# (MONGODB_URI, JWT_SECRET)

# Verifique o ambiente (opcional, legacy script)
python3 check_install.py
```

---

## 💻 Uso

### 1. Iniciar o Scanner do Terminal
```bash
python3 menu.py
```

### Módulos Disponíveis
| ID | Módulo | Descrição |
|----|--------|-----------|
| 1 | **domain** | Enumeração de subdomínios e portas |
| 2 | **urls** | Descoberta e validação de URLs (Wayback + Live) |
| 3 | **services** | Probing de serviços e banners Nmap |
| 4 | **files** | Busca e filtragem por arquivos sensíveis |
| 5 | **jsscanner** | Análise estática profunda de JavaScript |
| 6 | **fingerprint** | Identificação de Tech Stack e Frameworks |
| 7 | **endpoint** | Mapeamento de Endpoints e rotas de API |
| 8 | **wordlist** | Geração de wordlists baseadas no alvo |
| 9 | **xss** | Scan passivo de vulnerabilidade XSS |
| 10 | **sourcemaps** | Extração de código e secrets vindo de Source Maps |
| 11 | **cve** | Correlação com banco de dados CVE |
| 12 | **admin** | Busca por painéis administrativos e bypass |
| 13 | **depconfusion** | Supply Chain Attack Detection via pacotes órfãos |
| 14 | **cors** | Misconfigurações e injeções de CORS |
| 15 | **takeover** | Subdomain Takeover Scanner (Cloud Services) |
| 16 | **headers** | Análise de Security Headers e notas de segurança |
| 17 | **waf** | Identificação de Firewalls Cloud protegendo origens |
| 18 | **emails** | Harvesting passivo de e-mails corporativos |
| 19 | **graphql** | GraphQL Introspection & Mutation Scanner |
| 20 | **cache_deception** | Web Cache Deception Detector |
| 21 | **jwt_analyzer** | Decode, brute-force e análise de fraquezas em tokens JWT |
| 22 | **crlf_injection** | CRLF Injection (com OAST) |
| 23 | **insecure_deser** | Insecure Deserialization Scanner |
| 24 | **api_fuzzer** | API Fuzzer (Kiterunner) |
| 25 | **cloud** | Cloud Recon (S3/Azure/GCP) |
| 26 | **all** | **Executa o fluxo completo inteligente (1 a 25)** |

---

## 📂 Estrutura de Saída

```
output/example.com/
├── report/           # Relatório HTML SPA moderno do site-alvo individual
├── domain/           # Subdomínios, DNS, IPs e Portas
├── urls/             # URLs descobertas e validadas
├── intelligence/     # Análise de risco/Engine de Impacto Score
├── jsscanner/        # Extrações de chaves e rotas JS
├── sourcemaps/       # Código fonte reconstruído de maps e credenciais neles
├── admin/            # Painéis de controle encontrados
├── depconfusion/     # Pacotes NPM vazados
└── wordlist/         # Dicionários gerados para brute force dinâmico
```

---

## 📋 Dependências Python
`requirements.txt` com as principais bibliotecas atualizadas:
```
httpx, requests, beautifulsoup4, lxml, FastAPI, uvicorn, PyMongo, python-jose, passlib[argon2], pydantic
```

---

## ⚠️ Disclaimer

Esta ferramenta é destinada exclusivamente para uso em **pentests profissionais autorizados** e **programas de bug bounty**. A responsabilidade por qualquer uso externo recai interinamente sob o aval e consciência do seu operador.
