# Enum-Allma ⚡

> **Ferramenta Profissional de Enumeração e Reconhecimento**
> *Enumeration, Reconnaissance, and Deep Analysis Tool*

Allma-Enum é uma suíte completa para pentest e bug bounty, focada em automação de reconhecimento, descoberta de ativos, análise de vulnerabilidades e geração de relatórios profissionais dinâmicos.

![Banner](https://img.shields.io/badge/Status-Active-success)
![Python](https://img.shields.io/badge/Python-3.9+-blue)
![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688)

## 🚀 Funcionalidades (Features)

### 🌐 Reconhecimento de Domínio
- **Multi-source Discovery**: Enumeração passiva e ativa com `Subfinder`, `crt.sh`, `haktrails`, `gau` e `waybackurls` (execução paralela).
- **Portas**: Scan rápido com `Naabu` (Top 100, 1000 ou Full) com rate limiting configurável.
- **DNS Resolver**: Resolução DNS concorrente com detecção de wildcard e filtragem de CDN (40+ CIDRs).
- **Fingerprinting**: Identificação de tecnologias e serviços com Wappalyzer-like detection.

### 🔗 Crawling & Discovery Avançado
- **Multi-Crawler**: Integração com `URLFinder` e ferramentas históricas (GAU/Wayback).
- **Deep Discovery**: Recursividade inteligente para encontrar URLs escondidas.
- **Forms & Params**: Extração automática de formulários e parâmetros GET/POST para análise.
- **JS Discovery**: Busca profunda por URLs dentro de arquivos JS e scripts inline.

### 🔍 Análise de Segurança Avançada
- **🆕 Attack Engine (Inteligência)**: Motor de priorização de ataques que pontua ativos vulneráveis baseados em riscos combinados.
- **Secret Finder e Validação**: Busca por chaves de API, com validação automática via API (Twilio, AWS, JWT, GitHub, etc).
- **🆕 JWT Analyzer**: Desmonta, verifica algoritmos fracos (None, HS256) e quebra tokens JWT mal configurados.
- **🆕 GraphQL Introspection**: Descobre mutations ocultas em APIs GraphQL através de introspection queries automáticas.
- **🗺️ Source Maps**: Extrai o código-fonte original desempacotando arquivos `.map` e busca segredos obscuros dentro do frontend das vítimas (Evidencia Source Map Exposure).
- **💉 CRLF & HTTP Smuggling**: Busca reativa contra divisões de pacotes (HTTP Response Splitting / Smuggling flaws).
- **🧬 Insecure Deserialization**: Rastreia assinaturas conhecidas de dados serializados (Java, PHP, Python Pickle, Node `__proto__`) trafegando nas requisições.
- **🎭 XSS Scanner**: Busca passiva por reflexões e sinks perigosos de Cross-Site Scripting.

### 🔑 Admin Panel Discovery
- **80+ paths comuns** testados (/admin, /wp-admin, /actuator, etc.).
- **Bypass de 403**: Técnicas semi-ativas e headers customizados para burlar restrições de acesso.

### ☁️ Cloud Security
- **Takeover detection**: Verificação de subdomínios órfãos apontando para serviços de nuvem (AWS, Azure, Vercel, etc.).

### 📦 Dependency Confusion
- **Package Extraction**: Extrai nomes de pacotes em arquivos JS e compara na internet.
- **Risk Classification**: Pacotes não encontrados = HIGH risk (potencial supply chain attack).

### 📊 Relatório e Web App Server (Novo Backend FastAPI)
O novo painel é servido por **FastAPI** e **MongoDB** num ambiente multi-tenant isolado. Permite gestão robusta, auth de admins e clientes.
- **Dashboard Web Dinâmico**: Interface completa gerida em React/HTML moderno.
- **Banco de Dados**: Persiste usuários, reports e convites de forma local no MongoDB.
- **Tokens JWT Seguros**: Login reforçado e suporte para isolamento contextual.
- Pressione `View HTTP` para ver as provas das requisições brutas convertidas em HTML em tempo real!

---

## 🛠️ Instalação

### Pré-requisitos
- Python 3.9+
- Go (para ferramentas externas)
- MongoDB Database (para a interface WebApp FastAPI)

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
| 22 | **crlf_injection** | Identifica Carriage Return Line Feed Injections (Response splitting) |
| 23 | **insecure_deser** | Identifica objetos vulneráveis que podem causar RCE por Insecure Deserialization |
| 24 | **ALL** | **Executa o fluxo completo inteligente (1 a 23)** |

### 2. Iniciar o Web App Dashboard
Abra seu report de forma estática com duplo clique, ou utilize o servidor inteligente executando:
```bash
cd core/webapp
uvicorn main:app --host 0.0.0.0 --port 8000
```
Visite `http://localhost:8000` em seu navegador para gerenciar os Relatórios Web interativos!

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
