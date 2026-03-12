# Enum-Allma ⚡

> **Ferramenta Profissional de Enumeração e Reconhecimento**
> *Enumeration, Reconnaissance, and Deep Analysis Tool*

Allma-Enum é uma suíte completa para pentest e bug bounty, focada em automação de reconhecimento, descoberta de ativos e geração de relatórios profissionais.

![Banner](https://img.shields.io/badge/Status-Active-success)
![Python](https://img.shields.io/badge/Python-3.9+-blue)

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

### 🔍 Análise de Segurança
- **Secret Finder**: Busca por chaves de API, tokens e credenciais vazadas em JS/HTML.
- **🆕 Token Validation**: Validação automática de tokens via API (GitHub, AWS, Google, Slack, Stripe, Twilio, SendGrid, JWT).
- **JS Analysis**: Extração de endpoints e rotas de arquivos JavaScript.
- **CVE Detection**: Correlação de tecnologias detectadas com CVEs conhecidos via Searchsploit.
- **🗺️ Source Maps**: Extração de código-fonte original e segredos de arquivos `.map` (Soucemap unpacker).
- **🗂️ Wordlist**: Geração de dicionários personalizados baseados no alvo para ataques de força bruta.
- **🎭 XSS Scanner**: Busca passiva por reflexões e sinks perigosos de Cross-Site Scripting.

### 🔑 Admin Panel Discovery
- **80+ paths comuns** testados (/admin, /wp-admin, /actuator, etc.).
- **Bypass de 403**: Técnicas semi-ativas e headers customizados para burlar restrições de acesso.
- **Login Form Detection**: Identificação automática de formulários de login.

### ☁️ Cloud Security
- **Takeover detection**: Verificação de subdomínios órfãos apontando para serviços de nuvem (AWS, Azure, Vercel, etc.).

### 📦 Dependency Confusion
- **Package Extraction**: Extrai nomes de pacotes de `require()` e `import` em arquivos JS.
- **Registry Check**: Verifica existência no npm público.
- **Risk Classification**: Pacotes não encontrados = HIGH risk (potencial supply chain attack).


### 📊 Relatórios Profissionais
- **Dashboard SPA**: Design moderno Dark Mode com navegação por abas.
- **13+ seções**: Dashboard, Subdomains, DNS/IPs, Security, CVEs, Services, URLs, Keys, Endpoints, JS, Source Maps, Admin Panels, Dep Confusion, Emails.
- **Login Flags**: Badge 🔑 LOGIN em subdomínios com páginas de login detectadas.
- **Export**: Dados brutos salvos em JSON/TXT.

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

# Verifique o ambiente
python3 check_install.py
```

---

## 💻 Uso

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
| 10 | **sourcemaps** | Extração de código de Source Maps |
| 11 | **cve** | Correlação com banco de dados CVE |
| 12 | **admin** | Busca por painéis administrativos e bypass |
| 13 | **depconfusion** | Supply Chain Attack Detection |
| 14 | **cors** | Misconfigurações de CORS detector |
| 15 | **takeover** | Subdomain Takeover Scanner |
| 16 | **headers** | Análise de Security Headers e notas |
| 17 | **waf** | Identificação de Firewalls Cloud |
| 18 | **emails** | Harvesting passivo de e-mails corporativos |
| 19 | **graphql** | GraphQL Introspection & Mutation Scan |
| 20 | **cache_deception** | Web Cache Deception Detector |
| 21 | **jwt_analyzer** | Decode e análise de tokens JWT |
| 22 | **crlf_injection** | CRLF Injection Scanner |
| 23 | **insecure_deser** | Insecure Deserialization Checker |
| 24 | **ALL** | **Executa o fluxo completo (1-23)** |

---

## 📂 Estrutura de Saída

```
output/example.com/
├── report/           # Relatório HTML SPA moderno
├── domain/           # Subdomínios, DNS, IPs e Portas
├── urls/             # URLs descobertas e validadas
├── intelligence/     # Análise de risco e dicas de hacking
├── jsscanner/        # Extrações de chaves e rotas JS
├── sourcemaps/       # Código fonte reconstruído de maps
├── admin/            # Painéis de controle encontrados
├── depconfusion/     # Pacotes NPM vulneráveis
└── wordlist/         # Dicionários gerados para brute force
```

---

## 📋 Dependências Python

```
httpx, requests, beautifulsoup4, lxml, reportlab,
matplotlib, weasyprint, dnspython, aiohttp, aiofiles
```

---

## ⚠️ Disclaimer

Esta ferramenta é destinada exclusivamente para uso em **pentests autorizados** e **programas de bug bounty**. O uso indevido é de responsabilidade do usuário.
