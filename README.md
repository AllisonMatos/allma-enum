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
- **Multi-Crawler**: Integração com `Katana`, `Gospider` e `URLFinder` com progresso em tempo real.
- **Deep Discovery**: Recursividade inteligente para encontrar URLs escondidas.
- **Forms & Params**: Extração automática de formulários e parâmetros GET/POST para fuzzing.
- **News in Code**: Busca profunda por URLs dentro de arquivos JS e scripts inline.
- **Historical Discovery**: Coleta de URLs históricas via Wayback Machine e Common Crawl.

### 🔍 Análise de Segurança
- **Secret Finder**: Busca por chaves de API, tokens e credenciais vazadas em JS/HTML.
- **🆕 Token Validation**: Validação automática de tokens via API (GitHub, AWS, Google, Slack, Stripe, Twilio, SendGrid, JWT).
- **JS Analysis**: Extração de endpoints e rotas de arquivos JavaScript.
- **XSS Scanner**: Detecção de vulnerabilidades XSS.
- **CVE Detection**: Correlação de tecnologias detectadas com CVEs conhecidos.

### 🔑 Admin Panel Discovery
- **80+ paths comuns** testados (wp-admin, phpmyadmin, /admin, etc.).
- **15 portas alternativas** (8080, 8443, 9090, etc.).
- **CMS Fingerprinting**: WordPress, Joomla, Drupal, Laravel, Django, Jenkins, Grafana, etc.
- **Login Form Detection**: Identificação automática de formulários de login.

### ☁️ Cloud Security
- **Bucket Discovery**: Detecção de buckets S3, GCS e Azure.
- **🆕 Permission Testing**: Teste automático de permissões LIST/READ/WRITE em buckets (WRITE é opt-in).

### 📦 Dependency Confusion
- **Package Extraction**: Extrai nomes de pacotes de `require()` e `import` em arquivos JS.
- **Registry Check**: Verifica existência no npm público.
- **Risk Classification**: Pacotes não encontrados = HIGH risk (potencial supply chain attack).

### 📸 Visual Recon
- **Screenshots**: Captura automática de todas as URLs válidas com `gowitness`.
- **Gallery**: Galeria HTML para navegação visual.
- **Report Integration**: Screenshots inline no relatório por subdomínio.

### 📊 Relatórios Profissionais
- **Dashboard SPA**: Design moderno Dark Mode com navegação por abas.
- **15 seções**: Dashboard, Subdomains, DNS/IPs, Security, CVEs, Services, URLs, Keys, Endpoints, JS, Params, Cloud, Admin Panels, Dep Confusion, Files.
- **Login Flags**: Badge 🔑 LOGIN em subdomínios com páginas de login detectadas + screenshots.
- **Validation Badges**: ✓ VALIDATED / ✗ INVALID / ⊘ NOT TESTED para secrets encontrados.
- **Cloud Permissions**: Coluna de permissões nos buckets descobertos.
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

### Ferramentas Externas

**Obrigatórias:**
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/jaeles-project/gospider@latest
go install github.com/sensepost/gowitness@latest
```

**Opcionais (melhoram cobertura):**
```bash
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/hakluke/haktrails@latest
```

---

## 💻 Uso

```bash
python3 menu.py
```

### Módulos Disponíveis
| ID | Módulo | Descrição |
|----|--------|-----------|
| 1 | **domain** | Enumeração de subdomínios, DNS e portas |
| 2 | **urls** | Crawling profundo (Katana + URLFinder + Histórico) |
| 3 | **services** | Probing de serviços e Nmap |
| 4 | **files** | Busca por arquivos sensíveis |
| 5 | **jsscanner** | Análise estática de JavaScript |
| 6 | **fingerprint** | Identificação de Tech Stack |
| 7 | **endpoint** | Mapeamento de API |
| 8 | **wordlist** | Geração de wordlists customizadas |
| 9 | **xss** | Scan de XSS |
| 10 | **ALL** | **Executa o fluxo completo (Recomendado)** |

> Módulo "ALL" inclui automaticamente: visual (screenshots), CVE detection, admin panel discovery e dependency confusion.

---

## 📂 Estrutura de Saída

```
output/example.com/
├── report/           # Relatório HTML SPA
├── domain/           # Subdomínios, DNS, IPs e Portas
├── urls/             # URLs descobertas e validadas
├── crawlers/         # Katana, Gospider
├── keys/             # Secrets e tokens encontrados
├── jsscanner/        # Análise de arquivos JS
├── visual/           # Screenshots (gowitness)
├── admin/            # Admin panels descobertos
├── depconfusion/     # Dependency confusion results
└── cloud/            # Cloud buckets e permissões
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
