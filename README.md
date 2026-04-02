# Enum-Allma V10.1 Pro Surgical ⚡

> **Ferramenta Profissional de Enumeração e Reconhecimento — Edição de Alta Precisão**
> *Professional Enumeration, Reconnaissance, and Surgical Security Analysis Tool*

Allma-Enum é uma suíte completa para pentest e bug bounty, focada em automação de reconhecimento, descoberta de ativos e análise de vulnerabilidades com **precisão cirúrgica** (zero falsos positivos).

![Banner](https://img.shields.io/badge/Version-V10.1%20Pro-red)
![Status](https://img.shields.io/badge/Status-Surgical-success)
![Python](https://img.shields.io/badge/Python-3.9+-blue)

## 🚀 Novidades da V10.1 Pro Surgical

A versão **V10.1 Pro** introduz um novo padrão de qualidade em ferramentas de bug bounty, focando em evidências reais e bypass de proteções modernas:

- **📄 XXE Pro**: Payloads Error-based e OAST com filtros automáticos contra Cloudflare e WAFs (403/405/429 bypass).
- **🏠 Host Header Surgical**: Blacklist inteligente de portas de painéis administrativos e detecção de Cache Poisoning/CRLF.
- **🔀 Open Redirect Double-Check**: Validação secundária automática que confirma o redirecionamento externo real antes de reportar.
- **🧬 Prototype Pollution Pro**: Detecção de sinks em lodash/Object.defineProperty com prova de conceito (Object overwrite) automática.
- **🛡️ Stealth & Depth**: Flags `--stealth` (delay de 0.6s/slow scan) e `--deep` (análise exaustiva de POST e APIs) integradas globalmente.
- **📊 Enriched Reporting**: Modal **Burp-style** reestruturado para exibir 100% do tráfego RAW (Request/Response) capturado em todos os achados.

---

## 🚀 Funcionalidades Principais (Core Features)

### 🌐 Reconhecimento & Crawling
- **Multi-source Discovery**: Enumeração passiva e ativa consolidada (`Subfinder`, `crt.sh`, `haktrails`, `Katana`).
- **Headless Crawling**: Motor Katana para renderização de SPAs (React/Vue/Angular) e descoberta de rotas ocultas.
- **Port Scanning**: Integração com Naabu para scans rápidos com rate-limit inteligente.
- **Fingerprinting**: Identificação profunda de stack tecnológica e versões de pacotes.

### 🔍 Análise de Segurança Cirúrgica
- **OAST (Blind Bugs)**: Integração centralizada com `Interactsh` para vulnerabilidades Out-of-Band.
- **Secret Finder**: Busca por API Keys e segredos em arquivos JS usando TruffleHog e Regex customizados.
- **API Security**: Fuzzing de rotas Kiterunner para descoberta de endpoints de API não documentados.
- **Cloud Recon**: Mapeamento de Buckets S3, Azure Blobs e GCP vinculados ao alvo.
- **JWT & GraphQL**: Suite completa para análise de tokens e introspecção de APIs modernas.
- **🗺️ Source Maps**: Reconstrução de código-fonte original a partir de arquivos `.map`.

---

## 🛠️ Instalação & Setup

### pré-requisitos
- Python 3.9+
- Go 1.19+

```bash
# Clone e Setup
git clone https://github.com/AllisonMatos/allma-enum.git
cd allma-enum
pip install -r requirements.txt
```

---

## 💻 Uso Profissional

### Modo Interativo
```bash
python3 menu.py
```

### Flags de Performance (V10.1)
- `--stealth`: Ativa o modo silencioso (delay global de 0.6s inter-threads).
- `--deep`: Ativa o modo intensivo (fuzzing em parâmetros POST e rotas profundas).

| ID | Módulo | Foco Principal |
|----|--------|----------------|
| 1-3 | **Discovery** | Domínios, IPs, Portas e Serviços |
| 5-7 | **Analysis** | JS Scanning, Tecnologias e API Mapping |
| 9-23 | **Vulnerabilities** | XSS, XXE, SSTI, Prototype Pollution, JWT, CORS, OAuth |
| 26 | **ALL-IN-ONE** | Fluxo completo automatizado com motor de inteligência |

---

## 📊 Relatórios & WebApp
O relatório interativo (`report.html`) e o Dashboard FastAPI oferecem:
- **Timeline de Ataque**: Visualização sequencial da execução dos plugins.
- **Burp-style Modal**: Clique em `View HTTP` para ver as provas base64 reais.
- **Expert Details**: Explicações técnicas e recomendações de mitigação para cada descoberta.

---

## 📂 Estrutura de Saída
```
output/alvo.com/
├── report/           # Relatório HTML Moderno
├── enriched_data.json # Dados consolidados V10.1 Pro
├── intelligence/     # Logs de OAST e Impact Score
├── urls/             # Endpoints validados e classificados
└── wordlist/         # Dicionários customizados gerados no scan
```

---

## ⚠️ Disclaimer
Uso exclusivo para fins de segurança defensiva, programas de Bug Bounty autorizados e Pentests profissionais. O autor não se responsabiliza pelo uso indevido da ferramenta.

**Enum-Allma V10.1 Pro Surgical: Precisão Total Garantida. 🛡️**
