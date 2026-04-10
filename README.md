# Enum-Allma V10.5 Pro Surgical ⚡

> **Ferramenta Profissional de Enumeração e Reconhecimento — Edição de Alta Precisão**
> *Professional Enumeration, Reconnaissance, and Surgical Security Analysis Tool*

Allma-Enum é uma suíte completa para pentest e bug bounty, focada em automação de reconhecimento profundo, descoberta de ativos e análise de vulnerabilidades com **precisão cirúrgica** (zero falsos positivos).

![Banner](https://img.shields.io/badge/Version-V10.5%20Pro-red)
![Status](https://img.shields.io/badge/Status-Surgical-success)
![Python](https://img.shields.io/badge/Python-3.9+-blue)

## 🚀 Capacidades da V10.5 Pro Surgical

A versão **V10.5 Pro** oferece um padrão de qualidade elitizado em ferramentas de bug bounty, orientando-se a evidências reais e algoritmos consolidados de bypass e detecção unificada:

- **🕷️ OSINT nativo**: Integração pre-vulnerabilidade via SpiderFoot, montando o contorno exato da inteligência de domínio antes dos testes.
- **📄 Extrema Precisão (SSTI & XXE)**: Payloads de OAST e numéricos sem ruídos. Checagem em tempo real de Cloudflare/WAFs e validação secundária para colisão numérica de SSTI.
- **☁️ Deduplicação Elegante de APIs (Secret Finder)**: TruffleHog unificado a Regex modulares, identificando com eficácia as credenciais únicas de Firebase, Cloud, AWS, GCP (sem alertar falsos clones).
- **🔀 Double-Check Core**: Validação secundária automática para Open Redirect e Prototype Pollution, garantindo uma detecção autêntica de Object overwrites.
- **🛡️ Stealth, Depth, e Anti-Timeout**: Tolerância impecável em escopos imensos (Sincronização correta GraphQL), fluxos nativos contra queda de sessão e uso das flags `--stealth` (slow) e `--deep` (API completas).
- **📊 Enriched Pipeline**: Dashboards profissionais renderizando 100% dos dados crudos (RAW HTTP) direto no output para todas as vulnerabilidades sem gargalos (Cache Deception, JWT Analisador).

---

## 🚀 Funcionalidades Principais (Core Features)

### 🌐 Reconhecimento de Inteligência (Recon & Crawling)
- **Multi-source Discovery**: Enumeração passiva/ativa avançada (`Subfinder`, `crt.sh`, `haktrails`, `Katana`) operando em cadeia com módulos OSINT e Google Dorks aperfeiçoados.
- **Headless Crawling**: Motor potente com integração tática de endpoints complexos de SPAs (React/Vue/Angular).
- **Port Scanning**: Roteamento rápido com Naabu e limites inteligentes de requests.
- **Fingerprinting**: Identificação profunda sem margem de erro.

### 🔍 Análise de Segurança Cirúrgica
### 🔍 Análise de Segurança Cirúrgica
- **OAST Centralizado**: Conexões integradas de `Interactsh` para falhas Out-of-Band Blind.
- **Advanced Secret Finder**: Verificação contínua de APIS e tokens, calculando entropia refinada para assegurar dados autênticos (com validação live interna).
- **Vast API Security**: Kiterunner e Introspecção densa GraphQL.
- **Cloud Recon**: Mapeamento limpo de S3/Azure/GCP expostos que cruzam as informações do alvo.
- **JWT & Deserializadores**: Plataformas focadas para auditoria em JWT estruturados com as devidas falhas de payload, e falhas de Insecure Deserialization.
- **🗺️ Source Maps**: Reconstrução imediata da branch JS de compilação.

---

## 🛠️ Instalação & Setup

### pré-requisitos
- Python 3.9+
- Go 1.19+

```bash
# Clone e Setup das Dependências Python
git clone https://github.com/AllisonMatos/allma-enum.git
cd allma-enum
pip install -r requirements.txt

# Verificação de Ferramentas Nativas
python3 check_install.py
```

> **Aviso Importante**: Bibliotecas (`httpx`, `aiohttp`, etc) são instaladas nativamente pelo `requirements.txt`. O arquivo **`check_install.py`** serve especificamente para validar quais ferramentas de Sistema Externo (como `katana`, `kiterunner`, `trufflehog`, `interactsh`...) estão instaladas no seu Linux/OS. Por favor, sempre verifique esse arquivo para saber quais utilitários binários ainda faltam instalar na sua máquina para que a ferramenta explore 100% de sua capacidade!

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
| 1-4 | **Discovery & OSINT** | Domínios, IPs, Portas, Dorks e Modelos de Inteligência Prévia |
| 5-8 | **Analysis** | JS Scanning Avançado, Source Maps e Integrações de Tecnologias |
| 9-25 | **Vulnerabilities** | XSS, XXE, Admin, Cache Deception, Insecure Deserialization, SSTI, Prototype Pollution, JWT Analyzer, CORS, OAuth, GraphQL |
| 26 | **ALL-IN-ONE** | Bateria autônoma de execução global limpa de todas as pontas |

---

## 📊 Relatórios Visuais & Profissionais (Web Dashboard)
O painel de monitoramento `report.html` com estética limpa padrão Dark Theme sem ruídos oferece:
- **Fluxo limpo sem emojis**: Visual moderno, ícones minimalistas e formato "bullet_points" idealizadas para auditores.
- **Timeline de Ataque**: Processamento linear direto via logs de OAST.
- **Burp-style Modal**: Visualizador em RAW autêntico (HTTP Headers & Corpo da Resposta) para uma checagem minuciosa em tempo real.
- **Expert Dicas**: Sugestões e tutoriais de Hacking em tempo de design integrados no dashboard.

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

**Enum-Allma V10.5 Pro Surgical: Precisão Total Garantida. 🛡️**
