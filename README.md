# Enum-Allma ⚡

> **Plataforma de Reconhecimento e Inteligência Ofensiva para Pentest & Bug Bounty**

Enum-Allma é uma suíte completa de automação para pentest e bug bounty, focada em reconhecimento profundo, descoberta de ativos, análise de vulnerabilidades e geração de relatórios interativos de alta qualidade.

![Version](https://img.shields.io/badge/Version-V11-red)
![Status](https://img.shields.io/badge/Status-Production-success)
![Python](https://img.shields.io/badge/Python-3.9+-blue)

---

## 🚀 Capacidades

- **27 módulos** de reconhecimento e análise de segurança em pipeline automatizado
- **OAST nativo** com Interactsh para detecção de falhas blind (SSRF, RCE, XXE out-of-band)
- **Relatório HTML interativo** com dashboard dark-mode, D3.js network graph, export CSV e resumo executivo
- **Scope enforcement** — filtra automaticamente URLs de domínios fora do escopo (SSO, CDN, analytics)
- **Custom User-Agent** — suporte a UA customizado para programas bug bounty (Bugcrowd, HackerOne)
- **Checkpoint/Resume** — retoma scans interrompidos sem re-executar módulos já completos
- **Intelligence Engine** — ranqueamento de alvos por exploitabilidade com Attack Priority e Quick Wins

---

## 🌐 Módulos

### Reconhecimento & Discovery
| # | Módulo | Descrição |
|---|--------|-----------|
| 1 | **domain** | Enumeração de subdomínios (Subfinder, crt.sh, haktrails, gau, waybackurls) + validação httpx + detecção de login pages |
| 2 | **urls** | Crawler multi-source (urlfinder, gau, waybackurls) + validação com scope filter |
| 3 | **services** | Port scanning (Naabu) + identificação de serviços (nmap -sV) |
| 4 | **files** | Classificação de arquivos sensíveis por extensão (.env, .sql, .bak, .zip) |
| 5 | **jsscanner** | Análise massiva de JS — extração de secrets, rotas API, tokens |
| 6 | **fingerprint** | Stack de tecnologias + certificados TLS (CN, SANs, expiração) |
| 7 | **endpoint** | Extração de endpoints API com filtro de extensões estáticas |
| 8 | **wordlist** | Geração de dicionários customizados do alvo para brute force |

### Análise de Segurança
| # | Módulo | Descrição |
|---|--------|-----------|
| 9 | **sourcemaps** | Caça source maps (.map) expostos em produção |
| 10 | **cve** | Lookup de CVEs via Searchsploit + NVD API |
| 11 | **admin** | Discovery de painéis admin (~80 paths) + bypass 403 + tags de categoria |
| 12 | **cors** | CORS Misconfiguration Scanner |
| 13 | **takeover** | Subdomain Takeover detection (AWS S3, Azure, GitHub Pages, Vercel) |
| 14 | **headers** | HTTP Security Headers grading (A-F) |
| 15 | **waf** | WAF Detection passivo (Cloudflare, Akamai, AWS WAF) |
| 16 | **emails** | Email Harvester passivo com classificação internal/external |
| 17 | **graphql** | Introspection + Batch Queries + Dangerous Mutations |
| 18 | **jwt_analyzer** | JWT Decoder + teste bypass alg:none |
| 19 | **api_fuzzer** | Fuzzer de endpoints API com Kiterunner |
| 20 | **cloud** | Cloud Storage Scanner (S3, Azure Blobs, GCP Buckets) |
| 21 | **host_header_injection** | Host Header Injection detection |
| 22 | **email_security** | SPF/DMARC/DKIM Check |
| 23 | **google_dorks** | Gerador de Google Dorks customizados |
| 24 | **cookies** | Análise de segurança de cookies (HttpOnly, Secure, SameSite) |
| 25 | **asn** | CIDR/ASN Mapping via Team Cymru DNS |
| 26 | **screenshots** | Captura visual de URLs via gowitness |
| 27 | **all** | Execução completa de todos os módulos |

### Pós-Scan
| Módulo | Descrição |
|--------|-----------|
| **intelligence** | Engine de ranqueamento: Attack Priority, Quick Wins, Knowledge Tips |
| **report** | Geração de relatório HTML interativo com dashboard completo |
| **diff** | Comparação entre scans para tracking de mudanças |

---

## 📊 Relatório Interativo

O dashboard HTML gerado automaticamente inclui:

- **Risk Assessment** — Score 0-100 com gauge visual e classificação (INFO → CRITICAL)
- **Network Graph** — Visualização D3.js interativa com zoom/drag (subdomínios, ASN, tecnologias)
- **Executive Summary** — Resumo automático dos achados para tomada de decisão
- **30+ seções** — Subdomínios, URLs, Portas, Keys, Admin Panels, CORS, Takeover, CVEs, JWT, GraphQL, etc.
- **Burp-style Modal** — Visualizador de requisições HTTP raw (request + response)
- **Export CSV** — Exportação de tabelas para análise externa
- **Sidebar navegável** — Acesso rápido a qualquer seção com badges de contagem

### Web Dashboard (Modo Servidor)
```bash
python3 core/webapp/server.py
# Acesse: http://127.0.0.1:5000
```

---

## 🛠️ Instalação

### Pré-requisitos
- Python 3.9+
- Go 1.19+ (para ferramentas ProjectDiscovery)
- Linux (Kali/Ubuntu recomendado)

```bash
# Clone
git clone https://github.com/AllisonMatos/allma-enum.git
cd allma-enum

# Dependências Python
pip install -r requirements.txt

# Verificar ferramentas do sistema
python3 check_install.py
```

> O `check_install.py` valida todas as ferramentas externas necessárias (katana, kiterunner, trufflehog, interactsh, gowitness, nmap, etc.) e oferece instalação automática das que faltam.

---

## 💻 Uso

### Modo Interativo
```bash
python3 menu.py
```

O menu interativo pergunta:
1. **Target** — domínio alvo (ex: `example.com`)
2. **Modo de escopo** — subdomínios automáticos ou lista fixa (closed-scope)
3. **User-Agent** — padrão (Chrome/124 com rotação) ou customizado (para bug bounty)
4. **Deep mode** — varredura profunda com fuzzing em parâmetros POST
5. **Stealth mode** — delay entre requests para evasão de WAF
6. **Exclude** — excluir hosts/patterns específicos do scan

### Flags de Performance
- `--deep`: Ativa modo intensivo (fuzzing POST, rotas profundas)
- `--stealth`: Ativa modo silencioso (delay 0.6s entre requests)
- `--exclude`: Exclui hosts/patterns específicos da pipeline

---

## 📂 Estrutura de Saída
```
output/target.com/
├── report/              # Relatório HTML interativo
├── domain/              # Subdomínios, login pages, DNS records
├── urls/                # URLs validadas (urls_200.txt)
├── services/            # Portas e serviços (nmap)
├── fingerprint/         # Stack tecnológico + TLS certs
├── admin/               # Painéis admin descobertos
├── intelligence/        # Attack Priority, Quick Wins, Knowledge Tips
├── asn/                 # CIDR/ASN mapping
├── screenshots/         # Capturas visuais
├── cookies/             # Análise de segurança de cookies
├── enriched_data.json   # Dados consolidados para report
├── plugin_timings.txt   # Tempo de execução de cada módulo
└── .checkpoint          # Estado do scan para resume
```

---

## ⚠️ Disclaimer

Uso exclusivo para fins de segurança defensiva, programas de Bug Bounty autorizados e Pentests profissionais com permissão explícita. O autor não se responsabiliza pelo uso indevido da ferramenta.

---

**Enum-Allma — Precisão. Inteligência. Resultados. 🛡️**
