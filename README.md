# Enum-Allma ⚡

> **Ferramenta Profissional de Enumeração e Reconhecimento**
> *Enumeration, Reconnaissance, and Deep Analysis Tool*

Allma-Enum é uma suíte completa para pentest e bug bounty, focada em automação de reconhecimento, descoberta de ativos e geração de relatórios profissionais.

![Banner](https://img.shields.io/badge/Status-Active-success)
![Python](https://img.shields.io/badge/Python-3.9+-blue)

## 🚀 Funcionalidades (Features)

### 🌐 Reconhecimento de Domínio
- **Subdomínios**: Enumeração passiva e ativa.
- **Portas**: Scan rápido com `Naabu` (Top 100, 1000 ou Full).
- **Fingerprinting**: Identificação de tecnologias e serviços.

### 🔗 Crowling & Discovery Avançado
- **Multi-Crawler**: Integração com `Katana` e `Gospider`.
- **Deep Discovery**: Recursividade inteligente para encontrar URLs escondidas.
- **Forms & Params**: Extração automática de formulários e parâmetros GET/POST para fuzzing.
- **News in Code**: Busca profunda por URLs dentro de arquivos JS e scripts inline.

### 🔍 Análise de Segurança
- **Secret Finder**: Busca por chaves de API, tokens e credenciais vazadas em JS/HTML.
- **JS Analysis**: Extração de endpoints e rotas de arquivos JavaScript.
- **Vulnerabilidades**: Verificação básica de misconfigs.

### 📊 Relatórios Profissionais 
Gera relatórios HTML visuais, interativos e prontos para apresentar a clientes ou time técnico.
- **6 Estilos Disponíveis**:
  - *Modern SaaS*, *Corporate Admin*, *Material Design* (Estilo Website).
  - *Dark Data-Dense*, *Notion Style*, *Cyber-Professional* (Estilo Técnico).
- **Dashboard Interativo**: Gráficos, abas e filtros.
- **Export**: Dados brutos também salvos em JSON/TXT.

---

## 🛠️ Instalação

### Pré-requisitos
- Python 3.9+
- Go (para ferramentas externas como Naabu/Katana)

### Setup

```bash
# Clone o repositório
git clone https://github.com/AllisonMatos/allma-enum.git
cd allma-enum

# Instale as dependências Python
pip install -r requirements.txt

# Verifique o ambiente (instala ferramentas faltantes)
python3 check_install.py
```

---

## 💻 Uso

A ferramenta possui um menu interativo para facilitar a execução.

```bash
python3 menu.py
```

### Módulos Disponíveis
| ID | Módulo | Descrição |
|----|--------|-----------|
| 1 | **domain** | Enumeração de subdomínios e portas |
| 2 | **urls** | Crawling profundo (Katana + Customs) |
| 3 | **services** | Probing de serviços e Nmap |
| 4 | **files** | Busca por arquivos sensíveis |
| 5 | **jsscanner** | Análise estática de JavaScript |
| 6 | **fingerprint** | Identificação de Tech Stack |
| 7 | **endpoint** | Mapeamento de API |
| 8 | **wordlist** | Geração de wordlists customizadas |
| 9 | **xss** | Scan básico de XSS |
| 10 | **ALL** | **Executa o fluxo completo (Recomendado)** |

---

## 📂 Estrutura de Saída

Os resultados são salvos em `output/<target>/`:

```
output/example.com/
├── report/           # Relatórios HTML (CyberPro, Notion, etc)
├── domain/           # Subdomínios, IPs e Portas
├── crawlers/         # URLs descobertas (Katana, Gospider)
├── keys/             # Segredos e Keys encontrados
├── jsscanner/        # Análise de arquivos JS
└── ...
```
