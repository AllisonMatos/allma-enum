# 🛠️ Ferramenta de Enumeração Passiva

**Coleta automática e passiva de informações sobre domínios, serviços, arquivos, endpoints e XSS.**

A ferramenta centraliza o fluxo completo de Recon Passivo em uma única aplicação modular, organizada por plugins independentes.

---

## 📦 Instalação

### **1. Clone o repositório**

```bash
git clone https://github.com/seu-usuario/seu-repo.git
cd seu-repo
```

### **2. (Opcional, mas recomendado) Crie um ambiente virtual**

```bash
python3 -m venv venv
source venv/bin/activate
```

### **3. Instale as dependências Python**

```bash
pip install -r requirements.txt
```

Dependências principais:

* **httpx**
* **requests**
* **beautifulsoup4**
* **reportlab** (geração automática do PDF final)
* **lxml**

---

## 🔧 Dependências externas obrigatórias

| Ferramenta                  | Uso                   | Instalação                                                         |
| --------------------------- | --------------------- | ------------------------------------------------------------------ |
| **subfinder**               | Coletar subdomínios   | `snap install subfinder --classic`                                 |
| **naabu**                   | Scan de portas        | `snap install naabu --classic`                                     |
| **httpx**                   | Verificação de URLs   | `go install github.com/projectdiscovery/httpx/v2/cmd/httpx@latest` |
| **nmap**                    | Detecção de serviços  | apt, pacman, brew                                                  |
| **urlfinder**               | Descoberta de URLs    | binário ProjectDiscovery                                           |
| **JSScanner.py** (opcional) | Scanner JS aprimorado | colocar em `tools/jsscanner/`                                      |

---

## 🚀 Execução

Para executar o menu principal:

```bash
python3 menu.py
```

Menu padrão:

```
1 - domain
2 - urls
3 - services
4 - files
5 - jsscanner
6 - fingerprint
7 - endpoint
8 - wordlist
9 - xss
10 - all
```

> Ao escolher qualquer plugin, ele executará automaticamente **as dependências anteriores**.
> Exemplo: escolher "services" = executa domain → urls → services.

---

# 📚 Descrição de Cada Plugin

Abaixo está a explicação completa de **cada módulo** e suas respectivas saídas.

---

# 1️⃣ DOMAIN

### Coleta inicial do Recon

✔ Subdomínios
✔ Varredura de portas
✔ Portas organizadas por host
✔ Construção de URLs
✔ Validação das URLs com httpx

### Saídas

`output/<alvo>/domain/`

| Arquivo          | Descrição                   |
| ---------------- | --------------------------- |
| `subdomains.txt` | Subdomínios encontrados     |
| `ports_raw.txt`  | Saída bruta do naabu        |
| `ports.txt`      | Portas organizadas por host |
| `urls.txt`       | URLs construídas            |
| `urls_valid.txt` | URLs válidas                |

---

# 2️⃣ URLS

### Descoberta de URLs internas e assets

✔ Captura via `urlfinder`
✔ Deduplica e normaliza
✔ Valida novamente via httpx

### Saídas

`output/<alvo>/urls/`

| Arquivo             | Descrição               |
| ------------------- | ----------------------- |
| `url_completas.txt` | URLs brutas encontradas |
| `urls_200.txt`      | URLs válidas            |

---

# 3️⃣ SERVICES

### Varredura profunda com Nmap

✔ Usa portas do módulo Domain
✔ Gera scans individuais
✔ Junta tudo em um único arquivo final

### Saídas

`output/<alvo>/services/`

| Arquivo           | Descrição     |
| ----------------- | ------------- |
| `scan_<host>.txt` | Scan por host |
| `scan_final.txt`  | Junção final  |

---

# 4️⃣ FILES

### Enumeração de arquivos por extensão

✔ Lê URLs válidas
✔ Extrai extensões automaticamente
✔ Agrupa em seções

### Saídas

`output/<alvo>/files/`

| Arquivo                  | Descrição                   |
| ------------------------ | --------------------------- |
| `files_by_extension.txt` | Arquivos separados por tipo |

---

# 5️⃣ JSSCANNER

### Análise avançada de arquivos JavaScript

✔ Extrai arquivos `.js`
✔ Executa JSScanner.py automaticamente (se existir)
✔ Caso contrário, baixa e analisa JS manualmente

### Saídas

`output/<alvo>/jsscanner/`

| Arquivo                | Descrição        |
| ---------------------- | ---------------- |
| `jsscanner_list.txt`   | JS identificados |
| `jsscanner_raw.txt`    | Conteúdo bruto   |
| `jsscanner_report.txt` | Relatório final  |

---

# 6️⃣ FINGERPRINT

### Fingerprinting de tecnologias

✔ Identifica tecnologias web
✔ Baseia-se na saída do httpx e headers

### Saídas

`output/<alvo>/fingerprint/`

| Arquivo    | Descrição              |
| ---------- | ---------------------- |
| `tech.txt` | Tecnologias detectadas |

---

# 7️⃣ ENDPOINT

### Coleta passiva de endpoints

✔ Procura padrões em HTML, JS e JSON
✔ Regexes para detectar APIs, rotas e funções expostas

### Saídas

`output/<alvo>/endpoint/`

| Arquivo         | Descrição                            |
| --------------- | ------------------------------------ |
| `endpoints.txt` | Lista única de endpoints encontrados |

---

# 8️⃣ WORDLIST

### Criação de wordlists customizadas

✔ Extrai palavras de páginas, arquivos e JS
✔ Remove stopwords
✔ Normaliza, limpa e organiza

### Saídas

`output/<alvo>/wordlist/`

| Arquivo        | Descrição      |
| -------------- | -------------- |
| `wordlist.txt` | Wordlist final |

---

# 9️⃣ XSS

### Scanner Passivo de XSS (sem payloads)

✔ Detecta reflexões
✔ Analisa DOM e Inline Scripts
✔ Crawling leve
✔ Baixa e inspeciona JS externos

### Saídas

`output/<alvo>/xss/`

| Arquivo            | Descrição               |
| ------------------ | ----------------------- |
| `parameters.txt`   | Parâmetros detectados   |
| `reflections.txt`  | Possíveis reflected XSS |
| `dom_suspects.txt` | DOM-dangerous patterns  |
| `js_suspects.txt`  | JS suspeito             |
| `final_report.txt` | Sumário                 |

---

# 🔟 ALL

Executa todos os plugins automaticamente:

```
domain → urls → services → files → jsscanner → fingerprint → endpoint → wordlist → xss → report
```

---

# 🧾 Relatório Final (PDF Automático)

Ao final da execução do pipeline completo, um PDF profissional é gerado automaticamente.

Local:

```
output/<alvo>/report/report.pdf
```

Conteúdo:

* Sumário geral
* Gráficos profissionais (subdomínios, portas, tecnologias)
* Tabelas completas (URLs, serviços, endpoints)
* Listas de arquivos
* Resultados do JSScanner
* Suspeitas de XSS

---

# 🗂️ Estrutura Final do Projeto

```
output/<target>/
 ├── domain/
 ├── urls/
 ├── services/
 ├── files/
 ├── jsscanner/
 ├── fingerprint/
 ├── endpoint/
 ├── wordlist/
 ├── xss/
 └── report/
```
