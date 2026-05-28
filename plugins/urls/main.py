#!/usr/bin/env python3
"""
plugins/urls/main.py - Coleta URLs a partir das URLs válidas do módulo domain
e valida novamente com httpx.

Saídas principais:
  output/<target>/urls/url_completas.txt   — todas as URLs dedupadas in-scope (pré-httpx)
  output/<target>/urls/urls_200.txt        — apenas 2xx (superfície viva; compatível com plugins)
  output/<target>/urls/urls_alive.txt      — cópia explícita das 2xx
  output/<target>/urls/urls_protected.txt  — 401/403/405
  output/<target>/urls/urls_dead.txt       — 404/410/5xx
  output/<target>/urls/urls_all.json       — registro completo por URL (status, title, content-type, …)
  output/<target>/urls/data_quality.json   — métricas de higiene do scan
"""

import shutil
from pathlib import Path
import subprocess

from menu import C
from plugins import ensure_outdir

from ..output import info, success, warn, error
from .utils import require_binary
WANT_STATUS = "200,201,204,301,302,303,307,308,401,403,404,405,500"

STATIC_PATH_SUFFIXES = (
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2",
    ".ttf", ".eot", ".map", ".pdf", ".zip",
)


def _path_only(url: str) -> str:
    from urllib.parse import urlparse
    try:
        return (urlparse(url).path or "").split("?")[0].lower()
    except Exception:
        return ""


def _is_static_path(url: str) -> bool:
    p = _path_only(url)
    return any(p.endswith(s) for s in STATIC_PATH_SUFFIXES)


def smart_normalize_urls(urls: list[str]) -> list[str]:
    """
    Use unfurl + uro when available for smarter URL normalization/dedup.
    Falls back to plain set-based dedup.
    """
    normalized = sorted(set(u.strip() for u in urls if u and u.strip()))
    if not normalized:
        return normalized

    uro = shutil.which("uro")
    unfurl = shutil.which("unfurl")
    if not uro and not unfurl:
        return normalized

    temp_in = Path("/tmp/enum_allma_urls_raw.txt")
    temp_out = Path("/tmp/enum_allma_urls_norm.txt")
    try:
        temp_in.write_text("\n".join(normalized) + "\n", encoding="utf-8")
        current = temp_in.read_text(encoding="utf-8")

        # First unfurl to keep canonical URL paths when tool is present.
        if unfurl:
            p = subprocess.run([unfurl, "format", "%s://%d%p?%q"], input=current, text=True, capture_output=True, timeout=120)
            if p.returncode == 0 and p.stdout.strip():
                current = p.stdout

        # Then uro for URL canonical dedup.
        if uro:
            p = subprocess.run([uro], input=current, text=True, capture_output=True, timeout=120)
            if p.returncode == 0 and p.stdout.strip():
                temp_out.write_text(p.stdout, encoding="utf-8")
                return sorted(set(l.strip() for l in temp_out.read_text(encoding="utf-8").splitlines() if l.strip()))
    except Exception:
        return normalized
    finally:
        temp_in.unlink(missing_ok=True)
        temp_out.unlink(missing_ok=True)
    return normalized


# ============================================================
# Validação com httpx + buckets (V12)
# ============================================================
def httpx_validate(
    in_file: Path,
    out_file: Path,
    *,
    target: str,
    scope_root: str,
    want_status: str = WANT_STATUS,
) -> list[str]:
    from core.config import is_in_scope
    import json as _json

    info(f"{C.BOLD}{C.BLUE}🔎 Validando URLs com httpx (mc={want_status})...{C.END}")

    httpx = require_binary("httpx")
    json_out_file = out_file.with_suffix(".json")
    outdir = out_file.parent
    urls_all_path = outdir / "urls_all.json"

    cmd = [
        httpx,
        "-l", str(in_file),
        "-mc", want_status,
        "-threads", "100",
        "-retries", "1",
        "-timeout", "10",
        "-random-agent",
        "-no-color",
        "-follow-redirects",
        "-json",
        "-sc",
        "-title",
        "-ct",
        "-location",
        "-o", str(json_out_file),
        "-silent",
    ]

    from core.timeouts import HTTPX_TIMEOUT

    info(f"   CMD: {' '.join(cmd)}")

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=HTTPX_TIMEOUT)

    if result.stderr:
        stderr_clean = result.stderr.strip()[:500]
        if stderr_clean:
            warn(f"httpx stderr: {stderr_clean}")

    if result.returncode != 0:
        warn(f"httpx exit code: {result.returncode}")

    if not json_out_file.exists() or json_out_file.stat().st_size == 0:
        warn("⚠️ httpx -o produziu arquivo vazio. Tentando via pipe...")
        cmd_pipe = [c for c in cmd if c not in ("-o", str(json_out_file))]
        result2 = subprocess.run(cmd_pipe, capture_output=True, text=True, timeout=HTTPX_TIMEOUT)
        if result2.stdout and result2.stdout.strip():
            json_out_file.write_text(result2.stdout)
            info("   ✅ Fallback via pipe funcionou!")
        else:
            if result2.stderr:
                warn(f"httpx pipe stderr: {result2.stderr.strip()[:300]}")
            warn("⚠️ Nenhuma resposta httpx.")
            return []

    def _to_int(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0

    all_rows = []
    dropped_oos = 0

    for line in json_out_file.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = _json.loads(line)
        except _json.JSONDecodeError:
            if line.startswith("http"):
                all_rows.append({
                    "url": line,
                    "input": line,
                    "final_url": line,
                    "status_code": 0,
                    "content_type": "",
                    "title": "",
                    "location": "",
                    "source": "httpx-raw-line",
                    "scope_status": "unknown",
                })
            continue

        url = (obj.get("url") or obj.get("input") or "").strip()
        if not url:
            continue
        if not is_in_scope(url, target, scope_root):
            dropped_oos += 1
            continue

        sc = _to_int(obj.get("status_code", obj.get("status-code")))
        final_u = (obj.get("final_url") or url).strip()
        row = {
            "url": url,
            "input": (obj.get("input") or url).strip(),
            "final_url": final_u,
            "status_code": sc,
            "content_type": (obj.get("content_type") or obj.get("content-type") or "").strip(),
            "title": (obj.get("title") or "").strip()[:300],
            "location": (obj.get("location") or "").strip(),
            "source": "httpx",
            "scope_status": "in_scope",
            "chain": obj.get("chain") or obj.get("chain_status_codes") or [],
        }
        all_rows.append(row)

    # Dedup por URL mantendo o pior status (maior) para diagnóstico
    by_url: dict = {}
    for r in all_rows:
        u = r["url"]
        if u not in by_url or r["status_code"] > by_url[u]["status_code"]:
            by_url[u] = r

    deduped = sorted(by_url.values(), key=lambda x: x["url"])
    urls_all_path.write_text(_json.dumps(deduped, indent=2, ensure_ascii=False))

    alive, protected, dead, assets = [], [], [], []
    for r in deduped:
        u = r["url"]
        sc = r["status_code"]
        if _is_static_path(u):
            assets.append(u)
        if 200 <= sc <= 299:
            alive.append(u)
        elif sc in (401, 403, 405):
            protected.append(u)
        elif sc == 404 or sc == 410 or sc >= 500:
            dead.append(u)

    alive = sorted(set(alive))
    protected = sorted(set(protected))
    dead = sorted(set(dead))
    assets = sorted(set(assets))

    out_file.write_text("\n".join(alive) + ("\n" if alive else ""))
    (outdir / "urls_alive.txt").write_text("\n".join(alive) + ("\n" if alive else ""))
    (outdir / "urls_protected.txt").write_text("\n".join(protected) + ("\n" if protected else ""))
    (outdir / "urls_dead.txt").write_text("\n".join(dead) + ("\n" if dead else ""))
    (outdir / "urls_assets.txt").write_text("\n".join(assets) + ("\n" if assets else ""))

    # Retrocompat: urls_200.json com todos os in-scope sondados (mapa de status no report)
    slim = [{"url": r["url"], "status_code": r["status_code"], "final_url": r["final_url"], "title": r["title"]} for r in deduped]
    json_out_file.write_text(_json.dumps(slim, indent=2, ensure_ascii=False))

    # V12: Heuristic login detection based on title, final_url, and SPA inference
    login_keywords = ["login", "signin", "sign in", "sign-in", "logon", "autentica", "auth", "sso"]
    login_pages = []
    login_pages_file = outdir.parent / "domain" / "login_pages.txt"
    if login_pages_file.exists():
        login_pages.extend([l.strip() for l in login_pages_file.read_text(errors="ignore").splitlines() if l.strip()])
        
    # Phase 1: Direct keyword match on title/final_url
    for r in deduped:
        u = r["url"]
        if _is_static_path(u):
            continue
        title_lower = r["title"].lower()
        final_lower = r["final_url"].lower()
        if any(k in title_lower for k in login_keywords) or any(f"/{k}" in final_lower for k in login_keywords) or any(f"{k}=" in final_lower for k in login_keywords):
            login_pages.append(u)
    
    # Phase 2: SPA inference — if host has /api/signin, /signin, /login endpoint,
    # then the base URL of that host is also a login page (JS-redirect pattern)
    from urllib.parse import urlparse as _lp
    hosts_with_auth_endpoints = set()
    for r in deduped:
        path_lower = _lp(r["url"]).path.lower()
        if any(f"/{k}" in path_lower for k in ["signin", "login", "logon", "auth", "sign-in"]):
            host = _lp(r["url"]).netloc
            hosts_with_auth_endpoints.add(host)
    
    # Add base URLs for hosts that have auth endpoints
    for r in deduped:
        parsed = _lp(r["url"])
        if parsed.netloc in hosts_with_auth_endpoints and parsed.path in ("", "/") and r["status_code"] == 200:
            if r["url"] not in login_pages:
                login_pages.append(r["url"])

    # Phase 3: HTTP 401 Unauthorized (Basic Auth / Bearer)
    for r in deduped:
        if r.get("status_code") == 401:
            login_pages.append(r["url"])
            
    if login_pages:
        login_pages_file.parent.mkdir(parents=True, exist_ok=True)
        # Merge com dados existentes preservando case e preferindo https
        final_logins = {}
        if login_pages_file.exists():
            for l in login_pages_file.read_text(errors="ignore").splitlines():
                clean = l.strip()
                if not clean: continue
                key = clean.lower().rstrip("/").replace("https://", "").replace("http://", "")
                final_logins[key] = clean
                
        for lp in login_pages:
            clean = lp.strip()
            if not clean: continue
            key = clean.lower().rstrip("/").replace("https://", "").replace("http://", "")
            
            if key not in final_logins:
                final_logins[key] = clean
            else:
                if clean.startswith("https://") and final_logins[key].startswith("http://"):
                    final_logins[key] = clean
                    
        login_pages_file.write_text("\n".join(sorted(final_logins.values())) + "\n")

    dq = {
        "target": target,
        "scope_root": scope_root,
        "httpx_match_codes": want_status,
        "probed_in_scope": len(deduped),
        "dropped_out_of_scope": dropped_oos,
        "alive_2xx": len(alive),
        "protected_401_403_405": len(protected),
        "dead_404_410_5xx": len(dead),
        "static_paths_detected": len(assets),
    }
    (outdir / "data_quality.json").write_text(_json.dumps(dq, indent=2, ensure_ascii=False))

    success(f"✨ {len(alive)} URLs vivas (2xx) → {C.GREEN}{out_file}{C.END}")
    success(f"   🛡️  Protegidas (401/403/405): {len(protected)} | 💀 Mortas (404/410/5xx): {len(dead)}")
    success(f"   📊 Metadados: {C.GREEN}{urls_all_path}{C.END}")
    return alive


# ============================================================
# Coleta Histórica (gauplus / gau / waybackurls / waymore)
# ============================================================
def run_historical_discovery(target: str, out_file: Path):
    """
    Executa gauplus/gau/waybackurls e complementa com waymore se disponível.
    """
    info(f"{C.BOLD}{C.BLUE}🕰️ Iniciando descoberta de URLs históricas...{C.END}")
    
    gauplus = shutil.which("gauplus")
    gau = shutil.which("gau")
    waybackurls = shutil.which("waybackurls")
    tool = gauplus or gau or waybackurls
    
    if not tool:
        warn("⚠️ Nenhuma ferramenta base (gauplus/gau/waybackurls) encontrada. Tentando apenas waymore se existir.")
    else:
        tool_name = Path(tool).name
        info(f"   🛠️ Usando ferramenta: {C.YELLOW}{tool_name}{C.END}")
        
        cmd = [tool]
        if "gau" in tool_name:
            cmd.extend([target, "-t", "10"])
            
        try:
            with out_file.open("w", encoding="utf-8", errors="ignore") as fout:
                if "waybackurls" in tool_name:
                    subprocess.run(cmd, input=target.encode(), stdout=fout, stderr=subprocess.DEVNULL, timeout=600)  # V11: 10min
                else:
                    subprocess.run(cmd, stdout=fout, stderr=subprocess.DEVNULL, timeout=600)  # V11: 10min
        except Exception as e:
            error(f"Erro na coleta histórica ({tool_name}): {e}")

    # Executar waymore como suplemento se existir
    waymore = shutil.which("waymore")
    if waymore:
        info(f"   🛠️ Coletando extras com: {C.YELLOW}waymore{C.END}")
        waymore_out = out_file.with_name("waymore_temp.txt")
        cmd_wm = [waymore, "-i", target, "-mode", "U", "-oU", str(waymore_out)]
        try:
            subprocess.run(cmd_wm, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600)
            if waymore_out.exists() and waymore_out.stat().st_size > 0:
                with out_file.open("a", encoding="utf-8", errors="ignore") as fout:
                    fout.write("\n" + waymore_out.read_text(errors="ignore"))
                waymore_out.unlink(missing_ok=True)
        except Exception as e:
            error(f"Erro no waymore: {e}")

    # Limpar duplicatas e retornar
    if out_file.exists() and out_file.stat().st_size > 0:
        raw_urls = [l.strip() for l in out_file.read_text(errors="ignore").splitlines() if l.strip()]
        urls = smart_normalize_urls(raw_urls)
        out_file.write_text("\n".join(urls) + "\n", encoding="utf-8")
        success(f"📜 {len(urls)} URLs históricas consolidadas salvas em: {C.GREEN}{out_file.name}{C.END}")
        return urls
        
    return []


# ============================================================
# Coleta Ativa (Katana Headless)
# ============================================================
def run_katana_discovery(target: str, out_file: Path, scope_root: str | None = None):
    """
    Executa katana para crawling ativo profundo e headless mode.
    """
    info(f"{C.BOLD}{C.BLUE}🕷️ Iniciando crawling ativo extremo com Katana...{C.END}")
    katana = shutil.which("katana")
    if not katana:
        warn("⚠️ 'katana' não encontrado no sistema. Pulando crawling ativo.")
        return []
        
    cmd = [
        katana,
        "-u", f"https://{target}",
        "-jc", "-jsl",   # Parse JS (Static + Dynamic)
        "-kf", "all",    # Known files (robots, sitemaps)
        "-aff",          # Form fill (Critical for params)
        "-fx",           # Extract from JSON/XML
        "-hl",           # Headless browser
        "-d", "2",       # Max depth 2
        "-ef", "css,png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot", # Filter garbage
        "-ct", "180",    # 3 min total crawl timeout
        "-retry", "2",   # Retry logic
        "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "-j",            # Output as JSONL
        "-silent",
        "-o", str(out_file)
    ]
    
    try:
        from core.timeouts import smart_wait_process, KATANA_HARD_TIMEOUT, STALE_TIMEOUT
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        smart_wait_process(
            proc, out_file,
            hard_timeout=KATANA_HARD_TIMEOUT,
            stale_timeout=STALE_TIMEOUT,
            label="Katana (urls)"
        )
        
    except Exception as e:
        error(f"Erro inesperado no Katana: {e}")
        
    # Mesmo com timeout ou erro, verificamos se o arquivo de output tem dados salvos parcialmentes
    if out_file.exists() and out_file.stat().st_size > 0:
        from core.config import is_in_scope
        import json
        sr = scope_root or target
        
        found_urls = set()
        forms = []
        params_list = []
        
        try:
            for line in out_file.read_text(errors="ignore").splitlines():
                if not line.strip(): continue
                try:
                    data = json.loads(line)
                    u = data.get("request", {}).get("endpoint") or data.get("request", {}).get("url")
                    if u and is_in_scope(u, target, sr):
                        found_urls.add(u)
                        
                    # Extract forms for report
                    if data.get("response", {}).get("forms"):
                        for f in data["response"]["forms"]:
                            f["source"] = u
                            forms.append(f)
                            
                    # Extract params for intelligence
                    if data.get("request", {}).get("params"):
                        params_list.append({
                            "url": u,
                            "params": data["request"]["params"]
                        })
                except Exception:
                    # Fallback if line is not JSON
                    if is_in_scope(line.strip(), target, sr):
                        found_urls.add(line.strip())
            
            # Save rich data for report (in urls folder)
            outdir = out_file.parent
            if forms:
                (outdir / "katana_forms_all.json").write_text(json.dumps(forms, indent=2))
            if params_list:
                (outdir / "katana_params_all.json").write_text(json.dumps(params_list, indent=2))
                
        except Exception as e:
            warn(f"   Erro ao processar JSON da Katana: {e}")
            
        found = sorted(list(found_urls))
        success(f"   🕷️  {len(found)} URLs recuperadas do Katana (crawling ativo - In-Scope).")
        return found
            
    return []

# ============================================================
# Coleta Parametrizada (ParamSpider)
# ============================================================
def run_paramspider_discovery(target: str, out_file: Path, scope_root: str | None = None):
    """Executa ParamSpider para descobrir URLs ricas em parâmetros."""
    info(f"{C.BOLD}{C.BLUE}🕷️ Iniciando descoberta de parâmetros com ParamSpider...{C.END}")
    paramspider = shutil.which("paramspider") or shutil.which("ParamSpider")
    
    if not paramspider and Path("/home/allma/.local/bin/paramspider").exists():
        paramspider = "/home/allma/.local/bin/paramspider"
        
    if not paramspider:
        warn("⚠️ 'paramspider' não encontrado. Pulando descoberta.")
        return []
        
    cmd = [paramspider, "-d", target]
    
    try:
        # A maioria das versões do paramspider redireciona a saída padrão ou possui flag -o
        # Vamos rodar no dirtório temp e salvar saída bruta
        with out_file.open("w", encoding="utf-8", errors="ignore") as fout:
            subprocess.run(cmd, stdout=fout, stderr=subprocess.DEVNULL, timeout=600)
    except subprocess.TimeoutExpired:
        warn(f"   [!] ParamSpider atingiu o timeout. Processando o que foi encontrado...")
    except Exception as e:
        error(f"Erro inesperado no ParamSpider: {e}")
        
    # Verificar caminhos comuns de output do paramspider que podem não ter ido pro stdout
    results_file = Path("results") / f"{target}.txt"
    if results_file.exists() and results_file.stat().st_size > 0:
        with out_file.open("a", encoding="utf-8") as fout:
            fout.write("\n" + results_file.read_text(errors="ignore"))
        results_file.unlink(missing_ok=True)
        
    if out_file.exists() and out_file.stat().st_size > 0:
        from core.config import is_in_scope
        sr = scope_root or target
        # V11: Filtro mais preciso — exige que a URL comece com http (evita substrings)
        found = [
            l.strip()
            for l in out_file.read_text(errors="ignore").splitlines()
            if l.strip() and l.strip().startswith("http") and is_in_scope(l.strip(), target, sr)
        ]
        # Rewrite limpo
        out_file.write_text("\n".join(found))
        success(f"   🕷️  {len(found)} URLs com parâmetros recuperadas.")
        return found
            
    return []


# ============================================================
# MAIN
# ============================================================
def run(context: dict):
    target = context.get("target")

    if not target:
        raise ValueError("context['target'] é obrigatório para o plugin urls")

    scope_root = (context.get("scope_root") or target).strip()

    # ============================================================
    # 🎯 CABEÇALHO PREMIUM
    # ============================================================
    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   🔗 {C.BOLD}{C.CYAN}INICIANDO MÓDULO: URLS{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    outdir = ensure_outdir(target, "urls")
    url_completas = outdir / "url_completas.txt"
    urls_200 = outdir / "urls_200.txt"

    # ============================================================
    # ETAPA 1 — Coletar URLs de múltiplas fontes
    # ============================================================
    info(f"{C.BOLD}{C.BLUE}📄 Coletando URLs de múltiplas fontes do pipeline...{C.END}")

    # Fonte 1: URLs validadas do DOMAIN
    domain_200 = Path("output") / target / "domain" / "urls_valid.txt"
    
    # Fonte 2: URLs HTTP descobertas pelo SERVICES (Nmap)
    services_http = Path("output") / target / "services" / "http_urls.txt"
    
    # Fonte 3: URLs descobertas pelo Katana (crawling do DOMAIN)
    katana_valid = Path("output") / target / "domain" / "katana_valid.txt"
    
    # Fonte 4: URLs descobertas inline pelo DOMAIN
    discovered_urls = Path("output") / target / "domain" / "discovered_urls.txt"

    # Coletar todas as seeds
    seed_urls = set()
    sources_found = []
    
    for source_name, source_path in [
        ("domain/urls_valid.txt", domain_200),
        ("services/http_urls.txt", services_http),
        ("domain/katana_valid.txt", katana_valid),
        ("domain/discovered_urls.txt", discovered_urls),
    ]:
        if source_path.exists():
            urls = [l.strip() for l in source_path.read_text(errors="ignore").splitlines() if l.strip()]
            if urls:
                seed_urls.update(urls)
                sources_found.append(f"{source_name} ({len(urls)} URLs)")
                info(f"   ✅ {C.GREEN}{source_name}{C.END}: {len(urls)} URLs")
        else:
            info(f"   ⚠️ {C.YELLOW}{source_name}{C.END}: não encontrado (opcional)")

    if not seed_urls:
        error(f"❌ Nenhuma URL seed encontrada de nenhuma fonte!")
        return []
    
    # V11: Scope enforcement — filtrar URLs fora do escopo
    from core.config import is_in_scope
    before_scope = len(seed_urls)
    seed_urls = {u for u in seed_urls if is_in_scope(u, target, scope_root)}
    filtered_out = before_scope - len(seed_urls)
    if filtered_out > 0:
        warn(f"   🔒 Scope filter: removidas {filtered_out} URLs fora do escopo ({scope_root})")
        
    info(f"   📊 {C.CYAN}Total de seeds (in-scope): {len(seed_urls)}{C.END}")

    # limpar arquivo anterior
    if url_completas.exists():
        url_completas.unlink()

    # ============================================================
    # ETAPA 1.5 — Filtrar URLs estáticas (Otimização)
    # ============================================================
    info(f"{C.BOLD}{C.BLUE}🧹 Filtrando arquivos estáticos para otimizar urlfinder...{C.END}")
    
    # Extensões para ignorar no urlfinder (crawling)
    # O usuário pediu especificamente para ignorar JS, mas adicionamos outras estáticas
    ignored_exts = {
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", 
        ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf", ".zip", 
        ".rar", ".tar", ".gz", ".7z", ".xml", ".txt", ".json"
    }
    
    urls_to_scan = []
    skipped_count = 0
    
    for line in seed_urls:
        # Verificar extensão na URL (ignorando query params)
        path = line.split("?")[0].lower()
        if any(path.endswith(ext) for ext in ignored_exts):
            skipped_count += 1
            continue
            
        urls_to_scan.append(line)
            
    urls_filtered_file = outdir / "urls_for_urlfinder.txt"
    urls_filtered_file.write_text("\n".join(urls_to_scan))
    
    info(f"   URLs totais de seeds: {len(seed_urls)}")
    info(f"   URLs ignoradas: {skipped_count} (arquivos estáticos/js)")
    info(f"   URLs para scan: {len(urls_to_scan)}")

    # ============================================================
    # ETAPA 2 — Executar urlfinder
    # ============================================================
    
    # Deduplica por base URL (scheme+host) — urlfinder crawla a partir do domínio
    from urllib.parse import urlparse as _urlparse
    base_seeds = set()
    for u in urls_to_scan:
        try:
            p = _urlparse(u)
            base = f"{p.scheme}://{p.netloc}"
            base_seeds.add(base)
        except Exception:
            pass
    
    urlfinder_seeds = sorted(base_seeds)
    info(f"{C.BOLD}{C.BLUE}🌐 Coletando URLs com urlfinder ({len(urlfinder_seeds)} hosts únicos, de {len(urls_to_scan)} seeds)...{C.END}")

    urlfinder = require_binary("urlfinder")
    
    import time as _time
    import tempfile as _tempfile
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import os

    # Parallelize urlfinder execution
    # Run 5 concurrent urlfinder instances, each handling a batch
    CONCURRENT_WORKERS = 5
    BATCH_SIZE = 50
    total_seeds = len(urlfinder_seeds)
    url_count = 0
    start_time = _time.time()
    
    def process_batch(batch_seeds):
        """Runs urlfinder for a batch of seeds and returns unique URLs found."""
        if not batch_seeds:
            return []

        found_lines = []
        temp_in = None
        try:
            # Input file for this batch
            fd_in, temp_in = _tempfile.mkstemp(suffix=".txt", text=True)
            with os.fdopen(fd_in, 'w') as f:
                f.write("\n".join(batch_seeds) + "\n")

            # Run urlfinder
            cmd = [urlfinder, "-list", temp_in, "-silent", "-timeout", "10"]
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=300
            )

            if proc.stdout:
                found_lines = [l for l in proc.stdout.splitlines() if l.strip()]

        except Exception:
            pass
        finally:
            # V11: Proteger contra UnboundLocalError se mkstemp falhar
            if temp_in and os.path.exists(temp_in):
                os.unlink(temp_in)

        return found_lines

    try:
        # Generate batches
        batches = []
        for i in range(0, total_seeds, BATCH_SIZE):
            batches.append(urlfinder_seeds[i:i + BATCH_SIZE])
            
        info(f"   🚀 Iniciando {len(batches)} lotes com {CONCURRENT_WORKERS} workers paralelos...")

        with url_completas.open("w", encoding="utf-8", errors="ignore") as fout:
            with ThreadPoolExecutor(max_workers=CONCURRENT_WORKERS) as executor:
                futures = {executor.submit(process_batch, batch): idx for idx, batch in enumerate(batches)}
                
                completed = 0
                for future in as_completed(futures):
                    completed += 1
                    batch_idx = futures[future]
                    try:
                        results = future.result()
                        # Write immediately to file
                        for line in results:
                            fout.write(line + "\n")
                        
                        url_count += len(results)
                        
                        # Progress log
                        elapsed = _time.time() - start_time
                        pct = int(completed / len(batches) * 100)
                        
                         # Estimar tempo
                        if completed > 0:
                            avg_time_per_batch = elapsed / completed
                            remaining_batches = len(batches) - completed
                            eta_secs = avg_time_per_batch * remaining_batches
                            eta_mins = int(eta_secs // 60)
                            eta_s = int(eta_secs % 60)
                            eta_str = f" | ETA ~{eta_mins}m{eta_s:02d}s"
                        else:
                            eta_str = ""

                        # Log only every few batches to avoid clutter if fast, or always if slow
                        print(f"   ⏳ urlfinder: {completed}/{len(batches)} batches ({pct}%) | +{len(results)} URLs | Total: {url_count}{eta_str}", end="\r")
                        
                    except Exception as e:
                        error(f"Erro no batch {batch_idx}: {e}")

        print("") # Newline
        
        elapsed = _time.time() - start_time
        mins = int(elapsed // 60)
        secs = int(elapsed % 60)
        info(f"   ✅ urlfinder concluído: {url_count} URLs em {mins}m{secs:02d}s")

    except Exception as e:
        error(f"❌ Falha ao executar urlfinder: {e}")
        # Dont return here, continue to historical
        
    # ============================================================
    # ETAPA 2.5 — Coleta Histórica & Ativa
    # ============================================================
    historical_file = outdir / "historical_raw.txt"
    run_historical_discovery(target, historical_file)
    
    katana_file = outdir / "katana_urls_raw.txt"
    run_katana_discovery(target, katana_file, scope_root)
    
    paramspider_file = outdir / "paramspider_urls_raw.txt"
    run_paramspider_discovery(target, paramspider_file, scope_root)
    
    # Merge files (V12: sempre incluir seeds in-scope — eram perdidas antes do httpx)
    all_raw_urls = []
    for u in sorted(seed_urls):
        all_raw_urls.append(u)
    
    if url_completas.exists():
         all_raw_urls.extend(url_completas.read_text(errors="ignore").splitlines())
         
    if historical_file.exists():
         all_raw_urls.extend(historical_file.read_text(errors="ignore").splitlines())
         
    if katana_file.exists():
         all_raw_urls.extend(katana_file.read_text(errors="ignore").splitlines())

    if paramspider_file.exists():
         all_raw_urls.extend(paramspider_file.read_text(errors="ignore").splitlines())

    if not all_raw_urls:
         warn("⚠️ Nenhuma URL encontrada (urlfinder + histórico).")
         return []
    
    # Write combined back to url_completas for deduplication
    url_completas.write_text("\n".join(all_raw_urls))

    # ============================================================
    # ETAPA 3 — Deduplicar URLs
    # ============================================================
    info(f"{C.BOLD}{C.BLUE}🧹 Deduplicando URLs encontradas...{C.END}")

    lines = [
        l.strip().rstrip("/")
        for l in url_completas.read_text(errors="ignore").splitlines()
        if l.strip()
    ]

    unique = smart_normalize_urls(lines)

    before_scope2 = len(unique)
    unique = [u for u in unique if is_in_scope(u, target, scope_root)]
    lost_oos = before_scope2 - len(unique)
    if lost_oos > 0:
        warn(f"   🔒 Pós-merge: removidas {lost_oos} URLs fora do escopo ({scope_root})")
        (outdir / "urls_rejected_out_of_scope.txt").write_text(
            "\n".join(sorted(set(lines) - set(unique))) + "\n"
        )

    url_completas.write_text("\n".join(unique) + "\n")

    success(f"📁 {len(unique)} URLs coletadas em: {C.GREEN}{url_completas}{C.END}")

    # ============================================================
    # ETAPA 4 — Validar URLs com httpx
    # ============================================================
    info(f"{C.BOLD}{C.BLUE}🔍 Validando URLs com HTTPX...{C.END}")

    valid_urls = httpx_validate(url_completas, urls_200, target=target, scope_root=scope_root)

    # ============================================================
    # ETAPA 5 — GF Patterns & Qsreplace Routing
    # ============================================================
    info(f"{C.BOLD}{C.BLUE}🔀 Roteando parâmetros vulneráveis (gf & qsreplace)...{C.END}")
    
    gf = shutil.which("gf")
    qsreplace = shutil.which("qsreplace")
    
    if gf and qsreplace:
        gf_patterns = ["xss", "ssrf", "sqli", "lfi", "redirect"]
        gf_dir = outdir / "patterns"
        gf_dir.mkdir(exist_ok=True)
        
        for pattern in gf_patterns:
            pattern_file = gf_dir / f"{pattern}_urls.txt"
            
            try:
                with open(urls_200, "r") as infile:
                    proc_gf = subprocess.run(
                        [gf, pattern], stdin=infile,
                        capture_output=True, text=True, timeout=120
                    )
                if proc_gf.stdout and proc_gf.stdout.strip():
                    pattern_file.write_text(proc_gf.stdout)
                else:
                    raise Exception("GF Empty Output")
            except Exception:
                # -------------------------------------------------------------
                # PYTHON NATIVE FALLBACK (GF Patterns Missing/Failed)
                # -------------------------------------------------------------
                import urllib.parse
                fallback_urls = []
                keywords = {
                    "ssrf": ["dest", "redirect", "uri", "path", "continue", "url", "window", "next", "data", "reference", "site", "html", "val", "validate", "domain", "callback", "return", "page", "feed", "host", "port", "to", "out", "view", "dir"],
                    "xss": ["q", "s", "search", "id", "lang", "keyword", "query", "page", "keywords", "year", "view", "email", "type", "name", "p"],
                    "redirect": ["redirect", "next", "url", "target", "return", "return_to", "continue", "view", "redirect_uri", "redirect_url", "forward"],
                    "sqli": ["id", "page", "dir", "search", "category", "file", "class", "url", "news", "item", "menu", "lang", "name", "ref"],
                    "lfi": ["file", "document", "folder", "root", "path", "pg", "style", "pdf", "template", "dir", "page", "include"]
                }
                
                try:
                    with open(urls_200, "r") as infile:
                        for line in infile:
                            u = line.strip()
                            parsed = urllib.parse.urlparse(u)
                            if parsed.query:
                                qs = urllib.parse.parse_qs(parsed.query)
                                # Adiciona se algum parâmetro bater com a lista
                                for k in qs:
                                    if any(kw in k.lower() for kw in keywords.get(pattern, [])):
                                        fallback_urls.append(u)
                                        break
                except Exception:
                    pass
                
                if fallback_urls:
                    pattern_file.write_text("\n".join(fallback_urls))
                else:
                    continue
            
            if pattern_file.exists() and pattern_file.stat().st_size > 0:
                payload_file = gf_dir / f"{pattern}_ready.txt"
                
                if pattern == "xss":
                    payload = '\\"\\><script>alert(1)</script>'
                elif pattern == "ssrf":
                    payload = "http://169.254.169.254/latest/meta-data/"
                elif pattern in ["sqli", "lfi"]:
                    payload = "FUZZ"
                else:
                    payload = "http://evil.com"
                    
                # qsreplace com pipe seguro
                try:
                    with open(pattern_file, "r") as infile:
                        proc_qs = subprocess.run(
                            [qsreplace, payload], stdin=infile,
                            capture_output=True, text=True, timeout=120
                        )
                    if proc_qs.stdout.strip():
                        payload_file.write_text(proc_qs.stdout)
                        count = len(proc_qs.stdout.strip().splitlines())
                        if count > 0:
                            success(f"   🎯 {count} URLs criadas para {pattern.upper()} ({payload_file.name})")
                except Exception:
                    continue
    else:
        warn("⚠️ 'gf' ou 'qsreplace' não encontrados. Pulando roteamento (instale via go install).")

    # ============================================================
    # 🎉 FINALIZAÇÃO
    # ============================================================
    success(
        f"\n{C.GREEN}{C.BOLD}✔ URLS concluído com sucesso!{C.END}\n"
        f"🔗 URLs válidas: {C.YELLOW}{len(valid_urls)}{C.END}\n"
        f"📂 Arquivo final salvo em:\n"
        f"   {C.CYAN}{urls_200}{C.END}\n"
    )

    return valid_urls
