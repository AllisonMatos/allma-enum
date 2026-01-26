import shutil
import subprocess
import json
from pathlib import Path
from ..output import info, success, warn, error

def run_katana(urls_file: Path, output_file: Path):
    """
    Executa o Katana para crawling aprofundado.
    Usa modo headless (-hl) para suportar sites com JavaScript pesado.
    Extrai: URLs, Forms, Endpoints JS, Parâmetros.
    """
    katana_bin = shutil.which("katana")
    if not katana_bin:
        warn("Katana nao encontrado. Pulando etapa.")
        return

    info(f"Executando Katana (headless + form extraction) em: {urls_file}")
    
    # Output em JSONL para dados ricos - usa o nome do output_file como base para não sobrescrever
    jsonl_output = output_file.with_suffix(".jsonl")
    
    cmd = [
        katana_bin,
        "-list", str(urls_file),
        "-hl",              # Headless mode - usa Chromium para sites com JS
        "-jc",              # JS crawling básico
        "-jsl",             # JSluice - parsing avançado de JS (endpoints, vars, etc)
        "-fx",              # Form extraction - extrai formulários
        "-kf", "all",       # Known files (robots.txt, sitemap, etc)
        "-d", "3",          # Depth
        "-c", "5",          # Concurrency (reduzido para headless)
        "-timeout", "30",   # Timeout maior para JS
        "-jsonl",           # Output em JSON Lines
        "-o", str(jsonl_output),
        "-silent"
    ]
    
    try:
        subprocess.run(cmd, timeout=600)  # 10 min timeout total
    except subprocess.TimeoutExpired:
        warn("Katana timeout - resultados parciais podem ter sido salvos.")
    except Exception as e:
        error(f"Erro ao executar Katana: {e}")
        return
    
    # Processar output JSONL
    results = parse_katana_jsonl(jsonl_output, output_file)
    
    if results.get("urls"):
        success(f"Katana finalizado. {len(results['urls'])} URLs, {len(results.get('forms', []))} forms, {len(results.get('params', {}))} params")
    else:
        warn("Katana finalizado sem resultados.")
    
    return results


def parse_katana_jsonl(jsonl_file: Path, urls_output: Path) -> dict:
    """
    Processa o output JSONL do Katana e separa em categorias.
    """
    results = {
        "urls": [],
        "forms": [],
        "params": {},        # param_name -> [list of URLs]
        "js_endpoints": [],  # URLs descobertas em arquivos JS
        "new_in_code": [],   # URLs encontradas em código fonte (JS, inline scripts)
    }
    
    if not jsonl_file.exists():
        return results
    
    try:
        for line in jsonl_file.read_text().splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                
                # URL sempre presente
                url = data.get("request", {}).get("endpoint") or data.get("endpoint", "")
                if url:
                    results["urls"].append(url)
                
                # Method (GET, POST, etc)
                method = data.get("request", {}).get("method", "GET")
                
                # Source indica de onde veio
                source = data.get("source", "")
                source_url = data.get("source_url", "")
                
                # Forms
                if source == "form" or data.get("form"):
                    form_data = {
                        "action": url,
                        "method": method,
                        "inputs": data.get("form", {}).get("inputs", []),
                        "source_url": source_url
                    }
                    results["forms"].append(form_data)
                
                # Parâmetros com URL de origem
                if "?" in url:
                    base_url = url.split("?")[0]
                    params_str = url.split("?")[1]
                    for param in params_str.split("&"):
                        if "=" in param:
                            param_name = param.split("=")[0]
                            if param_name not in results["params"]:
                                results["params"][param_name] = []
                            if base_url not in results["params"][param_name]:
                                results["params"][param_name].append(base_url)
                
                # JS Endpoints / New in Code
                # Lógica BROADER (Solicitada pelo usuário):
                # Tudo o que o Katana achar que não é a própria página de origem é "News in Code" / "Deep Finding"
                is_from_code = False
                
                # Se a URL encontrada é diferente da URL de origem, é um achado
                if url != source_url:
                    is_from_code = True
                
                if is_from_code:
                    results["js_endpoints"].append({
                        "url": url,
                        "source": source_url,
                        "type": source if source else "deep_crawl"
                    })
                    results["new_in_code"].append({
                        "url": url,
                        "found_in": source_url,
                        "type": source if source else "deep_crawl"
                    })
                    
            except json.JSONDecodeError:
                continue
                
    except Exception as e:
        warn(f"Erro ao processar JSONL: {e}")
    
    # Salvar URLs simples para compatibilidade
    if results["urls"]:
        urls_output.write_text("\n".join(sorted(set(results["urls"]))))
    
    # Salvar forms em JSON separado - usa prefixo do arquivo original
    prefix = jsonl_file.stem.replace("_full", "")
    
    forms_file = jsonl_file.parent / f"{prefix}_forms.json"
    if results["forms"]:
        forms_file.write_text(json.dumps(results["forms"], indent=2, ensure_ascii=False))
    
    # Salvar params como JSON
    params_file = jsonl_file.parent / f"{prefix}_params.json"
    if results["params"]:
        params_file.write_text(json.dumps(results["params"], indent=2, ensure_ascii=False))
    
    # Salvar JS endpoints / New in Code
    new_in_code_file = jsonl_file.parent / f"{prefix}_new_in_code.json"
    if results["new_in_code"]:
        new_in_code_file.write_text(json.dumps(results["new_in_code"], indent=2, ensure_ascii=False))
    
    return results
