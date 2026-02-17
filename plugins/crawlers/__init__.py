from pathlib import Path
from urllib.parse import urlparse
import subprocess
import shutil
from .katana import run_katana
from .gospider import run_gospider
from ..output import info, success, warn, error
from menu import C

def extract_domain_from_url(url: str) -> str:
    """Extrai o domínio base de uma URL (ex: lar.ind.br de https://www.lar.ind.br)"""
    try:
        parsed = urlparse(url)
        host = parsed.netloc.split(":")[0]  # Remove porta
        parts = host.split(".")
        # Pega os últimos 2-3 segmentos como domínio base
        if len(parts) >= 3 and parts[-2] in ["com", "org", "gov", "edu", "ind"]:
            return ".".join(parts[-3:])
        elif len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
    except:
        return ""

def filter_urls_by_domain(urls: list, target_domain: str) -> list:
    """Filtra URLs que pertencem ao domínio alvo"""
    target_base = extract_domain_from_url(f"https://{target_domain}")
    filtered = []
    
    for url in urls:
        url_domain = extract_domain_from_url(url)
        if url_domain and url_domain.endswith(target_base):
            filtered.append(url)
    
    return filtered

def validate_urls_quick(urls: list, outdir: Path) -> list:
    """Validação rápida de URLs com HTTPX"""
    if not urls:
        return []
        
    httpx_bin = shutil.which("httpx")
    if not httpx_bin:
        return []
    
    # Arquivo temporário para input
    temp_in = outdir / "temp_validate_in.txt"
    temp_out = outdir / "temp_validate_out.txt"
    
    temp_in.write_text("\n".join(urls))
    
    cmd = [
        httpx_bin,
        "-l", str(temp_in),
        "-mc", "200,301,302,307,308,401,403",
        "-timeout", "10",
        "-retries", "1",
        "-silent",
        "-o", str(temp_out)
    ]
    
    try:
        subprocess.run(cmd, timeout=120, check=False)
    except:
        return []
    
    if temp_out.exists():
        valid = [l.strip() for l in temp_out.read_text().splitlines() if l.strip()]
        return valid
    
    return []

def run_crawlers(urls_file: Path, outdir: Path):
    """
    Orquestra a execução dos crawlers com descoberta de novas URLs.
    Salva descobertas em katana_valid.txt (NÃO modifica urls_valid.txt).
    """
    crawlers_dir = outdir / "crawlers"
    crawlers_dir.mkdir(parents=True, exist_ok=True)
    
    # Ler URLs iniciais
    if urls_file.exists():
        initial_urls = set(l.strip() for l in urls_file.read_text().splitlines() if l.strip())
    else:
        warn("Arquivo de URLs não encontrado.")
        return
    
    if not initial_urls:
        warn("Nenhuma URL para crawling.")
        return
    
    # Extrair target domain
    first_url = list(initial_urls)[0]
    target = extract_domain_from_url(first_url)
    
    info(f"Crawling {len(initial_urls)} URLs iniciais...")
    
    all_discovered = set()
    all_valid = set(initial_urls)
    
    # ============================================================
    # RECURSIVE CRAWLING
    # ============================================================
    max_rounds = 3
    round_num = 1
    current_urls = initial_urls
    
    while round_num <= max_rounds and current_urls:
        info(f"=== Crawling Round {round_num}/{max_rounds} ({len(current_urls)} URLs) ===")
        
        # Preparar arquivo de input para este round
        round_input = crawlers_dir / f"round_{round_num}_input.txt"
        round_input.write_text("\n".join(current_urls))
        
        # 1. Katana
        # Salvar output específico do round
        katana_out = crawlers_dir / f"katana_round_{round_num}.txt"
        run_katana(round_input, katana_out)
        
        # Coletar URLs descobertas neste round
        round_discovered = set()
        if katana_out.exists():
            lines = set(l.strip() for l in katana_out.read_text().splitlines() if l.strip())
            round_discovered.update(lines)
            
        # 2. Gospider (Rodar apenas no primeiro round para não demorar demais)
        if round_num == 1:
            gospider_dir = crawlers_dir / "gospider"
            gospider_dir.mkdir(exist_ok=True)
            gospider_urls = run_gospider(round_input, gospider_dir)
            if gospider_urls:
                round_discovered.update(gospider_urls)
            
        all_discovered.update(round_discovered)
        
        # 3. Processar e Validar
        # Novas = (Descobertas neste round) - (Tudo que já conhecemos como válido)
        # Atenção: podemos redescobrir URLs inválidas anteriores, mas o validate filtra.
        # Vamos focar em validar o que ainda não está em all_valid e pertence ao dominio.
        
        potential_new = round_discovered - all_valid
        domain_urls = filter_urls_by_domain(list(potential_new), target)
        
        if not domain_urls:
            info(f"Round {round_num}: Nenhuma nova URL do domínio encontrada.")
            newly_valid = []
        else:
            info(f"Round {round_num}: {len(domain_urls)} URLs candidatas. Validando...")
            newly_valid = validate_urls_quick(domain_urls, crawlers_dir)
            
        if newly_valid:
            count = len(newly_valid)
            info(f"✨ Round {round_num}: {count} novas URLs válidas adicionadas!")
            all_valid.update(newly_valid)
            
            # Próximo round usa APENAS as novas URLs válidas
            current_urls = set(newly_valid)
            round_num += 1
        else:
            info(f"Round {round_num}: Nenhuma nova URL válida. Encerrando recursão.")
            break

    # ============================================================
    # SALVAR EM ARQUIVO SEPARADO (katana_valid.txt)
    # ============================================================
    katana_valid_file = outdir / "katana_valid.txt"
    katana_urls = sorted(all_valid)
    katana_valid_file.write_text("\n".join(katana_urls) + "\n")
    
    # Salvar todas as URLs descobertas (incluindo não validadas)
    discovered_file = outdir / "discovered_urls.txt"
    discovered_file.write_text("\n".join(sorted(all_discovered)))

    # ============================================================
    # AGREGAR E VALIDAR "NEWS IN CODE"
    # ============================================================
    info(f"{C.BOLD}{C.BLUE}Processando URLs encontradas no código (News in Code)...{C.END}")
    
    all_new_in_code = []
    all_forms = []
    all_params = {}
    
    # 1. Agregar de todos os rounds
    import json
    for json_file in crawlers_dir.glob("katana_round_*_new_in_code.json"):
        try:
            data = json.loads(json_file.read_text())
            all_new_in_code.extend(data)
        except:
            pass

    for json_file in crawlers_dir.glob("katana_round_*_forms.json"):
        try:
            data = json.loads(json_file.read_text())
            all_forms.extend(data)
        except:
            pass
            
    for json_file in crawlers_dir.glob("katana_round_*_params.json"):
        try:
            data = json.loads(json_file.read_text())
            for key, val in data.items():
                if key not in all_params:
                    all_params[key] = []
                # Merge unique URLs
                all_params[key] = list(set(all_params[key] + val))
        except:
            pass

    # 2. Validar URLs do News in Code
    if all_new_in_code:
        # Extrair URLs unicas para validar
        urls_to_validate = list({x["url"] for x in all_new_in_code})
        
        info(f"Validando {len(urls_to_validate)} URLs encontradas no código...")
        
        try:
            # Import dinâmico para evitar circular dependency se houver
            from ..domain.validator import validate_urls_detailed
            
            validation_results = validate_urls_detailed(urls_to_validate, max_workers=10)
            details = validation_results["details"]
            
            # Enriquecer lista original com validação
            enriched_news = []
            seen_urls = set()
            
            for item in all_new_in_code:
                u = item["url"]
                # Evitar duplicatas exatas de (url + found_in)
                composite_key = f"{u}|{item.get('found_in', '')}"
                if composite_key in seen_urls:
                    continue
                seen_urls.add(composite_key)
                
                # Adicionar dados de validação
                val_data = details.get(u, {})
                item["valid"] = val_data.get("valid", False)
                item["status"] = val_data.get("status_code")
                item["final_url"] = val_data.get("final_url")
                item["error"] = val_data.get("error")
                
                enriched_news.append(item)
            
            # Salvar JSON final validado
            news_file = outdir / "katana_new_in_code_validated.json"
            news_file.write_text(json.dumps(enriched_news, indent=2, ensure_ascii=False))
            
            info(f"   + Salvo {len(enriched_news)} itens em {news_file.name}")
            
        except ImportError:
            warn("Não foi possível importar validador. Salvando sem validação extra.")
            news_file = outdir / "katana_new_in_code.json"
            news_file.write_text(json.dumps(all_new_in_code, indent=2, ensure_ascii=False))
        except Exception as e:
            error(f"Erro ao validar News in Code: {e}")

    # Salvar forms e params agregados
    if all_forms:
        (outdir / "katana_forms_all.json").write_text(json.dumps(all_forms, indent=2, ensure_ascii=False))
        
    if all_params:
        (outdir / "katana_params_all.json").write_text(json.dumps(all_params, indent=2, ensure_ascii=False))

    
    success(f"Crawling concluído! {len(all_valid)} URLs válidas (katana_valid.txt)")
    info(f"   URLs iniciais: {len(initial_urls)}")
    info(f"   Novas descobertas: {len(all_valid) - len(initial_urls)}")

