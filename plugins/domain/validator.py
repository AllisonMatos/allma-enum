import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from .utils import require_binary
from ..output import info, success, warn, error
from menu import C

# Status codes aceitos - inclui 401/403 para detectar paginas protegidas
STATUS = "200,201,204,301,302,303,307,308,401,403,405"

# Portas padrao para cada protocolo
HTTPS_PORTS = {"443", "8443", "4443", "9443"}
HTTP_PORTS = {"80", "8080", "8000", "8008", "3000", "5000", "8888"}


# ============================================================
# NORMALIZACAO DE URLs
# ============================================================
def normalize_urls(in_file: Path) -> list:
    urls = []

    info(
        f"\n[VALIDATOR] Normalizando URLs\n"
        f"   Entrada: {C.YELLOW}{in_file}{C.END}\n"
    )

    if not in_file.exists():
        warn(f"{C.YELLOW}Arquivo nao encontrado:{C.END} {C.CYAN}{in_file}{C.END}")
        return []

    for line in in_file.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue

        # URL completa
        if line.startswith("http://") or line.startswith("https://"):
            urls.append(line)
            continue

        # host:port
        if ":" in line:
            host, port = line.split(":", 1)
            port = port.split("/")[0].strip()

            if not port.isdigit():
                continue

            # Determinar protocolo baseado na porta
            if port in HTTPS_PORTS:
                if port == "443":
                    urls.append(f"https://{host}")
                else:
                    urls.append(f"https://{host}:{port}")
            elif port in HTTP_PORTS:
                if port == "80":
                    urls.append(f"http://{host}")
                else:
                    urls.append(f"http://{host}:{port}")
            else:
                # Porta nao-padrao: testar ambos os protocolos
                urls.append(f"http://{host}:{port}")
                urls.append(f"https://{host}:{port}")
            continue

        # Apenas host - testar ambos protocolos
        urls.append(f"http://{line}")
        urls.append(f"https://{line}")

    # Remover duplicatas mantendo ordem
    seen = set()
    unique_urls = []
    for url in urls:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)

    info(f"{C.BLUE}Total normalizado: {len(unique_urls)} URLs{C.END}")

    return unique_urls


# ============================================================
# VALIDAR URL INDIVIDUAL COM HTTPX PYTHON
# ============================================================
def validate_single_url(url: str, timeout: int = 15) -> dict:
    """
    Valida uma URL individual e retorna informacoes detalhadas.
    """
    import httpx
    
    result = {
        "url": url,
        "valid": False,
        "status_code": None,
        "final_url": None,
        "is_login_page": False,
        "error": None
    }
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    
    valid_codes = {200, 201, 204, 301, 302, 303, 307, 308, 401, 403, 405}
    login_keywords = ["login", "signin", "auth", "authenticate", "logon", "sso", "oauth"]
    
    try:
        with httpx.Client(
            verify=False, 
            follow_redirects=True, 
            timeout=timeout,
            http2=True
        ) as client:
            resp = client.get(url, headers=headers)
            
            result["status_code"] = resp.status_code
            result["final_url"] = str(resp.url)
            
            if resp.status_code in valid_codes:
                result["valid"] = True
                
                # Detectar pagina de login
                final_url_lower = str(resp.url).lower()
                content_lower = resp.text[:5000].lower() if resp.text else ""
                
                for keyword in login_keywords:
                    if keyword in final_url_lower or keyword in content_lower:
                        result["is_login_page"] = True
                        break
                        
    except httpx.TimeoutException:
        result["error"] = "timeout"
    except httpx.ConnectError:
        result["error"] = "connection_error"
    except Exception as e:
        result["error"] = str(e)[:50]
        
    return result


# ============================================================
# VALIDAR URLs COM HTTPX CLI (PRINCIPAL)
# ============================================================
def validate_urls(in_file: Path, out_file: Path, threads: int = 50):
    httpx_bin = require_binary("httpx")

    info(
        f"\n[VALIDATOR] Validacao de URLs com HTTPX\n"
        f"   Origem: {C.CYAN}{in_file}{C.END}\n"
        f"   Codigos esperados: {C.GREEN}{STATUS}{C.END}\n"
    )

    # Normalizacao
    info(f"{C.BOLD}{C.BLUE}Normalizando URLs para o httpx...{C.END}")
    normalized = normalize_urls(in_file)

    if not normalized:
        warn("Nenhuma URL para validar.")
        out_file.write_text("")
        return []

    # Arquivo temporario
    temp_file = in_file.parent / "urls-normalized.txt"
    temp_file.write_text("\n".join(normalized))

    # Execucao do httpx com parametros otimizados
    info(f"{C.BOLD}{C.BLUE}Executando httpx (threads={threads})...{C.END}")

    cmd = [
        httpx_bin,
        "-l", str(temp_file),
        "-mc", STATUS,
        "-retries", "3",
        "-timeout", "20",
        "-random-agent",
        "-follow-redirects",
        "-silent",
        "-threads", str(threads),
        "-o", str(out_file)
    ]

    try:
        subprocess.run(cmd, check=False)
    except Exception as e:
        error(f"Erro executando httpx: {e}")
        return []

    # Leitura dos resultados
    if not out_file.exists():
        out_file.write_text("")
        
    valid_urls = set(x.strip() for x in out_file.read_text().splitlines() if x.strip())
    
    # ============================================================
    # FALLBACK: Tentar HTTP para URLs HTTPS que falharam
    # ============================================================
    https_urls = [u for u in normalized if u.startswith("https://")]
    validated_https = [u for u in valid_urls if u.startswith("https://")]
    
    # Encontrar HTTPS que falharam e criar versao HTTP
    failed_https = set(https_urls) - set(validated_https)
    http_fallback = []
    
    for url in failed_https:
        # Converter https:// para http://
        http_version = "http://" + url[8:]  # Remove "https://" e adiciona "http://"
        # Nao tentar se ja temos a versao HTTP validada
        if http_version not in valid_urls and http_version not in [u for u in normalized if u.startswith("http://")]:
            http_fallback.append(http_version)
    
    if http_fallback:
        info(f"{C.BOLD}{C.YELLOW}Tentando fallback HTTP para {len(http_fallback)} URLs...{C.END}")
        
        fallback_file = in_file.parent / "urls-fallback.txt"
        fallback_out = in_file.parent / "urls-fallback-result.txt"
        fallback_file.write_text("\n".join(http_fallback))
        
        cmd_fallback = [
            httpx_bin,
            "-l", str(fallback_file),
            "-mc", STATUS,
            "-retries", "2",
            "-timeout", "15",
            "-random-agent",
            "-follow-redirects",
            "-silent",
            "-threads", str(threads),
            "-o", str(fallback_out)
        ]
        
        try:
            subprocess.run(cmd_fallback, check=False)
            if fallback_out.exists():
                fallback_valid = [x.strip() for x in fallback_out.read_text().splitlines() if x.strip()]
                if fallback_valid:
                    info(f"   + {len(fallback_valid)} URLs adicionais via HTTP fallback")
                    valid_urls.update(fallback_valid)
        except Exception:
            pass

    # Remover duplicatas e salvar
    urls = sorted(valid_urls)
    out_file.write_text("\n".join(urls) + "\n")

    success(
        f"\n{C.GREEN}{C.BOLD}Validacao concluida!{C.END}\n"
        f"URLs validas: {C.CYAN}{len(urls)}{C.END}\n"
        f"Saida: {C.YELLOW}{out_file}{C.END}\n"
    )

    return urls


# ============================================================
# VALIDAR URLs E DETECTAR PAGINAS DE LOGIN
# ============================================================
def validate_urls_detailed(urls: list, max_workers: int = 20) -> dict:
    """
    Valida URLs em paralelo e retorna informacoes detalhadas.
    
    Returns:
        dict com:
        - valid_urls: list de URLs validas
        - login_pages: list de URLs que sao paginas de login
        - details: dict completo por URL
    """
    info(f"{C.BOLD}{C.BLUE}Validando {len(urls)} URLs com detalhes...{C.END}")
    
    results = {
        "valid_urls": [],
        "login_pages": [],
        "details": {}
    }
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(validate_single_url, url): url for url in urls}
        
        completed = 0
        total = len(urls)
        
        for future in as_completed(future_to_url):
            completed += 1
            
            if completed % 10 == 0:
                print(f"   [{completed}/{total}] URLs validadas...", end="\r")
                
            try:
                result = future.result()
                url = result["url"]
                results["details"][url] = result
                
                if result["valid"]:
                    results["valid_urls"].append(url)
                    
                    if result["is_login_page"]:
                        results["login_pages"].append(url)
                        
            except Exception:
                pass
                
    print("")  # Quebra de linha
    
    success(
        f"Validacao detalhada concluida:\n"
        f"   URLs validas: {C.GREEN}{len(results['valid_urls'])}{C.END}\n"
        f"   Paginas de login: {C.YELLOW}{len(results['login_pages'])}{C.END}\n"
    )
    
    return results
