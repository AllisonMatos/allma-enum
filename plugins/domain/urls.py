from pathlib import Path
from ..output import info, success, warn
from menu import C

# Portas conhecidas e seus protocolos preferidos
HTTPS_PORTS = {"443", "8443", "4443", "9443"}
HTTP_PORTS = {"80", "8080", "8000", "8008", "3000", "5000", "8888"}


def build_urls(ports_raw: Path, out_file: Path, subs_file: Path = None):
    """
    Constroi URLs a partir das portas brutas e subdominios.
    ports_raw: arquivo contendo linhas no formato host:porta/tcp
    out_file: arquivo onde as URLs serao salvas
    subs_file: arquivo opcional contendo lista de subdominios (para garantir 80/443)
    
    MELHORADO: Agora gera URLs com ambos protocolos para portas nao-padrao
    e considera mais portas comuns. Tambem inclui URLs padrao para todos subdominios.
    """

    info(
        f"\n[URLS] Geracao de URLs a partir das portas e subdominios\n"
        f"   Entrada Portas: {C.CYAN}{ports_raw}{C.END}\n"
        f"   Entrada Subs: {C.CYAN}{subs_file}{C.END}\n"
    )

    info(f"{C.BOLD}{C.BLUE}Processando portas e montando URLs...{C.END}")

    urls = set()
    stats = {"http": 0, "https": 0, "both": 0}

    # 1. Processar portas encontradas (ports_raw)
    if ports_raw.exists():
        for line in ports_raw.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue

            host, port = line.split(":", 1)
            port = port.split("/")[0].strip()

            if not port.isdigit():
                continue

            # Regras de construcao das URLs baseadas na porta
            if port == "80":
                urls.add(f"http://{host}")
                stats["http"] += 1
            elif port == "443":
                urls.add(f"https://{host}")
                stats["https"] += 1
            elif port in HTTPS_PORTS:
                # Portas HTTPS conhecidas
                urls.add(f"https://{host}:{port}")
                stats["https"] += 1
            elif port in HTTP_PORTS:
                # Portas HTTP conhecidas
                urls.add(f"http://{host}:{port}")
                stats["http"] += 1
            else:
                # Porta desconhecida: testar AMBOS os protocolos
                urls.add(f"http://{host}:{port}")
                urls.add(f"https://{host}:{port}")
                stats["both"] += 1

    # 2. Processar todos os subdominios (garantir 80 e 443)
    if subs_file and subs_file.exists():
        for sub in subs_file.read_text(errors="ignore").splitlines():
            sub = sub.strip()
            if not sub:
                continue
            
            # Adicionar http e https padrao para todo subdominio
            # O set() vai tratar duplicatas se ja tiver vindo do ports_raw
            urls.add(f"http://{sub}")
            urls.add(f"https://{sub}")
            stats["both"] += 1

    # Remover duplicatas e ordenar
    final_urls = sorted(urls)
    out_file.write_text("\n".join(final_urls) + "\n")

    success(
        f"\n{C.GREEN}{C.BOLD}URLs geradas com sucesso!{C.END}\n"
        f"Total: {C.CYAN}{len(final_urls)} URLs{C.END}\n"
        f"Salvo em: {C.YELLOW}{out_file}{C.END}\n"
    )

    return final_urls


def build_urls_from_subdomains(subdomains: list, ports_by_host: dict = None) -> list:
    """
    Constroi URLs a partir de uma lista de subdominios.
    Se ports_by_host for fornecido, usa as portas especificas de cada host.
    Caso contrario, gera URLs padrao com http e https.
    
    Args:
        subdomains: lista de subdominios
        ports_by_host: dict opcional {host: [portas]}
        
    Returns:
        list de URLs
    """
    urls = []
    
    for subdomain in subdomains:
        subdomain = subdomain.strip()
        if not subdomain:
            continue
            
        if ports_by_host and subdomain in ports_by_host:
            # Usar portas especificas
            for port in ports_by_host[subdomain]:
                port = str(port).strip()
                
                if port == "80":
                    urls.append(f"http://{subdomain}")
                elif port == "443":
                    urls.append(f"https://{subdomain}")
                elif port in HTTPS_PORTS:
                    urls.append(f"https://{subdomain}:{port}")
                elif port in HTTP_PORTS:
                    urls.append(f"http://{subdomain}:{port}")
                else:
                    urls.append(f"http://{subdomain}:{port}")
                    urls.append(f"https://{subdomain}:{port}")
        else:
            # URLs padrao
            urls.append(f"http://{subdomain}")
            urls.append(f"https://{subdomain}")
            
    return sorted(set(urls))
