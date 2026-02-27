"""
Email Harvesting — Extrai endereços de email do conteúdo HTML/JS coletado.
Classifica por domínio interno/externo e deduplica.
"""
import json
import re
from pathlib import Path
from collections import defaultdict

from menu import C
from ..output import info, success, warn, error

# Regex robusto para emails
# Regex robusto e seguro contra catastrophic backtracking
EMAIL_REGEX = re.compile(
    r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)*\.[a-zA-Z]{2,}',
    re.I
)

# Extensões de arquivo falsas (não são emails)
FAKE_EMAIL_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp",
    "css", "js", "map", "woff", "woff2", "ttf", "eot",
    "xml", "json", "pdf", "zip", "gz", "tar",
}

# Emails genéricos para ignorar
IGNORE_EMAILS = {
    "wss://",
    "your@email.com", "user@example.com", "email@example.com",
    "name@example.com", "test@test.com", "noreply@example.com",
}


def ensure_outdir(target: str) -> Path:
    outdir = Path("output") / target / "emails"
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir


def is_valid_email(email: str) -> bool:
    """Valida se parece ser um email real."""
    email = email.lower().strip()

    # Muito curto ou muito longo
    if len(email) < 5 or len(email) > 100:
        return False

    # Extensão de arquivo
    domain_part = email.split("@")[-1]
    ext = domain_part.split(".")[-1]
    if ext in FAKE_EMAIL_EXTENSIONS:
        return False

    # Email genérico
    if email in IGNORE_EMAILS:
        return False

    # Versão (2.0, 1.0, etc)
    if re.search(r'\d+\.\d+@', email):
        return False

    return True


def extract_emails_from_text(text: str) -> set:
    """Extrai emails de um texto de forma O(N)."""
    found = set()
    pos = 0
    length = len(text)
    
    # Pre-compute valid characters for fast lookups
    allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._%+-")
    
    while True:
        pos = text.find('@', pos)
        if pos == -1:
            break
            
        # Encontra o inicio da string que parece email
        start = pos - 1
        while start >= 0 and text[start] in allowed_chars:
            start -= 1
        start += 1
        
        # Encontra o final
        end = pos + 1
        while end < length and text[end] in allowed_chars:
            end += 1
            
        candidate = text[start:end]
        match = EMAIL_REGEX.fullmatch(candidate)
        if match:
            email = match.group(0).lower().strip(".")
            if is_valid_email(email):
                found.add(email)
                
        # Continuar a busca apos o fim deste candidato
        pos = end
        
    return found


def run(context: dict):
    """Executa harvesting de emails."""
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟩───────────────────────────────────────────────────────────🟩\n"
        f"   📧 {C.BOLD}{C.CYAN}EMAIL HARVESTING{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟩───────────────────────────────────────────────────────────🟩\n"
    )

    outdir = ensure_outdir(target)
    base = Path("output") / target

    all_emails = set()
    sources = defaultdict(set)  # email -> set of sources

    # Fontes de dados para procurar emails
    scan_targets = [
        ("domain/discovered_urls.txt", "URLs"),
        ("domain/urls_valid.txt", "Valid URLs"),
        ("domain/extracted_routes.json", "Routes"),
    ]

    # Procurar em todos os arquivos de texto/json do output
    info(f"   🔍 Varrendo arquivos do output...")

    # Varrer arquivos de texto e JSON
    text_extensions = {".txt", ".json", ".xml", ".html", ".csv"}
    files_scanned = 0

    for path in base.rglob("*"):
        if path.is_file() and path.suffix in text_extensions:
            try:
                content = path.read_text(errors="ignore")
                found = extract_emails_from_text(content)
                if found:
                    rel = str(path.relative_to(base))
                    for email in found:
                        all_emails.add(email)
                        sources[email].add(rel)
                files_scanned += 1
            except Exception:
                pass

    info(f"   📁 {files_scanned} arquivos varridos")

    # Procurar em crawlers (katana output, etc)
    crawler_dir = base / "domain" / "crawlers"
    if crawler_dir.exists():
        for path in crawler_dir.rglob("*"):
            if path.is_file():
                try:
                    content = path.read_text(errors="ignore")
                    found = extract_emails_from_text(content)
                    for email in found:
                        all_emails.add(email)
                        sources[email].add(f"crawlers/{path.name}")
                except Exception:
                    pass

    # Classificar por domínio
    target_domain = target.lower().replace("www.", "")
    internal = []
    external = []

    for email in sorted(all_emails):
        email_domain = email.split("@")[-1]
        source_list = sorted(sources.get(email, set()))

        entry = {
            "email": email,
            "domain": email_domain,
            "sources": source_list,
        }

        if target_domain in email_domain or email_domain in target_domain:
            entry["type"] = "internal"
            internal.append(entry)
        else:
            entry["type"] = "external"
            external.append(entry)

    # Resultado final
    result = {
        "target": target,
        "total": len(all_emails),
        "internal_count": len(internal),
        "external_count": len(external),
        "internal": internal,
        "external": external,
        "all_domains": sorted(set(e["domain"] for e in internal + external)),
    }

    output_file = outdir / "emails.json"
    output_file.write_text(json.dumps(result, indent=2, ensure_ascii=False))

    if all_emails:
        success(f"\n   📧 {len(all_emails)} emails encontrados!")
        info(f"   📊 Internos ({target}): {C.GREEN}{len(internal)}{C.END}")
        info(f"   📊 Externos: {C.YELLOW}{len(external)}{C.END}")

        # Mostrar primeiros emails
        if internal:
            info(f"   🏢 Emails internos:")
            for e in internal[:10]:
                info(f"      {C.GREEN}{e['email']}{C.END}")
            if len(internal) > 10:
                info(f"      ... e mais {len(internal) - 10}")

        if external:
            info(f"   🌐 Domínios externos: {', '.join(result['all_domains'][:10])}")

        success(f"   📂 Salvos em {output_file}")
    else:
        info("   ✅ Nenhum email encontrado nos outputs.")

    return result
