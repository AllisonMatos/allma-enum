#!/usr/bin/env python3
"""
GitHub/GitLab Dorking Scanner — Realiza buscas ativas em repositórios públicos
buscando por vazamentos de tokens, configs e subdomínios do target.
"""
import os
import json
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import httpx

from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from plugins.validation import finding

GITHUB_API_URL = "https://api.github.com/search/code"
GITLAB_API_URL = "https://gitlab.com/api/v4/search"

# Dorks para buscar
DORKS = [
    '"{target}" (password OR secret OR token OR api_key OR credentials)',
    '"{target}" AWS_ACCESS_KEY_ID',
    '"{target}" "BEGIN PRIVATE KEY"',
    '"{target}" filename:.env',
    '"{target}" filename:wp-config.php',
    '"{target}" extension:json (password OR secret)',
]

def search_github(query: str, token: str = None) -> list:
    """Realiza busca na API do Github."""
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    
    results = []
    try:
        r = httpx.get(GITHUB_API_URL, params={"q": query, "per_page": 10}, headers=headers, timeout=10)
        if r.status_code == 403 and "rate limit" in r.text.lower():
            warn(f"   [!] GitHub Rate Limit excedido para a query: {query}")
            return results
        if r.status_code == 200:
            data = r.json()
            for item in data.get("items", []):
                results.append({
                    "platform": "GitHub",
                    "repo": item.get("repository", {}).get("full_name", ""),
                    "file": item.get("name", ""),
                    "path": item.get("path", ""),
                    "url": item.get("html_url", ""),
                    "query": query
                })
        time.sleep(2) # Respeitar rate limits
    except Exception as e:
        warn(f"   [!] Erro consultando GitHub API: {e}")
    return results

def search_gitlab(query: str, token: str = None) -> list:
    """Realiza busca na API do GitLab."""
    headers = {}
    if token:
        headers["PRIVATE-TOKEN"] = token
    
    results = []
    try:
        r = httpx.get(GITLAB_API_URL, params={"scope": "blobs", "search": query}, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            for item in data:
                results.append({
                    "platform": "GitLab",
                    "repo": f"Project ID: {item.get('project_id', '')}",
                    "file": item.get("filename", ""),
                    "path": item.get("path", ""),
                    "url": f"https://gitlab.com/projects/{item.get('project_id')}/repository/files/{item.get('path')}",
                    "query": query
                })
        time.sleep(2)
    except Exception as e:
        pass # Ignorar erros do gitlab por enquanto
    return results

def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n🟩───────────────────────────────────────────────────────────🟩\n"
        f"   🐙 {C.BOLD}{C.CYAN}GITHUB/GITLAB DORKING ATIVO{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟩───────────────────────────────────────────────────────────🟩\n"
    )

    outdir = ensure_outdir(target, "github_dorks")
    
    github_token = os.environ.get("GITHUB_TOKEN")
    gitlab_token = os.environ.get("GITLAB_TOKEN")
    
    if not github_token:
        warn("   ⚠️ GITHUB_TOKEN não definido no ambiente. A busca será limitada a 10 requests/minuto (unauthenticated).")
    
    all_leaks = []
    
    # Process queries
    for template in DORKS:
        query = template.format(target=target)
        info(f"   🔎 Buscando: {query}")
        
        # Github
        gh_results = search_github(query, github_token)
        if gh_results:
            info(f"      [+] GitHub: {len(gh_results)} resultados encontrados.")
            all_leaks.extend(gh_results)
            
        # Gitlab
        if gitlab_token: # Gitlab search geralmente requer token para escopo global ou é muito restrito
            gl_results = search_gitlab(query, gitlab_token)
            if gl_results:
                info(f"      [+] GitLab: {len(gl_results)} resultados encontrados.")
                all_leaks.extend(gl_results)
                
    # Normalizar findings
    normalized_findings = []
    for leak in all_leaks:
        normalized_findings.append(
            finding(
                plugin="github_dorks",
                target=target,
                title=f"Source Code Leak in {leak['platform']}",
                issue_type="SOURCE_CODE_DISCLOSURE",
                risk="HIGH",
                confidence="HIGH",
                description=f"Possível vazamento de dados sensíveis encontrado no {leak['platform']} no repositório {leak['repo']}.",
                url=leak["url"],
                detection={"platform": leak["platform"], "query": leak["query"]},
                validation={"file": leak["file"], "path": leak["path"]},
                evidence={"observable_impact": "source_code_leak"},
                metadata=leak
            )
        )
        
    (outdir / "findings.json").write_text(json.dumps(normalized_findings, indent=2, ensure_ascii=False))
    
    if all_leaks:
        output_file = outdir / "leaks.json"
        output_file.write_text(json.dumps(all_leaks, indent=2, ensure_ascii=False))
        success(f"\n   🚨 {len(all_leaks)} vazamentos potenciais encontrados! Salvos em {output_file}")
    else:
        info("   ✅ Nenhum vazamento detectado no GitHub/GitLab com as dorks padrão.")
        
    return normalized_findings
