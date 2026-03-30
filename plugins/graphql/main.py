#!/usr/bin/env python3
"""
GraphQL Security Scanner — Introspection, Batch Queries, Field Suggestions, Mutations
Usa httpx + captura raw request/response
"""
from core.config import DEFAULT_USER_AGENT, REQUEST_DELAY
import json
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from ..http_utils import format_raw_request, format_raw_response

try:
    import httpx
except ImportError:
    httpx = None


GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/gql", "/query",
    "/api/graphql", "/api/gql", "/v1/graphql", "/v2/graphql",
    "/graphql/v1", "/playground", "/__graphql",
]

INTROSPECTION_QUERY = '{"query": "{ __schema { types { name fields { name } } } }"}'

BATCH_QUERY = '[{"query": "{ __typename }"}, {"query": "{ __typename }"}]'

MUTATIONS_QUERY = '{"query": "{ __schema { mutationType { fields { name args { name type { name } } } } } }"}'

SUGGESTIONS_QUERY = '{"query": "{ __typ }"}'


def test_endpoint(client, url):
    """Testa um endpoint GraphQL para diversas vulnerabilidades"""
    findings = []
    headers = {
        "Content-Type": "application/json",
        "User-Agent": DEFAULT_USER_AGENT,
    }
    
    import urllib.parse
    
    # 1) Introspection
    try:
        # Tenta POST primeiro
        resp = client.post(url, content=INTROSPECTION_QUERY, headers=headers, timeout=15)
        body = resp.text
        method_used = "POST"
        
        # Fallback para GET se POST falhar em detectar
        if resp.status_code in (405, 403, 400, 401) or "__schema" not in body:
            req_url = f"{url}?query={urllib.parse.quote('{ __schema { types { name fields { name } } } }')}"
            resp = client.get(req_url, headers={"User-Agent": DEFAULT_USER_AGENT}, timeout=15)
            body = resp.text
            method_used = "GET"

        if resp.status_code == 200 and "__schema" in body:
            if method_used == "POST":
                raw_req = format_raw_request("POST", url, dict(resp.request.headers), INTROSPECTION_QUERY)
            else:
                raw_req = format_raw_request("GET", req_url, dict(resp.request.headers))
                
            raw_res = format_raw_response(resp.status_code, dict(resp.headers), body[:3000])
            
            # Contar types
            try:
                data = resp.json()
                types_count = len(data.get("data", {}).get("__schema", {}).get("types", []))
            except Exception:
                types_count = 0
            
            findings.append({
                "url": url,
                "type": "INTROSPECTION_ENABLED",
                "risk": "HIGH",
                "status": resp.status_code,
                "length": len(body),
                "introspection": True,
                "types_count": types_count,
                "details": f"Introspection habilitada via {method_used} — {types_count} types expostos",
                "request_raw": raw_req,
                "response_raw": raw_res,
            })
    except Exception:
        pass
    
    # 2) Batch Queries (DoS potential)
    # Batch Queries geralmente funcionam apenas no POST em formato JSON List
    try:
        resp = client.post(url, content=BATCH_QUERY, headers=headers, timeout=15)
        body = resp.text
        
        if resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list) and len(data) > 1:
                    raw_req = format_raw_request("POST", url, dict(resp.request.headers), BATCH_QUERY)
                    raw_res = format_raw_response(resp.status_code, dict(resp.headers), body[:2000])
                    findings.append({
                        "url": url,
                        "type": "BATCH_QUERIES_ALLOWED",
                        "risk": "MEDIUM",
                        "status": resp.status_code,
                        "details": f"Batch queries aceitas — potencial DoS/rate limit bypass",
                        "request_raw": raw_req,
                        "response_raw": raw_res,
                    })
            except Exception:
                pass
    except Exception:
        pass
    
    # 3) Mutations expostas
    try:
        resp = client.post(url, content=MUTATIONS_QUERY, headers=headers, timeout=15)
        body = resp.text
        method_used = "POST"
        
        # Mutações no geral dependem de POST, mas testamos GET também caso o dev tenha feito algo aberrante
        if resp.status_code in (405, 403, 400) or "mutationType" not in body:
            req_url = f"{url}?query={urllib.parse.quote('{ __schema { mutationType { fields { name args { name type { name } } } } } }')}"
            resp = client.get(req_url, headers={"User-Agent": DEFAULT_USER_AGENT}, timeout=15)
            body = resp.text
            method_used = "GET"
            
        if resp.status_code == 200 and "mutationType" in body:
            try:
                data = resp.json()
                mutations = data.get("data", {}).get("__schema", {}).get("mutationType", {})
                if mutations:
                    fields = mutations.get("fields", [])
                    dangerous_mutations = [
                        f for f in fields
                        if any(k in f.get("name", "").lower() for k in 
                               ["delete", "remove", "update", "create", "admin", "reset", "password", "exec"])
                    ]
                    if dangerous_mutations:
                        names = [m["name"] for m in dangerous_mutations[:10]]
                        if method_used == "POST":
                            raw_req = format_raw_request("POST", url, dict(resp.request.headers), MUTATIONS_QUERY)
                        else:
                            raw_req = format_raw_request("GET", req_url, dict(resp.request.headers))
                            
                        raw_res = format_raw_response(resp.status_code, dict(resp.headers), body[:3000])
                        findings.append({
                            "url": url,
                            "type": "DANGEROUS_MUTATIONS_EXPOSED",
                            "risk": "HIGH",
                            "status": resp.status_code,
                            "mutations": names,
                            "details": f"Mutations perigosas expostas via {method_used}: {', '.join(names)}",
                            "request_raw": raw_req,
                            "response_raw": raw_res,
                        })
            except Exception:
                pass
    except Exception:
        pass
    
    # 4) Field Suggestions (info leak)
    try:
        resp = client.post(url, content=SUGGESTIONS_QUERY, headers=headers, timeout=10)
        body = resp.text
        method_used = "POST"
        
        if "Did you mean" not in body and "suggestions" not in body.lower():
            req_url = f"{url}?query={urllib.parse.quote('{ __typ }')}"
            resp = client.get(req_url, headers={"User-Agent": DEFAULT_USER_AGENT}, timeout=10)
            body = resp.text
            method_used = "GET"
            
        if "Did you mean" in body or "suggestions" in body.lower():
            if method_used == "POST":
                raw_req = format_raw_request("POST", url, dict(resp.request.headers), SUGGESTIONS_QUERY)
            else:
                raw_req = format_raw_request("GET", req_url, dict(resp.request.headers))
                
            raw_res = format_raw_response(resp.status_code, dict(resp.headers), body[:2000])
            findings.append({
                "url": url,
                "type": "FIELD_SUGGESTIONS_ENABLED",
                "risk": "LOW",
                "status": resp.status_code,
                "details": f"Field suggestions habilitadas via {method_used} — permite enumeração de campos",
                "request_raw": raw_req,
                "response_raw": raw_res,
            })
    except Exception:
        pass
    
    return findings


def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")
    
    if not httpx:
        error("httpx não instalado")
        return []

    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   🧬  {C.BOLD}{C.CYAN}GRAPHQL SECURITY SCANNER{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    outdir = ensure_outdir(target, "graphql")
    results_file = outdir / "graphql.json"
    
    # Carregar URLs
    urls_file = Path("output") / target / "domain" / "urls_valid.txt"
    if not urls_file.exists():
        urls_file = Path("output") / target / "urls" / "urls_200.txt"
    
    urls = set()
    if urls_file.exists():
        for line in urls_file.read_text().splitlines():
            url = line.strip()
            if url:
                parsed = urlparse(url)
                base = f"{parsed.scheme}://{parsed.netloc}"
                urls.add(base)
    
    # Gerar endpoints GraphQL para cada base URL
    test_urls = []
    for base in urls:
        for path in GRAPHQL_PATHS:
            test_urls.append(f"{base}{path}")
    
    # Adicionar endpoints encontrados pelo endpoint plugin
    endpoint_file = Path("output") / target / "endpoint" / "graphql.txt"
    if endpoint_file.exists():
        for line in endpoint_file.read_text().splitlines():
            if line.strip():
                test_urls.append(line.strip())
    
    test_urls = list(set(test_urls))
    total_urls = len(test_urls)
    info(f"   📊 Testando {total_urls} endpoints GraphQL potenciais")
    
    all_findings = []
    
    limits = httpx.Limits(max_keepalive_connections=50, max_connections=100)
    with httpx.Client(verify=False, follow_redirects=True, timeout=15, limits=limits) as client:
        with ThreadPoolExecutor(max_workers=35) as executor:
            futures = {executor.submit(test_endpoint, client, url): url for url in test_urls}
            
            done_count = 0
            for future in as_completed(futures):
                done_count += 1
                if done_count % 20 == 0 or done_count == total_urls:
                    pct = int((done_count / total_urls) * 100) if total_urls > 0 else 100
                    print(f"   [Total: {total_urls} | Atual: {done_count}] {pct}% completo... ({len(all_findings)} encontrados)", end="\r")

                try:
                    findings = future.result()
                    if findings:
                        all_findings.extend(findings)
                        print(" " * 80, end="\r")
                        for f in findings:
                            info(f"   🚨 {C.RED}{f['type']}: {futures[future]}{C.END}")
                except Exception:
                    pass
    
    print("")  # Quebra de linha apos o progresso
    
    results_file.write_text(json.dumps(all_findings, indent=2, ensure_ascii=False))
    
    if all_findings:
        success(f"🧬 {len(all_findings)} problemas GraphQL encontrados!")
    else:
        success("✅ Nenhum problema GraphQL detectado")
    
    return [str(results_file)]
