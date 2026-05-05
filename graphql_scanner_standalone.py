#!/usr/bin/env python3
"""
Standalone GraphQL Security Scanner
Extraído do Enum-Allma V11.6 para execução isolada.
Uso: python3 graphql_scanner_standalone.py https://alvo.com/
     python3 graphql_scanner_standalone.py urls.txt
"""
import sys
import json
import urllib.parse
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

try:
    import httpx
except ImportError:
    print("❌ Erro: A biblioteca 'httpx' é necessária. Instale com: pip install httpx")
    sys.exit(1)

# Configurações Padrão
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

# Cores ANSI
class C:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/gql", "/query",
    "/api/graphql", "/api/gql", "/v1/graphql", "/v2/graphql",
    "/graphql/v1", "/playground", "/__graphql",
    "/api/v1/gql", "/graphql/console", "/graphql/playground",
]

INTROSPECTION_QUERY = '{"query": "{ __schema { types { name fields { name } } } }"}'
BATCH_QUERY = '[{"query": "{ __typename }"}, {"query": "{ __typename }"}]'
MUTATIONS_QUERY = '{"query": "{ __schema { mutationType { fields { name args { name type { name } } } } } }"}'
SUGGESTIONS_QUERY = '{"query": "{ __typ }"}'


def format_raw_request(method: str, url: str, headers: dict, body: str = "") -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    host = parsed.netloc
    header_lines = f"Host: {host}\n"
    header_lines += "\n".join(f"{k}: {v}" for k, v in headers.items() if k.lower() != "host")
    result = f"{method} {path} HTTP/1.1\n{header_lines}"
    if body:
        result += f"\n\n{body}"
    return result

def format_raw_response(status_code: int, headers: dict, body: str = "") -> str:
    header_lines = "\n".join(f"{k}: {v}" for k, v in headers.items())
    result = f"HTTP/1.1 {status_code}\n{header_lines}"
    if body:
        content = body[:10000]
        if len(body) > 10000:
            content += "\n... [Truncated]"
        result += f"\n\n{content}"
    return result

def _generate_curl(request_raw: str, url: str) -> str:
    if not request_raw or not url: return ""
    lines = request_raw.strip().splitlines()
    if not lines: return ""
    method = lines[0].split()[0] if len(lines[0].split()) > 0 else "GET"
    headers, body, is_body = [], [], False
    for line in lines[1:]:
        if is_body: body.append(line)
        elif not line.strip(): is_body = True
        else: headers.append(line)
    curl = f"curl -i -s -k -X {method} '{url}'"
    for h in headers:
        if h.lower().startswith("host:") or h.lower().startswith("content-length:"): continue 
        h_escaped = h.replace("'", "'\\''")
        curl += f" \\\n    -H '{h_escaped}'"
    if body:
        body_str = "\\n".join(body).replace("'", "'\\''")
        curl += f" \\\n    --data-binary '{body_str}'"
    return curl

def finding(**kwargs):
    kwargs["timestamp"] = datetime.now(timezone.utc).isoformat()
    evidence = kwargs.get("evidence", {})
    if "request_raw" in evidence and kwargs.get("url"):
        evidence["curl_command"] = _generate_curl(evidence["request_raw"], kwargs["url"])
    kwargs["evidence"] = evidence
    return kwargs

def is_graphql_json_response(body: str) -> bool:
    try:
        data = json.loads(body)
    except Exception:
        return False
    if isinstance(data, dict):
        return "data" in data or "errors" in data
    if isinstance(data, list):
        return all(isinstance(i, dict) and ("data" in i or "errors" in i) for i in data)
    return False


def test_endpoint(client, url):
    findings = []
    headers = {"Content-Type": "application/json", "User-Agent": DEFAULT_USER_AGENT}
    
    # 1) Introspection
    try:
        resp = client.post(url, content=INTROSPECTION_QUERY, headers=headers, timeout=15)
        body, method_used = resp.text, "POST"
        
        if resp.status_code in (405, 403, 400, 401) or "__schema" not in body:
            req_url = f"{url}?query={urllib.parse.quote('{ __schema { types { name fields { name } } } }')}"
            resp = client.get(req_url, headers={"User-Agent": DEFAULT_USER_AGENT}, timeout=15)
            body, method_used = resp.text, "GET"

        detected = resp.status_code == 200 and "__schema" in body
        validated = detected and is_graphql_json_response(body)
        if validated:
            data = resp.json()
            types_count = len(data.get("data", {}).get("__schema", {}).get("types", []))
            
            raw_req = format_raw_request("POST", url, dict(resp.request.headers), INTROSPECTION_QUERY) if method_used == "POST" else format_raw_request("GET", req_url, dict(resp.request.headers))
            raw_res = format_raw_response(resp.status_code, dict(resp.headers), body[:3000])
            
            findings.append(finding(
                type="INTROSPECTION_ENABLED", risk="HIGH", confidence="CONFIRMED", url=url,
                description=f"Introspection habilitada via {method_used} — {types_count} types expostos",
                evidence={"request_raw": raw_req, "response_raw": raw_res}
            ))
    except Exception: pass
    
    # 2) Batch Queries
    try:
        resp = client.post(url, content=BATCH_QUERY, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list) and len(data) > 1:
                findings.append(finding(
                    type="BATCH_QUERIES_ALLOWED", risk="MEDIUM", confidence="HIGH", url=url,
                    description="Batch queries aceitas — potencial DoS/rate limit bypass",
                    evidence={"request_raw": format_raw_request("POST", url, dict(resp.request.headers), BATCH_QUERY),
                              "response_raw": format_raw_response(resp.status_code, dict(resp.headers), resp.text[:2000])}
                ))
    except Exception: pass
    
    # 3) Mutations
    try:
        resp = client.post(url, content=MUTATIONS_QUERY, headers=headers, timeout=15)
        body, method_used = resp.text, "POST"
        
        if resp.status_code in (405, 403, 400) or "mutationType" not in body:
            req_url = f"{url}?query={urllib.parse.quote('{ __schema { mutationType { fields { name args { name type { name } } } } } }')}"
            resp = client.get(req_url, headers={"User-Agent": DEFAULT_USER_AGENT}, timeout=15)
            body, method_used = resp.text, "GET"
            
        if resp.status_code == 200 and "mutationType" in body:
            data = resp.json()
            fields = data.get("data", {}).get("__schema", {}).get("mutationType", {}).get("fields", [])
            dangerous = [f["name"] for f in fields if any(k in f.get("name", "").lower() for k in ["delete", "remove", "update", "create", "admin", "reset", "password", "exec"])]
            
            if dangerous:
                raw_req = format_raw_request("POST", url, dict(resp.request.headers), MUTATIONS_QUERY) if method_used == "POST" else format_raw_request("GET", req_url, dict(resp.request.headers))
                findings.append(finding(
                    type="DANGEROUS_MUTATIONS_EXPOSED", risk="HIGH", confidence="HIGH", url=url,
                    description=f"Mutations perigosas expostas: {', '.join(dangerous[:10])}",
                    evidence={"request_raw": raw_req, "response_raw": format_raw_response(resp.status_code, dict(resp.headers), body[:3000])}
                ))
    except Exception: pass
    
    # 4) Field Suggestions
    try:
        resp = client.post(url, content=SUGGESTIONS_QUERY, headers=headers, timeout=10)
        body, method_used = resp.text, "POST"
        if "Did you mean" not in body and "suggestions" not in body.lower():
            req_url = f"{url}?query={urllib.parse.quote('{ __typ }')}"
            resp = client.get(req_url, headers={"User-Agent": DEFAULT_USER_AGENT}, timeout=10)
            body, method_used = resp.text, "GET"
            
        if resp.status_code == 200 and ("Did you mean" in body or "suggestions" in body.lower()) and is_graphql_json_response(body):
            raw_req = format_raw_request("POST", url, dict(resp.request.headers), SUGGESTIONS_QUERY) if method_used == "POST" else format_raw_request("GET", req_url, dict(resp.request.headers))
            findings.append(finding(
                type="FIELD_SUGGESTIONS_ENABLED", risk="LOW", confidence="HIGH", url=url,
                description=f"Field suggestions habilitadas via {method_used} — permite enumeração de campos",
                evidence={"request_raw": raw_req, "response_raw": format_raw_response(resp.status_code, dict(resp.headers), body[:2000])}
            ))
    except Exception: pass
    
    return findings


def main():
    print(f"\n{C.BOLD}{C.CYAN}🧬 STANDALONE GRAPHQL SECURITY SCANNER{C.END}")
    
    if len(sys.argv) < 2:
        print(f"Uso: python3 {sys.argv[0]} [http://alvo.com/ | lista_urls.txt]")
        sys.exit(1)
        
    target_input = sys.argv[1]
    urls = set()
    
    if target_input.startswith("http://") or target_input.startswith("https://"):
        parsed = urlparse(target_input)
        # Se mandou o /graphql direto, escaneia só ele
        if parsed.path.endswith("ql"):
            urls.add(target_input)
            test_urls = [target_input]
        else:
            base = f"{parsed.scheme}://{parsed.netloc}"
            urls.add(base)
            test_urls = [f"{base}{path}" for path in GRAPHQL_PATHS]
    else:
        try:
            with open(target_input, "r") as f:
                for line in f:
                    u = line.strip()
                    if u.startswith("http"): urls.add(f"{urlparse(u).scheme}://{urlparse(u).netloc}")
            test_urls = [f"{base}{path}" for base in urls for path in GRAPHQL_PATHS]
        except Exception as e:
            print(f"Erro lendo arquivo: {e}")
            sys.exit(1)
            
    test_urls = list(set(test_urls))
    total_urls = len(test_urls)
    print(f"📊 Testando {total_urls} endpoints GraphQL potenciais...\n")
    
    all_findings = []
    
    def test_endpoint_safe(url):
        with httpx.Client(verify=False, follow_redirects=True, timeout=15) as thread_client:
            return test_endpoint(thread_client, url)

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(test_endpoint_safe, url): url for url in test_urls}
        done_count = 0
        for future in as_completed(futures):
            done_count += 1
            if done_count % 10 == 0 or done_count == total_urls:
                print(f"   [{done_count}/{total_urls}] Verificando...", end="\r")
            try:
                res = future.result()
                if res:
                    all_findings.extend(res)
                    print(" " * 80, end="\r")
                    for f in res:
                        print(f"🚨 {C.RED}[{f['risk']}] {f['type']}: {futures[future]}{C.END}")
            except Exception: pass
            
    print("\n")
    if all_findings:
        out_file = "graphql_results.json"
        with open(out_file, "w") as f:
            json.dump(all_findings, f, indent=2, ensure_ascii=False)
        print(f"{C.GREEN}✔ {len(all_findings)} problemas GraphQL encontrados! Salvos em {out_file}{C.END}")
    else:
        print(f"{C.GREEN}✔ Nenhum problema GraphQL detectado.{C.END}")

if __name__ == "__main__":
    main()
