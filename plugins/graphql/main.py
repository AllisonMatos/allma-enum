#!/usr/bin/env python3
"""
GraphQL Introspection Checker — Verifica se o schema está exposto.
"""
import requests
from pathlib import Path

from menu import C
from ..output import info, success, warn, error

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
  }
}
fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
}
fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}
fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
"""

def ensure_outdir(target: str) -> Path:
    outdir = Path("output") / target / "graphql"
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir

def check_graphql(url: str) -> dict | None:
    """Verifica um endpoint específico."""
    try:
        resp = requests.post(
            url, 
            json={"query": INTROSPECTION_QUERY}, 
            verify=False, 
            timeout=10,
            headers={"Content-Type": "application/json"}
        )
        if resp.status_code == 200 and "__schema" in resp.text:
            return {
                "url": url,
                "vulnerable": True,
                "size": len(resp.text)
            }
    except:
        pass
    return None

def run(context: dict):
    target = context.get("target")
    if not target:
        raise ValueError("Target required")
        
    info(
        f"\n🧬───────────────────────────────────────────────────────────🧬\n"
        f"   📊 {C.BOLD}{C.CYAN}INICIANDO MÓDULO: GRAPHQL INTROSPECTION CHECKER{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🧬───────────────────────────────────────────────────────────🧬\n"
    )
    
    # 1. Carregar URLs e procurar por /graphql
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    if not urls_file.exists():
        warn("⚠️ Arquivo de URLs não encontrado.")
        return []
        
    urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]
    
    # Filtrar potenciais endpoints GraphQL
    graphql_endpoints = set()
    for u in urls:
        if "/graphql" in u or "/gql" in u or "/v1/graphql" in u:
            graphql_endpoints.add(u)
    
    # Se não encontrar nada óbvio, tentar o padrão
    if not graphql_endpoints:
        from urllib.parse import urlparse
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else f"https://{target}"
        graphql_endpoints.add(f"{base}/graphql")
        graphql_endpoints.add(f"{base}/api/graphql")

    info(f"   📂 Testando {len(graphql_endpoints)} potenciais endpoints GraphQL...")
    
    findings = []
    for ep in graphql_endpoints:
        result = check_graphql(ep)
        if result:
            warn(f"   🚩 [GRAPHQL INTROSPECTION] {C.YELLOW}{ep}{C.END} (Schema exposto!)")
            findings.append(result)
            
    # 3. Salvar Resultados
    outdir = ensure_outdir(target)
    out_file = outdir / "findings.json"
    
    import json
    with open(out_file, "w") as f:
        json.dump(findings, f, indent=4)
        
    if findings:
        success(f"\n   ✔ {len(findings)} endpoints GraphQL vulneráveis encontrados!")
    else:
        info("\n   ✔ Nenhum endpoint GraphQL com introspection habilitado.")
        
    return findings
