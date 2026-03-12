import re
import json
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from collections import defaultdict
from typing import List, Dict, Any

from menu import C
from ..output import info, warn, success, error

# ====================================================================
# CONFIGS & RULES
# ====================================================================

# Rule sets for URL Classification
ClassificationRules = {
    "LOGIN": r"(?i)(/login|/signin|/auth|/oauth|/sso|/logon)",
    "API": r"(?i)(/api/|/graphql|/v[0-9]+/|/rest)",
    "ADMIN": r"(?i)(/admin|/administrator|/manage|/dashboard|/panel|/wp-admin)",
    "UPLOAD": r"(?i)(/upload|/import|/media|/file|/attachment)",
    "DEBUG": r"(?i)(/debug|/test|/dev|/trace|/console|phpinfo)",
    "DOCS": r"(?i)(/swagger|/docs|/openapi|/api-docs)"
}

# Rule sets for Vulnerability Pattern Detection
VulnPatterns = {
    "LFI_RFI": {
        "params": ["file", "path", "dir", "document", "folder", "root", "pg", "style", "pdf", "template"],
        "name": "Local/Remote File Inclusion",
        "risk": "HIGH"
    },
    "SQLI_IDOR": {
        "params": ["id", "user", "account", "number", "order", "query", "search", "q", "pwd", "email"],
        "name": "SQLi / IDOR",
        "risk": "HIGH"
    }
}

# Base de Conhecimento mapeando Tecnologias para Dicas de Hacking (Tips)
KnowledgeBase = {
    "Spring Boot": ["Busque por actuators expostos: /actuator/env, /actuator/heapdump", "Teste para restrições de Spring4Shell"],
    "Cloudflare": ["Tente bypassar o WAF encontrando o IP de origem via Censys/Shodan", "Configurações incorretas de cache (Web Cache Poisoning)"],
    "Amazon S3": ["Teste se o bucket permite leitura/escrita anônima (AWS CLI)", "Verifique subdomain takeover se retornar 404"],
    "GraphQL": ["Execute query de instrospecção", "Teste ataque de batch query para bypassar Rate Limiting", "Teste IDORs em queries GraphQL customizadas"],
    "WebSocket": ["Verifique Cross-Site WebSocket Hijacking (CSWSH)", "Fuzzing para exceções não tratadas que derrubam o websocket"],
    "WordPress": ["Enumere usuários via /wp-json/wp/v2/users", "Escaneie por plugins obsoletos e vulneráveis", "Verifique xmlrpc.php para ataques de brute-force"],
    "PHP": ["Procure por phpinfo.php exposto", "Busque por vulnerabilidades de Type Juggling", "Teste comparações soltas (loose comparisons)"],
    "React": ["Verifique Source Maps por lógica sensível ou chaves expostas", "Busque XSS em dangerouslySetInnerHTML"],
    "Firebase": ["Verifique se o banco de dados está aberto para leitura/escrita em /.json", "Extraia chaves de API dos bundles JS principais"]
}

# ====================================================================
# ENGINE CLASSES
# ====================================================================

class IntelligenceEngine:
    def __init__(self, target: str):
        self.target = target
        self.base_dir = Path("output") / target
        self.outdir = self.base_dir / "intelligence"
        self.outdir.mkdir(parents=True, exist_ok=True)
        
        # Load Raw Data
        self.urls = self._load_urls()
        self.technologies = self._load_technologies()
        self.js_files = self._load_json("domain/extracted_js_routes.json") # Note: was moved to jsscanner in domain
        if not self.js_files:
             self.js_files = self._load_json("jsscanner/js_routes.json")
             
        # Output artifacts
        self.classified_urls = []
        self.vuln_patterns = []
        self.risk_ranking = defaultdict(lambda: {"score": 0.0, "reasons": [], "tags": set()})
        self.knowledge_tips = {}

    def _load_urls(self) -> List[str]:
        f = self.base_dir / "urls" / "urls_valid.txt"
        if f.exists():
            return [line.strip() for line in f.read_text().splitlines() if line.strip()]
        return []
        
    def _load_technologies(self) -> Dict:
        f = self.base_dir / "domain" / "technologies.json"
        if f.exists():
            try: return json.loads(f.read_text())
            except: pass
        return {}

    def _load_json(self, relative_path: str) -> Any:
        f = self.base_dir / relative_path
        if f.exists():
            try: return json.loads(f.read_text())
            except: pass
        return []

    def classify_urls(self):
        """Analyzes all URLs and assigns tags (LOGIN, API, etc.)"""
        for url in self.urls:
            tags = []
            for tag_name, regex in ClassificationRules.items():
                if re.search(regex, url):
                    tags.append(tag_name)
                    
            if tags:
                self.classified_urls.append({
                    "url": url,
                    "tags": tags
                })
                
                # Apply rules to Global Risk Score
                subdomain = urlparse(url).netloc
                for tag in tags:
                    self.risk_ranking[subdomain]["tags"].add(tag)
                    if tag == "ADMIN":
                        self.risk_ranking[subdomain]["score"] += 3.0
                        self.risk_ranking[subdomain]["reasons"].append("Exposed Admin Panel/Path")
                    elif tag == "API" or tag == "DEBUG":
                        self.risk_ranking[subdomain]["score"] += 1.5
                    elif tag == "LOGIN":
                        self.risk_ranking[subdomain]["score"] += 1.0

    def detect_vulnerabilities(self):
        """Detect risk patterns based on URL parameters"""
        for url in self.urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query).keys()
            
            if not params:
                 continue
                 
            for vuln_key, vuln_info in VulnPatterns.items():
                 matched_params = [p for p in params if p.lower() in vuln_info["params"]]
                 if matched_params:
                      self.vuln_patterns.append({
                           "url": url,
                           "vulnerability": vuln_info["name"],
                           "risk_level": vuln_info["risk"],
                           "matched_parameters": matched_params
                      })
                      
                      # Apply to Global Risk Score
                      subdomain = parsed.netloc
                      self.risk_ranking[subdomain]["score"] += 2.0
                      self.risk_ranking[subdomain]["reasons"].append(f"Suspicious params for {vuln_info['name']}")

    def generate_knowledge(self):
        """Map discovered technologies to actionable Hacking Tips"""
        for subdomain, data in self.technologies.items():
            tips = []
            matched_techs = []
            
            tech_list = data.get("technologies", [])
            for tech in tech_list:
                t_name = tech.get("name", "")
                
                # Loose matching against our Knowledge Base
                for kb_name, kb_tips in KnowledgeBase.items():
                    if kb_name.lower() in t_name.lower():
                        tips.extend(kb_tips)
                        matched_techs.append(t_name)
                        
            # Remove duplicated tips
            tips = list(set(tips))
            
            if tips:
                self.knowledge_tips[subdomain] = {
                    "matched_technologies": list(set(matched_techs)),
                    "tips": tips
                }
                
                # Factor in the Risk ranking
                self.risk_ranking[subdomain]["score"] += 0.5 * len(tips)

    def process_js_risk(self):
         """Increases risk score if APIs or logic flaws exist in JavaScript"""
         if not self.js_files:
              return
              
         for js_data in self.js_files:
              # js_routes.json array structure has "source", "routes", "parameters"
              src = js_data.get("source", "")
              num_routes = len(js_data.get("routes", []))
              
              if num_routes > 0:
                   subdomain = urlparse(src).netloc
                   # Limiting unbounded score growth
                   self.risk_ranking[subdomain]["score"] += min(num_routes * 0.2, 3.0)
                   self.risk_ranking[subdomain]["reasons"].append(f"Exposed {num_routes} API routes in JavaScript")

    def run_all(self):
        info(f"{C.BOLD}{C.BLUE}[*] Running Intelligence Engine Analysis...{C.END}")
        
        info("   - Classifying URLs...")
        self.classify_urls()
        
        info("   - Finding Vulnerability Patterns...")
        self.detect_vulnerabilities()
        
        info("   - Analyzing JS Risk factors...")
        self.process_js_risk()
        
        info("   - Querying Knowledge Base against Core Technologies...")
        self.generate_knowledge()
        
        # Cleanup and sort Risk Ranking
        final_ranking = []
        for subdomain, metrics in self.risk_ranking.items():
            # Round score
            final_score = round(min(metrics["score"], 10.0), 1)
            
            # Remove duplicate reasons
            reasons = list(set(metrics["reasons"]))
            
            final_ranking.append({
                "subdomain": subdomain,
                "score": final_score,
                "tags": list(metrics["tags"]),
                "reasons": reasons
            })
            
        final_ranking = sorted(final_ranking, key=lambda x: x["score"], reverse=True)
        
        # Save artifacts
        with open(self.outdir / "risk_ranking.json", "w") as f:
            json.dump(final_ranking, f, indent=2)
            
        with open(self.outdir / "url_classification.json", "w") as f:
            json.dump(self.classified_urls, f, indent=2)
            
        with open(self.outdir / "vuln_patterns.json", "w") as f:
            json.dump(self.vuln_patterns, f, indent=2)
            
        with open(self.outdir / "knowledge_tips.json", "w") as f:
            json.dump(self.knowledge_tips, f, indent=2)
            
        success(f"   + Top High Value Target: {final_ranking[0]['subdomain']} (Score: {final_ranking[0]['score']})" if final_ranking else "   + No high value targets generated.")
        success(f"   + {len(self.vuln_patterns)} suspicious vulnerability patterns detected.")
        success(f"   + {len(self.classified_urls)} URLs automatically classified.")
        
        return {
            "risk_ranking": final_ranking,
            "classified_urls": self.classified_urls,
            "vuln_patterns": self.vuln_patterns,
            "knowledge_tips": self.knowledge_tips
        }

def run(context: dict):
    target = context.get("target")
    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   🧠 {C.BOLD}{C.CYAN}INICIANDO MÓDULO: ATTACK SURFACE INTELLIGENCE{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )
    
    engine = IntelligenceEngine(target)
    engine.run_all()
    
    success(f"✔ Inteligência gerada salva em: {engine.outdir}\n")
    return True
