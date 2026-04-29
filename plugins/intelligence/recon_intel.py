"""
recon_intel.py v2.0 — 20 detectores independentes para Recon Intelligence.
Integrado ao pipeline do Enum-Allma como modulo importavel.
"""
import re, sys, json, base64
from pathlib import Path
from dataclasses import dataclass, asdict
from urllib.parse import urlparse

@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str
    evidence: str = ""
    fix: str = ""

SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
SEV_COLORS = {
    "critical":("#ff4040","rgba(255,64,64,0.15)"),
    "high":("#f85149","rgba(248,81,73,0.12)"),
    "medium":("#d29922","rgba(210,153,34,0.12)"),
    "low":("#3fb950","rgba(63,185,80,0.10)"),
    "info":("#58a6ff","rgba(88,166,255,0.10)"),
}

def strip_html(html):
    t = re.sub(r'<style[^>]*>.*?</style>','',html,flags=re.DOTALL)
    t = re.sub(r'<script[^>]*>.*?</script>','',t,flags=re.DOTALL)
    t = re.sub(r'<[^>]+>',' ',t)
    return re.sub(r'\s+',' ',t).strip()

def code_text(html):
    blocks = re.findall(r'<(?:code|pre)[^>]*>(.*?)</(?:code|pre)>',html,re.DOTALL)
    return ' '.join(re.sub(r'<[^>]+>','',b) for b in blocks)

def all_urls(html):
    return list(set(re.findall(r'https?://[^\s"\'<>]{8,}',html)))

# D01 ALB/Origin
def detect_alb_origins(html,text):
    findings=[]
    pats=[r'https?://((?:alb|nlb|elb|lb|origin|direct|backend|raw)\.[^\s"\'<>/]+)',
          r'https?://([a-z0-9-]+\.new\.[^\s"\'<>/]+)',
          r'https?://([a-z0-9-]+\.internal\.[^\s"\'<>/]+)']
    found=set()
    for pat in pats:
        for host in re.findall(pat,html,re.IGNORECASE):
            if host not in found:
                found.add(host)
                prefix=host.split('.')[0].upper()
                findings.append(Finding("high","WAF BYPASS",
                    f"`{host}` — origin direto, fora do escopo catalogado",
                    f"Prefixo <b>{prefix}</b> indica LB/origin exposto sem WAF/CDN.",
                    host,f"curl -sI https://{host} | grep -i 'cf-ray\\|server\\|x-cache'"))
    return findings

# D02 Path Leaks
SYSTEM_USERS={'www-data','ubuntu','ec2-user','root','deploy','runner','node','app','git','nginx'}
def detect_path_leaks(html,text):
    findings=[]
    for user,path in re.findall(r'/home/([a-z_][a-z0-9_-]{1,32})/([^\s"\'<>]{4,80})',html):
        if user in SYSTEM_USERS: continue
        findings.append(Finding("medium","PATH LEAK",
            f"Username <code>{user}</code> exposto via source map",
            f"Caminho <code>/home/{user}/{path[:50]}</code> vazando em JS bundle.",
            f"/home/{user}/{path[:60]}",f'site:github.com "{user}"'))
    return findings

# D03 SPF IPs
def detect_spf_ips(html,text):
    findings=[]
    spf_blocks=re.findall(r'v=spf1[^<"\']{10,500}',text,re.IGNORECASE)
    ips=[]
    for b in spf_blocks: ips+=re.findall(r'ip[46]:([0-9a-fA-F.:\/]+)',b)
    ips=list(dict.fromkeys(ips))
    if ips:
        findings.append(Finding("high","ORIGIN IPs",
            f"IPs de origem no SPF: {', '.join(ips[:3])}{'...' if len(ips)>3 else ''}",
            f"SPF expoe <b>{len(ips)} IP(s)</b> de servidores reais. Bypass de CDN possivel.",
            ' | '.join(ips[:6]),
            f"curl -sk https://{ips[0].split('/')[0]} -H 'Host: TARGET' -I"))
    return findings

# D04 Staging
STAGING_KW=r'(?:tst|stg|staging|dev|uat|qa|test|sandbox|beta|pre|preprod|homolog|hml|demo|lab)'
def detect_staging(html,text):
    findings=[]
    hosts=set(re.findall(rf'([a-z0-9-]+\.{STAGING_KW}\.[a-z0-9.-]{{4,}})',html,re.IGNORECASE))
    hosts|=set(re.findall(rf'https?://([a-z0-9-]+\.(?:{STAGING_KW})\.[a-z0-9.-]{{3,}})',html,re.IGNORECASE))
    if hosts:
        hl=sorted(hosts)[:8]
        findings.append(Finding("medium","STAGING",
            f"{len(hosts)} ambiente(s) de teste/staging ativos",
            f"Staging: auth fraca, DEBUG, CORS permissivo.<br>Hosts: <code>{'</code> · <code>'.join(hl)}</code>",
            ', '.join(hl),"nuclei -t exposures/ -t misconfigs/ -l staging.txt"))
    return findings

# D05 Internal Tools
INTERNAL_TOOLS={
    'jenkins':('critical','Jenkins — RCE via Script Console'),
    'gitlab':('high','GitLab — source code, CI/CD tokens'),
    'jira':('medium','Jira — tickets internos'),
    'confluence':('medium','Confluence — docs internos'),
    'grafana':('medium','Grafana — dashboards internos'),
    'kibana':('high','Kibana — logs de producao'),
    'portainer':('critical','Portainer — gerenciamento Docker'),
    'vault':('critical','HashiCorp Vault — secrets'),
    'pgadmin':('critical','pgAdmin — painel PostgreSQL'),
    'phpmyadmin':('critical','phpMyAdmin — painel MySQL'),
    'jupyter':('critical','Jupyter Notebook — RCE Python'),
    'airflow':('critical','Apache Airflow — DAGs com RCE'),
    'prometheus':('medium','Prometheus — metricas expostas'),
}
def detect_internal_tools(html,text):
    findings=[]
    for tool,(sev,desc) in INTERNAL_TOOLS.items():
        hits=list(set(re.findall(rf'https?://[^\s"\'<>]*{tool}[^\s"\'<>]{{0,40}}',html,re.IGNORECASE)))
        if hits:
            findings.append(Finding(sev,"INTERNAL TOOL",
                f"{desc.split('—')[0].strip()} detectado: <code>{str(hits[0])[:60]}</code>",
                desc,str(hits[0])[:80],f"curl -sI {str(hits[0])[:60]} | head -20"))
    return findings

# D06 Dangerous Ports
DANGEROUS_PORTS={
    6379:('critical','Redis','Sem auth -> RCE via SLAVEOF'),
    27017:('critical','MongoDB','Sem auth -> dump completo'),
    9200:('critical','Elasticsearch','API REST sem auth'),
    2375:('critical','Docker API','Socket TCP sem TLS -> RCE'),
    5432:('high','PostgreSQL','Banco exposto'),
    3306:('high','MySQL','Banco exposto'),
    5984:('high','CouchDB','API REST -> dump'),
    8500:('high','Consul HTTP','Service discovery exposto'),
    5601:('high','Kibana','Logs expostos'),
    21:('high','FTP','FTP exposto'),
    23:('critical','Telnet','Cleartext'),
    3389:('high','RDP','Brute force, BlueKeep'),
    6443:('high','Kubernetes API','Verificar auth anonima'),
}
def detect_dangerous_ports(html,text):
    findings=[]
    seen=set()
    for groups in re.findall(r':(\d{2,5})\b|(\d{2,5})/tcp|[Pp]ort\s+(\d{2,5})',text):
        for g in groups:
            if g and g.isdigit(): seen.add(int(g))
    for url in all_urls(html):
        p=urlparse(url)
        if p.port: seen.add(p.port)
    for port in sorted(seen):
        if port in DANGEROUS_PORTS:
            sev,svc,desc=DANGEROUS_PORTS[port]
            findings.append(Finding(sev,f"PORT {port}",
                f"Porta <b>{port}</b> ({svc}) exposta",desc,f":{port}",
                f"nmap -sV -p {port} TARGET"))
    return findings

# D07 CNAME Takeover
TAKEOVER_SERVICES={
    'github.io':('high','GitHub Pages — repo deletado'),
    'herokuapp.com':('high','Heroku — app deletado'),
    'azurewebsites.net':('high','Azure Web Apps — recurso deletado'),
    's3.amazonaws.com':('high','S3 — bucket deletado'),
    'storage.googleapis.com':('high','GCS — bucket nao reclamado'),
}
def detect_cname_takeover(html,text):
    findings=[]
    for svc,(sev,desc) in TAKEOVER_SERVICES.items():
        if svc in html:
            findings.append(Finding(sev,"CNAME TAKEOVER",
                f"CNAME aponta para <code>{svc}</code> — possivel takeover",
                f"{desc}. Verificar se recurso existe.",svc,
                f"curl -sI https://{svc}"))
    return findings

# D08 JWT Analysis
def _b64decode(s):
    s+='='*(-len(s)%4)
    try: return base64.b64decode(s.replace('-','+').replace('_','/')).decode('utf-8',errors='replace')
    except: return ''

def detect_jwt_analysis(html,text):
    findings=[]
    jwts=list(set(re.findall(r'ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}',html)))
    if not jwts: return findings
    weak_algs=[]
    for jwt in jwts[:20]:
        parts=jwt.split('.')
        if len(parts)<2: continue
        header=_b64decode(parts[0])
        m=re.search(r'"alg"\s*:\s*"([^"]+)"',header)
        if m and m.group(1).upper().startswith('HS'): weak_algs.append(m.group(1))
    findings.append(Finding("high","JWT",
        f"{len(jwts)} JWT(s) — analisar algoritmo e claims",
        f"Algoritmos HMAC: <code>{'</code> <code>'.join(set(weak_algs)) or 'verificar'}</code>. Vetores: alg:none, weak secret, kid injection.",
        f"{len(jwts)} tokens","hashcat -a 0 -m 16500 token.jwt rockyou.txt"))
    return findings

# D09 Secrets
SECRET_PATTERNS=[
    ('critical','AWS Access Key',r'AKIA[0-9A-Z]{16}'),
    ('critical','GitHub Token',r'gh[pousr]_[A-Za-z0-9]{36,}'),
    ('critical','Slack Token',r'xox[baprs]-[A-Za-z0-9]{10,}'),
    ('critical','Stripe Live Key',r'sk_live_[A-Za-z0-9]{24,}'),
    ('high','Google API Key',r'AIza[0-9A-Za-z_-]{35}'),
    ('high','DB Connection String',r'(?:mysql|postgresql|mongodb|redis)://[^\s"\'<>]{8,80}'),
    ('medium','Internal RFC1918 IP',r'(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+'),
    ('medium','Basic Auth in URL',r'https?://[^:@\s]+:[^@\s]+@[^\s"\'<>]+'),
]
def detect_secrets(html,text):
    findings=[]
    space=code_text(html)+' '+text
    seen=set()
    for sev,name,pattern in SECRET_PATTERNS:
        if name in seen: continue
        matches=re.findall(pattern,space)
        if matches:
            seen.add(name)
            sample=str(matches[0])
            if len(sample)>12: sample=sample[:6]+'***'+sample[-4:]
            findings.append(Finding(sev,"SECRET",
                f"{name} detectado no report",
                f"Padrao encontrado {len(matches)}x. Validar se sao reais.",
                f"{sample} ({len(matches)}x)",
                f"grep -rE '{pattern[:50]}' . --include='*.js'"))
    return findings

# D10 CORS
def detect_cors(html,text):
    findings=[]
    if re.search(r'Access-Control-Allow-Origin.*\*.*Access-Control-Allow-Credentials.*true',text,re.IGNORECASE|re.DOTALL):
        findings.append(Finding("critical","CORS",
            "CORS: wildcard origin com credentials=true",
            "Qualquer origem pode fazer requests autenticados via JS.",
            "Allow-Origin: * + credentials: true",""))
    return findings

# D11 HTTP Methods
def detect_http_methods(html,text):
    findings=[]
    dangerous={'TRACE':('medium','Cross-Site Tracing'),'PUT':('high','Upload sem auth -> RCE')}
    for method,(sev,desc) in dangerous.items():
        if re.search(rf'\b{method}\b',html):
            findings.append(Finding(sev,"HTTP METHOD",
                f"Metodo HTTP <code>{method}</code> referenciado",desc,method,
                f"curl -X {method} https://TARGET/ -v"))
    return findings

# D12 Info Headers
def detect_info_headers(html,text):
    findings=[]
    for pat,sev,name,desc in [
        (r'[Ss]erver\s*:\s*(Apache[^\n<"\']{0,30}|nginx[^\n<"\']{0,30}|IIS[^\n<"\']{0,30})','medium','Server version','Versao exposta'),
        (r'[Xx]-[Pp]owered-[Bb]y\s*:\s*([^\n<"\']{3,60})','low','X-Powered-By','Framework exposto'),
    ]:
        m=re.search(pat,html+text)
        if m:
            val=m.group(1) if m.lastindex else m.group(0)
            findings.append(Finding(sev,"INFO DISCLOSURE",
                f"Header <code>{name}</code>: <code>{val[:50]}</code>",
                f"{desc}. Facilita fingerprinting.",f"{name}: {val[:60]}",""))
    return findings

# D13 Cloud Buckets
def detect_cloud_buckets(html,text):
    findings=[]
    for name in set(re.findall(r'([a-z0-9-]{3,63})\.blob\.core\.windows\.net',html)):
        findings.append(Finding("medium","CLOUD/AZURE",
            f"Azure Blob <code>{name}</code> — permissoes nao testadas",
            "Container Azure pode permitir listing anonimo.",
            f"https://{name}.blob.core.windows.net",
            f"curl -s 'https://{name}.blob.core.windows.net/?comp=list&restype=container'"))
    for name in set(re.findall(r'([a-z0-9.-]{3,63})\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com',html)):
        findings.append(Finding("medium","CLOUD/S3",
            f"S3 Bucket <code>{name}</code> detectado",
            "Verificar public access block e ACL.",
            f"https://{name}.s3.amazonaws.com",f"aws s3 ls s3://{name} --no-sign-request"))
    return findings

# D14 Email Security
def detect_email_security(html,text):
    findings=[]
    if re.search(r'DMARC.*?p=none',text,re.IGNORECASE):
        findings.append(Finding("medium","EMAIL SPOOF",
            "DMARC <code>p=none</code> — spoofing possivel",
            "Politica sem enforcement. Vetor de phishing.","DMARC p=none","Migrar: p=reject"))
    if re.search(r'v=spf1.*\+all',text,re.IGNORECASE):
        findings.append(Finding("critical","SPF",
            "SPF com <code>+all</code> — QUALQUER servidor pode enviar email!",
            "+all permite qualquer IP enviar email.","SPF: +all","Substituir +all por -all"))
    return findings

# D15 Tech CVEs
TECH_CVES={
    'Django':[('high','CVE-2024-38875','SQL injection via QuerySet')],
    'IIS':[('critical','CVE-2022-21907','IIS RCE via HTTP Trailer')],
    'jQuery':[('medium','CVE-2020-11022','XSS via html()')],
    'nginx':[('high','CVE-2021-23017','Resolver heap overflow')],
    'Apache':[('critical','CVE-2021-41773','Path traversal + RCE')],
    'Jenkins':[('critical','CVE-2024-23897','Arbitrary file read -> RCE')],
    'GitLab':[('critical','CVE-2023-7028','Account takeover')],
    'Confluence':[('critical','CVE-2023-22518','Auth bypass -> RCE')],
    'WordPress':[('high','CVE-2023-2745','Directory traversal')],
}
def detect_tech_cves(html,text):
    findings=[]
    for tech,cves in TECH_CVES.items():
        if re.search(rf'\b{re.escape(tech)}\b',html+text,re.IGNORECASE):
            for sev,cve_id,desc in cves[:2]:
                findings.append(Finding(sev,f"CVE/{tech}",
                    f"<b>{tech}</b> detectado — {cve_id}",desc,
                    f"{tech} + {cve_id}",f"nuclei -t cves/ -tags {tech.lower()} -u TARGET"))
    return findings

# D16 WAF Bypasses
WAF_BYPASSES={
    'Cloudflare':('medium',['Unicode normalization','Origin IP direto via SPF/Shodan']),
    'AWS WAF':('medium',['Chunked Transfer-Encoding bypass','Null bytes']),
    'F5 BIG-IP':('high',['CVE-2022-1388: auth bypass']),
}
def detect_waf_bypasses(html,text):
    findings=[]
    for waf,(sev,bypasses) in WAF_BYPASSES.items():
        if re.search(rf'\b{re.escape(waf)}\b',html+text,re.IGNORECASE):
            items='</li><li>'.join(bypasses)
            findings.append(Finding(sev,"WAF BYPASS",
                f"<b>{waf}</b> — tecnicas de bypass",
                f"<ul style='margin:4px 0 0 16px;'><li>{items}</li></ul>",
                waf,"wafwoof -u TARGET"))
    return findings

# D17 Suspicious Endpoints
SUSPICIOUS_ENDPOINTS={
    '/.env':('critical','Arquivo .env — credenciais'),
    '/.git':('critical','Repositorio Git exposto'),
    '/console':('high','Console de execucao'),
    '/debug':('high','Debug endpoint'),
    '/actuator':('high','Spring Boot Actuator'),
    '/swagger':('medium','Swagger UI'),
    '/graphiql':('medium','GraphiQL IDE'),
    '/metrics':('medium','Metricas internas'),
}
def detect_suspicious_endpoints(html,text):
    findings=[]
    found={}
    for url in all_urls(html):
        path=urlparse(url).path
        for suffix,(sev,desc) in SUSPICIOUS_ENDPOINTS.items():
            if path==suffix or path.startswith(suffix+'/'):
                if suffix not in found: found[suffix]=(sev,desc,url)
    for suffix,(sev,desc,url) in found.items():
        findings.append(Finding(sev,"ENDPOINT",
            f"<code>{suffix}</code> — {desc}",
            f"{desc}<br><code>{url[:80]}</code>",url,
            f"curl -sI '{url}'"))
    return findings

# D18 Dep Confusion
def detect_dep_confusion(html,text):
    findings=[]
    m=re.search(r'[Dd]ep[.\s_-]*[Cc]onf',html)
    if m:
        findings.append(Finding("high","DEP CONFUSION",
            "Pacotes internos detectados — supply chain attack",
            "Pacotes internos podem ser squatted em npm/PyPI -> RCE no CI/CD.",
            "dependency confusion","npm view PACKAGE 2>&1 | grep 'not found'"))
    return findings

# D19 Internal IPs
RFC1918=re.compile(r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b')
def detect_internal_ips(html,text):
    findings=[]
    clean=re.sub(r'v=spf1[^<"\']{0,400}','',text)
    hits=list(set(RFC1918.findall(clean)))
    if hits:
        findings.append(Finding("medium","INTERNAL IP",
            f"{len(hits)} IP(s) RFC1918 vazando",
            f"IPs internos: <code>{'</code> · <code>'.join(hits[:6])}</code>",
            ', '.join(hits[:8]),"Sanitizar headers/respostas"))
    return findings

# D20 Severity Mismatches
def detect_severity_mismatches(html,text):
    findings=[]
    if re.search(r'ip[46]:[0-9]',text,re.IGNORECASE) and re.search(r'SPF.*?tag-low',html,re.IGNORECASE|re.DOTALL):
        findings.append(Finding("info","SEV PATCH",
            "SPF com IPs marcado LOW -> deveria ser HIGH",
            "SPF com ip4/ip6 expoe servidores reais.","SPF + ip4","Corrigir scoring"))
    return findings

ALL_DETECTORS=[
    detect_alb_origins,detect_path_leaks,detect_spf_ips,detect_staging,
    detect_internal_tools,detect_dangerous_ports,detect_cname_takeover,
    detect_jwt_analysis,detect_secrets,detect_cors,detect_http_methods,
    detect_info_headers,detect_cloud_buckets,detect_email_security,
    detect_tech_cves,detect_waf_bypasses,detect_suspicious_endpoints,
    detect_dep_confusion,detect_internal_ips,detect_severity_mismatches,
]

def run_detectors(html_content, only_sev=None):
    """Run all 20 detectors on HTML content and return sorted findings."""
    text=strip_html(html_content)
    findings=[]
    for det in ALL_DETECTORS:
        try: findings.extend(det(html_content,text))
        except Exception as e: print(f"[WARN] {det.__name__}: {e}",file=sys.stderr)
    seen,unique=set(),[]
    for f in findings:
        if f.title not in seen:
            seen.add(f.title)
            unique.append(f)
    if only_sev:
        unique=[f for f in unique if f.severity in only_sev]
    unique.sort(key=lambda f: SEV_ORDER.get(f.severity,9))
    return unique

def sev_badge(sev):
    color,bg=SEV_COLORS.get(sev,("#8b949e","rgba(139,148,158,0.1)"))
    return (f'<span style="display:inline-flex;align-items:center;padding:2px 8px;'
            f'border-radius:8px;font-size:10px;font-weight:700;background:{bg};'
            f'color:{color};border:1px solid {color};white-space:nowrap;flex-shrink:0;">'
            f'{sev.upper()}</span>')

def finding_row(f):
    fix_html=""
    if f.fix:
        fix_html=(f'<pre style="margin:6px 0 0;padding:6px 10px;'
                  f'background:var(--bg-primary,#0d1117);border:1px solid var(--border-color,#30363d);'
                  f'border-radius:4px;font-size:10px;color:#3fb950;white-space:pre-wrap;'
                  f'overflow-x:auto;">{f.fix}</pre>')
    return (f'\n<div style="display:flex;gap:10px;align-items:flex-start;'
            f'padding:10px 16px;border-bottom:1px solid var(--border-color,#30363d);">'
            f'{sev_badge(f.severity)}'
            f'<div style="flex:1;min-width:0;">'
            f'<div style="font-size:12px;font-weight:600;color:var(--text-primary,#e6edf3);'
            f'margin-bottom:2px;">{f.title}</div>'
            f'<div style="font-size:11px;color:var(--text-secondary,#8b949e);line-height:1.6;">'
            f'{f.detail}{fix_html}</div></div></div>')

def build_intel_card(findings):
    """Build the Recon Intelligence HTML card from findings list."""
    if not findings: return ""
    n_total=len(findings)
    n_high=sum(1 for f in findings if f.severity in ('critical','high'))
    n_med=sum(1 for f in findings if f.severity=='medium')
    rows=''.join(finding_row(f) for f in findings)
    return (
        '\n<div style="margin-bottom:24px;border:1px solid rgba(248,81,73,0.4);border-radius:8px;overflow:hidden;">\n'
        '<div style="background:rgba(248,81,73,0.08);padding:10px 16px;border-bottom:1px solid rgba(248,81,73,0.3);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">\n'
        '<span style="font-size:13px;font-weight:700;color:#f85149;">🔍 Recon Intelligence — Achados Enterrados</span>\n'
        '<div style="display:flex;gap:6px;align-items:center;">\n'
        f'<span style="font-size:10px;padding:2px 8px;border-radius:8px;background:rgba(248,81,73,0.15);color:#f85149;border:1px solid rgba(248,81,73,0.4);">{n_high} critical/high</span>\n'
        f'<span style="font-size:10px;padding:2px 8px;border-radius:8px;background:rgba(210,153,34,0.12);color:#d29922;border:1px solid rgba(210,153,34,0.4);">{n_med} medium</span>\n'
        f'<span style="font-size:10px;padding:2px 8px;border-radius:8px;background:var(--bg-tertiary,#161b22);color:var(--text-muted,#6e7681);border:1px solid var(--border-color,#30363d);">{n_total} total</span>\n'
        '</div></div>\n'
        '<div style="padding:4px 0;">\n'
        '<p style="font-size:11px;color:var(--text-muted,#6e7681);margin:8px 16px 10px;">Detectado automaticamente — 20 detectores independentes.</p>\n'
        f'{rows}\n</div></div>\n')
