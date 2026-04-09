#!/usr/bin/env python3
"""
plugins/xss/main.py - XSS passive scanner otimizado
Com: threading, conexões persistentes, análise em batch e cache
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
from typing import List, Tuple, Dict, Set
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
    'max_workers': 20,           # Threads para crawling
    'max_conn_per_host': 5,      # Conexões simultâneas por host
    'timeout': 8,                # Timeout por requisição
    'batch_size': 10,            # Tamanho do batch para processamento
    'max_pages': 300,            # Máximo de páginas para crawlear
    'max_redirects': 3,          # Máximo de redirects
    'cache_ttl': 300,            # Cache TTL em segundos
    'rate_limit': 0.1,           # Delay entre requisições (por worker)
}

# ============================================================
# HELPER DE CORES (com fallback)
# ============================================================
def get_color(color_name: str) -> str:
    """Get color with fallback to available colors."""
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
    context_type: str = "HTML"  # HTML, ATTRIBUTE, SCRIPT, COMMENT
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
        """Fetch URL com cache e rate limiting."""
        
        # Verificar cache
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
                    
                    # Extrair links e scripts
                    links = await self.extract_links(text, url)
                    scripts = await self.extract_script_srcs(text, url)
                    inline_scripts = await self.extract_inline_scripts(text)
                    
                    # Extrair parâmetros da URL
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
                    
                    # Cache
                    self.cache.set(cache_key, result)
                    
                    # Rate limiting
                    await asyncio.sleep(CONFIG['rate_limit'])
                    
                    return result
                    
            except asyncio.TimeoutError:
                warn(f"Timeout fetching {url}")
            except Exception as e:
                warn(f"Error fetching {url}: {str(e)[:50]}")
            
            return None
    
    async def extract_links(self, html_text: str, base_url: str) -> List[str]:
        """Extrair links de forma eficiente."""
        if not html_text:
            return []
        
        # Regex otimizada
        link_pattern = r'href=["\']([^"\']+)["\']'
        matches = re.findall(link_pattern, html_text, re.IGNORECASE)
        
        # Filtrar e normalizar
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
        """Extrair src de scripts."""
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
        """Extrair scripts inline."""
        if not html_text:
            return []
        
        pattern = r'<script\b[^>]*>(.*?)</script>'
        matches = re.findall(pattern, html_text, re.IGNORECASE | re.DOTALL)
        
        return [m.strip() for m in matches if m.strip()]

# ============================================================
# PATTERNS OTIMIZADOS
# ============================================================

# V10.4: Fontes de input do usuário (taint sources) para validar DOM sinks
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

# V10.4: Bibliotecas externas conhecidas — ignorar sinks dentro delas
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
    """V10.4: Verifica se a URL pertence a uma biblioteca externa conhecida."""
    try:
        path = urlparse(url).path.lower()
        filename = path.rsplit('/', 1)[-1].rsplit('.', 1)[0]  # remove extension
        # Remove versão do nome (jquery-3.6.0 -> jquery)
        filename = re.sub(r'[\-\.]\d+(\.\d+)*$', '', filename)
        return filename in LIBRARY_FILENAMES
    except Exception:
        return False


class XSSPatterns:
    def __init__(self):
        # Compilar regex uma vez
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
            re.compile(r'(?=[A-Za-z0-9\-_]*[A-Z])(?=[A-Za-z0-9\-_]*[a-z])(?=[A-Za-z0-9\-_]*[0-9])[A-Za-z0-9\-_]{32,}'),  # Mix of upper+lower+digits, 32+ chars (likely tokens)
        ]
        
        self.param_min_len = 2 # Aumentado para reduzir FP em params muito curtos
    
    def detect_context(self, text: str, start: int, end: int) -> Tuple[str, str]:
        """
        Detecta o contexto da reflexão e retorna (context_type, severity)
        
        Simple heuristics:
        1. Comment: <!-- ... -->
        2. Script: <script> ... </script>
        3. Attribute: <tag attr="...">
        4. HTML: > ... <
        """
        # Pega um chunk anterior para analise
        chunk_before = text[max(0, start - 1000):start]
        chunk_after = text[end:min(len(text), end + 1000)]
        
        # 1. Check COMMENT
        # Se encontrar <!-- sem fechar --> antes
        r_info = chunk_before.rfind('<!--')
        r_close = chunk_before.rfind('-->')
        if r_info > r_close:
            # Confirmar que fecha depois
            if '-->' in chunk_after:
                return "COMMENT", "info"
        
        # 2. Check SCRIPT
        # Se encontrar <script> sem fechar </script> antes
        # Ignorar case
        lower_before = chunk_before.lower()
        r_script = lower_before.rfind('<script')
        r_script_close = lower_before.rfind('</script')
        
        if r_script > r_script_close:
            # Estamos dentro de um bloco script
            return "SCRIPT", "critical"
            
        # 3. Check ATTRIBUTE
        # Se encontrar <tag sem fechar > antes
        r_tag_open = chunk_before.rfind('<')
        r_tag_close = chunk_before.rfind('>')
        
        if r_tag_open > r_tag_close:
            # Estamos dentro de uma tag. Verificar se estamos em aspas
            tag_content = chunk_before[r_tag_open:]
            # Contar aspas simples e duplas
            dq_count = tag_content.count('"')
            sq_count = tag_content.count("'")
            
            if dq_count % 2 != 0:
                return "ATTRIBUTE (Double Quote)", "medium"
            if sq_count % 2 != 0:
                return "ATTRIBUTE (Single Quote)", "medium"
                
            # Se não está em aspas, mas dentro da tag (ex: <div class=VALUE>)
            return "TAG_NAME/VAL", "medium"
            
        # Default: HTML Body
        return "HTML", "low"
    
    def find_reflections(self, text: str, params: List[Tuple[str, str]]) -> List[XSSFinding]:
        """Encontrar reflexões de parâmetros no texto."""
        findings = []
        
        for param, value in params:
            if len(value) < self.param_min_len:
                continue
                
            # Busca otimizada
            if value in text:
                # Encontrar contexto
                idx = text.find(value)
                start = max(0, idx - 50)
                end = min(len(text), idx + 50)
                context_preview = text[start:end]
                
                # Detectar Contexto e Severidade
                ctx_type, severity = self.detect_context(text, idx, idx + len(value))
                
                # Ignorar reflexões inofensivas (HTML body comum ou comentários) para reduzir Falsos Positivos
                if severity in ["low", "info"]:
                    continue
                
                findings.append(XSSFinding(
                    url="",  # Será preenchido depois
                    param=param,
                    value=value,
                    pattern="PARAM_REFLECTION",
                    context=context_preview,
                    context_type=ctx_type,
                    severity=severity
                ))
                
        return findings
    
    def scan_dom(self, text: str) -> List[XSSFinding]:
        """Scan por padrões DOM perigosos com taint tracking V10.4."""
        findings = []
        
        for pattern in self.dom_patterns:
            matches = pattern.finditer(text)
            for match in matches:
                # Obter uma prévia do contexto real 
                idx = match.start()
                start = max(0, idx - 40)
                end = min(len(text), idx + 60)
                context_preview = text[start:end].replace('\n', ' ').strip()
                
                # Ignorar FPs básicos (atribuição vazia ou inofensiva)
                lower_ctx = context_preview.lower()
                safe_patterns = [
                    'innerhtml=""', "innerhtml=''", 'innerhtml = ""', "innerhtml = ''",
                    "location.href='/'", 'location.href="/"', "location='/'", 'location="/"',
                    "location.href = '/'", 'location.href = "/"', "location = '/'", 'location = "/"'
                ]
                if any(safe in lower_ctx for safe in safe_patterns):
                    continue
                
                # V10.4: Taint tracking — verificar se alguma fonte de input do usuário
                # alimenta este sink no contexto próximo (±500 chars)
                taint_start = max(0, idx - 500)
                taint_end = min(len(text), idx + 500)
                taint_context = text[taint_start:taint_end]
                
                has_taint_source = bool(TAINT_SOURCES.search(taint_context))
                
                if has_taint_source:
                    # Sink COM fonte de input controlável → MEDIUM (potencialmente explorável)
                    findings.append(XSSFinding(
                        url="",
                        pattern=pattern.pattern,
                        context=context_preview,
                        context_type="TAINTED_SINK",
                        severity="medium"
                    ))
                
        return findings
    
    def scan_js(self, js_code: str, source_url: str = "") -> List[XSSFinding]:
        """Scan por padrões JS perigosos com filtro de bibliotecas V10.4."""
        findings = []
        
        # V10.4: Ignorar sinks em bibliotecas externas conhecidas
        if source_url and _is_library_url(source_url):
            return findings
        
        for pattern in self.js_patterns:
            matches = pattern.finditer(js_code)
            for match in matches:
                idx = match.start()
                start = max(0, idx - 40)
                end = min(len(js_code), idx + 60)
                context_preview = js_code[start:end].replace('\n', ' ').strip()
                
                # V10.4: Taint tracking para JS também
                taint_start = max(0, idx - 500)
                taint_end = min(len(js_code), idx + 500)
                taint_context = js_code[taint_start:taint_end]
                if has_taint_source:
                    findings.append(XSSFinding(
                        url="",
                        pattern=pattern.pattern,
                        context=context_preview,
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
        """Adicionar URLs iniciais."""
        for url in urls:
            if url not in self.visited:
                self.to_visit.append((url, 0))
    
    def is_same_origin(self, url: str) -> bool:
        """Verificar se URL é do mesmo origin."""
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return True
            return (parsed.netloc == self.base_netloc or 
                   parsed.netloc.endswith("." + self.base_netloc))
        except:
            return False
    
    async def crawl(self):
        """Crawlear URLs de forma assíncrona."""
        info(f"{C.BOLD}{get_color('BLUE')}🚀 Iniciando crawler assíncrono...{C.END}")
        
        async with AsyncHTTPClient() as client:
            while self.to_visit and len(self.visited) < CONFIG['max_pages']:
                # Processar em batch
                batch = []
                while self.to_visit and len(batch) < CONFIG['batch_size']:
                    url, depth = self.to_visit.popleft()
                    if url not in self.visited and depth <= self.depth:
                        batch.append((url, depth))
                
                if not batch:
                    break
                
                # Fetch em paralelo
                tasks = []
                for url, depth in batch:
                    tasks.append(self.process_url(client, url, depth))
                
                # Aguardar resultados do batch
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Processar resultados
                for result in batch_results:
                    if result and not isinstance(result, Exception):
                        url, url_result, new_urls = result
                        if url_result:
                            self.results.append((url, url_result))
                            # Análise em tempo real
                            await self.analyze_result(url, url_result)
                            
                            # Adicionar novos URLs para visita
                            for new_url in new_urls:
                                if (self.is_same_origin(new_url) and 
                                    new_url not in self.visited and
                                    len(self.visited) < CONFIG['max_pages']):
                                    self.to_visit.append((new_url, depth + 1))
        
        info(f"{C.BOLD}{get_color('GREEN')}✅ Crawling concluído: {len(self.visited)} páginas{C.END}")
    
    async def process_url(self, client: AsyncHTTPClient, url: str, depth: int):
        """Processar uma URL."""
        try:
            if url in self.visited:
                return None
                
            self.visited.add(url)
            
            info(f"   🔍 {get_color('YELLOW')}{url}{C.END}")
            
            # Fetch
            result = await client.fetch(url)
            if not result:
                return url, None, []
            
            # Extrair links para crawlear
            new_urls = []
            for link in result.links:
                if (self.is_same_origin(link) and 
                    link not in self.visited and
                    len(self.visited) < CONFIG['max_pages']):
                    new_urls.append(link)
            
            return url, result, new_urls
            
        except Exception as e:
            warn(f"Erro processando {url}: {str(e)[:50]}")
            return url, None, []
    
    async def analyze_result(self, url: str, result: URLResult):
        """Analisar resultado em tempo real."""
        if not result or not result.text:
            return
        
        # 1. Verificar reflexões de parâmetros
        param_reflections = self.patterns.find_reflections(result.text, result.params)
        for finding in param_reflections:
            finding.url = url
            self.findings.append(finding)
        
        # 2. Scan DOM
        dom_findings = self.patterns.scan_dom(result.text)
        for finding in dom_findings:
            finding.url = url
            self.findings.append(finding)
        
        # 3. Scan scripts inline
        for js_code in result.inline_scripts:
            js_findings = self.patterns.scan_js(js_code)
            for finding in js_findings:
                finding.url = url + "#inline"
                self.findings.append(finding)
        
        # 4. Scan scripts externos (async)
        if result.scripts:
            in_scope_scripts = [s for s in result.scripts if self.is_same_origin(s)]
            await self.analyze_external_scripts(in_scope_scripts)

    async def analyze_external_scripts(self, scripts: List[str]):
        """Analisar scripts externos."""
        async with AsyncHTTPClient() as client:
            tasks = []
            for script_url in scripts[:10]:  # Limitar a 10 scripts
                tasks.append(self.analyze_single_script(client, script_url))
            
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def analyze_single_script(self, client: AsyncHTTPClient, script_url: str):
        """Analisar um único script."""
        try:
            result = await client.fetch(script_url)
            if result and result.text:
                js_findings = self.patterns.scan_js(result.text, source_url=script_url)
                for finding in js_findings:
                    finding.url = script_url
                    self.findings.append(finding)
        except:
            pass

# ============================================================
# MAIN FUNCTION OTIMIZADA
# ============================================================
async def run_async(context: dict):
    """Função principal assíncrona."""
    start = time.time()
    
    target = context.get("target")
    depth = int(context.get("depth", 1))
    
    if not target:
        raise ValueError("context['target'] é obrigatório no plugin XSS")
    
    # ==========================================================================
    # 🎯 CABEÇALHO (com cores seguras)
    # ==========================================================================
    header_color = get_color('CYAN')
    target_color = get_color('GREEN')
    depth_color = get_color('YELLOW')
    
    info(
        f"\n{C.BOLD}{header_color}╔══════════════════════════════════════════════════════════╗{C.END}\n"
        f"{C.BOLD}{header_color}║   🎭 {C.CYAN if hasattr(C, 'CYAN') else ''}XSS PASSIVE SCAN (OTIMIZADO){header_color}                    ║{C.END}\n"
        f"{C.BOLD}{header_color}║   🎯 {C.WHITE if hasattr(C, 'WHITE') else ''}Alvo: {target_color}{target}{header_color}                              ║{C.END}\n"
        f"{C.BOLD}{header_color}║   📏 {C.WHITE if hasattr(C, 'WHITE') else ''}Profundidade: {depth_color}{depth}{header_color} Workers: {depth_color}{CONFIG['max_workers']}{header_color}         ║{C.END}\n"
        f"{C.BOLD}{header_color}╚══════════════════════════════════════════════════════════╝{C.END}\n"
    )
    
    outdir = ensure_outdir(target, "xss")
    
    # ==========================================================================
    # 📥 CARREGAR URLS INICIAIS
    # ==========================================================================
    urls200 = Path("output") / target / "urls" / "urls_200.txt"
    if not urls200.exists():
        warn(f"⚠️ Arquivo não encontrado: {urls200}")
        return []
    
    seed_urls = []
    try:
        async with aiofiles.open(urls200, 'r') as f:
            content = await f.read()
            seed_urls = [u.strip() for u in content.splitlines() if u.strip()]
    except:
        # Fallback síncrono
        seed_urls = [u.strip() for u in urls200.read_text().splitlines() if u.strip()]
    
    if not seed_urls:
        warn("⚠️ Nenhuma URL disponível para XSS scan.")
        return []
    
    info(f"{C.BOLD}{get_color('BLUE')}🌐 URLs iniciais: {len(seed_urls)}{C.END}")
    
    # ==========================================================================
    # 🕷️ EXECUTAR CRAWLER
    # ==========================================================================
    crawler = XSSCrawler(target, depth)
    crawler.add_seed_urls(seed_urls)
    
    await crawler.crawl()
    
    # ==========================================================================
    # 📊 GERAR RELATÓRIOS
    # ==========================================================================
    info(f"{C.BOLD}{get_color('BLUE')}📊 Gerando relatórios...{C.END}")
    
    # Agrupar findings por tipo - APENAS SEVERIDADE MEDIA/ALTA PARA NAO POLUIR O REPORT GERAL
    # A maioria dos sinks dom passivos são FPs sem estar associado a um input. Filtramos "low" out.
    valid_findings = [f for f in crawler.findings if f.severity in ("medium", "high", "critical")]
    reflections = [f for f in valid_findings if f.pattern == "PARAM_REFLECTION"]
    dom_findings = [f for f in valid_findings if f not in reflections and "PARAM" not in f.pattern]
    
    # Salvar relatórios
    await save_reports(outdir, crawler, reflections, dom_findings, valid_findings)
    
    # ==========================================================================
    # 📈 ESTATÍSTICAS
    # ==========================================================================
    elapsed = time.time() - start
    
    success(
        f"\n{C.BOLD}{get_color('GREEN')}✅ XSS SCAN CONCLUÍDO EM {elapsed:.1f}s{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}┌─────────────────────────────────────────────┐{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}│   📊 {C.CYAN if hasattr(C, 'CYAN') else ''}ESTATÍSTICAS{C.WHITE if hasattr(C, 'WHITE') else ''}                         │{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}├─────────────────────────────────────────────┤{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}│   🌐 Páginas analisadas: {get_color('YELLOW')}{len(crawler.visited)}{C.WHITE if hasattr(C, 'WHITE') else ''}          │{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}│   🔄 Reflexões (High+): {get_color('YELLOW')}{len(reflections)}{C.WHITE if hasattr(C, 'WHITE') else ''}                  │{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}│   🧬 Tainted Sinks: {get_color('YELLOW')}{len(dom_findings)}{C.WHITE if hasattr(C, 'WHITE') else ''}               │{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}│   ⚡ Total findings (Med/High): {get_color('YELLOW')}{len(valid_findings)}{C.WHITE if hasattr(C, 'WHITE') else ''}             │{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}│   ⏱️  Tempo total: {get_color('YELLOW')}{elapsed:.1f}s{C.WHITE if hasattr(C, 'WHITE') else ''}                 │{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}└─────────────────────────────────────────────┘{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}📄 Relatório final: {C.CYAN if hasattr(C, 'CYAN') else ''}{outdir / 'final_report.txt'}{C.END}\n"
    )
    
    return [str(outdir / 'final_report.txt')]

async def save_reports(outdir, crawler, reflections, dom_findings, valid_findings):
    """Salvar relatórios de forma assíncrona."""
    
    # Salvar parâmetros
    params_content = []
    dalfox_urls = set()
    for url, result in crawler.results:
        if result and result.params:
            for param, value in result.params:
                params_content.append(f"{url}\t{param}\t{value}")
            dalfox_urls.add(url)
            
    if dalfox_urls:
        async with aiofiles.open(outdir / "dalfox_targets.txt", 'w') as f:
            await f.write("\n".join(dalfox_urls))
    
    if params_content:
        async with aiofiles.open(outdir / "parameters.txt", 'w') as f:
            await f.write("\n".join(params_content))
    
    # Salvar reflexões
    if reflections:
        reflections_content = []
        for finding in reflections:
            reflections_content.append(
                f"{finding.url}\t{finding.param}\t{finding.value}\n{finding.context}\n---"
            )
        async with aiofiles.open(outdir / "reflections.txt", 'w') as f:
            await f.write("\n".join(reflections_content))
    
    # Salvar DOM findings
    if dom_findings:
        dom_content = []
        for finding in dom_findings:
            dom_content.append(f"{finding.url}\t{finding.pattern}\n{finding.context}\n---")
        async with aiofiles.open(outdir / "dom_suspects.txt", 'w') as f:
            await f.write("\n".join(dom_content))
    
    # Salvar JS findings
    js_findings = [f for f in valid_findings if "PARAM" not in f.pattern]
    if js_findings:
        js_content = []
        for finding in js_findings[:100]:  # Limitar
            js_content.append(f"{finding.url}\t{finding.pattern}\n{finding.context}\n---")
        async with aiofiles.open(outdir / "js_suspects.txt", 'w') as f:
            await f.write("\n".join(js_content))
    
    # Relatório final
    summary = [
        f"XSS Passive Scan - {crawler.target}",
        f"Gerado em: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"Páginas visitadas: {len(crawler.visited)}",
        f"Total findings: {len(valid_findings)}",
        f"Reflexões de parâmetros: {len(reflections)}",
        f"Sinks DOM encontrados (avaliar manualmente): {len(dom_findings)}",
        "",
    ]
    
    # Listar todas as reflexões encontradas
    if reflections:
        summary.append("=== REFLEXÕES DE PARÂMETROS ===")
        summary.append("")
        for i, ref in enumerate(reflections, 1):
            summary.append(f"{i}. {ref.url}")
            summary.append(f"   Parâmetro: {ref.param} = {ref.value[:80]}")
            if hasattr(ref, 'context_type') and ref.context_type:
                summary.append(f"   Contexto: {ref.context_type}")
            if ref.context:
                ctx_preview = ref.context.strip()[:120]
                summary.append(f"   Trecho: {ctx_preview}")
            summary.append("")
    
    summary.append("=== TOP 10 FINDINGS ===")
    summary.append("")
    
    # Adicionar top findings
    all_findings_sorted = sorted(valid_findings, key=lambda x: x.severity, reverse=True)
    for i, finding in enumerate(all_findings_sorted[:10]):
        summary.append(f"{i+1}. [{finding.severity.upper()}] {finding.url}")
        summary.append(f"   Padrão: {finding.pattern[:50]}")
        if hasattr(finding, 'context_type'):
            summary.append(f"   Contexto: {finding.context_type}")
        if finding.param:
            summary.append(f"   Parâmetro: {finding.param} = {finding.value[:30]}")
        summary.append("")
    
    summary.append("=== RECOMENDAÇÕES ===")
    summary.append("1. Testar reflexões com payloads XSS básicos")
    summary.append("2. Verificar se há sanitização nos parâmetros refletidos")
    summary.append("3. Analisar sinks DOM encontrados")
    summary.append("4. Testar scripts externos por vulnerabilidades")
    
    async with aiofiles.open(outdir / "final_report.txt", 'w') as f:
        await f.write("\n".join(summary))

# ============================================================
# V10.4: ACTIVE XSS VALIDATION (teste ativo simples)
# ============================================================
def _active_xss_test(target: str, outdir: Path, reflections: list):
    """
    V10.4: Teste ativo simples — injeta payloads canary nos parâmetros
    que já mostraram reflexão e verifica se escapam do contexto HTML.
    """
    import httpx
    from core.config import REQUEST_DELAY, DEFAULT_TIMEOUT
    
    CANARY = "eNuMaLlMa"
    ACTIVE_PAYLOADS = [
        (f'"{CANARY}', f'"{CANARY}', "ATTRIBUTE_BREAKOUT"),         # Escapa de atributo com aspas duplas
        (f"'{CANARY}", f"'{CANARY}", "ATTRIBUTE_BREAKOUT_SQ"),     # Escapa de atributo com aspas simples
        (f"<{CANARY}", f"<{CANARY}", "TAG_INJECTION"),             # Injeta tag HTML
        (f"<img src=x onerror={CANARY}>", f"onerror={CANARY}", "EVENT_HANDLER"),  # Event handler
        (f"javascript:{CANARY}", f"javascript:{CANARY}", "JS_URI"),  # URI JavaScript
    ]
    
    if not reflections:
        return []
    
    # Coletar pares únicos (url, param)
    seen = set()
    test_targets = []
    for ref in reflections:
        key = (ref.url, ref.param)
        if key not in seen and ref.url and ref.param:
            seen.add(key)
            test_targets.append((ref.url, ref.param, ref.context_type))
    
    test_targets = test_targets[:30]  # Limitar para não sobrecarregar
    
    info(f"\n   🎯 {C.BOLD}{C.CYAN}[V10.4] Active XSS Validation em {len(test_targets)} reflexões...{C.END}")
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
                    
                    # Verificar se o payload aparece SEM encoding no body
                    if marker in body:
                        # Confirmar que não é um false positive (o marker não estava na página original)
                        original_resp = client.get(url, headers={"User-Agent": DEFAULT_USER_AGENT})
                        if marker not in original_resp.text:
                            severity = "high"
                            if attack_type == "EVENT_HANDLER":
                                severity = "critical"
                            elif attack_type == "TAG_INJECTION":
                                severity = "high"
                            
                            active_findings.append({
                                "url": url,
                                "test_url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "attack_type": attack_type,
                                "context": ctx_type,
                                "severity": severity,
                                "type": "ACTIVE_XSS",
                                "details": f"XSS Ativo: Payload '{payload}' refletido sem sanitização via '{param}' ({attack_type})",
                            })
                            info(f"   🔴 {C.RED}[ACTIVE XSS — {severity.upper()}]{C.END} {url} → '{param}' ({attack_type})")
                            break  # Um payload confirmado basta por parâmetro
                except Exception:
                    pass
    
    if active_findings:
        import json
        active_file = outdir / "active_xss_results.json"
        active_file.write_text(json.dumps(active_findings, indent=2, ensure_ascii=False))
        success(f"   🎯 {len(active_findings)} XSS Ativos confirmados! Salvos em {active_file}")
    else:
        info(f"   ✅ Nenhum XSS ativo confirmado nas reflexões testadas.")
    
    return active_findings


def run(context: dict):
    """Wrapper síncrono para função assíncrona."""
    try:
        # Configurar asyncio para melhor performance
        if hasattr(asyncio, 'WindowsSelectorEventLoopPolicy'):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
        # Executar
        reports = asyncio.run(run_async(context))
        
        # Post-processing Dalfox
        target = context.get("target", "")
        if target:
            from plugins import ensure_outdir
            from plugins.http_utils import check_tool_installed
            import subprocess
            outdir = ensure_outdir(target, "xss")
            dalfox_targets = outdir / "dalfox_targets.txt"
            
            if dalfox_targets.exists() and check_tool_installed("dalfox"):
                info(f"\n   🦊 {C.CYAN}Executando Dalfox (Active XSS Scan)...{C.END}")
                dalfox_out = outdir / "dalfox_results.txt"
                cmd = ["dalfox", "file", str(dalfox_targets), "--skip-bav", "--silence", "-w", "20", "-o", str(dalfox_out)]
                try:
                    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1200)
                    if dalfox_out.exists():
                        success(f"   🦊 Resultados do Dalfox salvos em {dalfox_out}")
                except subprocess.TimeoutExpired:
                    warn("   🦊 Dalfox demorou muito e foi interrompido.")
            
            # V10.4: Active XSS Validation Test
            info(f"\n   🎭 {C.BOLD}{C.CYAN}[V10.4] Iniciando Active XSS Validation...{C.END}")
            reflections_file = outdir / "reflections.txt"
            # Reconstruir lista de reflexões para teste ativo
            active_reflections = []
            if reflections_file.exists():
                content = reflections_file.read_text(errors="ignore")
                for block in content.split("---"):
                    lines = block.strip().splitlines()
                    if lines:
                        parts = lines[0].split("\t")
                        if len(parts) >= 3:
                            active_reflections.append(XSSFinding(
                                url=parts[0], param=parts[1], value=parts[2],
                                pattern="PARAM_REFLECTION", context="", severity="medium"
                            ))
            _active_xss_test(target, outdir, active_reflections)
                    
        return reports
    except KeyboardInterrupt:
        warn("\n⏹️ Scan interrompido pelo usuário")
        return []
    except Exception as e:
        error(f"Erro no XSS scan: {str(e)}")
        import traceback
        traceback.print_exc()
        return []
