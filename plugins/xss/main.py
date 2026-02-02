#!/usr/bin/env python3
"""
plugins/xss/main.py - XSS passive scanner otimizado
Com: threading, conexões persistentes, análise em batch e cache
"""

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
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
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
            except:
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
            except:
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
            re.compile(r'[A-Za-z0-9\-_]{20,}', re.I),
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
        """Scan por padrões DOM perigosos."""
        findings = []
        
        for pattern in self.dom_patterns:
            matches = pattern.finditer(text)
            for match in matches:
                findings.append(XSSFinding(
                    url="",
                    pattern=pattern.pattern,
                    context=match.group(),
                    severity="low"
                ))
                
        return findings
    
    def scan_js(self, js_code: str) -> List[XSSFinding]:
        """Scan por padrões JS perigosos."""
        findings = []
        
        for pattern in self.js_patterns:
            matches = pattern.finditer(js_code)
            for match in matches:
                findings.append(XSSFinding(
                    url="",
                    pattern=pattern.pattern,
                    context=match.group(),
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
            await self.analyze_external_scripts(result.scripts)

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
                js_findings = self.patterns.scan_js(result.text)
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
    
    from .utils import ensure_outdir
    outdir = ensure_outdir(target)
    
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
    
    # Agrupar findings por tipo
    reflections = [f for f in crawler.findings if f.pattern == "PARAM_REFLECTION"]
    dom_findings = [f for f in crawler.findings if f not in reflections and "PARAM" not in f.pattern]
    
    # Salvar relatórios
    await save_reports(outdir, crawler, reflections, dom_findings)
    
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
        f"{C.BOLD}{get_color('CYAN')}│   🔄 Reflexões: {get_color('YELLOW')}{len(reflections)}{C.WHITE if hasattr(C, 'WHITE') else ''}                  │{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}│   🧬 DOM Suspeitas: {get_color('YELLOW')}{len(dom_findings)}{C.WHITE if hasattr(C, 'WHITE') else ''}               │{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}│   ⚡ Total findings: {get_color('YELLOW')}{len(crawler.findings)}{C.WHITE if hasattr(C, 'WHITE') else ''}             │{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}│   ⏱️  Tempo total: {get_color('YELLOW')}{elapsed:.1f}s{C.WHITE if hasattr(C, 'WHITE') else ''}                 │{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}└─────────────────────────────────────────────┘{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}📄 Relatório final: {C.CYAN if hasattr(C, 'CYAN') else ''}{outdir / 'final_report.txt'}{C.END}\n"
    )
    
    return [str(outdir / 'final_report.txt')]

async def save_reports(outdir, crawler, reflections, dom_findings):
    """Salvar relatórios de forma assíncrona."""
    
    # Salvar parâmetros
    params_content = []
    for url, result in crawler.results:
        if result and result.params:
            for param, value in result.params:
                params_content.append(f"{url}\t{param}\t{value}")
    
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
    js_findings = [f for f in crawler.findings if "PARAM" not in f.pattern]
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
        f"Total findings: {len(crawler.findings)}",
        f"Reflexões de parâmetros: {len(reflections)}",
        f"Suspeitas DOM/JS: {len(dom_findings)}",
        "",
        "=== TOP 10 FINDINGS ===",
        ""
    ]
    
    # Adicionar top findings
    all_findings = sorted(crawler.findings, key=lambda x: x.severity, reverse=True)
    for i, finding in enumerate(all_findings[:10]):
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

def run(context: dict):
    """Wrapper síncrono para função assíncrona."""
    try:
        # Configurar asyncio para melhor performance
        if hasattr(asyncio, 'WindowsSelectorEventLoopPolicy'):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
        # Executar
        return asyncio.run(run_async(context))
    except KeyboardInterrupt:
        warn("\n⏹️ Scan interrompido pelo usuário")
        return []
    except Exception as e:
        error(f"Erro no XSS scan: {str(e)}")
        import traceback
        traceback.print_exc()
        return []