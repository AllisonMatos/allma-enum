#!/usr/bin/env python3
"""
plugins/sourcemaps/main.py - Source Map Extractor Plugin
Hunts for .map files associated with discovered JavaScript files,
unpacks the original frontend application code, and scans for secrets.
"""

from pathlib import Path
import re
import time
import json
import asyncio
import aiohttp
import traceback
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse, urljoin

from menu import C
from ..output import info, warn, success, error

CONFIG = {
    'max_conn_per_host': 10,
    'timeout': 10,
    'batch_size': 20
}

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

# Regex Patterns for Secrets
PATTERNS = {
    "AWS Access Key": re.compile(r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
    "AWS Secret Key": re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"](?P<key>[a-zA-Z0-9/+=]{40})['\"]"),
    "Generic API Key": re.compile(r"(?i)(?:api_key|apikey|secret|token|auth_token|access_token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.]{16,})['\"]"),
    "GraphQL Mutation": re.compile(r"mutation\s+[\w]+\s*\([^\)]*\)\s*\{"),
    "Unauthenticated Endpoint": re.compile(r"(?i)(?:api/v[0-9]+/|/api/)(?:users|admin|config|settings|data|graphql|query)"),
    "JWT Token": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
}

class SourceMapScanner:
    def __init__(self, target: str):
        self.target = target
        self.outdir = Path("output") / target / "sourcemaps"
        self.outdir.mkdir(parents=True, exist_ok=True)
        self.findings = []
        
    async def fetch(self, session: aiohttp.ClientSession, url: str) -> Tuple[str, str]:
        """Fetch content from URL and return text/json."""
        try:
            async with session.get(url, allow_redirects=True, timeout=CONFIG['timeout']) as response:
                if response.status == 200:
                    text = await response.text(errors='ignore')
                    return url, text
        except Exception:
            pass
        return url, ""

    async def scan_js_list(self, js_urls: List[str]):
        """Scan a list of JS URLs for sourcemaps and unpack them."""
        info(f"{C.BOLD}{get_color('BLUE')}🔍 Scanning {len(js_urls)} JS files for Source Maps...{C.END}")
        
        connector = aiohttp.TCPConnector(limit_per_host=CONFIG['max_conn_per_host'])
        async with aiohttp.ClientSession(connector=connector) as session:
            
            # Step 1: Fetch JS to find sourceMappingURL or try .map
            tasks = []
            for js_url in js_urls:
                tasks.append(self.process_js_file(session, js_url))
                
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for index, res in enumerate(results):
                 if isinstance(res, Exception):
                      warn(f"Failed to process {js_urls[index]}: {str(res)}")

    async def process_js_file(self, session: aiohttp.ClientSession, js_url: str):
        url, content = await self.fetch(session, js_url)
        map_url = None
        
        if content:
            # Check for sourceMappingURL
            match = re.search(r"//#\s*sourceMappingURL=(.*?\.map)", content)
            if match:
                map_url = urljoin(js_url, match.group(1))
            else:
                map_url = js_url + ".map" # Fallback guess
                
        if map_url:
            await self.unpack_map(session, map_url, js_url)

    async def unpack_map(self, session: aiohttp.ClientSession, map_url: str, original_js: str):
         url, content = await self.fetch(session, map_url)
         if not content:
             return
             
         try:
             data = json.loads(content)
             if data and "sourcesContent" in data and "sources" in data:
                 sources_content = data["sourcesContent"]
                 sources = data["sources"]
                 
                 for idx, source_code in enumerate(sources_content):
                      if not source_code:
                           continue
                      source_filename = sources[idx] if idx < len(sources) else f"unknown_{idx}.js"
                      
                      # Scan original source code
                      self.scan_original_code(source_code, map_url, source_filename)
         except json.JSONDecodeError:
             pass
         except Exception as e:
             warn(f"Error parsing map {map_url}: {str(e)}")

    def scan_original_code(self, source_code: str, map_url: str, source_filename: str):
         """Run regex scanner over the unpacked original source code."""
         lines = source_code.splitlines()
         
         for pattern_name, pattern in PATTERNS.items():
              for i, line in enumerate(lines):
                   matches = pattern.finditer(line)
                   for match in matches:
                        self.findings.append({
                            "type": pattern_name,
                            "map_url": map_url,
                            "source_file": source_filename,
                            "line_num": i + 1,
                            "match": match.group(0),
                            "context": line.strip()[:150]
                        })

async def run_async(context: dict):
    start = time.time()
    target = context.get("target")
    if not target:
        raise ValueError("context['target'] é obrigatório no plugin Souremaps")
        
    header_color = get_color('CYAN')
    target_color = get_color('GREEN')
    
    info(
        f"\n{C.BOLD}{header_color}╔══════════════════════════════════════════════════════════╗{C.END}\n"
        f"{C.BOLD}{header_color}║   🗺️  {C.CYAN if hasattr(C, 'CYAN') else ''}SOURCE MAPS ANALYZER{header_color}                               ║{C.END}\n"
        f"{C.BOLD}{header_color}║   🎯 {C.WHITE if hasattr(C, 'WHITE') else ''}Alvo: {target_color}{target}{header_color}                              ║{C.END}\n"
        f"{C.BOLD}{header_color}╚══════════════════════════════════════════════════════════╝{C.END}\n"
    )

    base = Path("output") / target
    js_urls = set()
    
    # Try different sources for JS files
    extracted_js = base / "domain" / "extracted_js.json"
    if extracted_js.exists():
        try:
             data = json.loads(extracted_js.read_text())
             for items in data.values():
                  for item in items:
                       js_urls.add(item)
        except Exception:
             pass
             
    # Fallback to JSSCANNER output or URLs output
    if not js_urls:
         urls_file = base / "urls" / "urls_valid.txt"
         if urls_file.exists():
              for url in urls_file.read_text().splitlines():
                   if url.strip().endswith(".js"):
                        js_urls.add(url.strip())
                        
    if not js_urls:
         warn("⚠️ Nenhum arquivo JS encontrado para analisar Source Maps.")
         return []
         
    js_urls_list = list(js_urls)
    scanner = SourceMapScanner(target)
    await scanner.scan_js_list(js_urls_list)
    
    # Save findings
    outdir = scanner.outdir
    findings_file = outdir / "secrets.txt"
    json_file = outdir / "secrets.json"
    
    if scanner.findings:
         with json_file.open('w') as f:
             json.dump(scanner.findings, f, indent=4)
             
         with findings_file.open('w') as f:
             for item in scanner.findings:
                  f.write(f"[{item['type']}] - File: {item['source_file']} (from {item['map_url']})\n")
                  f.write(f"Line {item['line_num']}: {item['match']}\n")
                  f.write(f"Context: {item['context']}\n")
                  f.write("-" * 60 + "\n")
                  
    elapsed = time.time() - start
    success(
        f"\n{C.BOLD}{get_color('GREEN')}✅ SOURCE MAPS CONCLUÍDO EM {elapsed:.1f}s{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}│   🌐 JS Analisados: {get_color('YELLOW')}{len(js_urls_list)}{C.WHITE if hasattr(C, 'WHITE') else ''}        │{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}│   🚨 Segredos Encontrados: {get_color('YELLOW')}{len(scanner.findings)}{C.WHITE if hasattr(C, 'WHITE') else ''}        │{C.END}\n"
    )
    
    return [str(findings_file)]

def run(context: dict):
    try:
        if hasattr(asyncio, 'WindowsSelectorEventLoopPolicy'):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        return asyncio.run(run_async(context))
    except KeyboardInterrupt:
        warn("\n⏹️ Scan interrompido pelo usuário")
        return []
    except Exception as e:
        error(f"Erro no Source Maps plugin: {str(e)}")
        traceback.print_exc()
        return []
