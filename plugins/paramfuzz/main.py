#!/usr/bin/env python3
"""
plugins/paramfuzz/main.py - Parameter Fuzzing Plugin
Discovers hidden HTTP parameters on functional URLs using a curated wordlist.
"""

from pathlib import Path
import time
import json
import asyncio
import aiohttp
import traceback
from typing import List, Dict, Any, Tuple
import httpx
from plugins.http_utils import format_http_request, format_http_response
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from menu import C
from ..output import info, warn, success, error

CONFIG = {
    'max_conn_per_host': 15,
    'timeout': 7,
    'batch_size': 50
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

# Curated top ~250 common hidden parameters
WORDLIST = [
    "admin", "debug", "test", "dir", "file", "id", "user", "username", "password",
    "email", "role", "action", "cmd", "exec", "query", "url", "redirect", "next",
    "page", "id", "q", "search", "filter", "key", "token", "hash", "auth", "login",
    "password", "pass", "pwd", "uid", "session", "type", "mode", "view", "show",
    "edit", "update", "delete", "create", "new", "save", "download", "upload", "path",
    "folder", "doc", "document", "xml", "json", "config", "settings", "profile",
    "account", "status", "state", "code", "lang", "locale", "date", "time", "year",
    "month", "day", "start", "end", "limit", "offset", "count", "size", "sort",
    "order", "by", "format", "out", "cb", "callback", "jsonp", "api", "version",
    "v", "client", "app", "os", "device", "browser", "ip", "host", "port", "env",
    "test", "demo", "dev", "prod", "staging", "internal", "private", "hidden"
]

class ParamFuzzer:
    def __init__(self, target: str):
        self.target = target
        self.outdir = Path("output") / target / "paramfuzz"
        self.outdir.mkdir(parents=True, exist_ok=True)
        self.findings = []
        
    def fetch_sync(self, url: str) -> Tuple[int, int, str, str, str]:
        """Fetch content from URL and return status, length, text, req_raw, res_raw."""
        try:
            with httpx.Client(verify=False, follow_redirects=True, timeout=CONFIG['timeout']) as client:
                resp = client.get(url)
                return resp.status_code, len(resp.text), resp.text, format_http_request(resp.request), format_http_response(resp)
        except Exception:
            return 0, 0, "", "", ""

    async def fetch(self, session: aiohttp.ClientSession, url: str) -> Tuple[int, int, str, str, str]:
        """Async fetch - we'll use a wrapper for httpx sync for now to keep format_http_utils easy, 
        or stick to aiohttp if we can capture its raw req/res easily. 
        Actually, let's use httpx.AsyncClient for consistency."""
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=CONFIG['timeout']) as client:
                resp = await client.get(url)
                return resp.status_code, len(resp.text), resp.text, format_http_request(resp.request), format_http_response(resp)
        except Exception:
            return 0, 0, "", "", ""

    async def get_baseline(self, session: aiohttp.ClientSession, base_url: str) -> Tuple[int, int, str, str, str]:
         """Get baseline response for the URL."""
         # Append random non-existent parameter to avoid caching and establish dynamic baseline
         import random
         import string
         rand_param = ''.join(random.choices(string.ascii_lowercase, k=10))
         
         parsed = list(urlparse(base_url))
         query = parse_qsl(parsed[4])
         query.append((rand_param, "zzzzzzzz"))
         parsed[4] = urlencode(query)
         test_url = urlunparse(parsed)
         
         return await self.fetch(session, test_url)

    def is_functional_url(self, url: str) -> bool:
         """Ignore static assets."""
         exts = ['.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.ico', '.js']
         try:
              parsed = urlparse(url)
              path = parsed.path.lower()
              return not any(path.endswith(ext) for ext in exts)
         except:
              return False

    async def scan_urls(self, urls: List[str]):
        """Scan a list of functional URLs for hidden parameters."""
        functional_urls = [u for u in urls if self.is_functional_url(u)]
        
        # Limit to 50 URLs to avoid excessively long scans, or deduplicate by path
        seen_paths = set()
        unique_urls = []
        for u in functional_urls:
            try:
                parsed = urlparse(u)
                core_path = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if core_path not in seen_paths:
                    seen_paths.add(core_path)
                    unique_urls.append(u)
            except:
                pass
                
        # Limit to 30 unique paths for speed
        unique_urls = unique_urls[:30]
        info(f"{C.BOLD}{get_color('BLUE')}🔍 Fuzzing {len(unique_urls)} functional endpoints for parameters...{C.END}")
        
        connector = aiohttp.TCPConnector(limit_per_host=CONFIG['max_conn_per_host'])
        async with aiohttp.ClientSession(connector=connector) as session:
            for url in unique_urls:
                 await self.fuzz_url(session, url)

    async def fuzz_url(self, session: aiohttp.ClientSession, base_url: str):
        # 1. Establish baseline
        baseline_status, baseline_len, baseline_text = await self.get_baseline(session, base_url)
        if baseline_status == 0:
             return
             
        parsed = list(urlparse(base_url))
        base_query = parse_qsl(parsed[4])
        
        test_val = "fuzztest123"
        batch_tasks = []
        param_list = []
        
        # We test parameters 1 by 1 for clarity, or batch them? Let's do 1 by 1 asynchronously.
        for param in WORDLIST:
             query = base_query.copy()
             query.append((param, test_val))
             parsed[4] = urlencode(query)
             test_url = urlunparse(parsed)
             
             param_list.append(param)
             batch_tasks.append(self.fetch(session, test_url))
             
        results = await asyncio.gather(*batch_tasks, return_exceptions=True)
        
        for idx, res in enumerate(results):
             if isinstance(res, Exception) or res[0] == 0:
                  continue
             
             status, length, text = res
             param = param_list[idx]
             
             # Comparison Logic
             is_different = False
             reason = []
             
             if status != baseline_status:
                  is_different = True
                  reason.append(f"Status changed: {baseline_status} -> {status}")
                  
             # Content length change > 5% or Reflection
             len_diff = abs(length - baseline_len)
             if baseline_len > 0 and (len_diff / baseline_len) > 0.05:
                  is_different = True
                  reason.append(f"Length changed: {baseline_len} -> {length}")
                  
             # Reflection Check
             if test_val in text and test_val not in baseline_text:
                  is_different = True
                  reason.append(f"Reflection found")
                  
             if is_different:
                  status, length, text, req_raw, res_raw = res
                  self.findings.append({
                       "url": base_url,
                       "parameter": param,
                       "status": status,
                       "baseline_status": baseline_status,
                       "length": length,
                       "baseline_length": baseline_len,
                       "reason": ", ".join(reason),
                       "request_raw": req_raw,
                       "response_raw": res_raw
                  })


async def run_async(context: dict):
    start = time.time()
    target = context.get("target")
    if not target:
        raise ValueError("context['target'] é obrigatório no plugin ParamFuzz")
        
    header_color = get_color('CYAN')
    target_color = get_color('GREEN')
    
    info(
        f"\n{C.BOLD}{header_color}╔══════════════════════════════════════════════════════════╗{C.END}\n"
        f"{C.BOLD}{header_color}║   🔍 {C.CYAN if hasattr(C, 'CYAN') else ''}PARAMETER FUZZER{header_color}                                   ║{C.END}\n"
        f"{C.BOLD}{header_color}║   🎯 {C.WHITE if hasattr(C, 'WHITE') else ''}Alvo: {target_color}{target}{header_color}                              ║{C.END}\n"
        f"{C.BOLD}{header_color}╚══════════════════════════════════════════════════════════╝{C.END}\n"
    )

    base = Path("output") / target
    urls = []
    
    urls_file = base / "urls" / "urls_valid.txt"
    if urls_file.exists():
         urls = [u.strip() for u in urls_file.read_text().splitlines() if u.strip()]
                        
    if not urls:
         warn("⚠️ Nenhuma URL encontrada para fuzzing.")
         return []
         
    fuzzer = ParamFuzzer(target)
    await fuzzer.scan_urls(urls)
    
    # Save findings
    outdir = fuzzer.outdir
    findings_file = outdir / "findings.txt"
    json_file = outdir / "hidden_params.json"
    
    if fuzzer.findings:
         with json_file.open('w') as f:
             json.dump(fuzzer.findings, f, indent=4)
             
         with findings_file.open('w') as f:
             for item in fuzzer.findings:
                  f.write(f"URL: {item['url']}\n")
                  f.write(f"Parameter Discovered: {item['parameter']}\n")
                  f.write(f"Reason: {item['reason']}\n")
                  f.write("-" * 60 + "\n")
                  
    elapsed = time.time() - start
    success(
        f"\n{C.BOLD}{get_color('GREEN')}✅ PARAMETER FUZZING CONCLUÍDO EM {elapsed:.1f}s{C.END}\n"
        f"{C.BOLD}{get_color('CYAN')}│   🚨 Parâmetros Encontrados: {get_color('YELLOW')}{len(fuzzer.findings)}{C.WHITE if hasattr(C, 'WHITE') else ''}        │{C.END}\n"
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
        error(f"Erro no ParamFuzz plugin: {str(e)}")
        traceback.print_exc()
        return []
