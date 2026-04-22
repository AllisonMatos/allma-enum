#!/usr/bin/env python3
"""
HTTP Request Smuggling Scanner (CL.TE & TE.CL)
Detects Desync vulnerabilities via timing analysis using raw sockets.
"""
import json
import base64
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
    # V11: Usar urlparse para extrair host/port (suporta IPv6)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    
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
    
    # V10.6: Multi-sample timing — confirmar com 3 amostras para reduzir FPs de jitter de rede
    if clte_time > (baseline_time + timing_threshold):
        # Coletar mais 2 amostras
        clte_times = [clte_time]
        for _ in range(2):
            t, _ = raw_request(host, port, is_https, cl_te_payload, timeout=TIMEOUT)
            if t > 0:
                clte_times.append(t)
        
        clte_times.sort()
        median_time = clte_times[len(clte_times) // 2]
        hits = sum(1 for t in clte_times if t > (baseline_time + timing_threshold))
        
        # V11: Parsear status code numericamente (evita FP se URL contiver '500' ou '400')
        clte_status = 0
        if clte_resp:
            try:
                clte_status = int(clte_resp.split(" ")[1])
            except (IndexError, ValueError):
                pass
        if hits >= 2 and median_time > (baseline_time + timing_threshold) and clte_status not in (400, 500, 501, 502, 503):
            findings.append({
                "url": url,
                "type": "CL.TE Smuggling",
                "risk": "HIGH",
                "details": f"Possível CL.TE vulnerability (median {median_time:.2f}s em {len(clte_times)} amostras vs {baseline_time:.2f}s base, {hits}/{len(clte_times)} hits)",
                "payload": cl_te_payload,
                "raw_request": base64.b64encode(cl_te_payload.encode()).decode(),
                "raw_response": base64.b64encode(clte_resp.encode()).decode()
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
    
    # V10.6: Multi-sample timing para TE.CL
    if tecl_time > (baseline_time + timing_threshold):
        tecl_times = [tecl_time]
        for _ in range(2):
            t, _ = raw_request(host, port, is_https, te_cl_payload, timeout=TIMEOUT)
            if t > 0:
                tecl_times.append(t)
        
        tecl_times.sort()
        median_time = tecl_times[len(tecl_times) // 2]
        hits = sum(1 for t in tecl_times if t > (baseline_time + timing_threshold))
        
        # V11: Parsear status code numericamente
        tecl_status = 0
        if tecl_resp:
            try:
                tecl_status = int(tecl_resp.split(" ")[1])
            except (IndexError, ValueError):
                pass
        if hits >= 2 and median_time > (baseline_time + timing_threshold) and tecl_status not in (400, 500, 501, 502, 503):
            findings.append({
                "url": url,
                "type": "TE.CL Smuggling",
                "risk": "HIGH",
                "details": f"Possível TE.CL vulnerability (median {median_time:.2f}s em {len(tecl_times)} amostras vs {baseline_time:.2f}s base, {hits}/{len(tecl_times)} hits)",
                "payload": te_cl_payload,
                "raw_request": base64.b64encode(te_cl_payload.encode()).decode(),
                "raw_response": base64.b64encode(tecl_resp.encode()).decode()
            })

    # 3. V11: TE.TE Obfuscation Payload
    tete_payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {DEFAULT_USER_AGENT}\r\n"
        "Connection: keep-alive\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Transfer-Encoding: x\r\n"
        "\r\n"
        "1\r\n"
        "Z\r\n"
        "Q\r\n"
        "\r\n"
    )

    tete_time, tete_resp = raw_request(host, port, is_https, tete_payload, timeout=TIMEOUT)
    if tete_time > (baseline_time + timing_threshold):
        tete_times = [tete_time]
        for _ in range(2):
            t, _ = raw_request(host, port, is_https, tete_payload, timeout=TIMEOUT)
            if t > 0:
                tete_times.append(t)
        tete_times.sort()
        median_time = tete_times[len(tete_times) // 2]
        hits = sum(1 for t in tete_times if t > (baseline_time + timing_threshold))
        tete_status = 0
        if tete_resp:
            try:
                tete_status = int(tete_resp.split(" ")[1])
            except (IndexError, ValueError):
                pass
        if hits >= 2 and median_time > (baseline_time + timing_threshold) and tete_status not in (400, 500, 501, 502, 503):
            findings.append({
                "url": url,
                "type": "TE.TE Smuggling (Obfuscation)",
                "risk": "HIGH",
                "details": f"Possível TE.TE vulnerability (median {median_time:.2f}s em {len(tete_times)} amostras vs {baseline_time:.2f}s base, {hits}/{len(tete_times)} hits)",
                "payload": tete_payload,
                "raw_request": base64.b64encode(tete_payload.encode()).decode(),
                "raw_response": base64.b64encode(tete_resp.encode()).decode()
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
    # V11: Reduzido de 10 para 5 workers para evitar distorção de timing por rate limiting
    with ThreadPoolExecutor(max_workers=5) as executor:
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
