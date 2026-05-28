#!/usr/bin/env python3
"""
Nuclei Scanner — Varredura automatizada de vulnerabilidades.

Roda o binário do Nuclei com flags otimizadas para balancear
velocidade e evasão de WAF (concurrency reduzida, rate limit fixo).
Foca apenas em templates críticos e altos: CVEs, painéis expostos, etc.
"""
import json
import shutil
import subprocess
from pathlib import Path

from menu import C
from plugins import ensure_outdir
from plugins.validation import finding
from ..output import info, success, warn, error


def run(context: dict):
    """Executa o scanner Nuclei de forma otimizada e WAF-friendly."""
    target = context.get("target")
    if not target:
        raise ValueError("Target required")

    info(
        f"\n☢️───────────────────────────────────────────────────────────☢️\n"
        f"   ☢️  {C.BOLD}{C.RED}NUCLEI VULNERABILITY SCANNER{C.END}\n"
        f"   🎯 Alvo: {C.GREEN}{target}{C.END}\n"
        f"☢️───────────────────────────────────────────────────────────☢️\n"
    )

    nuclei_bin = shutil.which("nuclei")
    if not nuclei_bin:
        warn("   ⚠️ 'nuclei' não encontrado no PATH. Pulando varredura automatizada.")
        return []

    outdir = ensure_outdir(target, "nuclei")

    # Carregar URLs válidas
    from core.url_sources import primary_urls_txt_for_scan
    urls_file = primary_urls_txt_for_scan(target)
    if not urls_file.exists():
        urls_file = Path("output") / target / "urls" / "urls_200.txt"
    if not urls_file.exists():
        urls_file = Path("output") / target / "domain" / "urls_valid.txt"
    if not urls_file.exists():
        warn("   ⚠️ Nenhuma URL válida encontrada. Execute o módulo urls primeiro.")
        (outdir / "findings.json").write_text("[]")
        return []

    # Otimização de tempo e WAF-friendly:
    # -c 30 : baixa concorrência (default é 150)
    # -rl 150 : rate limit conservador (default é 150)
    # -bulk-size 25 : reduz explosões de requests
    # -timeout 5 -retries 1 : fast fail
    # -severity critical,high : foca no que importa para ROI rápido
    # -tags cve,exposed-panels,misconfig,takeover : templates prioritários
    
    output_jsonl = outdir / "nuclei_raw.jsonl"
    
    cmd = [
        nuclei_bin,
        "-l", str(urls_file),
        "-severity", "critical,high",
        "-tags", "cve,exposed-panels,misconfig,takeover",
        "-c", "30",
        "-rl", "150",
        "-bulk-size", "25",
        "-timeout", "5",
        "-retries", "1",
        "-stats", "-si", "30",  # Habilita estatísticas a cada 30 segundos
        "-j", "-o", str(output_jsonl)
    ]
    
    info(f"   🚀 Iniciando Nuclei Scanner WAF-friendly...")
    info(f"   ⚙️  Flags: -c 30 -rl 150 -severity critical,high")
    info(f"   💡 Dica: O Nuclei imprimirá o progresso a cada 30s. Isso pode demorar horas dependendo da quantidade de URLs!")
    
    try:
        # Popen sem -silent para permitir que o usuário veja a % de progresso no log
        subprocess.run(cmd, check=False)
    except Exception as e:
        error(f"   ❌ Erro ao executar o Nuclei: {e}")
        return []

    # Parsear os resultados
    all_findings = []
    if output_jsonl.exists():
        for line in output_jsonl.read_text(errors="ignore").splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                all_findings.append(data)
            except json.JSONDecodeError:
                pass

    if not all_findings:
        info("   ✅ Nenhuma vulnerabilidade crítica/alta detectada pelo Nuclei.")
        (outdir / "findings.json").write_text("[]")
        return []

    info(f"   🚨 {C.RED}{len(all_findings)} VULNERABILIDADES DETECTADAS!{C.END}")

    # Normalizar para o schema do Enum-allma
    normalized = []
    for f in all_findings:
        # Extrair dados do Nuclei JSON schema
        template_id = f.get("template-id", "Unknown")
        name = f.get("info", {}).get("name", "Vulnerability")
        risk = f.get("info", {}).get("severity", "medium").upper()
        
        # Evitar mapear severity como INFO
        if risk == "INFO": risk = "LOW"
            
        desc = f.get("info", {}).get("description", "")
        url = f.get("matched-at", "") or f.get("host", "")
        
        req_raw = f.get("request", "")
        res_raw = f.get("response", "")
        curl = f.get("curl-command", "")
        extracted = f.get("extracted-results", [])

        # Mostrar no console
        sev_color = C.RED if risk == "CRITICAL" else C.YELLOW if risk == "HIGH" else C.CYAN
        info(f"   {sev_color}[{risk}]{C.END} {name} ({template_id}) -> {url}")

        normalized.append(
            finding(
                plugin="nuclei",
                target=target,
                title=f"Nuclei: {name}",
                issue_type="NUCLEI_FINDING",
                risk=risk,
                confidence="HIGH",
                description=desc,
                url=url,
                detection={
                    "template_id": template_id,
                    "extracted_results": extracted,
                },
                validation={
                    "confirmed": True,
                    "curl_command": curl,
                },
                evidence={
                    "request_raw": req_raw,
                    "response_raw": res_raw,
                    "observable_impact": f"Template: {template_id}",
                    "curl_command": curl,
                },
                metadata=f,
            )
        )

    # Salvar resultados normalizados
    (outdir / "findings.json").write_text(json.dumps(normalized, indent=2, ensure_ascii=False))
    success(f"   📂 Resultados salvos em {outdir}/findings.json")

    return normalized
