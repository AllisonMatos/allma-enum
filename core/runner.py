#!/usr/bin/env python3
import sys
import time
from pathlib import Path
from datetime import datetime
from importlib import import_module
from core.output import info, error, success, warn


# --------- CARREGAMENTO DINÂMICO ---------
def load_module(name: str):
    try:
        module = import_module(f"plugins.{name}.main")
        return module
    except Exception as e:
        error(f"Falha ao importar plugin '{name}': {e}")
        return None


# --------- FORMATAÇÃO DE TEMPO ---------
def format_duration(seconds: float) -> str:
    """Formata duração em formato legível."""
    if seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.2f}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = seconds % 60
        return f"{hours}h {minutes}m {secs:.2f}s"


# --------- EXECUÇÃO EM CADEIA ---------
def execute_chain(target: str, chain: list, params: dict):

    PLUGIN_MAP = {
        "1": "domain",
        "2": "services",   # SERVICES antes de URLS para alimentar pipeline com URLs do Nmap
        "3": "urls",
        "4": "files",
        "5": "jsscanner",
        "6": "fingerprint",
        "7": "endpoint",
        "8": "wordlist",
        "9": "xss",
        "10": "cloud",
        "11": "visual",
        "12": "cve"
    }

    # ==========================================
    #  TIMING: Inicialização
    # ==========================================
    pipeline_start = time.time()
    plugin_timings = []  # Lista de (nome, duração, status)
    
    info(f"\n⏱️  [TIMING] Pipeline iniciado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    for step in chain:
        name = PLUGIN_MAP.get(step)
        if not name:
            error(f"Plugin desconhecido: {step}")
            continue

        info(f"[+] Executando módulo: {name}")

        module = load_module(name)
        if not module:
            error(f"Não foi possível carregar módulo '{name}'")
            plugin_timings.append((name, 0.0, "ERRO_LOAD"))
            continue

        plugin_context = {
            "target": target,
            **params.get(name, {})
        }

        try:
            # ⏱️ TIMESTAMP: Início do plugin
            plugin_start = time.time()
            
            module.run(plugin_context)
            
            # ⏱️ TIMESTAMP: Fim do plugin
            plugin_end = time.time()
            duration = plugin_end - plugin_start
            
            plugin_timings.append((name, duration, "OK"))
            success(f"⏱️  [{name.upper()}] Tempo de execução: {format_duration(duration)}")
            
        except Exception as e:
            plugin_end = time.time()
            duration = plugin_end - plugin_start
            plugin_timings.append((name, duration, "ERRO"))
            error(f"Erro ao executar '{name}': {e}")
            sys.exit(1)

    # ==========================================
    #  REPORT — SEMPRE RODA POR ÚLTIMO
    # ==========================================
    info("[i] Gerando relatório final (report)...")

    report_module = load_module("report")
    if report_module:
        try:
            report_start = time.time()
            report_module.run({"target": target})
            report_end = time.time()
            report_duration = report_end - report_start
            plugin_timings.append(("report", report_duration, "OK"))
            success(f"⏱️  [REPORT] Tempo de execução: {format_duration(report_duration)}")
            success("[✔] Report final gerado com sucesso.")
        except Exception as e:
            report_end = time.time()
            report_duration = report_end - report_start
            plugin_timings.append(("report", report_duration, "ERRO"))
            error(f"Falha ao gerar o relatório final: {e}")
    else:
        error("Plugin 'report' não encontrado — pulando report.")
        plugin_timings.append(("report", 0.0, "NOT_FOUND"))

    # ==========================================
    #  TIMING: Finalização e geração do arquivo
    # ==========================================
    pipeline_end = time.time()
    total_duration = pipeline_end - pipeline_start
    
    # Gerar arquivo de timing
    _save_timing_report(target, plugin_timings, total_duration)
    
    info("[✔] Pipeline completo.")


def _save_timing_report(target: str, timings: list, total_duration: float):
    """Salva relatório de tempo de execução dos plugins."""
    
    outdir = Path("output") / target
    outdir.mkdir(parents=True, exist_ok=True)
    timing_file = outdir / "plugin_timings.txt"
    
    # Ordenar por tempo (maior primeiro)
    sorted_timings = sorted(timings, key=lambda x: x[1], reverse=True)
    
    lines = [
        "=" * 60,
        "RELATÓRIO DE TEMPO DE EXECUÇÃO DOS PLUGINS",
        "=" * 60,
        f"Target: {target}",
        f"Data/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Tempo Total do Pipeline: {format_duration(total_duration)}",
        "",
        "-" * 60,
        f"{'PLUGIN':<20} {'TEMPO':<20} {'STATUS':<10}",
        "-" * 60,
    ]
    
    for name, duration, status in sorted_timings:
        status_symbol = "✔" if status == "OK" else "✖" if "ERRO" in status else "⚠"
        lines.append(f"{name:<20} {format_duration(duration):<20} {status_symbol} {status}")
    
    lines.extend([
        "-" * 60,
        "",
        "📊 ANÁLISE DE PERFORMANCE:",
        "",
    ])
    
    # Identificar plugins mais lentos
    if sorted_timings:
        slowest = sorted_timings[0]
        if slowest[1] > 60:  # Mais de 1 minuto
            lines.append(f"⚠️  Plugin mais lento: {slowest[0]} ({format_duration(slowest[1])})")
            lines.append("   Considere otimizações ou verificar dependências de rede.")
        
        # Calcular percentuais
        lines.append("")
        lines.append("📈 DISTRIBUIÇÃO DE TEMPO (%):")
        for name, duration, status in sorted_timings:
            if total_duration > 0:
                pct = (duration / total_duration) * 100
                bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
                lines.append(f"   {name:<15} [{bar}] {pct:.1f}%")
    
    lines.extend([
        "",
        "=" * 60,
        "Gerado automaticamente por Enum-Allma",
        "=" * 60,
    ])
    
    timing_file.write_text("\n".join(lines), encoding="utf-8")
    
    # Exibir resumo no console
    info(f"\n{'='*60}")
    info(f"⏱️  RESUMO DE TEMPO DE EXECUÇÃO")
    info(f"{'='*60}")
    for name, duration, status in sorted_timings:
        status_emoji = "✅" if status == "OK" else "❌"
        info(f"   {status_emoji} {name:<15}: {format_duration(duration)}")
    info(f"{'-'*60}")
    info(f"   🏁 TEMPO TOTAL: {format_duration(total_duration)}")
    info(f"{'='*60}")
    success(f"📄 Relatório de timing salvo em: {timing_file}\n")