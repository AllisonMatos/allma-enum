#!/usr/bin/env python3
import sys
import time
from pathlib import Path
from datetime import datetime
from importlib import import_module
from core.oast import OastClient
from core.output import info, error, success, warn, set_target_logfile
from menu import C


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
def execute_chain(target: str, chain: list, params: dict, deep: bool = False, stealth: bool = False):
    # V11: Sincronizado com menu.py MODULES
    PLUGIN_MAP = {
        "1": "domain",
        "2": "urls",
        "3": "services",
        "4": "files",
        "5": "jsscanner",
        "6": "fingerprint",
        "7": "endpoint",
        "8": "wordlist",
        "9": "sourcemaps",
        "10": "cve",
        "11": "admin",
        "12": "cors",
        "13": "takeover",
        "14": "headers",
        "15": "waf",
        "16": "emails",
        "17": "graphql",
        "18": "jwt_analyzer",
        "19": "api_fuzzer",
        "20": "cloud",
        "21": "host_header_injection",
        "22": "email_security",
        "23": "google_dorks",
        "24": "cookies",
        "25": "asn",
        "26": "screenshots",
        "99": "intelligence",
    }

    # Set logger to write to specific output folder
    set_target_logfile(target)

    # V11: Set global scope target
    import core.config as _cfg
    _cfg.SCOPE_TARGET = target

    # ==========================================
    #  CHECKPOINT: Resume / Skip
    # ==========================================
    checkpoint_file = Path("output") / target / ".checkpoint"
    completed_steps = set()
    
    if checkpoint_file.exists():
        try:
            completed_steps = set(checkpoint_file.read_text().strip().splitlines())
        except Exception:
            pass
    
    if completed_steps:
        completed_names = [PLUGIN_MAP.get(s, s) for s in completed_steps if s in PLUGIN_MAP]
        if completed_names:
            info(f"\n📋 Scan anterior detectado! Módulos já completos: {', '.join(completed_names)}")
            resume = input(
                f"\n  [S] Pular módulos já completos (resume)\n"
                f"  [R] Recomeçar tudo do zero\n"
                f"  Escolha [S/r]: "
            ).strip().lower()
            
            if resume in ("r", "recomeçar", "reset"):
                completed_steps = set()
                checkpoint_file.unlink(missing_ok=True)
                info("🔄 Recomeçando do zero...")
            else:
                info(f"⏩ Resumindo — pulando {len(completed_steps)} módulos já completos\n")

    # ==========================================
    #  OAST: Start Interactsh-Client via OastClient
    # ==========================================
    import shutil
    
    oast_client = None
    oast_url = None

    interactsh_bin = shutil.which("interactsh-client")
    if interactsh_bin:
        info(f"\n{C.BOLD}{C.PURPLE}[i] Iniciando Interactsh-client (OAST) em background...{C.END}")

        # Configura caminhos
        outdir_base = Path("output") / target
        outdir_base.mkdir(parents=True, exist_ok=True)

        payload_file = outdir_base / "oast_payload.txt"
        results_file = outdir_base / "interactsh.json"

        # Limpa arquivos antigos
        if payload_file.exists():
            payload_file.unlink()
        if results_file.exists():
            results_file.unlink()

        # Instancia o gerenciador OAST
        oast_client = OastClient(
            payloads_file=payload_file,
            results_file=results_file
        )

        # Inicia o subprocesso e obtém a URL real
        oast_url = oast_client.start()

        if oast_url:
            oast_client.base_host = oast_url
            success(f"   [+] Payload OAST Ativo: {C.YELLOW}{oast_url}{C.END}")
        else:
            warn("\n   ⚠️ Interactsh não conectou em 45s. Continuando SEM OAST.")
            oast_client = None
    else:
        warn("   ⚠️ 'interactsh-client' não encontrado no path. Testes blind não serão realizados.")

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

        # Skip se já completou (resume)
        if step in completed_steps:
            info(f"[⏩] Pulando módulo já completo: {name}")
            plugin_timings.append((name, 0.0, "SKIP"))
            continue

        info(f"[+] Executando módulo: {name}")

        module = load_module(name)
        if not module:
            error(f"Não foi possível carregar módulo '{name}'")
            plugin_timings.append((name, 0.0, "ERRO_LOAD"))
            continue

        plugin_context = {
            "target": target,
            "deep": deep,
            "stealth": stealth,
            "oast_url": oast_url,          # mantido para plugins antigos
            "oast": oast_client,           # NOVO: cliente OAST para plugins modernos
            **params.get(name, {})
        }

        try:
            # ⏱️ TIMESTAMP: Início do plugin
            plugin_start = time.time()
            
            result = module.run(plugin_context)
            
            # ⏱️ TIMESTAMP: Fim do plugin
            plugin_end = time.time()
            duration = plugin_end - plugin_start
            
            plugin_timings.append((name, duration, "OK"))
            success(f"⏱️  [{name.upper()}] Tempo de execução: {format_duration(duration)}")
            
            # Salvar checkpoint
            checkpoint_file.parent.mkdir(parents=True, exist_ok=True)
            with checkpoint_file.open("a") as f:
                f.write(f"{step}\n")
            
        except Exception as e:
            plugin_end = time.time()
            duration = plugin_end - plugin_start
            plugin_timings.append((name, duration, "ERRO"))
            error(f"Erro ao executar '{name}': {e}")
            warn(f"⚠️  Continuando pipeline apesar do erro em '{name}'...")
            # Salvar checkpoint mesmo com erro para não re-executar
            checkpoint_file.parent.mkdir(parents=True, exist_ok=True)
            with checkpoint_file.open("a") as f:
                f.write(f"{step}\n")
            continue

    # ==========================================
    #  ENRICHMENT & INTELLIGENCE
    # ==========================================
    # Coletar todos os resultados JSON de todos os plugins para enriquecimento
    all_results = {}
    out_base = Path("output") / target
    for p_dir in out_base.iterdir():
        if p_dir.is_dir():
            res_file = next(p_dir.glob("*_results.json"), None)
            if res_file:
                try:
                    all_results[p_dir.name] = json.loads(res_file.read_text())
                except: pass

    enrich_report_data(target, all_results)

    info("[i] Executando Intelligence Engine...")
    
    intel_step_id = "99"
    if intel_step_id not in completed_steps:
        intel_module = load_module("intelligence")
        if intel_module:
            try:
                intel_start = time.time()
                intel_module.run({"target": target})
                intel_end = time.time()
                intel_duration = intel_end - intel_start
                plugin_timings.append(("intelligence", intel_duration, "OK"))
                
                # Checkpoint
                with checkpoint_file.open("a") as f:
                    f.write(f"{intel_step_id}\n")
            except Exception as e:
                intel_end = time.time()
                intel_duration = intel_end - intel_start
                plugin_timings.append(("intelligence", intel_duration, "ERRO"))
                error(f"Falha ao rodar intelligence: {e}")
        else:
            plugin_timings.append(("intelligence", 0.0, "NOT_FOUND"))
    else:
        info("[⏩] Pulando módulo já completo: intelligence")
        plugin_timings.append(("intelligence", 0.0, "SKIP"))

    info("\n[i] Gerando relatório final (report)...")

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
    #  OAST: Stop Interactsh-Client
    # ==========================================
    if oast_client:
        info(f"\n{C.BOLD}{C.PURPLE}[i] Encerrando sessão OAST e coletando pings tardios...{C.END}")
        time.sleep(3)  # aguarda últimos callbacks
        oast_client.stop()

        results_file = Path("output") / target / "interactsh.json"
        if results_file.exists():
            lines = [l for l in results_file.read_text(errors="ignore").splitlines() if l.strip()]
            if lines:
                success(f"🚨 ALERTA CRÍTICO: {len(lines)} interações OAST (Blind Bugs) detectadas!")
                for line in lines[:3]:  # print amostra
                    info(f"   {line[:150]}...")
            else:
                info("   Nenhuma interação OAST detectada.")

            # Copiar para intelligence para o report consumir
            intel_dir = Path("output") / target / "intelligence"
            intel_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(results_file), str(intel_dir / "oast_interactions.json"))
            info(f"   📂 OAST copiado para {intel_dir / 'oast_interactions.json'}")

    # ==========================================
    #  TIMING: Finalização e geração do arquivo
    # ==========================================
    pipeline_end = time.time()
    total_duration = pipeline_end - pipeline_start
    
    # Gerar arquivo de timing
    _save_timing_report(target, plugin_timings, total_duration)
    
    info("[✔] Pipeline completo.")

import json
def enrich_report_data(target: str, results: dict):
    """
    Junta dados brutos (Raw HTTP), interações OAST e timings para o report final.
    Garante que o modal 'Burp' tenha dados populados.
    """
    out_dir = Path("output") / target
    enriched_file = out_dir / "enriched_data.json"
    
    # Carregar OAST
    oast_data = []
    oast_file = out_dir / "intelligence" / "oast_interactions.json"
    if oast_file.exists():
        try:
            oast_data = json.loads(oast_file.read_text())
        except: pass

    data = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "findings_with_raw": [],
        "oast": oast_data,
        "summary": {
            "total_plugins": len(results),
            "total_findings": sum(len(v) if isinstance(v, list) else 1 for v in results.values())
        }
    }

    # Extrair achados que possuem request_raw ou response_raw
    for plugin, findings in results.items():
        if isinstance(findings, list):
            for f in findings:
                if isinstance(f, dict) and ("request_raw" in f or "response_raw" in f):
                    f["plugin"] = plugin
                    data["findings_with_raw"].append(f)

    enriched_file.write_text(json.dumps(data, indent=2))
    info(f"   [+] Dados enriquecidos salvos em {enriched_file} ({len(data['findings_with_raw'])} raw findings)")


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