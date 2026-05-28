"""
core/multi_runner.py — Orquestrador Multi-Target para Enum-allma.

Executa a pipeline completa (execute_chain) para múltiplos targets em paralelo,
cada um em um processo separado (multiprocessing) para isolamento total de globals.

Cada target tem:
  - Seu próprio output em output/<target>/
  - Seu próprio log em output/<target>/execution.log
  - Seus próprios globals de config (SCOPE_TARGET, SCOPE_ROOT, etc.)
"""

import os
import sys
import time
import multiprocessing
from pathlib import Path
from datetime import datetime
from core.output import info, success, warn, error
from core.colors import C


# ============================================================
# WORKER: Executa pipeline para 1 target (roda em processo filho)
# ============================================================
def _run_single_target(target: str, chain: list, params: dict,
                       deep: bool, stealth: bool, status_dir: str):
    """
    Worker function executada em um processo separado.
    Roda execute_chain para um único target e reporta status via arquivo.
    """
    status_file = Path(status_dir) / f"{target}.status"

    # Criar pasta do target e arquivo de log
    log_dir = Path("output") / target
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "execution.log"
    
    # Redirecionar STDOUT e STDERR para o arquivo de log (com unbuffered mode usando flush)
    class Logger:
        def __init__(self, filename):
            self.terminal = sys.stdout
            self.log = open(filename, "w", buffering=1) # line buffered

        def write(self, message):
            self.log.write(message)
            self.log.flush() # Garante que o tail -f leia instantaneamente

        def flush(self):
            self.log.flush()

    sys.stdout = Logger(log_file)
    sys.stderr = sys.stdout

    # Escrever status inicial
    _write_status(status_file, "RUNNING", module="init", step=0, total=len(chain))

    # Configurar prefixo de log para este target
    import core.output as _out
    _out._MULTI_TARGET_PREFIX = target

    try:
        from core.runner import execute_chain

        # Hook para reportar progresso: monkey-patch temporário do runner
        # para escrever status a cada plugin
        _original_info = _out.info
        _step_counter = {"current": 0}

        def _tracking_info(msg):
            """Info wrapper que detecta início de plugins para tracking."""
            if "[+] Executando módulo:" in msg:
                module_name = msg.split("módulo:")[-1].strip() if "módulo:" in msg else "?"
                _step_counter["current"] += 1
                _write_status(
                    status_file, "RUNNING",
                    module=module_name,
                    step=_step_counter["current"],
                    total=len(chain)
                )
            _original_info(msg)

        _out.info = _tracking_info

        # Executar pipeline completa
        execute_chain(target, chain, params, deep=deep, stealth=stealth, auto_resume=True)

        _write_status(status_file, "DONE", module="complete",
                      step=len(chain), total=len(chain))

    except KeyboardInterrupt:
        _write_status(status_file, "CANCELLED", module="interrupted")
    except Exception as e:
        _write_status(status_file, "ERROR", module=str(e)[:100])
    finally:
        # Restaurar info original (não importa muito pois o processo morre)
        pass


def _write_status(status_file: Path, state: str, module: str = "",
                  step: int = 0, total: int = 0):
    """Escreve arquivo de status para comunicação entre processos."""
    try:
        status_file.parent.mkdir(parents=True, exist_ok=True)
        status_file.write_text(
            f"{state}|{module}|{step}|{total}|{time.time()}\n"
        )
    except Exception:
        pass


def _read_status(status_file: Path) -> dict:
    """Lê arquivo de status de um target."""
    try:
        if status_file.exists():
            parts = status_file.read_text().strip().split("|")
            return {
                "state": parts[0],
                "module": parts[1] if len(parts) > 1 else "",
                "step": int(parts[2]) if len(parts) > 2 else 0,
                "total": int(parts[3]) if len(parts) > 3 else 0,
                "timestamp": float(parts[4]) if len(parts) > 4 else 0,
            }
    except Exception:
        pass
    return {"state": "PENDING", "module": "", "step": 0, "total": 0, "timestamp": 0}


# ============================================================
# DASHBOARD: Exibe progresso de todos os targets
# ============================================================
def _print_dashboard(targets: list, status_dir: str, start_time: float):
    """Imprime dashboard de progresso no terminal."""
    elapsed = time.time() - start_time
    elapsed_str = f"{int(elapsed // 3600)}h {int((elapsed % 3600) // 60)}m"

    completed = 0
    running = 0
    errors = 0

    lines = []
    for target in targets:
        status_file = Path(status_dir) / f"{target}.status"
        status = _read_status(status_file)

        state = status["state"]
        module = status["module"]
        step = status["step"]
        total = status["total"]

        if state == "DONE":
            completed += 1
            emoji = "✅"
            detail = f"Completo [{step}/{total}]"
            color = C.GREEN
        elif state == "RUNNING":
            running += 1
            emoji = "🔄"
            # Calcular tempo do target
            target_elapsed = time.time() - status["timestamp"] if status["timestamp"] else 0
            mins = int(target_elapsed // 60)
            detail = f"{module} ({mins}m) [{step}/{total}]"
            color = C.CYAN
        elif state == "ERROR":
            errors += 1
            emoji = "❌"
            detail = f"Erro: {module[:40]}"
            color = C.RED
        elif state == "CANCELLED":
            emoji = "⚠️"
            detail = "Cancelado"
            color = C.YELLOW
        else:
            emoji = "⏳"
            detail = "Aguardando..."
            color = C.GRAY

        lines.append(f"  {emoji} {color}{target:<25}{C.END} — {detail}")

    # Cabeçalho
    total_targets = len(targets)
    print(f"\033c", end="")  # Limpa tela
    print(f"\n{C.BOLD}{C.PURPLE}╔{'═' * 62}╗{C.END}")
    print(f"{C.BOLD}{C.PURPLE}║  🎯 MULTI-TARGET SCAN — {completed}/{total_targets} completos | ⏱️  {elapsed_str:<14} ║{C.END}")
    print(f"{C.BOLD}{C.PURPLE}╠{'═' * 62}╣{C.END}")

    for line in lines:
        print(f"{C.BOLD}{C.PURPLE}║{C.END}{line}")

    print(f"{C.BOLD}{C.PURPLE}╠{'═' * 62}╣{C.END}")
    print(f"{C.BOLD}{C.PURPLE}║{C.END}  🟢 Running: {running}  ✅ Done: {completed}  ❌ Errors: {errors}  ⏳ Queue: {total_targets - completed - running - errors}")
    print(f"{C.BOLD}{C.PURPLE}╚{'═' * 62}╝{C.END}\n")


# ============================================================
# RELATÓRIO CONSOLIDADO
# ============================================================
def _generate_multi_report(targets: list, status_dir: str, total_duration: float):
    """Gera relatório HTML consolidado com links para reports individuais."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    report_path = Path("output") / f"multi_report_{timestamp}.html"

    target_rows = []
    for target in targets:
        status = _read_status(Path(status_dir) / f"{target}.status")
        report_link = f"<a href='{target}/report.html'>{target}/report.html</a>"

        # Contar dados básicos
        subs_count = 0
        urls_count = 0
        subs_file = Path("output") / target / "domain" / "subdomains.txt"
        urls_file = Path("output") / target / "urls" / "urls_200.txt"

        if subs_file.exists():
            subs_count = sum(1 for l in subs_file.read_text(errors="ignore").splitlines() if l.strip())
        if urls_file.exists():
            urls_count = sum(1 for l in urls_file.read_text(errors="ignore").splitlines() if l.strip())

        state_badge = {
            "DONE": '<span style="color:#00ff88">✅ Completo</span>',
            "ERROR": '<span style="color:#ff4444">❌ Erro</span>',
            "CANCELLED": '<span style="color:#ffaa00">⚠️ Cancelado</span>',
        }.get(status["state"], '<span style="color:#888">⏳ Desconhecido</span>')

        target_rows.append(f"""
        <tr>
            <td><strong>{target}</strong></td>
            <td>{state_badge}</td>
            <td>{subs_count}</td>
            <td>{urls_count}</td>
            <td>{report_link}</td>
        </tr>""")

    duration_str = f"{int(total_duration // 3600)}h {int((total_duration % 3600) // 60)}m {int(total_duration % 60)}s"

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Enum-Allma — Multi-Target Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', 'Inter', sans-serif;
            background: #0a0e17;
            color: #e0e0e0;
            padding: 40px;
        }}
        h1 {{
            background: linear-gradient(135deg, #7c3aed, #06b6d4);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-size: 2rem;
            margin-bottom: 8px;
        }}
        .meta {{
            color: #888;
            margin-bottom: 30px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #111827;
            border-radius: 12px;
            overflow: hidden;
        }}
        th {{
            background: #1e293b;
            padding: 14px 16px;
            text-align: left;
            color: #94a3b8;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 0.05em;
        }}
        td {{
            padding: 12px 16px;
            border-bottom: 1px solid #1e293b;
        }}
        tr:hover {{ background: #1a2332; }}
        a {{
            color: #06b6d4;
            text-decoration: none;
        }}
        a:hover {{ text-decoration: underline; }}
        .summary {{
            display: flex;
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: #111827;
            border: 1px solid #1e293b;
            border-radius: 12px;
            padding: 20px;
            flex: 1;
            text-align: center;
        }}
        .card .num {{
            font-size: 2rem;
            font-weight: 700;
            background: linear-gradient(135deg, #7c3aed, #06b6d4);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .card .label {{ color: #888; font-size: 0.85rem; margin-top: 4px; }}
    </style>
</head>
<body>
    <h1>🎯 Enum-Allma — Multi-Target Report</h1>
    <p class="meta">Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Duração total: {duration_str}</p>

    <div class="summary">
        <div class="card">
            <div class="num">{len(targets)}</div>
            <div class="label">Targets</div>
        </div>
        <div class="card">
            <div class="num">{sum(1 for t in targets if _read_status(Path(status_dir) / f'{t}.status')['state'] == 'DONE')}</div>
            <div class="label">Completos</div>
        </div>
        <div class="card">
            <div class="num">{duration_str}</div>
            <div class="label">Tempo Total</div>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th>Target</th>
                <th>Status</th>
                <th>Subdomínios</th>
                <th>URLs Vivas</th>
                <th>Relatório</th>
            </tr>
        </thead>
        <tbody>
            {''.join(target_rows)}
        </tbody>
    </table>
</body>
</html>"""

    report_path.write_text(html, encoding="utf-8")
    return report_path


# ============================================================
# MAIN: Orquestrador Multi-Target
# ============================================================
def execute_multi_target(
    targets: list,
    chain: list,
    params: dict,
    deep: bool = False,
    stealth: bool = False,
    max_parallel: int = 3,
    open_terminals: bool = False,
):
    """
    Executa a pipeline completa para múltiplos targets em paralelo.

    Args:
        targets: Lista de domínios para enumerar.
        chain: Lista de steps (plugin IDs) para executar.
        params: Dict de parâmetros por plugin.
        deep: Habilitar deep scan.
        stealth: Habilitar stealth mode.
        max_parallel: Máximo de targets simultâneos.
    """
    total = len(targets)
    info(f"\n{C.BOLD}{C.PURPLE}🎯 MULTI-TARGET MODE — {total} targets, {max_parallel} paralelos{C.END}\n")

    # Diretório para status de cada target
    status_dir = str(Path("output") / ".multi_status")
    Path(status_dir).mkdir(parents=True, exist_ok=True)

    # Limpar status antigo
    for f in Path(status_dir).glob("*.status"):
        f.unlink()

    # Tratamento de wildcards no nível global
    clean_targets = []
    target_scopes = {}
    for t in targets:
        clean_t = t[2:] if t.startswith("*.") else t
        target_scopes[clean_t] = [] if t.startswith("*.") else [clean_t]
        clean_targets.append(clean_t)
    targets = clean_targets
    
    # Configuração de Sessão do Tmux para Terminais Unificados
    tmux_session = None
    if open_terminals:
        import shutil, subprocess
        if shutil.which("tmux"):
            tmux_session = f"enum_allma_{int(time.time())}"
            # Cria sessão em background (detached)
            subprocess.run(["tmux", "new-session", "-d", "-s", tmux_session, "bash", "-c", "echo 'Enum-allma Multi-Target Live Logs (Aguardando processos...)'; sleep infinity"])
            
            # Abre o emulador de terminal atachado à sessão
            try:
                subprocess.Popen(["x-terminal-emulator", "-geometry", "140x41", "-e", "tmux", "attach-session", "-t", tmux_session], stderr=subprocess.DEVNULL)
            except Exception:
                try:
                    subprocess.Popen(["gnome-terminal", "--geometry=140x41", "--", "tmux", "attach-session", "-t", tmux_session], stderr=subprocess.DEVNULL)
                except Exception:
                    try:
                        subprocess.Popen(["konsole", "--geometry", "140x41", "-e", "tmux", "attach-session", "-t", tmux_session], stderr=subprocess.DEVNULL)
                    except Exception:
                        pass
        else:
            warn("⚠️ Tmux não encontrado! Abrindo janelas separadas...")

    pipeline_start = time.time()

    # Pool de processos com limite de paralelismo
    active_processes: dict[str, multiprocessing.Process] = {}
    pending_targets = list(targets)
    completed_targets = []
    failed_targets = []

    try:
        while pending_targets or active_processes:
            # Iniciar novos processos se há slots disponíveis
            while pending_targets and len(active_processes) < max_parallel:
                target = pending_targets.pop(0)

                # Clonar params para este target (cada um precisa do seu scope_root)
                target_params = {}
                for plugin_name, plugin_params in params.items():
                    target_params[plugin_name] = dict(plugin_params)
                    target_params[plugin_name]["scope_root"] = target
                
                if "domain" in target_params:
                    target_params["domain"]["closed_scope"] = target_scopes[target]

                p = multiprocessing.Process(
                    target=_run_single_target,
                    args=(target, chain, target_params, deep, stealth, status_dir),
                    name=f"enum-{target}",
                    daemon=False,
                )
                p.start()
                active_processes[target] = p
                info(f"  🚀 Iniciado: {C.GREEN}{target}{C.END} (PID {p.pid})")
                
                # Iniciar janela de terminal isolada ou painel do tmux se configurado
                if open_terminals:
                    import subprocess, shlex
                    log_file = Path("output") / target / "execution.log"
                    log_file.parent.mkdir(parents=True, exist_ok=True)
                    log_file.touch(exist_ok=True)
                    
                    safe_log = shlex.quote(str(log_file.absolute()))
                    cmd_tail = f"tail --pid={p.pid} -f {safe_log}"
                    
                    if tmux_session:
                        # Injeta um novo split na sessão do tmux e balanceia o layout
                        subprocess.run(["tmux", "split-window", "-t", tmux_session, "-h", "bash", "-c", cmd_tail])
                        subprocess.run(["tmux", "select-layout", "-t", tmux_session, "tiled"])
                    else:
                        # Fallback: janelas separadas se tmux não existir
                        try:
                            subprocess.Popen(["x-terminal-emulator", "-geometry", "56x41", "-e", "bash", "-c", cmd_tail], stderr=subprocess.DEVNULL)
                        except Exception:
                            try:
                                subprocess.Popen(["gnome-terminal", "--geometry=56x41", "--", "bash", "-c", cmd_tail], stderr=subprocess.DEVNULL)
                            except Exception:
                                try:
                                    subprocess.Popen(["konsole", "--geometry", "56x41", "-e", "bash", "-c", cmd_tail], stderr=subprocess.DEVNULL)
                                except Exception:
                                    pass

            # Verificar processos finalizados
            finished = []
            for target, proc in active_processes.items():
                if not proc.is_alive():
                    finished.append(target)
                    status = _read_status(Path(status_dir) / f"{target}.status")
                    if status["state"] == "DONE":
                        completed_targets.append(target)
                        success(f"  ✅ Completo: {target}")
                    else:
                        failed_targets.append(target)
                        error(f"  ❌ Falhou: {target} — {status.get('module', 'unknown')}")

            for target in finished:
                active_processes[target].join(timeout=5)
                del active_processes[target]

            # Dashboard
            if active_processes:
                _print_dashboard(targets, status_dir, pipeline_start)

            time.sleep(5)  # Poll interval

    except KeyboardInterrupt:
        warn("\n⚠️  Ctrl+C detectado! Encerrando processos...")
        for target, proc in active_processes.items():
            proc.terminate()
            _write_status(
                Path(status_dir) / f"{target}.status",
                "CANCELLED", module="user_interrupt"
            )
        for proc in active_processes.values():
            proc.join(timeout=10)
        warn("Todos os processos encerrados.")

    # Tempo total
    total_duration = time.time() - pipeline_start

    # Dashboard final
    _print_dashboard(targets, status_dir, pipeline_start)

    # Relatório consolidado HTML (desativado a pedido do usuário)
    # report_path = _generate_multi_report(targets, status_dir, total_duration)
    # Resumo final
    duration_str = f"{int(total_duration // 3600)}h {int((total_duration % 3600) // 60)}m {int(total_duration % 60)}s"
    print(f"\n{C.BOLD}{C.GREEN}{'=' * 60}{C.END}")
    print(f"{C.BOLD}{C.GREEN}🏁 MULTI-TARGET SCAN CONCLUÍDO{C.END}")
    print(f"{C.BOLD}{C.GREEN}{'=' * 60}{C.END}")
    print(f"  ✅ Completos: {len(completed_targets)}/{total}")
    print(f"  ❌ Erros:     {len(failed_targets)}/{total}")
    print(f"  ⏱️  Tempo:     {duration_str}")
    print(f"{C.BOLD}{C.GREEN}{'=' * 60}{C.END}\n")

    # Limpar status dir
    # (mantém para debug — pode ser removido se preferir)

    return {
        "completed": completed_targets,
        "failed": failed_targets,
        "duration": total_duration
    }
