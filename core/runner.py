#!/usr/bin/env python3
import sys
from importlib import import_module
from core.output import info, error, success


# --------- CARREGAMENTO DINÂMICO ---------
def load_module(name: str):
    try:
        module = import_module(f"plugins.{name}.main")
        return module
    except Exception as e:
        error(f"Falha ao importar plugin '{name}': {e}")
        return None


# --------- EXECUÇÃO EM CADEIA ---------
def execute_chain(target: str, chain: list, params: dict):

    PLUGIN_MAP = {
        "1": "domain",
        "2": "urls",
        "3": "services",
        "4": "files",
        "5": "jsscanner",
        "6": "fingerprint",
        "7": "endpoint",
        "8": "wordlist",
        "9": "xss",
    }

    for step in chain:
        name = PLUGIN_MAP.get(step)
        if not name:
            error(f"Plugin desconhecido: {step}")
            continue

        info(f"[+] Executando módulo: {name}")

        module = load_module(name)
        if not module:
            error(f"Não foi possível carregar módulo '{name}'")
            continue

        plugin_context = {
            "target": target,
            **params.get(name, {})
        }

        try:
            module.run(plugin_context)
        except Exception as e:
            error(f"Erro ao executar '{name}': {e}")
            sys.exit(1)

    # ==========================================
    #  REPORT — SEMPRE RODA POR ÚLTIMO
    # ==========================================
    info("[i] Gerando relatório final (report)...")

    report_module = load_module("report")
    if report_module:
        try:
            report_module.run({"target": target})
            success("[✔] Report final gerado com sucesso.")
        except Exception as e:
            error(f"Falha ao gerar o relatório final: {e}")
    else:
            error("Plugin 'report' não encontrado — pulando report.")

    info("[✔] Pipeline completo.")