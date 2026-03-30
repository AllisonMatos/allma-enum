#!/usr/bin/env python3
import sys

from menu import C
from plugins import ensure_outdir
from .data import DOCS

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.markup import escape
    from rich import box
    RICH_INSTALLED = True
except ImportError:
    RICH_INSTALLED = False

def print_fallback(plugin_name):
    # Fallback to simple print if rich is not installed
    data = DOCS.get(plugin_name)
    if not data:
        print(f"{C.RED}Plugin não encontrado na documentação.{C.END}")
        return

    print(f"\n{C.BOLD}{C.CYAN}--- DOCUMENTAÇÃO: {plugin_name.upper()} ---{C.END}")
    print(f"{C.BOLD}{C.YELLOW}Resumo:{C.END} {data['resumo']}")
    print(f"\n{C.BOLD}{C.YELLOW}Comandos / Código Executado:{C.END}")
    print(data['comandos'])
    print(f"\n{C.BOLD}{C.YELLOW}Rationale (Por que usar):{C.END}")
    print(data['rationale'])
    print(f"\n{C.BOLD}{C.YELLOW}O que deveria achar e ignorar:{C.END}")
    print(data['esperado'])
    print(f"\n{C.BOLD}{C.YELLOW}Exploração (Se Vulnerabilidade):{C.END}")
    print(data['exploracao'])
    print(f"{C.CYAN}---------------------------------------------{C.END}\n")

def print_rich(plugin_name):
    console = Console()
    data = DOCS.get(plugin_name)
    if not data:
        console.print(f"[bold red]Plugin não encontrado na documentação.[/bold red]")
        return
    
    title = f"🧠 INFORMAÇÕES TÉCNICAS: [cyan]{data['nome'].upper()}[/cyan]"
    console.print(Panel(f"[bold yellow]Resumo Rápido:[/bold yellow] [white]{escape(data['resumo'])}[/white]", title=title, border_style="blue"))
    
    table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED, padding=(1, 1))
    table.add_column("Informação", style="cyan", width=30)
    table.add_column("Detalhe Técnico", style="white")

    table.add_row("[bold yellow]Comandos / Código Executado[/bold yellow]", escape(data['comandos']))
    table.add_row("[bold yellow]Por que usar?[/bold yellow]", escape(data['rationale']))
    table.add_row("[bold yellow]O que ele acha e ignora[/bold yellow]", escape(data['esperado']))
    table.add_row("[bold red]Exploração (Vulnerabilidade)[/bold red]", escape(data['exploracao']))

    console.print(table)
    console.print()

def run_docs():
    while True:
        print(f"\n{C.BOLD}{C.PURPLE}=== VISUALIZADOR DE DOCUMENTAÇÃO DE PLUGINS ==={C.END}")
        print(f"{C.GRAY}Aqui você pode ler como cada plugin funciona internamente sem depender de arquivos Markdown ou Github.{C.END}\n")
        
        plugins_list = list(DOCS.keys())
        
        # Print columns of plugins
        half = len(plugins_list) // 2 + len(plugins_list) % 2
        for i in range(half):
            p1 = plugins_list[i]
            p2 = plugins_list[i + half] if i + half < len(plugins_list) else ""
            idx1 = f"[{i+1}]"
            idx2 = f"[{i+1+half}]" if p2 else ""
            print(f"  {C.CYAN}{idx1:>4}{C.END} {p1:<25} {C.CYAN}{idx2:>4}{C.END} {p2}")

        print(f"\n  {C.CYAN}[ 0]{C.END} Sair para Menu Principal")
        
        choice = input(f"\n{C.BOLD}{C.BLUE}Escolha o número do plugin para ler (ou 0 para sair): {C.END}").strip()
        
        if choice == "0" or choice.lower() == "sair":
            break
            
        try:
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(plugins_list):
                selected_plugin = plugins_list[choice_idx]
                if RICH_INSTALLED:
                    print_rich(selected_plugin)
                else:
                    print_fallback(selected_plugin)
                input(f"{C.GRAY}Pressione [ENTER] para continuar...{C.END}")
            else:
                print(f"{C.RED}❌ Opção Inválida.{C.END}")
        except ValueError:
            print(f"{C.RED}❌ Digite um número.{C.END}")
