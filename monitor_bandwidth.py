#!/usr/bin/env python3
import time
import os
import sys

from core.colors import C  # Centralizado em core/colors.py

def get_net_io():
    """Lê bytes de RX/TX do /proc/net/dev"""
    interfaces = {}
    try:
        with open("/proc/net/dev", "r") as f:
            lines = f.readlines()[2:]  # Pula o cabeçalho
            for line in lines:
                parts = line.split()
                if not parts: continue
                iface = parts[0].strip(":")
                rx = int(parts[1])
                tx = int(parts[9])
                interfaces[iface] = (rx, tx)
    except Exception:
        pass
    return interfaces

def format_speed(bytes_per_sec):
    """Formata bytes para KB/s ou MB/s"""
    kb = bytes_per_sec / 1024
    if kb > 1024:
        return f"{kb/1024:.2f} MB/s"
    return f"{kb:.2f} KB/s"

def main():
    os.system("clear")
    print(f"{C.BOLD}{C.CYAN}🚀 MONITOR DE BANDA - Enum-Allma Utility{C.END}")
    print(f"{C.YELLOW}Pressione Ctrl+C para sair{C.END}\n")

    # Tenta descobrir o processo do Enum-Allma
    print(f"{C.BOLD}DICA:{C.END} Abra outro terminal e rode o {C.GREEN}menu.py{C.END} para ver o impacto.")
    
    last_io = get_net_io()
    if not last_io:
        print(f"{C.RED}Erro: Não foi possível ler /proc/net/dev. Este script funciona apenas em Linux.{C.END}")
        return

    # Encontra a interface principal (a que tem mais tráfego inicial ou não é loopback)
    main_iface = "eth0"
    for iface in last_io:
        if iface != "lo":
            main_iface = iface
            break

    try:
        while True:
            time.sleep(1)
            current_io = get_net_io()
            
            if main_iface not in current_io:
                # Caso a interface suma ou mude
                main_iface = next(iter(current_io))

            rx_diff = current_io[main_iface][0] - last_io[main_iface][0]
            tx_diff = current_io[main_iface][1] - last_io[main_iface][1]
            
            last_io = current_io

            # Visualização
            rx_str = format_speed(rx_diff)
            tx_str = format_speed(tx_diff)

            # Barra de progresso visual simples
            rx_bar = "█" * min(int(rx_diff / 50000), 40) # 1 bloco por 50KB/s
            tx_bar = "█" * min(int(tx_diff / 50000), 40)

            os.system("clear")
            print(f"{C.BOLD}{C.CYAN}🚀 MONITOR DE BANDA - Interface: {C.GREEN}{main_iface}{C.END}")
            print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            print(f"{C.BOLD}DOWNLOAD:{C.END} {C.BLUE}{rx_str:<12}{C.END} {C.BLUE}{rx_bar}{C.END}")
            print(f"{C.BOLD}UPLOAD:  {C.END} {C.YELLOW}{tx_str:<12}{C.END} {C.YELLOW}{tx_bar}{C.END}")
            print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            
            # Tenta listar processos do Enum-Allma rodando (apenas para info)
            try:
                pids = os.popen("pgrep -f 'python3 menu.py|naabu|katana|subfinder'").read().strip().split()
                if pids:
                    print(f"\n{C.GREEN}✔ {len(pids)} processos do Enum-Allma detectados ativos.{C.END}")
                else:
                    print(f"\n{C.GRAY}○ Aguardando execução do Enum-Allma...{C.END}")
            except:
                pass

    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}Monitor finalizado.{C.END}")

if __name__ == "__main__":
    main()
