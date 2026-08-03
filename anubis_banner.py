#!/usr/bin/env python3
# anubis_banner.py - ANUBIS Banner

from colorama import init, Fore, Style
init(autoreset=True)

def print_banner():
    banner = f"""
{Fore.YELLOW}{Style.BRIGHT}
    █████╗ ███╗   ██╗██╗   ██╗██████╗ ██╗███████╗
   ██╔══██╗████╗  ██║██║   ██║██╔══██╗██║██╔════╝
   ███████║██╔██╗ ██║██║   ██║██████╔╝██║███████╗
   ██╔══██║██║╚██╗██║██║   ██║██╔══██╗██║╚════██║
   ██║  ██║██║ ╚████║╚██████╔╝██████╔╝██║███████║
   ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═╝╚══════╝
{Fore.CYAN}
        ☥  SHADOW SCANNING. ABSOLUTE PRECISION.  ⚡
{Fore.YELLOW}
        🏛️  ANUBIS RECON ENGINE v1.0  🏛️
{Fore.MAGENTA}
        ⚡  Crafted by: Obito Uchiha [ h4ck3r ]  |  ANUBIS Protocol  ⚡
{Fore.RESET}
"""
    print(banner)

if __name__ == "__main__":
    print_banner()
