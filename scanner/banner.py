"""ASCII banner URL AUTO SCANNER."""
from __future__ import annotations

from rich.console import Console

VERSION = "1.0.0"

BANNER = r"""
 ██╗   ██╗██████╗ ██╗         █████╗ ██╗   ██╗████████╗ ██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
 ██║   ██║██╔══██╗██║        ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
 ██║   ██║██████╔╝██║        ███████║██║   ██║   ██║   ██║   ██║    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
 ██║   ██║██╔══██╗██║        ██╔══██║██║   ██║   ██║   ██║   ██║    ╚════██║██║     ██╔══██║██╚ ██╗██║██ ╚██╗██║██╔══╝  ██╔══██╗
 ╚██████╔╝██║  ██║███████╗   ██║  ██║╚██████╔╝   ██║   ╚██████╔╝    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
  ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
"""

CREDITS = (
    f"                     [bold white]VERSION: {VERSION}[/bold white]   "
    "[bold cyan]AUTHOR : ZLAXTERT[/bold cyan]   "
    "[bold magenta]TEAM   : DARKXCODE[/bold magenta]   "
    "[bold white]TG     : https://t.me/zlaxtert[/bold white]"
)


def print_banner(console: Console) -> None:
    """Print the banner and credits block."""
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    console.print(CREDITS)
    console.print()
