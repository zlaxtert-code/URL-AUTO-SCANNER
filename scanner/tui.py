"""Shared TUI helpers: console theme, result table, status printing."""
from __future__ import annotations

from rich.console import Console, Theme
from rich.table import Table

THEME = Theme({
    "info": "cyan",
    "ok": "green",
    "warn": "yellow",
    "bad": "red",
    "module": "magenta",
    "dim": "dim",
})

STATUS_STYLE = {"ok": "[ok]", "partial": "[warn]", "failed": "[bad]"}


def make_console(no_color: bool = False) -> Console:
    """Create the shared Rich console with the project theme."""
    return Console(theme=THEME, no_color=no_color, highlight=False)


def print_module_start(console: Console, name: str) -> None:
    """Print a module start rule."""
    console.rule(f"[module]{name}[/module]")


def print_result(console: Console, name: str, result: dict) -> None:
    """Print the final status line for a module result."""
    style = STATUS_STYLE.get(result.get("status", "failed"), "[bad]")
    console.print(f"{style}[{result.get('status', 'failed').upper()}][/]"
                  f" [module]{name}[/module]"
                  f" -> {result.get('saved_to') or result.get('error') or ''}")


def kv_table(title: str, rows: list[tuple[str, str]]) -> Table:
    """Build a two-column key/value table."""
    table = Table(title=title, show_header=False)
    table.add_column(style="cyan", no_wrap=True)
    table.add_column()
    for key, value in rows:
        table.add_row(key, value)
    return table
