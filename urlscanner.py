"""URL AUTO SCANNER — entrypoint, argparse CLI and interactive TUI."""
from __future__ import annotations

# stdlib
import argparse
import sys

# Windows legacy consoles default to cp1252; force UTF-8 for the banner.
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

# third-party
from rich.console import Console

# local
import scanner.banner as banner
import scanner.cms_checker
import scanner.dns_records
import scanner.header_checker
import scanner.http_client
import scanner.ip_checker
import scanner.port_scanner
import scanner.reverse_ip
import scanner.ssl_check
import scanner.subdomain_finder
import scanner.waf_detector
import scanner.tui
from scanner.utils import build_context

VERSION = "1.0.0"

PIPELINE = [
    ("ssl", scanner.ssl_check),
    ("header", scanner.header_checker),
    ("cms", scanner.cms_checker),
    ("waf", scanner.waf_detector),
    ("subdomain", scanner.subdomain_finder),
    ("dns", scanner.dns_records),
    ("ip", scanner.ip_checker),
    ("port", scanner.port_scanner),
    ("reverse_ip", scanner.reverse_ip),
]


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    
    parser = argparse.ArgumentParser(
        prog="urlscanner",
        description="URL AUTO SCANNER - modular URL reconnaissance tool",
        epilog="Run with no arguments for interactive TUI mode.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--url", type=str, default=None,
                        help="Target URL or domain")
    parser.add_argument("--threads", type=int, default=100,
                        help="Port scan + subdomain validation threads (max 300)")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="Per-request timeout (seconds)")
    parser.add_argument("--ports", type=str, default=None,
                        help="Comma list or range (e.g. 80,443,8000-8100)")
    parser.add_argument("--output-dir", type=str, default="result",
                        help="Output folder")
    parser.add_argument("--only", type=str, default=None,
                        help="Comma list of modules to run (e.g. dns,port)")
    parser.add_argument("--skip", type=str, default=None,
                        help="Comma list of modules to skip")
    parser.add_argument("--passive-reverse", action="store_true", default=False,
                        help="Enable HackerTarget reverse IP")
    parser.add_argument("--no-color", action="store_true", default=False,
                        help="Disable Rich colors")
    parser.add_argument("--json", action="store_true", default=False,
                        help="Also write <module>_<host>.json files")
    parser.add_argument("--interactive", action="store_true", default=False,
                        help="Launch interactive TUI mode")
    parser.add_argument("--verbose", action="store_true", default=False,
                        help="Log to result/debug_<hostname>.log")
    parser.add_argument("--version", action="version",
                        version=f"URL AUTO SCANNER v{VERSION}")
    return parser


def _selected_modules(args: argparse.Namespace) -> list[tuple[str, object]]:
    """Apply --only / --skip filtering to the pipeline."""
    only = [s.strip().lower() for s in (args.only or "").split(",") if s.strip()] or None
    skip = {s.strip().lower() for s in (args.skip or "").split(",") if s.strip()}
    return [(slug, mod) for slug, mod in PIPELINE
            if (only is None or slug in only) and slug not in skip]


def run_pipeline(url: str, args: argparse.Namespace) -> list[dict]:
    """Execute the full (filtered) pipeline for one target."""
    console: Console = args.console
    ctx = build_context(url, args)
    ctx.console = console
    ctx.session = scanner.http_client.get_session(args)
    console.print(f"[info]Target: {ctx.hostname} "
                  f"(root: {ctx.root_domain})[/info]\n")

    results: list[dict] = []
    for slug, mod in _selected_modules(args):
        try:
            result = mod.run(ctx)
        except KeyboardInterrupt:
            console.print(f"[bad][FAILED][/bad] {mod.MODULE_NAME} "
                          "(cancelled)")
            continue
        except Exception as exc:
            console.print(f"[bad][FAILED][/bad] {mod.MODULE_NAME}: {exc}")
            result = {"module": mod.MODULE_NAME, "status": "failed",
                      "data": {}, "saved_to": None, "error": str(exc)}
        scanner.tui.print_result(console, mod.MODULE_NAME, result)
        results.append(result)
        console.print()

    return results


def interactive(args: argparse.Namespace) -> None:
    """Run the interactive TUI menu loop."""
    console: Console = args.console
    last_results: list[dict] = []
    while True:
        console.print("[module]MAIN MENU[/module]")
        console.print("  [1] Start a new scan")
        console.print("  [2] Configure options")
        console.print("  [3] View last results")
        console.print("  [4] Exit")
        choice = input("  > ").strip()
        if choice == "1":
            url = input(" [+] Enter URL or domain > ").strip()
            if not url:
                console.print("[bad]Empty input[/bad]")
                continue
            try:
                last_results = run_pipeline(url, args)
                console.print("[ok][DONE][/ok]")
            except KeyboardInterrupt:
                console.print("\n[warn]Scan cancelled; partial results kept[/warn]")
        elif choice == "2":
            console.print(f"  threads={args.threads} timeout={args.timeout} "
                          f"ports={args.ports} output-dir={args.output_dir} "
                          f"json={args.json}")
            key = input("Option to set (threads/timeout/ports/output-dir/json): ").strip()
            if key == "threads":
                args.threads = int(input("Value: "))
            elif key == "timeout":
                args.timeout = float(input("Value: "))
            elif key == "ports":
                args.ports = input("Value: ") or None
            elif key == "output-dir":
                args.output_dir = input("Value: ")
            elif key == "json":
                args.json = not args.json
        elif choice == "3":
            if not last_results:
                console.print("[warn]No results yet[/warn]")
            for r in last_results:
                scanner.tui.print_result(console, r.get("module", "?"), r)
        elif choice == "4":
            return
        else:
            console.print("[bad]Invalid choice[/bad]")


def main(argv: list[str] | None = None) -> int:
    """Program entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)
    args.console = scanner.tui.make_console(args.no_color)
    console: Console = args.console

    banner.print_banner(console)

    if args.url:
        try:
            run_pipeline(args.url, args)
            console.print("[ok][DONE][/ok]")
        except KeyboardInterrupt:
            console.print("\n[warn]Cancelled; saved files remain intact[/warn]")
        return 0

    if args.interactive or not sys.argv[1:] or argv == []:
        interactive(args)
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
