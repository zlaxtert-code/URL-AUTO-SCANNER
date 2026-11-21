"""Threaded TCP port scanner with banner grab."""
from __future__ import annotations

# stdlib
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# local
from scanner.utils import (ScanContext, load_top_ports, parse_port_spec,
                           save_result, save_json)

MODULE_NAME = "PORT SCANNER"

MAX_THREADS = 300

SERVICE_HINTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "Submission", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-proxy", 8443: "HTTPS-alt", 27017: "MongoDB",
}


def _failed(code: str, msg: str) -> dict:
    return {"module": MODULE_NAME, "status": "failed",
            "data": {}, "saved_to": None, "error": f"{code}: {msg}"}


def _scan_port(ip: str, port: int, timeout: float) -> dict:
    """Connect-scan a single TCP port and grab a banner."""
    result = {"port": port, "state": "filtered", "service": SERVICE_HINTS.get(port, ""),
              "banner": ""}
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            result["state"] = "open"
            sock.settimeout(0.2)
            try:
                banner = sock.recv(1024)
                if banner:
                    result["banner"] = banner.decode("utf-8", "replace")[:200]
            except (socket.timeout, OSError):
                pass
    except ConnectionRefusedError:
        result["state"] = "closed"
    except (socket.timeout, TimeoutError):
        result["state"] = "filtered"
    except OSError:
        result["state"] = "filtered"
    return result


def run(ctx: ScanContext) -> dict:
    """Run threaded port scan against the resolved IP."""
    ctx.console.rule(f"[magenta]{MODULE_NAME}[/magenta]")
    if not ctx.ip:
        ctx.console.print("[red]  ✗ no IP resolved[/red]")
        return _failed("no_ip", "no IP resolved")

    try:
        ports = (parse_port_spec(ctx.args.ports) if ctx.args.ports
                 else load_top_ports())
    except ValueError as exc:
        ctx.console.print(f"[red]  ✗ bad --ports: {exc}[/red]")
        return _failed("bad_ports", str(exc))

    threads = min(ctx.args.threads, MAX_THREADS)
    timeout = ctx.args.timeout

    results: list[dict] = []
    open_ports: list[dict] = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_scan_port, ctx.ip, p, timeout): p
                   for p in ports}
        for future in as_completed(futures):
            res = future.result()
            results.append(res)
            if res["state"] == "open":
                open_ports.append(res)

    results.sort(key=lambda r: r["port"])
    open_ports.sort(key=lambda r: r["port"])

    lines = [f"Target IP : {ctx.ip}",
             f"Ports scanned : {len(ports)}",
             f"Open ports : {len(open_ports)}",
             ""]
    lines.append("OPEN PORTS:")
    if open_ports:
        for r in open_ports:
            line = (f"  {r['port']:<6} {r['service'] or 'unknown':<12}"
                    f" {r['banner']}")
            lines.append(line.rstrip())
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append(f"Closed/filtered: "
                 f"{sum(1 for r in results if r['state'] != 'open')} ports")

    for r in open_ports:
        ctx.console.print(f"  [cyan]•[/cyan] {r['port']}/tcp "
                          f"{r['service'] or 'unknown'} {r['banner'][:60]}")

    data = {"ip": ctx.ip, "ports_scanned": len(ports),
            "open": open_ports, "results": results}

    try:
        path = save_result(ctx, "port", "\n".join(lines))
    except Exception as exc:
        ctx.console.print(f"[red]  ✗ Save failed: {exc}[/red]")
        return {"module": MODULE_NAME, "status": "partial",
                "data": data, "saved_to": None, "error": f"save_error: {exc}"}

    save_json(ctx, "port", data)
    ctx.console.print(f"  ✓ Saved → {path}")
    return {"module": MODULE_NAME, "status": "ok", "data": data,
            "saved_to": str(path), "error": None}
