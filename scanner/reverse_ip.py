"""Reverse IP: PTR records + optional passive reverse."""
from __future__ import annotations

# third-party
import dns.resolver

# local
from scanner.http_client import get_session, safe_get
from scanner.utils import ScanContext, save_result, save_json

MODULE_NAME = "REVERSE IP"


def _failed(code: str, msg: str) -> dict:
    return {"module": MODULE_NAME, "status": "failed",
            "data": {}, "saved_to": None, "error": f"{code}: {msg}"}


def _ptr_lookup(ip: str) -> list[str]:
    """Resolve PTR records for an IP address."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    try:
        answer = resolver.resolve(dns.reversename.from_address(ip), "PTR")
        return [str(rdata).rstrip(".") for rdata in answer]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception:
        return []


def _hackertarget_reverse(session, ip: str, timeout: float) -> list[str]:
    """Passive reverse IP lookup via HackerTarget."""
    resp = safe_get(session,
                    f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                    timeout=timeout)
    if resp is None or resp.status_code != 200:
        return []
    domains = []
    for line in resp.text.splitlines():
        name = line.split(",")[0].strip().lower()
        if name and not name.startswith("error") and "." in name:
            domains.append(name)
    return domains


def run(ctx: ScanContext) -> dict:
    """Run reverse IP lookups for every A record."""
    ctx.console.rule(f"[magenta]{MODULE_NAME}[/magenta]")
    if not ctx.ips:
        ctx.console.print("[red]  ✗ No IPs to reverse[/red]")
        return _failed("no_ip", "no A records to reverse")

    session = ctx.session if ctx.session else get_session(ctx.args)
    lines: list[str] = []
    entries: list[dict] = []
    any_ptr = False

    for ip in ctx.ips:
        ptrs = _ptr_lookup(ip)
        hosted: list[str] = []
        if ctx.args.passive_reverse:
            hosted = _hackertarget_reverse(session, ip, ctx.args.timeout)
        if ptrs:
            any_ptr = True
        lines.append(f"IP: {ip}")
        lines.append(f"  PTR     : {', '.join(ptrs) if ptrs else '(none)'}")
        if ctx.args.passive_reverse:
            lines.append(f"  Hosted  : {', '.join(hosted) if hosted else '(none)'}")
        entries.append({"ip": ip, "ptr": ptrs, "hosted_domains": hosted})

    data = {"entries": entries, "passive_reverse_enabled": ctx.args.passive_reverse}

    for entry in entries:
        ctx.console.print(f"  [cyan]•[/cyan] {entry['ip']} -> "
                          f"{', '.join(entry['ptr']) or '(no PTR)'}")

    try:
        path = save_result(ctx, "reverse_ip", "\n".join(lines))
    except Exception as exc:
        ctx.console.print(f"[red]  ✗ Save failed: {exc}[/red]")
        return {"module": MODULE_NAME, "status": "partial",
                "data": data, "saved_to": None, "error": f"save_error: {exc}"}

    save_json(ctx, "reverse_ip", data)
    status = "ok" if any_ptr else "partial"
    ctx.console.print(f"  ✓ Saved → {path}")
    return {"module": MODULE_NAME, "status": status, "data": data,
            "saved_to": str(path), "error": None}
