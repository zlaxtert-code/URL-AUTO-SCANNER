"""SSL/TLS certificate check."""
from __future__ import annotations

# stdlib
import socket
import ssl
from datetime import datetime, timezone

# local
from scanner.utils import ScanContext, save_result, save_json

MODULE_NAME = "SSL CHECK"


def _failed(code: str, msg: str) -> dict:
    return {"module": MODULE_NAME, "status": "failed",
            "data": {}, "saved_to": None, "error": f"{code}: {msg}"}


def _fetch_cert(hostname: str, timeout: float) -> dict:
    """Connect and pull the peer certificate plus TLS info."""
    ctx = ssl.create_default_context()
    with socket.create_connection((hostname, 443), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
            cert = tls.getpeercert()
            cipher = tls.cipher()
            return {
                "cert": cert or {},
                "tls_version": tls.version(),
                "cipher": f"{cipher[0]} {cipher[1]}" if cipher else "",
            }


def run(ctx: ScanContext) -> dict:
    """Run SSL/TLS check."""
    ctx.console.rule(f"[magenta]{MODULE_NAME}[/magenta]")
    if ctx.scheme != "https":
        ctx.console.print("[yellow]  • Target is not HTTPS; skipping TLS check[/yellow]")
        return _failed("skipped", "target is http")

    try:
        info = _fetch_cert(ctx.hostname, ctx.args.timeout)
    except (ssl.SSLError, OSError) as exc:
        ctx.console.print(f"[red]  ✗ TLS error: {exc}[/red]")
        return _failed("tls_error", str(exc))

    cert = info["cert"]
    now = datetime.now(timezone.utc)
    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
    not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
    days_remaining = (not_after - now).days

    issuer_cn = next((v for k, v in cert.get("issuer", ()) if k == "commonName"), "")
    subject_cn = next((v for k, v in cert.get("subject", ()) if k == "commonName"), "")
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]

    data = {
        "issuer_cn": issuer_cn,
        "subject_cn": subject_cn,
        "san": sans,
        "not_before": not_before.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "not_after": not_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "days_remaining": days_remaining,
        "tls_version": info["tls_version"],
        "cipher": info["cipher"],
        "valid": days_remaining > 0,
        "expired": days_remaining <= 0,
        "self_signed": issuer_cn == subject_cn,
    }

    lines = [
        f"Issuer CN      : {issuer_cn}",
        f"Subject CN     : {subject_cn}",
        f"Valid From     : {data['not_before']}",
        f"Valid Until    : {data['not_after']}",
        f"Days Remaining : {days_remaining}",
        f"TLS Version    : {data['tls_version']}",
        f"Cipher         : {data['cipher']}",
        f"Self-Signed    : {'yes' if data['self_signed'] else 'no'}",
        "SAN Entries:",
    ]
    lines += [f"  - {san}" for san in sans] or ["  (none)"]

    for key, value in data.items():
        if key != "san":
            ctx.console.print(f"  [cyan]{key:<16}[/cyan] {value}")

    status = "ok" if data["valid"] else "partial"
    try:
        path = save_result(ctx, "ssl", "\n".join(lines))
    except Exception as exc:
        ctx.console.print(f"[red]  ✗ Save failed: {exc}[/red]")
        return {"module": MODULE_NAME, "status": "partial",
                "data": data, "saved_to": None, "error": f"save_error: {exc}"}

    save_json(ctx, "ssl", data)
    ctx.console.print(f"  ✓ Saved → {path}")
    return {"module": MODULE_NAME, "status": status, "data": data,
            "saved_to": str(path), "error": None}
