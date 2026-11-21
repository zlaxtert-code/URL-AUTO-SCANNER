"""Domain→IP resolution + IP geolocation via ip-api.com."""
from __future__ import annotations

# stdlib
import time

# local
from scanner.http_client import get_session, safe_get
from scanner.utils import ScanContext, save_result, save_json

MODULE_NAME = "IP CHECKER"

IP_API_FIELDS = ("status,country,countryCode,region,regionName,city,isp,"
                 "org,as,timezone,lat,lon,reverse")


def _failed(code: str, msg: str) -> dict:
    return {"module": MODULE_NAME, "status": "failed",
            "data": {}, "saved_to": None, "error": f"{code}: {msg}"}


def _geo_lookup(session, ip: str, timeout: float) -> dict | None:
    """Look up IP info on ip-api.com (free, no key)."""
    
    resp = safe_get(session, f"http://ip-api.com/json/{ip}?fields={IP_API_FIELDS}",
                    timeout=timeout)
    if resp is None or resp.status_code != 200:
        return None
    try:
        payload = resp.json()
    except ValueError:
        return None
    return payload if payload.get("status") == "success" else None


def run(ctx: ScanContext) -> dict:
    """Run domain-to-IP resolution and IP geolocation."""
    
    ctx.console.rule(f"[magenta]{MODULE_NAME}[/magenta]")
    session = ctx.session if ctx.session else get_session(ctx.args)

    if not ctx.ips:
        ctx.console.print("[red]  ✗ No A records available[/red]")
        return _failed("no_ip", "no A records resolved")

    ip = ctx.ip or ctx.ips[0]
    lines = ["Domain -> IP", f"  Primary IP : {ip}",
             f"  All A records : {', '.join(ctx.ips)}"]
    if ctx.aaaas:
        lines.append(f"  AAAA records  : {', '.join(ctx.aaaas)}")

    geo = _geo_lookup(session, ip, ctx.args.timeout)
    geo_list = []
    if geo is None:
        # Retry once with 1s backoff.
        time.sleep(1.0)
        geo = _geo_lookup(session, ip, ctx.args.timeout)
    if geo:
        # ip-api.com rate limit: 45 req/min -> sleep 1.5s per call.
        time.sleep(1.5)
        lines.append("")
        lines.append("IP Info (ip-api.com)")
        for key in ("country", "regionName", "city", "isp", "org", "as",
                    "timezone", "lat", "lon", "reverse"):
            value = geo.get(key, "")
            if value:
                lines.append(f"  {key:<10} : {value}")
        geo_list.append(geo)
    else:
        lines.append("")
        lines.append("IP Info (ip-api.com): lookup failed")

    data = {"primary_ip": ip, "ips": ctx.ips, "aaaas": ctx.aaaas,
            "geo": geo_list}

    for key in ("country", "regionName", "city", "isp", "as"):
        if geo and geo.get(key):
            ctx.console.print(f"  [cyan]{key:<10}[/cyan] {geo[key]}")

    try:
        path = save_result(ctx, "ip", "\n".join(lines))
    except Exception as exc:
        ctx.console.print(f"[red]  ✗ Save failed: {exc}[/red]")
        return {"module": MODULE_NAME, "status": "partial",
                "data": data, "saved_to": None, "error": f"save_error: {exc}"}

    save_json(ctx, "ip", data)
    status = "ok" if geo else "partial"
    ctx.console.print(f"  ✓ Saved → {path}")
    return {"module": MODULE_NAME, "status": status, "data": data,
            "saved_to": str(path), "error": None}
