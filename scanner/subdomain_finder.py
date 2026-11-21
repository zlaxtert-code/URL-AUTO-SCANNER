"""Passive subdomain enumeration via crt.sh + HackerTarget."""
from __future__ import annotations

# stdlib
import random
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# third-party
import requests
import dns.resolver

# local
from scanner.http_client import get_session, safe_get
from scanner.utils import ScanContext, save_result, save_json

MODULE_NAME = "SUBDOMAIN FINDER"

MAX_THREADS = 300
# crt.sh is frequently slow; give the JSON API a floor above the user timeout.
CRTSH_TIMEOUT_FLOOR = 20.0


def _failed(code: str, msg: str) -> dict:
    return {"module": MODULE_NAME, "status": "failed",
            "data": {}, "saved_to": None, "error": f"{code}: {msg}"}


def _from_crt_sh(session: requests.Session, root_domain: str, timeout: float) -> set[str]:
    """Fetch subdomains from the crt.sh JSON API (retries once on 5xx/timeout)."""
    url = f"https://crt.sh/?q=%25.{root_domain}&output=json"
    eff_timeout = max(timeout, CRTSH_TIMEOUT_FLOOR)
    for attempt in range(2):  # Retry once with 1s backoff.
        resp = safe_get(session, url, timeout=eff_timeout)
        if resp is not None and resp.status_code == 200:
            try:
                subs: set[str] = set()
                for entry in resp.json():
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith("." + root_domain):
                            subs.add(name)
                return subs
            except ValueError:
                return set()
        if attempt == 0:
            time.sleep(1.0)
    return set()


def _from_hackertarget(session: requests.Session, root_domain: str, timeout: float) -> set[str]:
    """Fetch subdomains from the HackerTarget hostsearch API."""
    url = f"https://api.hackertarget.com/hostsearch/?q={root_domain}"
    resp = safe_get(session, url, timeout=timeout)
    if resp is None or resp.status_code != 200:
        return set()
    subs: set[str] = set()
    for line in resp.text.splitlines():
        name = line.split(",")[0].strip().lower()
        if name.endswith("." + root_domain):
            subs.add(name)
    return subs


def _resolve_subdomain(resolver: dns.resolver.Resolver, name: str) -> dict:
    """Resolve A and CNAME records for one subdomain."""
    result = {"subdomain": name, "ips": [], "cname": "", "resolved": False}
    try:
        try:
            answer = resolver.resolve(name, "CNAME")
            result["cname"] = str(answer[0].target).rstrip(".")
        except Exception:
            pass
        answer = resolver.resolve(name, "A")
        result["ips"] = [rdata.address for rdata in answer]
        result["resolved"] = True
    except Exception:
        pass
    # worker thread so parallelism is preserved.
    time.sleep(random.uniform(0.1, 0.3))
    return result


def run(ctx: ScanContext) -> dict:
    """Run subdomain finder."""
    ctx.console.rule(f"[magenta]{MODULE_NAME}[/magenta]")
    session = ctx.session if ctx.session else get_session(ctx.args)

    sources_ok = 0
    sources_failed = []

    try:
        crt_subs = _from_crt_sh(session, ctx.root_domain, ctx.args.timeout)
        if crt_subs:
            sources_ok += 1
        else:
            sources_failed.append("crt.sh")
    except Exception as exc:
        crt_subs = set()
        sources_failed.append(f"crt.sh ({exc})")

    try:
        ht_subs = _from_hackertarget(session, ctx.root_domain, ctx.args.timeout)
        if ht_subs:
            sources_ok += 1
        else:
            sources_failed.append("hackertarget")
    except Exception as exc:
        ht_subs = set()
        sources_failed.append(f"hackertarget ({exc})")

    all_subs = sorted(crt_subs | ht_subs)
    if not all_subs:
        ctx.console.print("[red]  ✗ No subdomains from any source[/red]")
        return _failed("no_results", f"sources failed: {sources_failed or 'empty'}")

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0
    threads = min(ctx.args.threads, MAX_THREADS)
    validated: list[dict] = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(_resolve_subdomain, resolver, name)
                   for name in all_subs]
        for future in as_completed(futures):
            res = future.result()
            if res["resolved"]:
                validated.append(res)

    validated.sort(key=lambda r: r["subdomain"])

    data = {
        "total_found": len(all_subs),
        "total_resolved": len(validated),
        "sources_failed": sources_failed,
        "subdomains": all_subs,
        "resolved": validated,
    }

    lines = [f"Found {len(all_subs)} unique subdomains "
             f"({len(validated)} resolve)."]
    if sources_failed:
        lines.append("Failed/empty sources: " + ", ".join(sources_failed))
    lines.append("")
    for res in validated:
        line = f"  {res['subdomain']:<40} {', '.join(res['ips'])}"
        if res["cname"]:
            line += f"  (CNAME: {res['cname']})"
        lines.append(line)

    for res in validated[:10]:
        ctx.console.print(f"  [cyan]•[/cyan] {res['subdomain']} -> "
                          f"{', '.join(res['ips'])}")

    try:
        path = save_result(ctx, "subdomain", "\n".join(lines))
    except Exception as exc:
        ctx.console.print(f"[red]  ✗ Save failed: {exc}[/red]")
        return {"module": MODULE_NAME, "status": "partial",
                "data": data, "saved_to": None, "error": f"save_error: {exc}"}

    save_json(ctx, "subdomain", data)
    status = "ok" if sources_ok == 2 else "partial"
    ctx.console.print(f"  ✓ Saved → {path}")
    return {"module": MODULE_NAME, "status": status, "data": data,
            "saved_to": str(path), "error": None}
