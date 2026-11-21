"""DNS record scan with resolver fallback."""
from __future__ import annotations

# third-party
import dns.resolver

# local
from scanner.utils import ScanContext, save_result, save_json

MODULE_NAME = "DNS RECORDS"

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]
RESOLVER_IPS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


def _failed(code: str, msg: str) -> dict:
    return {"module": MODULE_NAME, "status": "failed",
            "data": {}, "saved_to": None, "error": f"{code}: {msg}"}


def _get_resolver() -> dns.resolver.Resolver:
    """Build a resolver chain: system first, then public fallbacks."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    return resolver


def _resolve_with_fallback(domain: str, rtype: str) -> list[dict]:
    """Resolve one record type, trying system then public resolvers."""
    attempts: list[dns.resolver.Resolver] = []
    system = _get_resolver()
    attempts.append(system)
    for ip in RESOLVER_IPS:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [ip]
        r.lifetime = 5.0
        attempts.append(r)

    for resolver in attempts:
        try:
            answer = resolver.resolve(domain, rtype)
            ttl = answer.rrset.ttl
            return [{"value": str(rdata), "ttl": ttl} for rdata in answer]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
        except Exception:
            continue
    return []


def resolve_ips(ctx: ScanContext, domain: str) -> tuple[list[str], list[str]]:
    """Resolve A and AAAA records for the domain."""
    
    ipv4 = [r["value"] for r in _resolve_with_fallback(domain, "A")]
    ipv6 = [r["value"] for r in _resolve_with_fallback(domain, "AAAA")]
    return ipv4, ipv6


def run(ctx: ScanContext) -> dict:
    """Run DNS record scan on root_domain and populate ctx.ip/ips/aaaas."""
    
    
    ctx.console.rule(f"[magenta]{MODULE_NAME}[/magenta]")
    domain = ctx.root_domain

    records: dict[str, list[dict]] = {}
    lines: list[str] = []
    for rtype in RECORD_TYPES:
        results = _resolve_with_fallback(domain, rtype)
        records[rtype] = results
        if results:
            lines.append(f"{rtype} records:")
            lines += [f"  {r['value']}  (TTL {r['ttl']})" for r in results]
        else:
            lines.append(f"{rtype} records: (none)")

    # Populate context for downstream modules.
    ipv4 = [r["value"] for r in records["A"]]
    ipv6 = [r["value"] for r in records["AAAA"]]
    ctx.ips = ipv4
    ctx.aaaas = ipv6
    ctx.ip = ipv4[0] if ipv4 else None

    data = {"domain": domain, "records": records}
    for rtype in RECORD_TYPES:
        if records[rtype]:
            ctx.console.print(f"  [cyan]{rtype:<6}[/cyan] "
                              f"{records[rtype][0]['value']}"
                              + (f" (+{len(records[rtype]) - 1} more)"
                                 if len(records[rtype]) > 1 else ""))

    if not ipv4 and not records.get("NS"):
        ctx.console.print("[red]  ✗ DNS resolution failed[/red]")
        return _failed("dns_error", f"no records for {domain}")

    try:
        path = save_result(ctx, "dns", "\n".join(lines))
    except Exception as exc:
        ctx.console.print(f"[red]  ✗ Save failed: {exc}[/red]")
        return {"module": MODULE_NAME, "status": "partial",
                "data": data, "saved_to": None, "error": f"save_error: {exc}"}

    save_json(ctx, "dns", data)
    status = "ok" if ipv4 else "partial"
    ctx.console.print(f"  ✓ Saved → {path}")
    return {"module": MODULE_NAME, "status": status, "data": data,
            "saved_to": str(path), "error": None}
