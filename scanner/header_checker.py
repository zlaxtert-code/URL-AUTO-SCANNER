"""Response header retrieval and security header audit."""
from __future__ import annotations

# local
from scanner.http_client import get_session, safe_get
from scanner.utils import ScanContext, save_result, save_json

MODULE_NAME = "HEADER CHECKER"

SECURITY_HEADERS: list[str] = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
]


def _failed(code: str, msg: str) -> dict:
    return {"module": MODULE_NAME, "status": "failed",
            "data": {}, "saved_to": None, "error": f"{code}: {msg}"}


def _audit_security_headers(headers) -> list[dict]:
    """Check presence of each recommended security header."""
    lower = {k.lower(): v for k, v in headers.items()}
    out = []
    for h in SECURITY_HEADERS:
        present = h.lower() in lower
        out.append({"header": h, "present": present,
                    "value": lower.get(h.lower(), "")})
    return out


def _audit_cookies(headers) -> list[dict]:
    """Flag cookies missing Secure/HttpOnly/SameSite."""
    cookies = headers.get("Set-Cookie", "")
    if isinstance(cookies, (list, tuple)):
        cookies = "; ".join(cookies)
    results = []
    for part in cookies.split(","):
        name = part.split("=")[0].strip()
        if not name:
            continue
        rest = part.lower()
        results.append({
            "cookie": name,
            "secure": "secure" in rest,
            "httponly": "httponly" in rest,
            "samesite": "samesite" in rest,
        })
    return results


def run(ctx: ScanContext) -> dict:
    """Run header checker."""
    ctx.console.rule(f"[magenta]{MODULE_NAME}[/magenta]")
    session = ctx.session if ctx.session else get_session(ctx.args)

    resp = safe_get(session, ctx.url, timeout=ctx.args.timeout,
                    allow_redirects=True)
    if resp is None:
        ctx.console.print("[red]  ✗ HTTP error: request failed[/red]")
        return _failed("http_error", "request failed")

    headers = resp.headers
    security = _audit_security_headers(headers)
    cookies = _audit_cookies(headers)

    data = {
        "status_code": resp.status_code,
        "final_url": resp.url,
        "server": headers.get("Server", ""),
        "powered_by": headers.get("X-Powered-By", ""),
        "headers": dict(headers),
        "security_headers": security,
        "cookies": cookies,
    }

    ctx.console.print(f"  {resp.status_code} {resp.url}")

    lines = [f"Status Code  : {resp.status_code}",
             f"Final URL    : {resp.url}",
             "Response Headers:"]
    lines += [f"  {k}: {v}" for k, v in headers.items()]
    lines.append("Security Headers:")
    lines += [f"  {s['header']:<35} {'present' if s['present'] else 'MISSING'}"
              for s in security]
    lines.append("Cookies:")
    lines += [f"  {c['cookie']} (Secure={c['secure']}, "
              f"HttpOnly={c['httponly']}, SameSite={c['samesite']})"
              for c in cookies] or ["  (none)"]

    try:
        path = save_result(ctx, "header", "\n".join(lines))
    except Exception as exc:
        ctx.console.print(f"[red]  ✗ Save failed: {exc}[/red]")
        return {"module": MODULE_NAME, "status": "partial",
                "data": data, "saved_to": None, "error": f"save_error: {exc}"}

    save_json(ctx, "header", data)
    ctx.console.print(f"  ✓ Saved → {path}")
    return {"module": MODULE_NAME, "status": "ok", "data": data,
            "saved_to": str(path), "error": None}
