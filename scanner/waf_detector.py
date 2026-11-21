"""WAF detection via benign vs suspicious request comparison."""
from __future__ import annotations

# local
from scanner.http_client import get_session, safe_get
from scanner.utils import ScanContext, save_result, save_json

MODULE_NAME = "WAF DETECTOR"

# (name, vendor, header substrings, cookie substrings, body substrings)
WAF_SIGNATURES: list[dict] = [
    {"name": "Cloudflare", "vendor": "Cloudflare",
     "headers": ["cf-ray", "cf-cache-status", "server: cloudflare"],
     "cookies": ["__cfduid", "__cf_bm"],
     "body": ["cloudflare", "attention required! | cloudflare"]},
    {"name": "Akamai", "vendor": "Akamai",
     "headers": ["server: akamaighost", "x-akamai-transformed"],
     "cookies": ["akamai_"], "body": ["akamai"]},
    {"name": "AWS WAF / CloudFront", "vendor": "Amazon",
     "headers": ["x-amz-cf-id", "x-cache:"],
     "cookies": ["awsalb", "awselb"],
     "body": ["aws", "cloudfront"]},
    {"name": "Sucuri", "vendor": "Sucuri",
     "headers": ["x-sucuri-id", "server: sucuri"],
     "cookies": ["sucuri_cloudproxy_uuid"],
     "body": ["sucuri"]},
    {"name": "Imperva / Incapsula", "vendor": "Imperva",
     "headers": ["x-iinfo", "x-cdn: incapsula"],
     "cookies": ["incap_ses", "visid_incap"],
     "body": ["incapsula"]},
    {"name": "F5 BIG-IP ASM", "vendor": "F5",
     "headers": ["x-wa-info", "server: bigip", "ts="],
     "cookies": ["ts", "f5hc"],
     "body": ["bigip", "the requested url was rejected"]},
    {"name": "Barracuda", "vendor": "Barracuda",
     "headers": ["server: barracudastorage"],
     "cookies": ["barra_counter_session"],
     "body": ["barracuda"]},
    {"name": "ModSecurity", "vendor": "OWASP",
     "headers": ["server: mod_security", "x-mod-security"],
     "cookies": [],
     "body": ["mod_security", "not acceptable", "406"]},
    {"name": "Wordfence", "vendor": "Defiant",
     "headers": [],
     "cookies": ["wordfence_verifiedHuman"],
     "body": ["wordfence"]},
    {"name": "Fastly", "vendor": "Fastly",
     "headers": ["x-served-by: cache-", "x-fastly-request-id"],
     "cookies": [], "body": ["fastly"]},
    {"name": "Vercel", "vendor": "Vercel",
     "headers": ["x-vercel-id", "server: vercel"],
     "cookies": [], "body": ["vercel"]},
    {"name": "Netlify", "vendor": "Netlify",
     "headers": ["x-nf-request-id"],
     "cookies": [], "body": ["netlify"]},
    {"name": "StackPath", "vendor": "StackPath",
     "headers": ["x-stackpath-id"],
     "cookies": ["sp-"], "body": ["stackpath"]},
    {"name": "Azure Front Door", "vendor": "Microsoft",
     "headers": ["x-azure-ref", "x-forwarded-for"],
     "cookies": [], "body": ["azure"]},
    {"name": "FortiWeb", "vendor": "Fortinet",
     "headers": ["server: fortisweb", "x-dot-defensive"],
     "cookies": ["fwb_"], "body": ["fortiweb"]},
    {"name": "Radware", "vendor": "Radware",
     "headers": ["x-sl-ip", "server: radware"],
     "cookies": [], "body": ["radware"]},
    {"name": "Wallarm", "vendor": "Wallarm",
     "headers": ["wallarm"],
     "cookies": [], "body": ["wallarm"]},
]

SUSPICIOUS_PAYLOAD = "?x=../../etc/passwd"


def _failed(code: str, msg: str) -> dict:
    return {"module": MODULE_NAME, "status": "failed",
            "data": {}, "saved_to": None, "error": f"{code}: {msg}"}


def _match_signatures(headers: dict, body: str, cookies: str) -> list[dict]:
    """Match WAF signatures against response evidence."""
    header_blob = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    body_l = body.lower()
    cookies_l = cookies.lower()
    matches = []
    for sig in WAF_SIGNATURES:
        evidence: list[str] = []
        for h in sig["headers"]:
            if h.lower() in header_blob:
                evidence.append(f"header: {h}")
        for c in sig["cookies"]:
            if c in cookies_l:
                evidence.append(f"cookie: {c}")
        for b in sig["body"]:
            if b in body_l:
                evidence.append(f"body: {b}")
        if evidence:
            if len(evidence) >= 2:
                confidence = "high"
            else:
                confidence = "medium"
            matches.append({"name": sig["name"], "vendor": sig["vendor"],
                            "evidence": evidence, "confidence": confidence})
    return matches


def run(ctx: ScanContext) -> dict:
    """Run WAF detector."""
    ctx.console.rule(f"[magenta]{MODULE_NAME}[/magenta]")
    session = ctx.session if ctx.session else get_session(ctx.args)

    benign = safe_get(session, ctx.url, timeout=ctx.args.timeout,
                      allow_redirects=True)
    if benign is None:
        ctx.console.print("[red]  ✗ HTTP error: benign request failed[/red]")
        return _failed("http_error", "benign request failed")

    suspect = safe_get(session, ctx.url.rstrip("/") + SUSPICIOUS_PAYLOAD,
                       timeout=ctx.args.timeout, allow_redirects=True)

    cookies = str(benign.headers.get("Set-Cookie", ""))
    headers = dict(benign.headers)
    body = benign.text[:200000] if "text" in benign.headers.get(
        "Content-Type", "") else ""
    blocked = False
    if suspect is not None:
        cookies += str(suspect.headers.get("Set-Cookie", ""))
        headers.update(dict(suspect.headers))
        if "text" in suspect.headers.get("Content-Type", ""):
            body += suspect.text[:200000]
        # Big status delta or a block page on the payload is WAF evidence.
        if (suspect.status_code in (403, 406, 429, 501, 999)
                or abs(suspect.status_code - benign.status_code) >= 3):
            blocked = True

    matches = _match_signatures(headers, body, cookies)
    if blocked and not matches:
        matches.append({"name": "Unknown WAF", "vendor": "unknown",
                        "evidence": ["behavioral: suspicious payload got a "
                                     "different/blocked response"],
                        "confidence": "low"})

    data = {
        "benign_status": benign.status_code,
        "suspect_status": suspect.status_code if suspect else None,
        "blocked": blocked,
        "detected": matches,
    }

    if matches:
        lines = ["Detected WAF:"]
        for m in matches:
            lines.append(f"  Name      : {m['name']}")
            lines.append(f"  Vendor    : {m['vendor']}")
            lines.append(f"  Confidence: {m['confidence']}")
            lines.append("  Evidence  : " + "; ".join(m["evidence"]))
    else:
        lines = ["No WAF signatures matched.", f"Benign status: {benign.status_code}",
                 f"Suspect status: {suspect.status_code if suspect else 'n/a'}"]

    for m in matches:
        ctx.console.print(f"  [cyan]•[/cyan] {m['name']} ({m['confidence']})")

    try:
        path = save_result(ctx, "waf", "\n".join(lines))
    except Exception as exc:
        ctx.console.print(f"[red]  ✗ Save failed: {exc}[/red]")
        return {"module": MODULE_NAME, "status": "partial",
                "data": data, "saved_to": None, "error": f"save_error: {exc}"}

    save_json(ctx, "waf", data)
    status = "ok" if matches else "partial"
    ctx.console.print(f"  ✓ Saved → {path}")
    return {"module": MODULE_NAME, "status": status, "data": data,
            "saved_to": str(path), "error": None}
