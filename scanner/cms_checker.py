"""CMS + framework detection from HTML, headers, cookies and probes."""
from __future__ import annotations

# stdlib
import re

# third-party
from bs4 import BeautifulSoup

# local
from scanner.http_client import get_session, safe_get
from scanner.utils import ScanContext, save_result, save_json

MODULE_NAME = "CMS CHECKER"

SIGNATURES: list[dict] = [
    # --- CMS ---
    {"name": "WordPress", "kind": "cms",
     "strong": [r"/wp-content/", r"/wp-includes/"],
     "weak": [r'name=["\']generator["\'][^>]*content=["\']wordpress\s*([\d.]+)',
              r"wp-json", r"xmlrpc\.php"],
     "cookies": ["wordpress_logged_in", "wp-settings-", "wordpress_test_cookie"],
     "headers": [], "probe": "/wp-login.php"},
    {"name": "Joomla", "kind": "cms",
     "strong": [r"/components/com_", r"/media/jui/", r"/modules/mod_"],
     "weak": [r'name=["\']generator["\'][^>]*content=["\']joomla!?\s*([\d.]+)',
              r"joomla!"],
     "cookies": ["joomla_user_state", "joomla_"],
     "headers": [], "probe": "/administrator/"},
    {"name": "Drupal", "kind": "cms",
     "strong": [r"/sites/default/files/", r"drupal-settings-json",
                r"/core/assets/"],
     "weak": [r'name=["\']generator["\'][^>]*content=["\']drupal\s*([\d.]+)',
              r"drupal\.js", r"Drupal\.settings"],
     "cookies": ["drupal.visitor", "drupal_"],
     "headers": ["x-drupal-cache", "x-drupal-dynamic-cache"],
     "probe": "/user/login"},
    {"name": "Magento", "kind": "cms",
     "strong": [r"/skin/frontend/", r"/static/frontend/", r"/pub/static/frontend/"],
     "weak": [r"magento_version", r"/mage/", r"requirejs-config\.js"],
     "cookies": ["frontend", "mage-cache-sessid", "mage-messages"],
     "headers": [], "probe": None},
    {"name": "Shopify", "kind": "platform",
     "strong": [r"cdn\.shopify\.com", r"shopify\.theme", r"shopify-features"],
     "weak": [r"shopify\.analytics", r"myshopify"],
     "cookies": ["_shopify_", "shopify_pay"],
     "headers": ["x-shopid", "x-shopify-stage"],
     "probe": None},
    {"name": "Wix", "kind": "platform",
     "strong": [r"static\.wixstatic\.com", r"_wixcss"],
     "weak": [r"wix\.com", r"wixapps"],
     "cookies": [], "headers": ["x-wix-render-server", "x-wix-request-id"],
     "probe": None},
    {"name": "Ghost", "kind": "cms",
     "strong": [r"ghost-sdk", r"/ghost/api/", r"ghost\.min\.js"],
     "weak": [r'name=["\']generator["\'][^>]*content=["\']ghost\s*([\d.]+)'],
     "cookies": ["ghost-admin-api-session"],
     "headers": ["x-powered-by: ghost"], "probe": "/ghost/"},
    {"name": "PrestaShop", "kind": "cms",
     "strong": [r"/modules/[a-z0-9]+/views", r"prestashop"],
     "weak": [r"ps_shoppingcart", r"/themes/default-bootstrap/"],
     "cookies": ["prestashop-", "ps_"],
     "headers": [], "probe": None},
    {"name": "OpenCart", "kind": "cms",
     "strong": [r"index\.php\?route=common/home", r"index\.php\?route=product/"],
     "weak": [r"opencart\.min\.js", r"/catalog/view/javascript/"],
     "cookies": ["ocsessionid", "ocse8243"],
     "headers": [], "probe": None},
    {"name": "TYPO3", "kind": "cms",
     "strong": [r"/typo3temp/", r"/typo3conf/", r"typo3-login"],
     "weak": [r'name=["\']generator["\'][^>]*content=["\']typo3\s*([\d.]+)'],
     "cookies": ["fe_typo_user"],
     "headers": [], "probe": "/typo3/"},
    {"name": "Craft CMS", "kind": "cms",
     "strong": [r"craft/cms", r"/cpresources/"],
     "weak": [r"craftcms", r"craft\.js"],
     "cookies": ["craftsessionid", "craft_"],
     "headers": ["x-powered-by: craftcms"], "probe": "/admin/login"},
    {"name": "Squarespace", "kind": "platform",
     "strong": [r"static1\.squarespace\.com", r"squarespace\.com/templates"],
     "weak": [r"squarespace"],
     "cookies": [], "headers": ["x-servedby: squarespace"],
     "probe": None},
    {"name": "Blogger", "kind": "platform",
     "strong": [r"www\.blogger\.com/static", r"blogger\.com/navbar"],
     "weak": [r"blogspot", r"blogger-templates"],
     "cookies": ["blogger_sid"],
     "headers": [], "probe": None},
    {"name": "Webflow", "kind": "platform",
     "strong": [r"assets\.website-files\.com", r"webflow\.js"],
     "weak": [r"data-wf-page", r"webflow\.com"],
     "cookies": [], "headers": ["x-webflow-version"],
     "probe": None},
    {"name": "Bitrix", "kind": "cms",
     "strong": [r"/bitrix/templates/", r"/bitrix/js/"],
     "weak": [r"bitrix", r"bxcore"],
     "cookies": ["bitrix_"],
     "headers": ["x-powered-cms: bitrix site manager"],
     "probe": "/bitrix/admin/"},
    {"name": "CS-Cart", "kind": "cms",
     "strong": [r"/skins/customer", r"cs-cart\.js"],
     "weak": [r"cs-cart", r"cscart"],
     "cookies": ["cs_cookies"],
     "headers": [], "probe": None},
    {"name": "BigCommerce", "kind": "platform",
     "strong": [r"cdn\d*\.bigcommerce\.com", r"bigcommerce\.com/js"],
     "weak": [r"stencil", r"bigcommerce"],
     "cookies": ["store_key"],
     "headers": ["x-bigcommerce-"],
     "probe": None},
    {"name": "HubSpot CMS", "kind": "platform",
     "strong": [r"hs-scripts\.com", r"js\.hsforms\.net"],
     "weak": [r"hubspot", r"hs-analytics"],
     "cookies": ["__hstc", "hubspotutk"],
     "headers": [], "probe": None},
    # --- Frameworks / stacks ---
    {"name": "Laravel", "kind": "framework",
     "strong": [r"laravel_session", r"csrf-laravel-token",
                r'name="_token"'],
     "weak": [r"laravel", r"storage/framework", r"/vendor/laravel/"],
     "cookies": ["laravel_session", "xsrf-token", "remember_"],
     "headers": ["x-powered-by: laravel"],
     "probe": None},
    {"name": "Symfony", "kind": "framework",
     "strong": [r"_sf2_attributes|sf_"],
     "weak": [r"symfony", r"/bundles/sensiodistribution/"],
     "cookies": ["symfony", "phpsessid"],
     "headers": ["x-powered-by: symfony"],
     "probe": None},
    {"name": "ASP.NET", "kind": "framework",
     "strong": [r"__viewstate", r"__eventvalidation", r"webresource\.axd",
                r"scriptresource\.axd"],
     "weak": [r"asp\.net", r"aspnet_", r"\.aspx?", r"asp-session"],
     "cookies": ["asp\.net_sessionid", "aspnetsession",
                 "asp\.net_formsauth"],
     "headers": ["x-aspnet-version", "x-aspnetmvc-version",
                 "x-powered-by: asp.net"],
     "probe": None},
    {"name": "Ruby on Rails", "kind": "framework",
     "strong": [r'<meta name="csrf-param"'],
     "weak": [r"turbolinks", r"ruby on rails",
              r"/assets/application-[a-f0-9]{20,}\.js"],
     "cookies": ["_rails_session"],
     "headers": ["x-powered-by: phusion passenger"],
     "probe": "/rails/info"},
    {"name": "Django", "kind": "framework",
     "strong": [r"csrfmiddlewaretoken", r"__admin_media_prefix__"],
     "weak": [r"/static/admin/", r"django", r"django\.js"],
     "cookies": ["csrftoken", "sessionid", "messages"],
     "headers": [], "probe": "/admin/login/"},
    {"name": "Express (Node.js)", "kind": "framework",
     "strong": [r"x-powered-by: express"],
     "weak": [r"node\.js", r"next\.js", r"__next"],
     "cookies": ["connect\.sid", "io"],
     "headers": ["x-powered-by: express", "x-nextjs-cache"],
     "probe": None},
    {"name": "CodeIgniter", "kind": "framework",
     "strong": [r"csrf_test_name"],
     "weak": [r"codeigniter"],
     "cookies": ["csrf_test_name", "ci_session"],
     "headers": [], "probe": None},
    {"name": "Yii", "kind": "framework",
     "strong": [r"/assets/[a-f0-9]{8}/"],
     "weak": [r"yii", r"csrf-token.*yii"],
     "cookies": ["csrf_token", "phpsessid"],
     "headers": ["x-powered-by: yii"],
     "probe": None},
    {"name": "Nuxt.js", "kind": "framework",
     "strong": [r"__nuxt", r"/_nuxt/"],
     "weak": [r"nuxt\.js", r"nuxt-link"],
     "cookies": [], "headers": [], "probe": None},
    {"name": "Next.js", "kind": "framework",
     "strong": [r"__next", r"/_next/static/"],
     "weak": [r"next\.js", r"nextjs"],
     "cookies": [], "headers": ["x-nextjs-cache", "x-nextjs-page"],
     "probe": None},
    {"name": "Vue.js", "kind": "framework",
     "strong": [r"data-v-[a-f0-9]{8}", r"vue\.min\.js", r"vue\.runtime"],
     "weak": [r"vuejs", r"v-bind:", r"v-if="],
     "cookies": [], "headers": [], "probe": None},
    {"name": "React", "kind": "framework",
     "strong": [r"data-reactroot", r"react-dom", r"__react"],
     "weak": [r"react\.js", r"react\.production\.min\.js"],
     "cookies": [], "headers": [], "probe": None},
    {"name": "Angular", "kind": "framework",
     "strong": [r"ng-version=", r"angular\.min\.js", r"ng-app"],
     "weak": [r"angular\.js", r"_nghost", r"ng_"],
     "cookies": [], "headers": [], "probe": None},
    {"name": "jQuery", "kind": "library",
     "strong": [r"jquery[.-]([\d.]+)(\.min)?\.js"],
     "weak": [r"jquery"],
     "cookies": [], "headers": [], "probe": None},
    {"name": "PHP", "kind": "language",
     "strong": [r"\.php"],
     "weak": [r"phpsessid"],
     "cookies": ["phpsessid"],
     "headers": ["x-powered-by: php"],
     "probe": None},
]

PROBE_PATHS = ["/", "/robots.txt", "/sitemap.xml", "/readme.html",
               "/wp-login.php", "/admin/login", "/user/login", "/typo3/",
               "/admin/login/", "/rails/info", "/ghost/"]

COOKIE_RE = re.compile(r"([A-Za-z0-9_.\-]+)\s*=", re.IGNORECASE)


def _failed(code: str, msg: str) -> dict:
    return {"module": MODULE_NAME, "status": "failed",
            "data": {}, "saved_to": None, "error": f"{code}: {msg}"}


def _scan_signatures(evidence: str, headers: dict, cookie_names: list[str]) -> list[dict]:
    """Match every signature against collected evidence."""
    generator = ""
    gen_match = re.search(
        r'name=["\']generator["\'][^>]*content=["\']([^"\']+)', evidence,
        re.IGNORECASE)
    if gen_match:
        generator = gen_match.group(1)

    header_blob = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    cookie_blob = " " + " ".join(cookie_names).lower() + " "
    found: list[dict] = []

    for sig in SIGNATURES:
        evidence_lines: list[str] = []
        score = 0

        for pat in sig.get("strong", []):
            m = re.search(pat, evidence, re.IGNORECASE)
            if m:
                score += 2
                evidence_lines.append(f"strong: /{pat}/ matched")

        for pat in sig.get("weak", []):
            if re.search(pat, evidence, re.IGNORECASE):
                score += 1
                evidence_lines.append(f"weak: /{pat}/ matched")

        if generator and sig["name"].split(" ")[0].lower() in generator.lower():
            score += 2
            evidence_lines.append(f"meta generator: {generator}")

        for cookie_pat in sig.get("cookies", []):
            for cname in cookie_names:
                if re.match(cookie_pat, cname, re.IGNORECASE):
                    score += 1
                    evidence_lines.append(f"cookie: {cname}")
                    break

        for hpat in sig.get("headers", []):
            if hpat.lower() in header_blob:
                score += 2  # headers are highly reliable evidence
                evidence_lines.append(f"header: {hpat}")

        # Report only with >=2 signals or 1 strong signal.
        strong_hits = sum(1 for pat in sig.get("strong", [])
                          if re.search(pat, evidence, re.IGNORECASE))
        if (score >= 2 or strong_hits >= 1) and evidence_lines:
            version = ""
            vm = re.search(
                r"(?:version[\"'\s:=]+|/v?)(\d+(?:\.\d+){0,3})", generator,
                re.IGNORECASE)
            if generator:
                vm = re.search(r"(\d+(?:\.\d+){0,3})", generator)
                if vm:
                    version = vm.group(1)
            if not version:
                for pat in sig.get("strong", []) + sig.get("weak", []):
                    vm = re.search(pat + r".*?(\d+(?:\.\d+){1,3})",
                                   evidence, re.IGNORECASE)
                    if vm:
                        version = vm.group(1)
                        break
            if score >= 4 or strong_hits >= 1:
                confidence = "high"
            elif score >= 2:
                confidence = "medium"
            else:
                confidence = "low"
            found.append({
                "name": sig["name"], "kind": sig["kind"],
                "signals": score, "evidence": evidence_lines,
                "version": version, "confidence": confidence,
            })

    found.sort(key=lambda c: c["signals"], reverse=True)
    return found


def run(ctx: ScanContext) -> dict:
    """Run CMS checker."""
    ctx.console.rule(f"[magenta]{MODULE_NAME}[/magenta]")
    session = ctx.session if ctx.session else get_session(ctx.args)

    evidence_text = ""
    cookie_names: list[str] = []
    merged_headers: dict = {}
    pages_ok = 0
    base = ctx.url.rstrip("/")

    # Homepage first (always GET, needed for HTML signals).
    resp = safe_get(session, base + "/", timeout=ctx.args.timeout,
                    allow_redirects=True)
    if resp is not None:
        pages_ok += 1
        merged_headers.update(dict(resp.headers))
        cookie_names += COOKIE_RE.findall(
            str(resp.headers.get("Set-Cookie", "")))
        if "text" in resp.headers.get("Content-Type", "").lower():
            evidence_text += resp.text[:200000]

    # Light probes: HEAD where safe, GET for robots/sitemap bodies.
    for path in PROBE_PATHS[1:]:
        head = safe_get(session, base + path, timeout=ctx.args.timeout,
                        allow_redirects=False)
        if head is None:
            continue
        merged_headers.update(dict(head.headers))
        pages_ok += 1
        if path in ("/robots.txt", "/sitemap.xml") and head.status_code == 200:
            body = safe_get(session, base + path, timeout=ctx.args.timeout)
            if body is not None and "text" in body.headers.get(
                    "Content-Type", "").lower():
                evidence_text += body.text[:100000]

    if pages_ok == 0:
        ctx.console.print("[red]  ✗ HTTP error: all probes failed[/red]")
        return _failed("http_error", "all probe requests failed")

    candidates = _scan_signatures(evidence_text, merged_headers, cookie_names)

    if not candidates:
        data = {"detected": [], "probed_paths": PROBE_PATHS}
        lines = ["No CMS/framework detected (insufficient evidence).",
                 f"Probed paths: {', '.join(PROBE_PATHS)}"]
    else:
        top = candidates[0]
        confidence = top["confidence"]
        data = {"detected": candidates, "top": {
            "name": top["name"], "version": top["version"],
            "kind": top["kind"], "confidence": confidence}}
        label = top["kind"].upper()
        lines = [f"Top match : [{label}] {top['name']} "
                 f"{top['version']}".rstrip(),
                 f"Confidence: {confidence}",
                 "Evidence:"]
        lines += [f"  - {e}" for e in top["evidence"]]
        if len(candidates) > 1:
            lines.append("Other candidates:")
            lines += [f"  - {c['name']} ({c['kind']}, {c['signals']} signals,"
                      f" {c['confidence']})" for c in candidates[1:8]]

    for c in candidates[:5]:
        ctx.console.print(f"  [cyan]•[/cyan] {c['name']} "
                          f"({c['kind']}, {c['confidence']})")

    try:
        path = save_result(ctx, "cms", "\n".join(lines))
    except Exception as exc:
        ctx.console.print(f"[red]  ✗ Save failed: {exc}[/red]")
        return {"module": MODULE_NAME, "status": "partial",
                "data": data, "saved_to": None, "error": f"save_error: {exc}"}

    save_json(ctx, "cms", data)
    status = "ok" if candidates else "partial"
    ctx.console.print(f"  ✓ Saved → {path}")
    return {"module": MODULE_NAME, "status": status, "data": data,
            "saved_to": str(path), "error": None}
