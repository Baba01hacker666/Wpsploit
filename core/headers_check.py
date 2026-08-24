# core/headers_check.py
import requests
from urllib.parse import urlparse
from .utils import safe_get, get_default_timeout

SECURITY_HEADERS = {
    "strict-transport-security": {
        "severity": "high",
        "why": "HSTS missing: connections can be downgraded to HTTP",
    },
    "content-security-policy": {
        "severity": "medium",
        "why": "CSP missing: no browser-side mitigation for injected content",
    },
    "x-frame-options": {
        "severity": "low",
        "why": "X-Frame-Options missing: clickjacking protection not enforced",
    },
    "x-content-type-options": {
        "severity": "low",
        "why": "nosniff not set: browsers may MIME-sniff responses",
    },
    "referrer-policy": {
        "severity": "low",
        "why": "Referrer-Policy missing: full URLs may leak to third parties",
    },
    "permissions-policy": {
        "severity": "info",
        "why": "Permissions-Policy missing: powerful browser features unrestricted",
    },
}

VERSION_DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-pingback")


def _cookie_flags(set_cookie_value):
    value = set_cookie_value.lower()
    return {
        "httponly": "httponly" in value,
        "secure": "secure" in value,
        "samesite": "samesite" in value,
    }


def analyze_headers(session, base_url):
    """Fetch the homepage and login page and audit response headers and cookies."""
    report = {
        "url": base_url,
        "missing": [],
        "present": [],
        "disclosure": {},
        "cookies": [],
        "raw_headers": {},
        "errors": [],
    }

    try:
        r = safe_get(session, base_url, timeout=get_default_timeout())
        report["raw_headers"] = dict(r.headers)
        headers = {k.lower(): v for k, v in r.headers.items()}
    except requests.RequestException as e:
        report["errors"].append(f"homepage request failed: {e}")
        return report

    is_https = urlparse(base_url).scheme == "https"

    for name, meta in SECURITY_HEADERS.items():
        if name in headers:
            report["present"].append(name)
        elif name == "strict-transport-security" and not is_https:
            continue
        else:
            report["missing"].append(
                {"header": name, "severity": meta["severity"], "why": meta["why"]}
            )

    for h in VERSION_DISCLOSURE_HEADERS:
        if h in headers:
            report["disclosure"][h] = headers[h]

    try:
        login_url = base_url.rstrip("/") + "/wp-login.php"
        r2 = safe_get(session, login_url, timeout=get_default_timeout())
        raw_cookies = r2.headers.get("Set-Cookie", "")
        if isinstance(raw_cookies, str) and raw_cookies:
            cookies = [c.strip() + "," for c in raw_cookies.split("Expires") if c]
            merged = []
            seen = set()
            for chunk in raw_cookies.split(","):
                chunk = chunk.strip()
                if not chunk:
                    continue
                name = chunk.split("=", 1)[0].split(";")[0].strip()
                if name and name.lower().endswith("expires"):
                    continue
                if name in ("Path", "Domain", "Max-Age", "HttpOnly", "Secure", "SameSite"):
                    continue
                flags = _cookie_flags(chunk)
                missing_flags = [k.upper() for k, v in flags.items() if not v]
                if name not in seen or missing_flags:
                    seen.add(name)
                    entry = {"name": name, "missing_flags": missing_flags}
                    if entry not in merged:
                        merged.append(entry)
            report["cookies"] = merged
    except requests.RequestException as e:
        report["errors"].append(f"login page request failed: {e}")

    return report


def header_findings(report):
    """Convert an analyze_headers() report into a list of finding dicts."""
    findings = []
    for m in report.get("missing", []):
        findings.append(
            {
                "severity": m["severity"],
                "module": "headers",
                "title": f"Missing security header: {m['header']}",
                "detail": m["why"],
            }
        )
    for h, val in report.get("disclosure", {}).items():
        findings.append(
            {
                "severity": "low",
                "module": "headers",
                "title": f"Version disclosure via '{h}' header",
                "detail": str(val)[:120],
            }
        )
    for c in report.get("cookies", []):
        if c.get("missing_flags"):
            findings.append(
                {
                    "severity": "medium",
                    "module": "headers",
                    "title": f"Cookie '{c['name']}' lacks hardening flags",
                    "detail": "missing: " + ", ".join(c["missing_flags"]),
                }
            )
    return findings
