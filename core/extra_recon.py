import requests
import re
import concurrent.futures
from .utils import safe_get, get_default_timeout

VERSION_CHECK_FOUND = "found"
VERSION_CHECK_NOT_FOUND = "not_found"
VERSION_CHECK_REQUEST_ERROR = "request_error"

WP_VERSION_RE = re.compile(r'WordPress (\d+\.\d+(?:\.\d+)*)')
META_WP_VERSION_RE = re.compile(r'content="WordPress[^"]*"')
PLUGIN_RE = re.compile(r'wp-content/plugins/([^/"\']+)')
THEME_RE = re.compile(r'wp-content/themes/([^/"\']+)')
ASSET_VER_RE = re.compile(r'\?ver=([^"\'> ]+)')

_VALID_SLUG_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{2,}$')


def _clean_slugs(matches):
    return sorted({m for m in matches if _VALID_SLUG_RE.match(m)})


def _fetch_version_from_endpoint(session, base_url, ep):
    try:
        r = safe_get(session, base_url + ep, timeout=get_default_timeout())
        version_match = WP_VERSION_RE.search(r.text)

        if version_match:
            return ep, version_match.group(1), VERSION_CHECK_FOUND, None

        return ep, None, VERSION_CHECK_NOT_FOUND, None

    except requests.RequestException as err:
        return ep, None, VERSION_CHECK_REQUEST_ERROR, str(err)


def identify_wp_version(session, base_url, html_content=None):
    """Identify WordPress version from HTML meta tags, license.txt, or readme.html."""
    findings = {"statuses": {}}

    # 🔹 Meta extraction
    if html_content:
        meta_matches = META_WP_VERSION_RE.findall(html_content)
    else:
        try:
            r = safe_get(session, base_url, timeout=get_default_timeout())
            meta_matches = META_WP_VERSION_RE.findall(r.text)
        except requests.RequestException as err:
            findings["statuses"]["meta"] = VERSION_CHECK_REQUEST_ERROR
            findings.setdefault("errors", {})["meta"] = str(err)
            meta_matches = []

    findings["statuses"]["meta"] = VERSION_CHECK_FOUND if meta_matches else VERSION_CHECK_NOT_FOUND
    if meta_matches:
        findings["meta"] = meta_matches

    # 🔹 Concurrent endpoint checks
    endpoints = ["/license.txt", "/readme.html"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(endpoints)) as executor:
        futures = [
            executor.submit(_fetch_version_from_endpoint, session, base_url, ep)
            for ep in endpoints
        ]

        for future in concurrent.futures.as_completed(futures):
            ep, val, status, error = future.result()
            findings["statuses"][ep] = status

            if status == VERSION_CHECK_FOUND:
                findings[ep] = val
            elif status == VERSION_CHECK_REQUEST_ERROR:
                findings.setdefault("errors", {})[ep] = error

    return findings


def enumerate_plugins_and_themes(session, base_url, html_content=None):
    """Enumerate plugins and themes from HTML source."""
    plugins, themes = [], []

    if html_content is None:
        try:
            r = safe_get(session, base_url, timeout=get_default_timeout())
            html_content = r.text
        except requests.RequestException:
            html_content = ""

    if html_content:
        plugins = _clean_slugs(PLUGIN_RE.findall(html_content))
        themes = _clean_slugs(THEME_RE.findall(html_content))

    return plugins, themes


def extract_versions_from_assets(session, base_url, html_content=None):
    """Extract ?ver= parameters from asset links."""
    versions = set()

    if html_content is None:
        try:
            r = safe_get(session, base_url, timeout=get_default_timeout())
            html_content = r.text
        except requests.RequestException:
            html_content = ""

    if html_content:
        versions.update(ASSET_VER_RE.findall(html_content))

    return sorted(versions)


def fetch_user_info_json(session, base_url, post_url=None):
    """Fetch user info via oEmbed and pages API."""
    data = {}

    # 🔹 oEmbed
    if post_url:
        oembed_url = f"{base_url}/wp-json/oembed/1.0/embed?url={post_url}"
        try:
            r = safe_get(session, oembed_url, timeout=get_default_timeout())
            if r.status_code == 200:
                data["oembed"] = r.json()
        except requests.RequestException:
            data["oembed"] = None

    # 🔹 Pages API
    pages_url = f"{base_url}/wp-json/wp/v2/pages"
    try:
        r = safe_get(session, pages_url, timeout=get_default_timeout())
        if r.status_code == 200:
            data["pages"] = r.json()
    except requests.RequestException:
        data["pages"] = None

    return data


def enumerate_rest_namespaces(session, base_url):
    """Enumerate wp-json namespaces; each namespace often maps to an active plugin."""
    try:
        r = safe_get(session, base_url + "/wp-json/", timeout=get_default_timeout())
        if r.status_code != 200:
            return [], f"HTTP {r.status_code}"
        data = r.json()
        routes = data.get("routes", {})
        namespaces = set()
        for route in routes:
            parts = route.strip("/").split("/")
            if len(parts) >= 2 and parts[0] != "wp" and not parts[0].startswith("oembed"):
                candidate = "/".join(parts[:2])
                ns_field = data.get("namespaces", [])
                for declared in ns_field:
                    if candidate == declared or candidate.startswith(declared):
                        namespaces.add(declared)
                        break
                else:
                    namespaces.add(candidate)
        return sorted(namespaces), None
    except requests.RequestException as e:
        return [], str(e)
    except ValueError as e:
        return [], f"invalid JSON: {e}"


def check_xmlrpc_available(session, base_url):
    """Check XML-RPC endpoint availability."""
    xml_payload = """<?xml version="1.0"?>
    <methodCall>
      <methodName>system.listMethods</methodName>
      <params></params>
    </methodCall>"""

    url = base_url + "/xmlrpc.php"

    try:
        headers = session.headers.copy()
        headers.update({"Content-Type": "text/xml"})

        r = session.post(url, data=xml_payload, headers=headers, timeout=get_default_timeout())
        return r.status_code, r.text[:300]

    except requests.RequestException as e:
        return None, str(e)
