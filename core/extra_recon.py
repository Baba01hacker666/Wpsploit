import requests
import re
import concurrent.futures

VERSION_CHECK_FOUND = "found"
VERSION_CHECK_NOT_FOUND = "not_found"
VERSION_CHECK_REQUEST_ERROR = "request_error"

WP_VERSION_RE = re.compile(r'WordPress (\d+\.\d+(\.\d+)*)')
META_WP_VERSION_RE = re.compile(r'content="WordPress[^"]*"')
PLUGIN_RE = re.compile(r'wp-content/plugins/([^/"\']+)')
THEME_RE = re.compile(r'wp-content/themes/([^/"\']+)')
ASSET_VER_RE = re.compile(r'\?ver=([^"\'> ]+)')


def _fetch_version_from_endpoint(session, base_url, ep):
    try:
        r = session.get(base_url + ep, timeout=7)
        version_match = WP_VERSION_RE.search(r.text)
        if version_match:
            return ep, version_match.group(0), VERSION_CHECK_FOUND, None
        return ep, None, VERSION_CHECK_NOT_FOUND, None
    except requests.RequestException as err:
        return ep, None, VERSION_CHECK_REQUEST_ERROR, str(err)

def identify_wp_version(session, base_url, html_content=None):
    """Identify WordPress version from HTML meta tags, license.txt, or readme.html."""
    findings = {"statuses": {}}
    # Try main index using provided html_content if available
    if html_content:
        meta_matches = META_WP_VERSION_RE.findall(html_content)
        findings["statuses"]["meta"] = VERSION_CHECK_FOUND if meta_matches else VERSION_CHECK_NOT_FOUND
        if meta_matches:
            findings['meta'] = meta_matches
    else:
        try:
            r = session.get(base_url, timeout=10)
            meta_matches = META_WP_VERSION_RE.findall(r.text)
            findings["statuses"]["meta"] = VERSION_CHECK_FOUND if meta_matches else VERSION_CHECK_NOT_FOUND
            if meta_matches:
                findings['meta'] = meta_matches
        except requests.RequestException as err:
            findings["statuses"]["meta"] = VERSION_CHECK_REQUEST_ERROR
            findings.setdefault("errors", {})["meta"] = str(err)

    # Try license.txt and readme.html concurrently
    endpoints = ["/license.txt", "/readme.html"]
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(endpoints)) as executor:
        future_to_ep = {executor.submit(_fetch_version_from_endpoint, session, base_url, ep): ep for ep in endpoints}
        for future in concurrent.futures.as_completed(future_to_ep):
            ep, val, status, error = future.result()
            findings["statuses"][ep] = status
            if status == VERSION_CHECK_FOUND:
                findings[ep] = val
            elif status == VERSION_CHECK_REQUEST_ERROR:
                findings.setdefault("errors", {})[ep] = error

    return findings

def enumerate_plugins_and_themes(session, base_url, html_content=None):
    """Enumerate plugins and themes from HTML source."""
    plugins = set()
    themes = set()

    if html_content is None:
        try:
            r = session.get(base_url, timeout=10)
            html_content = r.text
        except requests.RequestException:
            html_content = ""

    if html_content:
        plugins.update(PLUGIN_RE.findall(html_content))
        themes.update(THEME_RE.findall(html_content))

    return sorted(list(plugins)), sorted(list(themes))

def extract_versions_from_assets(session, base_url, html_content=None):
    """Extract ?ver= parameters from asset links."""
    versions = set()

    if html_content is None:
        try:
            r = session.get(base_url, timeout=10)
            html_content = r.text
        except requests.RequestException:
            html_content = ""

    if html_content:
        versions.update(ASSET_VER_RE.findall(html_content))

    return sorted(list(versions))

def fetch_user_info_json(session, base_url, post_url=None):
    """Fetch user info via oEmbed and pages API."""
    data = {}
    # oEmbed API (for a post)
    if post_url:
        oembed_url = f"{base_url}/wp-json/oembed/1.0/embed?url={post_url}"
        try:
            r = session.get(oembed_url, timeout=10)
            if r.status_code == 200:
                data['oembed'] = r.json()
        except requests.RequestException:
            data['oembed'] = None
    # Pages API
    pages_url = f"{base_url}/wp-json/wp/v2/pages"
    try:
        r = session.get(pages_url, timeout=10)
        if r.status_code == 200:
            data['pages'] = r.json()
    except requests.RequestException:
        data['pages'] = None
    return data

def check_xmlrpc_available(session, base_url):
    """Check XML-RPC endpoint availability."""
    headers = {"Content-Type": "text/xml"}
    xml_payload = """<?xml version="1.0"?>
    <methodCall>
      <methodName>system.listMethods</methodName>
      <params></params>
    </methodCall>"""
    url = base_url + "/xmlrpc.php"
    try:
        # We need to temporarily update headers for this specific POST request
        custom_headers = session.headers.copy()
        custom_headers.update(headers)
        r = session.post(url, data=xml_payload, headers=custom_headers, timeout=10)
        return r.status_code, r.text[:300]
    except requests.RequestException as e:
        return None, str(e)
