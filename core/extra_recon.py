import requests
import re
from bs4 import BeautifulSoup
from .utils import get_random_user_agent

def identify_wp_version(base_url):
    """Identify WordPress version from HTML meta tags, license.txt, or readme.html."""
    headers = {"User-Agent": get_random_user_agent()}
    findings = {}
    # Try main index
    try:
        r = requests.get(base_url, headers=headers, timeout=10)
        meta_matches = re.findall(r'content="WordPress[^"]*"', r.text)
        if meta_matches:
            findings['meta'] = meta_matches
    except requests.RequestException:
        findings['meta'] = None
    # Try license.txt and readme.html
    for ep in ["/license.txt", "/readme.html"]:
        try:
            r = requests.get(base_url + ep, headers=headers, timeout=7)
            version_match = re.search(r'WordPress (\d+\.\d+(\.\d+)*)', r.text)
            if version_match:
                findings[ep] = version_match.group(0)
        except requests.RequestException:
            findings[ep] = None
    return findings

def enumerate_plugins_and_themes(base_url):
    """Enumerate plugins and themes from HTML source."""
    headers = {"User-Agent": get_random_user_agent()}
    plugins = set()
    themes = set()
    try:
        r = requests.get(base_url, headers=headers, timeout=10)
        plugins.update(re.findall(r'wp-content/plugins/[^"\']+', r.text))
        themes.update(re.findall(r'wp-content/themes/[^"\']+', r.text))
    except requests.RequestException:
        pass
    return sorted(plugins), sorted(themes)

def extract_versions_from_assets(base_url):
    """Extract ?ver= parameters from asset links."""
    headers = {"User-Agent": get_random_user_agent()}
    versions = set()
    try:
        r = requests.get(base_url, headers=headers, timeout=10)
        versions.update(re.findall(r'\?ver=[^"\'> ]+', r.text))
    except requests.RequestException:
        pass
    return sorted(versions)

def fetch_user_info_json(base_url, post_url=None):
    """Fetch user info via oEmbed and pages API."""
    headers = {"User-Agent": get_random_user_agent()}
    data = {}
    # oEmbed API (for a post)
    if post_url:
        oembed_url = f"{base_url}/wp-json/oembed/1.0/embed?url={post_url}"
        try:
            r = requests.get(oembed_url, headers=headers, timeout=10)
            if r.status_code == 200:
                data['oembed'] = r.json()
        except requests.RequestException:
            data['oembed'] = None
    # Pages API
    pages_url = f"{base_url}/wp-json/wp/v2/pages"
    try:
        r = requests.get(pages_url, headers=headers, timeout=10)
        if r.status_code == 200:
            data['pages'] = r.json()
    except requests.RequestException:
        data['pages'] = None
    return data

def check_xmlrpc_available(base_url):
    """Check XML-RPC endpoint availability."""
    headers = {"User-Agent": get_random_user_agent(), "Content-Type": "text/xml"}
    xml_payload = """<?xml version="1.0"?>
    <methodCall>
      <methodName>system.listMethods</methodName>
      <params></params>
    </methodCall>"""
    url = base_url + "/xmlrpc.php"
    try:
        r = requests.post(url, data=xml_payload, headers=headers, timeout=10)
        return r.status_code, r.text[:300]
    except requests.RequestException as e:
        return None, str(e)
