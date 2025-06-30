# core/extract_info.py
import requests
from .utils import get_random_user_agent

def extract_info(base_url):
    endpoints = [
        "/wp-json/wp/v2/users",
        "/wp-json/wp/v2/posts",
        "/wp-json/wp/v2/pages",
        "/wp-json/wp/v2/media",
        "/wp-json/wp/v2/comments"
    ]
    info = {}
    headers = {"User-Agent": get_random_user_agent()}

    for ep in endpoints:
        try:
            url = base_url + ep
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200 and r.headers.get('Content-Type', '').startswith('application/json'):
                data = r.json()
                info[ep] = data if isinstance(data, list) else [data]
                if ep.endswith("users") and data:
                    print("  [>] Public Users Found via API:")
                    for u in data:
                        print(f"    - Name: {u.get('name')}, Slug: {u.get('slug')}")
            else:
                info[ep] = f"Non-200 or Non-JSON (Status: {r.status_code})"
        except requests.exceptions.RequestException as e:
            info[ep] = str(e)

    return info