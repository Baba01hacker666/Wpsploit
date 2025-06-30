# core/extract_info.py
import requests

headers = {"User-Agent": "Mozilla/5.0 (WPScanner)"}

def extract_info(base_url):
    endpoints = [
        "/wp-json/wp/v2/users",
        "/wp-json/wp/v2/posts",
        "/wp-json/wp/v2/pages",
        "/wp-json/wp/v2/media",
        "/wp-json/wp/v2/comments"
    ]
    info = {}

    for ep in endpoints:
        try:
            url = base_url + ep
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200 and r.headers.get('Content-Type', '').startswith('application/json'):
                data = r.json()
                info[ep] = data if isinstance(data, list) else [data]
                if ep.endswith("users"):
                    print("[+] Users Found:")
                    for u in data:
                        print(" -", u.get("name"), f"(@{u.get('slug')})")
            else:
                info[ep] = f"Non-200 or Non-JSON ({r.status_code})"
        except Exception as e:
            info[ep] = str(e)

    return info