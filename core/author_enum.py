# core/author_enum.py
import requests
import re

headers = {"User-Agent": "Mozilla/5.0 (WPScanner)"}

def author_enum(base_url, max_id=15):
    found = []
    for i in range(1, max_id + 1):
        try:
            r = requests.get(f"{base_url}/?author={i}", headers=headers, timeout=10, allow_redirects=False)
            if 'Location' in r.headers:
                match = re.search(r'/author/([^/]+)/', r.headers['Location'])
                if match:
                    found.append(match.group(1))
        except:
            continue
    return list(set(found))