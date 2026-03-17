# core/extract_info.py
import requests
import concurrent.futures
from .utils import sanitize_output

def fetch_api_endpoint(session, base_url, ep):
    try:
        url = base_url + ep
        r = session.get(url, timeout=10)
        if r.status_code == 200 and r.headers.get('Content-Type', '').startswith('application/json'):
            data = r.json()
            return ep, data if isinstance(data, list) else [data]
        else:
            return ep, f"Non-200 or Non-JSON (Status: {r.status_code})"
    except requests.exceptions.RequestException as e:
        return ep, str(e)

def extract_info(session, base_url, threads=5):
    endpoints = [
        "/wp-json/wp/v2/users",
        "/wp-json/wp/v2/posts",
        "/wp-json/wp/v2/pages",
        "/wp-json/wp/v2/media",
        "/wp-json/wp/v2/comments"
    ]
    info = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_ep = {executor.submit(fetch_api_endpoint, session, base_url, ep): ep for ep in endpoints}

        for future in concurrent.futures.as_completed(future_to_ep):
            ep, data = future.result()
            info[ep] = data

            if ep.endswith("users") and isinstance(data, list):
                # Filter out error strings or non-lists before iterating
                if data and isinstance(data[0], dict) and 'slug' in data[0]:
                    print("  [>] Public Users Found via API:")
                    for u in data:
                        name = sanitize_output(u.get('name'))
                        slug = sanitize_output(u.get('slug'))
                        print(f"    - Name: {name}, Slug: {slug}")

    return info