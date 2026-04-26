import requests
import re
import concurrent.futures
from .utils import safe_get

def check_author_id(session, base_url, author_id):
    try:
        url = f"{base_url}/?author={author_id}"
        r = safe_get(session, url, timeout=10, allow_redirects=False)

        # Successful enumeration redirects to /author/username/
        if r.status_code in [301, 302] and 'Location' in r.headers:
            location = r.headers['Location']
            match = re.search(r'/author/([^/]+)', location)
            if match:
                return match.group(1)
    except requests.exceptions.RequestException:
        return None
    return None

def author_enum(session, base_url, max_id=15, threads=10):
    found_users = set()
    print(f"  [*] Brute-forcing author IDs from 1 to {max_id} with {threads} threads...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_id = {executor.submit(check_author_id, session, base_url, i): i for i in range(1, max_id + 1)}

        for future in concurrent.futures.as_completed(future_to_id):
            username = future.result()
            if username:
                found_users.add(username)

    return sorted(list(found_users))
