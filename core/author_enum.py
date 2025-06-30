# core/author_enum.py
import requests
import re
from .utils import get_random_user_agent

def author_enum(base_url, max_id=15):
    found_users = set()
    print(f"  [*] Brute-forcing author IDs from 1 to {max_id}...")
    for i in range(1, max_id + 1):
        headers = {"User-Agent": get_random_user_agent()}
        try:
            url = f"{base_url}/?author={i}"
            r = requests.get(url, headers=headers, timeout=10, allow_redirects=False)
            
            # Successful enumeration redirects to /author/username/
            if r.status_code in [301, 302] and 'Location' in r.headers:
                location = r.headers['Location']
                match = re.search(r'/author/([^/]+)', location)
                if match:
                    username = match.group(1)
                    found_users.add(username)
        except requests.exceptions.RequestException:
            continue
            
    return sorted(list(found_users))