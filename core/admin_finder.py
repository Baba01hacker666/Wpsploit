# core/admin_finder.py
import requests
import concurrent.futures
from urllib.parse import urljoin
from .utils import load_endpoints, get_random_user_agent

def check_admin_path(base_url, path):
    """Checks if a path exists and returns the URL if successful."""
    url = urljoin(base_url, path)
    headers = {"User-Agent": get_random_user_agent()}
    try:
        r = requests.get(url, headers=headers, timeout=7, allow_redirects=True)
        # A successful login page will usually be 200 OK
        if r.status_code == 200 and "log in" in r.text.lower():
            return r.url
    except requests.exceptions.RequestException:
        return None
    return None

def find_admin_panels(base_url, threads):
    """Scans for admin panels using a list of common paths."""
    found_panels = []
    admin_paths = load_endpoints("endpoints/admin_paths.txt")

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_path = {executor.submit(check_admin_path, base_url, path): path for path in admin_paths}
        
        for future in concurrent.futures.as_completed(future_to_path):
            result_url = future.result()
            if result_url:
                found_panels.append(result_url)
    
    return sorted(list(set(found_panels)))