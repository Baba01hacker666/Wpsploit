# core/scanner.py
import requests
import concurrent.futures
from urllib.parse import urljoin
from core.utils import load_endpoints

headers = {"User-Agent": "Mozilla/5.0 (WPScanner)"}

def check_endpoint(base_url, endpoint):
    url = urljoin(base_url, endpoint)
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            return (endpoint, True, r.text[:300])
        elif r.status_code in [301, 302]:
            return (endpoint, "redirect", r.headers.get("Location"))
        else:
            return (endpoint, False, r.status_code)
    except Exception as e:
        return (endpoint, "error", str(e))

def scan_all_endpoints(base_url, threads):
    results = {}

    groups = {
        "base": load_endpoints("endpoints/base.txt"),
        "wp-json": load_endpoints("endpoints/wp-json.txt"),
        "xmlrpc": load_endpoints("endpoints/xmlrpc.txt")
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_endpoint, base_url, ep): ep for ep in groups['base']}
        for f in concurrent.futures.as_completed(futures):
            ep, status, info = f.result()
            results[ep] = {"status": status, "info": info}
            print(f"[{'+' if status==True else '-'}] {ep} => {status}")

    if results.get("/wp-json/", {}).get("status") == True:
        for ep in groups['wp-json']:
            ep, status, info = check_endpoint(base_url, ep)
            results[ep] = {"status": status, "info": info}
            print(f"[{'+' if status==True else '-'}] {ep} => {status}")

    if results.get("/xmlrpc.php", {}).get("status") == True:
        for ep in groups['xmlrpc']:
            ep, status, info = check_endpoint(base_url, ep)
            results[ep] = {"status": status, "info": info}
            print(f"[{'+' if status==True else '-'}] {ep} => {status}")

    return results