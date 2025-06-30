# core/scanner.py
import requests
import concurrent.futures
from urllib.parse import urljoin
from .utils import load_endpoints, get_random_user_agent

def check_endpoint(base_url, endpoint):
    url = urljoin(base_url, endpoint)
    headers = {"User-Agent": get_random_user_agent()}
    try:
        r = requests.get(url, headers=headers, timeout=10, allow_redirects=False)
        if r.status_code == 200:
            return (endpoint, True, r.text[:300])
        elif r.status_code in [301, 302]:
            return (endpoint, "redirect", r.headers.get("Location"))
        else:
            return (endpoint, False, r.status_code)
    except requests.exceptions.RequestException as e:
        return (endpoint, "error", str(e))

def scan_all_endpoints(base_url, threads):
    results = {}
    
    # Combine all endpoint lists into one
    endpoints_to_scan = []
    for list_name in ["base", "wp-json", "xmlrpc"]:
        endpoints_to_scan.extend(load_endpoints(f"endpoints/{list_name}.txt"))
    
    # Remove duplicates
    endpoints_to_scan = sorted(list(set(endpoints_to_scan)))

    print(f"[*] Queued {len(endpoints_to_scan)} endpoints for scanning with {threads} threads.")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_ep = {executor.submit(check_endpoint, base_url, ep): ep for ep in endpoints_to_scan}
        
        for future in concurrent.futures.as_completed(future_to_ep):
            ep = future_to_ep[future]
            try:
                ep_result, status, info = future.result()
                results[ep_result] = {"status": status, "info": info}
                status_symbol = '+' if status is True else '-'
                print(f"  [{status_symbol}] {base_url}{ep_result} (Status: {status})")
            except Exception as exc:
                print(f"[!] {ep} generated an exception: {exc}")
                results[ep] = {"status": "error", "info": str(exc)}

    return results