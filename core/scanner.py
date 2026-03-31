# core/scanner.py
import requests
import concurrent.futures
from urllib.parse import urljoin
from .utils import load_endpoints, get_random_user_agent, Colors, sanitize_output

def check_endpoint(session, base_url, endpoint):
    url = urljoin(base_url, endpoint)
    try:
        r = session.get(url, timeout=10, allow_redirects=False)
        if r.status_code == 200:
            return (endpoint, True, r.text[:300])
        elif r.status_code in [301, 302]:
            return (endpoint, "redirect", r.headers.get("Location"))
        else:
            return (endpoint, False, r.status_code)
    except requests.exceptions.RequestException as e:
        return (endpoint, "error", str(e))

def scan_all_endpoints(session, base_url, threads):
    results = {}
    
    # Combine all endpoint lists into one, using a set for automatic deduplication
    endpoints_to_scan = set()
    for list_name in ["base", "wp-json", "xmlrpc"]:
        endpoints_to_scan.update(load_endpoints(f"endpoints/{list_name}.txt"))
    
    # Final sorted list of unique endpoints
    endpoints_to_scan = sorted(endpoints_to_scan)

    print(f"[*] Queued {len(endpoints_to_scan)} endpoints for scanning with {threads} threads.")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_ep = {executor.submit(check_endpoint, session, base_url, ep): ep for ep in endpoints_to_scan}
        
        for future in concurrent.futures.as_completed(future_to_ep):
            ep = future_to_ep[future]
            try:
                ep_result, status, info = future.result()
                results[ep_result] = {"status": status, "info": info}

                if status is True:
                    print(f"  [{Colors.GREEN}+{Colors.RESET}] {base_url}{ep_result} (Status: {Colors.GREEN}{status}{Colors.RESET})")
                elif status == "redirect":
                    s_info = sanitize_output(info)
                    print(f"  [{Colors.YELLOW}-{Colors.RESET}] {base_url}{ep_result} (Status: {Colors.YELLOW}{status}{Colors.RESET}, Location: {s_info})")
                else:
                    print(f"  [{Colors.RED}-{Colors.RESET}] {base_url}{ep_result} (Status: {Colors.RED}{status}{Colors.RESET})")
            except Exception as exc:
                print(f"[{Colors.RED}!{Colors.RESET}] {ep} generated an exception: {exc}")
                results[ep] = {"status": "error", "info": str(exc)}

    return results