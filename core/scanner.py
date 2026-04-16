# core/scanner.py
import requests
import concurrent.futures
from urllib.parse import urljoin
from .utils import load_endpoints, Colors, sanitize_output, safe_get

def check_endpoint(session, base_url, endpoint):
    url = urljoin(base_url, endpoint)
    try:
        r = safe_get(session, url, timeout=10, allow_redirects=False)
        if r.status_code == 200:
            return (endpoint, "accessible", r.text[:300], r.status_code)
        elif r.status_code in [401, 403]:
            return (endpoint, "protected", "authentication/authorization required", r.status_code)
        elif 300 <= r.status_code < 400:
            return (endpoint, "redirect", r.headers.get("Location"), r.status_code)
        elif r.status_code == 404:
            return (endpoint, "not_found", "resource not found", r.status_code)
        return (endpoint, "other", f"http {r.status_code}", r.status_code)
    except requests.exceptions.RequestException as e:
        return (endpoint, "error", str(e), None)

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
                ep_result, status, info, status_code = future.result()
                results[ep_result] = {
                    "status": status,
                    "status_code": status_code,
                    "info": info
                }

                if status == "accessible":
                    print(f"  [{Colors.GREEN}+{Colors.RESET}] {base_url}{ep_result} ({Colors.GREEN}{status}{Colors.RESET}, HTTP {status_code})")
                elif status == "protected":
                    print(f"  [{Colors.BLUE}!{Colors.RESET}] {base_url}{ep_result} ({Colors.BLUE}{status}{Colors.RESET}, HTTP {status_code})")
                elif status == "redirect":
                    s_info = sanitize_output(info)
                    print(
                        f"  [{Colors.YELLOW}>{Colors.RESET}] {base_url}{ep_result} "
                        f"({Colors.YELLOW}{status}{Colors.RESET}, HTTP {status_code}, Location: {s_info})"
                    )
                elif status == "not_found":
                    print(f"  [{Colors.RED}-{Colors.RESET}] {base_url}{ep_result} ({Colors.RED}{status}{Colors.RESET}, HTTP {status_code})")
                elif status == "error":
                    s_info = sanitize_output(info)
                    print(f"  [{Colors.RED}!{Colors.RESET}] {base_url}{ep_result} ({Colors.RED}{status}{Colors.RESET}: {s_info})")
                else:
                    print(f"  [{Colors.YELLOW}-{Colors.RESET}] {base_url}{ep_result} ({Colors.YELLOW}{status}{Colors.RESET}, HTTP {status_code})")
            except Exception as exc:
                print(f"[{Colors.RED}!{Colors.RESET}] {ep} generated an exception: {exc}")
                results[ep] = {"status": "error", "status_code": None, "info": str(exc)}

    return results
