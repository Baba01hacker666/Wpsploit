# core/scanner.py
import requests
import concurrent.futures
from urllib.parse import urljoin
from .utils import load_endpoints, sanitize_output, safe_get, get_default_timeout
from . import ui

LISTING_MARKERS = ("<title>Index of /", "Directory listing for", "Parent Directory")

INTERESTING_ENDPOINTS = {
    "/.git/": "Exposed git repository",
    "/.env": "Exposed environment file",
    "/wp-config.php.save": "Backup of wp-config",
    "/wp-json/wp/v2/users": "Public user listing via REST API",
    "/wp-login.php?action=register": "Open user registration",
    "/xmlrpc.php": "XML-RPC interface active",
}


def check_endpoint(session, base_url, endpoint):
    url = urljoin(base_url, endpoint)
    try:
        r = safe_get(session, url, timeout=get_default_timeout(), allow_redirects=False)
        if r.status_code == 200:
            body = r.text[:2000]
            is_listing = any(m in body for m in LISTING_MARKERS)
            is_blank = not r.text.strip() and endpoint.endswith(".php")
            return (endpoint, "accessible", r.text[:300], r.status_code, is_listing or False, is_blank)
        elif r.status_code in [401, 403]:
            return (endpoint, "protected", "authentication/authorization required", r.status_code, False, False)
        elif 300 <= r.status_code < 400:
            return (endpoint, "redirect", r.headers.get("Location"), r.status_code, False, False)
        elif r.status_code == 404:
            return (endpoint, "not_found", "resource not found", r.status_code, False, False)
        return (endpoint, "other", f"http {r.status_code}", r.status_code, False, False)
    except requests.exceptions.RequestException as e:
        return (endpoint, "error", str(e), None, False, False)


def scan_all_endpoints(session, base_url, threads, extra_endpoints=None):
    results = {}

    # Combine all endpoint lists into one, using a set for automatic deduplication
    endpoints_to_scan = set()
    for list_name in ["base", "wp-json", "xmlrpc"]:
        endpoints_to_scan.update(load_endpoints(f"endpoints/{list_name}.txt"))
    if extra_endpoints:
        endpoints_to_scan.update(extra_endpoints)

    # Final sorted list of unique endpoints
    endpoints_to_scan = sorted(endpoints_to_scan)

    ui.info(f"Queued {len(endpoints_to_scan)} endpoints with {threads} threads")

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_ep = {executor.submit(check_endpoint, session, base_url, ep): ep for ep in endpoints_to_scan}

        for future in concurrent.futures.as_completed(future_to_ep):
            ep = future_to_ep[future]
            try:
                ep_result, status, info_text, status_code, is_listing, is_blank = future.result()
                results[ep_result] = {
                    "status": status,
                    "status_code": status_code,
                    "info": info_text,
                    "listing": is_listing,
                    "blank": is_blank,
                }

                if status == "accessible":
                    if is_blank:
                        ui.dim(f"{base_url}{ep_result} (blank 200 — executes server-side, not exposed)")
                        continue
                    note = INTERESTING_ENDPOINTS.get(ep_result)
                    suffix = f" — {note}" if note else ""
                    if is_listing:
                        suffix += " [open directory listing]"
                    ui.ok(f"{base_url}{ep_result} ({status}, HTTP {status_code}){suffix}")
                elif status == "protected":
                    ui.info(f"{base_url}{ep_result} (protected, HTTP {status_code})")
                elif status == "redirect":
                    s_info = sanitize_output(info_text)
                    ui.warn(
                        f"{base_url}{ep_result} ({status}, HTTP {status_code}, Location: {s_info})"
                    )
                elif status == "not_found":
                    ui.dim(f"{base_url}{ep_result} ({status}, HTTP {status_code})")
                elif status == "error":
                    s_info = sanitize_output(info_text)
                    ui.err(f"{base_url}{ep_result} ({status}: {s_info})")
                else:
                    ui.dim(f"{base_url}{ep_result} ({status}, HTTP {status_code})")
            except Exception as exc:
                ui.err(f"{ep} generated an exception: {exc}")
                results[ep] = {"status": "error", "status_code": None, "info": str(exc), "listing": False, "blank": False}

    return results
