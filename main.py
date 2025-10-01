# main.py
import argparse
import json
import os
from urllib.parse import urlparse

from core.scanner import scan_all_endpoints
from core.author_enum import author_enum
from core.crawler import crawl_site
from core.extract_info import extract_info
from core.admin_finder import find_admin_panels

def main():
    parser = argparse.ArgumentParser(description="wpsploit - WordPress Information Gathering Tool")
    parser.add_argument("-u", "--url", required=True, help="Target WordPress site URL")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads for scanning")
    parser.add_argument("--output", action="store_true", help="Save results to a directory named after the domain")
    
    # Feature flags
    parser.add_argument("--brute", action="store_true", help="Enable ?author= ID brute-forcing")
    parser.add_argument("--crawl", action="store_true", help="Enable site crawling to find links")
    parser.add_argument("--extract", action="store_true", help="Enable API data extraction (users, posts, etc.)")
    parser.add_argument("--admin-finder", action="store_true", help="Enable admin login page finder")
    
    # Feature-specific options
    parser.add_argument("--max-author-id", type=int, default=15, help="Max author ID to check for brute-forcing")
    parser.add_argument("--crawl-depth", type=int, default=2, help="Max depth for the crawler")
    parser.add_argument("--extra-recon", action="store_true", help="Enable extra reconnaissance techniques (version, plugins, themes, asset versions, user info, XML-RPC)")

    args = parser.parse_args()
    base_url = args.url.rstrip("/")
    domain = urlparse(base_url).netloc
    
    # --- Output Directory Setup ---
    output_dir = domain if args.output else None
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        print(f"[+] Results will be saved in '{output_dir}/' directory")

    print(f"[+] Starting scan on: {base_url}")
    results = {}

    # --- Core Scanning ---
    print("\n[+] Scanning for common and vulnerable endpoints...")
    endpoint_results = scan_all_endpoints(base_url, args.threads)
    results["endpoint_scan"] = endpoint_results

    # --- Optional Modules ---
    if args.brute:
        print("\n[+] Performing ?author= enumeration...")
        users = author_enum(base_url, max_id=args.max_author_id)
        results["enumerated_users"] = users
        for u in users:
            print(f"  [>] Found user via author scanning: {u}")

    if args.admin_finder:
        print("\n[+] Searching for admin panels...")
        admin_panels = find_admin_panels(base_url, args.threads)
        results["found_admin_panels"] = admin_panels
        for panel in admin_panels:
            print(f"  [>] Found potential admin panel: {panel}")

    if args.crawl:
        print("\n[+] Crawling site...")
        internal_links, external_links = crawl_site(base_url, max_depth=args.crawl_depth)
        results["crawled_internal_links"] = internal_links
        results["crawled_external_links"] = external_links
        print(f"  [>] Found {len(internal_links)} internal links and {len(external_links)} external links.")
        if output_dir:
            with open(os.path.join(output_dir, "internal_links.txt"), "w") as f:
                f.write("\n".join(internal_links))
            with open(os.path.join(output_dir, "external_links.txt"), "w") as f:
                f.write("\n".join(external_links))

    if args.extract:
        print("\n[+] Extracting data from accessible REST APIs...")
        api_data = extract_info(base_url)
        results["extracted_info"] = api_data
    if args.extra_recon:
    from core.extra_recon import (
        identify_wp_version,
        enumerate_plugins_and_themes,
        extract_versions_from_assets,
        fetch_user_info_json,
        check_xmlrpc_available
    )
    print("\n[+] Running extra reconnaissance techniques...")
    version_info = identify_wp_version(base_url)
    plugins, themes = enumerate_plugins_and_themes(base_url)
    asset_versions = extract_versions_from_assets(base_url)
    user_json = fetch_user_info_json(base_url)
    xmlrpc_status, xmlrpc_resp = check_xmlrpc_available(base_url)
    results["wp_version_info"] = version_info
    results["plugins"] = plugins
    results["themes"] = themes
    results["asset_versions"] = asset_versions
    results["user_json"] = user_json
    results["xmlrpc"] = {"status": xmlrpc_status, "response": xmlrpc_resp}
    # Print highlights
    print("  [>] WP Version Info:", version_info)
    print("  [>] Plugins:", plugins)
    print("  [>] Themes:", themes)
    print("  [>] Asset versions:", asset_versions)
    print("  [>] User info:", user_json)
    print("  [>] XML-RPC:", xmlrpc_status)

    # --- Summarize Important Findings ---
    print("\n" + "="*20 + " IMPORTANT FINDINGS " + "="*20)
    has_findings = False
    if results.get("endpoint_scan", {}).get("/.git/", {}).get("status") == True:
        print("[!] CRITICAL: /.git directory is exposed!")
        has_findings = True
    if results.get("endpoint_scan", {}).get("/wp-config.php.save", {}).get("status") == True:
        print("[!] CRITICAL: /wp-config.php.save is exposed!")
        has_findings = True
    if results.get("enumerated_users"):
        print(f"[!] HIGH: Found {len(results['enumerated_users'])} usernames via author enumeration: {', '.join(results['enumerated_users'])}")
        has_findings = True
    if results.get("found_admin_panels"):
        print(f"[!] INFO: Found {len(results['found_admin_panels'])} potential admin panel(s).")
        has_findings = True
    if results.get("extracted_info", {}).get("/wp-json/wp/v2/users"):
        users_api = results["extracted_info"]["/wp-json/wp/v2/users"]
        if isinstance(users_api, list) and users_api:
            usernames = [u.get('slug') for u in users_api]
            print(f"[!] HIGH: User listing is public via REST API. Users: {', '.join(usernames)}")
            has_findings = True
    if not has_findings:
        print("[-] No high-impact issues automatically identified.")
    print("="*62)


    # --- Save Final Results ---
    if output_dir:
        output_file = os.path.join(output_dir, "results.json")
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n[+] Full scan results saved to {output_file}")

if __name__ == "__main__":
    main()
