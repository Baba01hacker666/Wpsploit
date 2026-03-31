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
from core.utils import setup_session, Colors, sanitize_output, sanitize_filename

def print_banner():
    banner = rf"""{Colors.BLUE}
 __      __                .__         .__  __
/  \    /  \_____  _______ |  |   ____ |__|/  |_
\   \/\/   /\__  \ \____ \|  |  /  _ \|  \   __\
 \        /  / __ \|  |_> >  |_(  <_> )  ||  |
  \__/\  /  (____  /   __/|____/\____/|__||__|
       \/        \/|__|
{Colors.CYAN}WordPress Information Gathering Tool{Colors.RESET}
    """
    print(banner)

def main():
    print_banner()
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
    domain = sanitize_filename(urlparse(base_url).netloc)
    
    # --- Session Setup ---
    session = setup_session()

    # --- Output Directory Setup ---
    output_dir = domain if args.output else None
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        print(f"[{Colors.GREEN}+{Colors.RESET}] Results will be saved in '{output_dir}/' directory")

    print(f"[{Colors.BLUE}+{Colors.RESET}] Starting scan on: {Colors.CYAN}{base_url}{Colors.RESET}")
    results = {}

    # --- Core Scanning ---
    print(f"\n[{Colors.BLUE}+{Colors.RESET}] Scanning for common and vulnerable endpoints...")
    endpoint_results = scan_all_endpoints(session, base_url, args.threads)
    results["endpoint_scan"] = endpoint_results

    # --- Optional Modules ---
    if args.brute:
        print(f"\n[{Colors.BLUE}+{Colors.RESET}] Performing ?author= enumeration...")
        users = author_enum(session, base_url, max_id=args.max_author_id, threads=args.threads)
        results["enumerated_users"] = users
        for u in users:
            s_u = sanitize_output(u)
            print(f"  [{Colors.GREEN}>{Colors.RESET}] Found user via author scanning: {Colors.GREEN}{s_u}{Colors.RESET}")

    if args.admin_finder:
        print(f"\n[{Colors.BLUE}+{Colors.RESET}] Searching for admin panels...")
        admin_panels = find_admin_panels(session, base_url, args.threads)
        results["found_admin_panels"] = admin_panels
        for panel in admin_panels:
            print(f"  [{Colors.GREEN}>{Colors.RESET}] Found potential admin panel: {Colors.GREEN}{panel}{Colors.RESET}")

    if args.crawl:
        print(f"\n[{Colors.BLUE}+{Colors.RESET}] Crawling site...")
        internal_links, external_links = crawl_site(session, base_url, max_depth=args.crawl_depth, threads=args.threads)
        results["crawled_internal_links"] = internal_links
        results["crawled_external_links"] = external_links
        print(f"  [{Colors.GREEN}>{Colors.RESET}] Found {len(internal_links)} internal links and {len(external_links)} external links.")
        if output_dir:
            with open(os.path.join(output_dir, "internal_links.txt"), "w") as f:
                f.write("\n".join(internal_links))
            with open(os.path.join(output_dir, "external_links.txt"), "w") as f:
                f.write("\n".join(external_links))

    if args.extract:
        print(f"\n[{Colors.BLUE}+{Colors.RESET}] Extracting data from accessible REST APIs...")
        api_data = extract_info(session, base_url, threads=args.threads)
        results["extracted_info"] = api_data
    if args.extra_recon:
     from core.extra_recon import (
        identify_wp_version,
        enumerate_plugins_and_themes,
        extract_versions_from_assets,
        fetch_user_info_json,
        check_xmlrpc_available
     )
     print(f"\n[{Colors.BLUE}+{Colors.RESET}] Running extra reconnaissance techniques...")

     # Fetch homepage once for shared use
     try:
         r = session.get(base_url, timeout=10)
         html_content = r.text
     except Exception:
         html_content = ""

     version_info = identify_wp_version(session, base_url, html_content)
     plugins, themes = enumerate_plugins_and_themes(session, base_url, html_content)
     asset_versions = extract_versions_from_assets(session, base_url, html_content)
     user_json = fetch_user_info_json(session, base_url)
     xmlrpc_status, xmlrpc_resp = check_xmlrpc_available(session, base_url)

     results["wp_version_info"] = version_info
     results["plugins"] = plugins
     results["themes"] = themes
     results["asset_versions"] = asset_versions
     results["user_json"] = user_json
     results["xmlrpc"] = {"status": xmlrpc_status, "response": xmlrpc_resp}

     # Print highlights
     print(f"  [{Colors.GREEN}>{Colors.RESET}] WP Version Info: {sanitize_output(version_info)}")
     print(f"  [{Colors.GREEN}>{Colors.RESET}] Plugins: {sanitize_output(plugins)}")
     print(f"  [{Colors.GREEN}>{Colors.RESET}] Themes: {sanitize_output(themes)}")
     print(f"  [{Colors.GREEN}>{Colors.RESET}] Asset versions: {sanitize_output(asset_versions)}")
     print(f"  [{Colors.GREEN}>{Colors.RESET}] XML-RPC Status: {sanitize_output(xmlrpc_status)}")
    # --- Summarize Important Findings ---
    print("\n" + Colors.CYAN + "="*20 + " IMPORTANT FINDINGS " + "="*20 + Colors.RESET)
    has_findings = False
    if results.get("endpoint_scan", {}).get("/.git/", {}).get("status") == True:
        print(f"[{Colors.RED}!{Colors.RESET}] CRITICAL: /.git directory is exposed!")
        has_findings = True
    if results.get("endpoint_scan", {}).get("/wp-config.php.save", {}).get("status") == True:
        print(f"[{Colors.RED}!{Colors.RESET}] CRITICAL: /wp-config.php.save is exposed!")
        has_findings = True
    if results.get("enumerated_users"):
        s_users = [sanitize_output(u) for u in results['enumerated_users']]
        print(f"[{Colors.RED}!{Colors.RESET}] HIGH: Found {len(results['enumerated_users'])} usernames via author enumeration: {', '.join(s_users)}")
        has_findings = True
    if results.get("found_admin_panels"):
        print(f"[{Colors.BLUE}!{Colors.RESET}] INFO: Found {len(results['found_admin_panels'])} potential admin panel(s).")
        has_findings = True
    if results.get("extracted_info", {}).get("/wp-json/wp/v2/users"):
        users_api = results["extracted_info"]["/wp-json/wp/v2/users"]
        if isinstance(users_api, list) and users_api:
            # Check for actual user entries before warning
            if users_api and isinstance(users_api[0], dict) and 'slug' in users_api[0]:
                usernames = [sanitize_output(u.get('slug')) for u in users_api if isinstance(u, dict)]
                print(f"[{Colors.RED}!{Colors.RESET}] HIGH: User listing is public via REST API. Users: {', '.join(usernames)}")
                has_findings = True
    if not has_findings:
        print(f"[{Colors.YELLOW}-{Colors.RESET}] No high-impact issues automatically identified.")
    print(Colors.CYAN + "="*62 + Colors.RESET)


    # --- Save Final Results ---
    if output_dir:
        output_file = os.path.join(output_dir, "results.json")
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n[+] Full scan results saved to {output_file}")

if __name__ == "__main__":
    main()
