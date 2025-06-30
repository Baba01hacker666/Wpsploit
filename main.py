# main.py
import argparse
from core.scanner import scan_all_endpoints
from core.author_enum import author_enum
from core.crawler import crawl_site
from core.extract_info import extract_info
import json

def main():
    parser = argparse.ArgumentParser(description="WordPress Info Gatherer CLI Tool")
    parser.add_argument("-u", "--url", required=True, help="Target WordPress site URL")
    parser.add_argument("--threads", type=int, default=10, help="Thread count")
    parser.add_argument("--output", help="Output JSON file")
    parser.add_argument("--brute", action="store_true", help="Enable ?author= ID brute-forcing")
    parser.add_argument("--crawl", action="store_true", help="Enable site crawling")
    parser.add_argument("--extract", action="store_true", help="Enable API data extraction")

    args = parser.parse_args()
    base_url = args.url.rstrip("/")

    print("[+] Starting scan on:", base_url)
    results = scan_all_endpoints(base_url, args.threads)

    if args.brute:
        print("\n[+] Performing ?author= enumeration...")
        users = author_enum(base_url)
        results["enumerated_users"] = users
        for u in users:
            print(f"[+] Found user: {u}")

    if args.crawl:
        print("\n[+] Crawling site...")
        links = crawl_site(base_url)
        results["crawled_links"] = links
        print(f"[+] Found {len(links)} internal links")

    if args.extract:
        print("\n[+] Extracting data from accessible APIs...")
        api_data = extract_info(base_url)
        results["extracted_info"] = api_data

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()