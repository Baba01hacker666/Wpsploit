# core/crawler.py
import requests
import concurrent.futures
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def fetch_and_parse(session, url, base_url, base_netloc):
    try:
        r = session.get(url, timeout=10)
        # Only parse HTML content
        if 'text/html' not in r.headers.get('Content-Type', ''):
            return url, set(), set()

        soup = BeautifulSoup(r.text, 'html.parser')
        new_internal = set()
        new_external = set()

        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            if not href or href.startswith(('#', 'mailto:', 'tel:')):
                continue

            link = urljoin(base_url, href)
            link_netloc = urlparse(link).netloc

            if link_netloc == base_netloc:
                new_internal.add(link)
            else:
                new_external.add(link)

        return url, new_internal, new_external
    except requests.exceptions.RequestException:
        return url, set(), set()

def crawl_site(session, base_url, max_depth=2, threads=5):
    visited = set()
    to_visit = {base_url}
    found_internal_links = set()
    found_external_links = set()
    base_netloc = urlparse(base_url).netloc

    for _ in range(max_depth):
        if not to_visit:
            break
        
        current_urls = list(to_visit)
        to_visit = set()
        
        # Filter out already visited URLs before submitting to ThreadPool
        urls_to_fetch = [u for u in current_urls if u not in visited]
        if not urls_to_fetch:
            continue

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_url = {executor.submit(fetch_and_parse, session, url, base_url, base_netloc): url for url in urls_to_fetch}
            
            for future in concurrent.futures.as_completed(future_to_url):
                url, new_internal, new_external = future.result()
                visited.add(url)
                
                # Add to total found sets
                found_internal_links.update(new_internal)
                found_external_links.update(new_external)

                # Add new internal links to to_visit if not already visited
                for link in new_internal:
                    if link not in visited:
                        to_visit.add(link)

    return sorted(list(found_internal_links)), sorted(list(found_external_links))