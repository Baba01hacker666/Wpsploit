# core/crawler.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

headers = {"User-Agent": "Mozilla/5.0 (WPScanner)"}

def crawl_site(base_url, max_depth=2):
    visited = set()
    to_visit = set([base_url])
    found_links = []

    for _ in range(max_depth):
        next_round = set()
        for url in to_visit:
            try:
                r = requests.get(url, headers=headers, timeout=10)
                visited.add(url)
                soup = BeautifulSoup(r.text, 'html.parser')
                for a in soup.find_all('a', href=True):
                    link = urljoin(url, a['href'])
                    if base_url in link and link not in visited:
                        next_round.add(link)
                        found_links.append(link)
            except:
                continue
        to_visit = next_round

    return list(set(found_links))