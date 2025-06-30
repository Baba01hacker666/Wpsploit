# core/crawler.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from .utils import get_random_user_agent

def crawl_site(base_url, max_depth=2):
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
        
        for url in current_urls:
            if url in visited:
                continue
            
            headers = {"User-Agent": get_random_user_agent()}
            try:
                r = requests.get(url, headers=headers, timeout=10)
                visited.add(url)
                
                # Only parse HTML content
                if 'text/html' not in r.headers.get('Content-Type', ''):
                    continue

                soup = BeautifulSoup(r.text, 'html.parser')
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href']
                    if not href or href.startswith(('#', 'mailto:', 'tel:')):
                        continue
                    
                    link = urljoin(base_url, href)
                    link_netloc = urlparse(link).netloc
                    
                    if link_netloc == base_netloc:
                        if link not in visited:
                            to_visit.add(link)
                        found_internal_links.add(link)
                    else:
                        found_external_links.add(link)
            except requests.exceptions.RequestException:
                continue

    return sorted(list(found_internal_links)), sorted(list(found_external_links))