import requests
from bs4 import BeautifulSoup
import json
import os
import time
from urllib.parse import urlparse

# Constants
BASE_URL = "https://thedfirreport.com"
TARGET_DIR = r"c:\Users\user\Desktop\Temp\data\raw\Yechan\dfirreport_json"
MAX_PAGES = 50

def get_page(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Referer': 'https://thedfirreport.com/'
        }
        response = requests.get(url, headers=headers, timeout=20)
        if response.status_code == 200:
            return response.text
        print(f"Failed with status: {response.status_code} for {url}")
        return None
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None

def extract_links(html):
    soup = BeautifulSoup(html, 'html.parser')
    links = set()
    for a in soup.find_all('a', href=True):
        href = a['href']
        if 'thedfirreport.com/20' in href:
            href = href.split('#')[0].split('?')[0]
            links.add(href)
    return list(links)

def parse_article(url, html):
    soup = BeautifulSoup(html, 'html.parser')
    title = soup.title.text.strip() if soup.title else "No Title"
    
    content_node = soup.find('div', class_='entry-content-wrapper') or \
                   soup.find('div', class_='content-column') or \
                   soup.find('div', id='main')
    
    if content_node:
        for tag in content_node(['script', 'style', 'nav', 'footer', 'header']):
            tag.decompose()
        content = content_node.get_text(separator='\n', strip=True)
    else:
        content = ""
        
    return {
        "url": url,
        "title": title.replace(" - The DFIR Report", "").strip(),
        "source": "The DFIR Report",
        "category": "incident-response",
        "content": content
    }

def main():
    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR)
        
    visited_links = set()
    all_links = []
    
    for page in range(1, MAX_PAGES + 1):
        page_url = BASE_URL if page == 1 else f"{BASE_URL}/page/{page}/"
        print(f"Fetching index: {page_url}")
        
        html = get_page(page_url)
        if not html:
            print("Reached end of pagination or encountered an error.")
            break
            
        links = extract_links(html)
        if not links:
            print("No new links found on this page.")
            break
            
        new_links = [l for l in links if l not in visited_links]
        if not new_links:
            print("No new links on this page. Stopping pagination.")
            break
            
        all_links.extend(new_links)
        visited_links.update(new_links)
        time.sleep(3)  # Increased delay
        
    print(f"\nTotal unique articles found: {len(all_links)}")
    
    # 2. Scrape each article
    success_count = 0
    for idx, link in enumerate(all_links, 1):
        print(f"[{idx}/{len(all_links)}] Scraping: {link}")
        html = get_page(link)
        
        if html:
            data = parse_article(link, html)
            
            # Create safe filename
            parsed_url = urlparse(link)
            path_parts = [p for p in parsed_url.path.split('/') if p]
            # Use the last part of the URL as filename, e.g., the slug
            slug = path_parts[-1] if path_parts else f"article_{int(time.time())}"
            filename = f"{slug}.json"
            filepath = os.path.join(TARGET_DIR, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=4)
            success_count += 1
            
        time.sleep(1) # Polite delay
        
    print(f"\nFinished scraping The DFIR Report. Saved {success_count} files to {TARGET_DIR}.")

if __name__ == "__main__":
    main()
