import requests
from bs4 import BeautifulSoup
import json
import os
import time
from urllib.parse import urljoin

BASE_URL = "https://cyberdefenders.org"
BLOG_URL = "https://cyberdefenders.org/blog/"
OUTPUT_DIR = os.path.join("data", "raw", "cyberdefenders_blog")

def get_page(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return None

def extract_blog_links(html):
    soup = BeautifulSoup(html, 'html.parser')
    links = set()
    for a in soup.find_all('a', href=True):
        href = a['href']
        if href.startswith('/blog/') and href != '/blog/' and not href.startswith('/blog/?page='):
            links.add(urljoin(BASE_URL, href))
    return list(links)

def parse_article(url, html):
    soup = BeautifulSoup(html, 'html.parser')
    
    title = soup.title.text.strip() if soup.title else "No Title"
    
    # Attempt to find the main content container
    article = soup.find('article') or soup.find('main')
    
    if not article:
        # Fallback if no semantic tags
        article = soup.find('body')
        
    if article:
        # Extract text, removing script and style elements
        for script_or_style in article(['script', 'style']):
            script_or_style.decompose()
        content = article.get_text(separator='\n', strip=True)
    else:
        content = ""
        
    return {
        "url": url,
        "title": title,
        "content": content
    }

def main():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        
    page = 1
    visited_links = set()
    
    while True:
        print(f"Fetching blog index page {page}...")
        url = f"{BLOG_URL}?page={page}"
        if page == 1:
            url = BLOG_URL
            
        html = get_page(url)
        if not html:
            break
            
        links = extract_blog_links(html)
        if not links:
            print("No more links found on this page. Ending pagination.")
            break
            
        new_links = [l for l in links if l not in visited_links]
        if not new_links:
            print("No new links found. Ending pagination.")
            break
            
        for link in new_links:
            print(f"  Scraping article: {link}")
            article_html = get_page(link)
            if article_html:
                article_data = parse_article(link, article_html)
                
                # Create a safe filename from the URL
                filename = link.strip('/').split('/')[-1]
                if not filename or filename == 'blog':
                    filename = f"post_{int(time.time())}"
                
                filepath = os.path.join(OUTPUT_DIR, f"{filename}.json")
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(article_data, f, ensure_ascii=False, indent=4)
                    
                visited_links.add(link)
                time.sleep(1) # Polite delay
                
        # Check if there is a next page indicator in pagination
        soup = BeautifulSoup(html, 'html.parser')
        next_page_link = soup.find('a', href=f"/blog/?page={page+1}")
        if not next_page_link:
            print(f"No link to page {page+1} found. Ending pagination.")
            break
            
        page += 1
        
    print(f"Finished crawling. Total articles collected: {len(visited_links)}")

if __name__ == "__main__":
    main()
