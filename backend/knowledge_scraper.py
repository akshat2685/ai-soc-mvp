import requests
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from rag_engine import ingest_text_document

# RSS feeds for major security blogs
SECURITY_FEEDS = [
    {"name": "Google Cloud Security Blog", "url": "https://cloudblog.withgoogle.com/products/identity-security/rss/"},
    {"name": "Microsoft Security Blog", "url": "https://www.microsoft.com/security/blog/feed/"},
    {"name": "Palo Alto Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/"},
    {"name": "Mandiant Blog", "url": "https://www.mandiant.com/resources/blog/rss.xml"},
    {"name": "Cisco Talos", "url": "https://blog.talosintelligence.com/rss/"}
]

def scrape_feed(feed_info, max_articles=5):
    """
    Scrapes the given RSS feed, extracts text from the recent articles,
    and ingests it into the RAG vector database.
    """
    feed_url = feed_info["url"]
    feed_name = feed_info["name"]
    print(f"[SCRAPER] Fetching RSS feed for {feed_name}...")
    
    try:
        # User-Agent to avoid basic 403 Forbidden on RSS feeds
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        resp = requests.get(feed_url, headers=headers, timeout=10)
        
        if resp.status_code != 200:
            print(f"[SCRAPER] Failed to fetch {feed_name}: HTTP {resp.status_code}")
            return
            
        # Parse XML
        root = ET.fromstring(resp.content)
        
        # Depending on RSS/Atom format, items are usually under <channel><item> or <entry>
        items = root.findall(".//item")
        if not items:
            items = root.findall("{http://www.w3.org/2005/Atom}entry")
            
        ingested_count = 0
        for item in items[:max_articles]:
            title = item.find("title")
            title_text = title.text if title is not None else "Unknown Title"
            
            link = item.find("link")
            link_url = link.text if link is not None else ""
            if not link_url and link is not None:
                link_url = link.get("href", "")
                
            # Some feeds include full content in description or content:encoded
            desc = item.find("description")
            content_encoded = item.find("{http://purl.org/rss/1.0/modules/content/}encoded")
            
            html_content = ""
            if content_encoded is not None and content_encoded.text:
                html_content = content_encoded.text
            elif desc is not None and desc.text:
                html_content = desc.text
                
            if html_content:
                # Clean HTML
                soup = BeautifulSoup(html_content, "html.parser")
                clean_text = soup.get_text(separator="\n", strip=True)
                
                # Ingest into RAG Engine
                metadata = {
                    "title": title_text,
                    "source": feed_name,
                    "url": link_url
                }
                
                print(f"  -> Ingesting: {title_text[:50]}...")
                ingest_text_document(clean_text, metadata=metadata)
                ingested_count += 1
                
        print(f"[SCRAPER] Finished {feed_name}. Ingested {ingested_count} articles.")
        
    except Exception as e:
        print(f"[SCRAPER] Error processing {feed_name}: {e}")

def run_knowledge_scraper():
    print("[SCRAPER] Starting Threat Intelligence Knowledge Scraper...")
    for feed in SECURITY_FEEDS:
        scrape_feed(feed, max_articles=3) # Limit to 3 for MVP demo
    print("[SCRAPER] Knowledge Scrape Complete.")

if __name__ == "__main__":
    run_knowledge_scraper()
