import re
from urllib.parse import urlparse, urljoin, urlunparse
from bs4 import BeautifulSoup
import json
from collections import Counter
from datetime import datetime


STOP_WORDS = set([
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are", "aren't", 
    "as", "at", "be", "because", "been", "before", "being", "below", "between", "both", "but", "by", 
    "can't", "cannot", "could", "couldn't", "did", "didn't", "do", "does", "doesn't", "doing", "don't", 
    "down", "during", "each", "few", "for", "from", "further", "had", "hadn't", "has", "hasn't", "have", 
    "haven't", "having", "he", "he'd", "he'll", "he's", "her", "here", "here's", "hers", "herself", 
    "him", "himself", "his", "how", "how's", "i", "i'd", "i'll", "i'm", "i've", "if", "in", "into", 
    "is", "isn't", "it", "it's", "its", "itself", "let's", "me", "more", "most", "mustn't", "my", 
    "myself", "no", "nor", "not", "of", "off", "on", "once", "only", "or", "other", "ought", "our", 
    "ours", "ourselves", "out", "over", "own", "same", "shan't", "she", "she'd", "she'll", "she's", 
    "should", "shouldn't", "so", "some", "such", "than", "that", "that's", "the", "their", "theirs", 
    "them", "themselves", "then", "there", "there's", "these", "they", "they'd", "they'll", "they're", 
    "they've", "this", "those", "through", "to", "too", "under", "until", "up", "very", "was", "wasn't", 
    "we", "we'd", "we'll", "we're", "we've", "were", "weren't", "what", "what's", "when", "when's", 
    "where", "where's", "which", "while", "who", "who's", "whom", "why", "why's", "with", "won't", 
    "would", "wouldn't", "you", "you'd", "you'll", "you're", "you've", "your", "yours", "yourself", "yourselves"
])

record = {
    "word_freq": Counter(),
    "longest_page": {"url": "", "word_count": 0},
    "unique_urls": set(),
    "subdomains": Counter()
}

def log_trap_or_error(url, status, reason):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] Status: {status} | Reason: {reason} | URL: {url}\n"
    
    with open("detected_traps.txt", "a") as f:
        f.write(log_entry)

def save_stats_to_file():
    sorted_subdomains = {k: v for k, v in sorted(record["subdomains"].items())}
    
    report = {
        "unique_pages_count": len(record["unique_urls"]),
        "longest_page": record["longest_page"],
        "top_50_words": record["word_freq"].most_common(50),
        "subdomains": sorted_subdomains
    }
    
    with open("crawler_results.json", "w") as f:
        json.dump(report, f, indent=4)
        
def scraper(url, resp):
    links = extract_next_links(url, resp)
    
    if resp.status != 200 or not resp.raw_response:
        log_trap_or_error(url, resp.status, "Non-200 Response or Empty Content")
        return [] 
        
    record["unique_urls"].add(url)
    print(f"Current unique pages: {len(record['unique_urls'])} | URL: {url}")
    
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc.lower()
    if hostname.endswith(".uci.edu"):
        record["subdomains"][hostname] += 1
    
    soup = BeautifulSoup(resp.raw_response.content, "lxml")
    raw_text = soup.get_text(separator=" ")
    words = re.findall(r'[a-zA-Z0-9]+', raw_text.lower())
    
    current_word_count = len(words)
    if current_word_count > record["longest_page"]["word_count"]:
        record["longest_page"] = {"url": url, "word_count": current_word_count}
        
    meaningful_words = [w for w in words if len(w) > 1 and w not in STOP_WORDS]
    record["word_freq"].update(meaningful_words)
    
    if len(record["unique_urls"]) % 5 == 0:
        save_stats_to_file()
        print(f"--- 💾 Auto-saved {len(record['unique_urls'])} pages! ---")

    return [link for link in links if is_valid(link)]

def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    output_links = []
    if resp.status == 200 and resp.raw_response:
        soup = BeautifulSoup(resp.raw_response.content, "lxml")
        for anchor in soup.find_all('a', href=True):
            full_url = urljoin(url, anchor['href'])
            parsed = urlparse(full_url)
            clean_url = urlunparse(parsed._replace(fragment=""))
            output_links.append(clean_url)
    return output_links


def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        
        if parsed.scheme not in {"http", "https"}:
            return False
        
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        
        allowed_domains = [
            "ics.uci.edu",
            "cs.uci.edu",
            "informatics.uci.edu",
            "stat.uci.edu"
        ]
        
        is_allowed = False
        for allowed in allowed_domains:
            if domain == allowed or domain.endswith("." + allowed):
                is_allowed = True
                break
        
        if not is_allowed:
            return False

        excluded_pattern = r'\.(css|js|bmp|gif|jpe?g|ico|png|tiff?|mid|mp2|mp3|mp4' \
                          r'|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf|ps|eps|tex' \
                          r'|ppt|pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2' \
                          r'|tar|msi|bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1' \
                          r'|thmx|mso|arff|rtf|jar|csv|rm|smil|wmv|swf|wma' \
                          r'|zip|rar|gz)(?:[?#&]|$)'
        
        if re.search(excluded_pattern, path):
            return False
        
        if parsed.query and re.search(excluded_pattern, parsed.query.lower()):
            return False

        if len(url) > 300:
            return False
        
        path_segments = [s for s in parsed.path.split('/') if s]
        if len(path_segments) > 20:
            return False
        
        if "ics.uci.edu" in domain or "cs.uci.edu" in domain or "stat.uci.edu" in domain:
            if path.startswith("/people") or path.startswith("/happening"):
                return False
        
        if "informatics.uci.edu" in domain:
            if path.startswith("/wp-admin/") and "admin-ajax.php" not in path:
                return False
 
        if "calendar" in path or "event" in path or "events" in path:
            if parsed.query or re.search(r'\d{4}', path):
                return False
        
        if "archive" in domain:
            return False

        if "/datasets/" in path or "/dataset/" in path:
            return False

        wiki_traps = ["do=", "tab_files=", "tab_details=", "rev=", "do=media", "do=edit"]
        if any(trap in query for trap in wiki_traps):
            log_trap_or_error(url, "Blocked", "DokuWiki Trap Detected")
            return False

        if "gitlab.ics.uci.edu" in domain:
            if "/-/commit/" in path or "/-/commits/" in path or "view=" in query:
                return False
            if any(p in path for p in ["/-/blob/", "/-/tree/", "/-/raw/"]):
                return False
        
        return True
        
    except Exception as e:
        return False




































