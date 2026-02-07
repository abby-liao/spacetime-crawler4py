import re
from urllib.parse import urlparse, urljoin, urlunparse
from bs4 import BeautifulSoup
import json
from collections import Counter

STOP_WORDS = {
    "a", "about", "above", "after", "again", "against", "all", "am",
    "an", "and", "any", "are", "aren't", "as", "at",
    "be", "because", "been", "before", "being", "below", "between",
    "both", "but", "by",
    "can't", "cannot", "could", "couldn't",
    "did", "didn't", "do", "does", "doesn't", "doing", "don't",
    "down", "during",
    "each", "few", "for", "from", "further",
    "had", "hadn't", "has", "hasn't", "have", "haven't", "having",
    "he", "he'd", "he'll", "he's", "her", "here", "here's",
    "hers", "herself", "him", "himself", "his",
    "how", "how's",
    "i", "i'd", "i'll", "i'm", "i've",
    "if", "in", "into", "is", "isn't", "it", "it's", "its", "itself",
    "let's",
    "me", "more", "most", "mustn't", "my", "myself",
    "no", "nor", "not",
    "of", "off", "on", "once", "only", "or", "other", "ought",
    "our", "ours"
}

record = {
    "word_freq": Counter(),
    "longest_page": {"url": "", "word_count": 0},
    "unique_urls": set()
}

def save_stats_to_file():
    report = {
        "unique_pages_count": len(record["unique_urls"]),
        "longest_page": record["longest_page"],
        "top_50_words": record["word_freq"].most_common(50),
        "subdomains": Counter()
    }
    
    with open("crawler_results.json", "w") as f:
        json.dump(report, f, indent=4)
        
def scraper(url, resp):
    links = extract_next_links(url, resp)
    if resp.status == 200 and resp.raw_response:
        record["unique_urls"].add(url)
        
        soup = BeautifulSoup(resp.raw_response.content, "lxml")
        raw_text = soup.get_text(separator=" ")
        words = re.findall(r'[a-zA-Z0-9]+', raw_text.lower())
        
        current_word_count = len(words)
        if current_word_count > record["longest_page"]["word_count"]:
            record["longest_page"] = {"url": url, "word_count": current_word_count}
            
        meaningful_words = [w for w in words if len(w) > 1 and w not in STOP_WORDS]
        record["word_freq"].update(meaningful_words)
        
        if len(record["unique_urls"]) % 100 == 0:
            save_stats_to_file()
            print(f"save_stats_to_file {len(record['unique_urls'])} pages! :)")

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
        if parsed.scheme not in set(["http", "https"]):
            return False
        
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        if not path.endswith('/'): path += '/'

        allowed_domains = ["ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu"]
        if not any(domain.endswith(d) for d in allowed_domains):
            return False

        if re.match(r".*\.(css|js|bmp|gif|jpe?g|ico|png|tiff?|mid|mp2|mp3|mp4|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1|thmx|mso|arff|rtf|jar|csv|rm|smil|wmv|swf|wma|zip|rar|gz)$", path):
            return False

        if any(d in domain for d in ["ics.uci.edu", "cs.uci.edu", "stat.uci.edu"]):
            if path.startswith("/people/") or path.startswith("/happening/"):
                return False

        if "informatics.uci.edu" in domain:
            if path.startswith("/wp-admin/"):
                return "admin-ajax.php" in path
            
            if path.startswith("/research/") and path != "/research/":
                allowed_research = [
                    "/research/labs-centers/", "/research/areas-of-expertise/",
                    "/research/example-research-projects/", "/research/phd-research/",
                    "/research/past-dissertations/", "/research/masters-research/",
                    "/research/undergraduate-research/", "/research/gifts-grants/"
                ]
                return any(path.startswith(r) for r in allowed_research)
        
        if "events" in path or "calendar" in path:
            if query or any(char.isdigit() for char in path): 
                return False

        return True
    except Exception as e:
        return False














