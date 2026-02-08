"""
scraper.py - Core scraper module for the UCI Web Crawler (Assignment 2)

This module implements the main scraping logic:
  1. scraper()           - Entry point called by the crawler framework for each page
  2. extract_next_links() - Extracts and cleans all hyperlinks from a page
  3. is_valid()           - Filters URLs to only crawl allowed domains and avoid traps

Analytics collected (for the report):
  Q1: Unique page count    -> record["unique_urls"]
  Q2: Longest page         -> record["longest_page"]
  Q3: Top 50 common words  -> record["word_freq"]
  Q4: Subdomains of *.ics.uci.edu -> record["subdomains"]

Results are periodically saved to crawler_results.json.
Detected traps/errors are logged to detected_traps.txt for monitoring.
"""

import re
from urllib.parse import urlparse, urljoin, urlunparse
from bs4 import BeautifulSoup
import json
from collections import Counter
from datetime import datetime


# =============================================================================
# STOP WORDS
# =============================================================================
# English stop words list from https://www.ranks.nl/stopwords
# Used in Q3 to filter out common words when computing word frequencies.
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


# =============================================================================
# GLOBAL ANALYTICS RECORD
# =============================================================================
# This dictionary persists across all calls to scraper() during a single crawl run.
# It collects the data needed to answer the 4 report questions.
record = {
    "word_freq": Counter(),                          # Q3: word -> count (excluding stop words)
    "longest_page": {"url": "", "word_count": 0},    # Q2: tracks the page with most words
    "unique_urls": set(),                             # Q1: set of all unique defragmented URLs
    "subdomains": Counter()                           # Q4: subdomain -> unique page count (*.ics.uci.edu only)
}

# Tracks how many times each generalized URL pattern has been seen.
# Used to detect infinite traps (e.g., calendar pages generating endless links).
# If the same pattern appears >100 times, we stop following it.
url_pattern_counter = Counter()


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def log_trap_or_error(url, status, reason):
    """
    Append a log entry to detected_traps.txt for monitoring purposes.
    Helps us identify problematic URLs, traps, and dead pages during/after the crawl.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] Status: {status} | Reason: {reason} | URL: {url}\n"
    try:
        with open("detected_traps.txt", "a") as f:
            f.write(log_entry)
    except Exception:
        pass  # Don't let logging failures crash the crawler


def save_stats_to_file():
    """
    Save current analytics to crawler_results.json.
    Called every 10 unique pages so we don't lose progress if the crawler crashes.
    The JSON file contains all data needed to generate the final report.
    """
    try:
        # Sort subdomains alphabetically as required by Q4
        sorted_subdomains = {k: v for k, v in sorted(record["subdomains"].items())}

        report = {
            "unique_pages_count": len(record["unique_urls"]),
            "longest_page": record["longest_page"],
            "top_50_words": record["word_freq"].most_common(50),
            "subdomains": sorted_subdomains
        }

        with open("crawler_results.json", "w") as f:
            json.dump(report, f, indent=4)
    except Exception as e:
        print(f"Error saving stats: {e}")


def get_url_pattern(url):
    """
    Convert a URL into a generalized pattern for trap detection.
    Replaces numeric segments and hex hashes with '<ID>' placeholders,
    so that URLs like /page/1, /page/2, /page/3 all map to the same pattern.

    Example:
        https://example.com/blog/2024/post/abc123
        -> example.com/blog/<ID>/post/<ID>
    """
    parsed = urlparse(url)
    segments = [s for s in parsed.path.split('/') if s]
    normalized = []
    for seg in segments:
        # Replace pure numbers (e.g., page IDs, years) and hex strings (commit hashes)
        if re.match(r'^[\d]+$', seg) or re.match(r'^[a-f0-9]{6,}$', seg):
            normalized.append('<ID>')
        else:
            normalized.append(seg)
    return parsed.netloc + '/' + '/'.join(normalized)


def is_low_information(text, words):
    """
    Determine if a page has too little textual content to be useful.
    Pages with fewer than 25 words are likely error pages, empty templates,
    or redirect stubs — not worth indexing or extracting links from.
    """
    if len(words) < 25:
        return True
    return False


# =============================================================================
# MAIN SCRAPER FUNCTION
# =============================================================================

def scraper(url, resp):
    """
    Main entry point called by the crawler framework for each fetched page.

    Workflow:
      1. Validate the HTTP response (status code, content existence)
      2. Filter out non-HTML content and oversized files
      3. Deduplicate URLs (skip if already processed)
      4. Parse HTML and extract text
      5. Skip low-information pages
      6. Detect infinite traps via URL pattern analysis
      7. Collect analytics (unique count, longest page, word freq, subdomains)
      8. Extract and return valid outgoing links

    Args:
        url:  The URL that was fetched
        resp: The response object from the crawler framework
              - resp.status: HTTP status code
              - resp.raw_response: the actual HTTP response (has .content and .headers)
              - resp.error: error message if status != 200

    Returns:
        List of valid URLs (strings) to be added to the crawl frontier
    """

    # --- Step 1: Validate HTTP response ---
    # Only process pages with status 200; log errors for monitoring
    if resp.status != 200:
        if resp.status >= 600:
            # 600+ codes are custom errors from the course cache server
            log_trap_or_error(url, resp.status, "Cache server error")
        elif resp.status != 301 and resp.status != 302:
            # 301/302 are redirects handled by the framework, no need to log
            log_trap_or_error(url, resp.status, f"HTTP error {resp.status}")
        return []

    # Check for dead URLs: status 200 but empty content body
    if not resp.raw_response or not resp.raw_response.content:
        log_trap_or_error(url, resp.status, "200 but empty content (dead URL)")
        return []

    # --- Step 2: Check content type ---
    # Only process HTML pages; skip PDFs, images, etc. that might return 200
    content_type = resp.raw_response.headers.get('Content-Type', '')
    if content_type and 'text/html' not in content_type.lower():
        return []

    # --- Step 3: Check content size ---
    # Avoid processing very large files (>10MB) which are likely data dumps
    content_length = len(resp.raw_response.content)
    if content_length > 10 * 1024 * 1024:
        log_trap_or_error(url, resp.status, f"Very large file: {content_length} bytes")
        return []

    # --- Step 4: URL deduplication ---
    # Remove fragment (e.g., #section) and check if we've already processed this URL.
    # Per assignment spec: http://page#aaa and http://page#bbb are the same URL.
    parsed_url = urlparse(url)
    clean_url = urlunparse(parsed_url._replace(fragment=""))
    if clean_url in record["unique_urls"]:
        return []  # Already visited — skip to avoid double-counting analytics

    # --- Step 5: Parse HTML and extract text ---
    try:
        soup = BeautifulSoup(resp.raw_response.content, "lxml")
    except Exception as e:
        log_trap_or_error(url, resp.status, f"HTML parse error: {e}")
        return []

    # Extract visible text (excludes HTML tags, scripts, styles)
    raw_text = soup.get_text(separator=" ")
    # Tokenize: only keep alphabetic words (no numbers, no punctuation)
    words = re.findall(r'[a-zA-Z]+', raw_text.lower())

    # --- Step 6: Skip low-information pages ---
    # Pages with very few words are likely empty templates or error pages
    if is_low_information(raw_text, words):
        log_trap_or_error(url, "LowInfo", f"Only {len(words)} words")
        return []

    # --- Step 7: Trap detection via URL pattern frequency ---
    # If the same URL structure (e.g., /calendar/<ID>/<ID>) appears 100+ times,
    # it's likely an infinite trap generating endless similar pages
    pattern = get_url_pattern(clean_url)
    url_pattern_counter[pattern] += 1
    if url_pattern_counter[pattern] > 100:
        log_trap_or_error(url, "Trap", f"Pattern seen {url_pattern_counter[pattern]} times: {pattern}")
        return []

    # --- Step 8: Record analytics for the report ---

    # Q1: Add to unique pages set
    record["unique_urls"].add(clean_url)
    print(f"[{len(record['unique_urls'])}] {clean_url}")

    # Q4: Track subdomains — assignment asks specifically about *.ics.uci.edu
    hostname = parsed_url.netloc.lower()
    if hostname.endswith(".ics.uci.edu") or hostname == "ics.uci.edu":
        record["subdomains"][hostname] += 1

    # Q2: Track the longest page by word count
    current_word_count = len(words)
    if current_word_count > record["longest_page"]["word_count"]:
        record["longest_page"] = {"url": clean_url, "word_count": current_word_count}

    # Q3: Update word frequencies (exclude stop words and single-character tokens)
    meaningful_words = [w for w in words if len(w) > 1 and w not in STOP_WORDS]
    record["word_freq"].update(meaningful_words)

    # --- Step 9: Periodically save stats to disk ---
    # Save every 10 pages so we have progress even if the crawler crashes
    if len(record["unique_urls"]) % 10 == 0:
        save_stats_to_file()

    # --- Step 10: Extract outgoing links and filter ---
    # Pass the already-parsed soup object to avoid parsing HTML twice
    links = extract_next_links(clean_url, resp, soup)
    return [link for link in links if is_valid(link)]


# =============================================================================
# LINK EXTRACTION
# =============================================================================

def extract_next_links(url, resp, soup=None):
    """
    Extract all hyperlinks (<a href="...">) from the parsed HTML page.

    For each link found:
      - Resolve relative URLs to absolute using urljoin
      - Remove the fragment part (#...)
      - Skip javascript:, mailto:, and tel: links

    Args:
        url:  The base URL of the current page (used to resolve relative links)
        resp: The response object (not used directly since we pass soup)
        soup: Pre-parsed BeautifulSoup object to avoid double-parsing

    Returns:
        List of cleaned, absolute URL strings
    """
    output_links = []
    if soup is None:
        return output_links

    for anchor in soup.find_all('a', href=True):
        href = anchor['href'].strip()

        # Skip non-HTTP links (javascript actions, email links, phone links)
        if not href or href.startswith(('javascript:', 'mailto:', 'tel:')):
            continue

        # Convert relative URLs (e.g., "/about") to absolute (e.g., "https://site.com/about")
        full_url = urljoin(url, href)

        # Remove fragment — per assignment spec, fragments don't make URLs unique
        parsed = urlparse(full_url)
        clean_url = urlunparse(parsed._replace(fragment=""))
        clean_url = clean_url.strip()

        if clean_url:
            output_links.append(clean_url)

    return output_links


# =============================================================================
# URL VALIDATION
# =============================================================================

def is_valid(url):
    """
    Determine whether a URL should be crawled.

    Checks performed (in order):
      1. Scheme must be http or https
      2. Domain must be in the allowed list (*.ics.uci.edu, *.cs.uci.edu, etc.)
      3. File extension must not be a binary/non-HTML type
      4. URL length and path depth limits (trap avoidance)
      5. Repeating path segments (infinite loop detection)
      6. Calendar/event trap patterns (date-parameterized pages)
      7. Known problematic domains and paths
      8. DokuWiki, GitLab, WordPress-specific trap patterns
      9. Share/feed/action links that generate infinite variations
      10. Pagination with extremely high page numbers

    Args:
        url: The URL string to validate

    Returns:
        True if the URL should be crawled, False otherwise
    """
    try:
        parsed = urlparse(url)

        # --- Check 1: Scheme ---
        if parsed.scheme not in {"http", "https"}:
            return False

        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()

        # --- Check 2: Domain whitelist ---
        # Only crawl URLs within the 4 allowed domains specified in the assignment
        allowed_domains = [
            "ics.uci.edu",
            "cs.uci.edu",
            "informatics.uci.edu",
            "stat.uci.edu"
        ]

        is_allowed = False
        for allowed in allowed_domains:
            # Match exact domain (e.g., "ics.uci.edu") or any subdomain (e.g., "vision.ics.uci.edu")
            if domain == allowed or domain.endswith("." + allowed):
                is_allowed = True
                break

        if not is_allowed:
            return False

        # --- Check 3: File extension filter ---
        # Block binary files, documents, media, archives, and code files.
        # These are not HTML pages and won't contain useful text for searching.
        excluded_pattern = r'\.(css|js|bmp|gif|jpe?g|ico|png|tiff?|mid|mp2|mp3|mp4' \
                          r'|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf|ps|eps|tex' \
                          r'|ppt|pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2' \
                          r'|tar|msi|bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1' \
                          r'|thmx|mso|arff|rtf|jar|csv|rm|smil|wmv|swf|wma' \
                          r'|zip|rar|gz|sql|json|xml|rss|atom|apk|img|bak' \
                          r'|mpg|flv|odc|ipynb|py|java|c|cpp|h|r|m|nb|mat|sas)(?:[?#&]|$)'

        if re.search(excluded_pattern, path):
            return False

        # Also check query string for file extensions (e.g., ?file=data.csv)
        if parsed.query and re.search(excluded_pattern, query):
            return False

        # --- Check 4: URL length and path depth limits ---
        # Very long URLs or deeply nested paths are often signs of infinite traps
        if len(url) > 250:
            return False

        path_segments = [s for s in parsed.path.split('/') if s]
        if len(path_segments) > 15:
            return False

        # --- Check 5: Repeating path segments ---
        # Patterns like /a/b/a/b/a/b indicate an infinite directory loop
        if len(path_segments) != len(set(path_segments)):
            for seg in path_segments:
                # If any non-trivial segment appears 3+ times, it's likely a trap
                if len(seg) > 2 and path_segments.count(seg) >= 3:
                    return False

        # --- Check 6: Calendar/event trap patterns ---
        # Calendar systems often generate infinite pages with different date parameters.
        # We use specific regex patterns instead of broadly blocking all "event" URLs,
        # since some legitimate research pages may contain "event" in their path.
        calendar_trap_patterns = [
            r'/calendar.*[\?&](date|month|year|day)=',       # Calendar with date query params
            r'/events?/\d{4}[-/]\d{2}',                      # /event/2024-01 or /events/2024/01
            r'/events?/.*[\?&](date|month|year|start|end)=',  # Events with date filters
            r'/(calendar|events?)/\d{4}/?$',                  # /calendar/2024
            r'/(calendar|events?)/\d{4}/\d{2}',              # /calendar/2024/01
            r'/day/',                                         # Day view pages
            r'/week/',                                        # Week view pages
        ]
        full_path_query = path + ('?' + query if query else '')
        for pattern in calendar_trap_patterns:
            if re.search(pattern, full_path_query):
                return False

        # --- Check 7: Known problematic domains and paths ---
        # "archive" subdomains tend to have massive amounts of duplicate/low-value content
        if "archive" in domain:
            return False

        # Dataset pages are usually large data files, not useful HTML content
        if "/datasets/" in path or "/dataset/" in path:
            return False

        # --- Check 8a: DokuWiki traps ---
        # DokuWiki generates many action URLs (edit, revisions, diff, etc.)
        # that create infinite variations of the same page
        wiki_traps = ["do=edit", "do=media", "do=revisions", "do=backlink",
                      "do=diff", "do=admin", "do=recent", "do=index",
                      "tab_files=", "tab_details=", "rev=", "image=",
                      "do=login", "do=export"]
        if any(trap in query for trap in wiki_traps):
            return False

        # --- Check 8b: GitLab traps ---
        # GitLab repositories have many auto-generated pages (commits, blobs, diffs, etc.)
        # that are not useful text content and can trap a crawler indefinitely
        if "gitlab" in domain:
            gitlab_traps = ["/-/commit/", "/-/commits/", "/-/blob/", "/-/tree/",
                           "/-/raw/", "/-/blame/", "/-/merge_requests/",
                           "/-/issues/", "/-/pipelines/", "/-/jobs/",
                           "/-/tags/", "/-/branches/", "/-/compare/"]
            if any(trap in path for trap in gitlab_traps):
                return False
            if "view=" in query:
                return False

        # --- Check 8c: WordPress admin pages ---
        # wp-admin pages require login and have no useful public content
        if "informatics.uci.edu" in domain:
            if "/wp-admin/" in path:
                return False

        # --- Check 9: Share/action/feed links ---
        # These generate infinite URL variations and contain no unique text content
        share_traps = ["share=", "replytocom=", "action=login", "action=edit",
                       "action=download", "format=xml", "format=json",
                       "feed=", "/feed/", "/rss/", "/atom/"]
        for trap in share_traps:
            if trap in (path + '?' + query):
                return False

        # --- Check 10: Pagination trap ---
        # Block pages with very high page numbers (likely auto-generated or infinite)
        page_match = re.search(r'[?&]page=(\d+)', query)
        if page_match and int(page_match.group(1)) > 50:
            return False

        # All checks passed — this URL is safe to crawl
        return True

    except Exception as e:
        # If anything goes wrong during URL parsing, skip this URL to be safe
        return False
