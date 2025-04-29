import re
import time
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import configparser

import nltk
from nltk.corpus import stopwords
from collections import Counter
import string

nltk.download('stopwords')
nltk.download('punkt_tab') 

url_to_words = {}
subdomain_counter = {}

# Global sets to track visited and blacklisted URLs
visited_urls = set()
blacklisted_urls = set()
domain_access_time = {}

config = configparser.ConfigParser()
config.read('config.ini')

politeness_delay = float(config['CRAWLER'].get('POLITENESS', 0.5))

def clean_and_tokenize(text):
    tokens = nltk.word_tokenize(text)
    stop_words = set(stopwords.words('english'))
    words = [
        word.lower() for word in tokens
        if word.isalpha() and word.lower() not in stop_words
    ]
    return words

def scraper(url, resp):
    enforce_politeness(url, delay=politeness_delay)
    links = extract_next_links(url, resp)
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
    extracted_links = []

    if resp.status != 200 or resp.raw_response is None or url in blacklisted_urls:
        blacklisted_urls.add(url)
        return extracted_links

    if url in visited_urls:
        return extracted_links

    visited_urls.add(url)


    try:

        page_soup = BeautifulSoup(resp.raw_response.content, "html.parser")
        page_text = page_soup.get_text()
        tokens = re.findall(r'\b\w+\b', page_text)

        words = clean_and_tokenize(page_text)
        url_to_words[url] = words

        parsed = urlparse(url)
        if parsed.netloc.endswith('.uci.edu'):
            subdomain = parsed.netloc
            subdomain_counter[subdomain] = subdomain_counter.get(subdomain, 0) + 1

        # Trap detection: If very few words, treat as low-value page
        #low-value page = small pages filled with ads, redirects, traps
        if len(tokens) < 200:
            blacklisted_urls.add(url)
            return extracted_links

        # Trap detection: check for heavy repetition of sentences
        # Page could be archive pages or fake calendars
        sentences = [s.strip() for s in page_text.split('.') if s.strip()]
        if sentence_repetition(sentences, limit=4) is False:
            blacklisted_urls.add(url)
            return extracted_links

        for tag in page_soup.find_all("a", href=True):
            candidate = urljoin(url, tag['href'])
            candidate = candidate.split('#')[0]             # Removes URL fragment, if URL is https://ics.uci.edu/index.html#section2, removes the fragment #section2 to avoid duplicate URLs

            if candidate in visited_urls or candidate in blacklisted_urls:
                continue  # Skip already seen or blacklisted URLs

            # Avoid certain URL patterns manually
            # Avoid PDFs, publication uploads
            if any(trap in candidate for trap in ["/files/", "/papers/", "/publications/"]):
                blacklist_urls.add(candidate)
                continue

            extracted_links.append(candidate)
            visited_urls.add(candidate)

    except Exception as err:
        print(f"Extraction error for {url}: {err}")

    return extracted_links


def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    
    print(f"Checking URL validity: {url}")

    #add valid domains check
    valid_domains = ["ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu", "today.uci.edu/department/information_computer_sciences"]
  
    # Blacklist patterns (trap URLs)
    trap_keywords = [
        "/calendar", "/event", "?action=login", "timeline?", "/history", "/diff?version=", "?share=", "/?afg", "/img_"
    ]

    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            print("Rejected: Scheme not http/https")
            return False

        if not any(parsed.netloc.endswith(domain) for domain in valid_domains):
            return False

        # Block trap URLs containing suspicious patterns
        for keyword in trap_keywords:
            if keyword in url:
                print(f"Rejected: matched trap keyword {keyword}")
                return False

        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        raise

def sentence_repetition(sentences, limit=3):
    seen = {}
    for sent in sentences:
        if len(sent) > 30:
            seen[sent] = seen.get(sent, 0) + 1
            if seen[sent] >= limit:
                return False
    return True

def enforce_politeness(url, delay=1):
    domain = urlparse(url).netloc
    now = time.time()
    last_access = domain_access_time.get(domain, 0)
    if now - last_access < delay:
        time.sleep(delay - (now-last_access))
    domain_access_time[domain] = time.time()

def print_report():

    stop_words = set(stopwords.words('english'))

    print(f"Number of unique pages: {len(visited_urls)}")

    longest_page = ""
    longest_word_count = 0
    for url in visited_urls:
        if url in url_to_words:
            word_count = len(url_to_words[url])
            if word_count > longest_word_count:
                longest_word_count = word_count
                longest_page = url
    print(f"Longest page URL: {longest_page} ({longest_word_count} words)")

    all_words = []
    for url in url_to_words:
        all_words += url_to_words[url]

    filtered_words = [w.lower() for w in all_words if w.isalpha() and w.lower() not in stop_words]
    counter = Counter(filtered_words)
    most_common_50 = counter.most_common(50)

    print("\nTop 50 most common words:")
    for word, freq in most_common_50:
        print(f"{word}: {freq}")

    subdomains = {}
    for url in visited_urls:
        parsed = urlparse(url)
        netloc = parsed.netloc
        if netloc.endswith(".uci.edu"):
            subdomains[netloc] = subdomains.get(netloc, 0) + 1

    print("\nSubdomains found (alphabetical):")
    for subdomain in sorted(subdomains.keys()):
        print(f"{subdomain}, {subdomains[subdomain]}")