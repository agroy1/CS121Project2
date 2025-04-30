import re
import time
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import configparser
import threading

import nltk
from nltk.corpus import stopwords
from collections import Counter
import string

nltk.download('stopwords', quiet=True)
nltk.download('punkt_tab', quiet=True)                                                              

# Thread-safe collections using locks
class ThreadSafeDict:
    def __init__(self):
        self.data = {}
        self.lock = threading.RLock()
        
    def __getitem__(self, key):
        with self.lock:
            return self.data.get(key)
            
    def __setitem__(self, key, value):
        with self.lock:
            self.data[key] = value
            
    def get(self, key, default=None):
        with self.lock:
            return self.data.get(key, default)
            
    def __contains__(self, key):
        with self.lock:
            return key in self.data
            
    def items(self):
        with self.lock:
            return list(self.data.items())
            
    def __len__(self):
        with self.lock:
            return len(self.data)

class ThreadSafeSet:
    def __init__(self):
        self.data = set()
        self.lock = threading.RLock()
        
    def add(self, item):
        with self.lock:
            self.data.add(item)
            
    def __contains__(self, item):
        with self.lock:
            return item in self.data
            
    def __len__(self):
        with self.lock:
            return len(self.data)

url_to_words = ThreadSafeDict()
subdomain_counter = ThreadSafeDict()
visited_urls = ThreadSafeSet()
blacklisted_urls = ThreadSafeSet()
domain_access_time = ThreadSafeDict()

file_lock = threading.RLock()
stats_lock = threading.RLock()

page_counter = 0
last_visited_url = None
longest_last_page_url = ""
longest_last_word_count = 0

config = configparser.ConfigParser()
config.read('config.ini')

# politeness_delay = float(config['CRAWLER'].get('POLITENESS', 0.5))  # Re-enabled politeness delay

def update_visited_count_log():
    with file_lock:
        count = len(visited_urls)
        with open("visited_count.txt", "w") as f:
            f.write(f"Visited URLs: {count}\n")

def clean_and_tokenize(text):
    tokens = nltk.word_tokenize(text)
    stop_words = set(stopwords.words('english'))
    words = [
        word.lower() for word in tokens
        if word.isalpha() and word.lower() not in stop_words
    ]
    return words

def scraper(url, resp):
    global page_counter, last_visited_url, longest_last_page_url, longest_last_word_count

    normalized_url = url.split('#')[0]

    if normalized_url in visited_urls or normalized_url in blacklisted_urls:
        return []
        
    # enforce_politeness(normalized_url)  # Re-enabled politeness enforcement

    try:
        thread_name = threading.current_thread().name
        print(f"[{time.strftime('%H:%M:%S')}] {thread_name} Visiting: {normalized_url}")
        
        with stats_lock:
            last_visited_url = normalized_url

        links = extract_next_links(normalized_url, resp)

        if links:
            visited_urls.add(normalized_url)
            
            with stats_lock:
                global page_counter
                page_counter += 1
                if page_counter % 10 == 0:
                    update_visited_count_log()

        return [link for link in links if is_valid(link)]

    except Exception as e:
        with stats_lock:
            print(f"CRASH RECOVERY DUMP — Last URL: {last_visited_url}")
            print(f"Visited: {len(visited_urls)} | Blacklisted: {len(blacklisted_urls)}")
            print(f"Longest page so far: {longest_last_page_url} ({longest_last_word_count} words)")
            print(f"Frontier words mapped: {len(url_to_words)} URLs")
        raise e

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
    
    global longest_last_page_url, longest_last_word_count

    extracted_links = set()

    if resp.status != 200 or resp.raw_response is None or url in blacklisted_urls:
        blacklisted_urls.add(url)
        return list(extracted_links)

    try:

        page_soup = BeautifulSoup(resp.raw_response.content, "html.parser")
        page_text = page_soup.get_text()
        tokens = re.findall(r'\b\w+\b', page_text)

        words = clean_and_tokenize(page_text)
        url_to_words[url] = words
        
        with stats_lock:
            if len(words) > longest_last_word_count:
                longest_last_word_count = len(words)
                longest_last_page_url = url

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
        if len(words) < 5000:
            if not sentence_repetition(page_text.split('.'), limit=5):
                blacklisted_urls.add(url)
                return extracted_links

        for tag in page_soup.find_all("a", href=True):
            candidate = urljoin(url, tag['href'])
            candidate = candidate.split('#')[0]             # Removes URL fragment, if URL is https://ics.uci.edu/index.html#section2, removes the fragment #section2 to avoid duplicate URLs

            if candidate in blacklisted_urls or candidate in visited_urls:
                continue # Skip already seen or blacklisted URLs 

            # Avoid certain URL patterns manually
            # Avoid PDFs, publication uploads
            if any(trap in candidate for trap in ["/files/", "/papers/", "/publications/"]):
                blacklisted_urls.add(candidate)
                continue

            extracted_links.add(candidate)

    except Exception as err:
        print(f"Extraction error for {url}: {err}")

    return list(extracted_links)


def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.

    # print(f"Checking URL validity: {url}")

    #add valid domains check
    valid_domains = ["ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu", "today.uci.edu/department/information_computer_sciences"]
  
    # Blacklist patterns (trap URLs)
    trap_keywords = [
        "/calendar", "/event", "?action=login", "timeline?", "/history", "/diff?version=", "?share=", "/?afg", "/img_"
    ]

    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            # print("Rejected: Scheme not http/https")
            return False

        if not any(parsed.netloc.endswith(domain) for domain in valid_domains):
            return False

        # Block trap URLs containing suspicious patterns
        for keyword in trap_keywords:
            if keyword in url:
                # print(f"Rejected: matched trap keyword {keyword}")
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
        print("TypeError for ", parsed)
        raise

def sentence_repetition(sentences, limit=5):
    seen = {}
    for sent in sentences:
        if len(sent) > 30:
            seen[sent] = seen.get(sent, 0) + 1
            if seen[sent] >= limit:
                return False
    return True

# def enforce_politeness(url, delay=politeness_delay):
#     """
#     Enforce politeness for each domain by ensuring sufficient delay between requests.
#     Each thread will wait if needed to maintain politeness to the same domain.
#     """
#     domain = urlparse(url).netloc
#     now = time.time()
    
#     with threading.RLock():  # Use a lock when checking/updating access times
#         last_access = domain_access_time.get(domain, 0)
#         if now - last_access < delay:
#             sleep_time = delay - (now-last_access)
#             time.sleep(sleep_time)  # Sleep to maintain politeness
#         domain_access_time[domain] = time.time()

def print_report():
    stop_words = set(stopwords.words('english'))

    print(f"Number of unique pages: {len(visited_urls)}")

    longest_page = ""
    longest_word_count = 0
    for url, words in url_to_words.items():
        word_count = len(words)
        if word_count > longest_word_count:
            longest_word_count = word_count
            longest_page = url
    print(f"Longest page URL: {longest_page} ({longest_word_count} words)")

    all_words = []
    for url, words in url_to_words.items():
        all_words.extend(words)

    filtered_words = [w.lower() for w in all_words if w.isalpha() and w.lower() not in stop_words]
    counter = Counter(filtered_words)
    most_common_50 = counter.most_common(50)

    print("\nTop 50 most common words:")
    for word, freq in most_common_50:
        print(f"{word}: {freq}")

    subdomains = {}
    for subdomain, count in subdomain_counter.items():
        subdomains[subdomain] = count

    print("\nSubdomains found (alphabetical):")
    for subdomain in sorted(subdomains.keys()):
        print(f"{subdomain}, {subdomains[subdomain]}")