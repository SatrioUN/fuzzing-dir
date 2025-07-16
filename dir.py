import requests
import threading
import queue
import argparse
import sys
import os
import time
import json
import re
from hashlib import md5
import hashlib
import signal
import random
from urllib.parse import urlparse, urljoin, quote
from bs4 import BeautifulSoup
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from datetime import datetime
import warnings
warnings.filterwarnings('ignore', category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

def print_banner():
    BLUE_BRIGHT = "\033[94m"  
    RESET = "\033[0m"         

    banner = f"""
{BLUE_BRIGHT} ____  ___   ___ 
|  _ \\|_ _| / _ \\
| |_) || | | | | |
|  _ < | | | |_| |
|_| \\_\\___| \\___/ 
============================================================================================
development : rioocns
===========================================================================================
Description : Halo! Kamu lagi pakai alat fuzzer direktori sensitif yang powerful dan robust.
Alat ini dilengkapi dengan fitur-fitur canggih seperti AI-powered path prediction,
adaptive threading, advanced evasion, real-time vulnerability detection,
machine learning untuk menyaring false positive, comprehensive reporting,
dan juga integrasi cloud untuk kemudahan penggunaan.
============================================================================================
Note:
Alat ini dirancang untuk membantu kamu dalam pengujian keamanan aplikasi web.
Selamat mencoba dan semoga alat ini membantu kamu dalam pengujian keamanan.
Dan pastikan untuk selalu mematuhi etika dan hukum yang berlaku saat melakukan pengujian keamanan!{RESET}
"""
    print(banner)

if __name__ == "__main__":
    print_banner()

class ColoredOutput:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class EnhancedDirFuzzer:
    COMMON_EXTENSIONS = ['', '.php', '.html', '.htm', '.asp', '.aspx', '.jsp', '.js', '.json', '.xml', '.txt', 
                        '.bak', '.old', '.orig', '.backup', '.tmp', '.swp', '.save', '.zip', '.tar.gz', '.rar',
                        '.sql', '.db', '.log', '.conf', '.config', '.ini', '.env', '.key', '.pem', '.crt',
                        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.csv', '.tar', '.gz', '.7z']
    
    PAYLOADS = {
        'traversal': ['../', '../../', '../../../', '..../', '...../', '..\\', '..\\..\\', '..\\..\\..\\'],
        'backup': ['~', '.bak', '.backup', '.old', '.orig', '.tmp', '.save', '.swp', '.copy'],
        'sensitive': ['.env', '.git', '.svn', '.htaccess', '.htpasswd', 'web.config', 'config.php', 'database.php']
    }
    
    STATUS_COLORS = {
        200: ColoredOutput.GREEN,
        201: ColoredOutput.GREEN,
        204: ColoredOutput.GREEN,
        301: ColoredOutput.BLUE,
        302: ColoredOutput.BLUE,
        307: ColoredOutput.BLUE,
        308: ColoredOutput.BLUE,
        401: ColoredOutput.YELLOW,
        403: ColoredOutput.YELLOW,
        405: ColoredOutput.YELLOW,
        500: ColoredOutput.RED,
        502: ColoredOutput.RED,
        503: ColoredOutput.RED
    }

    def __init__(self, url, wordlist, threads=20, timeout=10, retries=3, rate_limit=0,
                 output=None, output_json=None, user_agent=None, proxy=None,
                 enable_receiver=False, enable_crawl=False, max_crawl_depth=3, verbose=False,
                 recursive=False, extensions=None, exclude_status=None, include_status=None,
                 follow_redirects=False, verify_ssl=True, custom_headers=None, 
                 random_agent=False, stealth_mode=False, brute_force=False, 
                 content_discovery=False, technology_detection=False, smart_filter=True,
                 export_html=False, resume_scan=False, save_responses=False):
        
        self.url = url.rstrip('/')
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.retries = retries
        self.rate_limit = rate_limit
        self.output = output
        self.output_json = output_json
        self.recursive = recursive
        self.extensions = extensions or self.COMMON_EXTENSIONS
        self.exclude_status = exclude_status or []
        self.include_status = include_status or [200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500, 502, 503]
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.custom_headers = custom_headers or {}
        self.random_agent = random_agent
        self.stealth_mode = stealth_mode
        self.brute_force = brute_force
        self.content_discovery = content_discovery
        self.technology_detection = technology_detection
        self.smart_filter = smart_filter
        self.export_html = export_html
        self.resume_scan = resume_scan
        self.save_responses = save_responses
        
        self.enable_receiver = enable_receiver
        self.enable_crawl = enable_crawl
        self.max_crawl_depth = max_crawl_depth
        self.verbose = verbose

        # User agents pool
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
            user_agent or "Mozilla/5.0 (compatible; EnhancedDirFuzzer/2.0; +https://github.com/security-tools)"
        ]

        self.q = queue.Queue()
        self.lock = threading.Lock()
        self.found = []
        self.errors = []
        self.stop_receiver = threading.Event()
        self.session_lock = threading.Lock()
        
        # Statistics
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'start_time': None,
            'directories_found': 0,
            'files_found': 0,
            'interesting_files': 0
        }

        # Create session with connection pooling and retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=self.retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=self.threads, pool_maxsize=self.threads)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        if proxy:
            self.session.proxies.update({'http': proxy, 'https': proxy})

        self.headers = {'User-Agent': self.get_user_agent()}
        self.headers.update(self.custom_headers)

        # Content analysis
        self.not_found_signatures = []
        self.content_signatures = {}
        
        # Path management
        self.tested_paths = set()
        self.crawl_depths = {}
        self.interesting_patterns = [
            r'admin', r'login', r'dashboard', r'panel', r'config', r'backup', r'database',
            r'api', r'test', r'dev', r'staging', r'debug', r'upload', r'download'
        ]
        
        # Resume functionality
        self.resume_file = f"resume_{self.get_domain_hash()}.json"
        
        # Technology detection patterns
        self.tech_patterns = {
            'PHP': [r'\.php', r'phpmyadmin', r'wp-admin', r'wordpress'],
            'ASP.NET': [r'\.aspx?', r'web\.config', r'bin/', r'App_Data'],
            'JSP': [r'\.jsp', r'WEB-INF', r'struts'],
            'Python': [r'\.py', r'django', r'flask', r'__pycache__'],
            'Node.js': [r'package\.json', r'node_modules', r'\.js$'],
            'Java': [r'\.java', r'\.class', r'\.jar'],
            'Ruby': [r'\.rb', r'Gemfile', r'config\.ru'],
            'Go': [r'\.go', r'main\.go']
        }

        # Signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, signum, frame):
        print(f"\n{ColoredOutput.YELLOW}[!] Received interrupt signal. Saving progress...{ColoredOutput.ENDC}")
        self.save_progress()
        sys.exit(0)

    def get_domain_hash(self):
        return hashlib.md5(self.url.encode()).hexdigest()[:8]

    def get_user_agent(self):
        if self.random_agent:
            return random.choice(self.user_agents)
        return self.user_agents[-1]

    def log(self, msg, color=None):
        if self.verbose:
            with self.lock:
                if color:
                    print(f"{color}{msg}{ColoredOutput.ENDC}")
                else:
                    print(msg)

    def validate_url(self):
        parsed = urlparse(self.url)
        if not parsed.scheme or not parsed.netloc:
            print(f"{ColoredOutput.RED}[!] Invalid URL: {self.url}{ColoredOutput.ENDC}")
            sys.exit(1)

    def load_wordlist(self):
        if not os.path.isfile(self.wordlist):
            print(f"{ColoredOutput.RED}[!] Wordlist file not found: {self.wordlist}{ColoredOutput.ENDC}")
            sys.exit(1)
        
        print(f"{ColoredOutput.CYAN}[*] Loading wordlist from: {self.wordlist}{ColoredOutput.ENDC}")
        
        try:
            with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
                
            # Filter duplicate words
            unique_words = list(set(words))
            
            # Add payloads if brute force is enabled
            if self.brute_force:
                for payload_type, payloads in self.PAYLOADS.items():
                    for word in unique_words[:]:
                        for payload in payloads:
                            unique_words.append(f"{payload}{word}")
                            unique_words.append(f"{word}{payload}")
            
            # Add to queue
            for word in unique_words:
                with self.lock:
                    if word not in self.tested_paths:
                        self.q.put(word)
                        self.tested_paths.add(word)
                        self.crawl_depths[word] = 0
                        
            print(f"{ColoredOutput.GREEN}[*] Loaded {len(unique_words)} unique words{ColoredOutput.ENDC}")
            
        except Exception as e:
            print(f"{ColoredOutput.RED}[!] Error loading wordlist: {e}{ColoredOutput.ENDC}")
            sys.exit(1)

    def get_content_signatures(self):
        """Get signatures for different response types"""
        test_paths = [
            "/thispagedoesnotexist1234567890",
            "/nonexistent" + str(random.randint(1000, 9999)),
            "/404error" + str(random.randint(1000, 9999))
        ]
        
        signatures = []
        for test_path in test_paths:
            try:
                resp = self.session.get(
                    self.url + test_path, 
                    headers=self.headers, 
                    timeout=self.timeout, 
                    allow_redirects=False,
                    verify=self.verify_ssl
                )
                
                signature = {
                    'status': resp.status_code,
                    'length': len(resp.content),
                    'content_hash': hashlib.md5(resp.content).hexdigest(),
                    'title': self.extract_title(resp.text),
                    'headers': dict(resp.headers)
                }
                signatures.append(signature)
                
            except Exception as e:
                self.log(f"[!] Failed to get signature for {test_path}: {e}", ColoredOutput.RED)
        
        self.not_found_signatures = signatures
        self.log(f"[*] Captured {len(signatures)} not-found signatures", ColoredOutput.CYAN)

    def extract_title(self, html):
        try:
            soup = BeautifulSoup(html, 'html.parser')
            title = soup.find('title')
            return title.get_text().strip() if title else None
        except:
            return None

    def is_false_positive(self, response):
        if not self.smart_filter or not self.not_found_signatures:
            return False
            
        current_signature = {
            'status': response.status_code,
            'length': len(response.content),
            'content_hash': hashlib.md5(response.content).hexdigest(),
            'title': self.extract_title(response.text)
        }
        
        for signature in self.not_found_signatures:
            if (current_signature['content_hash'] == signature['content_hash'] or
                (current_signature['length'] == signature['length'] and 
                 current_signature['title'] == signature['title'])):
                return True
        
        return False

    def detect_technology(self, response, url):
        """Detect web technologies based on response"""
        technologies = []
        content = response.text.lower()
        headers = response.headers
        
        # Header-based detection
        if 'server' in headers:
            server = headers['server'].lower()
            if 'apache' in server:
                technologies.append('Apache')
            elif 'nginx' in server:
                technologies.append('Nginx')
            elif 'iis' in server:
                technologies.append('IIS')
        
        if 'x-powered-by' in headers:
            powered_by = headers['x-powered-by'].lower()
            if 'php' in powered_by:
                technologies.append('PHP')
            elif 'asp.net' in powered_by:
                technologies.append('ASP.NET')
        
        # Content-based detection
        for tech, patterns in self.tech_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    technologies.append(tech)
                    break
        
        return list(set(technologies))

    def is_interesting_file(self, path):
        """Check if the file is interesting based on patterns"""
        interesting_extensions = ['.env', '.config', '.sql', '.db', '.log', '.bak', '.old', '.backup']
        
        for ext in interesting_extensions:
            if path.endswith(ext):
                return True
        
        for pattern in self.interesting_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                return True
                
        return False

    def analyze_response(self, response, url, path):
        """Analyze response for interesting content"""
        analysis = {
            'content_type': response.headers.get('content-type', ''),
            'content_length': len(response.content),
            'technologies': self.detect_technology(response, url),
            'interesting': self.is_interesting_file(path),
            'title': self.extract_title(response.text),
            'forms': len(re.findall(r'<form', response.text, re.IGNORECASE)),
            'inputs': len(re.findall(r'<input', response.text, re.IGNORECASE)),
            'links': len(re.findall(r'<a\s+href', response.text, re.IGNORECASE))
        }
        
        # Check for sensitive information
        sensitive_patterns = [
            r'password', r'api[_-]?key', r'secret', r'token', r'database',
            r'db[_-]?password', r'admin', r'root', r'config'
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                analysis['sensitive_content'] = True
                break
        
        return analysis

    def try_request(self, url, path):
        """Make HTTP request with improved error handling"""
        if self.random_agent:
            self.headers['User-Agent'] = self.get_user_agent()
            
        if self.stealth_mode:
            time.sleep(random.uniform(0.5, 2.0))
            
        for attempt in range(self.retries + 1):
            try:
                with self.session_lock:
                    self.stats['total_requests'] += 1
                    
                resp = self.session.get(
                    url, 
                    headers=self.headers, 
                    timeout=self.timeout, 
                    allow_redirects=self.follow_redirects,
                    verify=self.verify_ssl
                )
                
                with self.session_lock:
                    self.stats['successful_requests'] += 1
                    
                return resp
                
            except requests.RequestException as e:
                if attempt == self.retries:
                    with self.lock:
                        self.errors.append((url, str(e)))
                        self.stats['failed_requests'] += 1
                    self.log(f"[!] Request failed for {url}: {e}", ColoredOutput.RED)
                else:
                    time.sleep(2 ** attempt)  # Exponential backoff
        
        return None

    def extract_links(self, html, base_url):
        """Extract links from HTML content"""
        links = set()
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Extract from different elements
            for element in soup.find_all(['a', 'link', 'script', 'img', 'form'], href=True):
                href = element.get('href') or element.get('src') or element.get('action')
                if href:
                    abs_url = urljoin(base_url, href.strip())
                    parsed_base = urlparse(self.url)
                    parsed_abs = urlparse(abs_url)
                    
                    if parsed_base.netloc == parsed_abs.netloc:
                        path = parsed_abs.path.lstrip('/')
                        if path and not path.startswith('http'):
                            links.add(path)
            
            # Extract from JavaScript
            js_patterns = [
                r'["\']([^"\']*\.(?:php|html|jsp|asp|aspx|js|css|json|xml))["\']',
                r'url\s*:\s*["\']([^"\']+)["\']',
                r'href\s*=\s*["\']([^"\']+)["\']'
            ]
            
            for pattern in js_patterns:
                matches = re.findall(pattern, html, re.IGNORECASE)
                for match in matches:
                    if not match.startswith(('http://', 'https://', '//')):
                        links.add(match.lstrip('/'))
                        
        except Exception as e:
            self.log(f"[!] Error extracting links: {e}", ColoredOutput.RED)
        
        return links

    def save_response(self, response, path):
        """Save response content to file"""
        if not self.save_responses:
            return
            
        responses_dir = f"responses_{self.get_domain_hash()}"
        os.makedirs(responses_dir, exist_ok=True)
        
        safe_path = re.sub(r'[^\w\-_\.]', '_', path)
        filepath = os.path.join(responses_dir, f"{safe_path}.html")
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(response.text)
        except Exception as e:
            self.log(f"[!] Error saving response: {e}", ColoredOutput.RED)

    def worker(self):
        """Enhanced worker thread"""
        while True:
            try:
                path = self.q.get(timeout=1)
            except queue.Empty:
                if self.enable_receiver and not self.stop_receiver.is_set():
                    continue
                else:
                    break

import argparse
import concurrent.futures
import json
import os
import queue
import random
import re
import threading
import time
from datetime import datetime
from hashlib import md5
from urllib.parse import urljoin, urlparse, quote

import requests
from bs4 import BeautifulSoup

# --- Helper Classes for Colored Output ---

class ColoredOutput:
    HEADER = '\033[95m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    ENDC = '\033[0m'
    WHITE = '\033[97m'

# --- Utility Functions ---

def normalize_url(url):
    parsed = urlparse(url)
    scheme = parsed.scheme or 'http'
    netloc = parsed.netloc
    path = parsed.path if parsed.path else '/'
    return f"{scheme}://{netloc}{path}"

def hash_content(content):
    return md5(content).hexdigest()

def load_wordlist(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

def random_delay(min_delay=0.1, max_delay=1.0):
    time.sleep(random.uniform(min_delay, max_delay))

# --- Main Fuzzer Class ---

class EnhancedDirFuzzer:
    def __init__(self, url, wordlist_path, threads=20, timeout=10, retries=3,
                 rate_limit=10, output=None, output_json=None, user_agent=None,
                 proxy=None, enable_receiver=False, enable_crawl=False,
                 max_crawl_depth=3, verbose=False, recursive=False,
                 extensions=None, exclude_status=None, include_status=None,
                 follow_redirects=False, verify_ssl=True, custom_headers=None,
                 random_agent=False, stealth_mode=False, brute_force=False,
                 content_discovery=False, technology_detection=False,
                 smart_filter=True, export_html=False, resume_scan=False,
                 save_responses=False):

        self.url = normalize_url(url)
        self.wordlist_path = wordlist_path
        self.threads = threads
        self.timeout = timeout
        self.retries = retries
        self.rate_limit = rate_limit  # global requests per second
        self.output = output
        self.output_json = output_json
        self.user_agent = user_agent or "Mozilla/5.0 (compatible; DirFuzzer/1.0)"
        self.proxy = proxy
        self.enable_receiver = enable_receiver
        self.enable_crawl = enable_crawl
        self.max_crawl_depth = max_crawl_depth
        self.verbose = verbose
        self.recursive = recursive
        self.extensions = extensions or ['', '.php', '.html', '.bak', '.old', '.txt']
        self.exclude_status = set(exclude_status or [])
        self.include_status = set(include_status) if include_status else None
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.custom_headers = custom_headers or {}
        self.random_agent = random_agent
        self.stealth_mode = stealth_mode
        self.brute_force = brute_force
        self.content_discovery = content_discovery
        self.technology_detection = technology_detection
        self.smart_filter = smart_filter
        self.export_html = export_html
        self.resume_scan = resume_scan
        self.save_responses = save_responses

        self.q = queue.Queue()
        self.lock = threading.Lock()
        self.rate_limit_lock = threading.Lock()
        self.last_request_time = 0

        self.tested_paths = set()
        self.crawl_depths = {}
        self.found = []
        self.errors = []
        self.stats = {
            'start_time': None,
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'directories_found': 0,
            'files_found': 0,
            'interesting_files': 0,
        }

        self.stop_receiver = threading.Event()
        self.resume_file = f"dirfuzzer_resume_{md5(self.url.encode()).hexdigest()}.json"

        # Preload wordlist
        self.wordlist = []
        self.load_wordlist()

        # Setup headers
        self.headers = self.build_headers()

        # Proxy dict for requests
        self.proxies = {'http': self.proxy, 'https': self.proxy} if self.proxy else None

        # Content signatures for false positive detection
        self.content_signatures = set()

    def build_headers(self):
        headers = self.custom_headers.copy()
        if self.random_agent:
            headers['User-Agent'] = self.get_random_user_agent()
        else:
            headers['User-Agent'] = self.user_agent
        return headers

    def get_random_user_agent(self):
        # Minimal list, can be extended or replaced with external lib
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
            " Chrome/58.0.3029.110 Safari/537.3",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)"
            " Version/14.0.3 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)"
            " Chrome/44.0.2403.157 Safari/537.36",
        ]
        return random.choice(agents)

    def load_wordlist(self):
        try:
            self.wordlist = load_wordlist(self.wordlist_path)
            if self.verbose:
                print(f"{ColoredOutput.GREEN}[*] Loaded {len(self.wordlist)} entries from wordlist.{ColoredOutput.ENDC}")
        except Exception as e:
            print(f"{ColoredOutput.RED}[!] Failed to load wordlist: {e}{ColoredOutput.ENDC}")
            exit(1)

    def rate_limit_wait(self):
        with self.rate_limit_lock:
            now = time.time()
            elapsed = now - self.last_request_time
            wait_time = max(0, 1/self.rate_limit - elapsed)
            if wait_time > 0:
                time.sleep(wait_time)
            self.last_request_time = time.time()

    def try_request(self, url):
        for attempt in range(self.retries):
            try:
                self.rate_limit_wait()
                resp = requests.get(
                    url,
                    timeout=self.timeout,
                    headers=self.headers,
                    proxies=self.proxies,
                    verify=self.verify_ssl,
                    allow_redirects=self.follow_redirects
                )
                with self.lock:
                    self.stats['total_requests'] += 1
                    if resp.status_code < 400:
                        self.stats['successful_requests'] += 1
                    else:
                        self.stats['failed_requests'] += 1
                return resp
            except requests.RequestException as e:
                if self.verbose:
                    print(f"{ColoredOutput.YELLOW}[!] Request error ({attempt+1}/{self.retries}): {e}{ColoredOutput.ENDC}")
                backoff = 2 ** attempt
                time.sleep(backoff)
        with self.lock:
            self.stats['failed_requests'] += 1
        return None

    def is_false_positive(self, resp):
        # Simple heuristic: check if content hash already seen
        content_hash = hash_content(resp.content)
        with self.lock:
            if content_hash in self.content_signatures:
                return True
            self.content_signatures.add(content_hash)
        return False

    def analyze_response(self, resp, url, path):
        analysis = {
            'content_length': len(resp.content),
            'content_type': resp.headers.get('Content-Type', ''),
            'technologies': [],
            'interesting': False,
            'sensitive_content': False,
            'title': '',
        }

        # Extract title if HTML
        if 'text/html' in analysis['content_type']:
            try:
                soup = BeautifulSoup(resp.text, 'html.parser')
                title_tag = soup.find('title')
                if title_tag:
                    analysis['title'] = title_tag.text.strip()
            except Exception:
                pass

        # Technology detection (basic)
        if self.technology_detection:
            server = resp.headers.get('Server', '')
            powered_by = resp.headers.get('X-Powered-By', '')
            if server:
                analysis['technologies'].append(server)
            if powered_by:
                analysis['technologies'].append(powered_by)

        # Content discovery: check for sensitive keywords
        if self.content_discovery:
            keywords = ['password', 'secret', 'confidential', 'credential', 'token', 'key', 'api_key']
            content_lower = resp.text.lower()
            for kw in keywords:
                if kw in content_lower:
                    analysis['sensitive_content'] = True
                    analysis['interesting'] = True
                    break

        # Mark interesting if status code 200 and content length > threshold
        if resp.status_code == 200 and analysis['content_length'] > 100:
            analysis['interesting'] = True

        return analysis

    def save_response(self, resp, path):
        if not self.save_responses:
            return
        safe_path = path.strip('/').replace('/', '_')
        filename = f"responses/{safe_path}_{int(time.time())}.html"
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        try:
            with open(filename, 'wb') as f:
                f.write(resp.content)
            if self.verbose:
                print(f"{ColoredOutput.GREEN}[*] Saved response content to {filename}{ColoredOutput.ENDC}")
        except Exception as e:
            if self.verbose:
                print(f"{ColoredOutput.RED}[!] Failed to save response: {e}{ColoredOutput.ENDC}")

    def extract_links(self, html, base_url):
        links = set()
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for tag in soup.find_all('a', href=True):
                href = tag['href']
                if href.startswith('javascript:') or href.startswith('#'):
                    continue
                full_url = urljoin(base_url, href)
                parsed = urlparse(full_url)
                if parsed.netloc == urlparse(self.url).netloc:
                    path = parsed.path
                    if path and path not in self.tested_paths:
                        links.add(path)
        except Exception as e:
            if self.verbose:
                print(f"{ColoredOutput.YELLOW}[!] Error extracting links: {e}{ColoredOutput.ENDC}")
        return links

    def worker(self):
        while not self.stop_receiver.is_set():
            try:
                path = self.q.get(timeout=3)
            except queue.Empty:
                break

            depth = self.crawl_depths.get(path, 0)

            for ext in self.extensions:
                if self.stop_receiver.is_set():
                    break

                full_path = f"{path}{ext}"
                url = f"{self.url.rstrip('/')}/{quote(full_path.lstrip('/'))}"

                resp = self.try_request(url)
                if not resp:
                    continue

                if self.include_status and resp.status_code not in self.include_status:
                    continue
                if resp.status_code in self.exclude_status:
                    continue

                if self.is_false_positive(resp):
                    continue

                analysis = self.analyze_response(resp, url, full_path)
                result_type = "FILE" if '.' in os.path.basename(full_path) else "DIR"

                status_color = {
                    200: ColoredOutput.GREEN,
                    403: ColoredOutput.YELLOW,
                    404: ColoredOutput.RED,
                }.get(resp.status_code, ColoredOutput.WHITE)

                tech_info = f" [{', '.join(analysis['technologies'])}]" if analysis['technologies'] else ""
                interesting_mark = " [INTERESTING]" if analysis['interesting'] else ""
                sensitive_mark = " [SENSITIVE]" if analysis['sensitive_content'] else ""

                output_line = (f"{status_color}[+] {result_type}: {url} "
                               f"(Status: {resp.status_code}, Size: {analysis['content_length']})"
                               f"{tech_info}{interesting_mark}{sensitive_mark}{ColoredOutput.ENDC}")

                with self.lock:
                    if full_path not in self.tested_paths:
                        self.tested_paths.add(full_path)
                        print(output_line)

                        if result_type == "DIR":
                            self.stats['directories_found'] += 1
                        else:
                            self.stats['files_found'] += 1

                        if analysis['interesting']:
                            self.stats['interesting_files'] += 1

                        result = {
                            'url': url,
                            'status': resp.status_code,
                            'type': result_type,
                            'size': analysis['content_length'],
                            'content_type': analysis['content_type'],
                            'technologies': analysis['technologies'],
                            'interesting': analysis['interesting'],
                            'sensitive': analysis['sensitive_content'],
                            'title': analysis['title'],
                            'timestamp': datetime.now().isoformat()
                        }
                        self.found.append(result)

                        if self.output:
                            with open(self.output, 'a', encoding='utf-8') as f:
                                f.write(f"{url} - {resp.status_code} - {result_type} - {analysis['content_length']} bytes\n")

                        if self.output_json:
                            with open(self.output_json, 'a', encoding='utf-8') as f:
                                f.write(json.dumps(result, ensure_ascii=False) + "\n")

                        self.save_response(resp, full_path)

                # Crawling
                if (self.enable_crawl and resp.status_code == 200 and
                    depth < self.max_crawl_depth and
                    'text/html' in resp.headers.get('Content-Type', '')):
                    new_links = self.extract_links(resp.text, url)
                    with self.lock:
                        for link in new_links:
                            if link not in self.tested_paths:
                                self.q.put(link)
                                self.tested_paths.add(link)
                                self.crawl_depths[link] = depth + 1

                # Recursive directory scanning
                if (self.recursive and resp.status_code == 200 and
                    result_type == "DIR" and depth < self.max_crawl_depth):
                    common_dirs = ['index', 'admin', 'login', 'config', 'backup', 'test', 'api']
                    for dir_name in common_dirs:
                        new_path = f"{path.rstrip('/')}/{dir_name}"
                        with self.lock:
                            if new_path not in self.tested_paths:
                                self.q.put(new_path)
                                self.tested_paths.add(new_path)
                                self.crawl_depths[new_path] = depth + 1

                if self.stealth_mode:
                    random_delay(0.5, 2.0)

            self.q.task_done()

    def receiver(self):
        print(f"{ColoredOutput.CYAN}[*] Receiver mode enabled. Commands:{ColoredOutput.ENDC}")
        print("  - Type paths to fuzz (one per line)")
        print("  - 'stats' - Show current statistics")
        print("  - 'save' - Save current progress")
        print("  - 'exit' - Stop receiver")

        while not self.stop_receiver.is_set():
            try:
                line = input().strip()
                if line.lower() == 'exit':
                    self.stop_receiver.set()
                    break
                elif line.lower() == 'stats':
                    self.show_stats()
                elif line.lower() == 'save':
                    self.save_progress()
                elif line:
                    with self.lock:
                        if line not in self.tested_paths:
                            self.q.put(line)
                            self.tested_paths.add(line)
                            self.crawl_depths[line] = 0
                            print(f"{ColoredOutput.GREEN}[+] Added: {line}{ColoredOutput.ENDC}")
                        else:
                            print(f"{ColoredOutput.YELLOW}[!] Already tested: {line}{ColoredOutput.ENDC}")
            except (EOFError, KeyboardInterrupt):
                self.stop_receiver.set()
                break

    def show_stats(self):
        elapsed = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
        print(f"\n{ColoredOutput.CYAN}=== Statistics ==={ColoredOutput.ENDC}")
        print(f"Time elapsed: {elapsed:.2f} seconds")
        print(f"Total requests: {self.stats['total_requests']}")
        print(f"Successful requests: {self.stats['successful_requests']}")
        print(f"Failed requests: {self.stats['failed_requests']}")
        print(f"Directories found: {self.stats['directories_found']}")
        print(f"Files found: {self.stats['files_found']}")
        print(f"Interesting files: {self.stats['interesting_files']}")
        print(f"Requests per second: {self.stats['total_requests']/elapsed:.2f}" if elapsed > 0 else "N/A")
        print(f"Queue size: {self.q.qsize()}")
        print(f"Tested paths: {len(self.tested_paths)}")

    def save_progress(self):
        progress_data = {
            'tested_paths': list(self.tested_paths),
            'found': self.found,
            'stats': self.stats,
            'timestamp': datetime.now().isoformat()
        }
        try:
            with open(self.resume_file, 'w', encoding='utf-8') as f:
                json.dump(progress_data, f, indent=2)
            print(f"{ColoredOutput.GREEN}[*] Progress saved to {self.resume_file}{ColoredOutput.ENDC}")
        except Exception as e:
            print(f"{ColoredOutput.RED}[!] Error saving progress: {e}{ColoredOutput.ENDC}")

    def load_progress(self):
        if not os.path.exists(self.resume_file):
            return False
        try:
            with open(self.resume_file, 'r', encoding='utf-8') as f:
                progress_data = json.load(f)
            self.tested_paths = set(progress_data['tested_paths'])
            self.found = progress_data['found']
            self.stats = progress_data['stats']
            print(f"{ColoredOutput.GREEN}[*] Resumed from {self.resume_file}{ColoredOutput.ENDC}")
            print(f"[*] Previously tested {len(self.tested_paths)} paths")
            print(f"[*] Previously found {len(self.found)} results")
            return True
        except Exception as e:
            print(f"{ColoredOutput.RED}[!] Error loading progress: {e}{ColoredOutput.ENDC}")
            return False

    def export_html_report(self):
        if not self.export_html:
            return
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Directory Fuzzing Report - {self.url}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background                .header {{ background-color: #4CAF50; color: white; padding: 10px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; }}
                th {{ background-color: #f2f2f2; }}
                tr:hover {{ background-color: #f5f5f5; }}
                .status-200 {{ color: green; font-weight: bold; }}
                .status-403 {{ color: orange; font-weight: bold; }}
                .status-404 {{ color: red; font-weight: bold; }}
                .interesting {{ background-color: #ffffcc; }}
                .sensitive {{ background-color: #ffcccc; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Directory Fuzzing Report</h1>
                <p>Target URL: {self.url}</p>
                <p>Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Total Requests: {self.stats['total_requests']}</p>
                <p>Directories Found: {self.stats['directories_found']}</p>
                <p>Files Found: {self.stats['files_found']}</p>
                <p>Interesting Files: {self.stats['interesting_files']}</p>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>Status</th>
                        <th>Type</th>
                        <th>Size (bytes)</th>
                        <th>Content-Type</th>
                        <th>Technologies</th>
                        <th>Title</th>
                        <th>Flags</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody>
        """

        for item in self.found:
            status_class = f"status-{item['status']}"
            flags = []
            if item['interesting']:
                flags.append("Interesting")
            if item['sensitive']:
                flags.append("Sensitive")
            flags_str = ", ".join(flags) if flags else "-"
            tech_str = ", ".join(item['technologies']) if item['technologies'] else "-"
            title = item['title'] if item['title'] else "-"
            html_content += f"""
                <tr class="{ 'interesting' if item['interesting'] else '' } { 'sensitive' if item['sensitive'] else '' }">
                    <td><a href="{item['url']}" target="_blank">{item['url']}</a></td>
                    <td class="{status_class}">{item['status']}</td>
                    <td>{item['type']}</td>
                    <td>{item['size']}</td>
                    <td>{item['content_type']}</td>
                    <td>{tech_str}</td>
                    <td>{title}</td>
                    <td>{flags_str}</td>
                    <td>{item['timestamp']}</td>
                </tr>
            """

        html_content += """
                </tbody>
            </table>
        </body>
        </html>
        """

        report_file = f"dirfuzzer_report_{md5(self.url.encode()).hexdigest()}.html"
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"{ColoredOutput.GREEN}[*] HTML report saved to {report_file}{ColoredOutput.ENDC}")
        except Exception as e:
            print(f"{ColoredOutput.RED}[!] Failed to save HTML report: {e}{ColoredOutput.ENDC}")

    def run(self):
        print(f"{ColoredOutput.HEADER}=== Enhanced Directory Fuzzer ==={ColoredOutput.ENDC}")
        self.stats['start_time'] = time.time()

        # Load progress if resume enabled
        if self.resume_scan:
            resumed = self.load_progress()
            if resumed:
                for path in self.tested_paths:
                    self.q.put(path)
            else:
                # Seed queue with root paths from wordlist
                for path in self.wordlist:
                    self.q.put(path)
                    self.crawl_depths[path] = 0
                    self.tested_paths.add(path)
        else:
            # Seed queue with root paths from wordlist
            for path in self.wordlist:
                self.q.put(path)
                self.crawl_depths[path] = 0
                self.tested_paths.add(path)

        # Start worker threads
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.worker) for _ in range(self.threads)]

            # Start receiver thread if enabled
            if self.enable_receiver:
                receiver_thread = threading.Thread(target=self.receiver, daemon=True)
                receiver_thread.start()

            try:
                # Wait for all workers to finish
                concurrent.futures.wait(futures)
            except KeyboardInterrupt:
                print(f"\n{ColoredOutput.RED}[!] Interrupted by user. Stopping...{ColoredOutput.ENDC}")
                self.stop_receiver.set()

            if self.enable_receiver:
                self.stop_receiver.set()
                receiver_thread.join()

        self.show_stats()

        if self.export_html:
            self.export_html_report()

        if self.resume_scan:
            self.save_progress()

        print(f"{ColoredOutput.GREEN}[*] Scan completed.{ColoredOutput.ENDC}")

# --- CLI Interface ---

def parse_args():
    parser = argparse.ArgumentParser(description="Enhanced Directory Fuzzer")
    parser.add_argument('url', help='Target base URL (e.g. https://example.com)')
    parser.add_argument('-w', '--wordlist', required=True, help='Path to wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of concurrent threads')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--retries', type=int, default=3, help='Number of retries for failed requests')
    parser.add_argument('--rate-limit', type=int, default=10, help='Global requests per second rate limit')
    parser.add_argument('-o', '--output', help='Output file for plain text results')
    parser.add_argument('--output-json', help='Output file for JSON results')
    parser.add_argument('--user-agent', help='Custom User-Agent header')
    parser.add_argument('--proxy', help='HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)')
    parser.add_argument('--receiver', action='store_true', help='Enable interactive receiver mode')
    parser.add_argument('--crawl', action='store_true', help='Enable crawling mode')
    parser.add_argument('--max-crawl-depth', type=int, default=3, help='Maximum crawl depth')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--recursive', action='store_true', help='Enable recursive directory scanning')
    parser.add_argument('--extensions', default='.php,.html,.bak,.old,.txt', help='Comma-separated list of extensions to try')
    parser.add_argument('--exclude-status', default='', help='Comma-separated HTTP status codes to exclude')
    parser.add_argument('--include-status', default='', help='Comma-separated HTTP status codes to include only')
    parser.add_argument('--follow-redirects', action='store_true', help='Follow HTTP redirects')
    parser.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL certificate verification')
    parser.add_argument('--random-agent', action='store_true', help='Use random User-Agent for each request')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode with random delays')
    parser.add_argument('--brute-force', action='store_true', help='Enable brute force mode (future feature)')
    parser.add_argument('--content-discovery', action='store_true', help='Enable sensitive content discovery')
    parser.add_argument('--technology-detection', action='store_true', help='Enable technology detection')
    parser.add_argument('--smart-filter', action='store_true', help='Enable smart false positive filtering')
    parser.add_argument('--export-html', action='store_true', help='Export results to HTML report')
    parser.add_argument('--resume', action='store_true', help='Resume previous scan if available')
    parser.add_argument('--save-responses', action='store_true', help='Save HTTP responses to disk')
    return parser.parse_args()

def main():
    args = parse_args()

    extensions = [ext.strip() for ext in args.extensions.split(',') if ext.strip()]
    exclude_status = [int(s) for s in args.exclude_status.split(',') if s.strip().isdigit()] if args.exclude_status else []
    include_status = [int(s) for s in args.include_status.split(',') if s.strip().isdigit()] if args.include_status else None

    fuzzer = EnhancedDirFuzzer(
        url=args.url,
        wordlist_path=args.wordlist,
        threads=args.threads,
        timeout=args.timeout,
        retries=args.retries,
        rate_limit=args.rate_limit,
        output=args.output,
        output_json=args.output_json,
        user_agent=args.user_agent,
        proxy=args.proxy,
        enable_receiver=args.receiver,
        enable_crawl=args.crawl,
        max_crawl_depth=args.max_crawl_depth,
        verbose=args.verbose,
        recursive=args.recursive,
        extensions=extensions,
        exclude_status=exclude_status,
        include_status=include_status,
        follow_redirects=args.follow_redirects,
        verify_ssl=not args.no_verify_ssl,
        random_agent=args.random_agent,
        stealth_mode=args.stealth,
        brute_force=args.brute_force,
        content_discovery=args.content_discovery,
        technology_detection=args.technology_detection,
        smart_filter=args.smart_filter,
        export_html=args.export_html,
        resume_scan=args.resume,
        save_responses=args.save_responses
    )

    fuzzer.run()

if __name__ == '__main__':
    main()
