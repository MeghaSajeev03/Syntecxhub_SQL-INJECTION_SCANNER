# SQL Injection Scanner

A basic Python tool to probe web inputs (URL parameters and HTML forms) for common SQL injection vulnerabilities.

## Features
- Scans URL parameters and form fields for SQL injection points.
- Uses common SQL injection payloads.
- Validates vulnerabilities based on SQL error messages returned in the response.
- Implements basic rate limiting (`--delay`) to control request frequency.
- Uses basic concurrency (`--threads`) to scan multiple fields/payloads quickly.
- Logs results to a file (`sql_scanner.log`) and standard output.

## Disclaimer
**This tool is strictly for educational and authorized testing purposes ONLY. Do not use this tool on any web application or server that you do not own or do not have explicit permission to test (such as local applications or deliberately vulnerable applications like DVWA). Unauthorized scanning is illegal and unethical.**

## Installation

1. Create a virtual environment (optional but recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Basic usage:
```bash
python sql_scanner.py <target_url>
```

Example scanning a test site:
```bash
python sql_scanner.py "http://testphp.vulnweb.com/listproducts.php?cat=1"
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--threads` | Number of concurrent threads to use for scanning. | `5` |
| `--delay` | Delay (in seconds) between requests to avoid overloading the server. | `1.0` |
| `--yes` | Auto-confirm the legal disclaimer prompt (use with caution). | `False` |

Example with custom threads and delay:
```bash
python sql_scanner.py "http://testphp.vulnweb.com/login.php" --threads 10 --delay 0.5
```

## How It Works
1. **Forms**: The script sends a GET request to the target URL to extract all HTML `<form>` elements. It then attempts to inject basic SQL payloads into every input field (handling both GET and POST forms).
2. **Parameters**: If the initial target URL contains query parameters (e.g., `?id=1`), the script individually modifies each parameter by injecting standard SQL payloads.
3. **Detection**: It examines the HTML content of the response. If it detects common backend SQL error messages (e.g., "you have an error in your sql syntax"), it marks the input as potentially vulnerable.
