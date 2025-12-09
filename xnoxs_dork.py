#!/usr/bin/env python3
"""
xnoxs-dork - SQL Injection Vulnerability Scanner
A security research tool for detecting SQL injection vulnerabilities.
For educational and authorized testing purposes only.
"""

import argparse
import os
import re
import sys
import urllib.parse
from colorama import Fore, Style, init
import requests
from SearchEngine import GoogleSearch

init(autoreset=True)

SQL_ERROR_PATTERNS = {
    'MySQL': [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"MySqlException",
        r"valid MySQL result",
        r"check the manual that corresponds to your (MySQL|MariaDB) server version",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc\.exceptions",
        r"You have an error in your SQL syntax",
        r"mysql_fetch_array\(\)",
        r"mysql_num_rows\(\)",
    ],
    'PostgreSQL': [
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError:",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
    ],
    'Microsoft SQL Server': [
        r"Driver.* SQL[\-\_\ ]*Server",
        r"OLE DB.* SQL Server",
        r"\bSQL Server[^&lt;&quot;]+Driver",
        r"Warning.*mssql_.*",
        r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
        r"System\.Data\.SqlClient\.SqlException",
        r"Exception.*\WRoadhouse\.Cms\.",
        r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
        r"Unclosed quotation mark after the character string",
        r"ODBC SQL Server Driver",
    ],
    'Oracle': [
        r"\bORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*\Woci_.*",
        r"Warning.*\Wora_.*",
        r"oracle\.jdbc\.driver",
        r"quoted string not properly terminated",
    ],
    'SQLite': [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_.*",
        r"Warning.*SQLite3::",
        r"\[SQLITE_ERROR\]",
        r"SQLITE_MISUSE",
    ],
    'IBM DB2': [
        r"CLI Driver.*DB2",
        r"DB2 SQL error",
        r"\bdb2_\w+\(",
        r"SQLSTATE.+SQLCODE",
    ],
    'Generic': [
        r"SQL syntax.*",
        r"syntax error.*SQL",
        r"unexpected end of SQL command",
        r"invalid query",
        r"SQL command not properly ended",
        r"unterminated quoted string",
    ]
}

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║  {Fore.RED}██╗  ██╗███╗   ██╗ ██████╗ ██╗  ██╗███████╗{Fore.CYAN}                 ║
║  {Fore.RED}╚██╗██╔╝████╗  ██║██╔═══██╗╚██╗██╔╝██╔════╝{Fore.CYAN}                 ║
║  {Fore.RED} ╚███╔╝ ██╔██╗ ██║██║   ██║ ╚███╔╝ ███████╗{Fore.CYAN}                 ║
║  {Fore.RED} ██╔██╗ ██║╚██╗██║██║   ██║ ██╔██╗ ╚════██║{Fore.CYAN}                 ║
║  {Fore.RED}██╔╝ ██╗██║ ╚████║╚██████╔╝██╔╝ ██╗███████║{Fore.CYAN}                 ║
║  {Fore.RED}╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝{Fore.CYAN}                 ║
║                                                              ║
║  {Fore.YELLOW}DORK - SQL Injection Vulnerability Scanner{Fore.CYAN}                 ║
║  {Fore.WHITE}For Security Research Purposes Only{Fore.CYAN}                        ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""


def print_banner():
    print(BANNER)


def print_info(msg):
    print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {msg}")


def print_success(msg):
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")


def print_error(msg):
    print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")


def print_warning(msg):
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")


def print_vuln(url, db_type, error_snippet):
    print(f"\n{Fore.RED}{'='*60}")
    print(f"{Fore.RED}[VULNERABLE]{Style.RESET_ALL} SQL Injection Detected!")
    print(f"{Fore.RED}{'='*60}")
    print(f"{Fore.YELLOW}URL:{Style.RESET_ALL} {url}")
    print(f"{Fore.YELLOW}Database:{Style.RESET_ALL} {db_type}")
    print(f"{Fore.YELLOW}Error:{Style.RESET_ALL} {error_snippet[:200]}...")
    print(f"{Fore.RED}{'='*60}\n")


def detect_sql_error(response_text):
    for db_type, patterns in SQL_ERROR_PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 50)
                end = min(len(response_text), match.end() + 100)
                snippet = response_text[start:end].strip()
                snippet = re.sub(r'<[^>]+>', '', snippet)
                return db_type, snippet
    return None, None


def inject_payload(url, payload="'"):
    parsed = urllib.parse.urlparse(url)
    
    if parsed.query:
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        injected_urls = []
        
        for param in params:
            new_params = params.copy()
            original_value = new_params[param][0] if new_params[param] else ''
            new_params[param] = [original_value + payload]
            
            new_query = urllib.parse.urlencode(new_params, doseq=True)
            injected_url = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment
            ))
            injected_urls.append((param, injected_url))
        
        return injected_urls
    else:
        return [('path', url + payload)]


def test_url(url, timeout=10):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'close',
        }
        
        response = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
        return response.text
    except requests.exceptions.Timeout:
        print_warning(f"Timeout: {url[:60]}...")
        return None
    except requests.exceptions.ConnectionError:
        print_warning(f"Connection error: {url[:60]}...")
        return None
    except Exception as e:
        print_warning(f"Error: {str(e)[:50]}")
        return None


def scan_url(url, timeout=10):
    vulnerabilities = []
    
    injected_urls = inject_payload(url)
    
    for param_name, injected_url in injected_urls:
        print_info(f"Testing parameter: {param_name}")
        
        response_text = test_url(injected_url, timeout)
        
        if response_text:
            db_type, error_snippet = detect_sql_error(response_text)
            
            if db_type:
                vulnerabilities.append({
                    'url': injected_url,
                    'parameter': param_name,
                    'db_type': db_type,
                    'error': error_snippet
                })
                print_vuln(injected_url, db_type, error_snippet)
    
    return vulnerabilities


def search_dork(dork, num_results=10):
    print_info(f"Searching Google for: {dork}")
    
    try:
        scraper_api_key = os.environ.get('SCRAPER_API_KEY')
        if scraper_api_key:
            print_info("Using ScraperAPI to bypass captcha...")
            search = GoogleSearch(scraper_api_key=scraper_api_key)
        else:
            print_warning("No ScraperAPI key found. Google may block requests.")
            search = GoogleSearch()
        
        results = search.search(dork, num_results=num_results)
        
        urls = []
        for result in results:
            if hasattr(result, 'url'):
                urls.append(result.url)
            elif isinstance(result, dict) and 'url' in result:
                urls.append(result['url'])
            elif isinstance(result, str):
                urls.append(result)
        
        print_success(f"Found {len(urls)} URLs")
        return urls
    except Exception as e:
        print_error(f"Search error: {str(e)}")
        return []


def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='xnoxs-dork - SQL Injection Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python xnoxs_dork.py -d "inurl:php?id="
  python xnoxs_dork.py -d "inurl:product.php?id=" -n 20
  python xnoxs_dork.py -u "http://example.com/page.php?id=1"
  python xnoxs_dork.py -d "site:example.com inurl:?id=" -t 15

For security research purposes only. Use responsibly.
        """
    )
    
    parser.add_argument('-d', '--dork', type=str, help='Google dork query to search')
    parser.add_argument('-u', '--url', type=str, help='Single URL to test')
    parser.add_argument('-n', '--num', type=int, default=10, help='Number of search results (default: 10)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    
    args = parser.parse_args()
    
    if not args.dork and not args.url:
        parser.print_help()
        print_error("\nPlease provide either a dork (-d) or URL (-u)")
        sys.exit(1)
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    all_vulnerabilities = []
    
    if args.url:
        print_info(f"Testing single URL: {args.url}")
        vulns = scan_url(args.url, args.timeout)
        all_vulnerabilities.extend(vulns)
    
    if args.dork:
        urls = search_dork(args.dork, args.num)
        
        if urls:
            print_info(f"Scanning {len(urls)} URLs for SQL injection...")
            print()
            
            for i, url in enumerate(urls, 1):
                print(f"\n{Fore.CYAN}[{i}/{len(urls)}]{Style.RESET_ALL} Scanning: {url[:70]}...")
                vulns = scan_url(url, args.timeout)
                all_vulnerabilities.extend(vulns)
    
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}                    SCAN COMPLETE")
    print(f"{Fore.CYAN}{'='*60}")
    
    if all_vulnerabilities:
        print_success(f"Found {len(all_vulnerabilities)} potential SQL injection vulnerabilities!\n")
        
        for i, vuln in enumerate(all_vulnerabilities, 1):
            print(f"{Fore.GREEN}[{i}]{Style.RESET_ALL} {vuln['url']}")
            print(f"    {Fore.YELLOW}Parameter:{Style.RESET_ALL} {vuln['parameter']}")
            print(f"    {Fore.YELLOW}Database:{Style.RESET_ALL} {vuln['db_type']}")
            print(f"    {Fore.YELLOW}Error:{Style.RESET_ALL} {vuln['error'][:100]}...")
            print()
    else:
        print_warning("No SQL injection vulnerabilities found.")
    
    print(f"\n{Fore.CYAN}Thank you for using xnoxs-dork!{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Remember: Always get proper authorization before testing.{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
