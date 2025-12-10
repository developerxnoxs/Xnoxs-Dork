#!/usr/bin/env python3
"""
xnoxs-dork - SQL Injection & XSS Vulnerability Scanner
A security research tool for detecting SQL injection and XSS vulnerabilities.
For educational and authorized testing purposes only.
"""

import os
import re
import sys
import time
import urllib.parse
import html
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Back, Style, init
import requests
from SearchEngine import GoogleSearch

init(autoreset=True)

thread_lock = threading.Lock()

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert("XSS")>',
    '"><script>alert("XSS")</script>',
    "'><script>alert('XSS')</script>",
    '<body onload=alert("XSS")>',
    '<iframe src="javascript:alert(\'XSS\')">',
    '"><img src=x onerror=alert("XSS")>',
    "javascript:alert('XSS')",
    '<div onmouseover="alert(\'XSS\')">',
]

DOM_XSS_SOURCES = [
    r'document\.URL',
    r'document\.documentURI',
    r'document\.URLUnencoded',
    r'document\.baseURI',
    r'location\.href',
    r'location\.search',
    r'location\.hash',
    r'location\.pathname',
    r'document\.cookie',
    r'document\.referrer',
    r'window\.name',
    r'history\.pushState',
    r'history\.replaceState',
    r'localStorage\.',
    r'sessionStorage\.',
]

DOM_XSS_SINKS = [
    r'eval\s*\(',
    r'setTimeout\s*\(',
    r'setInterval\s*\(',
    r'Function\s*\(',
    r'\.innerHTML\s*=',
    r'\.outerHTML\s*=',
    r'\.insertAdjacentHTML\s*\(',
    r'document\.write\s*\(',
    r'document\.writeln\s*\(',
    r'\.src\s*=',
    r'\.href\s*=',
    r'\.action\s*=',
    r'\.data\s*=',
    r'jQuery\s*\(\s*["\']<',
    r'\$\s*\(\s*["\']<',
    r'\.html\s*\(',
    r'\.append\s*\(',
    r'\.prepend\s*\(',
    r'\.after\s*\(',
    r'\.before\s*\(',
]

XSS_DETECTION_PATTERNS = [
    r'<script>alert\(["\']XSS["\']\)</script>',
    r'<img\s+src=x\s+onerror=alert\(["\']XSS["\']\)>',
    r'<svg\s+onload=alert\(["\']XSS["\']\)>',
    r'<body\s+onload=alert\(["\']XSS["\']\)>',
    r'<iframe\s+src=["\']?javascript:alert',
    r'<div\s+onmouseover=["\']alert\(["\']XSS["\']\)["\']>',
    r'onerror\s*=\s*alert\s*\(',
    r'onload\s*=\s*alert\s*\(',
    r'onmouseover\s*=\s*alert\s*\(',
]

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

settings = {
    'num_results': 100,
    'timeout': 10,
    'threads': 5
}

all_vulnerabilities = []
all_xss_vulnerabilities = []
all_dom_xss_vulnerabilities = []


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    banner = f"""
{Fore.CYAN}╔════════════════════════════════════════════════════════════════════════════════╗
{Fore.CYAN}║{Fore.RED}  ██╗  ██╗███╗   ██╗ ██████╗ ██╗  ██╗███████╗  {Fore.MAGENTA}██████╗  ██████╗ ██████╗ ██╗  ██╗{Fore.CYAN}║
{Fore.CYAN}║{Fore.RED}  ╚██╗██╔╝████╗  ██║██╔═══██╗╚██╗██╔╝██╔════╝  {Fore.MAGENTA}██╔══██╗██╔═══██╗██╔══██╗██║ ██╔ {Fore.CYAN}║
{Fore.CYAN}║{Fore.RED}   ╚███╔╝ ██╔██╗ ██║██║   ██║ ╚███╔╝ ███████╗  {Fore.MAGENTA}██║  ██║██║   ██║██████╔╝█████╔╝ {Fore.CYAN}║
{Fore.CYAN}║{Fore.RED}   ██╔██╗ ██║╚██╗██║██║   ██║ ██╔██╗ ╚════██║  {Fore.MAGENTA}██║  ██║██║   ██║██╔══██╗██╔═██╗ {Fore.CYAN}║
{Fore.CYAN}║{Fore.RED}  ██╔╝ ██╗██║ ╚████║╚██████╔╝██╔╝ ██╗███████║  {Fore.MAGENTA}██████╔╝╚██████╔╝██║  ██║██║  ██╗{Fore.CYAN}║
{Fore.CYAN}║{Fore.RED}  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝  {Fore.MAGENTA}╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝{Fore.CYAN}║
{Fore.CYAN}╠════════════════════════════════════════════════════════════════════════════════╣
{Fore.CYAN}║{Fore.WHITE}            SQLi & XSS Vulnerability Scanner v2.2 [Multi-threaded]              {Fore.CYAN}║
{Fore.CYAN}║{Fore.GREEN}                      For Security Research Purposes Only                       {Fore.CYAN}║
{Fore.CYAN}╚════════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
    print(banner)


def print_menu():
    api_status = f"{Fore.GREEN}Active"
    
    menu = f"""
    {Fore.CYAN}┌────────────────────────────────────────────────────────────────────┐
    │                                                                    │
    │  {Fore.YELLOW}[1]{Fore.WHITE} ◆  Scan dengan Google Dork (Multi-threaded)                   {Fore.CYAN}│
    │  {Fore.YELLOW}[2]{Fore.WHITE} ◆  Scan URL Tunggal                                           {Fore.CYAN}│
    │  {Fore.YELLOW}[3]{Fore.WHITE} ◆  Lihat Hasil Vulnerability                                  {Fore.CYAN}│
    │  {Fore.YELLOW}[4]{Fore.WHITE} ◆  Pengaturan                                                 {Fore.CYAN}│
    │  {Fore.YELLOW}[5]{Fore.WHITE} ◆  Tentang Tool                                               {Fore.CYAN}│
    │  {Fore.YELLOW}[0]{Fore.WHITE} ◆  Keluar                                                     {Fore.CYAN}│
    │                                                                    │
    ├────────────────────────────────────────────────────────────────────┤
    │  {Fore.MAGENTA}Threads: {Fore.WHITE}{settings['threads']}  {Fore.CYAN}│  {Fore.MAGENTA}Timeout: {Fore.WHITE}{settings['timeout']}s  {Fore.CYAN}│  {Fore.MAGENTA}Results: {Fore.WHITE}{settings['num_results']}  {Fore.CYAN}│  {Fore.MAGENTA}API: {api_status}      {Fore.CYAN}│
    └────────────────────────────────────────────────────────────────────┘
{Style.RESET_ALL}"""
    print(menu)


def print_divider():
    print(f"\n    {Fore.CYAN}{'═' * 68}{Style.RESET_ALL}\n")


def print_info(msg):
    print(f"    {Fore.BLUE}[*]{Style.RESET_ALL} {msg}")


def print_success(msg):
    print(f"    {Fore.GREEN}[+]{Style.RESET_ALL} {msg}")


def print_error(msg):
    print(f"    {Fore.RED}[-]{Style.RESET_ALL} {msg}")


def print_warning(msg):
    print(f"    {Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")


def print_vuln(url, db_type, error_snippet):
    print(f"""
    {Fore.RED}╔{'═'*66}╗
    ║{Back.RED}{Fore.WHITE}  VULNERABLE  {Style.RESET_ALL}{Fore.RED}║ SQL Injection Detected!                           ║
    ╠{'═'*66}╣{Style.RESET_ALL}
    {Fore.RED}║{Fore.YELLOW} URL:{Style.RESET_ALL} {url[:58]}{'...' if len(url) > 58 else ''}{' ' * max(0, 58 - len(url[:58]))} {Fore.RED}║
    {Fore.RED}║{Fore.YELLOW} Database:{Style.RESET_ALL} {db_type}{' ' * (53 - len(db_type))} {Fore.RED}║
    {Fore.RED}║{Fore.YELLOW} Error:{Style.RESET_ALL} {error_snippet[:56]}{'...' if len(error_snippet) > 56 else ''}{' ' * max(0, 56 - len(error_snippet[:56]))} {Fore.RED}║
    {Fore.RED}╚{'═'*66}╝{Style.RESET_ALL}
""")


def print_xss_vuln(url, xss_type, payload):
    payload_display = payload[:50] if len(payload) > 50 else payload
    print(f"""
    {Fore.MAGENTA}╔{'═'*66}╗
    ║{Back.MAGENTA}{Fore.WHITE}  VULNERABLE  {Style.RESET_ALL}{Fore.MAGENTA}║ XSS (Cross-Site Scripting) Detected!              ║
    ╠{'═'*66}╣{Style.RESET_ALL}
    {Fore.MAGENTA}║{Fore.YELLOW} URL:{Style.RESET_ALL} {url[:58]}{'...' if len(url) > 58 else ''}{' ' * max(0, 58 - len(url[:58]))} {Fore.MAGENTA}║
    {Fore.MAGENTA}║{Fore.YELLOW} Type:{Style.RESET_ALL} {xss_type}{' ' * (57 - len(xss_type))} {Fore.MAGENTA}║
    {Fore.MAGENTA}║{Fore.YELLOW} Payload:{Style.RESET_ALL} {payload_display}{' ' * max(0, 54 - len(payload_display))} {Fore.MAGENTA}║
    {Fore.MAGENTA}╚{'═'*66}╝{Style.RESET_ALL}
""")


def print_dom_xss_vuln(url, source, sink):
    source_display = source[:45] if len(source) > 45 else source
    sink_display = sink[:45] if len(sink) > 45 else sink
    print(f"""
    {Fore.YELLOW}╔{'═'*66}╗
    ║{Back.YELLOW}{Fore.BLACK}  VULNERABLE  {Style.RESET_ALL}{Fore.YELLOW}║ DOM-based XSS Detected!                           ║
    ╠{'═'*66}╣{Style.RESET_ALL}
    {Fore.YELLOW}║{Fore.WHITE} URL:{Style.RESET_ALL} {url[:58]}{'...' if len(url) > 58 else ''}{' ' * max(0, 58 - len(url[:58]))} {Fore.YELLOW}║
    {Fore.YELLOW}║{Fore.WHITE} Source:{Style.RESET_ALL} {source_display}{' ' * max(0, 55 - len(source_display))} {Fore.YELLOW}║
    {Fore.YELLOW}║{Fore.WHITE} Sink:{Style.RESET_ALL} {sink_display}{' ' * max(0, 57 - len(sink_display))} {Fore.YELLOW}║
    {Fore.YELLOW}╚{'═'*66}╝{Style.RESET_ALL}
""")


def loading_animation(text, duration=1):
    frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    end_time = time.time() + duration
    i = 0
    while time.time() < end_time:
        print(f"\r    {Fore.CYAN}{frames[i % len(frames)]}{Style.RESET_ALL} {text}", end='', flush=True)
        time.sleep(0.1)
        i += 1
    print(f"\r    {Fore.GREEN}✓{Style.RESET_ALL} {text}")


def progress_bar(current, total, prefix=''):
    bar_length = 40
    filled = int(bar_length * current / total)
    bar = f"{Fore.GREEN}{'█' * filled}{Fore.WHITE}{'░' * (bar_length - filled)}{Style.RESET_ALL}"
    percent = f"{100 * current / total:.1f}%"
    print(f"\r    {prefix} [{bar}] {percent} ({current}/{total})", end='', flush=True)


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


def detect_xss(response_text, payload):
    if payload in response_text:
        return 'Reflected XSS', payload
    
    decoded_payload = html.unescape(payload)
    if decoded_payload in response_text:
        return 'Reflected XSS (HTML Decoded)', payload
    
    for pattern in XSS_DETECTION_PATTERNS:
        if re.search(pattern, response_text, re.IGNORECASE):
            return 'Reflected XSS', payload
    
    return None, None


def detect_dom_xss(response_text):
    dom_vulns = []
    found_sources = []
    found_sinks = []
    
    for source_pattern in DOM_XSS_SOURCES:
        matches = re.findall(source_pattern, response_text, re.IGNORECASE)
        if matches:
            found_sources.append(source_pattern.replace('\\', ''))
    
    for sink_pattern in DOM_XSS_SINKS:
        matches = re.findall(sink_pattern, response_text, re.IGNORECASE)
        if matches:
            found_sinks.append(sink_pattern.replace('\\', '').replace(r'\s*', '').replace(r'\(', '('))
    
    if found_sources and found_sinks:
        for source in found_sources[:3]:
            for sink in found_sinks[:3]:
                dom_vulns.append({
                    'source': source,
                    'sink': sink
                })
    
    return dom_vulns


def scan_dom_xss(url, timeout=10, silent=False):
    dom_vulns = []
    
    response_text = test_url(url, timeout)
    
    if response_text:
        detected_dom = detect_dom_xss(response_text)
        
        for dom in detected_dom:
            vuln = {
                'url': url,
                'source': dom['source'],
                'sink': dom['sink']
            }
            dom_vulns.append(vuln)
            with thread_lock:
                all_dom_xss_vulnerabilities.append(vuln)
            if not silent:
                with thread_lock:
                    print_dom_xss_vuln(url, dom['source'], dom['sink'])
            break
    
    return dom_vulns


def inject_xss_payload(url, payload):
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
            injected_urls.append((param, injected_url, payload))
        
        return injected_urls
    else:
        return [('path', url + urllib.parse.quote(payload), payload)]


def scan_xss(url, timeout=10, silent=False):
    xss_vulns = []
    tested_params = set()
    
    for payload in XSS_PAYLOADS:
        injected_urls = inject_xss_payload(url, payload)
        
        for param_name, injected_url, used_payload in injected_urls:
            if param_name in tested_params:
                continue
            
            response_text = test_url(injected_url, timeout)
            
            if response_text:
                xss_type, detected_payload = detect_xss(response_text, used_payload)
                
                if xss_type:
                    vuln = {
                        'url': injected_url,
                        'parameter': param_name,
                        'xss_type': xss_type,
                        'payload': used_payload
                    }
                    xss_vulns.append(vuln)
                    with thread_lock:
                        all_xss_vulnerabilities.append(vuln)
                    tested_params.add(param_name)
                    if not silent:
                        with thread_lock:
                            print_xss_vuln(injected_url, xss_type, used_payload)
    
    return xss_vulns


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
        return None
    except requests.exceptions.ConnectionError:
        return None
    except Exception:
        return None


def scan_url(url, timeout=10, silent=False):
    vulnerabilities = []
    xss_vulns = []
    dom_vulns = []
    
    if not silent:
        with thread_lock:
            print_info(f"{Fore.CYAN}[SQL Injection Scan]{Style.RESET_ALL}")
    
    injected_urls = inject_payload(url)
    
    for param_name, injected_url in injected_urls:
        if not silent:
            with thread_lock:
                print_info(f"Testing parameter: {Fore.YELLOW}{param_name}{Style.RESET_ALL}")
        
        response_text = test_url(injected_url, timeout)
        
        if response_text:
            db_type, error_snippet = detect_sql_error(response_text)
            
            if db_type:
                vuln = {
                    'url': injected_url,
                    'parameter': param_name,
                    'db_type': db_type,
                    'error': error_snippet
                }
                vulnerabilities.append(vuln)
                with thread_lock:
                    all_vulnerabilities.append(vuln)
                if not silent:
                    with thread_lock:
                        print_vuln(injected_url, db_type, error_snippet)
    
    if not silent:
        with thread_lock:
            print_info(f"{Fore.MAGENTA}[Reflected XSS Scan]{Style.RESET_ALL}")
    
    xss_vulns = scan_xss(url, timeout, silent)
    
    if not silent:
        with thread_lock:
            print_info(f"{Fore.YELLOW}[DOM-based XSS Scan]{Style.RESET_ALL}")
    
    dom_vulns = scan_dom_xss(url, timeout, silent)
    
    return vulnerabilities, xss_vulns, dom_vulns


def scan_url_threaded(url, timeout=10):
    return scan_url(url, timeout, silent=True)


def multi_threaded_scan(urls, timeout=10, num_threads=5):
    results = {
        'sql_vulns': 0,
        'xss_vulns': 0,
        'dom_vulns': 0,
        'scanned': 0
    }
    
    def scan_worker(url):
        try:
            sql, xss, dom = scan_url_threaded(url, timeout)
            return len(sql), len(xss), len(dom), url
        except Exception:
            return 0, 0, 0, url
    
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {executor.submit(scan_worker, url): url for url in urls}
        
        for future in as_completed(futures):
            try:
                sql_count, xss_count, dom_count, scanned_url = future.result()
                results['sql_vulns'] += sql_count
                results['xss_vulns'] += xss_count
                results['dom_vulns'] += dom_count
                results['scanned'] += 1
                
                with thread_lock:
                    progress_bar(results['scanned'], len(urls), f"{Fore.CYAN}Scanning{Style.RESET_ALL}")
                    
                    status_parts = []
                    if sql_count > 0:
                        status_parts.append(f"{Fore.RED}SQLi:{sql_count}{Style.RESET_ALL}")
                    if xss_count > 0:
                        status_parts.append(f"{Fore.MAGENTA}XSS:{xss_count}{Style.RESET_ALL}")
                    if dom_count > 0:
                        status_parts.append(f"{Fore.YELLOW}DOM:{dom_count}{Style.RESET_ALL}")
                    
                    if status_parts:
                        print(f"\n    {Fore.GREEN}[+]{Style.RESET_ALL} {scanned_url[:50]}... [{', '.join(status_parts)}]")
                    else:
                        print(f"\n    {Fore.BLUE}[-]{Style.RESET_ALL} {scanned_url[:60]}...")
                        
            except Exception:
                results['scanned'] += 1
    
    return results


def search_dork(dork, num_results=100):
    try:
        scraper_api_key = "1820c54a47ebf6d3557d9be57aa70c81"
        print_info("Menggunakan ScraperAPI untuk bypass captcha...")
        search = GoogleSearch(scraper_api_key=scraper_api_key)
        
        urls = []
        results_per_page = 10
        total_pages = (num_results + results_per_page - 1) // results_per_page
        
        for page in range(1, total_pages + 1):
            loading_animation(f"Mencari di Google... (Halaman {page}/{total_pages})", 1)
            try:
                results = search.search(dork, num_results=results_per_page, page=page)
                
                for result in results:
                    if hasattr(result, 'url'):
                        urls.append(result.url)
                    elif isinstance(result, dict) and 'url' in result:
                        urls.append(result['url'])
                    elif isinstance(result, str):
                        urls.append(result)
                
                print_info(f"Halaman {page}: Ditemukan {Fore.YELLOW}{len(results)}{Style.RESET_ALL} URL")
                
                if len(urls) >= num_results:
                    break
                    
                if len(results) < results_per_page:
                    break
                    
            except Exception as e:
                print_warning(f"Halaman {page} error: {str(e)}")
                continue
        
        urls = list(dict.fromkeys(urls))[:num_results]
        
        print_success(f"Total ditemukan {Fore.YELLOW}{len(urls)}{Style.RESET_ALL} URL unik")
        return urls
    except Exception as e:
        print_error(f"Search error: {str(e)}")
        return []


def menu_dork_scan():
    clear_screen()
    print_banner()
    
    print(f"""
    {Fore.CYAN}┌────────────────────────────────────────────────────────────────────┐
    │  {Fore.YELLOW}◆  GOOGLE DORK SCANNER{Fore.CYAN}                                           │
    └────────────────────────────────────────────────────────────────────┘
{Style.RESET_ALL}""")
    
    print(f"    {Fore.WHITE}Contoh dork:{Style.RESET_ALL}")
    print(f"    {Fore.GREEN}•{Style.RESET_ALL} inurl:php?id=")
    print(f"    {Fore.GREEN}•{Style.RESET_ALL} inurl:product.php?id=")
    print(f"    {Fore.GREEN}•{Style.RESET_ALL} site:example.com inurl:?id=")
    print()
    
    dork = input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Masukkan Google Dork: ").strip()
    
    if not dork:
        print_error("Dork tidak boleh kosong!")
        input(f"\n    {Fore.CYAN}Tekan Enter untuk kembali...{Style.RESET_ALL}")
        return
    
    print_divider()
    print_info(f"Mencari: {Fore.YELLOW}{dork}{Style.RESET_ALL}")
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    urls = search_dork(dork, settings['num_results'])
    
    if urls:
        print_divider()
        print_info(f"Memulai scan {len(urls)} URL dengan {Fore.GREEN}{settings['threads']} threads{Style.RESET_ALL}")
        print_info(f"Scan: SQL Injection + Reflected XSS + DOM-based XSS")
        print()
        
        results = multi_threaded_scan(urls, settings['timeout'], settings['threads'])
        
        print_divider()
        total_vulns = results['sql_vulns'] + results['xss_vulns'] + results['dom_vulns']
        print(f"""
    {Fore.CYAN}╔{'═'*66}╗
    ║{Fore.GREEN}                      SCAN SELESAI                               {Fore.CYAN}║
    ╠{'═'*66}╣
    ║{Fore.WHITE}  Total URL di-scan    : {Fore.YELLOW}{len(urls):<40}{Fore.CYAN}║
    ║{Fore.WHITE}  SQL Injection Found  : {Fore.RED if results['sql_vulns'] > 0 else Fore.GREEN}{results['sql_vulns']:<40}{Fore.CYAN}║
    ║{Fore.WHITE}  Reflected XSS Found  : {Fore.MAGENTA if results['xss_vulns'] > 0 else Fore.GREEN}{results['xss_vulns']:<40}{Fore.CYAN}║
    ║{Fore.WHITE}  DOM-based XSS Found  : {Fore.YELLOW if results['dom_vulns'] > 0 else Fore.GREEN}{results['dom_vulns']:<40}{Fore.CYAN}║
    ║{Fore.WHITE}  Total Vulnerability  : {Fore.RED if total_vulns > 0 else Fore.GREEN}{total_vulns:<40}{Fore.CYAN}║
    ╚{'═'*66}╝{Style.RESET_ALL}
""")
    else:
        print_error("Tidak ada URL ditemukan.")
    
    input(f"\n    {Fore.CYAN}Tekan Enter untuk kembali ke menu...{Style.RESET_ALL}")


def menu_single_url():
    clear_screen()
    print_banner()
    
    print(f"""
    {Fore.CYAN}┌────────────────────────────────────────────────────────────────────┐
    │  {Fore.YELLOW}◆  SINGLE URL SCANNER{Fore.CYAN}                                            │
    └────────────────────────────────────────────────────────────────────┘
{Style.RESET_ALL}""")
    
    print(f"    {Fore.WHITE}Contoh URL:{Style.RESET_ALL}")
    print(f"    {Fore.GREEN}•{Style.RESET_ALL} http://example.com/page.php?id=1")
    print(f"    {Fore.GREEN}•{Style.RESET_ALL} http://example.com/product.php?cat=5&id=10")
    print()
    
    url = input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Masukkan URL target: ").strip()
    
    if not url:
        print_error("URL tidak boleh kosong!")
        input(f"\n    {Fore.CYAN}Tekan Enter untuk kembali...{Style.RESET_ALL}")
        return
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    print_divider()
    print_info(f"Target: {Fore.YELLOW}{url}{Style.RESET_ALL}")
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    loading_animation("Menyiapkan scan (SQLi + Reflected XSS + DOM XSS)...", 1)
    
    sql_vulns, xss_vulns, dom_vulns = scan_url(url, settings['timeout'])
    
    print_divider()
    total_vulns = len(sql_vulns) + len(xss_vulns) + len(dom_vulns)
    if total_vulns > 0:
        print_success(f"Ditemukan: {Fore.RED}{len(sql_vulns)}{Style.RESET_ALL} SQLi, {Fore.MAGENTA}{len(xss_vulns)}{Style.RESET_ALL} Reflected XSS, {Fore.YELLOW}{len(dom_vulns)}{Style.RESET_ALL} DOM XSS")
    else:
        print_warning("Tidak ada vulnerability ditemukan.")
    
    input(f"\n    {Fore.CYAN}Tekan Enter untuk kembali ke menu...{Style.RESET_ALL}")


def menu_view_results():
    clear_screen()
    print_banner()
    
    print(f"""
    {Fore.CYAN}┌────────────────────────────────────────────────────────────────────┐
    │  {Fore.YELLOW}◆  HASIL VULNERABILITY{Fore.CYAN}                                           │
    └────────────────────────────────────────────────────────────────────┘
{Style.RESET_ALL}""")
    
    total_vulns = len(all_vulnerabilities) + len(all_xss_vulnerabilities) + len(all_dom_xss_vulnerabilities)
    
    if total_vulns == 0:
        print_warning("Belum ada vulnerability yang ditemukan.")
        print_info("Lakukan scan terlebih dahulu untuk melihat hasil.")
    else:
        print_success(f"Total: {Fore.RED}{len(all_vulnerabilities)}{Style.RESET_ALL} SQLi, {Fore.MAGENTA}{len(all_xss_vulnerabilities)}{Style.RESET_ALL} Reflected XSS, {Fore.YELLOW}{len(all_dom_xss_vulnerabilities)}{Style.RESET_ALL} DOM XSS\n")
        
        if all_vulnerabilities:
            print(f"\n    {Fore.RED}═══ SQL INJECTION VULNERABILITIES ═══{Style.RESET_ALL}")
            for i, vuln in enumerate(all_vulnerabilities, 1):
                print(f"""
    {Fore.RED}[SQLi-{i}]{Style.RESET_ALL} {Fore.CYAN}{'─'*54}{Style.RESET_ALL}
    {Fore.YELLOW}URL:{Style.RESET_ALL} {vuln['url'][:70]}{'...' if len(vuln['url']) > 70 else ''}
    {Fore.YELLOW}Parameter:{Style.RESET_ALL} {vuln['parameter']}
    {Fore.YELLOW}Database:{Style.RESET_ALL} {vuln['db_type']}
    {Fore.YELLOW}Error:{Style.RESET_ALL} {vuln['error'][:80]}...""")
        
        if all_xss_vulnerabilities:
            print(f"\n    {Fore.MAGENTA}═══ REFLECTED XSS VULNERABILITIES ═══{Style.RESET_ALL}")
            for i, vuln in enumerate(all_xss_vulnerabilities, 1):
                payload_display = vuln['payload'][:60] if len(vuln['payload']) > 60 else vuln['payload']
                print(f"""
    {Fore.MAGENTA}[XSS-{i}]{Style.RESET_ALL} {Fore.CYAN}{'─'*55}{Style.RESET_ALL}
    {Fore.YELLOW}URL:{Style.RESET_ALL} {vuln['url'][:70]}{'...' if len(vuln['url']) > 70 else ''}
    {Fore.YELLOW}Parameter:{Style.RESET_ALL} {vuln['parameter']}
    {Fore.YELLOW}Type:{Style.RESET_ALL} {vuln['xss_type']}
    {Fore.YELLOW}Payload:{Style.RESET_ALL} {payload_display}""")
        
        if all_dom_xss_vulnerabilities:
            print(f"\n    {Fore.YELLOW}═══ DOM-BASED XSS VULNERABILITIES ═══{Style.RESET_ALL}")
            for i, vuln in enumerate(all_dom_xss_vulnerabilities, 1):
                print(f"""
    {Fore.YELLOW}[DOM-{i}]{Style.RESET_ALL} {Fore.CYAN}{'─'*55}{Style.RESET_ALL}
    {Fore.WHITE}URL:{Style.RESET_ALL} {vuln['url'][:70]}{'...' if len(vuln['url']) > 70 else ''}
    {Fore.WHITE}Source:{Style.RESET_ALL} {vuln['source']}
    {Fore.WHITE}Sink:{Style.RESET_ALL} {vuln['sink']}""")
        
        print(f"\n    {Fore.CYAN}{'─'*60}{Style.RESET_ALL}")
    
    input(f"\n    {Fore.CYAN}Tekan Enter untuk kembali ke menu...{Style.RESET_ALL}")


def menu_settings():
    while True:
        clear_screen()
        print_banner()
        
        api_status = f"{Fore.GREEN}Active"
        
        print(f"""
    {Fore.CYAN}┌────────────────────────────────────────────────────────────────────┐
    │  {Fore.YELLOW}◆  PENGATURAN{Fore.CYAN}                                                    │
    ├────────────────────────────────────────────────────────────────────┤
    │                                                                    │
    │  {Fore.YELLOW}[1]{Fore.WHITE} Jumlah Hasil Pencarian  : {Fore.GREEN}{settings['num_results']:<35}{Fore.CYAN}│
    │  {Fore.YELLOW}[2]{Fore.WHITE} Request Timeout (detik) : {Fore.GREEN}{settings['timeout']:<35}{Fore.CYAN}│
    │  {Fore.YELLOW}[3]{Fore.WHITE} Jumlah Thread           : {Fore.GREEN}{settings['threads']:<35}{Fore.CYAN}│
    │                                                                    │
    ├────────────────────────────────────────────────────────────────────┤
    │  {Fore.MAGENTA}ScraperAPI Status: {api_status}{' '*40}{Fore.CYAN}│
    ├────────────────────────────────────────────────────────────────────┤
    │  {Fore.YELLOW}[0]{Fore.WHITE} Kembali ke Menu Utama                                      {Fore.CYAN}│
    └────────────────────────────────────────────────────────────────────┘
{Style.RESET_ALL}""")
        
        choice = input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Pilih opsi: ").strip()
        
        if choice == '1':
            try:
                num = int(input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Jumlah hasil (1-100): "))
                if 1 <= num <= 100:
                    settings['num_results'] = num
                    print_success("Pengaturan disimpan!")
                else:
                    print_error("Nilai harus antara 1-100")
            except ValueError:
                print_error("Masukkan angka yang valid!")
            time.sleep(1)
        
        elif choice == '2':
            try:
                timeout = int(input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Timeout (5-60 detik): "))
                if 5 <= timeout <= 60:
                    settings['timeout'] = timeout
                    print_success("Pengaturan disimpan!")
                else:
                    print_error("Nilai harus antara 5-60")
            except ValueError:
                print_error("Masukkan angka yang valid!")
            time.sleep(1)
        
        elif choice == '3':
            try:
                threads = int(input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Jumlah thread (1-20): "))
                if 1 <= threads <= 20:
                    settings['threads'] = threads
                    print_success("Pengaturan disimpan!")
                else:
                    print_error("Nilai harus antara 1-20")
            except ValueError:
                print_error("Masukkan angka yang valid!")
            time.sleep(1)
        
        elif choice == '0':
            break


def menu_about():
    clear_screen()
    print_banner()
    
    print(f"""
    {Fore.CYAN}┌────────────────────────────────────────────────────────────────────┐
    │  {Fore.YELLOW}◆  TENTANG XNOXS-DORK{Fore.CYAN}                                             │
    ├────────────────────────────────────────────────────────────────────┤
    │                                                                    │
    │  {Fore.WHITE}xnoxs-dork adalah tool untuk mendeteksi kerentanan SQL{Fore.CYAN}           │
    │  {Fore.WHITE}Injection dan XSS pada website. Tool ini melakukan:{Fore.CYAN}              │
    │                                                                    │
    │  {Fore.GREEN}•{Fore.WHITE} Pencarian Google menggunakan dork query{Fore.CYAN}                      │
    │  {Fore.GREEN}•{Fore.WHITE} Multi-threaded scanning untuk performa lebih cepat{Fore.CYAN}           │
    │  {Fore.GREEN}•{Fore.WHITE} Scan SQL Injection (MySQL, PostgreSQL, MSSQL, dll){Fore.CYAN}           │
    │  {Fore.GREEN}•{Fore.WHITE} Scan Reflected XSS dengan multiple payload{Fore.CYAN}                   │
    │  {Fore.GREEN}•{Fore.WHITE} Scan DOM-based XSS (source & sink analysis){Fore.CYAN}                  │
    │  {Fore.GREEN}•{Fore.WHITE} Bypass captcha Google dengan ScraperAPI{Fore.CYAN}                      │
    │                                                                    │
    ├────────────────────────────────────────────────────────────────────┤
    │  {Fore.RED}DISCLAIMER:{Fore.CYAN}                                                       │
    │  {Fore.WHITE}Tool ini hanya untuk keperluan edukasi dan security research.{Fore.CYAN}    │
    │  {Fore.WHITE}Pastikan Anda memiliki izin sebelum melakukan testing.{Fore.CYAN}           │
    │                                                                    │
    ├────────────────────────────────────────────────────────────────────┤
    │  {Fore.MAGENTA}Version: {Fore.WHITE}2.2{Fore.CYAN}                                                      │
    │  {Fore.MAGENTA}Author:{Fore.WHITE}  xnoxs{Fore.CYAN}                                                    │
    │  {Fore.MAGENTA}GitHub:{Fore.WHITE}  github.com/developerxnoxs{Fore.CYAN}                                │
    └────────────────────────────────────────────────────────────────────┘
{Style.RESET_ALL}""")
    
    input(f"\n    {Fore.CYAN}Tekan Enter untuk kembali ke menu...{Style.RESET_ALL}")


def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    while True:
        clear_screen()
        print_banner()
        print_menu()
        
        choice = input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Pilih menu: ").strip()
        
        if choice == '1':
            menu_dork_scan()
        elif choice == '2':
            menu_single_url()
        elif choice == '3':
            menu_view_results()
        elif choice == '4':
            menu_settings()
        elif choice == '5':
            menu_about()
        elif choice == '0':
            clear_screen()
            print(f"""
    {Fore.CYAN}╔════════════════════════════════════════════════════════════════════╗
    ║                                                                    ║
    ║  {Fore.YELLOW}Terima kasih telah menggunakan xnoxs-dork!{Fore.CYAN}                       ║
    ║  {Fore.WHITE}Gunakan dengan bijak dan bertanggung jawab.{Fore.CYAN}                      ║
    ║                                                                    ║
    ╚════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")
            sys.exit(0)
        else:
            print_error("Pilihan tidak valid!")
            time.sleep(1)


if __name__ == "__main__":
    main()
