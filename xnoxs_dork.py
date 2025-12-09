#!/usr/bin/env python3
"""
xnoxs-dork - SQL Injection Vulnerability Scanner
A security research tool for detecting SQL injection vulnerabilities.
For educational and authorized testing purposes only.
"""

import os
import re
import sys
import time
import urllib.parse
from colorama import Fore, Back, Style, init
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

settings = {
    'num_results': 10,
    'timeout': 10
}

all_vulnerabilities = []


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    banner = f"""
{Fore.CYAN}    ╔══════════════════════════════════════════════════════════════════════╗
    ║                                                                      ║
    ║  {Fore.RED}██╗  ██╗███╗   ██╗ ██████╗ ██╗  ██╗███████╗    {Fore.MAGENTA}██████╗  ██████╗ ██████╗ ██╗  ██╗{Fore.CYAN}  ║
    ║  {Fore.RED}╚██╗██╔╝████╗  ██║██╔═══██╗╚██╗██╔╝██╔════╝    {Fore.MAGENTA}██╔══██╗██╔═══██╗██╔══██╗██║ ██╔╝{Fore.CYAN}  ║
    ║  {Fore.RED} ╚███╔╝ ██╔██╗ ██║██║   ██║ ╚███╔╝ ███████╗    {Fore.MAGENTA}██║  ██║██║   ██║██████╔╝█████╔╝{Fore.CYAN}   ║
    ║  {Fore.RED} ██╔██╗ ██║╚██╗██║██║   ██║ ██╔██╗ ╚════██║    {Fore.MAGENTA}██║  ██║██║   ██║██╔══██╗██╔═██╗{Fore.CYAN}   ║
    ║  {Fore.RED}██╔╝ ██╗██║ ╚████║╚██████╔╝██╔╝ ██╗███████║    {Fore.MAGENTA}██████╔╝╚██████╔╝██║  ██║██║  ██╗{Fore.CYAN}  ║
    ║  {Fore.RED}╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝    {Fore.MAGENTA}╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝{Fore.CYAN}  ║
    ║                                                                      ║
    ║  {Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Fore.CYAN}  ║
    ║  {Fore.WHITE}           SQL Injection Vulnerability Scanner v2.0{Fore.CYAN}                ║
    ║  {Fore.GREEN}              For Security Research Purposes Only{Fore.CYAN}                  ║
    ║  {Fore.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Fore.CYAN}  ║
    ║                                                                      ║
    ╚══════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
    print(banner)


def print_menu():
    api_status = f"{Fore.GREEN}Active" if os.environ.get('SCRAPER_API_KEY') else f"{Fore.RED}Not Set"
    
    menu = f"""
    {Fore.CYAN}┌────────────────────────────────────────────────────────────────────┐
    │                                                                    │
    │  {Fore.YELLOW}[1]{Fore.WHITE} ◆  Scan dengan Google Dork                                  {Fore.CYAN}│
    │  {Fore.YELLOW}[2]{Fore.WHITE} ◆  Scan URL Tunggal                                         {Fore.CYAN}│
    │  {Fore.YELLOW}[3]{Fore.WHITE} ◆  Lihat Hasil Vulnerability                                {Fore.CYAN}│
    │  {Fore.YELLOW}[4]{Fore.WHITE} ◆  Pengaturan                                               {Fore.CYAN}│
    │  {Fore.YELLOW}[5]{Fore.WHITE} ◆  Tentang Tool                                             {Fore.CYAN}│
    │  {Fore.YELLOW}[0]{Fore.WHITE} ◆  Keluar                                                   {Fore.CYAN}│
    │                                                                    │
    ├────────────────────────────────────────────────────────────────────┤
    │  {Fore.MAGENTA}ScraperAPI: {api_status}  {Fore.CYAN}│  {Fore.MAGENTA}Timeout: {Fore.WHITE}{settings['timeout']}s  {Fore.CYAN}│  {Fore.MAGENTA}Max Results: {Fore.WHITE}{settings['num_results']}       {Fore.CYAN}│
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
    
    injected_urls = inject_payload(url)
    
    for param_name, injected_url in injected_urls:
        if not silent:
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
                all_vulnerabilities.append(vuln)
                if not silent:
                    print_vuln(injected_url, db_type, error_snippet)
    
    return vulnerabilities


def search_dork(dork, num_results=10):
    try:
        scraper_api_key = os.environ.get('SCRAPER_API_KEY')
        if scraper_api_key:
            print_info("Menggunakan ScraperAPI untuk bypass captcha...")
            search = GoogleSearch(scraper_api_key=scraper_api_key)
        else:
            print_warning("ScraperAPI key tidak ditemukan. Google mungkin memblokir request.")
            search = GoogleSearch()
        
        loading_animation("Mencari di Google...", 2)
        results = search.search(dork, num_results=num_results)
        
        urls = []
        for result in results:
            if hasattr(result, 'url'):
                urls.append(result.url)
            elif isinstance(result, dict) and 'url' in result:
                urls.append(result['url'])
            elif isinstance(result, str):
                urls.append(result)
        
        print_success(f"Ditemukan {Fore.YELLOW}{len(urls)}{Style.RESET_ALL} URL")
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
        print_info(f"Memulai scan {len(urls)} URL...")
        print()
        
        found_vulns = 0
        for i, url in enumerate(urls, 1):
            progress_bar(i, len(urls), f"{Fore.CYAN}Scanning{Style.RESET_ALL}")
            print(f"\n    {Fore.CYAN}[{i}/{len(urls)}]{Style.RESET_ALL} {url[:60]}...")
            vulns = scan_url(url, settings['timeout'])
            found_vulns += len(vulns)
        
        print_divider()
        print(f"""
    {Fore.CYAN}╔{'═'*66}╗
    ║{Fore.GREEN}                      SCAN SELESAI                               {Fore.CYAN}║
    ╠{'═'*66}╣
    ║{Fore.WHITE}  Total URL di-scan    : {Fore.YELLOW}{len(urls):<40}{Fore.CYAN}║
    ║{Fore.WHITE}  Vulnerability Found  : {Fore.RED if found_vulns > 0 else Fore.GREEN}{found_vulns:<40}{Fore.CYAN}║
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
    
    loading_animation("Menyiapkan scan...", 1)
    
    vulns = scan_url(url, settings['timeout'])
    
    print_divider()
    if vulns:
        print_success(f"Ditemukan {Fore.RED}{len(vulns)}{Style.RESET_ALL} vulnerability!")
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
    
    if not all_vulnerabilities:
        print_warning("Belum ada vulnerability yang ditemukan.")
        print_info("Lakukan scan terlebih dahulu untuk melihat hasil.")
    else:
        print_success(f"Total: {Fore.YELLOW}{len(all_vulnerabilities)}{Style.RESET_ALL} vulnerability ditemukan\n")
        
        for i, vuln in enumerate(all_vulnerabilities, 1):
            print(f"""
    {Fore.GREEN}[{i}]{Style.RESET_ALL} {Fore.CYAN}{'─'*60}{Style.RESET_ALL}
    {Fore.YELLOW}URL:{Style.RESET_ALL} {vuln['url'][:70]}{'...' if len(vuln['url']) > 70 else ''}
    {Fore.YELLOW}Parameter:{Style.RESET_ALL} {vuln['parameter']}
    {Fore.YELLOW}Database:{Style.RESET_ALL} {vuln['db_type']}
    {Fore.YELLOW}Error:{Style.RESET_ALL} {vuln['error'][:80]}...""")
        
        print(f"\n    {Fore.CYAN}{'─'*60}{Style.RESET_ALL}")
    
    input(f"\n    {Fore.CYAN}Tekan Enter untuk kembali ke menu...{Style.RESET_ALL}")


def menu_settings():
    while True:
        clear_screen()
        print_banner()
        
        api_status = f"{Fore.GREEN}Active" if os.environ.get('SCRAPER_API_KEY') else f"{Fore.RED}Not Set"
        
        print(f"""
    {Fore.CYAN}┌────────────────────────────────────────────────────────────────────┐
    │  {Fore.YELLOW}◆  PENGATURAN{Fore.CYAN}                                                    │
    ├────────────────────────────────────────────────────────────────────┤
    │                                                                    │
    │  {Fore.YELLOW}[1]{Fore.WHITE} Jumlah Hasil Pencarian  : {Fore.GREEN}{settings['num_results']:<35}{Fore.CYAN}│
    │  {Fore.YELLOW}[2]{Fore.WHITE} Request Timeout (detik) : {Fore.GREEN}{settings['timeout']:<35}{Fore.CYAN}│
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
    │  {Fore.WHITE}Injection pada website. Tool ini melakukan:{Fore.CYAN}                      │
    │                                                                    │
    │  {Fore.GREEN}•{Fore.WHITE} Pencarian Google menggunakan dork query{Fore.CYAN}                      │
    │  {Fore.GREEN}•{Fore.WHITE} Injeksi payload (single quote) ke parameter URL{Fore.CYAN}              │
    │  {Fore.GREEN}•{Fore.WHITE} Deteksi error database (MySQL, PostgreSQL, MSSQL, dll){Fore.CYAN}       │
    │  {Fore.GREEN}•{Fore.WHITE} Bypass captcha Google dengan ScraperAPI{Fore.CYAN}                      │
    │                                                                    │
    ├────────────────────────────────────────────────────────────────────┤
    │  {Fore.RED}DISCLAIMER:{Fore.CYAN}                                                       │
    │  {Fore.WHITE}Tool ini hanya untuk keperluan edukasi dan security research.{Fore.CYAN}    │
    │  {Fore.WHITE}Pastikan Anda memiliki izin sebelum melakukan testing.{Fore.CYAN}           │
    │                                                                    │
    ├────────────────────────────────────────────────────────────────────┤
    │  {Fore.MAGENTA}Version: {Fore.WHITE}2.0{Fore.CYAN}                                                      │
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
