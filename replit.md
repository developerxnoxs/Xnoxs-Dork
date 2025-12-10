# XNOXS DORK - Multi-Vulnerability Scanner

## Overview
Tool komprehensif untuk mendeteksi berbagai kerentanan keamanan termasuk SQL Injection, XSS, LFI, dan RCE menggunakan Google Dork scanning, multi-threading, dan advanced URL filtering.

## Fitur Utama
- **SQL Injection Detection** (Error-based, Boolean-based Blind, Time-based Blind)
- **XSS Detection** (Reflected XSS, DOM-based XSS)
- **LFI Detection** (Local File Inclusion) - Path Traversal, Null Byte Injection
- **RCE Detection** (Remote Code Execution) - Command Injection untuk Linux & Windows
- Google Dork Scanning dengan ScraperAPI
- Multi-threaded scanning
- **Advanced URL Filtering System** - Filter otomatis domain yang tidak relevan
- **Sample Dorks Library** - Koleksi dorks untuk SQLi, XSS, LFI, RCE
- Export ke JSON, CSV, HTML
- Interactive CLI dan Command-line mode

## Vulnerability Types

### SQL Injection (Critical)
- Error-based SQLi
- Boolean-based Blind SQLi
- Time-based Blind SQLi

### XSS - Cross-Site Scripting (High)
- Reflected XSS
- DOM-based XSS

### LFI - Local File Inclusion (Critical)
- Path Traversal (../../etc/passwd)
- Null Byte Injection
- PHP Wrapper Attacks

### RCE - Remote Code Execution (Critical)
- Command Injection (Linux: ; | && etc)
- Command Injection (Windows: & | etc)
- Code Execution via system functions

## Advanced URL Filter System

### Kategori Filter (8 Kategori)
1. **code_repos** - GitHub, GitLab, Bitbucket, SourceForge, dll
2. **forums** - StackOverflow, Reddit, Quora, StackExchange, dll
3. **docs** - Documentation sites (MDN, W3Schools, ReadTheDocs, dll)
4. **social** - Social media (Twitter/X, Facebook, YouTube, dll)
5. **search_engines** - Google, Bing, Yahoo, DuckDuckGo, dll
6. **cdn** - CDN & static assets (Cloudflare, jsDelivr, dll)
7. **security** - Security sites (VirusTotal, Shodan, HackerOne, dll)
8. **pastebin** - Pastebin sites

### Fitur Filter
- Toggle kategori ON/OFF
- Custom domain exclusion
- Pattern regex matching
- Whitelist domains (tidak akan difilter)
- Load/save konfigurasi dari file JSON
- Statistik filter detail

## Penggunaan

### Direct Command (Recommended)
```bash
xnoxs-dork
```

### Interactive Mode (Alternative)
```bash
python xnoxs_dork.py
```

### Command Line Mode
```bash
# Scan single URL
python xnoxs_dork.py -u "http://example.com/page.php?id=1"

# Scan dengan Google Dork
python xnoxs_dork.py -d "inurl:php?id=" -r 50

# Scan dari file
python xnoxs_dork.py -f urls.txt

# Export hasil
python xnoxs_dork.py -d "inurl:php?id=" -o results.json
```

### Filter Options (CLI)
```bash
# Disable semua filter
python xnoxs_dork.py -d "inurl:php?id=" --no-filter

# Gunakan hanya kategori tertentu
python xnoxs_dork.py -d "inurl:php?id=" --only-category code_repos --only-category forums

# Exclude kategori tertentu
python xnoxs_dork.py -d "inurl:php?id=" --exclude-category docs

# Whitelist domain (tidak akan difilter)
python xnoxs_dork.py -d "inurl:php?id=" --whitelist mysite.github.io

# Tambah domain ke exclusion
python xnoxs_dork.py -d "inurl:php?id=" --exclude-domain unwanted.com

# Load konfigurasi filter dari file
python xnoxs_dork.py -d "inurl:php?id=" --filter-config filter_config.json
```

## Sample Dorks Library

### SQL Injection Dorks
- `inurl:php?id=`
- `inurl:product.php?cat=`
- `inurl:news.php?id=`

### XSS Dorks
- `inurl:search.php?q=`
- `inurl:query= filetype:php`
- `inurl:msg= filetype:php`

### LFI Dorks
- `inurl:page= filetype:php`
- `inurl:file= filetype:php`
- `inurl:include= filetype:php`

### RCE Dorks
- `inurl:cmd= filetype:php`
- `inurl:exec= filetype:php`
- `inurl:shell= filetype:php`

## File Konfigurasi Filter (filter_config.json)
```json
{
  "categories": ["code_repos", "forums", "docs", "social", "search_engines", "cdn"],
  "excluded_domains": ["custom-exclude.com"],
  "excluded_patterns": [".*\\.edu$"],
  "whitelisted_domains": ["allowed-site.github.io"]
}
```

## Menu Pengaturan Filter (Interactive Mode)
1. Buka menu Pengaturan [6]
2. Pilih Advanced URL Filter [4]
3. Opsi tersedia:
   - Toggle Filter ON/OFF
   - Manage Filter Categories
   - Add Custom Domain/Pattern Exclusion
   - Manage Whitelist
   - View Current Filter Settings
   - Load/Save Filter Config
   - Reset to Default

## Dependencies
- colorama
- requests
- SearchEngine

## Recent Changes
- 2024-12: Added LFI (Local File Inclusion) detection with path traversal payloads
- 2024-12: Added RCE (Remote Code Execution) detection with command injection payloads
- 2024-12: Added Sample Dorks Library with SQLi, XSS, LFI, RCE categories
- 2024-12: Updated all export formats (JSON, CSV, HTML) to include LFI/RCE results
- 2024-12: Enhanced multi-threaded scanning to include all 6 vulnerability types
- 2024: Upgraded URL filter ke Advanced version dengan 8 kategori, pattern matching, whitelist, dan CLI options
