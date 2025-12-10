# xnoxs-dork v3.0 - SQL Injection & XSS Vulnerability Scanner

## Overview
A comprehensive Python security research tool with interactive menu for detecting SQL injection and XSS vulnerabilities. Features multi-threaded scanning, Google dork integration, and multiple export formats.

## Usage

```bash
# Interactive menu
python xnoxs_dork.py

# CLI mode with arguments
python xnoxs_dork.py -d "inurl:php?id=" -o results.json
python xnoxs_dork.py -u "http://example.com/page.php?id=1"
python xnoxs_dork.py -f urls.txt -o report.html
python xnoxs_dork.py --help
```

## Menu Options (Indonesian)
1. Scan dengan Google Dork - Search Google and scan found URLs
2. Scan URL Tunggal - Test a single URL directly
3. Lihat Hasil Vulnerability - View all found vulnerabilities
4. Pengaturan - Configure timeout, threads, and results count
5. Export Hasil - Export to JSON/CSV/HTML
6. Import URL dari File - Load URLs from text file
7. Tentang Tool - About the tool
0. Keluar - Exit

## CLI Arguments
- `-d, --dork` - Google dork query
- `-u, --url` - Single URL to scan
- `-f, --file` - File with URLs (one per line)
- `-o, --output` - Output file (.json/.csv/.html)
- `-t, --threads` - Number of threads (default: 5)
- `--timeout` - Request timeout in seconds (default: 10)
- `-n, --num-results` - Max URLs from Google (default: 100)

## Features
- Google dork search with pagination (up to 100 URLs)
- ScraperAPI integration for bypassing Google captcha
- Multi-threaded scanning with ThreadPoolExecutor
- SQL Injection detection:
  - Error-based (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, IBM DB2)
  - Blind SQLi - Boolean-based
  - Blind SQLi - Time-based
- XSS detection:
  - Reflected XSS with multiple payloads
  - DOM-based XSS pattern analysis
- Export formats: JSON, CSV, HTML
- Import URLs from file
- Colored CLI output with progress bars

## Secrets
- ScraperAPI key is hardcoded in the tool

## Dependencies
- requests
- colorama
- xnoxs-engine (from https://github.com/developerxnoxs/SearchEngine)

## Architecture
- `xnoxs_dork.py` - Main CLI tool with all functionality
  - SQL error pattern detection
  - Blind SQLi detection (Boolean + Time-based)
  - XSS payload injection and reflection detection
  - DOM XSS source/sink pattern analysis
  - Multi-threaded scanning
  - Export functions (JSON, CSV, HTML)
  - CLI argument parsing with argparse
