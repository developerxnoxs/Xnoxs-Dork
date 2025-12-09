# xnoxs-dork - SQL Injection Vulnerability Scanner

## Overview
A Python security research tool with interactive menu for detecting SQL injection vulnerabilities by testing websites with single quote (') injection and detecting database error patterns.

## Usage

```bash
# Run the interactive menu
python xnoxs_dork.py
```

## Menu Options
1. Scan dengan Google Dork - Search Google and scan found URLs
2. Scan URL Tunggal - Test a single URL directly
3. Lihat Hasil Vulnerability - View all found vulnerabilities
4. Pengaturan - Configure timeout and number of results
5. Tentang Tool - About the tool
0. Keluar - Exit

## Features
- Google dork search integration via xnoxs-engine library
- ScraperAPI integration for bypassing Google captcha
- SQL injection detection by injecting single quote (')
- Error pattern recognition for: MySQL, PostgreSQL, MSSQL, Oracle, SQLite, IBM DB2
- Colored CLI output with vulnerability reports

## Secrets Required
- `SCRAPER_API_KEY` - ScraperAPI key for Google search (already configured)

## Dependencies
- requests
- colorama
- xnoxs-engine (from https://github.com/developerxnoxs/SearchEngine)

## Architecture
- `xnoxs_dork.py` - Main CLI tool with all functionality
  - `SQL_ERROR_PATTERNS` - Database-specific error regex patterns
  - `inject_payload()` - URL parameter injection
  - `detect_sql_error()` - Error pattern matching
  - `scan_url()` - URL vulnerability testing
  - `search_dork()` - Google search integration with ScraperAPI
