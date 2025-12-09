# xnoxs-dork - SQL Injection Vulnerability Scanner

## Overview
A Python CLI security research tool for detecting SQL injection vulnerabilities by testing websites with single quote (') injection and detecting database error patterns.

## Usage

```bash
# Search using Google dork and test URLs
python xnoxs_dork.py -d "inurl:php?id="

# Test a single URL
python xnoxs_dork.py -u "http://example.com/page.php?id=1"

# More results with custom timeout
python xnoxs_dork.py -d "inurl:product.php?id=" -n 20 -t 15
```

## Options
- `-d, --dork` - Google dork query to search
- `-u, --url` - Single URL to test
- `-n, --num` - Number of search results (default: 10)
- `-t, --timeout` - Request timeout in seconds (default: 10)

## Features
- Google dork search integration via xnoxs-engine library
- SQL injection detection by injecting single quote (')
- Error pattern recognition for: MySQL, PostgreSQL, MSSQL, Oracle, SQLite, IBM DB2
- Colored CLI output with vulnerability reports

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
  - `search_dork()` - Google search integration
