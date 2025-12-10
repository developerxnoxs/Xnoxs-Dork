# XNOXS DORK

SQLi & XSS Vulnerability Scanner v2.2 [Multi-threaded]

## Deskripsi

XNOXS DORK adalah tool keamanan untuk mendeteksi kerentanan SQL Injection dan XSS (Cross-Site Scripting) pada website. Tool ini menggunakan Google Dork untuk mencari target URL dan melakukan scanning secara otomatis dengan multi-threading.

**For Security Research Purposes Only**

## Fitur

- **Google Dork Scanner** - Mencari target URL menggunakan Google Dork dengan pagination (hingga 100+ URL)
- **SQL Injection Detection** - Mendeteksi kerentanan SQLi pada berbagai database (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, dll)
- **Reflected XSS Detection** - Mendeteksi kerentanan Reflected XSS
- **DOM-based XSS Detection** - Analisis source & sink untuk mendeteksi DOM XSS
- **Multi-threaded Scanning** - Scanning paralel untuk performa lebih cepat
- **ScraperAPI Integration** - Bypass Google captcha untuk hasil pencarian yang lebih andal
- **Export Results** - Simpan hasil vulnerability ke file

## Instalasi

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/xnoxs-dork.git
cd xnoxs-dork
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

## Penggunaan

### Jalankan Tool

```bash
python xnoxs_dork.py
```

### Menu Utama

```
[1] Scan dengan Google Dork (Multi-threaded)
[2] Scan URL Tunggal
[3] Lihat Hasil Vulnerability
[4] Pengaturan
[5] Tentang Tool
[0] Keluar
```

### Contoh Google Dork

```
inurl:php?id=
inurl:product.php?id=
site:example.com inurl:?id=
inurl:index.php?page=
inurl:article.php?id=
```

## Pengaturan

- **Threads** - Jumlah thread untuk scanning paralel (default: 5)
- **Timeout** - Timeout request dalam detik (default: 10s)
- **Results** - Jumlah maksimal URL dari Google Dork (default: 100)

## Database yang Didukung

Tool ini dapat mendeteksi error SQL Injection dari berbagai database:

- MySQL / MariaDB
- PostgreSQL
- Microsoft SQL Server
- Oracle
- SQLite
- IBM DB2
- Generic SQL Errors

## Disclaimer

Tool ini dibuat untuk tujuan edukasi dan penelitian keamanan. Penggunaan tool ini untuk aktivitas ilegal atau tanpa izin adalah tanggung jawab pengguna sepenuhnya. Selalu dapatkan izin tertulis sebelum melakukan pengujian keamanan pada sistem yang bukan milik Anda.

## Requirements

- Python 3.9+
- colorama
- requests
- xnoxs-engine

## Lisensi

MIT License

## Author

XNOXS Team
