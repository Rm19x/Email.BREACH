# Privacy & Email Breach Auditor 

Aplikasi audit privasi berbasis Command Line Interface (CLI) yang ditulis menggunakan Python. Alat ini dirancang untuk mendeteksi apakah alamat email atau kata sandi Anda telah terekspos dalam kasus kebocoran data (*data breach*) global di internet secara riil. 

Alat ini memanfaatkan API publik gratis yang andal dari **XposedOrNot (Breach Analytics)** untuk pemeriksaan email dan **PwnedPasswords (k-Anonymity)** untuk pengecekan kata sandi tanpa memerlukan pendaftaran atau kunci API (*API Key*).

---
<img src="https://raw.githubusercontent.com/Rm19x/Email.BREACH/refs/heads/main/auditor.png">

---

## Fitur Utama

* **Pengecekan Email Tunggal:** Memberikan analisis mendalam terkait tingkat risiko akun, total kebocoran, jenis data yang bocor, serta detail instansi beserta umur insiden.
* **Pemindaian Massal (Bulk Scan):** Membaca daftar email dari file `.txt` eksternal secara sekaligus, dilengkapi dengan *live progress bar* di terminal dan jeda aman (*rate-limiting handler*).
* **Statistik Pemindaian:** Menampilkan ringkasan data pasca-pemindaian massal yang mencakup total email aman vs terekspos.
* **Laporan HTML Otomatis:** Menghasilkan file laporan visual `.html` yang rapi setelah pemindaian massal selesai dilakukan.
* **Cek Kebocoran Kata Sandi:** Menguji keamanan kata sandi menggunakan metode aman *k-Anonymity* (hanya 5 karakter pertama dari hash SHA-1 yang dikirim ke internet, pencocokan sisa hash dilakukan secara lokal di memori RAM Anda).
* **Panduan Remediasi:** Menyediakan langkah-langkah mitigasi awal jika privasi akun Anda terindikasi dalam bahaya.

---

## Prasyarat & Instalasi

Sebelum menjalankan aplikasi ini, pastikan komputer Anda sudah terinstal **Python 3.x** dan pustaka **requests**.

```
pip install requests
python auditor.py
```
---

##  Detail Teknis API & Struktur Data

Aplikasi ini tidak menyimpan database kebocoran secara lokal, melainkan berkomunikasi secara langsung (*real-time*) dengan dua penyedia intelijen ancaman terkemuka:

### 1. XposedOrNot (Breach Analytics)
* **Endpoint:** `https://api.xposedornot.com/v1/breach-analytics?email=`
* **Metode:** `GET`
* **Analisis yang Diekstrak:**
  * **Risk Score & Level:** Mengalkulasi tingkat keparahan berdasarkan jenis data sensitif yang bocor (skor 0-100).
  * **Data Classes:** Mengidentifikasi komponen apa saja yang terekspos (Kata sandi, IP Address, Nama, Nomor Telepon).
  * **Breach Summary:** Menarik kronologi nama instansi/situs web yang mengalami peretasan beserta tahun kejadiannya untuk menghitung umur insiden secara akurat.

### 2. PwnedPasswords (k-Anonymity)
* **Endpoint:** `https://api.pwnedpasswords.com/range/[5_karakter_awal_hash]`
* **Metode:** `GET`
* **Keamanan Mutlak:** Menggunakan prinsip *Mathematical Privacy*. Program akan mengubah kata sandi Anda menjadi hash SHA-1 di memori lokal, memotong 5 karakter pertamanya untuk dikirim ke API, lalu mencocokkan sisa 35 karakter hash-nya secara lokal. Kata sandi asli Anda **tidak pernah** keluar dari komputer Anda.

---

##  Struktur Folder Proyek

Untuk memastikan proyek Anda rapi saat diunggah ke GitHub, pastikan struktur foldernya mengikuti susunan berikut:

```text
Nama-Repositori-Anda/
│
├── auditor.py          # Skrip utama aplikasi Python
├── README.md           # Dokumentasi lengkap proyek (File ini)
│
# File-file di bawah ini akan otomatis tercipta saat program dijalankan:
├── email.txt           # File input buatan Anda untuk pemindaian massal
└── report_*.html       # Laporan hasil audit visual berbasis web yang dihasilkan otomatis
