import os
import re
import hashlib
import requests
import json
import time
from datetime import datetime

class SecurityAuditor:
    def __init__(self):
        self.version = "1.2.0"
        self.email_api_url = "https://api.xposedornot.com/v1/breach-analytics?email="
        self.password_api_url = "https://api.pwnedpasswords.com/range/"

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def validate_email(self, email):
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(email_regex, email) is not None

    def check_email_analytics(self, email, silent=False):
        if not silent:
            print(f"\n[*] Memeriksa email (Analisis Mendalam): {email} ...")
        headers = {"User-Agent": "Privacy-Auditor-Client/1.0"}
        
        try:
            # Menggunakan endpoint breach-analytics yang mengembalikan data statistik lengkap
            response = requests.get(f"{self.email_api_url}{email}", headers=headers, timeout=15)
            
            if response.status_code == 200:
                if not silent:
                    print(f"[!] PERINGATAN: Email ini ditemukan dalam database kebocoran data!")
                return response.json()
            elif response.status_code == 404:
                if not silent:
                    print("[+] Aman! Email tidak ditemukan dalam daftar kebocoran data.")
                return {}
            elif response.status_code == 429:
                print("[-] Error: Terlalu banyak permintaan ke server. Silakan tunggu beberapa saat.")
                return None
            else:
                print(f"[-] Respons server tidak dikenal. Status Code: {response.status_code}")
                return None
        except requests.exceptions.RequestException as e:
            print(f"[-] Gangguan Koneksi Internet: {e}")
            return None

    def check_password_leak(self, password):
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        try:
            response = requests.get(f"{self.password_api_url}{prefix}", timeout=10)
            if response.status_code != 200:
                print("[-] Gagal terhubung ke database kata sandi.")
                return False

            hashes = (line.split(':') for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    print(f"\n[!] PERINGATAN: Kata sandi ini telah bocor sebanyak {count} kali di internet!")
                    print("[⚠️] Jangan gunakan kata sandi ini di akun mana pun.")
                    return True
            
            print("\n[+] Aman! Kata sandi tidak ditemukan dalam database kebocoran.")
            return False
        except requests.exceptions.RequestException as e:
            print(f"[-] Error Jaringan: {e}")
            return False

    def parse_analytics_data(self, data):
        """Memproses data JSON mendalam dari endpoint breach-analytics"""
        if not data or "BreachMetrics" not in data:
            return None
            
        metrics = data.get("BreachMetrics", {})
        summary = data.get("ExposedBreaches", {}).get("breaches_details", [])
        
        # Ekstrak nama situs dan tahun kejadian (No. 8)
        sites_info = []
        current_year = datetime.now().year
        for b in summary:
            site_name = b.get("breach", "Unknown")
            leak_year_str = b.get("year", "")
            
            age_info = "Tahun tidak diketahui"
            if leak_year_str.isdigit():
                age = current_year - int(leak_year_str)
                age_info = f"Insiden {age} tahun yang lalu ({leak_year_str})"
                
            sites_info.append(f"{site_name} ({age_info})")

        # Ekstrak tipe data terekspos (No. 10)
        exposed_data = data.get("ExposedData", {}).get("data_classes", [])
        
        # Penanda tingkat risiko berdasarkan skor dari API (No. 11)
        risk_score = metrics.get("risk_score", 0)
        if risk_score > 75:
            risk_level = "SANGAT TINGGI"
        elif risk_score > 40:
            risk_level = "TINGGI"
        elif risk_score > 15:
            risk_level = "SEDANG"
        else:
            risk_level = "RENDAH"

        return {
            "total_breaches": metrics.get("number_of_breaches", 0),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "sites": sites_info,
            "data_types": exposed_data
        }

    def generate_html_report(self, results):
        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Privacy Audit Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f4f6f9; }}
                .container {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                h1 {{ color: #2c3e50; border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; }}
                .danger {{ color: #c0392b; font-weight: bold; }}
                .warning {{ color: #d35400; font-weight: bold; }}
                .success {{ color: #27ae60; font-weight: bold; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; vertical-align: top; }}
                th {{ background-color: #34495e; color: white; }}
                ul {{ margin: 0; padding-left: 20px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Laporan Audit Privasi Data (Analisis Mendalam)</h1>
                <p>Waktu Pemindaian: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <table>
                    <tr>
                        <th>Target Email</th>
                        <th>Skor & Tingkat Risiko</th>
                        <th>Sumber Kebocoran & Umur Insiden</th>
                        <th>Komponen Data yang Bocor</th>
                    </tr>
        """
        
        for target, raw_data in results.items():
            if raw_data:
                info = self.parse_analytics_data(raw_data)
                if info:
                    risk_class = "danger" if info["risk_score"] > 40 else "warning"
                    
                    sites_html = "".join([f"<li>{s}</li>" for s in info["sites"]])
                    types_html = "".join([f"<li>{t}</li>" for t in info["data_types"]])
                    
                    html_content += f"""<tr>
                        <td>{target}</td>
                        <td class='{risk_class}'>{info['risk_level']}<br>(Skor: {info['risk_score']})</td>
                        <td>Total: {info['total_breaches']} kebocoran<ul>{sites_html}</ul></td>
                        <td><ul>{types_html}</ul></td>
                    </tr>"""
                    continue
                    
            html_content += f"""<tr>
                <td>{target}</td>
                <td class='success'>AMAN</td>
                <td>Tidak ada kebocoran terdeteksi</td>
                <td>-</td>
            </tr>"""
                
        html_content += """
                </table>
            </div>
        </body>
        </html>
        """
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"\n[+] Laporan HTML Berhasil Dibuat: {os.path.abspath(filename)}")

    def run_bulk_scan(self):
        file_path = input("\n[*] Masukkan jalur file teks (contoh: email.txt): ").strip()
        if not os.path.exists(file_path):
            print("[-] File tidak ditemukan!")
            return

        with open(file_path, "r") as f:
            targets = [line.strip() for line in f if line.strip()]

        total_targets = len(targets)
        print(f"[*] Menemukan {total_targets} email. Memulai pemindaian...")
        
        batch_results = {}
        leaked_count = 0
        safe_count = 0

        for index, target in enumerate(targets, 1):
            # Fitur No. 27: Progress bar sederhana di terminal
            progress = (index / total_targets) * 100
            bar = '█' * int(progress / 10) + '░' * (10 - int(progress / 10))
            print(f"\r[*] Memproses: [{bar}] {progress:.1f}% ({index}/{total_targets})", end="", flush=True)

            if not self.validate_email(target):
                continue
            
            time.sleep(0.5) # Jeda aman anti rate-limiting
            
            res = self.check_email_analytics(target, silent=True)
            if res:
                batch_results[target] = res
                leaked_count += 1
            else:
                batch_results[target] = {}
                safe_count += 1
        
        print("\n\n[*] Pemindaian selesai.")
        
        # Fitur No. 13: Ringkasan statistik pemindaian
        print("\n================ STATISTIK PEMINDAIAN ================")
        print(f"Total Email Diperiksa : {total_targets}")
        print(f"Total Email Aman      : {safe_count}")
        print(f"Total Email Terekspos : {leaked_count}")
        print("======================================================")
            
        self.generate_html_report(batch_results)

    def print_remediation(self):
        print("\n================ PANDUAN KEAMANAN ================")
        print("[1] Aktifkan Otentikasi Dua Faktor (2FA).")
        print("[2] Gunakan Password Manager lokal atau open-source.")
        print("[3] Ganti kata sandi secara berkala jika terindikasi bocor.")
        print("==================================================")
        input("\nTekan Enter untuk kembali...")

    def menu(self):
        while True:
            self.clear_screen()
            print("====================================================")
            print("         EMAIL & PRIVACY AUDITOR by Mr.Rm19              ")
            print("====================================================")
            print(" [1] Pengecekan Email Tunggal (Breach Analytics)")
            print(" [2] Pemindaian Massal via File Teks (.txt)")
            print(" [3] Cek Kebocoran Kata Sandi")
            print(" [4] Lihat Panduan Remediasi")
            print(" [5] Keluar")
            print("----------------------------------------------------")
            pilihan = input("[*] Pilih menu (1-5): ").strip()

            if pilihan == "1":
                target = input("\n[*] Masukkan Email: ").strip()
                if not self.validate_email(target):
                    print("[-] Format email tidak valid!")
                    input("\nTekan Enter...")
                    continue
                res = self.check_email_analytics(target)
                if res:
                    info = self.parse_analytics_data(res)
                    if info:
                        print(f"\n[+] TINGKAT RISIKO AKUN : {info['risk_level']} (Skor: {info['risk_score']})")
                        print(f"[+] TOTAL KEBOCORAN     : {info['total_breaches']} kali")
                        
                        print("\n[!] Komponen Data yang Bocor:")
                        for t in info['data_types']:
                            print(f" - {t}")
                            
                        print("\n[!] Detail Instansi & Umur Kebocoran:")
                        for s in info['sites']:
                            print(f" - {s}")
                input("\nTekan Enter...")
            elif pilihan == "2":
                self.run_bulk_scan()
                input("\nTekan Enter...")
            elif pilihan == "3":
                pwd = input("\n[*] Masukkan kata sandi yang ingin diuji: ").strip()
                self.check_password_leak(pwd)
                input("\nTekan Enter...")
            elif pilihan == "4":
                self.print_remediation()
            elif pilihan == "5":
                print("\nProgram dihentikan.")
                break

if __name__ == "__main__":
    suite = SecurityAuditor()
    suite.menu()