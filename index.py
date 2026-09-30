print("=" * 70)
print("SISTEM AUDIT KEAMANAN PASSWORD SECUREPASS")
print("D4 Rekayasa Keamanan Siber")
print("=" * 70)

# Definisi daftar IP berbahaya di tingkat global agar dapat diakses fungsi lain
ip_berbahaya = ["192.168.1.100", "10.0.0.1", "172.16.0.1"]

def tampilkan_header():
    """Menampilkan Header Sistem."""
    print("\n" + "=" * 70)
    print("SISTEM AUDIT KEAMANAN PASSWORD SECUREPASS")
    print("=" * 70)
    
# Pemanggilan fungsi
tampilkan_header()

def validasi_ip(ip):
    """Memvalidasi format alamat IP.
    Parameter:
    ip (str): Alamat IP yang akan divalidasi
    Return:
    bool: True jika valid, False jika tidak"""
    
    bagian = ip.split(".")
    
    if len(bagian) != 4:
        return False
    
    for b in bagian:
        if not b.isdigit():
            return False
        if int(b) < 0 or int(b) > 255:
            return False
        
    return True

def klasifikasi_ip(ip, daftar_berbahaya):
    """Mengklasifikasikan alamat IP berdasarkan daftar berbahaya."""
    if ip in daftar_berbahaya:
        return "BERBAHAYA"
    # Perbaikan 1: '172.' diubah menjadi string "172."
    elif ip.startswith("192.168") or ip.startswith("10.") or ip.startswith("172."):
        return "IP PRIVAT"
    else:
        return "IP PUBLIK"

# Perbaikan 2: Pengujian dipindahkan keluar dari dalam fungsi klasifikasi_ip
print("\n--- PENGUJIAN FUNGSI POSITIONAL ---")
ip_test1 = "192.168.1.100"
ip_test2 = "8.8.8.8"

print(f"IP {ip_test1} valid? {validasi_ip(ip_test1)}")
print(f"IP {ip_test2} valid? {validasi_ip(ip_test2)}")
print(f"Klasifikasi {ip_test1}: {klasifikasi_ip(ip_test1, ip_berbahaya)}")
print(f"Klasifikasi {ip_test2}: {klasifikasi_ip(ip_test2, ip_berbahaya)}")
    
def validasi_login(username, password, ip):
    """Memvalidasi login pengguna dengan keyword arguments."""
    database = {
        "admin": {"password": "Admin123", "ip": "192.168.1.100"},
        "user1": {"password": "User123", "ip": "192.168.1.101"},
    }
    
    if username not in database:
        return "GAGAL! - Username tidak terdaftar"
    if password != database[username]["password"]:
        return "GAGAL - Password salah"
    if ip != database[username]["ip"]:
        return "GAGAL - IP tidak terdaftar"
    
    return f"BERHASIL - Selamat datang {username}!"

# Pemanggilan keyword (urutan bebas)
print("\n--- PENGUJIAN FUNGSI KEYWORD ---")
hasil1 = validasi_login(password="Admin123", username="admin", ip="192.168.1.100")
hasil2 = validasi_login(ip="192.168.1.101", username="user1", password="User123")
hasil3 = validasi_login(username="admin", password="salah", ip="192.168.1.100")

print(f"Login 1: {hasil1}")
print(f"Login 2: {hasil2}")
print(f"Login 3: {hasil3}")

def scan_port(ip, port=80, protokol="TCP"):
    """Memindai satu port pada alamat IP tertentu."""
    port_berbahaya = [21, 23, 25, 135, 445, 3389]
    
    if port in port_berbahaya:
        status = "TERBUKA - BERBAHAYA"
    elif port < 1024:
        status = "TERBUKA - PERLU VERIFIKASI"
    else:
        status = "TERTUTUP"
        
    return f"{ip}:{port}/{protokol} -> {status}"

# Pemanggilan dengan default
print("\n--- PENGUJIAN FUNGSI DEFAULT ---")
print(scan_port("192.168.1.100"))            # Pakai default port 80, TCP
print(scan_port("192.168.1.100", 443))       # Pakai default protokol TCP
print(scan_port("192.168.1.100", 21, "UDP")) # Semua argumen diberikan

# Perbaikan 3: Parameter *port disamakan dengan variabel ports di dalam fungsi
def pindai_banyak_port(ip, *ports):
    """Memindai beberapa port pada satu alamat IP."""
    port_berbahaya = [21, 23, 25, 135, 445, 3389]
    jumlah_berbahaya = 0
    
    print(f"\nMemindai IP: {ip}")
    print(f"Total port yang dipindai: {len(ports)}")
    
    for port in ports:
        if port in port_berbahaya:
            status = "BERBAHAYA"
            jumlah_berbahaya += 1
        else:
            status = "AMAN"
        print(f"Port {port}: {status}")
        
    return jumlah_berbahaya

# Pemanggilan dengan *args
print("\n--- PENGUJIAN FUNGSI *ARGS ---")
total_bahaya = pindai_banyak_port("192.168.1.100", 21, 22, 80, 443, 445)
print(f"Total port berbahaya: {total_bahaya}")

def profil_analis(**data):
    """"Menampilkan profil analis dari keyword arguments."""
    print("\n--- PROFIL ANALIS ---")
    for key, value in data.items():
        label = key.replace("_", " ").title()
        print(f"{label:<20}: {value}")
        
    if "nama" in data:
        return data["nama"]
    return "Unknown"

# Pemanggilan dengan **kwargs
print("\n--- PENGUJIAN FUNGSI **KWARGS ---")
nama1 = profil_analis(
    nama="Budi Santoso",
    role="Security Analyst",
    shift="Malam",
    level=5
)

nama2 = profil_analis(
    nama="Siti Aminah",
    role="Penetration Tester"
)

print(f"\nAnalis yang bertugas: {nama1} dan {nama2}")

def analisis_password(password, username=""):
    """Menganalisis kekuatan password berdasarkan 6 kriteria."""
    karakter_spesial = "!@#$%^&*()_+<>~`?/"
    
    k1 = len(password) >= 12
    k2 = sum(1 for c in password if c.isupper()) >= 2
    k3 = any(c.islower() for c in password)
    k4 = sum(1 for c in password if c.isdigit()) >= 3
    k5 = any(c in karakter_spesial for c in password)
    k6 = username.lower() not in password.lower() if username else True
    
    skor = sum([k1, k2, k3, k4, k5, k6])
    
    # Perbaikan 4: Pengaturan indentasi pada 'level'
    if skor >= 6:
        level = "SANGAT KUAT"
    elif skor >= 5:
        level = "KUAT"
    elif skor >= 3:
        level = "SEDANG"
    elif skor >= 1:
        level = "LEMAH"
    else:
        level = "SANGAT LEMAH"
    
    detail = [k1, k2, k3, k4, k5, k6]
    
    return skor, level, detail

# Pemanggilan dengan multiple return
print("\n--- PENGUJIAN MULTIPLE RETURN ---")
password_test = "Secure@2024!"
skor, level, detail = analisis_password(password_test, "admin")

print(f"Password        : {'*' * len(password_test)}")
print(f"Skor            : {skor}/6")
print(f"Level           : {level}")
print(f"Detail Kriteria : ")
print(f"  - Minimal 12 Karakter    : {'YA' if detail[0] else 'TIDAK'}")
print(f"  - Minimal 2 Huruf besar  : {'YA' if detail[1] else 'TIDAK'}")
print(f"  - Mengandung Huruf kecil : {'YA' if detail[2] else 'TIDAK'}")
print(f"  - Minimal 3 angka        : {'YA' if detail[3] else 'TIDAK'}")
print(f"  - Mengandung simbol khusus: {'YA' if detail[4] else 'TIDAK'}")
print(f"  - Tidak mengandung Username: {'YA' if detail[5] else 'TIDAK'}")

total_audit_global = 0
log_audit = []

def catat_audit(username, skor, level):
    """Mencatat hasil audit ke dalam log global."""
    global total_audit_global
    
    status_aman = skor >= 5
    total_audit_global += 1
    
    entri = {
        "no": total_audit_global,
        "username": username,
        "skor": skor,
        "level": level,
        "aman": status_aman
    }
    log_audit.append(entri)
    
    return status_aman

# Perbaikan 5: Menghapus baris kode yang salah di luar loop pada tampilkan_log_audit()
def tampilkan_log_audit():
    print("\n--- LOG AUDIT ---")
    print(f"{'No':<4} | {'Username':<12} | {'Skor':<6} | {'Level':<15} | {'Status':<10}")
    print("-" * 60)
    for entri in log_audit:
        status = "AMAN" if entri["aman"] else "PERLU PERBAIKAN"
        # Perbaikan 6: Kutip ganda/tunggal di perbaiki dan variabel `skor` diganti 'skor'
        print(f"{entri['no']:<4} | {entri['username']:<12} | "
              f"{entri['skor']}/6 | {entri['level']:<15} | {status:<10}")

# Pengujian scope variabel
print("\n--- PENGUJIAN SCOPE VARIABEL ---")
print(f"Total audit sebelum: {total_audit_global}")

users = [
    ("admin", "Admin123"),
    ("user1", "User1Pass!"),
    ("security", "Secur3P@ssw0rd2024"),
    ("guest", "guest")
]        

for user, pwd in users:
    skor_u, level_u, _ = analisis_password(pwd, user)
    status = catat_audit(user, skor_u, level_u)
    print(f"Audit {user}: skor {skor_u}/6, level {level_u}, aman={status}")
    
print(f"\nTotal audit setelah: {total_audit_global}")
# Perbaikan 7: Menambahkan tanda kurung () untuk memanggil fungsi
tampilkan_log_audit()

def deteksi_ancaman_login():
    """Fungsi utama untuk mendeteksi ancaman login."""
    print("\n" + "=" * 70)
    print("DETEKSI ANCAMAN LOGIN TERINTEGRASI")
    print("=" * 70)
    
    username = input("Masukkan Username: ")
    ip_input = input("Masukkan Alamat IP: ")
    password = input("Masukkan Password: ")
    
    if not validasi_ip(ip_input):
        print("\nERROR: Format IP tidak valid!")
        return
        
    status_ip = klasifikasi_ip(ip_input, ip_berbahaya)
    skor, level, detail = analisis_password(password, username)
    
    is_ip_berbahaya = (status_ip == "BERBAHAYA")
    is_password_lemah = (skor < 3)
    is_username_mencurigakan = username in ["admin", "root", "guest"]

    if is_ip_berbahaya and is_username_mencurigakan and is_password_lemah:
        tingkat = "TINGGI"
        rekomendasi = "Segera blokir IP dan lakukan investigasi menyeluruh"
    elif is_ip_berbahaya and (is_username_mencurigakan or is_password_lemah):
        tingkat = "SEDANG"
        rekomendasi = "Lakukan monitoring ketat dan verifikasi dengan user"
    elif is_ip_berbahaya:
        tingkat = "RENDAH"
        rekomendasi = "Pantau aktivitas user dan catat dalam log"
    elif is_username_mencurigakan and is_password_lemah:
        tingkat = "SEDANG"
        rekomendasi = "Verifikasi identitas user dan sarankan ganti password"
    elif is_username_mencurigakan or is_password_lemah:
        tingkat = "RENDAH"
        rekomendasi = "Pantau aktivitas user"
    else:
        tingkat = "AMAN"
        rekomendasi = "Tidak ada tindakan yang diperlukan"
        
    print("\n" + "=" * 70) 
    print("LAPORAN ANALISIS ANCAMAN") 
    print("=" * 70) 
    print(f"Username        : {username}") 
    print(f"IP Address      : {ip_input}") 
    print(f"Status IP       : {status_ip}") 
    print(f"Password        : {'*' * len(password)}") 
    print(f"Skor Password   : {skor}/6") 
    print(f"Level Password  : {level}") 
    print(f"Tingkat Ancaman : {tingkat}") 
    print(f"Rekomendasi     : {rekomendasi}") 
    print("=" * 70)
    
    catat_audit(username, skor, level)

# Perbaikan 8: Menambahkan tanda kurung () untuk memanggil fungsi interaktif jika diperlukan
# deteksi_ancaman_login()

def audit_batch(daftar_pengguna):
    """Melakukan audit password untuk banyak pengguna sekaligus."""
    statistik = {
        "total": 0,
        "sangat_kuat": 0,
        "kuat": 0,
        "sedang": 0,
        "lemah": 0,
        "sangat_lemah": 0,
    }
    
    print("\n--- HASIL AUDIT BATCH---")
    print(f"{'User':<12} | {'Password':<18} | {'Skor':<6} | {'Level':<15}")
    print("-" * 65)
    
    for pengguna in daftar_pengguna:
        user = pengguna["username"]
        pwd = pengguna["password"]
        
        skor, level, _ = analisis_password(pwd, user)
        
        statistik["total"] += 1
        if level == "SANGAT KUAT":
            statistik["sangat_kuat"] += 1
        elif level == "KUAT":
            statistik["kuat"] += 1
        elif level == "SEDANG":
            statistik["sedang"] += 1
        elif level == "LEMAH":
            statistik["lemah"] += 1
        else:
            statistik["sangat_lemah"] += 1
            
        pwd_tampil = "*" * len(pwd)
        print(f"{user:<12} | {pwd_tampil:<18} | {skor}/6 | {level:<15}")
        
    return statistik

daftar_pengguna = [
    {"username": "admin", "password": "admin"},
    {"username": "user1", "password": "User123"},
    {"username": "security", "password": "Secur3P@ssw0rd2024"},
    {"username": "manager", "password": "M@nager2024!x"},
    {"username": "guest", "password": "guest"}
]

statistik = audit_batch(daftar_pengguna)

print("\n--- STATISTIK AUDIT ---")
print(f"Total pengguna : {statistik['total']}")
print(f"Sangat Kuat    : {statistik['sangat_kuat']}")
print(f"Kuat           : {statistik['kuat']}")
print(f"Sedang         : {statistik['sedang']}")
print(f"Lemah          : {statistik['lemah']}")
print(f"Sangat Lemah   : {statistik['sangat_lemah']}")

def laporan_analis(nama, role, *keahlian, level=1, **info_tambahan):
    """Menghasilkan laporan lengkap analis."""
    laporan = {
        "nama": nama,
        "role": role,
        "keahlian": list(keahlian),
        "level": level,
        "info": info_tambahan
    }
    
    print(f"\n--- LAPORAN ANALIS: {nama} ---")
    print(f"Role     : {role}")
    print(f"Level    : {level}")
    print(f"Keahlian : {', '.join(keahlian)}")
    
    if info_tambahan:
        print("Info Tambahan:")
        for key, value in info_tambahan.items():
            label = key.replace("_", " ").title()
            print(f" {label}: {value}")
            
    return laporan

print("\n--- PENGUJIAN KOMBINASI PARAMETER LENGKAP ---")
laporan1 = laporan_analis(
    "Budi Santoso",
    "Senior Analyst",
    "Penetration Testing",
    "Incident Response",
    "Forensik Digital",
    level=5,
    sertifikasi="CEH, OSCP",
    tahun_bergabung=2018
)

laporan2 = laporan_analis(
    "Siti Aminah",
    "Junior Analyst",
    "Network Security",
    level=2
)

print("\n" + "=" * 70)
print("PRAKTIKUM FUNGSI SELESAI")
print("=" * 70)
print("Materi yang telah dipraktikkan: ")
# Perbaikan 9: Memperbaiki penulisan print bertingkat
print(" 1. Fungsi sederhana tanpa parameter")
print(" 2. Fungsi dengan positional argument")
print(" 3. Fungsi dengan keyword argument")
print(" 4. Fungsi dengan default argument")
print(" 5. Fungsi dengan *args (variadic positional)")
print(" 6. Fungsi dengan **kwargs (variadic keyword)")
print(" 7. Fungsi dengan multiple return values")
print(" 8. Ruang lingkup variabel (local vs global)")
print(" 9. Studi kasus terintegrasi")
print(" 10. Kombinasi lengkap semua parameter")
print("=" * 70)