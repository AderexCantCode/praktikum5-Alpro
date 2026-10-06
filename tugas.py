import re

# Bagian 8: Variabel Global
total_audit_global = 0
log_audit_kripto = []

# Bagian 1: Fungsi Sederhana Tanpa Parameter
def tampilkan_header():
    print("=" * 50)
    print(" SISTEM MANAJEMEN KUNCI ENKRIPSI CRYPTOVAULT ")
    print("=" * 50)

# Bagian 2: Fungsi dengan Positional Argument
def validasi_key_id(key_id):
    pola = r"^KEY-\d{4}-[A-Za-z0-9]+-\d{3}$"
    return bool(re.match(pola, key_id))

def klasifikasi_key(key_id, daftar_algoritma):
    try:
        algoritma = key_id.split('-')[2]
        if algoritma in daftar_algoritma:
            return "ALGORITMA VALID"
        return "ALGORITMA TIDAK DIIZINKAN"
    except IndexError:
        return "FORMAT KEY TIDAK VALID"

# Bagian 3: Fungsi dengan Keyword Argument
def validasi_akses_kms(engineer_id, passphrase, kms_endpoint):
    db_engineer = {
        "ENG-001": {"passphrase": "Crypto@2024", "endpoint": "kms.cryptovault.id:8443"},
        "ENG-002": {"passphrase": "Secure#Vault", "endpoint": "kms2.cryptovault.id:8443"}
    }
    
    if engineer_id not in db_engineer:
        return f"Akses Gagal: engineer_id {engineer_id} tidak terdaftar."
    if db_engineer[engineer_id]["passphrase"] != passphrase:
        return "Akses Gagal: Passphrase salah."
    if db_engineer[engineer_id]["endpoint"] != kms_endpoint:
        return "Akses Gagal: Endpoint KMS tidak cocok."
    
    return "Akses Berhasil"

# Bagian 4: Fungsi dengan Default Argument
def scan_port_kms(host, port=8443, protokol="HTTPS", timeout=30):
    kategori_port = ""
    if port == 8443:
        kategori_port = "KMS STANDAR"
    elif port == 9443:
        kategori_port = "KMS ALTERNATIF"
    elif port < 1024:
        kategori_port = "PORT SISTEM"
    else:
        kategori_port = "PORT TIDAK DIKENAL"
        
    return f"Scan [{protokol}] {host}:{port} (Timeout: {timeout}s) - Status: {kategori_port}"

# Bagian 5: Fungsi dengan *args
def pindai_banyak_port(host, *ports):
    port_berbahaya = [22, 23, 3389, 5900, 6379]
    jumlah_berbahaya = 0
    for p in ports:
        if p in port_berbahaya:
            jumlah_berbahaya += 1
    return jumlah_berbahaya

# Bagian 6: Fungsi dengan **kwargs
def profil_engineer(**data):
    print("--- Profil Engineer ---")
    nama = data.get("nama", "Unknown")
    for k, v in data.items():
        key_bersih = k.replace("_", " ").title()
        print(f"{key_bersih}: {v}")
    return nama

# Bagian 7: Fungsi dengan Return Lebih dari Satu Nilai
def analisis_passphrase(passphrase, engineer_id=""):
    skor = 0
    detail = []
    
    if len(passphrase) >= 16: skor += 1; detail.append("Panjang >= 16")
    if len(re.findall(r'[A-Z]', passphrase)) >= 2: skor += 1; detail.append(">= 2 Huruf Besar")
    if re.search(r'[a-z]', passphrase): skor += 1; detail.append("Ada huruf kecil")
    if len(re.findall(r'\d', passphrase)) >= 4: skor += 1; detail.append(">= 4 Angka")
    if re.search(r'[!@#$%]', passphrase): skor += 1; detail.append("Ada simbol khusus")
    if engineer_id and engineer_id not in passphrase: skor += 1; detail.append("Tidak mengandung ID")
    
    if skor == 6: level = "SANGAT KUAT"
    elif skor == 5: level = "KUAT"
    elif skor >= 3: level = "CUKUP"
    elif skor >= 1: level = "LEMAH"
    else: level = "SANGAT LEMAH"
        
    return skor, level, detail


# Bagian 8: Log dan Audit Kriptografi (Global/Lokal)
def catat_audit_kripto(engineer_id, skor, level):
    global total_audit_global
    status_aman = True if skor >= 5 else False
    total_audit_global += 1
    log_audit_kripto.append({
        "id": engineer_id, "skor": skor, "level": level, "aman": status_aman
    })
    return status_aman

def tampilkan_log():
    print(f"\nTotal Audit: {total_audit_global}")
    print(f"{'ID':<10} | {'SKOR':<5} | {'LEVEL':<15} | {'STATUS AMAN'}")
    print("-" * 50)
    for log in log_audit_kripto:
        print(f"{log['id']:<10} | {log['skor']:<5} | {log['level']:<15} | {log['aman']}")


# Bagian 9: Studi Kasus Terintegrasi
def deteksi_anomali_kripto():
    print("\n--- Orkestrator Deteksi Anomali ---")
    engineer_id = input("Masukkan Engineer ID: ")
    key_id = input("Masukkan Key ID: ")
    passphrase = input("Masukkan Passphrase: ")
    
    is_key_valid = validasi_key_id(key_id)
    skor, level, _ = analisis_passphrase(passphrase, engineer_id)
    
    if not is_key_valid and skor <= 2:
        tingkat_anomali = "ANOMALI TINGGI"
    elif not is_key_valid or skor <= 2:
        tingkat_anomali = "ANOMALI SEDANG"
    else:
        tingkat_anomali = "AKSES NORMAL"
        
    print(f"Laporan Orkestrator: {tingkat_anomali}")
    catat_audit_kripto(engineer_id, skor, level)


# Bagian 10 & 16: Batch Processing
def audit_batch_engineer(daftar_engineer):
    distribusi = {"SANGAT KUAT": 0, "KUAT": 0, "CUKUP": 0, "LEMAH": 0, "SANGAT LEMAH": 0}
    for eng in daftar_engineer:
        skor, level, _ = analisis_passphrase(eng["passphrase"], eng["id"])
        distribusi[level] += 1
    return distribusi

def analisis_passphrase_batch(daftar_passphrase):
    print("\n--- Analisis Batch Passphrase ---")
    print(f"{'ID':<10} | {'SKOR':<5} | {'LEVEL':<15}")
    print("-" * 35)
    dist = {"SANGAT KUAT": 0, "KUAT": 0, "CUKUP": 0, "LEMAH": 0, "SANGAT LEMAH": 0}
    for data in daftar_passphrase:
        s, l, _ = analisis_passphrase(data['passphrase'], data['id'])
        print(f"{data['id']:<10} | {s:<5} | {l:<15}")
        dist[l] += 1
    return dist


# Bagian 11: Kombinasi Lengkap Semua Parameter

def laporan_engineer(nama, role, *sertifikasi, level=1, **info_tambahan):
    data = {
        "nama": nama, "role": role, "sertifikasi": sertifikasi,
        "level": level, "info_tambahan": info_tambahan
    }
    print(f"\nLaporan Engineer {nama} - Role: {role}")
    return data


# Bagian 12: Simulasi Rotasi Kunci

def rotasi_kunci(key_lama, key_baru, interval_hari=90):
    if not validasi_key_id(key_lama) or not validasi_key_id(key_baru):
        return {"status": "Gagal", "alasan": "Format key tidak valid"}
    if key_lama == key_baru:
        return {"status": "Gagal", "alasan": "Key baru tidak boleh sama"}
        
    sisa_hari = interval_hari % 365 
    return {"status": "Berhasil", "sisa_hari_rotasi": sisa_hari, "rekomendasi": "Lanjutkan operasional"}


# Bagian 13: Filter Log Kriptografi
def filter_log_kripto(daftar_log, kata_kunci):
    hasil_filter = []
    for log in daftar_log:
        if kata_kunci not in log['pesan']:
            continue
        hasil_filter.append(log)
        if log['status'] == "CRITICAL":
            break
    return hasil_filter


# Bagian 14: Matriks Skor Risiko Kunci

def matriks_risiko_kunci():
    matriks = [
        [1, 2, 3, 4],
        [3, 4, 8, 2],
        [2, 9, 1, 3],
        [4, 2, 5, 7]
    ]
    max_val, max_row, max_col = -1, -1, -1
    print("\n--- Matriks Risiko ---")
    for r in range(len(matriks)):
        for c in range(len(matriks[r])):
            print(f"{matriks[r][c]}", end=" ")
            if matriks[r][c] > max_val:
                max_val = matriks[r][c]
                max_row, max_col = r, c
        print()
    return max_val, max_row, max_col

# Bagian 15: Analisis Multi-Key
def analisis_multi_key(daftar_key):
    stats = {}
    for k in daftar_key:
        algo = k["algoritma"]
        stats.setdefault(algo, {"aktif": 0, "tidak_aktif": 0})
        if k["status"] == "aktif": stats[algo]["aktif"] += 1
        else: stats[algo]["tidak_aktif"] += 1
    return stats


if __name__ == "__main__":
    tampilkan_header()
    
    print(klasifikasi_key("KEY-2024-AES-001", ["AES", "RSA", "ECC", "ChaCha20"]))
    print(validasi_akses_kms(kms_endpoint="kms.cryptovault.id:8443", passphrase="Crypto@2024", engineer_id="ENG-001"))
    print(scan_port_kms("192.168.1.10", port=9443))
    print(f"Port berbahaya terdeteksi: {pindai_banyak_port('localhost', 22, 80, 443, 3389)}")
    
    profil_engineer(nama="Ade", role="Crypto Analyst", departemen="Keamanan")
    
    skor, lvl, detail = analisis_passphrase("Passw0rdKuat!2345", "ENG-101")
    catat_audit_kripto("ENG-101", skor, lvl)
    tampilkan_log()
    
    laporan_engineer("Ade Rasya", "Auditor", "CEH", "CompTIA", level=2, shift="Malam")
    
    print(rotasi_kunci("KEY-2023-RSA-001", "KEY-2024-RSA-002", 90))
    
    max_risiko = matriks_risiko_kunci()
    print(f"Risiko tertinggi {max_risiko[0]} di baris {max_risiko[1]}, kolom {max_risiko[2]}")