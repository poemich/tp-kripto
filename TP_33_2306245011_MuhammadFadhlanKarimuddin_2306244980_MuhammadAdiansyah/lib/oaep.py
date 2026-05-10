import hashlib
import os

def mgf1(seed, length, hash_func=hashlib.sha256):
    """
    Mask Generation Function 1 (MGF1) sesuai standar PKCS#1 v2.1.
    
    Argumen:
    seed -- Nilai bytes sebagai dasar pembuatan mask.
    length -- Panjang mask yang ingin dihasilkan dalam bytes.
    hash_func -- Fungsi hash yang digunakan (default SHA-256).
    
    Return:
    Bytes mask dengan panjang 'length'.
    """
    hLen = hash_func().digest_size
    # Jika panjang mask terlalu besar
    if length > (2**32) * hLen:
        raise ValueError("Mask terlalu panjang")
        
    T = b""
    # Iterasi sebanyak ceil(length / hLen)
    counter = 0
    while len(T) < length:
        # Konversi counter ke bentuk 4 byte integer (big-endian)
        C = counter.to_bytes(4, byteorder='big')
        # T = T || Hash(seed || C)
        T += hash_func(seed + C).digest()
        counter += 1
        
    # Kembalikan sejumlah byte yang diminta
    return T[:length]

def xor_bytes(b1, b2):
    """
    Melakukan operasi XOR antara dua byte string.
    Panjang b1 dan b2 harus sama.
    """
    return bytes(x ^ y for x, y in zip(b1, b2))

def oaep_pad(message, k, label=b"", hash_func=hashlib.sha256):
    """
    Melakukan proses padding OAEP pada pesan.
    
    Argumen:
    message -- Pesan plaintext dalam bentuk bytes.
    k -- Panjang modulus RSA dalam bytes (2048 bit = 256 bytes).
    label -- Label opsional (default string kosong).
    hash_func -- Fungsi hash (default SHA-256).
    
    Return:
    Bytes hasil padding (Encoded Message / EM) sepanjang k bytes.
    """
    hLen = hash_func().digest_size
    mLen = len(message)
    
    # Pengecekan panjang pesan maksimal
    if mLen > k - 2 * hLen - 2:
        raise ValueError("Pesan terlalu panjang untuk dienkripsi dengan RSA-OAEP")
        
    # 1. Buat lHash dari label
    lHash = hash_func(label).digest()
    
    # 2. Buat padding string (PS) berisi byte 0x00
    ps_len = k - mLen - 2 * hLen - 2
    PS = b'\x00' * ps_len
    
    # 3. Bentuk Data Block (DB): lHash || PS || 0x01 || M
    DB = lHash + PS + b'\x01' + message
    
    # 4. Bangkitkan nilai acak 'seed' sepanjang hLen
    seed = os.urandom(hLen)
    
    # 5. Hasilkan dbMask = MGF1(seed, k - hLen - 1)
    dbMask = mgf1(seed, k - hLen - 1, hash_func)
    
    # 6. maskedDB = DB XOR dbMask
    maskedDB = xor_bytes(DB, dbMask)
    
    # 7. Hasilkan seedMask = MGF1(maskedDB, hLen)
    seedMask = mgf1(maskedDB, hLen, hash_func)
    
    # 8. maskedSeed = seed XOR seedMask
    maskedSeed = xor_bytes(seed, seedMask)
    
    # 9. Bentuk Encoded Message (EM): 0x00 || maskedSeed || maskedDB
    EM = b'\x00' + maskedSeed + maskedDB
    return EM

def oaep_unpad(em, k, label=b"", hash_func=hashlib.sha256):
    """
    Membalikkan proses padding OAEP untuk mendapatkan pesan asli.
    
    Argumen:
    em -- Encoded Message (bytes) hasil padding OAEP.
    k -- Panjang modulus RSA dalam bytes (2048 bit = 256 bytes).
    label -- Label opsional (default string kosong).
    hash_func -- Fungsi hash (default SHA-256).
    
    Return:
    Bytes pesan plaintext yang asli.
    """
    hLen = hash_func().digest_size
    
    # Pengecekan panjang
    if len(em) != k:
        raise ValueError("Ukuran blok tidak sesuai dengan ukuran modulus k.")
    if k < 2 * hLen + 2:
        raise ValueError("Ukuran modulus k terlalu kecil.")
        
    # 1. Pisahkan EM: Y || maskedSeed || maskedDB
    Y = em[0:1]
    maskedSeed = em[1:1+hLen]
    maskedDB = em[1+hLen:]
    
    # 2. Dapatkan seedMask = MGF1(maskedDB, hLen)
    seedMask = mgf1(maskedDB, hLen, hash_func)
    
    # 3. Kembalikan seed = maskedSeed XOR seedMask
    seed = xor_bytes(maskedSeed, seedMask)
    
    # 4. Dapatkan dbMask = MGF1(seed, k - hLen - 1)
    dbMask = mgf1(seed, k - hLen - 1, hash_func)
    
    # 5. Kembalikan DB = maskedDB XOR dbMask
    DB = xor_bytes(maskedDB, dbMask)
    
    # 6. Cek lHash dan validitas DB: DB = lHash || PS || 0x01 || M
    lHash_expected = hash_func(label).digest()
    lHash_actual = DB[:hLen]
    
    if lHash_expected != lHash_actual:
        raise ValueError("Dekripsi OAEP gagal: Label Hash tidak cocok.")
        
    # Memisahkan PS, 0x01, dan Message (M)
    # Kita cari byte 0x01 mulai dari posisi hLen
    # Semua byte sebelumnya harus bernilai 0x00 (PS)
    index = hLen
    while index < len(DB) and DB[index] == 0x00:
        index += 1
        
    if index >= len(DB) or DB[index] != 0x01:
        raise ValueError("Dekripsi OAEP gagal: Format blok data salah (tidak ada byte pemisah 0x01).")
        
    if Y != b'\x00':
         raise ValueError("Dekripsi OAEP gagal: Byte pertama bukan 0x00.")
         
    # Pesan asli ada setelah byte 0x01
    message = DB[index + 1:]
    return message
