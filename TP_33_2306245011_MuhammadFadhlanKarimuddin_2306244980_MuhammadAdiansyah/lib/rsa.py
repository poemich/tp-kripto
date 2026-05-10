import os
import random

def is_prime_miller_rabin(n, k=40):
    """
    Melakukan uji keprimaan Miller-Rabin untuk angka n.
    
    Argumen:
    n -- Angka yang akan diuji keprimaannya (int).
    k -- Jumlah putaran uji (int). Semakin tinggi, semakin akurat.
    
    Return:
    True jika n kemungkinan besar prima, False jika n komposit (bukan prima).
    """
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False

    # Tulis n-1 sebagai d * 2^r
    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Lakukan uji sebanyak k kali
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_large_prime(bits):
    """
    Membangkitkan bilangan prima acak sebesar 'bits'.
    
    Argumen:
    bits -- Panjang bit dari bilangan prima (misal 1024).
    
    Return:
    Bilangan prima acak (int).
    """
    while True:
        # Menghasilkan angka acak sebesar bits
        # os.urandom lebih aman dari random biasa
        rand_bytes = os.urandom(bits // 8)
        # Konversi bytes ke integer
        num = int.from_bytes(rand_bytes, byteorder='big')
        
        # Pastikan angka tersebut memiliki panjang bit yang benar dan ganjil
        num |= (1 << (bits - 1)) | 1
        
        # Cek keprimaan
        if is_prime_miller_rabin(num):
            return num

def extended_gcd(a, b):
    """
    Algoritma Euclidean Diperluas. 
    Mencari faktor x dan y sedemikian hingga ax + by = gcd(a, b).
    
    Return:
    (gcd, x, y)
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def mod_inverse(a, m):
    """
    Mencari invers modulo dari 'a' modulo 'm'.
    Artinya mencari angka x sehingga (a * x) % m == 1.
    """
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Invers modulo tidak ada (angka tidak koprima)')
    else:
        return x % m

def generate_keypair(bits=2048):
    """
    Membangkitkan pasangan kunci publik dan privat RSA.
    
    Argumen:
    bits -- Panjang kunci modulus n dalam bit (default 2048).
    
    Return:
    public_key -- Tuple (e, n)
    private_key -- Tuple (d, n)
    """
    # Karena n = p * q, panjang bit p dan q adalah setengah dari n
    prime_bits = bits // 2
    
    # 1. Pilih dua bilangan prima besar p dan q
    p = generate_large_prime(prime_bits)
    q = generate_large_prime(prime_bits)
    # Pastikan p != q
    while p == q:
        q = generate_large_prime(prime_bits)
        
    # 2. Hitung modulus n = p * q
    n = p * q
    
    # 3. Hitung fungsi totient Carmichael atau Euler: phi(n) = (p-1)*(q-1)
    phi = (p - 1) * (q - 1)
    
    # 4. Pilih e (eksponen publik)
    # Biasanya 65537 (0x10001) adalah nilai e yang umum, aman, dan efisien
    e = 65537
    
    # 5. Hitung d (eksponen privat), yaitu invers dari e modulo phi
    d = mod_inverse(e, phi)
    
    return ((e, n), (d, n))

def encrypt_raw(message_int, public_key):
    """
    Enkripsi mentah RSA menggunakan eksponensiasi modular.
    C = M^e mod n
    
    Argumen:
    message_int -- Pesan dalam bentuk integer.
    public_key -- Tuple (e, n).
    
    Return:
    Ciphertext dalam bentuk integer.
    """
    e, n = public_key
    if message_int >= n:
        raise ValueError("Pesan terlalu besar untuk modulus RSA ini.")
    # Menggunakan fungsi pow bawaan Python yang sudah sangat efisien untuk (M^e mod n)
    return pow(message_int, e, n)

def decrypt_raw(ciphertext_int, private_key):
    """
    Dekripsi mentah RSA menggunakan eksponensiasi modular.
    M = C^d mod n
    
    Argumen:
    ciphertext_int -- Ciphertext dalam bentuk integer.
    private_key -- Tuple (d, n).
    
    Return:
    Plaintext dalam bentuk integer.
    """
    d, n = private_key
    # Menggunakan fungsi pow bawaan: M = C^d mod n
    return pow(ciphertext_int, d, n)
