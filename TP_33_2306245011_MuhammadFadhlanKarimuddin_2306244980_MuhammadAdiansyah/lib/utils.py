import struct
import os
from .rsa import encrypt_raw, decrypt_raw
from .oaep import oaep_pad, oaep_unpad

MAGIC_HEADER = b"RSAOAEP1"
CHUNK_SIZE_MAX = 190
RSA_BLOCK_SIZE = 256
HEADER_FORMAT = ">8sHHQ16s"

def save_key(key_tuple, filepath):
    """
    Menyimpan tuple kunci (e, n) atau (d, n) ke dalam file text dalam format hex.
    
    Argumen:
    key_tuple -- Tuple berisi dua integer, contoh: (e, n).
    filepath -- Lokasi file untuk menyimpan.
    """
    val1, val2 = key_tuple
    with open(filepath, 'w') as f:
        f.write(f"{hex(val1)[2:]}\n{hex(val2)[2:]}")

def load_key(filepath):
    """
    Membaca file kunci format hex dan mengembalikannya sebagai tuple of integers.
    
    Argumen:
    filepath -- Lokasi file kunci.
    
    Return:
    Tuple of integer: (val1, val2).
    """
    with open(filepath, 'r') as f:
        lines = f.read().splitlines()
        val1 = int(lines[0], 16)
        val2 = int(lines[1], 16)
        return (val1, val2)

def get_ciphertext_ext(ciphertext_path):
    """
    Membaca header dari file ciphertext untuk mendapatkan ekstensi asli.
    
    Argumen:
    ciphertext_path -- Lokasi file ciphertext.
    
    Return:
    String ekstensi file asli (misal '.jpg' atau '.txt').
    """
    try:
        with open(ciphertext_path, 'rb') as f:
            header_size = struct.calcsize(HEADER_FORMAT)
            header_data = f.read(header_size)
            if len(header_data) == header_size:
                magic, _, _, _, ext_bytes = struct.unpack(HEADER_FORMAT, header_data)
                if magic == MAGIC_HEADER:
                    # Hapus padding byte null
                    ext = ext_bytes.strip(b'\x00').decode('utf-8')
                    return ext
    except Exception:
        pass
    return ""

def encrypt_file(plaintext_path, public_key_path, output_path):
    """
    Mengenakripsi file dengan memecahnya menjadi chunk-chunk (Chunking) 
    menggunakan RSA-OAEP-256.
    
    Argumen:
    plaintext_path -- Lokasi file yang akan dienkripsi.
    public_key_path -- Lokasi file kunci publik (.key).
    output_path -- Lokasi untuk menyimpan file hasil enkripsi.
    """
    pub_key = load_key(public_key_path)
    
    file_size = os.path.getsize(plaintext_path)
    
    # Ambil ekstensi asli dari file dan batasi max 16 bytes
    _, ext = os.path.splitext(plaintext_path)
    ext_bytes = ext.encode('utf-8')[:16].ljust(16, b'\x00')
    
    with open(plaintext_path, 'rb') as fin, open(output_path, 'wb') as fout:
        # Tulis Header
        # Format: MAGIC(8s) + CHUNK_SIZE(H) + BLOCK_SIZE(H) + FILE_SIZE(Q) + EXTENSION(16s)
        header = struct.pack(HEADER_FORMAT, MAGIC_HEADER, CHUNK_SIZE_MAX, RSA_BLOCK_SIZE, file_size, ext_bytes)
        fout.write(header)
        
        while True:
            chunk = fin.read(CHUNK_SIZE_MAX)
            if not chunk:
                break
                
            # Pad chunk menggunakan OAEP
            padded = oaep_pad(chunk, RSA_BLOCK_SIZE)
            
            # Konversi bytes ke integer
            m_int = int.from_bytes(padded, byteorder='big')
            
            # Enkripsi RSA mentah
            c_int = encrypt_raw(m_int, pub_key)
            
            # Konversi ciphertext integer ke bytes dan tulis ke file
            c_bytes = c_int.to_bytes(RSA_BLOCK_SIZE, byteorder='big')
            fout.write(c_bytes)

def decrypt_file(ciphertext_path, private_key_path, output_path):
    """
    Mendekripsi file hasil chunking RSA-OAEP-256 dan merangkai kembali 
    menjadi file aslinya.
    
    Argumen:
    ciphertext_path -- Lokasi file yang telah dienkripsi.
    private_key_path -- Lokasi file kunci privat (.key).
    output_path -- Lokasi untuk menyimpan file hasil dekripsi.
    """
    priv_key = load_key(private_key_path)
    
    with open(ciphertext_path, 'rb') as fin, open(output_path, 'wb') as fout:
        # Baca Header
        header_size = struct.calcsize(HEADER_FORMAT)
        header_data = fin.read(header_size)
        if len(header_data) < header_size:
            raise ValueError("Format file salah atau file terlalu kecil.")
            
        magic, chunk_size, block_size, orig_size, ext_bytes = struct.unpack(HEADER_FORMAT, header_data)
        
        if magic != MAGIC_HEADER:
            raise ValueError("File bukan merupakan ciphertext RSA-OAEP dari aplikasi ini.")
        if block_size != RSA_BLOCK_SIZE:
            raise ValueError(f"Ukuran blok RSA tidak didukung: {block_size}.")
            
        written_bytes = 0
        
        while True:
            c_bytes = fin.read(block_size)
            if not c_bytes:
                break
                
            if len(c_bytes) != block_size:
                raise ValueError("Potongan ciphertext rusak atau tidak lengkap.")
                
            # Konversi ciphertext bytes ke integer
            c_int = int.from_bytes(c_bytes, byteorder='big')
            
            # Dekripsi RSA mentah
            m_int = decrypt_raw(c_int, priv_key)
            
            # Kembalikan ke format bytes
            m_bytes = m_int.to_bytes(block_size, byteorder='big')
            
            # Buka padding OAEP
            original_chunk = oaep_unpad(m_bytes, block_size)
            
            # Karena ini chunk terakhir mungkin lebih kecil, kita tulis sesuai ukurannya
            # tetapi batasi dengan orig_size agar padding sisa (jika ada) tidak ikut tertulis.
            to_write = min(len(original_chunk), orig_size - written_bytes)
            fout.write(original_chunk[:to_write])
            written_bytes += to_write
