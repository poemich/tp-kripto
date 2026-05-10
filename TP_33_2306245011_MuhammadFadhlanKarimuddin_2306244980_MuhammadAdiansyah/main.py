import sys
import time
from lib.rsa import generate_keypair
from lib.utils import save_key, encrypt_file, decrypt_file

def print_help():
    print("Penggunaan CLI RSA-OAEP-256")
    print("=================================")
    print("1. Generate Keys:")
    print("   python main.py generate <public_key_output> <private_key_output>")
    print("   Contoh: python main.py generate public.key private.key")
    print()
    print("2. Enkripsi:")
    print("   python main.py encrypt <plaintext_file> <public_key_file> <output_file>")
    print("   Contoh: python main.py encrypt data.txt public.key data.enc")
    print()
    print("3. Dekripsi:")
    print("   python main.py decrypt <ciphertext_file> <private_key_file> <output_file>")
    print("   Contoh: python main.py decrypt data.enc private.key data_decrypted.txt")
    print()

def main():
    if len(sys.argv) < 2:
        print_help()
        sys.exit(1)
        
    command = sys.argv[1].lower()
    
    try:
        if command == "generate":
            if len(sys.argv) != 4:
                print("Error: Argumen tidak lengkap untuk generate.")
                print_help()
                sys.exit(1)
            
            pub_out = sys.argv[2]
            priv_out = sys.argv[3]
            print("Sedang membangkitkan pasangan kunci RSA 2048-bit. Mohon tunggu...")
            start = time.time()
            pub_key, priv_key = generate_keypair(2048)
            save_key(pub_key, pub_out)
            save_key(priv_key, priv_out)
            print(f"Selesai dalam {time.time() - start:.2f} detik.")
            print(f"Kunci publik disimpan ke: {pub_out}")
            print(f"Kunci privat disimpan ke: {priv_out}")
            
        elif command == "encrypt":
            if len(sys.argv) != 5:
                print("Error: Argumen tidak lengkap untuk encrypt.")
                print_help()
                sys.exit(1)
                
            plain_file = sys.argv[2]
            pub_key_file = sys.argv[3]
            out_file = sys.argv[4]
            
            print(f"Mulai enkripsi '{plain_file}'...")
            start = time.time()
            encrypt_file(plain_file, pub_key_file, out_file)
            print(f"Enkripsi berhasil dalam {time.time() - start:.2f} detik.")
            print(f"File output disimpan di: {out_file}")
            
        elif command == "decrypt":
            if len(sys.argv) != 5:
                print("Error: Argumen tidak lengkap untuk decrypt.")
                print_help()
                sys.exit(1)
                
            cipher_file = sys.argv[2]
            priv_key_file = sys.argv[3]
            out_file = sys.argv[4]
            
            print(f"Mulai dekripsi '{cipher_file}'...")
            start = time.time()
            decrypt_file(cipher_file, priv_key_file, out_file)
            print(f"Dekripsi berhasil dalam {time.time() - start:.2f} detik.")
            print(f"File output disimpan di: {out_file}")
            
        else:
            print("Perintah tidak dikenali.")
            print_help()
            
    except Exception as e:
        print(f"Terjadi kesalahan: {str(e)}")

if __name__ == "__main__":
    main()
