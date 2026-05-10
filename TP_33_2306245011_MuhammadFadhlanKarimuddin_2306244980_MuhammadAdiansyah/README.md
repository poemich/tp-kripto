# Tugas Pemrograman Kriptografi - RSA-OAEP-256

## Anggota Kelompok
- Muhammad Fadhlan Karimuddin (2306245011)
- Muhammad Adiansyah (2306244980)

## Disclaimer Penggunaan AI
Dalam pengerjaan program ini, AI digunakan sebagai alat bantu untuk brainstorming, merapikan struktur kode, membantu penulisan dokumentasi, dan mengecek ulang bagian-bagian implementasi. Keputusan desain, pemahaman algoritma, penyesuaian kode, serta pengujian tetap dilakukan oleh anggota kelompok berdasarkan kebutuhan tugas RSA-OAEP-256 ini.

## Asumsi Implementasi

Program ini mengimplementasikan RSA-OAEP-256 secara murni menggunakan Python standard library untuk mendapatkan bonus implementasi mandiri (tanpa external library kriptografi seperti `cryptography` atau `PyCryptodome`).

Karena RSA-OAEP-256 dengan kunci 2048-bit hanya dapat mengenkripsi maksimal 190 byte per operasi, maka file input diproses menggunakan **pendekatan chunking**.

Pada proses enkripsi:
1. File plaintext dibaca sebagai bytes.
2. Dipecah menjadi beberapa chunk berukuran maksimal 190 byte.
3. Setiap chunk kemudian diproses dengan OAEP menggunakan SHA-256.
4. Setiap hasil padding OAEP dienkripsi menggunakan RSA.
5. Setiap hasil enkripsi menghasilkan block ciphertext berukuran 256 byte.

Pendekatan ini dipilih karena Python standard library tidak menyediakan implementasi algoritma simetris seperti AES, sementara penggunaan library kriptografi eksternal tidak diperbolehkan. Oleh karena itu, pendekatan hybrid enkripsi tidak kami gunakan demi mempertahankan orisinalitas pengerjaan murni dari nol.

### Struktur File Ciphertext
Untuk memastikan keakuratan dekripsi dan kenyamanan pengguna, kami menambahkan header khusus pada file output yang juga menyimpan ekstensi file asli:
- `MAGIC HEADER` (8 byte) : `b"RSAOAEP1"`
- `CHUNK_SIZE` (2 byte)   : `190`
- `RSA_BLOCK_SIZE` (2 byte): `256`
- `ORIGINAL_SIZE` (8 byte) : Ukuran file asli dalam bytes.
- `EXTENSION` (16 byte)    : Ekstensi file asli (misal `.jpg`), sehingga saat dekripsi GUI dapat otomatis mengembalikan formatnya.
- `CIPHERTEXT_BLOCKS`      : Blok-blok ciphertext berukuran 256 byte.

## Cara Penggunaan

### 1. Command Line Interface (CLI)
Buka terminal dan arahkan ke folder ini, lalu jalankan perintah:

* Generate Key:
  `python main.py generate public.key private.key`
* Enkripsi File:
  `python main.py encrypt plaintext.txt public.key ciphertext.bin`
* Dekripsi File:
  `python main.py decrypt ciphertext.bin private.key result.txt`

### 2. Graphical User Interface (GUI)
Jalankan file `gui.py` untuk membuka tampilan antarmuka:
`python gui.py`
