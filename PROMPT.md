# tp-kripto

## Soal:

```
1
CSCE 604243 Cryptography & Information Security
Tugas Pemrograman
• Batas waktu pengumpulan di SCeLE: Selasa 12 Mei 2026 (23:55 WIB)
• Mulailah mengerjakan tugas ini sesegera mungkin.
1. Tugas pemrograman ini dikerjakan oleh tim yang terdiri dari 2 atau 3 orang. Tim harus mendaftarkan
nama-nama anggotanya paling lambat jam 23:55 WIB (SCeLE) Selasa 5 Mei 2026 di SCeLE. Setelah
itu, tim tidak boleh berubah. Kalau ada masalah, harap segera menghubungi dosen atau asisten,
sebelum batas waktu tersebut.
2. Dalam tugas ini, Anda melakukan implementasi software untuk skema enkripsi dan dekripsi menurut
RSA-OAEP-256. Panjang kunci 2048 bit. Buatlah sebuah program Python yang mampu melakukan
enkripsi dan dekripsi. Anda diperbolehkan untuk menggunakan library kriptografi yang sudah ada
atau buat sendiri. Yang buat sendiri akan diberi bonus <= 50%. Buat GUI yang sesuai.
3. Program menerima input berupa dua buah file dan menuliskan hasil prosesnya ke sebuah file output.
Untuk perintah enkripsi, maka file-file inputnya terdiri dari file yang berisi plaintext (belum tentu
text biasa, bisa file binary pada umumnya) dan file yang berisi key. Key ditulis sebagai teks dalam
notasi hexadecimal. File output adalah file yang berisi ciphertext-nya. Untuk perintah dekripsi, file-
file inputnya terdiri file yang berisi ciphertext dan file yang berisi key. File output-nya berisi
plaintext hasil dekripsi.
4. Pastikan bahwa ciphertext hasil enkripsi apabila didekripsi akan kembali menghasilkan plaintext
aslinya. Lakukan testing terhadap berbagai jenis dokumen: text, image, video, audio, binary
executable code.
5. Pengumpulan tugas dilakukan secara online melalui SCeLE. File yang di-upload adalah satu berkas
berformat zip yang berisi semua berkas program. Keterlambatan akan diberi penalti 10% per hari.
Demo akan dijadwalkan kemudian bersama asisten.
Selamat belajar!
```

tolong kerjakan soal di atas:
- buat bonus, jadi bikin kode sendiri, tapi standsrd library untuk operasi dasar seperti hashing dan modular exponentiation dibolehkan.
- bikin semua kode nya di folder TP_33_2306245011_MuhammadFadhlanKarimuddin_2306244980_MuhammadAdiansyah/
- buat modular, bikin fungsi fungsi nya di folder lib
- bikin 2 versi, 1 standard command line interface di main.py, dan 1 lagi dengan GUI di gui.py
- berikan komentar lengkap, hingga orang yang tidak terlalu paham kriptografi pun bisa mengerti
- buat komentar untuk setiap fungsi, menjelaskan apa yang dilakukan fungsi tersebut, input dan outputnya, serta contoh penggunaannya jika perlu.
- buat komentar dalam bahasa indonesia
- keep it simple, jangan terlalu rumit, tapi tetap jelas dan mudah dipahami
- tulis semua asumsi yang kamu buat dalam pengerjaan tugas ini, agar orang lain bisa memahami konteksnya dengan baik.

tulis di README.md di folder TP_33_2306245011_MuhammadFadhlanKarimuddin_2306244980_MuhammadAdiansyah:
- kelompok
- disclaimer pakai AI
- asumsi yang dibuat: bilang kalo RSA-OAEP-256 gak bisa file besar, jadi untuk file file besar bilang ada pilihan chuncking atau hybrid, nah pilih hybrid oaep nya di key aes

base plan:
```md
Menurut saya **chunking adalah pilihan yang lebih masuk akal** dibanding “hybrid dengan custom stream cipher berbasis hash”, **kalau batasannya benar-benar hanya boleh standard library**.

Saya akan pilih:

```text
Opsi 1: Chunking RSA-OAEP murni
```

Alasannya: lebih mudah dipertanggungjawabkan ke asisten/dosen karena tetap sesuai kata kunci soal: **RSA-OAEP-256**.

---

## Kenapa chunking masuk akal?

RSA-OAEP-256 dengan key 2048-bit punya batas maksimal plaintext per enkripsi:

```text
k - 2hLen - 2
```

Dengan:

```text
k    = 256 byte   karena RSA 2048-bit
hLen = 32 byte    karena SHA-256
```

Maka:

```text
256 - 2(32) - 2 = 190 byte
```

Artinya satu operasi RSA-OAEP-256 hanya bisa mengenkripsi maksimal:

```text
190 byte plaintext
```

Kalau file lebih besar, solusinya adalah dipotong:

```text
file plaintext besar
↓
chunk 190 byte
↓
setiap chunk dienkripsi RSA-OAEP-256
↓
setiap chunk ciphertext menjadi 256 byte
↓
digabung menjadi file ciphertext
```

---

## Alur chunking enkripsi

```text
Input:
- plaintext file
- public key file

Proses:
1. Baca plaintext sebagai bytes
2. Baca public key RSA
3. Pecah plaintext menjadi chunk 190 byte
4. Untuk setiap chunk:
   - lakukan OAEP pad dengan SHA-256
   - enkripsi pakai RSA public key
   - hasilnya block ciphertext 256 byte
5. Gabungkan semua block ciphertext
6. Tulis ke output file

Output:
- ciphertext file
```

Gambarnya:

```text
plaintext file
     │
     ▼
dibaca sebagai bytes
     │
     ▼
dipecah per 190 byte
     │
     ▼
┌───────────┬───────────┬───────────┬───────────┐
│ chunk 1   │ chunk 2   │ chunk 3   │ chunk n   │
│ ≤190 byte │ ≤190 byte │ ≤190 byte │ ≤190 byte │
└─────┬─────┴─────┬─────┴─────┬─────┴─────┬─────┘
      ▼           ▼           ▼           ▼
 RSA-OAEP     RSA-OAEP    RSA-OAEP    RSA-OAEP
      ▼           ▼           ▼           ▼
  256 byte    256 byte    256 byte    256 byte
      └───────────┴───────────┴───────────┘
                    ▼
            ciphertext file
```

---

## Alur chunking dekripsi

```text
Input:
- ciphertext file
- private key file

Proses:
1. Baca ciphertext
2. Baca private key RSA
3. Pecah ciphertext menjadi block 256 byte
4. Untuk setiap block:
   - dekripsi pakai RSA private key
   - lakukan OAEP unpad
   - hasilnya plaintext chunk
5. Gabungkan semua plaintext chunk
6. Tulis ke output file

Output:
- plaintext asli
```

Gambarnya:

```text
ciphertext file
      │
      ▼
dipecah per 256 byte
      │
      ▼
┌──────────┬──────────┬──────────┬──────────┐
│ block 1  │ block 2  │ block 3  │ block n  │
│ 256 byte │ 256 byte │ 256 byte │ 256 byte │
└────┬─────┴────┬─────┴────┬─────┴────┬─────┘
     ▼          ▼          ▼          ▼
 RSA decrypt RSA decrypt RSA decrypt RSA decrypt
     ▼          ▼          ▼          ▼
 OAEP unpad  OAEP unpad  OAEP unpad  OAEP unpad
     ▼          ▼          ▼          ▼
 plaintext   plaintext   plaintext   plaintext
 chunk       chunk       chunk       chunk
     └──────────┴──────────┴──────────┘
                   ▼
            plaintext asli
```

---

## Kelebihan chunking

**1. Paling sesuai dengan soal**

Soal bilang implementasi **RSA-OAEP-256**. Dengan chunking, setiap bagian file memang dienkripsi memakai RSA-OAEP-256.

**2. Tidak perlu AES**

Karena standard library Python tidak menyediakan AES, chunking menghindari kebutuhan membuat AES sendiri atau memakai library eksternal.

**3. Lebih aman daripada custom stream cipher buatan sendiri**

Membuat stream cipher sendiri dari `hashlib.sha256` memang bisa terlihat praktis, tapi itu lebih sulit dipertanggungjawabkan secara kriptografi. Nanti bisa ditanya:

> “Ini stream cipher-nya standar apa?”

Kalau chunking, jawabannya jelas:

> “Setiap chunk dienkripsi dengan RSA-OAEP-256.”

**4. Lebih mudah dijelaskan saat demo**

Demo-nya sederhana:

```text
plaintext → chunk 190 byte → RSA-OAEP encrypt → ciphertext block 256 byte
```

---

## Kekurangan chunking

Tetap ada kekurangan penting.

**1. Lambat untuk file besar**

RSA itu berat. Kalau file video besar, misalnya 50 MB:

```text
50 MB / 190 byte ≈ 276.000 chunk
```

Artinya program harus melakukan RSA-OAEP ratusan ribu kali. Itu bisa lama.

**2. Output lebih besar**

Setiap maksimal 190 byte plaintext berubah jadi 256 byte ciphertext.

Rasio pembesarannya:

```text
256 / 190 ≈ 1.35
```

Jadi ciphertext bisa sekitar **35% lebih besar** dari file asli.

**3. Bukan desain production**

Di dunia nyata, RSA biasanya tidak dipakai untuk mengenkripsi file besar secara langsung, bahkan dengan chunking. Biasanya tetap hybrid:

```text
AES untuk file
RSA-OAEP untuk AES key
```

Tapi karena tugas ini membatasi library eksternal, chunking bisa dibela sebagai desain tugas akademik.

---

## Yang harus ditulis di README

Saya sarankan tulis asumsi seperti ini:

```markdown
## Asumsi Implementasi

Program ini mengimplementasikan RSA-OAEP-256 secara murni menggunakan Python standard library. Karena RSA-OAEP-256 dengan kunci 2048-bit hanya dapat mengenkripsi maksimal 190 byte per operasi, maka file input diproses menggunakan pendekatan chunking.

Pada proses enkripsi, file plaintext dibaca sebagai bytes dan dipecah menjadi beberapa chunk berukuran maksimal 190 byte. Setiap chunk kemudian diproses dengan OAEP menggunakan SHA-256 dan dienkripsi menggunakan RSA. Setiap hasil enkripsi menghasilkan block ciphertext berukuran 256 byte.

Pendekatan ini dipilih karena Python standard library tidak menyediakan implementasi AES, sementara penggunaan library kriptografi eksternal tidak diperbolehkan.
```

---

## Format file ciphertext yang bagus

Saya sarankan jangan cuma langsung gabung block. Tambahkan header sederhana.

Contoh format:

```text
MAGIC HEADER      8 byte    b"RSAOAEP1"
CHUNK_SIZE        2 byte    190
RSA_BLOCK_SIZE    2 byte    256
ORIGINAL_SIZE     8 byte    ukuran file asli
CIPHERTEXT_BLOCKS n × 256 byte
```

Jadi output-nya punya struktur:

```text
┌────────────────────────┐
│ MAGIC: RSAOAEP1         │
├────────────────────────┤
│ chunk size: 190         │
├────────────────────────┤
│ RSA block size: 256     │
├────────────────────────┤
│ original file size      │
├────────────────────────┤
│ ciphertext block 1      │
├────────────────────────┤
│ ciphertext block 2      │
├────────────────────────┤
│ ciphertext block 3      │
├────────────────────────┤
│ ...                    │
└────────────────────────┘
```

Ini membuat dekripsi lebih rapi dan mudah divalidasi.

---

## Kesimpulan saya

Pilih **chunking RSA-OAEP murni**.

Kalimat simpelnya:

```text
Karena tidak boleh memakai library kriptografi eksternal dan Python standard library tidak menyediakan AES, maka pendekatan hybrid AES tidak digunakan. Sebagai gantinya, program menggunakan chunking RSA-OAEP-256: file dipecah menjadi blok maksimal 190 byte, lalu setiap blok dienkripsi menggunakan RSA-OAEP-256.
```

Jadi menurut saya:

```text
Chunking = paling aman untuk tugas
Custom stream cipher = lebih cepat, tapi lebih susah dibela
AES sendiri = terlalu berat kalau waktunya mepet
```

Untuk tugas kuliah ini, saya akan ambil **chunking**.

```