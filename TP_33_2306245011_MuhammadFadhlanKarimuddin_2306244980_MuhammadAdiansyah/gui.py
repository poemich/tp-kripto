import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import os
from lib.rsa import generate_keypair
from lib.utils import save_key, encrypt_file, decrypt_file, get_ciphertext_ext

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA-OAEP-256 Tool (Chunking)")
        self.root.geometry("500x350")
        self.root.resizable(False, False)
        
        self.create_widgets()
        
    def create_widgets(self):
        # Tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(pady=10, expand=True)
        
        self.frame_encrypt = ttk.Frame(self.notebook, width=480, height=300)
        self.frame_decrypt = ttk.Frame(self.notebook, width=480, height=300)
        self.frame_keys = ttk.Frame(self.notebook, width=480, height=300)
        
        self.frame_encrypt.pack(fill='both', expand=True)
        self.frame_decrypt.pack(fill='both', expand=True)
        self.frame_keys.pack(fill='both', expand=True)
        
        self.notebook.add(self.frame_encrypt, text='Enkripsi')
        self.notebook.add(self.frame_decrypt, text='Dekripsi')
        self.notebook.add(self.frame_keys, text='Generate Keypair')
        
        self.setup_encrypt_tab()
        self.setup_decrypt_tab()
        self.setup_keys_tab()

    def select_file_encrypt(self):
        filename = filedialog.askopenfilename(title="Pilih File Plaintext")
        if filename:
            self.enc_plain_entry.delete(0, tk.END)
            self.enc_plain_entry.insert(0, filename)
            
            # Auto-fill output
            dir_path = os.path.dirname(filename)
            base_name = os.path.basename(filename)
            name, _ = os.path.splitext(base_name)
            out_path = os.path.join(dir_path, f"{name}_encrypted.bin")
            
            self.enc_out_entry.delete(0, tk.END)
            self.enc_out_entry.insert(0, out_path)

    def select_file_decrypt(self):
        filename = filedialog.askopenfilename(title="Pilih File Ciphertext")
        if filename:
            self.dec_cipher_entry.delete(0, tk.END)
            self.dec_cipher_entry.insert(0, filename)
            
            # Auto-fill output
            dir_path = os.path.dirname(filename)
            base_name = os.path.basename(filename)
            name, _ = os.path.splitext(base_name)
            
            # Hapus suffix _encrypted jika ada
            if name.endswith("_encrypted"):
                name = name[:-10]
            
            # Ambil ekstensi asli dari ciphertext
            ext = get_ciphertext_ext(filename)
            
            # Beri akhiran _decrypted + ekstensi asli
            out_path = os.path.join(dir_path, f"{name}_decrypted{ext}")
            
            self.dec_out_entry.delete(0, tk.END)
            self.dec_out_entry.insert(0, out_path)

    def select_key_file(self, entry_widget):
        filename = filedialog.askopenfilename(title="Pilih File Kunci")
        if filename:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, filename)

    def select_directory(self, entry_widget):
        dirname = filedialog.askdirectory(title="Pilih Folder Penyimpanan")
        if dirname:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, dirname)

    # --- ENCRYPT TAB ---
    def setup_encrypt_tab(self):
        tk.Label(self.frame_encrypt, text="File Plaintext:").place(x=20, y=20)
        self.enc_plain_entry = tk.Entry(self.frame_encrypt, width=40)
        self.enc_plain_entry.place(x=120, y=20)
        tk.Button(self.frame_encrypt, text="Pilih", command=self.select_file_encrypt).place(x=380, y=15)
        
        tk.Label(self.frame_encrypt, text="File Public Key:").place(x=20, y=60)
        self.enc_key_entry = tk.Entry(self.frame_encrypt, width=40)
        self.enc_key_entry.place(x=120, y=60)
        tk.Button(self.frame_encrypt, text="Pilih", command=lambda: self.select_key_file(self.enc_key_entry)).place(x=380, y=55)
        
        tk.Label(self.frame_encrypt, text="Output File:").place(x=20, y=100)
        self.enc_out_entry = tk.Entry(self.frame_encrypt, width=40)
        self.enc_out_entry.place(x=120, y=100)
        
        self.btn_encrypt = tk.Button(self.frame_encrypt, text="Proses Enkripsi", bg="lightblue", command=self.run_encrypt)
        self.btn_encrypt.place(x=180, y=150)
        
        self.enc_status = tk.Label(self.frame_encrypt, text="Status: Menunggu", fg="blue")
        self.enc_status.place(x=20, y=200)

    def run_encrypt(self):
        plain = self.enc_plain_entry.get()
        key = self.enc_key_entry.get()
        out = self.enc_out_entry.get()
        
        if not plain or not key or not out:
            messagebox.showwarning("Peringatan", "Semua field harus diisi!")
            return
            
        self.btn_encrypt.config(state="disabled")
        self.enc_status.config(text="Status: Sedang mengenkripsi... (Mungkin agak lama)")
        
        # Pindahkan ke thread agar GUI tidak freeze
        threading.Thread(target=self._thread_encrypt, args=(plain, key, out)).start()

    def _thread_encrypt(self, plain, key, out):
        try:
            encrypt_file(plain, key, out)
            self.root.after(0, lambda: self.enc_status.config(text="Status: Enkripsi Berhasil!"))
            self.root.after(0, lambda: messagebox.showinfo("Sukses", "File berhasil dienkripsi!"))
        except Exception as e:
            self.root.after(0, lambda: self.enc_status.config(text=f"Status: Error - {str(e)}"))
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        finally:
            self.root.after(0, lambda: self.btn_encrypt.config(state="normal"))


    # --- DECRYPT TAB ---
    def setup_decrypt_tab(self):
        tk.Label(self.frame_decrypt, text="File Ciphertext:").place(x=20, y=20)
        self.dec_cipher_entry = tk.Entry(self.frame_decrypt, width=40)
        self.dec_cipher_entry.place(x=120, y=20)
        tk.Button(self.frame_decrypt, text="Pilih", command=self.select_file_decrypt).place(x=380, y=15)
        
        tk.Label(self.frame_decrypt, text="File Private Key:").place(x=20, y=60)
        self.dec_key_entry = tk.Entry(self.frame_decrypt, width=40)
        self.dec_key_entry.place(x=120, y=60)
        tk.Button(self.frame_decrypt, text="Pilih", command=lambda: self.select_key_file(self.dec_key_entry)).place(x=380, y=55)
        
        tk.Label(self.frame_decrypt, text="Output File:").place(x=20, y=100)
        self.dec_out_entry = tk.Entry(self.frame_decrypt, width=40)
        self.dec_out_entry.place(x=120, y=100)
        
        self.btn_decrypt = tk.Button(self.frame_decrypt, text="Proses Dekripsi", bg="lightgreen", command=self.run_decrypt)
        self.btn_decrypt.place(x=180, y=150)
        
        self.dec_status = tk.Label(self.frame_decrypt, text="Status: Menunggu", fg="blue")
        self.dec_status.place(x=20, y=200)

    def run_decrypt(self):
        cipher = self.dec_cipher_entry.get()
        key = self.dec_key_entry.get()
        out = self.dec_out_entry.get()
        
        if not cipher or not key or not out:
            messagebox.showwarning("Peringatan", "Semua field harus diisi!")
            return
            
        self.btn_decrypt.config(state="disabled")
        self.dec_status.config(text="Status: Sedang mendekripsi... (Mungkin agak lama)")
        
        threading.Thread(target=self._thread_decrypt, args=(cipher, key, out)).start()

    def _thread_decrypt(self, cipher, key, out):
        try:
            decrypt_file(cipher, key, out)
            self.root.after(0, lambda: self.dec_status.config(text="Status: Dekripsi Berhasil!"))
            self.root.after(0, lambda: messagebox.showinfo("Sukses", "File berhasil didekripsi!"))
        except Exception as e:
            self.root.after(0, lambda: self.dec_status.config(text=f"Status: Error - {str(e)}"))
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        finally:
            self.root.after(0, lambda: self.btn_decrypt.config(state="normal"))

    # --- KEYS TAB ---
    def setup_keys_tab(self):
        tk.Label(self.frame_keys, text="Folder Simpan:").place(x=20, y=30)
        self.key_dir_entry = tk.Entry(self.frame_keys, width=40)
        self.key_dir_entry.insert(0, os.getcwd())
        self.key_dir_entry.place(x=120, y=30)
        tk.Button(self.frame_keys, text="Pilih Folder", command=lambda: self.select_directory(self.key_dir_entry)).place(x=380, y=25)

        tk.Label(self.frame_keys, text="Nama Kunci:").place(x=20, y=70)
        self.key_name_entry = tk.Entry(self.frame_keys, width=40)
        self.key_name_entry.insert(0, "mykey")
        self.key_name_entry.place(x=120, y=70)

        self.btn_genkey = tk.Button(self.frame_keys, text="Generate Keypair", bg="yellow", command=self.run_genkey)
        self.btn_genkey.place(x=160, y=120)

        self.key_status = tk.Label(self.frame_keys, text="Peringatan: Mencari prima besar butuh waktu beberapa detik.", fg="gray")
        self.key_status.place(x=20, y=170)

    def run_genkey(self):
        folder = self.key_dir_entry.get()
        name = self.key_name_entry.get()
        
        if not folder or not name:
            messagebox.showwarning("Peringatan", "Folder dan Nama Kunci harus diisi!")
            return

        pub_out = os.path.join(folder, f"{name}_public.key")
        priv_out = os.path.join(folder, f"{name}_private.key")

        self.btn_genkey.config(state="disabled")
        self.key_status.config(text="Status: Sedang generate kunci 2048-bit... (Mohon tunggu)", fg="blue")
        
        threading.Thread(target=self._thread_genkey, args=(pub_out, priv_out)).start()

    def _thread_genkey(self, pub_out, priv_out):
        try:
            pub_key, priv_key = generate_keypair(2048)
            save_key(pub_key, pub_out)
            save_key(priv_key, priv_out)
            self.root.after(0, lambda: self.key_status.config(text=f"Status: Selesai! Tersimpan sebagai {os.path.basename(pub_out)}", fg="green"))
            self.root.after(0, lambda: messagebox.showinfo("Sukses", f"Keypair berhasil dibuat di:\n{os.path.dirname(pub_out)}"))
        except Exception as e:
            self.root.after(0, lambda: self.key_status.config(text=f"Status: Error - {str(e)}", fg="red"))
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        finally:
            self.root.after(0, lambda: self.btn_genkey.config(state="normal"))

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
