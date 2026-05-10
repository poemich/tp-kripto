import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import os
from lib.rsa import generate_keypair
from lib.utils import save_key, encrypt_file, decrypt_file, get_ciphertext_ext


class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA-OAEP-256 File Tool")
        self.root.geometry("760x620")
        self.root.minsize(720, 600)
        self.root.configure(bg="#0f172a")

        self.enc_name_as_original = tk.BooleanVar(value=True)
        self.dec_name_as_original = tk.BooleanVar(value=True)

        self.create_widgets()

    def create_widgets(self):
        self.configure_style()

        shell = ttk.Frame(self.root, style="App.TFrame", padding=24)
        shell.pack(fill="both", expand=True)

        header = ttk.Frame(shell, style="App.TFrame")
        header.pack(fill="x", pady=(0, 18))

        ttk.Label(header, text="RSA-OAEP-256", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Encrypt and decrypt any file as bytes using chunked RSA-OAEP-256.",
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(4, 0))

        self.notebook = ttk.Notebook(shell, style="Modern.TNotebook")
        self.notebook.pack(fill="both", expand=True)

        self.frame_encrypt = ttk.Frame(self.notebook, style="Card.TFrame", padding=22)
        self.frame_decrypt = ttk.Frame(self.notebook, style="Card.TFrame", padding=22)
        self.frame_keys = ttk.Frame(self.notebook, style="Card.TFrame", padding=22)

        self.notebook.add(self.frame_encrypt, text="  Encrypt  ")
        self.notebook.add(self.frame_decrypt, text="  Decrypt  ")
        self.notebook.add(self.frame_keys, text="  Generate Keypair  ")

        self.setup_encrypt_tab()
        self.setup_decrypt_tab()
        self.setup_keys_tab()

    def configure_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("App.TFrame", background="#0f172a")
        style.configure("Card.TFrame", background="#111827")
        style.configure("Section.TFrame", background="#111827")
        style.configure("Title.TLabel", background="#0f172a", foreground="#f8fafc", font=("Segoe UI", 22, "bold"))
        style.configure("Subtitle.TLabel", background="#0f172a", foreground="#94a3b8", font=("Segoe UI", 10))
        style.configure("Header.TLabel", background="#111827", foreground="#e2e8f0", font=("Segoe UI", 13, "bold"))
        style.configure("Modern.TLabel", background="#111827", foreground="#cbd5e1", font=("Segoe UI", 10))
        style.configure("Hint.TLabel", background="#111827", foreground="#64748b", font=("Segoe UI", 9))
        style.configure("Status.TLabel", background="#1e293b", foreground="#93c5fd", font=("Segoe UI", 10), padding=(10, 7))

        style.configure(
            "Modern.TEntry",
            fieldbackground="#0b1220",
            foreground="#e5e7eb",
            bordercolor="#334155",
            lightcolor="#334155",
            darkcolor="#334155",
            insertcolor="#e5e7eb",
            padding=8,
        )
        style.map("Modern.TEntry", fieldbackground=[("disabled", "#111827")], foreground=[("disabled", "#94a3b8")])

        style.configure("Modern.TButton", background="#334155", foreground="#f8fafc", borderwidth=0, padding=(14, 8), font=("Segoe UI", 10, "bold"))
        style.map("Modern.TButton", background=[("active", "#475569"), ("disabled", "#1e293b")])
        style.configure("Primary.TButton", background="#2563eb", foreground="#ffffff", borderwidth=0, padding=(18, 10), font=("Segoe UI", 10, "bold"))
        style.map("Primary.TButton", background=[("active", "#1d4ed8"), ("disabled", "#1e293b")])
        style.configure("Success.TButton", background="#16a34a", foreground="#ffffff", borderwidth=0, padding=(18, 10), font=("Segoe UI", 10, "bold"))
        style.map("Success.TButton", background=[("active", "#15803d"), ("disabled", "#1e293b")])
        style.configure("Warning.TButton", background="#ca8a04", foreground="#ffffff", borderwidth=0, padding=(18, 10), font=("Segoe UI", 10, "bold"))
        style.map("Warning.TButton", background=[("active", "#a16207"), ("disabled", "#1e293b")])

        style.configure("Modern.TCheckbutton", background="#111827", foreground="#cbd5e1", font=("Segoe UI", 10))
        style.map("Modern.TCheckbutton", background=[("active", "#111827")], foreground=[("active", "#f8fafc")])

        style.configure("Modern.TNotebook", background="#0f172a", borderwidth=0)
        style.configure("Modern.TNotebook.Tab", background="#1e293b", foreground="#cbd5e1", padding=(16, 9), font=("Segoe UI", 10, "bold"))
        style.map("Modern.TNotebook.Tab", background=[("selected", "#111827"), ("active", "#334155")], foreground=[("selected", "#f8fafc")])

    def add_row(self, parent, row, label, entry, button_text=None, button_command=None):
        ttk.Label(parent, text=label, style="Modern.TLabel").grid(row=row, column=0, sticky="w", pady=8)
        entry.grid(row=row, column=1, sticky="ew", padx=(16, 10), pady=8)
        if button_text:
            ttk.Button(parent, text=button_text, style="Modern.TButton", command=button_command).grid(row=row, column=2, sticky="ew", pady=8)

    def set_entry_value(self, entry, value):
        old_state = entry.cget("state")
        entry.configure(state="normal")
        entry.delete(0, tk.END)
        entry.insert(0, value)
        entry.configure(state=old_state)

    def select_key_file(self, entry_widget):
        filename = filedialog.askopenfilename(title="Pilih File Kunci")
        if filename:
            self.set_entry_value(entry_widget, filename)

    def select_directory(self, entry_widget):
        dirname = filedialog.askdirectory(title="Pilih Folder Penyimpanan")
        if dirname:
            self.set_entry_value(entry_widget, dirname)

    def select_file_encrypt(self):
        filename = filedialog.askopenfilename(title="Pilih File untuk Dienkripsi")
        if filename:
            self.set_entry_value(self.enc_plain_entry, filename)
            self.set_entry_value(self.enc_dir_entry, os.path.dirname(filename))
            self.refresh_encrypt_output_name()

    def select_file_decrypt(self):
        filename = filedialog.askopenfilename(title="Pilih File untuk Didekripsi")
        if filename:
            self.set_entry_value(self.dec_cipher_entry, filename)
            self.set_entry_value(self.dec_dir_entry, os.path.dirname(filename))
            self.refresh_decrypt_output_name()

    def get_default_encrypted_name(self):
        plain = self.enc_plain_entry.get().strip()
        if not plain:
            return "encrypted_output.bin"
        name, _ = os.path.splitext(os.path.basename(plain))
        return f"{name}.bin"

    def get_default_decrypted_name(self):
        cipher = self.dec_cipher_entry.get().strip()
        if not cipher:
            return "decrypted_output"

        base_name = os.path.basename(cipher)
        name, ext = os.path.splitext(base_name)
        candidate = name if ext.lower() == ".bin" else base_name

        if candidate.endswith("_encrypted"):
            return f"{candidate[:-10]}{get_ciphertext_ext(cipher)}"

        original_ext = get_ciphertext_ext(cipher)

        if os.path.splitext(candidate)[1]:
            return candidate

        if original_ext:
            return f"{candidate}{original_ext}"

        return f"{candidate}_decrypted"

    def refresh_encrypt_output_name(self):
        if self.enc_name_as_original.get():
            self.enc_out_name_entry.configure(state="normal")
            self.set_entry_value(self.enc_out_name_entry, self.get_default_encrypted_name())
            self.enc_out_name_entry.configure(state="disabled")
        else:
            self.enc_out_name_entry.configure(state="normal")
            if not self.enc_out_name_entry.get().strip():
                self.set_entry_value(self.enc_out_name_entry, "encrypted_output.bin")

    def refresh_decrypt_output_name(self):
        if self.dec_name_as_original.get():
            self.dec_out_name_entry.configure(state="normal")
            self.set_entry_value(self.dec_out_name_entry, self.get_default_decrypted_name())
            self.dec_out_name_entry.configure(state="disabled")
        else:
            self.dec_out_name_entry.configure(state="normal")
            if not self.dec_out_name_entry.get().strip():
                self.set_entry_value(self.dec_out_name_entry, "decrypted_output")

    def build_output_path(self, folder, name, force_bin=False):
        clean_name = name.strip()
        if force_bin and not clean_name.lower().endswith(".bin"):
            clean_name += ".bin"
        return os.path.join(folder.strip(), clean_name)

    # --- ENCRYPT TAB ---
    def setup_encrypt_tab(self):
        self.frame_encrypt.columnconfigure(0, weight=1)

        ttk.Label(self.frame_encrypt, text="Encrypt File", style="Header.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            self.frame_encrypt,
            text="Ciphertext output is a binary .bin file. Any input file type is read as bytes.",
            style="Hint.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(4, 18))

        form = ttk.Frame(self.frame_encrypt, style="Section.TFrame")
        form.grid(row=2, column=0, sticky="nsew")
        form.columnconfigure(1, weight=1)

        self.enc_plain_entry = ttk.Entry(form, style="Modern.TEntry")
        self.enc_key_entry = ttk.Entry(form, style="Modern.TEntry")
        self.enc_dir_entry = ttk.Entry(form, style="Modern.TEntry")
        self.enc_out_name_entry = ttk.Entry(form, style="Modern.TEntry")
        self.enc_out_name_entry.insert(0, self.get_default_encrypted_name())
        self.enc_out_name_entry.configure(state="disabled")

        self.add_row(form, 0, "File to encrypt", self.enc_plain_entry, "Browse", self.select_file_encrypt)
        self.add_row(form, 1, "Public key file", self.enc_key_entry, "Browse", lambda: self.select_key_file(self.enc_key_entry))
        self.add_row(form, 2, "Output folder", self.enc_dir_entry, "Browse", lambda: self.select_directory(self.enc_dir_entry))

        ttk.Checkbutton(
            form,
            text="Name file as original",
            variable=self.enc_name_as_original,
            command=self.refresh_encrypt_output_name,
            style="Modern.TCheckbutton",
        ).grid(row=3, column=1, sticky="w", padx=(16, 10), pady=(8, 2))
        ttk.Label(form, text="Checked: output replaces the original extension with .bin", style="Hint.TLabel").grid(row=4, column=1, sticky="w", padx=(16, 10), pady=(0, 8))

        self.add_row(form, 5, "Output file name", self.enc_out_name_entry)

        actions = ttk.Frame(self.frame_encrypt, style="Section.TFrame")
        actions.grid(row=3, column=0, sticky="ew", pady=(24, 0))
        actions.columnconfigure(1, weight=1)

        self.btn_encrypt = ttk.Button(actions, text="Encrypt File", style="Primary.TButton", command=self.run_encrypt)
        self.btn_encrypt.grid(row=0, column=0, sticky="w")
        self.enc_status = ttk.Label(actions, text="Status: Ready", style="Status.TLabel")
        self.enc_status.grid(row=0, column=1, sticky="ew", padx=(16, 0))

    def run_encrypt(self):
        plain = self.enc_plain_entry.get().strip()
        key = self.enc_key_entry.get().strip()
        folder = self.enc_dir_entry.get().strip()
        out_name = self.enc_out_name_entry.get().strip()

        if self.enc_name_as_original.get():
            out_name = self.get_default_encrypted_name()

        if not plain or not key or not folder or not out_name:
            messagebox.showwarning("Peringatan", "File input, kunci, folder output, dan nama output harus diisi!")
            return

        out = self.build_output_path(folder, out_name, force_bin=True)

        self.btn_encrypt.config(state="disabled")
        self.enc_status.config(text="Status: Encrypting... RSA chunking may take a while")
        threading.Thread(target=self._thread_encrypt, args=(plain, key, out), daemon=True).start()

    def _thread_encrypt(self, plain, key, out):
        try:
            encrypt_file(plain, key, out)
            self.root.after(0, lambda: self.enc_status.config(text=f"Status: Encrypted to {os.path.basename(out)}"))
            self.root.after(0, lambda: messagebox.showinfo("Sukses", f"File berhasil dienkripsi:\n{out}"))
        except Exception as e:
            self.root.after(0, lambda: self.enc_status.config(text=f"Status: Error - {str(e)}"))
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        finally:
            self.root.after(0, lambda: self.btn_encrypt.config(state="normal"))

    # --- DECRYPT TAB ---
    def setup_decrypt_tab(self):
        self.frame_decrypt.columnconfigure(0, weight=1)

        ttk.Label(self.frame_decrypt, text="Decrypt File", style="Header.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            self.frame_decrypt,
            text="Decrypt a .bin ciphertext and write the plaintext file back to disk.",
            style="Hint.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(4, 18))

        form = ttk.Frame(self.frame_decrypt, style="Section.TFrame")
        form.grid(row=2, column=0, sticky="nsew")
        form.columnconfigure(1, weight=1)

        self.dec_cipher_entry = ttk.Entry(form, style="Modern.TEntry")
        self.dec_key_entry = ttk.Entry(form, style="Modern.TEntry")
        self.dec_dir_entry = ttk.Entry(form, style="Modern.TEntry")
        self.dec_out_name_entry = ttk.Entry(form, style="Modern.TEntry")
        self.dec_out_name_entry.insert(0, self.get_default_decrypted_name())
        self.dec_out_name_entry.configure(state="disabled")

        self.add_row(form, 0, "File to decrypt", self.dec_cipher_entry, "Browse", self.select_file_decrypt)
        self.add_row(form, 1, "Private key file", self.dec_key_entry, "Browse", lambda: self.select_key_file(self.dec_key_entry))
        self.add_row(form, 2, "Output folder", self.dec_dir_entry, "Browse", lambda: self.select_directory(self.dec_dir_entry))

        ttk.Checkbutton(
            form,
            text="Name file as original",
            variable=self.dec_name_as_original,
            command=self.refresh_decrypt_output_name,
            style="Modern.TCheckbutton",
        ).grid(row=3, column=1, sticky="w", padx=(16, 10), pady=(8, 2))
        ttk.Label(form, text="Checked: gambar.jpg.bin becomes gambar.jpg when possible", style="Hint.TLabel").grid(row=4, column=1, sticky="w", padx=(16, 10), pady=(0, 8))

        self.add_row(form, 5, "Output file name", self.dec_out_name_entry)

        actions = ttk.Frame(self.frame_decrypt, style="Section.TFrame")
        actions.grid(row=3, column=0, sticky="ew", pady=(24, 0))
        actions.columnconfigure(1, weight=1)

        self.btn_decrypt = ttk.Button(actions, text="Decrypt File", style="Success.TButton", command=self.run_decrypt)
        self.btn_decrypt.grid(row=0, column=0, sticky="w")
        self.dec_status = ttk.Label(actions, text="Status: Ready", style="Status.TLabel")
        self.dec_status.grid(row=0, column=1, sticky="ew", padx=(16, 0))

    def run_decrypt(self):
        cipher = self.dec_cipher_entry.get().strip()
        key = self.dec_key_entry.get().strip()
        folder = self.dec_dir_entry.get().strip()
        out_name = self.dec_out_name_entry.get().strip()

        if self.dec_name_as_original.get():
            out_name = self.get_default_decrypted_name()

        if not cipher or not key or not folder or not out_name:
            messagebox.showwarning("Peringatan", "File input, kunci, folder output, dan nama output harus diisi!")
            return

        out = self.build_output_path(folder, out_name)

        self.btn_decrypt.config(state="disabled")
        self.dec_status.config(text="Status: Decrypting... RSA chunking may take a while")
        threading.Thread(target=self._thread_decrypt, args=(cipher, key, out), daemon=True).start()

    def _thread_decrypt(self, cipher, key, out):
        try:
            decrypt_file(cipher, key, out)
            self.root.after(0, lambda: self.dec_status.config(text=f"Status: Decrypted to {os.path.basename(out)}"))
            self.root.after(0, lambda: messagebox.showinfo("Sukses", f"File berhasil didekripsi:\n{out}"))
        except Exception as e:
            self.root.after(0, lambda: self.dec_status.config(text=f"Status: Error - {str(e)}"))
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        finally:
            self.root.after(0, lambda: self.btn_decrypt.config(state="normal"))

    # --- KEYS TAB ---
    def setup_keys_tab(self):
        self.frame_keys.columnconfigure(0, weight=1)

        ttk.Label(self.frame_keys, text="Generate RSA Keypair", style="Header.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            self.frame_keys,
            text="Creates a 2048-bit RSA public/private key pair in hexadecimal text format.",
            style="Hint.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(4, 18))

        form = ttk.Frame(self.frame_keys, style="Section.TFrame")
        form.grid(row=2, column=0, sticky="nsew")
        form.columnconfigure(1, weight=1)

        self.key_dir_entry = ttk.Entry(form, style="Modern.TEntry")
        self.key_dir_entry.insert(0, os.getcwd())
        self.key_name_entry = ttk.Entry(form, style="Modern.TEntry")
        self.key_name_entry.insert(0, "mykey")

        self.add_row(form, 0, "Output folder", self.key_dir_entry, "Browse", lambda: self.select_directory(self.key_dir_entry))
        self.add_row(form, 1, "Key name", self.key_name_entry)

        actions = ttk.Frame(self.frame_keys, style="Section.TFrame")
        actions.grid(row=3, column=0, sticky="ew", pady=(24, 0))
        actions.columnconfigure(1, weight=1)

        self.btn_genkey = ttk.Button(actions, text="Generate Keypair", style="Warning.TButton", command=self.run_genkey)
        self.btn_genkey.grid(row=0, column=0, sticky="w")
        self.key_status = ttk.Label(actions, text="Status: Ready. Prime search may take a few seconds.", style="Status.TLabel")
        self.key_status.grid(row=0, column=1, sticky="ew", padx=(16, 0))

    def run_genkey(self):
        folder = self.key_dir_entry.get().strip()
        name = self.key_name_entry.get().strip()

        if not folder or not name:
            messagebox.showwarning("Peringatan", "Folder dan nama kunci harus diisi!")
            return

        pub_out = os.path.join(folder, f"{name}_public.key")
        priv_out = os.path.join(folder, f"{name}_private.key")

        self.btn_genkey.config(state="disabled")
        self.key_status.config(text="Status: Generating 2048-bit RSA keypair...")
        threading.Thread(target=self._thread_genkey, args=(pub_out, priv_out), daemon=True).start()

    def _thread_genkey(self, pub_out, priv_out):
        try:
            pub_key, priv_key = generate_keypair(2048)
            save_key(pub_key, pub_out)
            save_key(priv_key, priv_out)
            self.root.after(0, lambda: self.key_status.config(text=f"Status: Saved {os.path.basename(pub_out)} and {os.path.basename(priv_out)}"))
            self.root.after(0, lambda: messagebox.showinfo("Sukses", f"Keypair berhasil dibuat di:\n{os.path.dirname(pub_out)}"))
        except Exception as e:
            self.root.after(0, lambda: self.key_status.config(text=f"Status: Error - {str(e)}"))
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        finally:
            self.root.after(0, lambda: self.btn_genkey.config(state="normal"))


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
