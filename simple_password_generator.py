import random
import string
import json
import os
import base64
import hashlib
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import messagebox

# Configuration
DATA_FILE = "data.enc"
KEY_FILE = "key.bin"

def generate_simple_key(master_password_str):
    hashed_pw = hashlib.sha256(master_password_str.encode()).digest()
    return base64.urlsafe_b64encode(hashed_pw)

def save_key(key_bytes):
    with open(KEY_FILE, 'wb') as f:
        f.write(key_bytes)

def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    return None

def generate_password(site_name, keywords=None, length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    pw_parts = []

    pw_parts.append(random.choice(string.ascii_lowercase))
    pw_parts.append(random.choice(string.ascii_uppercase))
    pw_parts.append(random.choice(string.digits))
    pw_parts.append(random.choice(string.punctuation))

    if site_name:
        pw_parts.append(site_name[:2].upper())

    if keywords:
        for kw in keywords.split():
            if kw:
                pw_parts.append(kw)

    random.shuffle(pw_parts)
    
    gen_pw = ''.join(pw_parts)

    if len(gen_pw) < length:
        gen_pw += ''.join(random.choice(chars) for _ in range(length - len(gen_pw)))
    elif len(gen_pw) > length:
        gen_pw = ''.join(random.sample(gen_pw, length))

    final_pw_list = list(gen_pw)
    random.shuffle(final_pw_list)
    return ''.join(final_pw_list)

def encrypt_and_save_data(f_obj, site, user, pw):
    stored_data = []
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'rb') as f:
                encrypted_content = f.read()
                if encrypted_content:
                    decrypted_content = f_obj.decrypt(encrypted_content).decode()
                    stored_data = json.loads(decrypted_content)
        except Exception:
            messagebox.showerror("Error", "Could not read or decrypt data. Wrong password?")
            return False

    new_entry = {
        "site": site,
        "user": user,
        "password": pw
    }
    stored_data.append(new_entry)

    encrypted_to_save = f_obj.encrypt(json.dumps(stored_data).encode())
    with open(DATA_FILE, 'wb') as f:
        f.write(encrypted_to_save)
    return True

def load_and_decrypt_data(f_obj):
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'rb') as f:
                encrypted_content = f.read()
                if not encrypted_content:
                    return []
                decrypted_content = f_obj.decrypt(encrypted_content).decode()
                return json.loads(decrypted_content)
        except Exception:
            messagebox.showerror("Error", "Failed to decrypt data. Is your master password correct?")
            return None
    return []

class App:
    def __init__(self, main_window):
        self.main_window = main_window
        main_window.title("Simple Password Manager")
        main_window.geometry("400x550")
        main_window.resizable(False, False)

        self.fernet_obj = None

        self.login_frame = tk.Frame(main_window, padx=10, pady=10)
        self.login_frame.pack(expand=True, fill="both")

        tk.Label(self.login_frame, text="Master Password:", font=('Arial', 12)).pack(pady=5)
        self.master_pw_entry = tk.Entry(self.login_frame, show='*', width=30)
        self.master_pw_entry.pack(pady=5)
        self.master_pw_entry.bind('<Return>', lambda event: self.check_login())

        tk.Button(self.login_frame, text="Login", command=self.check_login).pack(pady=10)

        if not load_key():
            tk.Label(self.login_frame, text="First time: Enter a password to set it up.").pack()
            self.master_pw_entry.focus_set()
        else:
            self.master_pw_entry.focus_set()

        self.app_frame = tk.Frame(main_window, padx=10, pady=10)

        tk.Label(self.app_frame, text="Site Name:").grid(row=0, column=0, sticky='w', pady=2)
        self.site_entry = tk.Entry(self.app_frame, width=30)
        self.site_entry.grid(row=0, column=1, pady=2)

        tk.Label(self.app_frame, text="Username:").grid(row=1, column=0, sticky='w', pady=2)
        self.user_entry = tk.Entry(self.app_frame, width=30)
        self.user_entry.grid(row=1, column=1, pady=2)

        tk.Label(self.app_frame, text="Keywords (opt):").grid(row=2, column=0, sticky='w', pady=2)
        self.keywords_entry = tk.Entry(self.app_frame, width=30)
        self.keywords_entry.grid(row=2, column=1, pady=2)

        tk.Label(self.app_frame, text="Length (8-24):").grid(row=3, column=0, sticky='w', pady=2)
        self.length_entry = tk.Entry(self.app_frame, width=10)
        self.length_entry.insert(0, "12")
        self.length_entry.grid(row=3, column=1, sticky='w', pady=2)

        tk.Button(self.app_frame, text="Generate", command=self.generate_and_display).grid(row=4, column=0, columnspan=2, pady=5)

        tk.Label(self.app_frame, text="Generated PW:").grid(row=5, column=0, sticky='w', pady=2)
        self.gen_pw_display = tk.Entry(self.app_frame, width=30, state='readonly')
        self.gen_pw_display.grid(row=5, column=1, pady=2)

        tk.Button(self.app_frame, text="Save Password", command=self.save_current_pw).grid(row=6, column=0, columnspan=2, pady=10)

        tk.Label(self.app_frame, text="Saved Passwords:").grid(row=7, column=0, columnspan=2, pady=5)
        self.saved_pw_text = tk.Text(self.app_frame, width=40, height=8, wrap='word')
        self.saved_pw_text.grid(row=8, column=0, columnspan=2, pady=5)
        self.saved_pw_text.config(state='disabled')

        tk.Button(self.app_frame, text="Refresh List", command=self.display_saved_passwords).grid(row=9, column=0, columnspan=2, pady=5)

    def check_login(self):
        master_pw = self.master_pw_entry.get()
        if not master_pw:
            messagebox.showwarning("Input", "Master password needed!")
            return

        stored_key_bytes = load_key()

        if not stored_key_bytes:
            new_key_bytes = generate_simple_key(master_pw)
            save_key(new_key_bytes)
            self.fernet_obj = Fernet(new_key_bytes)
            messagebox.showinfo("Setup", "Master password set!")
            self.show_app_frame()
        else:
            test_fernet = Fernet(generate_simple_key(master_pw))
            if load_and_decrypt_data(test_fernet) is not None:
                self.fernet_obj = test_fernet
                messagebox.showinfo("Login", "Login successful!")
                self.show_app_frame()
            else:
                messagebox.showerror("Login", "Incorrect password.")
        self.master_pw_entry.delete(0, tk.END)

    def show_app_frame(self):
        self.login_frame.pack_forget()
        self.app_frame.pack(expand=True, fill="both")
        self.display_saved_passwords()

    def generate_and_display(self):
        site = self.site_entry.get().strip()
        keywords = self.keywords_entry.get().strip()
        try:
            length = int(self.length_entry.get())
            if not (8 <= length <= 24):
                messagebox.showwarning("Length", "Length must be 8-24.")
                return
        except ValueError:
            messagebox.showwarning("Length", "Enter a number for length.")
            return

        if not site:
            messagebox.showwarning("Input", "Site name is required.")
            return

        new_pw = generate_password(site, keywords if keywords else None, length)
        self.gen_pw_display.config(state='normal')
        self.gen_pw_display.delete(0, tk.END)
        self.gen_pw_display.insert(0, new_pw)
        self.gen_pw_display.config(state='readonly')

    def save_current_pw(self):
        site = self.site_entry.get().strip()
        user = self.user_entry.get().strip()
        pw = self.gen_pw_display.get()

        if not site or not user or not pw:
            messagebox.showwarning("Input", "All fields needed to save.")
            return
        if not self.fernet_obj:
            messagebox.showerror("Error", "Not logged in!")
            return

        if encrypt_and_save_data(self.fernet_obj, site, user, pw):
            messagebox.showinfo("Saved", "Password saved.")
            self.site_entry.delete(0, tk.END)
            self.user_entry.delete(0, tk.END)
            self.keywords_entry.delete(0, tk.END)
            self.gen_pw_display.config(state='normal')
            self.gen_pw_display.delete(0, tk.END)
            self.gen_pw_display.config(state='readonly')
            self.display_saved_passwords()
        else:
            messagebox.showerror("Save Error", "Failed to save.")

    def display_saved_passwords(self):
        self.saved_pw_text.config(state='normal')
        self.saved_pw_text.delete(1.0, tk.END)

        if not self.fernet_obj:
            self.saved_pw_text.insert(tk.END, "Login first.")
            self.saved_pw_text.config(state='disabled')
            return

        pw_data = load_and_decrypt_data(self.fernet_obj)
        if pw_data is None:
            self.saved_pw_text.insert(tk.END, "Error loading.")
        elif not pw_data:
            self.saved_pw_text.insert(tk.END, "No passwords here.")
        else:
            for entry in pw_data:
                self.saved_pw_text.insert(tk.END, f"Site: {entry['site']}\n")
                self.saved_pw_text.insert(tk.END, f"User: {entry['user']}\n")
                self.saved_pw_text.insert(tk.END, f"PW: {entry['password']}\n\n")
        self.saved_pw_text.config(state='disabled')

root = tk.Tk()
app_instance = App(root)
root.mainloop()
