import random
import string
import hashlib
import base64
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import messagebox
import pyperclip

class PasswordGeneratorApp:
    def __init__(self, master):
        self.master = master
        master.title("Password Generator")  
        master.config(bg="#121212")

        self.label_num_passwords = tk.Label(master, text="Number of Passwords:", bg="#121212", fg="white")
        self.label_num_passwords.grid(row=0, column=0)

        self.entry_num_passwords = tk.Entry(master)
        self.entry_num_passwords.grid(row=0, column=1)

        self.label_length = tk.Label(master, text="Length:", bg="#121212", fg="white")
        self.label_length.grid(row=1, column=0)

        self.entry_length = tk.Entry(master)
        self.entry_length.grid(row=1, column=1)

        self.label_uppercase = tk.Label(master, text="Uppercase:", bg="#121212", fg="white")
        self.label_uppercase.grid(row=2, column=0)

        self.var_uppercase = tk.BooleanVar(value=False)
        self.check_uppercase = tk.Checkbutton(master, variable=self.var_uppercase, bg="#121212", fg="black", activebackground="#121212", activeforeground="white", highlightthickness=0, indicatoron=False, width=1, padx=5, pady=2)
        self.check_uppercase.grid(row=2, column=1)

        self.label_lowercase = tk.Label(master, text="Lowercase:", bg="#121212", fg="white")
        self.label_lowercase.grid(row=3, column=0)

        self.var_lowercase = tk.BooleanVar(value=False)
        self.check_lowercase = tk.Checkbutton(master, variable=self.var_lowercase, bg="#121212", fg="black", activebackground="#121212", activeforeground="white", highlightthickness=0, indicatoron=False, width=1, padx=5, pady=2)
        self.check_lowercase.grid(row=3, column=1)

        self.label_numbers = tk.Label(master, text="Numbers:", bg="#121212", fg="white")
        self.label_numbers.grid(row=4, column=0)

        self.var_numbers = tk.BooleanVar(value=False)
        self.check_numbers = tk.Checkbutton(master, variable=self.var_numbers, bg="#121212", fg="black", activebackground="#121212", activeforeground="white", highlightthickness=0, indicatoron=False, width=1, padx=5, pady=2)
        self.check_numbers.grid(row=4, column=1)

        self.label_symbols = tk.Label(master, text="Symbols:", bg="#121212", fg="white")
        self.label_symbols.grid(row=5, column=0)

        self.var_symbols = tk.BooleanVar(value=False)
        self.check_symbols = tk.Checkbutton(master, variable=self.var_symbols, bg="#121212", fg="black", activebackground="#121212", activeforeground="white", highlightthickness=0, indicatoron=False, width=1, padx=5, pady=2)
        self.check_symbols.grid(row=5, column=1)

        self.label_encryption = tk.Label(master, text="Encryption:", bg="#121212", fg="white")
        self.label_encryption.grid(row=6, column=0)

        self.var_encryption = tk.StringVar()
        self.var_encryption.set("None")
        self.encryption_options = ["None", "SHA512", "AES", "Base64", "Vigenere"]
        self.encryption_menu = tk.OptionMenu(master, self.var_encryption, *self.encryption_options)
        self.encryption_menu.config(bg="#121212", fg="white", activebackground="#121212", activeforeground="white", highlightthickness=0)
        self.encryption_menu["menu"].config(bg="#121212", fg="white", activebackground="#121212", activeforeground="white", borderwidth=0)
        self.encryption_menu.grid(row=6, column=1)

        self.strength_label = tk.Label(master, text="Strength:", bg="#121212", fg="white")
        self.strength_label.grid(row=7, column=0)

        self.strength_var = tk.StringVar()
        self.strength_meter = tk.Label(master, textvariable=self.strength_var, bg="#121212", fg="white")
        self.strength_meter.grid(row=7, column=1)

        self.generate_button = tk.Button(master, text="Generate", command=self.generate_passwords, bg="#333333", fg="white", bd=0, padx=10, pady=5, relief=tk.FLAT, highlightbackground="#333333", activebackground="#555555", activeforeground="white", borderwidth=0, highlightthickness=0)
        self.generate_button.grid(row=8, column=0, columnspan=2)

        self.clear_button = tk.Button(master, text="Clear", command=self.clear_fields, bg="#333333", fg="white", bd=0, padx=10, pady=5, relief=tk.FLAT, highlightbackground="#333333", activebackground="#555555", activeforeground="white", borderwidth=0, highlightthickness=0)
        self.clear_button.grid(row=9, column=0)

        self.copy_button = tk.Button(master, text="Copy", command=self.copy_password, bg="#333333", fg="white", bd=0, padx=10, pady=5, relief=tk.FLAT, highlightbackground="#333333", activebackground="#555555", activeforeground="white", borderwidth=0, highlightthickness=0)
        self.copy_button.grid(row=9, column=1)

        self.cancel_button = tk.Button(master, text="Cancel", command=master.quit, bg="#333333", fg="white", bd=0, padx=10, pady=5, relief=tk.FLAT, highlightbackground="#333333", activebackground="#555555", activeforeground="white", borderwidth=0, highlightthickness=0)
        self.cancel_button.grid(row=10, column=0, columnspan=2)

        self.password_label = tk.Label(master, text="Passwords:", bg="#121212", fg="white")
        self.password_label.grid(row=11, column=0, columnspan=2)

        self.password_text = tk.Text(master, height=10, width=30, bg="#333333", fg="white", bd=0, padx=5, pady=5, relief=tk.FLAT)
        self.password_text.grid(row=12, column=0, columnspan=2)

        self.undo_button = tk.Button(master, text="Undo", command=self.undo, bg="#333333", fg="white", bd=0, padx=10, pady=5, relief=tk.FLAT, highlightbackground="#333333", activebackground="#555555", activeforeground="white", borderwidth=0, highlightthickness=0)
        self.undo_button.grid(row=13, column=0)

        self.redo_button = tk.Button(master, text="Redo", command=self.redo, bg="#333333", fg="white", bd=0, padx=10, pady=5, relief=tk.FLAT, highlightbackground="#333333", activebackground="#555555", activeforeground="white", borderwidth=0, highlightthickness=0)
        self.redo_button.grid(row=13, column=1)

        self.undo_stack = []
        self.redo_stack = []

    def generate_passwords(self):
        num_passwords = int(self.entry_num_passwords.get())
        length = int(self.entry_length.get())
        use_uppercase = self.var_uppercase.get()
        use_lowercase = self.var_lowercase.get()
        use_numbers = self.var_numbers.get()
        use_symbols = self.var_symbols.get()

        characters = ""
        if use_uppercase:
            characters += string.ascii_uppercase
        if use_lowercase:
            characters += string.ascii_lowercase
        if use_numbers:
            characters += string.digits
        if use_symbols:
            characters += string.punctuation

        if not characters:
            messagebox.showerror("Error", "Please select at least one character type.")
            return

        for _ in range(num_passwords):
            password = ''.join(random.choice(characters) for _ in range(length))
            self.password_text.insert(tk.END, password + '\n')
            self.undo_stack.append(password)

            strength = self.evaluate_strength(password)
            self.strength_var.set(strength)

            encryption_type = self.var_encryption.get()
            if encryption_type != "None":
                encrypted_password, key = self.encrypt_password(password, encryption_type)
                self.password_text.insert(tk.END, f"Encrypted Password: {encrypted_password}\n")
                if key:
                    self.password_text.insert(tk.END, f"Key: {key}\n")

            self.save_to_file(password)

    def clear_fields(self):
        self.password_text.delete(1.0, tk.END)

    def copy_password(self):
        password = self.password_text.get(1.0, tk.END).strip()
        pyperclip.copy(password)
        messagebox.showinfo("Copied", "Password copied to clipboard.")

    def undo(self):
        if self.undo_stack:
            password = self.undo_stack.pop()
            self.redo_stack.append(password)
            self.password_text.delete(1.0, tk.END)
            for pw in self.undo_stack:
                self.password_text.insert(tk.END, pw + '\n')

    def redo(self):
        if self.redo_stack:
            password = self.redo_stack.pop()
            self.undo_stack.append(password)
            self.password_text.insert(tk.END, password + '\n')

    def evaluate_strength(self, password):
        length = len(password)
        variety = sum(1 for c in string.ascii_lowercase if c in password.lower()) + \
                  sum(1 for c in string.ascii_uppercase if c in password) + \
                  sum(1 for c in string.digits if c in password) + \
                  sum(1 for c in string.punctuation if c in password)
        strength = "Weak"
        if length >= 8 and variety >= 3:
            strength = "Strong"
        elif length >= 6 and variety >= 2:
            strength = "Moderate"
        return strength

    def encrypt_password(self, password, encryption_type):
        if encryption_type == 'SHA512':
            hashed_password = hashlib.sha512(password.encode()).hexdigest()
            return hashed_password, None
        elif encryption_type == 'AES':
            key = Fernet.generate_key()
            cipher = Fernet(key)
            encrypted_password = cipher.encrypt(password.encode()).decode()
            return encrypted_password, key.decode()
        elif encryption_type == 'Base64':
            return base64.b64encode(password.encode()).decode(), None
        elif encryption_type == 'Vigenere':
            key = ''.join(random.choice(string.ascii_lowercase) for _ in range(len(password)))
            encrypted_chars = []
            for i, char in enumerate(password):
                key_c = key[i % len(key)]
                encrypted_char = chr((ord(char) + ord(key_c)) % 256)
                encrypted_chars.append(encrypted_char)
            return ''.join(encrypted_chars), key


    def save_to_file(self, password):
        filename = "generated_passwords.txt"
        with open(filename, "a", encoding="utf-8") as file:
            i = len(open(filename).readlines()) + 1
        
            encryption_type = self.var_encryption.get()
            if encryption_type == "None":
                file.write(f"{i}- Your Password is: {password}\n")
            else:
                encrypted_password, _ = self.encrypt_password(password, encryption_type)
                file.write(f"{i}- Your Password before encryption: {password}, after encryption: {encrypted_password}\n")
        messagebox.showinfo("File Saved", f"Password saved to {filename}")



root = tk.Tk()
app = PasswordGeneratorApp(root)
root.mainloop()
