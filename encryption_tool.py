import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from Crypto.Cipher import AES, ChaCha20
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import base64
import json

class ComprehensiveEncryptionTool:
    def __init__(self, master):
        self.master = master
        master.title("Comprehensive Encryption Tool")
        master.geometry("600x550")
        
        style = ttk.Style()
        style.theme_use('clam')
        
        self.algorithm = tk.StringVar(value="AES-GCM")
        self.input_mode = tk.StringVar(value="file")
        self.output_mode = tk.StringVar(value="file")
        
        self.create_widgets()
        self.generate_rsa_keys()
    
    def create_widgets(self):
        # Algorithm selection
        ttk.Label(self.master, text="Encryption Algorithm:").grid(row=0, column=0, padx=5, pady=5)
        ttk.Radiobutton(self.master, text="AES-GCM", variable=self.algorithm, value="AES-GCM").grid(row=0, column=1, padx=5, pady=5)
        ttk.Radiobutton(self.master, text="AES-CBC", variable=self.algorithm, value="AES-CBC").grid(row=0, column=2, padx=5, pady=5)
        ttk.Radiobutton(self.master, text="ChaCha20", variable=self.algorithm, value="ChaCha20").grid(row=0, column=3, padx=5, pady=5)
        
        # Input mode selection
        ttk.Label(self.master, text="Input:").grid(row=1, column=0, padx=5, pady=5)
        ttk.Radiobutton(self.master, text="File", variable=self.input_mode, value="file").grid(row=1, column=1, padx=5, pady=5)
        ttk.Radiobutton(self.master, text="Text", variable=self.input_mode, value="text").grid(row=1, column=2, padx=5, pady=5)
        
        # Output mode selection
        ttk.Label(self.master, text="Output:").grid(row=2, column=0, padx=5, pady=5)
        ttk.Radiobutton(self.master, text="File", variable=self.output_mode, value="file").grid(row=2, column=1, padx=5, pady=5)
        ttk.Radiobutton(self.master, text="Text", variable=self.output_mode, value="text").grid(row=2, column=2, padx=5, pady=5)
        
        # Input
        self.input_text = tk.Text(self.master, height=5, width=60)
        self.input_text.grid(row=3, column=0, columnspan=4, padx=5, pady=5)
        
        # Output
        self.output_text = tk.Text(self.master, height=5, width=60)
        self.output_text.grid(row=4, column=0, columnspan=4, padx=5, pady=5)
        
        # Buttons
        ttk.Button(self.master, text="Encrypt", command=self.encrypt).grid(row=5, column=0, padx=5, pady=5)
        ttk.Button(self.master, text="Decrypt", command=self.decrypt).grid(row=5, column=1, padx=5, pady=5)
        ttk.Button(self.master, text="Clear", command=self.clear).grid(row=5, column=2, padx=5, pady=5)
        ttk.Button(self.master, text="Verify Signature", command=self.verify_signature).grid(row=5, column=3, padx=5, pady=5)
    
    def generate_rsa_keys(self):
        if not os.path.exists('private_key.pem') or not os.path.exists('public_key.pem'):
            key = RSA.generate(2048)
            private_key = key.export_key()
            with open("private_key.pem", "wb") as f:
                f.write(private_key)
            public_key = key.publickey().export_key()
            with open("public_key.pem", "wb") as f:
                f.write(public_key)
    
    def get_cipher(self, key):
        if self.algorithm.get() == "AES-GCM":
            nonce = get_random_bytes(12)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            return cipher, nonce
        elif self.algorithm.get() == "AES-CBC":
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            return cipher, iv
        else:
            cipher = ChaCha20.new(key=key)
            return cipher, cipher.nonce
    
    def sign_data(self, data):
        key = RSA.import_key(open('private_key.pem').read())
        h = SHA256.new(data)
        signature = pkcs1_15.new(key).sign(h)
        return signature
    
    def verify_signature(self):
        try:
            if self.input_mode.get() == "file":
                file_path = filedialog.askopenfilename()
                with open(file_path, 'r') as file:
                    data = json.loads(base64.b64decode(file.read()).decode('utf-8'))
            else:
                data = json.loads(base64.b64decode(self.input_text.get("1.0", tk.END).strip()).decode('utf-8'))
            
            key = RSA.import_key(open('public_key.pem').read())
            h = SHA256.new(base64.b64decode(data['ciphertext']))
            pkcs1_15.new(key).verify(h, base64.b64decode(data['signature']))
            messagebox.showinfo("Success", "Signature verified successfully!")
        except (ValueError, TypeError, json.JSONDecodeError):
            messagebox.showerror("Error", "Signature verification failed!")
    
    def encrypt(self):
        try:
            key = get_random_bytes(32)
            cipher, nonce_or_iv = self.get_cipher(key)
            
            if self.input_mode.get() == "file":
                file_path = filedialog.askopenfilename()
                with open(file_path, 'rb') as file:
                    data = file.read()
            else:
                data = self.input_text.get("1.0", tk.END).strip().encode()
            
            if not data:
                raise ValueError("Input data is empty")
            
            if self.algorithm.get() == "AES-CBC":
                encrypted_data = cipher.encrypt(pad(data, AES.block_size))
            else:
                encrypted_data = cipher.encrypt(data)
            
            signature = self.sign_data(encrypted_data)
            
            print(f"Encrypting with algorithm: {self.algorithm.get()}")

            output = {
                'algorithm': self.algorithm.get(),
                'nonce_or_iv': base64.b64encode(nonce_or_iv).decode('utf-8'),
                'ciphertext': base64.b64encode(encrypted_data).decode('utf-8'),
                'signature': base64.b64encode(signature).decode('utf-8')
            }

            output_str = base64.b64encode(json.dumps(output).encode('utf-8')).decode('utf-8')
            
            if self.output_mode.get() == "file":
                file_path = filedialog.asksaveasfilename(defaultextension=".enc")
                with open(file_path, 'w') as file:
                    file.write(output_str)
                messagebox.showinfo("Success", "File encrypted and signed successfully!")
            else:
                self.output_text.delete("1.0", tk.END)
                self.output_text.insert(tk.END, output_str)
            
            # Save the key
            with open('encryption_key.key', 'wb') as key_file:
                key_file.write(key)
        
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during encryption: {str(e)}")
    
    def decrypt(self):
        try:
            with open('encryption_key.key', 'rb') as key_file:
                key = key_file.read()

            if self.input_mode.get() == "file":
                file_path = filedialog.askopenfilename()
                with open(file_path, 'r') as file:
                    encrypted_data = json.loads(base64.b64decode(file.read()).decode('utf-8'))
            else:
                encrypted_data = json.loads(base64.b64decode(self.input_text.get("1.0", tk.END).strip()).decode('utf-8'))

            if not encrypted_data:
                raise ValueError("Input data is empty")

            algorithm = encrypted_data['algorithm']
            nonce_or_iv = base64.b64decode(encrypted_data['nonce_or_iv'])
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            signature = base64.b64decode(encrypted_data['signature'])

            # Debugging print statement
            print(f"Decrypting with algorithm: {algorithm}")

            if not self.verify_signature_data(ciphertext, signature):
                raise ValueError("Digital signature verification failed")

            if algorithm == "AES-GCM":
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce_or_iv)
                decrypted_data = cipher.decrypt(ciphertext)
            elif algorithm == "AES-CBC":
                cipher = AES.new(key, AES.MODE_CBC, iv=nonce_or_iv)
                decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
            elif algorithm == "ChaCha20":
                cipher = ChaCha20.new(key=key, nonce=nonce_or_iv)
                decrypted_data = cipher.decrypt(ciphertext)
            else:
                raise ValueError("Unsupported algorithm")

            if self.output_mode.get() == "file":
                file_path = filedialog.asksaveasfilename(defaultextension=".dec")
                with open(file_path, 'wb') as file:
                    file.write(decrypted_data)
                messagebox.showinfo("Success", "File decrypted successfully!")
            else:
                self.output_text.delete("1.0", tk.END)
                self.output_text.insert(tk.END, decrypted_data.decode())

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during decryption: {str(e)}")

    
    def verify_signature_data(self, data, signature):
        key = RSA.import_key(open('public_key.pem').read())
        h = SHA256.new(data)
        try:
            pkcs1_15.new(key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
    
    def clear(self):
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    encryption_tool = ComprehensiveEncryptionTool(root)
    root.mainloop()
