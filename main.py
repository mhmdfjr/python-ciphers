import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import numpy as np

# Cipher Implementations (from above)
# ...

def vigenere_encrypt(text, key):
    key = key.upper()
    encrypted = []
    for i, char in enumerate(text):
        if char.isalpha():
            shift = ord(key[i % len(key)]) - ord('A')
            encrypted_char = chr((ord(char.upper()) - ord('A') + shift) % 26 + ord('A'))
            encrypted.append(encrypted_char)
        else:
            encrypted.append(char)
    return ''.join(encrypted)

def vigenere_decrypt(text, key):
    key = key.upper()
    decrypted = []
    for i, char in enumerate(text):
        if char.isalpha():
            shift = ord(key[i % len(key)]) - ord('A')
            decrypted_char = chr((ord(char.upper()) - ord('A') - shift + 26) % 26 + ord('A'))
            decrypted.append(decrypted_char)
        else:
            decrypted.append(char)
    return ''.join(decrypted)


def generate_playfair_matrix(key):
    matrix = []
    seen = set()
    key = ''.join(sorted(set(key.upper()), key=lambda x: key.index(x)))
    key = key.replace('J', 'I')
    alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    
    for char in key:
        if char not in seen:
            matrix.append(char)
            seen.add(char)
    
    for char in alphabet:
        if char not in seen:
            matrix.append(char)
    
    return [matrix[i:i+5] for i in range(0, len(matrix), 5)]

def playfair_encrypt(text, key):
    matrix = generate_playfair_matrix(key)
    # Logika enkripsi Playfair Cipher
    return text  # Kembalikan teks terenkripsi (implementasi penuh butuh penanganan pasangan karakter)

def playfair_decrypt(text, key):
    matrix = generate_playfair_matrix(key)
    # Logika dekripsi Playfair Cipher
    return text  # Kembalikan teks terdekripsi (implementasi penuh butuh penanganan pasangan karakter)

def hill_encrypt(text, key_matrix):
    text_vector = [ord(char.upper()) - ord('A') for char in text]
    key_matrix = np.array(key_matrix)
    result = np.dot(key_matrix, text_vector) % 26
    encrypted = ''.join([chr(num + ord('A')) for num in result])
    return encrypted

def hill_decrypt(text, key_matrix):
    key_matrix = np.linalg.inv(key_matrix).astype(int) % 26
    text_vector = [ord(char.upper()) - ord('A') for char in text]
    result = np.dot(key_matrix, text_vector) % 26
    decrypted = ''.join([chr(num + ord('A')) for num in result])
    return decrypted

def encrypt_text():
    text = input_text.get("1.0", tk.END).strip()
    key = key_entry.get().strip()
    if len(key) < 12:
        messagebox.showerror("Error", "Kunci harus minimal 12 karakter")
        return
    cipher = cipher_var.get()
    
    if cipher == "Vigenère":
        output = vigenere_encrypt(text, key)
    elif cipher == "Playfair":
        output = playfair_encrypt(text, key)
    elif cipher == "Hill":
        # Example 2x2 matrix key for Hill Cipher (can be modified as per your requirement)
        matrix = [[3, 3], [2, 5]]
        output = hill_encrypt(text, matrix)
    else:
        output = "Invalid Cipher"

    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, output)

def decrypt_text():
    text = input_text.get("1.0", tk.END).strip()
    key = key_entry.get().strip()
    if len(key) < 12:
        messagebox.showerror("Error", "Kunci harus minimal 12 karakter")
        return
    cipher = cipher_var.get()
    
    if cipher == "Vigenère":
        output = vigenere_decrypt(text, key)
    elif cipher == "Playfair":
        output = playfair_decrypt(text, key)
    elif cipher == "Hill":
        matrix = [[3, 3], [2, 5]]
        output = hill_decrypt(text, matrix)
    else:
        output = "Invalid Cipher"
    
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, output)

def open_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    with open(file_path, 'r') as file:
        input_text.delete("1.0", tk.END)
        input_text.insert(tk.END, file.read())

def save_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    with open(file_path, 'w') as file:
        file.write(output_text.get("1.0", tk.END).strip())

# Main GUI Window
root = tk.Tk()
root.title("Cipher Encryption and Decryption")

# Input Area
input_label = tk.Label(root, text="Input Text")
input_label.pack()
input_text = tk.Text(root, height=10)
input_text.pack()

# Key Input
key_label = tk.Label(root, text="Key (Min 12 Characters)")
key_label.pack()
key_entry = tk.Entry(root)
key_entry.pack()

# Cipher Selection
cipher_var = tk.StringVar(value="Vigenère")
cipher_label = tk.Label(root, text="Choose Cipher")
cipher_label.pack()
cipher_combo = ttk.Combobox(root, textvariable=cipher_var, values=["Vigenère", "Playfair", "Hill"])
cipher_combo.pack()

# Buttons
encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_text)
encrypt_button.pack()

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_text)
decrypt_button.pack()

open_button = tk.Button(root, text="Open File", command=open_file)
open_button.pack()

save_button = tk.Button(root, text="Save Output", command=save_file)
save_button.pack()

# Output Area
output_label = tk.Label(root, text="Output Text")
output_label.pack()
output_text = tk.Text(root, height=10)
output_text.pack()

root.mainloop()
