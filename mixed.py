import tkinter as tk
from tkinter import filedialog, messagebox
import numpy as np

# Fungsi untuk enkripsi dan dekripsi Vigenere Cipher
def vigenere_encrypt(plain_text, key):
    cipher_text = ""
    key = key.lower()
    key_length = len(key)
    for i, char in enumerate(plain_text):
        if char.isalpha():
            shift = ord(key[i % key_length]) - ord('a')
            if char.isupper():
                cipher_text += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                cipher_text += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
        else:
            cipher_text += char
    return cipher_text

def vigenere_decrypt(cipher_text, key):
    plain_text = ""
    key = key.lower()
    key_length = len(key)
    for i, char in enumerate(cipher_text):
        if char.isalpha():
            shift = ord(key[i % key_length]) - ord('a')
            if char.isupper():
                plain_text += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            else:
                plain_text += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
        else:
            plain_text += char
    return plain_text

# Fungsi untuk enkripsi dan dekripsi Playfair Cipher
def generate_playfair_key_matrix(key):
    key = ''.join(sorted(set(key), key=key.index))
    key = key.lower().replace('j', 'i')
    alphabet = 'abcdefghiklmnopqrstuvwxyz'
    matrix = [char for char in key if char in alphabet]
    for char in alphabet:
        if char not in matrix:
            matrix.append(char)
    return np.array(matrix).reshape(5, 5)

def playfair_encrypt(plain_text, key):
    matrix = generate_playfair_key_matrix(key)
    plain_text = plain_text.lower().replace('j', 'i')
    digraphs = []
    i = 0
    while i < len(plain_text):
        a = plain_text[i]
        b = plain_text[i + 1] if i + 1 < len(plain_text) else 'x'
        if a == b:
            digraphs.append((a, 'x'))
            i += 1
        else:
            digraphs.append((a, b))
            i += 2
    cipher_text = ""
    for a, b in digraphs:
        a_row, a_col = np.where(matrix == a)
        b_row, b_col = np.where(matrix == b)
        if a_row == b_row:
            cipher_text += matrix[a_row, (a_col + 1) % 5] + matrix[b_row, (b_col + 1) % 5]
        elif a_col == b_col:
            cipher_text += matrix[(a_row + 1) % 5, a_col] + matrix[(b_row + 1) % 5, b_col]
        else:
            cipher_text += matrix[a_row, b_col] + matrix[b_row, a_col]
    return cipher_text

def playfair_decrypt(cipher_text, key):
    matrix = generate_playfair_key_matrix(key)
    digraphs = [(cipher_text[i], cipher_text[i + 1]) for i in range(0, len(cipher_text), 2)]
    plain_text = ""
    for a, b in digraphs:
        a_row, a_col = np.where(matrix == a)
        b_row, b_col = np.where(matrix == b)
        if a_row == b_row:
            plain_text += matrix[a_row, (a_col - 1) % 5] + matrix[b_row, (b_col - 1) % 5]
        elif a_col == b_col:
            plain_text += matrix[(a_row - 1) % 5, a_col] + matrix[(b_row - 1) % 5, b_col]
        else:
            plain_text += matrix[a_row, b_col] + matrix[b_row, a_col]
    return plain_text

# Fungsi untuk enkripsi dan dekripsi Hill Cipher
def hill_encrypt(plain_text, key_matrix):
    text_vector = [ord(char) - ord('a') for char in plain_text]
    encrypted_vector = np.dot(key_matrix, text_vector) % 26
    return ''.join(chr(num + ord('a')) for num in encrypted_vector)

def hill_decrypt(cipher_text, key_matrix):
    cipher_vector = [ord(char) - ord('a') for char in cipher_text]
    inverse_key_matrix = np.linalg.inv(key_matrix).astype(int) % 26
    decrypted_vector = np.dot(inverse_key_matrix, cipher_vector) % 26
    return ''.join(chr(num + ord('a')) for num in decrypted_vector)

# Fungsi untuk membuka file
def open_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, 'r') as file:
            text_box.delete(1.0, tk.END)
            text_box.insert(tk.END, file.read())

# Fungsi untuk menyimpan hasil ke file
def save_file(text):
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, 'w') as file:
            file.write(text)

# Fungsi untuk memproses enkripsi atau dekripsi
def process_text(action):
    cipher_choice = cipher_var.get()
    plain_text = text_box.get(1.0, tk.END).strip()
    key = key_entry.get().strip()

    if len(key) < 12:
        messagebox.showerror("Error", "Panjang kunci harus minimal 12 karakter.")
        return

    if cipher_choice == "Vigenere":
        if action == "Encrypt":
            result = vigenere_encrypt(plain_text, key)
        else:
            result = vigenere_decrypt(plain_text, key)

    elif cipher_choice == "Playfair":
        if action == "Encrypt":
            result = playfair_encrypt(plain_text, key)
        else:
            result = playfair_decrypt(plain_text, key)

    elif cipher_choice == "Hill":
        # Hill Cipher requires a 2x2 key matrix, modify as needed
        key_matrix = np.array([[1, 2], [3, 5]])  # Contoh kunci Hill Cipher
        if action == "Encrypt":
            result = hill_encrypt(plain_text, key_matrix)
        else:
            result = hill_decrypt(plain_text, key_matrix)

    text_box.delete(1.0, tk.END)
    text_box.insert(tk.END, result)

# GUI setup
root = tk.Tk()
root.title("Encryption Tool")
root.geometry("600x500")

# Teks Area
text_box = tk.Text(root, wrap=tk.WORD, height=15, width=60)
text_box.pack(pady=10)

# Label dan Input untuk kunci
key_label = tk.Label(root, text="Masukkan Kunci (Minimal 12 karakter):")
key_label.pack()
key_entry = tk.Entry(root, show="*", width=40)
key_entry.pack(pady=5)

# Pilihan cipher
cipher_var = tk.StringVar(value="Vigenere")
cipher_label = tk.Label(root, text="Pilih Cipher:")
cipher_label.pack()
cipher_menu = tk.OptionMenu(root, cipher_var, "Vigenere", "Playfair", "Hill")
cipher_menu.pack(pady=5)

# Tombol untuk enkripsi, dekripsi, membuka file, dan menyimpan
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

encrypt_button = tk.Button(button_frame, text="Enkripsi", command=lambda: process_text("Encrypt"))
encrypt_button.grid(row=0, column=0, padx=5)

decrypt_button = tk.Button(button_frame, text="Dekripsi", command=lambda: process_text("Decrypt"))
decrypt_button.grid(row=0, column=1, padx=5)

open_button = tk.Button(button_frame, text="Buka File", command=open_file)
open_button.grid(row=0, column=2, padx=5)

save_button = tk.Button(button_frame, text="Simpan Hasil", command=lambda: save_file(text_box.get(1.0, tk.END).strip()))
save_button.grid(row=0, column=3, padx=5)

# Jalankan GUI
root.mainloop()
