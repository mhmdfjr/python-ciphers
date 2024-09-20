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

def find_position(char, matrix):
    pos = np.where(matrix == char)
    return int(pos[0]), int(pos[1])

def playfair_encrypt(plain_text, key):
    matrix = generate_playfair_key_matrix(key)
    plain_text = plain_text.lower().replace('j', 'i')
    
    # Buat digraph dari plain_text
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
        a_row, a_col = find_position(a, matrix)
        b_row, b_col = find_position(b, matrix)
        if a_row == b_row:  # Huruf dalam satu baris
            cipher_text += matrix[a_row, (a_col + 1) % 5] + matrix[b_row, (b_col + 1) % 5]
        elif a_col == b_col:  # Huruf dalam satu kolom
            cipher_text += matrix[(a_row + 1) % 5, a_col] + matrix[(b_row + 1) % 5, b_col]
        else:  # Huruf dalam kotak
            cipher_text += matrix[a_row, b_col] + matrix[b_row, a_col]

    return cipher_text

def playfair_decrypt(cipher_text, key):
    matrix = generate_playfair_key_matrix(key)
    digraphs = [(cipher_text[i], cipher_text[i + 1]) for i in range(0, len(cipher_text), 2)]
    plain_text = ""
    for a, b in digraphs:
        a_row, a_col = find_position(a, matrix)
        b_row, b_col = find_position(b, matrix)
        if a_row == b_row:
            plain_text += matrix[a_row, (a_col - 1) % 5] + matrix[b_row, (b_col - 1) % 5]
        elif a_col == b_col:
            plain_text += matrix[(a_row - 1) % 5, a_col] + matrix[(b_row - 1) % 5, b_col]
        else:
            plain_text += matrix[a_row, b_col] + matrix[b_row, a_col]
    return plain_text

# Fungsi untuk enkripsi dan dekripsi Hill Cipher
def hill_encrypt(plain_text, key_matrix):
    plain_text = plain_text.lower()
    n = key_matrix.shape[0]
    
    # Menambahkan padding jika panjang plain_text tidak sesuai dengan ukuran matriks kunci
    if len(plain_text) % n != 0:
        plain_text += 'x' * (n - len(plain_text) % n)

    text_vector = np.array([ord(char) - ord('a') for char in plain_text]).reshape(-1, n)
    encrypted_vector = np.dot(text_vector, key_matrix) % 26
    return ''.join(chr(num + ord('a')) for row in encrypted_vector for num in row)

def hill_decrypt(cipher_text, key_matrix):
    cipher_text = cipher_text.lower()
    n = key_matrix.shape[0]
    
    # Menghitung invers dari matriks kunci
    det = int(np.round(np.linalg.det(key_matrix)))
    det_inv = pow(det, -1, 26)  # Invers determinan modulo 26
    adjugate_matrix = np.round(det * np.linalg.inv(key_matrix)).astype(int) % 26
    inv_key_matrix = (det_inv * adjugate_matrix) % 26
    
    cipher_vector = np.array([ord(char) - ord('a') for char in cipher_text]).reshape(-1, n)
    decrypted_vector = np.dot(cipher_vector, inv_key_matrix) % 26
    return ''.join(chr(num + ord('a')) for row in decrypted_vector for num in row)

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
        # Hill Cipher requires a 2x2 or 3x3 key matrix
        key_matrix = np.array([[6, 24], [1, 16]])  # Contoh matriks kunci 2x2
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
open_button.grid(row=1, column=0, padx=5)

save_button = tk.Button(button_frame, text="Simpan Hasil", command=lambda: save_file(text_box.get(1.0, tk.END)))
save_button.grid(row=1, column=1, padx=5)

root.mainloop()
