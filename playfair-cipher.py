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
