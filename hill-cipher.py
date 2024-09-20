import numpy as np

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
