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
