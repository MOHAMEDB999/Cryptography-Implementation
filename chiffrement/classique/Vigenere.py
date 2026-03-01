"""
Vigenere Cipher Implementation

An extension of the Caesar cipher that uses a keyword to vary the shift.
Each character in the key determines the shift for the corresponding plaintext character.

For example, with key 'KEY':
Position 0: shift by K (10)
Position 1: shift by E (4)
Position 2: shift by Y (24)
Then repeats...

Characteristics:
- Polyalphabetic substitution cipher
- More secure than Caesar (harder to break with frequency analysis)
- Still vulnerable to Kasiski examination and Index of Coincidence
"""

def vigenere_encrypt(plaintext, key):
    """
    Encrypt text using Vigenere cipher.
    
    Args:
        plaintext: Text to encrypt
        key: Keyword for encryption
        
    Returns:
        Encrypted text
    """
    result = []
    key = key.upper()
    key_index = 0
    
    for char in plaintext:
        if char.isalpha():
            # Get the shift value from the key
            shift = ord(key[key_index % len(key)]) - ord('A')
            key_index += 1
            
            if char.isupper():
                encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                encrypted_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            result.append(encrypted_char)
        else:
            result.append(char)
    
    return ''.join(result)


def vigenere_decrypt(ciphertext, key):
    """
    Decrypt Vigenere cipher.
    
    Args:
        ciphertext: Text to decrypt
        key: Keyword used for encryption
        
    Returns:
        Decrypted text
    """
    result = []
    key = key.upper()
    key_index = 0
    
    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            key_index += 1
            
            if char.isupper():
                decrypted_char = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            else:
                decrypted_char = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            result.append(decrypted_char)
        else:
            result.append(char)
    
    return ''.join(result)


if __name__ == "__main__":
    print("=" * 50)
    print("Vigenere Cipher Implementation")
    print("=" * 50)
    
    plaintext = "Hello World"
    key = "SECRET"
    
    ciphertext = vigenere_encrypt(plaintext, key)
    decrypted = vigenere_decrypt(ciphertext, key)
    
    print(f"\nPlaintext:  {plaintext}")
    print(f"Key:        {key}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted:  {decrypted}")
    
    # Example 2
    text2 = "The quick brown fox"
    key2 = "CIPHER"
    
    enc2 = vigenere_encrypt(text2, key2)
    print(f"\nPlaintext:  {text2}")
    print(f"Key:        {key2}")
    print(f"Ciphertext: {enc2}")
    print(f"Decrypted:  {vigenere_decrypt(enc2, key2)}")
