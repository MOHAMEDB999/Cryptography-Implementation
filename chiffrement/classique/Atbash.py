"""
Atbash Cipher Implementation

The Atbash cipher is a substitution cipher where each letter is replaced 
by its reverse in the alphabet:
A->Z, B->Y, C->X, ..., Z->A

It's also known as the reverse alphabet cipher.
Historically used in Hebrew texts.

Characteristics:
- Simple substitution cipher
- Symmetric (encrypting twice gives original text)
- Only works with letters, preserves case
- Not secure (can be broken by frequency analysis)
"""

def atbash_encrypt(text):
    """
    Encrypt text using Atbash cipher.
    
    Args:
        text: String to encrypt
        
    Returns:
        Encrypted string with reversed alphabet substitution
    """
    result = []
    for char in text:
        if char.isalpha():
            if char.isupper():
                # A=65, Z=90 in ASCII
                # A->Z: chr(90 - (65 - 65)) = chr(90)
                # B->Y: chr(90 - (66 - 65)) = chr(89)
                encrypted_char = chr(90 - (ord(char) - 65))
                result.append(encrypted_char)
            else:
                # a=97, z=122 in ASCII
                # a->z: chr(122 - (97 - 97)) = chr(122)
                # b->y: chr(122 - (98 - 97)) = chr(121)
                encrypted_char = chr(122 - (ord(char) - 97))
                result.append(encrypted_char)
        else:
            # Keep non-alphabetic characters unchanged
            result.append(char)
    
    return ''.join(result)


def atbash_decrypt(ciphertext):
    """
    Decrypt text using Atbash cipher.
    Since Atbash is symmetric, decryption is the same as encryption.
    
    Args:
        ciphertext: String to decrypt
        
    Returns:
        Decrypted string
    """
    return atbash_encrypt(ciphertext)


if __name__ == "__main__":
    print("=" * 50)
    print("Atbash Cipher Implementation")
    print("=" * 50)
    
    # Example 1: Simple text
    plaintext = "Hello World"
    ciphertext = atbash_encrypt(plaintext)
    decrypted = atbash_decrypt(ciphertext)
    
    print(f"\nPlaintext:  {plaintext}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted:  {decrypted}")
    
    # Example 2: Full alphabet
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    encrypted_alphabet = atbash_encrypt(alphabet)
    
    print(f"\nAlphabet:          {alphabet}")
    print(f"Atbash transform:  {encrypted_alphabet}")
    
    # Example 3: Case preservation
    text_mixed = "Python Cryptography"
    encrypted = atbash_encrypt(text_mixed)
    
    print(f"\nOriginal:   {text_mixed}")
    print(f"Encrypted:  {encrypted}")
    print(f"Decrypted:  {atbash_decrypt(encrypted)}")
