"""
Monoalphabetic Substitution Cipher Implementation

A substitution cipher where each letter of the plaintext alphabet is mapped
to a corresponding letter in the ciphertext alphabet. The mapping remains
the same throughout the encryption process.

Example mapping:
Plaintext:  ABCDEFGHIJKLMNOPQRSTUVWXYZ
Ciphertext: QWERTYUIOPASDFGHJKLZXCVBNM

This is more secure than Caesar cipher because it doesn't have a predictable
pattern, but it can still be broken by frequency analysis.

Characteristics:
- Substitution cipher (replaces each letter with another)
- Fixed mapping table (key)
- Vulnerable to frequency analysis
- More secure than Caesar cipher but still breakable
"""

import random

def create_random_mapping():
    """
    Create a random substitution mapping.
    
    Returns:
        A dictionary with mapping from plaintext to ciphertext
    """
    plaintext_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    ciphertext_alphabet = list(plaintext_alphabet)
    random.shuffle(ciphertext_alphabet)
    
    mapping = {}
    for i, letter in enumerate(plaintext_alphabet):
        mapping[letter] = ciphertext_alphabet[i]
        mapping[letter.lower()] = ciphertext_alphabet[i].lower()
    
    return mapping

def create_mapping_from_key(key):
    """
    Create a substitution mapping from a keyword.
    Uses the keyword followed by remaining letters of alphabet.
    
    Args:
        key: A string to use as the key
    
    Returns:
        A dictionary with mapping from plaintext to ciphertext
    """
    plaintext_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    key = key.upper().replace(' ', '')
    
    # Remove duplicate letters from key
    seen = set()
    unique_key = ''
    for letter in key:
        if letter.isalpha() and letter not in seen:
            unique_key += letter
            seen.add(letter)
    
    # Add remaining letters
    ciphertext_alphabet = unique_key
    for letter in plaintext_alphabet:
        if letter not in ciphertext_alphabet:
            ciphertext_alphabet += letter
    
    mapping = {}
    for i, letter in enumerate(plaintext_alphabet):
        mapping[letter] = ciphertext_alphabet[i]
        mapping[letter.lower()] = ciphertext_alphabet[i].lower()
    
    return mapping

def monoalphabetic_encrypt(plaintext, mapping):
    """
    Encrypt text using monoalphabetic substitution.
    
    Args:
        plaintext: Text to encrypt
        mapping: Dictionary containing the substitution mapping
    
    Returns:
        Encrypted text
    """
    result = []
    for char in plaintext:
        if char.isalpha():
            result.append(mapping.get(char, char))
        else:
            result.append(char)
    return ''.join(result)

def monoalphabetic_decrypt(ciphertext, mapping):
    """
    Decrypt text using monoalphabetic substitution.
    
    Args:
        ciphertext: Text to decrypt
        mapping: Dictionary containing the substitution mapping (encryption mapping)
    
    Returns:
        Decrypted text
    """
    # Reverse the mapping
    reverse_mapping = {v: k for k, v in mapping.items()}
    
    result = []
    for char in ciphertext:
        if char.isalpha():
            result.append(reverse_mapping.get(char, char))
        else:
            result.append(char)
    return ''.join(result)

def print_mapping(mapping):
    """
    Print the encryption mapping in a readable format.
    
    Args:
        mapping: The substitution mapping dictionary
    """
    plaintext_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    ciphertext_alphabet = ''.join([mapping[letter] for letter in plaintext_alphabet])
    
    print("\nSubstitution Mapping:")
    print("-" * 60)
    print(f"Plaintext:  {plaintext_alphabet}")
    print(f"Ciphertext: {ciphertext_alphabet}")
    print("-" * 60)

if __name__ == "__main__":
    print("=" * 60)
    print("Monoalphabetic Substitution Cipher Implementation")
    print("=" * 60)
    
    # Example 1: Using a keyword-based mapping
    key1 = "CRYPTOGRAPHY"
    mapping1 = create_mapping_from_key(key1)
    
    plaintext1 = "Hello World"
    ciphertext1 = monoalphabetic_encrypt(plaintext1, mapping1)
    decrypted1 = monoalphabetic_decrypt(ciphertext1, mapping1)
    
    print(f"\nExample 1: Using key '{key1}'")
    print(f"Plaintext: {plaintext1}")
    print_mapping(mapping1)
    print(f"Ciphertext: {ciphertext1}")
    print(f"Decrypted: {decrypted1}")
    
    # Example 2: Using another keyword
    key2 = "SECRET"
    mapping2 = create_mapping_from_key(key2)
    
    plaintext2 = "The quick brown fox jumps over the lazy dog"
    ciphertext2 = monoalphabetic_encrypt(plaintext2, mapping2)
    decrypted2 = monoalphabetic_decrypt(ciphertext2, mapping2)
    
    print(f"\nExample 2: Using key '{key2}'")
    print(f"Plaintext: {plaintext2}")
    print_mapping(mapping2)
    print(f"Ciphertext: {ciphertext2}")
    print(f"Decrypted: {decrypted2}")
    
    # Example 3: Using random mapping
    print(f"\nExample 3: Using random mapping")
    mapping3 = create_random_mapping()
    plaintext3 = "Monoalphabetic cipher is educational"
    ciphertext3 = monoalphabetic_encrypt(plaintext3, mapping3)
    decrypted3 = monoalphabetic_decrypt(ciphertext3, mapping3)
    
    print(f"Plaintext: {plaintext3}")
    print_mapping(mapping3)
    print(f"Ciphertext: {ciphertext3}")
    print(f"Decrypted: {decrypted3}")
