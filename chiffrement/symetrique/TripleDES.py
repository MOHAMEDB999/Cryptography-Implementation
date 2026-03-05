"""
Triple DES (3DES/TDES) Implementation

Triple DES is a symmetric-key block cipher that applies DES three times.
It uses either two or three keys to enhance security compared to standard DES.

Key Characteristics:
- Block size: 64 bits
- Key size: 168 bits (three 56-bit keys) or 112 bits (two 56-bit keys with EDE)
- Number of rounds: 48 (3 x 16 rounds of DES)
- Symmetric encryption (same key for encryption and decryption)
- EDE mode: Encrypt-Decrypt-Encrypt (more secure than EEE)

Modes of Operation:
- EDE (Encrypt-Decrypt-Encrypt): K1, K2, K3
- EEE (Encrypt-Encrypt-Encrypt): Less common

Security Note:
While more secure than DES, Triple DES is still considered legacy and should
be replaced with AES for new applications. It is included here for educational
purposes and historical understanding.
"""

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii

def generate_3des_key(use_two_keys=False):
    """
    Generate a random key for Triple DES.
    
    Args:
        use_two_keys: If True, generate a 16-byte key (two 8-byte keys).
                      If False, generate a 24-byte key (three 8-byte keys).
    
    Returns:
        bytes: 16-byte (two-key) or 24-byte (three-key) 3DES key
    """
    key_size = 16 if use_two_keys else 24
    return get_random_bytes(key_size)

def triple_des_encrypt(plaintext, key):
    """
    Encrypt plaintext using Triple DES in ECB mode.
    
    Args:
        plaintext: Text to encrypt (string)
        key: 16 or 24-byte 3DES key (bytes)
    
    Returns:
        str: Ciphertext in hexadecimal format
    """
    # Ensure plaintext is bytes
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Validate key length
    if len(key) not in (16, 24):
        raise ValueError("3DES key must be 16 or 24 bytes long")
    
    # Create 3DES cipher in ECB mode
    cipher = DES3.new(key, DES3.MODE_ECB)
    
    # Pad plaintext
    padded_plaintext = pad(plaintext, DES3.block_size)
    
    # Encrypt
    ciphertext = cipher.encrypt(padded_plaintext)
    
    return binascii.hexlify(ciphertext).decode()

def triple_des_decrypt(ciphertext_hex, key):
    """
    Decrypt ciphertext using Triple DES in ECB mode.
    
    Args:
        ciphertext_hex: Hexadecimal encoded ciphertext (string)
        key: 16 or 24-byte 3DES key (bytes)
    
    Returns:
        str: Decrypted plaintext
    """
    # Convert from hex
    ciphertext = binascii.unhexlify(ciphertext_hex)
    
    # Validate key length
    if len(key) not in (16, 24):
        raise ValueError("3DES key must be 16 or 24 bytes long")
    
    # Create 3DES cipher in ECB mode
    cipher = DES3.new(key, DES3.MODE_ECB)
    
    # Decrypt
    padded_plaintext = cipher.decrypt(ciphertext)
    
    # Unpad
    plaintext = unpad(padded_plaintext, DES3.block_size)
    
    return plaintext.decode('utf-8')

def triple_des_encrypt_cbc(plaintext, key):
    """
    Encrypt plaintext using Triple DES in CBC mode (more secure).
    
    Args:
        plaintext: Text to encrypt (string)
        key: 16 or 24-byte 3DES key (bytes)
    
    Returns:
        tuple: (ciphertext in hex, iv in hex)
    """
    # Ensure plaintext is bytes
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Validate key length
    if len(key) not in (16, 24):
        raise ValueError("3DES key must be 16 or 24 bytes long")
    
    # Generate random IV
    iv = get_random_bytes(DES3.block_size)
    
    # Create 3DES cipher in CBC mode
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    
    # Pad plaintext
    padded_plaintext = pad(plaintext, DES3.block_size)
    
    # Encrypt
    ciphertext = cipher.encrypt(padded_plaintext)
    
    return binascii.hexlify(ciphertext).decode(), binascii.hexlify(iv).decode()

def triple_des_decrypt_cbc(ciphertext_hex, key, iv_hex):
    """
    Decrypt ciphertext using Triple DES in CBC mode.
    
    Args:
        ciphertext_hex: Hexadecimal encoded ciphertext (string)
        key: 16 or 24-byte 3DES key (bytes)
        iv_hex: Hexadecimal encoded IV (string)
    
    Returns:
        str: Decrypted plaintext
    """
    # Convert from hex
    ciphertext = binascii.unhexlify(ciphertext_hex)
    iv = binascii.unhexlify(iv_hex)
    
    # Validate key length
    if len(key) not in (16, 24):
        raise ValueError("3DES key must be 16 or 24 bytes long")
    
    # Create 3DES cipher in CBC mode
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    
    # Decrypt
    padded_plaintext = cipher.decrypt(ciphertext)
    
    # Unpad
    plaintext = unpad(padded_plaintext, DES3.block_size)
    
    return plaintext.decode('utf-8')

if __name__ == "__main__":
    print("=" * 60)
    print("Triple DES (3DES/TDES) Implementation")
    print("=" * 60)
    print("\nNote: 3DES is legacy. Use AES for new applications.\n")
    
    # Generate a 24-byte (3-key) 3DES key
    key = generate_3des_key(use_two_keys=False)
    print(f"Generated 3DES Key (24-byte, hex): {binascii.hexlify(key).decode()}")
    
    # Example 1: ECB Mode
    plaintext1 = "Hello Triple DES"
    print(f"\n--- ECB Mode Example ---")
    print(f"Plaintext: {plaintext1}")
    
    ciphertext1 = triple_des_encrypt(plaintext1, key)
    print(f"Ciphertext (hex): {ciphertext1}")
    
    decrypted1 = triple_des_decrypt(ciphertext1, key)
    print(f"Decrypted: {decrypted1}")
    
    # Example 2: CBC Mode
    plaintext2 = "Triple DES with CBC Mode"
    print(f"\n--- CBC Mode Example (Recommended) ---")
    print(f"Plaintext: {plaintext2}")
    
    ciphertext2, iv2 = triple_des_encrypt_cbc(plaintext2, key)
    print(f"Ciphertext (hex): {ciphertext2}")
    print(f"IV (hex): {iv2}")
    
    decrypted2 = triple_des_decrypt_cbc(ciphertext2, key, iv2)
    print(f"Decrypted: {decrypted2}")
    
    # Example 3: Using 2-key variant
    key_2 = generate_3des_key(use_two_keys=True)
    plaintext3 = "3DES with 2 keys"
    print(f"\n--- 2-Key Triple DES (EDE Mode) ---")
    print(f"Plaintext: {plaintext3}")
    print(f"2-Key (16-byte, hex): {binascii.hexlify(key_2).decode()}")
    
    ciphertext3, iv3 = triple_des_encrypt_cbc(plaintext3, key_2)
    print(f"Ciphertext (hex): {ciphertext3}")
    print(f"IV (hex): {iv3}")
    
    decrypted3 = triple_des_decrypt_cbc(ciphertext3, key_2, iv3)
    print(f"Decrypted: {decrypted3}")
