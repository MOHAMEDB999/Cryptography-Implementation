"""
Blowfish Cipher Implementation

Blowfish is a symmetric block cipher designed by Bruce Schneier in 1993.
It is faster than DES and provides excellent encryption in a small amount of code.

Key Characteristics:
- Block size: 64 bits
- Key size: 32-448 bits (variable, commonly 128-256 bits)
- Number of rounds: 16
- Symmetric encryption (same key for encryption and decryption)
- Block cipher suitable for applications requiring fast encryption

Advantages:
- Small memory footprint (< 4 KB)
- Fast on 32-bit processors
- Variable key length for flexibility
- No known cryptanalytic attacks

Note:
Blowfish is becoming obsolete for new applications due to its small 64-bit block size.
Use AES or ChaCha20 for new cryptographic needs.
Blowfish is useful for password hashing (via bcrypt) and legacy systems.
"""

from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii

def generate_blowfish_key(key_size=16):
    """
    Generate a random Blowfish key.
    
    Args:
        key_size: Key size in bytes (4-56, default 16)
    
    Returns:
        bytes: Random Blowfish key
    """
    if key_size < 4 or key_size > 56:
        raise ValueError("Blowfish key size must be between 4 and 56 bytes")
    return get_random_bytes(key_size)

def blowfish_encrypt(plaintext, key):
    """
    Encrypt plaintext using Blowfish in ECB mode.
    
    Args:
        plaintext: Text to encrypt (string)
        key: Blowfish key (4-56 bytes)
    
    Returns:
        str: Ciphertext in hexadecimal format
    """
    # Ensure plaintext is bytes
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Validate key length
    if len(key) < 4 or len(key) > 56:
        raise ValueError("Blowfish key must be 4-56 bytes long")
    
    # Create Blowfish cipher in ECB mode
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    
    # Pad plaintext to 8-byte boundary
    padded_plaintext = pad(plaintext, Blowfish.block_size)
    
    # Encrypt
    ciphertext = cipher.encrypt(padded_plaintext)
    
    return binascii.hexlify(ciphertext).decode()

def blowfish_decrypt(ciphertext_hex, key):
    """
    Decrypt ciphertext using Blowfish in ECB mode.
    
    Args:
        ciphertext_hex: Hexadecimal encoded ciphertext (string)
        key: Blowfish key (4-56 bytes)
    
    Returns:
        str: Decrypted plaintext
    """
    # Convert from hex
    ciphertext = binascii.unhexlify(ciphertext_hex)
    
    # Validate key length
    if len(key) < 4 or len(key) > 56:
        raise ValueError("Blowfish key must be 4-56 bytes long")
    
    # Create Blowfish cipher in ECB mode
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    
    # Decrypt
    padded_plaintext = cipher.decrypt(ciphertext)
    
    # Unpad
    plaintext = unpad(padded_plaintext, Blowfish.block_size)
    
    return plaintext.decode('utf-8')

def blowfish_encrypt_cbc(plaintext, key):
    """
    Encrypt plaintext using Blowfish in CBC mode (more secure).
    
    Args:
        plaintext: Text to encrypt (string)
        key: Blowfish key (4-56 bytes)
    
    Returns:
        tuple: (ciphertext in hex, iv in hex)
    """
    # Ensure plaintext is bytes
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Validate key length
    if len(key) < 4 or len(key) > 56:
        raise ValueError("Blowfish key must be 4-56 bytes long")
    
    # Generate random IV
    iv = get_random_bytes(Blowfish.block_size)
    
    # Create Blowfish cipher in CBC mode
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    
    # Pad plaintext
    padded_plaintext = pad(plaintext, Blowfish.block_size)
    
    # Encrypt
    ciphertext = cipher.encrypt(padded_plaintext)
    
    return binascii.hexlify(ciphertext).decode(), binascii.hexlify(iv).decode()

def blowfish_decrypt_cbc(ciphertext_hex, key, iv_hex):
    """
    Decrypt ciphertext using Blowfish in CBC mode.
    
    Args:
        ciphertext_hex: Hexadecimal encoded ciphertext (string)
        key: Blowfish key (4-56 bytes)
        iv_hex: Hexadecimal encoded IV (string)
    
    Returns:
        str: Decrypted plaintext
    """
    # Convert from hex
    ciphertext = binascii.unhexlify(ciphertext_hex)
    iv = binascii.unhexlify(iv_hex)
    
    # Validate key length
    if len(key) < 4 or len(key) > 56:
        raise ValueError("Blowfish key must be 4-56 bytes long")
    
    # Create Blowfish cipher in CBC mode
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    
    # Decrypt
    padded_plaintext = cipher.decrypt(ciphertext)
    
    # Unpad
    plaintext = unpad(padded_plaintext, Blowfish.block_size)
    
    return plaintext.decode('utf-8')

if __name__ == "__main__":
    print("=" * 60)
    print("Blowfish Cipher Implementation")
    print("=" * 60)
    print("\nBlowfish: Fast, compact, and well-tested cipher.\n")
    
    # Generate a 128-bit (16-byte) key
    key = generate_blowfish_key(16)
    print(f"Generated Blowfish Key (16-byte, hex): {binascii.hexlify(key).decode()}")
    
    # Example 1: ECB Mode
    plaintext1 = "Hello Blowfish!"
    print(f"\n--- ECB Mode Example ---")
    print(f"Plaintext: {plaintext1}")
    
    ciphertext1 = blowfish_encrypt(plaintext1, key)
    print(f"Ciphertext (hex): {ciphertext1}")
    
    decrypted1 = blowfish_decrypt(ciphertext1, key)
    print(f"Decrypted: {decrypted1}")
    
    # Example 2: CBC Mode
    plaintext2 = "Blowfish CBC Mode Encryption Example"
    print(f"\n--- CBC Mode Example (Recommended) ---")
    print(f"Plaintext: {plaintext2}")
    
    ciphertext2, iv2 = blowfish_encrypt_cbc(plaintext2, key)
    print(f"Ciphertext (hex): {ciphertext2}")
    print(f"IV (hex): {iv2}")
    
    decrypted2 = blowfish_decrypt_cbc(ciphertext2, key, iv2)
    print(f"Decrypted: {decrypted2}")
    
    # Example 3: Using different key size
    key_32 = generate_blowfish_key(32)
    plaintext3 = "Blowfish with 256-bit key"
    print(f"\n--- Using 256-bit (32-byte) Key ---")
    print(f"Plaintext: {plaintext3}")
    print(f"Key (hex): {binascii.hexlify(key_32).decode()}")
    
    ciphertext3, iv3 = blowfish_encrypt_cbc(plaintext3, key_32)
    print(f"Ciphertext (hex): {ciphertext3}")
    print(f"IV (hex): {iv3}")
    
    decrypted3 = blowfish_decrypt_cbc(ciphertext3, key_32, iv3)
    print(f"Decrypted: {decrypted3}")
