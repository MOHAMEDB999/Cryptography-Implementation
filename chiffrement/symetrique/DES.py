"""
DES (Data Encryption Standard) Implementation

Data Encryption Standard is a symmetric-key block cipher that was widely used
for encryption before being replaced by AES. It operates on 64-bit blocks using
a 56-bit key (with 8 parity bits making it 64 bits total).

Key Characteristics:
- Block size: 64 bits
- Key size: 56 bits (56-bit effective key)
- Number of rounds: 16
- Symmetric encryption (same key for encryption and decryption)
- Block cipher mode of operation

Security Note:
DES is considered cryptographically broken and should NOT be used for
protecting sensitive information. It is included here for educational purposes only.
Use AES or other modern algorithms for actual security needs.
"""

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii

def generate_des_key():
    """
    Generate a random 8-byte (64-bit) DES key.
    Note: DES uses 56 bits for the key and 8 bits for parity.
    
    Returns:
        bytes: 8-byte DES key
    """
    return get_random_bytes(8)

def des_encrypt(plaintext, key):
    """
    Encrypt plaintext using DES in ECB mode.
    
    Args:
        plaintext: Text to encrypt (string)
        key: 8-byte DES key (bytes)
    
    Returns:
        tuple: (ciphertext in hex, iv) for ECB mode, iv is empty
    """
    # Ensure plaintext is bytes
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Ensure key is correct length
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes long")
    
    # Create DES cipher in ECB mode
    cipher = DES.new(key, DES.MODE_ECB)
    
    # Pad plaintext to multiple of 8 bytes
    padded_plaintext = pad(plaintext, DES.block_size)
    
    # Encrypt
    ciphertext = cipher.encrypt(padded_plaintext)
    
    return binascii.hexlify(ciphertext).decode(), None

def des_decrypt(ciphertext_hex, key):
    """
    Decrypt ciphertext using DES in ECB mode.
    
    Args:
        ciphertext_hex: Hexadecimal encoded ciphertext (string)
        key: 8-byte DES key (bytes)
    
    Returns:
        str: Decrypted plaintext
    """
    # Convert from hex
    ciphertext = binascii.unhexlify(ciphertext_hex)
    
    # Ensure key is correct length
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes long")
    
    # Create DES cipher in ECB mode
    cipher = DES.new(key, DES.MODE_ECB)
    
    # Decrypt
    padded_plaintext = cipher.decrypt(ciphertext)
    
    # Unpad
    plaintext = unpad(padded_plaintext, DES.block_size)
    
    return plaintext.decode('utf-8')

def des_encrypt_cbc(plaintext, key):
    """
    Encrypt plaintext using DES in CBC mode (more secure than ECB).
    
    Args:
        plaintext: Text to encrypt (string)
        key: 8-byte DES key (bytes)
    
    Returns:
        tuple: (ciphertext in hex, iv in hex)
    """
    # Ensure plaintext is bytes
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Ensure key is correct length
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes long")
    
    # Generate random IV
    iv = get_random_bytes(DES.block_size)
    
    # Create DES cipher in CBC mode
    cipher = DES.new(key, DES.MODE_CBC, iv)
    
    # Pad plaintext
    padded_plaintext = pad(plaintext, DES.block_size)
    
    # Encrypt
    ciphertext = cipher.encrypt(padded_plaintext)
    
    return binascii.hexlify(ciphertext).decode(), binascii.hexlify(iv).decode()

def des_decrypt_cbc(ciphertext_hex, key, iv_hex):
    """
    Decrypt ciphertext using DES in CBC mode.
    
    Args:
        ciphertext_hex: Hexadecimal encoded ciphertext (string)
        key: 8-byte DES key (bytes)
        iv_hex: Hexadecimal encoded IV (string)
    
    Returns:
        str: Decrypted plaintext
    """
    # Convert from hex
    ciphertext = binascii.unhexlify(ciphertext_hex)
    iv = binascii.unhexlify(iv_hex)
    
    # Ensure key is correct length
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes long")
    
    # Create DES cipher in CBC mode
    cipher = DES.new(key, DES.MODE_CBC, iv)
    
    # Decrypt
    padded_plaintext = cipher.decrypt(ciphertext)
    
    # Unpad
    plaintext = unpad(padded_plaintext, DES.block_size)
    
    return plaintext.decode('utf-8')

if __name__ == "__main__":
    print("=" * 60)
    print("DES (Data Encryption Standard) Implementation")
    print("=" * 60)
    print("\n⚠️  WARNING: DES is cryptographically broken!")
    print("This implementation is for educational purposes only.\n")
    
    # Generate a key
    key = generate_des_key()
    print(f"Generated DES Key (hex): {binascii.hexlify(key).decode()}")
    
    # Example 1: ECB Mode
    plaintext1 = "Hello World DES"
    print(f"\n--- ECB Mode Example ---")
    print(f"Plaintext: {plaintext1}")
    
    ciphertext1, _ = des_encrypt(plaintext1, key)
    print(f"Ciphertext (hex): {ciphertext1}")
    
    decrypted1 = des_decrypt(ciphertext1, key)
    print(f"Decrypted: {decrypted1}")
    
    # Example 2: CBC Mode (more secure)
    plaintext2 = "Secure DES CBC Mode Encryption"
    print(f"\n--- CBC Mode Example (Recommended) ---")
    print(f"Plaintext: {plaintext2}")
    
    ciphertext2, iv2 = des_encrypt_cbc(plaintext2, key)
    print(f"Ciphertext (hex): {ciphertext2}")
    print(f"IV (hex): {iv2}")
    
    decrypted2 = des_decrypt_cbc(ciphertext2, key, iv2)
    print(f"Decrypted: {decrypted2}")
    
    # Example 3: Another example
    plaintext3 = "Data Encryption Standard"
    print(f"\n--- Another Example ---")
    print(f"Plaintext: {plaintext3}")
    
    ciphertext3, iv3 = des_encrypt_cbc(plaintext3, key)
    print(f"Ciphertext (hex): {ciphertext3}")
    print(f"IV (hex): {iv3}")
    
    decrypted3 = des_decrypt_cbc(ciphertext3, key, iv3)
    print(f"Decrypted: {decrypted3}")
