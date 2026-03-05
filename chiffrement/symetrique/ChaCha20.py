"""
ChaCha20 Cipher Implementation

ChaCha20 is a modern stream cipher designed by Daniel J. Bernstein.
It is a variant of Salsa20 and is widely used in modern cryptography.

Key Characteristics:
- Stream cipher (not a block cipher)
- Key size: 256 bits (32 bytes)
- Nonce size: 96 bits (12 bytes) or 64 bits (8 bytes)
- Fast in software implementation
- Immune to timing attacks
- No known cryptanalytic attacks

Advantages:
- Fast and secure
- Good performance across different platforms
- Used by TLS 1.3, OpenVPN, Wireguard
- Provides authenticated encryption when used with Poly1305
- Simple design with good security properties

Applications:
- TLS/SSL connections
- VPN protocols
- Messaging applications
- Secure communication channels
"""

from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import binascii

def generate_chacha20_key():
    """
    Generate a random 256-bit (32-byte) ChaCha20 key.
    
    Returns:
        bytes: 32-byte ChaCha20 key
    """
    return get_random_bytes(32)

def generate_chacha20_nonce():
    """
    Generate a random 96-bit (12-byte) ChaCha20 nonce.
    Note: In ChaCha20, it's critical that each (key, nonce) pair is unique.
    
    Returns:
        bytes: 12-byte ChaCha20 nonce
    """
    return get_random_bytes(12)

def chacha20_encrypt(plaintext, key, nonce=None):
    """
    Encrypt plaintext using ChaCha20.
    
    Args:
        plaintext: Text to encrypt (string)
        key: 32-byte ChaCha20 key (bytes)
        nonce: 12-byte nonce (optional, generates random if None)
    
    Returns:
        tuple: (ciphertext in hex, nonce in hex)
    """
    # Ensure plaintext is bytes
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Validate key length
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes long")
    
    # Generate nonce if not provided
    if nonce is None:
        nonce = generate_chacha20_nonce()
    
    # Validate nonce length
    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce must be 12 bytes long")
    
    # Create ChaCha20 cipher
    cipher = ChaCha20.new(key=key, nonce=nonce)
    
    # Encrypt (no padding needed for stream ciphers)
    ciphertext = cipher.encrypt(plaintext)
    
    return binascii.hexlify(ciphertext).decode(), binascii.hexlify(nonce).decode()

def chacha20_decrypt(ciphertext_hex, key, nonce_hex):
    """
    Decrypt ciphertext using ChaCha20.
    
    Args:
        ciphertext_hex: Hexadecimal encoded ciphertext (string)
        key: 32-byte ChaCha20 key (bytes)
        nonce_hex: Hexadecimal encoded nonce (string)
    
    Returns:
        str: Decrypted plaintext
    """
    # Convert from hex
    ciphertext = binascii.unhexlify(ciphertext_hex)
    nonce = binascii.unhexlify(nonce_hex)
    
    # Validate key length
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes long")
    
    # Validate nonce length
    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce must be 12 bytes long")
    
    # Create ChaCha20 cipher
    cipher = ChaCha20.new(key=key, nonce=nonce)
    
    # Decrypt (stream cipher, same operation as encryption)
    plaintext = cipher.decrypt(ciphertext)
    
    return plaintext.decode('utf-8')

def chacha20_poly1305_encrypt(plaintext, key, nonce=None):
    """
    Encrypt and authenticate plaintext using ChaCha20-Poly1305 (AEAD).
    
    Args:
        plaintext: Text to encrypt (string)
        key: 32-byte key (bytes)
        nonce: 12-byte nonce (optional, generates random if None)
    
    Returns:
        tuple: (ciphertext in hex, nonce in hex, tag in hex)
    """
    # Ensure plaintext is bytes
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Validate key length
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes long")
    
    # Generate nonce if not provided
    if nonce is None:
        nonce = generate_chacha20_nonce()
    
    # Validate nonce length
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes long")
    
    # Create ChaCha20-Poly1305 cipher
    cipher = ChaCha20.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    return binascii.hexlify(ciphertext).decode(), binascii.hexlify(nonce).decode(), binascii.hexlify(tag).decode()

def chacha20_poly1305_decrypt(ciphertext_hex, key, nonce_hex, tag_hex):
    """
    Decrypt and verify ciphertext using ChaCha20-Poly1305 (AEAD).
    
    Args:
        ciphertext_hex: Hexadecimal encoded ciphertext (string)
        key: 32-byte key (bytes)
        nonce_hex: Hexadecimal encoded nonce (string)
        tag_hex: Hexadecimal encoded authentication tag (string)
    
    Returns:
        str: Decrypted and authenticated plaintext
    
    Raises:
        ValueError: If authentication fails
    """
    # Convert from hex
    ciphertext = binascii.unhexlify(ciphertext_hex)
    nonce = binascii.unhexlify(nonce_hex)
    tag = binascii.unhexlify(tag_hex)
    
    # Validate key length
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes long")
    
    # Validate nonce length
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes long")
    
    # Create ChaCha20-Poly1305 cipher
    cipher = ChaCha20.new(key=key, nonce=nonce)
    
    # Decrypt and verify
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    
    return plaintext.decode('utf-8')

if __name__ == "__main__":
    print("=" * 60)
    print("ChaCha20 Stream Cipher Implementation")
    print("=" * 60)
    print("\nChaCha20: Modern, fast, and secure stream cipher.\n")
    
    # Generate key and nonce
    key = generate_chacha20_key()
    print(f"Generated ChaCha20 Key (32-byte, hex): {binascii.hexlify(key).decode()}")
    
    # Example 1: Basic encryption
    plaintext1 = "Hello ChaCha20!"
    print(f"\n--- Basic ChaCha20 Encryption ---")
    print(f"Plaintext: {plaintext1}")
    
    ciphertext1, nonce1 = chacha20_encrypt(plaintext1, key)
    print(f"Ciphertext (hex): {ciphertext1}")
    print(f"Nonce (hex): {nonce1}")
    
    decrypted1 = chacha20_decrypt(ciphertext1, key, nonce1)
    print(f"Decrypted: {decrypted1}")
    
    # Example 2: Longer message
    plaintext2 = "ChaCha20 is a stream cipher that provides fast and secure encryption."
    print(f"\n--- Longer Message ---")
    print(f"Plaintext: {plaintext2}")
    
    ciphertext2, nonce2 = chacha20_encrypt(plaintext2, key)
    print(f"Ciphertext (hex): {ciphertext2}")
    print(f"Nonce (hex): {nonce2}")
    
    decrypted2 = chacha20_decrypt(ciphertext2, key, nonce2)
    print(f"Decrypted: {decrypted2}")
    
    # Example 3: ChaCha20-Poly1305 (Authenticated Encryption)
    plaintext3 = "Authenticated encryption with ChaCha20-Poly1305"
    print(f"\n--- ChaCha20-Poly1305 (AEAD) Example ---")
    print(f"Plaintext: {plaintext3}")
    
    ciphertext3, nonce3, tag3 = chacha20_poly1305_encrypt(plaintext3, key)
    print(f"Ciphertext (hex): {ciphertext3}")
    print(f"Nonce (hex): {nonce3}")
    print(f"Authentication Tag (hex): {tag3}")
    
    decrypted3 = chacha20_poly1305_decrypt(ciphertext3, key, nonce3, tag3)
    print(f"Decrypted and Verified: {decrypted3}")
    
    # Example 4: Attempting tampering detection
    print(f"\n--- Tampering Detection ---")
    print("Attempting to decrypt with wrong tag...")
    wrong_tag = binascii.hexlify(get_random_bytes(16)).decode()
    try:
        chacha20_poly1305_decrypt(ciphertext3, key, nonce3, wrong_tag)
        print("ERROR: Tampering not detected!")
    except ValueError as e:
        print(f"✓ Tampering detected: {type(e).__name__}")
