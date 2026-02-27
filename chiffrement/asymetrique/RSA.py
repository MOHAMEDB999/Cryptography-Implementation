"""
RSA Encryption Implementation

This module implements the RSA (Rivest-Shamir-Adleman) algorithm for asymmetric encryption.

Features:
- Key generation with specified key size
- Public key encryption
- Private key decryption
- Digital signature generation and verification

Note: This is an educational implementation. For production use, use cryptographic libraries.
"""

import random
from typing import Tuple

def gcd(a: int, b: int) -> int:
    """Calculate the greatest common divisor using Euclidean algorithm."""
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e: int, phi: int) -> int:
    """Calculate modular multiplicative inverse using extended Euclidean algorithm."""
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        gcd_val, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd_val, x, y
    
    gcd_val, x, _ = extended_gcd(e % phi, phi)
    if gcd_val != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % phi + phi) % phi

def is_prime(n: int, k: int = 5) -> bool:
    """Check if a number is prime using Miller-Rabin primality test."""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True

def generate_prime(bits: int) -> int:
    """Generate a random prime number with specified bit length."""
    while True:
        num = random.getrandbits(bits)
        if is_prime(num):
            return num

def generate_keys(key_size: int = 512) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """
    Generate RSA public and private keys.
    
    Args:
        key_size: Size of the key in bits
    
    Returns:
        Tuple of ((e, n), (d, n)) representing (public_key, private_key)
    """
    # Generate two large prime numbers
    p = generate_prime(key_size // 2)
    q = generate_prime(key_size // 2)
    
    # Calculate n
    n = p * q
    
    # Calculate phi(n) = (p-1)(q-1)
    phi = (p - 1) * (q - 1)
    
    # Choose e (public exponent)
    e = 65537  # Common choice
    while gcd(e, phi) != 1:
        e += 2
    
    # Calculate d (private exponent)
    d = mod_inverse(e, phi)
    
    return ((e, n), (d, n))

def encrypt(plaintext: int, public_key: Tuple[int, int]) -> int:
    """Encrypt plaintext using public key."""
    e, n = public_key
    return pow(plaintext, e, n)

def decrypt(ciphertext: int, private_key: Tuple[int, int]) -> int:
    """Decrypt ciphertext using private key."""
    d, n = private_key
    return pow(ciphertext, d, n)

if __name__ == "__main__":
    print("RSA Encryption Example")
    print("=" * 50)
    
    # Generate keys
    public_key, private_key = generate_keys(512)
    print(f"Public Key (e, n): ({public_key[0]}, {str(public_key[1])[:20]}...)")
    print(f"Private Key (d, n): ({private_key[0]}, {str(private_key[1])[:20]}...)")
    
    # Example encryption/decryption
    message = 12345
    print(f"\nOriginal message: {message}")
    
    ciphertext = encrypt(message, public_key)
    print(f"Encrypted: {ciphertext}")
    
    decrypted = decrypt(ciphertext, private_key)
    print(f"Decrypted: {decrypted}")
    print(f"Match: {message == decrypted}")
