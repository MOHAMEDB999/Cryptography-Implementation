"""
Caesar Cipher Implementation

The Caesar cipher is one of the simplest and most widely known encryption techniques.
Each letter in the plaintext is shifted a certain number of places down the alphabet.

For example, with a shift of 1:
A -> B, B -> C, ..., Z -> A

Historically used by Julius Caesar for military communications.

Characteristics:
- Substitution cipher with fixed shift (key)
- Works only with letters, preserves case
- Can be broken by brute force (only 26 possible keys)
- Vulnerable to frequency analysis
"""

def caesar_encrypt(text, shift=3):
    """
    Encrypt text using Caesar cipher.
    
    Args:
        text: String to encrypt
        shift: Number of positions to shift (default: 3)
        
    Returns:
        Encrypted string with shifted letters
    """
    result = []
    
    for char in text:
        if char.isalpha():
            if char.isupper():
                # Shift uppercase letters
                shifted = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
                result.append(shifted)
            else:
                # Shift lowercase letters
                shifted = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
                result.append(shifted)
        else:
            # Keep non-alphabetic characters unchanged
            result.append(char)
    
    return ''.join(result)


def caesar_decrypt(ciphertext, shift=3):
    """
    Decrypt Caesar cipher by shifting backwards.
    
    Args:
        ciphertext: String to decrypt
        shift: Number of positions the text was shifted (default: 3)
        
    Returns:
        Decrypted string
    """
    return caesar_encrypt(ciphertext, -shift)


def caesar_brute_force(ciphertext):
    """
    Attempt to break Caesar cipher by trying all 26 possible shifts.
    
    Args:
        ciphertext: Encrypted string
        
    Returns:
        List of tuples (shift, decrypted_text) for all possibilities
    """
    results = []
    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        results.append((shift, decrypted))
    return results


if __name__ == "__main__":
    print("=" * 50)
    print("Caesar Cipher Implementation")
    print("=" * 50)
    
    # Example 1: Default shift of 3
    plaintext = "Hello World"
    shift_value = 3
    ciphertext = caesar_encrypt(plaintext, shift_value)
    decrypted = caesar_decrypt(ciphertext, shift_value)
    
    print(f"\nOriginal text (shift={shift_value}): {plaintext}")
    print(f"Encrypted: {ciphertext}")
    print(f"Decrypted: {decrypted}")
    
    # Example 2: Different shift
    plaintext2 = "Python Cryptography"
    shift_value2 = 5
    ciphertext2 = caesar_encrypt(plaintext2, shift_value2)
    
    print(f"\nOriginal text (shift={shift_value2}): {plaintext2}")
    print(f"Encrypted: {ciphertext2}")
    print(f"Decrypted: {caesar_decrypt(ciphertext2, shift_value2)}")
    
    # Example 3: Brute force attack
    print(f"\nBrute force test on: {ciphertext2}")
    print("First 5 attempts:")
    for shift, text in caesar_brute_force(ciphertext2)[:5]:
        print(f"  Shift {shift:2d}: {text}")
