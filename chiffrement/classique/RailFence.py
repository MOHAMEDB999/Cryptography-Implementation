"""
Rail Fence Cipher Implementation

A transposition cipher that writes the plaintext in a zigzag pattern
across multiple "rails" and then reads off each rail.

Example with 3 rails and plaintext 'HELLOWORLDEXAMPLE':
  H . . . O . . . R . . . E . . .
  . E . L . W . R . D . X . M . L .
  . . L . . . O . . . L . . . P . .

Then reads: HOREELMWRDXMLLLOWDXMPLELLOWRDX (combining all rails in order)

Characteristics:
- Transposition cipher (rearranges characters)
- Simple but secure for educational purposes
- Number of rails affects the encryption
- Vulnerable to brute force (limited number of possible rail values)
"""

def rail_fence_encrypt(plaintext, num_rails):
    """
    Encrypt text using Rail Fence cipher.
    
    Args:
        plaintext: Text to encrypt
        num_rails: Number of rails (2-10 typical)
    
    Returns:
        Encrypted text
    """
    if num_rails <= 1:
        return plaintext
    
    # Create rails
    rails = [[] for _ in range(num_rails)]
    rail = 0
    direction = 1  # 1 for down, -1 for up
    
    # Fill rails with characters
    for char in plaintext:
        rails[rail].append(char)
        
        # Change direction at the top and bottom
        if rail == 0:
            direction = 1
        elif rail == num_rails - 1:
            direction = -1
        
        rail += direction
    
    # Concatenate all rails
    result = ''.join(''.join(rail) for rail in rails)
    return result

def rail_fence_decrypt(ciphertext, num_rails):
    """
    Decrypt Rail Fence cipher.
    
    Args:
        ciphertext: Text to decrypt
        num_rails: Number of rails used for encryption
    
    Returns:
        Decrypted text
    """
    if num_rails <= 1:
        return ciphertext
    
    # Calculate the length of each rail
    rail_lengths = [0] * num_rails
    rail = 0
    direction = 1
    
    for _ in ciphertext:
        rail_lengths[rail] += 1
        
        if rail == 0:
            direction = 1
        elif rail == num_rails - 1:
            direction = -1
        
        rail += direction
    
    # Create rails with appropriate lengths
    rails = [[] for _ in range(num_rails)]
    start = 0
    
    for i in range(num_rails):
        rails[i] = list(ciphertext[start:start + rail_lengths[i]])
        start += rail_lengths[i]
    
    # Reconstruct plaintext
    result = []
    rail_indices = [0] * num_rails
    rail = 0
    direction = 1
    
    for _ in ciphertext:
        result.append(rails[rail][rail_indices[rail]])
        rail_indices[rail] += 1
        
        if rail == 0:
            direction = 1
        elif rail == num_rails - 1:
            direction = -1
        
        rail += direction
    
    return ''.join(result)

if __name__ == "__main__":
    print("=" * 50)
    print("Rail Fence Cipher Implementation")
    print("=" * 50)
    
    # Example 1
    plaintext = "HELLOWORLDEXAMPLE"
    num_rails = 3
    
    ciphertext = rail_fence_encrypt(plaintext, num_rails)
    decrypted = rail_fence_decrypt(ciphertext, num_rails)
    
    print(f"\nPlaintext: {plaintext}")
    print(f"Number of Rails: {num_rails}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted: {decrypted}")
    
    # Example 2
    text2 = "CRYPTOGRAPHY"
    rails2 = 4
    
    enc2 = rail_fence_encrypt(text2, rails2)
    dec2 = rail_fence_decrypt(enc2, rails2)
    
    print(f"\nPlaintext: {text2}")
    print(f"Number of Rails: {rails2}")
    print(f"Ciphertext: {enc2}")
    print(f"Decrypted: {dec2}")
    
    # Example 3 - with different rails
    text3 = "THERANGEOFFIERCEPEOPLE"
    rails3 = 5
    
    enc3 = rail_fence_encrypt(text3, rails3)
    dec3 = rail_fence_decrypt(enc3, rails3)
    
    print(f"\nPlaintext: {text3}")
    print(f"Number of Rails: {rails3}")
    print(f"Ciphertext: {enc3}")
    print(f"Decrypted: {dec3}")
