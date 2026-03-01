"""
Columnar Transposition Cipher Implementation

A transposition cipher that arranges the plaintext in rows under a keyword,
then reads off the columns in the order determined by the alphabetical order
of the keyword letters.

Example with keyword 'KEYWORD':
  K E Y W O R D
  1 2 3 4 5 6 7
  
Arrange plaintext "SECRETMESSAGE" in matrix:
  K E Y W O R D
  S E C R E T M
  E S S A G E (padding if needed)

Then read columns in alphabetical order of keyword.

Characteristics:
- Transposition cipher (rearranges characters)
- Key-dependent (keyword determines column order)
- More complex than Rail Fence
- Matrix-based implementation
"""

def get_column_order(keyword):
    """
    Get the column order based on the keyword.
    Assigns numbers 1, 2, 3... based on alphabetical order.
    
    Args:
        keyword: The encryption keyword
    
    Returns:
        List of column indices in alphabetical order
    """
    # Create list of (letter, index) tuples
    indexed_keyword = [(letter, index) for index, letter in enumerate(keyword.upper())]
    
    # Sort by letter (alphabetical order)
    sorted_keyword = sorted(indexed_keyword, key=lambda x: x[0])
    
    # Return the original indices in sorted order
    column_order = [index for letter, index in sorted_keyword]
    return column_order

def columnar_transposition_encrypt(plaintext, keyword):
    """
    Encrypt text using columnar transposition cipher.
    
    Args:
        plaintext: Text to encrypt
        keyword: Keyword that determines column order
    
    Returns:
        Encrypted text
    """
    keyword = keyword.upper()
    num_columns = len(keyword)
    
    # Remove spaces and convert to uppercase
    plaintext = plaintext.upper().replace(' ', '')
    
    # Pad plaintext if necessary
    num_rows = (len(plaintext) + num_columns - 1) // num_columns
    plaintext = plaintext.ljust(num_rows * num_columns, 'X')
    
    # Create matrix
    matrix = []
    for i in range(num_rows):
        row = plaintext[i * num_columns:(i + 1) * num_columns]
        matrix.append(list(row))
    
    # Get column order
    column_order = get_column_order(keyword)
    
    # Read columns in alphabetical order
    ciphertext = ''
    for col_index in column_order:
        for row in matrix:
            ciphertext += row[col_index]
    
    return ciphertext

def columnar_transposition_decrypt(ciphertext, keyword):
    """
    Decrypt columnar transposition cipher.
    
    Args:
        ciphertext: Text to decrypt
        keyword: Keyword used for encryption
    
    Returns:
        Decrypted text
    """
    keyword = keyword.upper()
    num_columns = len(keyword)
    num_rows = len(ciphertext) // num_columns
    
    # Get column order
    column_order = get_column_order(keyword)
    
    # Create a matrix to hold the ciphertext characters
    matrix = [[''] * num_columns for _ in range(num_rows)]
    
    # Fill the matrix column by column in alphabetical order
    cipher_index = 0
    for col_index in column_order:
        for row in range(num_rows):
            matrix[row][col_index] = ciphertext[cipher_index]
            cipher_index += 1
    
    # Read row by row
    plaintext = ''
    for row in matrix:
        plaintext += ''.join(row)
    
    return plaintext

def print_matrix(matrix, keyword=None):
    """
    Print the encryption matrix in a readable format.
    
    Args:
        matrix: The 2D matrix
        keyword: Optional keyword to display above matrix
    """
    if keyword:
        print(f"\nKeyword: {keyword.upper()}")
        column_order = get_column_order(keyword)
        print(f"Column Order: {column_order}")
        print("-" * (len(keyword) * 3))
    
    for row in matrix:
        print(' '.join(row))
    print()

if __name__ == "__main__":
    print("=" * 60)
    print("Columnar Transposition Cipher Implementation")
    print("=" * 60)
    
    # Example 1: Basic example
    keyword1 = "KEYWORD"
    plaintext1 = "SECRETMESSAGEFORENCRYPTION"
    
    ciphertext1 = columnar_transposition_encrypt(plaintext1, keyword1)
    decrypted1 = columnar_transposition_decrypt(ciphertext1, keyword1)
    
    print(f"\nExample 1: Using keyword '{keyword1}'")
    print(f"Plaintext: {plaintext1}")
    print(f"Ciphertext: {ciphertext1}")
    print(f"Decrypted: {decrypted1}")
    
    # Example 2: Another keyword
    keyword2 = "CIPHER"
    plaintext2 = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
    
    ciphertext2 = columnar_transposition_encrypt(plaintext2, keyword2)
    decrypted2 = columnar_transposition_decrypt(ciphertext2, keyword2)
    
    print(f"\nExample 2: Using keyword '{keyword2}'")
    print(f"Plaintext: {plaintext2}")
    print(f"Ciphertext: {ciphertext2}")
    print(f"Decrypted: {decrypted2}")
    
    # Example 3: Shorter plaintext
    keyword3 = "SECRET"
    plaintext3 = "HELLO WORLD EXAMPLE"
    
    ciphertext3 = columnar_transposition_encrypt(plaintext3, keyword3)
    decrypted3 = columnar_transposition_decrypt(ciphertext3, keyword3)
    
    print(f"\nExample 3: Using keyword '{keyword3}'")
    print(f"Plaintext: {plaintext3}")
    print(f"Ciphertext: {ciphertext3}")
    print(f"Decrypted: {decrypted3}")
    
    # Show matrix structure for understanding
    print(f"\n--- Matrix Structure for Example 3 ---")
    keyword = keyword3.upper()
    plaintext = plaintext3.upper().replace(' ', '')
    num_columns = len(keyword)
    num_rows = (len(plaintext) + num_columns - 1) // num_columns
    plaintext = plaintext.ljust(num_rows * num_columns, 'X')
    
    matrix = []
    for i in range(num_rows):
        row = plaintext[i * num_columns:(i + 1) * num_columns]
        matrix.append(list(row))
    
    print_matrix(matrix, keyword3)
