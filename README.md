# Cryptography-Implementation

## Cryptography Methods Implementation

A comprehensive Python implementation of classical and modern cryptographic algorithms for educational and research purposes.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Implemented Algorithms](#implemented-algorithms)
- [Project Structure](#project-structure)
- [Educational Resources](#educational-resources)
- [Security Notice](#security-notice)
- [License](#license)

## 🔒 Overview

This project provides a complete implementation of various cryptographic methods, ranging from classical ciphers to modern encryption standards. It serves as both an educational resource and a practical toolkit for understanding cryptographic principles.

## ✨ Features

- **Classical Ciphers**: Historical encryption methods
- **Modern Symmetric Encryption**: Industry-standard algorithms
- **Asymmetric Encryption**: Public-key cryptography
- **Hash Functions**: Secure message digesting
- **Digital Signatures**: Authentication and non-repudiation
- **Interactive Menu**: Easy-to-use command-line interface
- **Educational Examples**: Clear demonstrations of each algorithm

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Required Dependencies

```bash
pip install cryptography numpy rich
```

### Optional Dependencies

```bash
pip install pycryptodome  # For additional cryptographic functions
```

## 💻 Usage

### Running Individual Implementations

```bash
# Run RSA encryption/decryption
python chiffrement/asymetrique/RSA.py

# Run AES implementation
python chiffrement/symetrique/AES.py

# Run SHA-256 hashing
python hachage/SHA_256.py

# Run DSA digital signatures
python signature/dsa.py
```

### Using the Menu Systems

```bash
# Run symmetric encryption menu
python chiffrement/symetrique/main.py

# Run signature schemes menu
python signature/main.py
```

## 🔐 Implemented Algorithms

### Asymmetric Encryption

- **RSA** - Complete implementation with key generation, encryption, and decryption
- **Diffie-Hellman Key Exchange** - Secure key agreement protocol
- **AES** - Advanced Encryption Standard with multiple key sizes (128, 192, 256-bit)

### Hash Functions

- **SHA-256** - Secure Hash Algorithm (256-bit)
- **RIPEMD-160** - Alternative hash function implementation

### Digital Signatures

- **DSA** - Digital Signature Algorithm (NIST standard)
- **ElGamal Signatures** - Discrete logarithm based signatures
- **RSA Signatures** - RSA-based digital signatures

### Advanced Schemes

- **Paillier Homomorphic Encryption** - Privacy-preserving computation
- **Shamir's Secret Sharing** - Threshold cryptography
- **Combined Cryptographic Systems** - Integrated multi-algorithm solutions

## 📁 Project Structure

```
cryptography-implementation/
├── README.md
├── LICENSE
├── requirements.txt
├── chiffrement/
│   ├── asymetrique/
│   │   ├── RSA.py
│   │   ├── AES.py
│   │   └── Diffie-Hellman.py
│   └── symetrique/
│       └── main.py
├── hachage/
│   ├── SHA_256.py
│   └── RIPEMD_160.py
└── signature/
    ├── dsa.py
    ├── elgamal_signature.py
    ├── rsa_signature.py
    ├── paillier_he.py
    ├── shamir_sss.py
    └── main.py
```

## 📚 Educational Resources

Each implementation includes:

- Detailed comments explaining the algorithm
- Mathematical foundations and formulas
- Security analysis and known vulnerabilities
- Historical context and practical applications
- Performance benchmarks and complexity analysis

## ⚠️ Security Notice

This implementation is for **educational purposes only**. While the algorithms are correctly implemented, they may not include all security measures required for production use. For real-world applications, use established cryptographic libraries like `cryptography`, `PyCryptodome`, or `OpenSSL`.

## 📖 Additional Features

- Multiple cryptographic algorithm implementations
- Test files for verification and learning
- Interactive menu-driven interfaces
- Clear documentation and usage examples
- Support for various key sizes and parameters

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Add new cryptographic algorithms
- Improve existing implementations
- Add more comprehensive tests
- Enhance documentation
- Fix bugs and security issues

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Note**: This repository is maintained as an educational resource. Always verify implementations with standards and security audits before using in any critical application.
