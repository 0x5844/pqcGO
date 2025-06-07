[![go build](https://github.com/0x5844/pqcGO/actions/workflows/go.yml/badge.svg)](https://github.com/0x5844/pqcGO/actions)
[![GitHub Tag](https://img.shields.io/github/v/tag/0x5844/pqcGO)](https://github.com/0x5844/pqcGO/releases)



# 🔒 Go-PQC-Stream: Post-Quantum File Encryption Tool

A high-performance command-line tool for secure file encryption using a hybrid post-quantum and classical cryptographic scheme. It is optimized for large files with a parallel streaming pipeline.

## Features

- **Hybrid Encryption**: Combines post-quantum **ML-KEM (Kyber)** with classical **X25519** for robust, forward-secure key exchange.
- **High-Speed Stream Cipher**: Uses **XChaCha20** for fast bulk data encryption.
- **Strong Integrity**: Implements **HMAC-BLAKE2s** for authenticated encryption. Each file is protected with a unique, randomly generated salt for the HMAC key derivation, enhancing security.
- **Optimized for Performance**: Utilizes a multi-threaded parallel pipeline and memory pooling to maximize throughput on multi-core systems, ideal for encrypting and decrypting large files.
- **Selectable Security Levels**: Supports NIST security levels 1 (128-bit), 3 (192-bit), and 5 (256-bit).

## Installation

1.  **Clone the repository:**
    ```
    git clone https://github.com/0x5844/pqcGO
    cd pqcGO
    ```

2.  **Install dependencies and build:**
    ```
    go mod tidy
    go build
    ```
    This will create an executable named `main` (or `main.exe` on Windows).

## Usage

### 1. Generate a Key Pair

Create a new hybrid public/private key pair.

```./main -generate -keyname my_keys -level 192```

This command generates `my_keys.pub` (public key) and `my_keys.key` (private key) for 192-bit security.

### 2. Encrypt a File

Encrypt a file using the recipient's public key.

```./main -encrypt document.txt -pubkey my_keys.pub -output document.enc```

This encrypts `document.txt` and saves it as `document.enc`.

### 3. Decrypt a File

Decrypt the file using your private key.

```./main -decrypt document.enc -privkey my_keys.key -output document.txt```

This decrypts `document.enc` and restores the original `document.txt`. The tool automatically verifies the file's integrity.

### 4. Run Benchmark

Run a stress test to measure performance across different file sizes and security levels.

```./main -benchmark```

text

### Command-Line Flags

- benchmark Run performance benchmark and stress test
- decrypt string File to decrypt
- encrypt string File to encrypt
- generate Generate new hybrid key pair
- help Show help message
- keyname string Base name for key files (default "quantum")
- level string Security level: 128, 192, or 256 bits (default "192")
- mlkem Use Go 1.24 ML-KEM (vs legacy Kyber) (default true)
- output string Output file (auto-generated if not specified)
- privkey string Private key file for decryption
- pubkey string Public key file for encryption
## Cryptographic Design

- **Key Encapsulation**: A shared secret is derived using HKDF-BLAKE2s on the outputs of three key exchanges: ML-KEM, Kyber (as a fallback), and X25519. This creates the final key for the ChaCha20 stream cipher.
- **Authenticated Encryption**: File integrity is ensured by an HMAC-BLAKE2s tag. The HMAC key is derived from the main encryption key and a unique 32-byte random salt, which is generated for each encryption and appended to the file.
- **File Format**: `[Header | Ciphertext | HMAC | HMAC_Salt]`
