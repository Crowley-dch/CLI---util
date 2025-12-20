# CryptoCore User Guide

## Table of Contents
1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [File Encryption & Decryption](#file-encryption--decryption)
4. [Hash Functions](#hash-functions)
5. [Message Authentication Codes (MAC)](#message-authentication-codes-mac)
6. [Authenticated Encryption](#authenticated-encryption)
7. [Key Derivation](#key-derivation)
8. [Key Generation](#key-generation)
9. [Troubleshooting](#troubleshooting)
10. [Security Best Practices](#security-best-practices)

## Installation

### Prerequisites
- Linux/Unix operating system
- GCC compiler (version 7.0 or higher)
- OpenSSL development libraries
- Make build system

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install build-essential libssl-dev
```
### Build from Source
``` bash
git clone <https://github.com/Crowley-dch/CLI---util.git>
cd CLI---util
```

make

### Verify Installation 
```bash
./CLI---util --version
./CLI---util --help
```
### Quick Start
### Encrypt a File
```bash
./cryptocore --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input document.txt --output document.enc
```
### Decrypt a File
```bash
./cryptocore --algorithm aes --mode cbc --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input document.enc --output document.txt
```
### Compute File Hash
```bash
./cryptocore dgst --algorithm sha256 --input document.txt
```
## File Encryption & Decryption
### Available Algorithms & Modes
- Algorithm: aes (AES-128)

- Modes: ecb, cbc, cfb, ofb, ctr, gcm

### Basic Encryption
```bash
./cryptocore --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input plaintext.txt --output ciphertext.bin

./cryptocore --algorithm aes --mode cbc --encrypt \
  --input plaintext.txt
# Output: Generated random key: 1a2b3c4d5e6f7890fedcba9876543210
```
## Basic Decryption
```bash
./cryptocore --algorithm aes --mode cbc --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input ciphertext.bin --output decrypted.txt

./cryptocore --algorithm aes --mode cbc --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --iv aabbccddeeff00112233445566778899 \
  --input ciphertext.bin --output decrypted.txt
```
## Hash Functions
### Compute File Hash
```bash
./cryptocore dgst --algorithm sha256 --input file.txt

./cryptocore dgst --algorithm blake2b --input file.txt

./cryptocore dgst --algorithm blake2b --input file.txt --length 32

./cryptocore dgst --algorithm sha256 --input file.txt --output hash.txt
```
### Hash Format
Output format matches standard *sum tools:

``` text
ba7816bf8f61cfea41414d6e5dae2223bb80361396177a9cb410ff61720
015ad file.txt
```
Verify Hash
```bash
./cryptocore dgst --algorithm sha256 --input file.txt > computed_hash.txt
sha256sum file.txt > expected_hash.txt
diff computed_hash.txt expected_hash.txt

sha256sum -c expected_hash.txt
```
## Message Authentication Codes (MAC)
### Generate HMAC
```bash
./cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input message.txt

echo -n "mysecretkey" > keyfile.txt
./cryptocore dgst --algorithm sha256 --hmac \
  --key $(cat keyfile.txt | xxd -p) \
  --input data.bin

# Save HMAC to file
./cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input important.doc --output hmac.txt
```

### Verify HMAC
```bash
./cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input message.txt --verify expected_hmac.txt


./cryptocore dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input message.txt > computed_hmac.txt
diff computed_hmac.txt expected_hmac.txt
```
## HMAC File Format
### HMAC files should contain:

```text
a1b2c3d4e5f6012345678901234567890123456789012345678901234567890123 message.txt
```

## Authenticated Encryption
### GCM Mode Encryption
```bash
./cryptocore --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input database.sql --output database.enc \
  --aad "database_version_3.2"

./cryptocore --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input secret.txt --output secret.enc
``` 
### GCM Mode Decryption
```bash
./cryptocore --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input database.enc --output database_decrypted.sql \
  --aad "database_version_3.2"
# Output: [SUCCESS] Decryption completed successfully

# Decryption with wrong AAD (will fail)
./cryptocore --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input database.enc --output database_decrypted.sql \
  --aad "wrong_version"
# Output: [ERROR] Authentication failed: AAD mismatch or ciphertext tampered
```
### Encrypt-then-MAC (ETM)
```bash
./cryptocore --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad "metadata" \
  --input data.txt --output data.enc

./cryptocore --algorithm aes --mode cbc --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad "metadata" \
  --input data.enc --output data_decrypted.txt
```

## Key Derivation
### Password-Based Key Derivation (PBKDF2)
```bash
./cryptocore derive --password "MySecurePassword123!" \
  --salt alb2c3d4e5f6012345678901234 \
  --iterations 100000 --length 32

./cryptocore derive --password "AnotherPassword" \
  --iterations 500000 --length 16
# Output: DERIVED_KEY_HEX GENERATED_SALT_HEX

./cryptocore derive --password "app_key" \
  --salt fixedappsalt --iterations 10000 --length 32 \
  --output app.key
```
### Key Hierarchy from Master Key
```bash
./cryptocore derive --master-key 00112233445566778899aabbccddeeff \
  --context "encryption" --length 16

./cryptocore derive --master-key 00112233445566778899aabbccddeeff \
  --context "authentication" --length 32
```
## Key Generation
### Automatic Key Generation
When --key is omitted during encryption:

```bash
./cryptocore --algorithm aes --mode cbc --encrypt \
  --input plaintext.txt
```
### Generate Random Key Only
``` bash
./cryptocore --generate-key 16
./cryptocore --generate-key 32
```
## Debug Mode
```bash
./cryptocore --verbose --algorithm aes --mode cbc --encrypt \
  --input test.txt --output test.enc
  ```

