# CryptoCore Development Guide

## Table of Contents
1. [Project Structure](#project-structure)


## Project Structure
cryptocore/
├── src/ # Main source code
│ ├── main.c # Entry point
│ ├── cli_parser.c/h # Command line interface
│ ├── file_io.c/h # File operations
│ ├── csprng.c/h # Random number generation
│ ├── aead.c/h # Authenticated encryption
│ └── ecb.c/h # ECB mode implementation
├── src/modes/ # Encryption modes
│ ├── cbc.c/h
│ ├── cfb.c/h
│ ├── ofb.c/h
│ ├── ctr.c/h
│ └── gcm.c/h # GCM authenticated encryption
├── src/hash/ # Hash functions
│ ├── sha256.c/h # SHA-256 implementation
│ └── blake2b.c/h # BLAKE2b via OpenSSL
├── src/mac/ # Message Authentication Codes
│ └── hmac.c/h # HMAC-SHA256
├── src/kdf/ # Key Derivation Functions
│ ├── pbkdf2.c/h # PBKDF2-HMAC-SHA256
│ └── hkdf.c/h # HKDF-style key hierarchy
├── include/ # Public headers (if needed)
├── tests/ # Test suite
│ ├── unit/ # Unit tests
│ ├── integration/ # Integration tests
│ ├── vectors/ # Test vectors
│ └── test_runner.c # Main test runner
├── docs/ # Documentation
│ ├── API.md
│ ├── USERGUIDE.md
│ └── DEVELOPMENT.md
├── Makefile # Build system
├── README.md # Project overview
