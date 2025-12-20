# CryptoCore API Documentation

## Table of Contents
- [Overview](#overview)
- [AES Block Cipher](#aes-block-cipher)
- [Modes of Operation](#modes-of-operation)
- [Hash Functions](#hash-functions)
- [MAC Functions](#mac-functions)
- [Authenticated Encryption](#authenticated-encryption)
- [Key Derivation Functions](#key-derivation-functions)
- [Random Number Generation](#random-number-generation)
- [Command Line Interface](#command-line-interface)
- [File I/O Utilities](#file-io-utilities)

## Overview

CryptoCore is a cryptographic library providing symmetric encryption, hashing, message authentication, and key derivation functions. All functions return 0 on success and non-zero error codes on failure.

## AES Block Cipher

### encrypt_ecb
Encrypts data using AES-128 in Electronic Codebook (ECB) mode.

Prototype:
int encrypt_ecb(const unsigned char *plaintext, size_t plaintext_len,
                const unsigned char *key, unsigned char **out_cipher, size_t *out_len);

### Parameters:

- plaintext: Input data to encrypt

- plaintext_len: Length of input data in bytes

- key: 16-byte AES encryption key

- out_cipher: Pointer to output buffer (allocated by function)

- out_len: Pointer to store output length

- Returns: 0 on success, non-zero error code on failure

## Notes:

Uses PKCS#7 padding automatically

Caller must free *out_cipher after use

### decrypt_ecb
Decrypts data using AES-128 in ECB mode.

**Prototype:**
int decrypt_ecb(const unsigned char *ciphertext, size_t cipher_len,
                const unsigned char *key, unsigned char **out_plain, size_t *out_len);
### Parameters:

- ciphertext: Encrypted data

- cipher_len: Length of ciphertext in bytes

- key: 16-byte AES decryption key (same as encryption key)

- out_plain: Pointer to output buffer (allocated by function)

- out_len: Pointer to store output length

- Returns: 0 on success, non-zero error code on failure

## Modes of Operation
### CBC Mode
encrypt_cbc
Encrypts data using AES-128 in Cipher Block Chaining (CBC) mode.

**Prototype:**
int encrypt_cbc(const unsigned char *plaintext, size_t plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **out_cipher, size_t *out_len);
###Parameters:

- plaintext: Input data to encrypt

- plaintext_len: Length of input data in bytes

- key: 16-byte AES encryption key

- iv: 16-byte initialization vector

- out_cipher: Pointer to output buffer

- out_len: Pointer to store output length

- Returns: 0 on success, non-zero error code on failure

## decrypt_cbc
Decrypts data using AES-128 in CBC mode.

**Prototype:**
int decrypt_cbc(const unsigned char *ciphertext, size_t cipher_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **out_plain, size_t *out_len);
### CFB Mode
encrypt_cfb
Encrypts data using AES-128 in Cipher Feedback (CFB) mode.

**Prototype:**
int encrypt_cfb(const unsigned char *plaintext, size_t plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **out_cipher, size_t *out_len);
###Notes:

- CFB mode operates as a stream cipher

- No padding required

- IV must be 16 bytes

### OFB Mode
encrypt_ofb
Encrypts data using AES-128 in Output Feedback (OFB) mode.

**Prototype:**
int encrypt_ofb(const unsigned char *plaintext, size_t plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **out_cipher, size_t *out_len);
### CTR Mode
encrypt_ctr
Encrypts data using AES-128 in Counter (CTR) mode.

**Prototype:**
int encrypt_ctr(const unsigned char *plaintext, size_t plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **out_cipher, size_t *out_len);

##Hash Functions##
###SHA-256###

SHA256_CTX
Context structure for incremental SHA-256 computation.
typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t buffer[64];
    size_t buffer_length;
} SHA256_CTX;
sha256_init
Initializes SHA-256 context.
**Prototype:**
void sha256_init(SHA256_CTX *ctx);
sha256_update
Updates SHA-256 hash with new data.

Prototype:
void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t length);
sha256_final
Finalizes SHA-256 computation and produces hash.

Prototype:
void sha256_final(SHA256_CTX *ctx, uint8_t hash[32]);
sha256_hash_hex
Computes SHA-256 hash and returns hexadecimal string.

Prototype:
c char* sha256_hash_hex(const uint8_t *data, size_t length);
Returns: Dynamically allocated hexadecimal string (caller must free)

###BLAKE2b
blake2b_hash_hex
Computes BLAKE2b hash with specified output length.

Prototype:
char* blake2b_hash_hex(const uint8_t *data, size_t len, size_t outlen);
###Parameters:

- data: Input data

-  len: Input data length

- outlen: Desired hash output length (1-64 bytes)

Returns: Dynamically allocated hexadecimal string

blake2b_hash_file_openssl
Computes BLAKE2b hash of a file using OpenSSL.

Prototype:
cchar* blake2b_hash_file_openssl(const char *filename, size_t outlen);

##MAC Functions
###HMAC-SHA256
hmac_sha256
Computes HMAC using SHA-256 as underlying hash function.

Prototype:
`c`c
int hmac_sha256(const uint8_t *key, size_t key_len,
                const uint8_t *data, size_t data_len,
                uint8_t *output);

###Parameters:

- key: HMAC key (arbitrary length)

- key_len: Key length in bytes

- data: Data to authenticate

- data_len: Data length in bytes

output: Output buffer (32 bytes for HMAC-SHA256)

Returns: 0 on success, non-zero error code on failure

hmac_sha256_file
Computes HMAC of a file.

Prototype:

int hmac_sha256_file(const char *filename, 
                    const uint8_t *key, size_t key_len,
                    uint8_t *output);
compare_hmac
Compares two HMAC values securely (constant-time).

Prototype:
int compare_hmac(const uint8_t *hmac1, const uint8_t *hmac2);
Returns: 0 if equal, 1 if different

##Authenticated Encryption

##GCM Mode
###`gcm_encrypt`
Encrypts and authenticates data using AES-GCM.

Prototype:
int gcm_encrypt(const uint8_t* plaintext, size_t plaintext_len,
                const uint8_t* key, size_t key_len,
                const uint8_t* nonce, size_t nonce_len,
                const uint8_t* aad, size_t aad_len,
                uint8_t* ciphertext,
                uint8_t* tag, size_t tag_len);
###Parameters:

- plaintext: Data to encrypt

- key: Encryption key (16, 24, or 32 bytes for AES-128/192/256)

- nonce: Nonce/IV (12 bytes recommended)

- aad: Additional Authenticated Data (optional, can be NULL)

- ciphertext: Output buffer for ciphertext (same size as plaintext)

- tag: Output buffer for authentication tag (16 bytes recommended)

Returns: 0 on success, non-zero error code on failure

###`gcm_decrypt`
Decrypts and verifies data using AES-GCM.

Prototype:
int gcm_decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
                const uint8_t* key, size_t key_len,
                const uint8_t* nonce, size_t nonce_len,
                const uint8_t* aad, size_t aad_len,
                const uint8_t* tag, size_t tag_len,
                uint8_t* plaintext);
Security Note: If authentication fails, function returns error without decrypting.

##Encrypt-then-MAC (ETM)
### etm_encrypt 
Encrypts data using any block cipher mode then computes MAC.

Prototype:
int etm_encrypt(const uint8_t* plaintext, size_t plaintext_len,
                const uint8_t* key, size_t key_len,
                const uint8_t* iv, size_t iv_len,
                const uint8_t* aad, size_t aad_len,
                uint8_t** ciphertext, size_t* ciphertext_len,
                uint8_t** tag, size_t* tag_len);
###`etm_encrypt_file`
Encrypts and authenticates a file using ETM paradigm.

Prototype:
int etm_encrypt_file(const char* input_file, const char* output_file,
                     const uint8_t* key, size_t key_len,
                     const uint8_t* aad, size_t aad_len);
Key Derivation Functions
##PBKDF2
###pbkdf2_hmac_sha256
Derives key from password using PBKDF2 with HMAC-SHA256.
Prototype:
int pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
                       const uint8_t *salt, size_t salt_len,
                       uint32_t iterations, size_t dklen,
                       uint8_t *derived_key);
###Parameters:

- password: Password/passphrase

- salt: Cryptographic salt

- iterations: Number of iterations (recommended ≥ 100,000)

- dklen: Desired derived key length in bytes

- derived_key: Output buffer for derived key

Returns: 0 on success, non-zero error code on failure

###generate_random_salt
Generates cryptographically random salt.

Prototype:
int generate_random_salt(uint8_t *salt, size_t salt_len);
HKDF-style Key Hierarchy
derive_key
Derives subkey from master key using HMAC-based KDF.

Prototype:
int derive_key(const uint8_t *master_key, size_t master_len,
               const uint8_t *context, size_t context_len,
               size_t length, uint8_t *derived_key);
###Parameters:

- master_key: Master/root key
- context: Context string (e.g., "encryption", "authentication")
- length: Desired derived key length
- derived_key: Output buffer
- derive_key_str
- String-based version of derive_key.

Prototype:
int derive_key_str(const uint8_t *master_key, size_t master_len,
                   const char *context,
                   size_t length, uint8_t *derived_key);
##Random Number Generation
###`generate_random_bytes`
Generates cryptographically secure random bytes.

Prototype:
int generate_random_bytes(unsigned char *buffer, size_t num_bytes);
implementation: Uses /dev/urandom on Linux, RAND_bytes() from OpenSSL

##Command Line Interface
###`cli_args_t`
Structure containing parsed command line arguments.
typedef struct {
    char *algorithm;
    char *input;
    char *output;
    subcommand_t subcommand;  // SUBCMD_NONE, SUBCMD_DGST, SUBCMD_DERIVE
    
    char *mode;           // Encryption mode
    bool encrypt;
    bool decrypt;
    char *key_hex;
    char *iv_hex;       
    char *aad_hex;      
    bool hmac_mode;
    bool cmac_mode;
    char *verify_file;
    bool digest_mode;
    char *password;      
    char *salt_hex;      
    uint32_t iterations;
    size_t key_length;   
    bool generate_salt; 
    char *password_file;
} cli_args_t;
###parse_cli_args
Parses command line arguments into structured format.

Prototype:
c int parse_cli_args(int argc, char **argv, cli_args_t *out);
free_cli_args
Frees memory allocated by parse_cli_args.

**rototype:**
c void free_cli_args(cli_args_t *args);
##File I/O Utilities
###`read_file`
Reads entire file into memory.

Prototype:
c int read_file(const char *path, unsigned char **data, size_t *len);
###`write_file_atomic`
Writes data to file atomically (creates temp file then renames).

**Prototype:**
c int write_file_atomic(const char *path, const unsigned char *data, size_t len);
###`write_file_with_iv`
Writes IV followed by ciphertext to file.

Prototype:
c int write_file_with_iv(const char *path, const unsigned char *iv,
                      const unsigned char *ciphertext, size_t cipher_len);
###`read_file_with_iv`
Reads file containing IV followed by ciphertext.

Prototype:
compute_file_hash_stream
Computes hash of file using streaming interface.

Prototype:
int compute_file_hash_stream(const char *filename, 
                           const char *algorithm,
                           char **hex_hash,
                           int (*update_func)(const unsigned char *, size_t),
                           int (*final_func)(unsigned char *));
##Memory Management Notes
- Functions returning char* allocate memory dynamically (use free())

- Functions with **out parameters allocate output buffers

- Caller is responsible for freeing all allocated memory

- Sensitive data (keys, passwords) should be cleared using memset() or secure_zero_memory()

##Thread Safety
- Most functions are not thread-safe (use per-thread contexts)

- Random number generation uses thread-safe sources

- File I/O functions are not thread-safe for same file paths

##Version
CryptoCore v1.0.0