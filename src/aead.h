#ifndef AEAD_H
#define AEAD_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t* ciphertext;
    size_t ciphertext_len;
    uint8_t* tag;
    size_t tag_len;
} etm_result_t;

int etm_encrypt(const uint8_t* plaintext, size_t plaintext_len,
                const uint8_t* key, size_t key_len,
                const uint8_t* iv, size_t iv_len,
                const uint8_t* aad, size_t aad_len,
                uint8_t** ciphertext, size_t* ciphertext_len,
                uint8_t** tag, size_t* tag_len);

int etm_decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
                const uint8_t* key, size_t key_len,
                const uint8_t* iv, size_t iv_len,
                const uint8_t* aad, size_t aad_len,
                const uint8_t* tag, size_t tag_len,
                uint8_t** plaintext, size_t* plaintext_len);

int etm_encrypt_file(const char* input_file, const char* output_file,
                     const uint8_t* key, size_t key_len,
                     const uint8_t* aad, size_t aad_len);

int etm_decrypt_file(const char* input_file, const char* output_file,
                     const uint8_t* key, size_t key_len,
                     const uint8_t* aad, size_t aad_len);

#endif