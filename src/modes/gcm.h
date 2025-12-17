#ifndef GCM_H
#define GCM_H

#include <stddef.h>
#include <stdint.h>

#define GCM_NONCE_SIZE 12
#define GCM_TAG_SIZE 16

int gcm_encrypt(const uint8_t* plaintext, size_t plaintext_len,
                const uint8_t* key, size_t key_len,
                const uint8_t* nonce, size_t nonce_len,
                const uint8_t* aad, size_t aad_len,
                uint8_t* ciphertext,
                uint8_t* tag, size_t tag_len);

int gcm_decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
                const uint8_t* key, size_t key_len,
                const uint8_t* nonce, size_t nonce_len,
                const uint8_t* aad, size_t aad_len,
                const uint8_t* tag, size_t tag_len,
                uint8_t* plaintext);

#endif