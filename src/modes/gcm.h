#ifndef GCM_H
#define GCM_H

#include <stdint.h>
#include <stddef.h>

#define GCM_NONCE_SIZE 12
#define GCM_TAG_SIZE 16
#define GCM_BLOCK_SIZE 16

int gcm_encrypt(const uint8_t *key, size_t key_len,
                const uint8_t *nonce, size_t nonce_len,
                const uint8_t *plaintext, size_t plaintext_len,
                const uint8_t *aad, size_t aad_len,
                uint8_t *ciphertext, uint8_t *tag);

int gcm_decrypt(const uint8_t *key, size_t key_len,
                const uint8_t *nonce, size_t nonce_len,
                const uint8_t *ciphertext, size_t ciphertext_len,
                const uint8_t *aad, size_t aad_len,
                const uint8_t *tag,
                uint8_t *plaintext);

void ghash(const uint8_t *key, 
           const uint8_t *aad, size_t aad_len,
           const uint8_t *ciphertext, size_t ciphertext_len,
           uint8_t *tag);

uint64_t gfmul(uint64_t x, uint64_t y);  

#endif