#ifndef AEAD_H
#define AEAD_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    int (*encrypt)(const uint8_t *key, size_t key_len,
                   const uint8_t *nonce, size_t nonce_len,
                   const uint8_t *plaintext, size_t plaintext_len,
                   const uint8_t *aad, size_t aad_len,
                   uint8_t *ciphertext, uint8_t *tag);
    
    int (*decrypt)(const uint8_t *key, size_t key_len,
                   const uint8_t *nonce, size_t nonce_len,
                   const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t *tag,
                   uint8_t *plaintext);
} aead_algorithm_t;

int encrypt_then_mac(const uint8_t *enc_key, size_t enc_key_len,
                     const uint8_t *mac_key, size_t mac_key_len,
                     const uint8_t *nonce, size_t nonce_len,
                     const uint8_t *plaintext, size_t plaintext_len,
                     const uint8_t *aad, size_t aad_len,
                     uint8_t *ciphertext, uint8_t *tag);

int decrypt_then_verify(const uint8_t *enc_key, size_t enc_key_len,
                        const uint8_t *mac_key, size_t mac_key_len,
                        const uint8_t *nonce, size_t nonce_len,
                        const uint8_t *ciphertext, size_t ciphertext_len,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *tag,
                        uint8_t *plaintext);

#endif