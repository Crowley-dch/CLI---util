#define _DEFAULT_SOURCE
#include "cfb.h"
#include <openssl/aes.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK_SIZE AES_BLOCK_SIZE

int encrypt_cfb(const unsigned char *plaintext, size_t plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **out_cipher, size_t *out_len) {
    if (!plaintext || !key || !iv || !out_cipher || !out_len) return -1;

    unsigned char *out = malloc(plaintext_len ? plaintext_len : 1);
    if (!out) return -2;

    AES_KEY aes_enc;
    if (AES_set_encrypt_key(key, 128, &aes_enc) < 0) { free(out); return -3; }

    unsigned char shift_reg[BLOCK_SIZE];
    memcpy(shift_reg, iv, BLOCK_SIZE);

    size_t offset = 0;
    while (offset < plaintext_len) {
        unsigned char keystream[BLOCK_SIZE];
        AES_encrypt(shift_reg, keystream, &aes_enc);

        size_t chunk = plaintext_len - offset;
        if (chunk > BLOCK_SIZE) chunk = BLOCK_SIZE;

        for (size_t i = 0; i < chunk; ++i) {
            unsigned char c = plaintext[offset + i] ^ keystream[i];
            out[offset + i] = c;
        }

        if (chunk == BLOCK_SIZE) {
            memcpy(shift_reg, out + offset, BLOCK_SIZE);
        } else {
            memmove(shift_reg, shift_reg + chunk, BLOCK_SIZE - chunk);
            memcpy(shift_reg + (BLOCK_SIZE - chunk), out + offset, chunk);
        }

        offset += chunk;
    }

    *out_cipher = out;
    *out_len = plaintext_len;
    return 0;
}

int decrypt_cfb(const unsigned char *ciphertext, size_t cipher_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **out_plain, size_t *out_len) {
    if (!ciphertext || !key || !iv || !out_plain || !out_len) return -1;

    unsigned char *out = malloc(cipher_len ? cipher_len : 1);
    if (!out) return -2;

    AES_KEY aes_enc; 
    if (AES_set_encrypt_key(key, 128, &aes_enc) < 0) { free(out); return -3; }

    unsigned char shift_reg[BLOCK_SIZE];
    memcpy(shift_reg, iv, BLOCK_SIZE);

    size_t offset = 0;
    while (offset < cipher_len) {
        unsigned char keystream[BLOCK_SIZE];
        AES_encrypt(shift_reg, keystream, &aes_enc);

        size_t chunk = cipher_len - offset;
        if (chunk > BLOCK_SIZE) chunk = BLOCK_SIZE;

        for (size_t i = 0; i < chunk; ++i) {
            unsigned char p = ciphertext[offset + i] ^ keystream[i];
            out[offset + i] = p;
        }

        if (chunk == BLOCK_SIZE) {
            memcpy(shift_reg, ciphertext + offset, BLOCK_SIZE);
        } else {
            memmove(shift_reg, shift_reg + chunk, BLOCK_SIZE - chunk);
            memcpy(shift_reg + (BLOCK_SIZE - chunk), ciphertext + offset, chunk);
        }

        offset += chunk;
    }

    *out_plain = out;
    *out_len = cipher_len;
    return 0;
}
