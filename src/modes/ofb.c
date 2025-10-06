#define _DEFAULT_SOURCE
#include "ofb.h"
#include <openssl/aes.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK_SIZE AES_BLOCK_SIZE

int encrypt_ofb(const unsigned char *plaintext, size_t plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **out_cipher, size_t *out_len) {
    if (!plaintext || !key || !iv || !out_cipher || !out_len) return -1;

    unsigned char *out = malloc(plaintext_len ? plaintext_len : 1);
    if (!out) return -2;

    AES_KEY aes_enc;
    if (AES_set_encrypt_key(key, 128, &aes_enc) < 0) { free(out); return -3; }

    unsigned char feedback[BLOCK_SIZE];
    memcpy(feedback, iv, BLOCK_SIZE);

    size_t offset = 0;
    while (offset < plaintext_len) {
        unsigned char keystream[BLOCK_SIZE];
        AES_encrypt(feedback, keystream, &aes_enc);
        memcpy(feedback, keystream, BLOCK_SIZE);

        size_t chunk = plaintext_len - offset;
        if (chunk > BLOCK_SIZE) chunk = BLOCK_SIZE;

        for (size_t i = 0; i < chunk; ++i) {
            out[offset + i] = plaintext[offset + i] ^ keystream[i];
        }

        offset += chunk;
    }

    *out_cipher = out;
    *out_len = plaintext_len;
    return 0;
}

int decrypt_ofb(const unsigned char *ciphertext, size_t cipher_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **out_plain, size_t *out_len) {
    return encrypt_ofb(ciphertext, cipher_len, key, iv, out_plain, out_len);
}
