#define _DEFAULT_SOURCE
#include "ecb.h"
#include <openssl/aes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define BLOCK_SIZE AES_BLOCK_SIZE // 16

int hex_to_bytes(const char *hex, unsigned char *out, size_t out_len) {
    if (!hex || !out) return -1;
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return -2;
    for (size_t i = 0; i < out_len; ++i) {
        unsigned int byte;
        if (sscanf(hex + 2*i, "%2x", &byte) != 1) return -3;
        out[i] = (unsigned char)byte;
    }
    return 0;
}

static unsigned char *pkcs7_pad(const unsigned char *in, size_t in_len, size_t *out_len) {
    size_t pad_len = BLOCK_SIZE - (in_len % BLOCK_SIZE);
    if (pad_len == 0) pad_len = BLOCK_SIZE;
    *out_len = in_len + pad_len;
    unsigned char *out = malloc(*out_len);
    if (!out) return NULL;
    memcpy(out, in, in_len);
    memset(out + in_len, (unsigned char)pad_len, pad_len);
    return out;
}

static int pkcs7_unpad(unsigned char *data, size_t len, size_t *out_len) {
    if (len == 0 || len % BLOCK_SIZE != 0) return -1;
    unsigned char pad = data[len - 1];
    if (pad == 0 || pad > BLOCK_SIZE) return -2;
    for (size_t i = 0; i < pad; ++i) {
        if (data[len - 1 - i] != pad) return -3;
    }
    *out_len = len - pad;
    return 0;
}

int encrypt_ecb(const unsigned char *plaintext, size_t plaintext_len,
                const unsigned char *key, unsigned char **out_cipher, size_t *out_len) {
    if (!plaintext || !key || !out_cipher || !out_len) return -1;
    size_t padded_len;
    unsigned char *padded = pkcs7_pad(plaintext, plaintext_len, &padded_len);
    if (!padded) return -2;
    *out_cipher = malloc(padded_len);
    if (!*out_cipher) { free(padded); return -3; }

    AES_KEY aes_enc;
    if (AES_set_encrypt_key(key, 128, &aes_enc) < 0) {
        free(padded); free(*out_cipher); return -4;
    }

    for (size_t off = 0; off < padded_len; off += BLOCK_SIZE) {
        AES_encrypt(padded + off, *out_cipher + off, &aes_enc);
    }
    *out_len = padded_len;
    free(padded);
    return 0;
}

int decrypt_ecb(const unsigned char *ciphertext, size_t cipher_len,
                const unsigned char *key, unsigned char **out_plain, size_t *out_len) {
    if (!ciphertext || !key || !out_plain || !out_len) return -1;
    if (cipher_len % BLOCK_SIZE != 0) return -2;
    *out_plain = malloc(cipher_len);
    if (!*out_plain) return -3;

    AES_KEY aes_dec;
    if (AES_set_decrypt_key(key, 128, &aes_dec) < 0) {
        free(*out_plain); return -4;
    }

    for (size_t off = 0; off < cipher_len; off += BLOCK_SIZE) {
        AES_decrypt(ciphertext + off, *out_plain + off, &aes_dec);
    }
    size_t unp_len = 0;
    int ures = pkcs7_unpad(*out_plain, cipher_len, &unp_len);
    if (ures != 0) {
        free(*out_plain);
        *out_plain = NULL;
        *out_len = 0;
        return -5; 
    }
    *out_len = unp_len;
    return 0;
}
