#define _DEFAULT_SOURCE
#include "cbc.h"
#include <openssl/aes.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK_SIZE AES_BLOCK_SIZE 

static unsigned char *pkcs7_pad(const unsigned char *in, size_t in_len, size_t *out_len) {
    if (!out_len) return NULL;
    size_t pad_len = BLOCK_SIZE - (in_len % BLOCK_SIZE);
    if (pad_len == 0) pad_len = BLOCK_SIZE;
    *out_len = in_len + pad_len;

    unsigned char *out = malloc(*out_len);
    if (!out) return NULL;

    if (in_len > 0 && in != NULL) memcpy(out, in, in_len);
    memset(out + in_len, (unsigned char)pad_len, pad_len);
    return out;
}

static int pkcs7_unpad(unsigned char *data, size_t len, size_t *out_len) {
    if (!data || !out_len) return -1;
    if (len == 0 || (len % BLOCK_SIZE) != 0) return -2;

    unsigned char pad = data[len - 1];
    if (pad == 0 || pad > BLOCK_SIZE) return -3;

    for (size_t i = 0; i < pad; ++i) {
        if (data[len - 1 - i] != pad) return -4;
    }
    *out_len = len - pad;
    return 0;
}


int encrypt_cbc(const unsigned char *plaintext, size_t plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **out_cipher, size_t *out_len) {
    if (!key || !iv || !out_cipher || !out_len) return -1;
    if ((plaintext_len > 0 && !plaintext) && plaintext_len != 0) return -1;

    size_t padded_len = 0;
    unsigned char *padded = pkcs7_pad(plaintext, plaintext_len, &padded_len);
    if (!padded) return -2;

    unsigned char *out = malloc(padded_len);
    if (!out) { free(padded); return -2; }

    AES_KEY aes_enc;
    if (AES_set_encrypt_key(key, 128, &aes_enc) < 0) {
        free(padded); free(out); return -3;
    }

    unsigned char prev[BLOCK_SIZE];
    memcpy(prev, iv, BLOCK_SIZE);

    for (size_t off = 0; off < padded_len; off += BLOCK_SIZE) {
        unsigned char block[BLOCK_SIZE];
        for (size_t i = 0; i < BLOCK_SIZE; ++i) {
            block[i] = padded[off + i] ^ prev[i];
        }
        AES_encrypt(block, out + off, &aes_enc);
        memcpy(prev, out + off, BLOCK_SIZE);
    }

    free(padded);
    *out_cipher = out;
    *out_len = padded_len;
    return 0;
}

int decrypt_cbc(const unsigned char *ciphertext, size_t cipher_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **out_plain, size_t *out_len) {
    if (!ciphertext || !key || !iv || !out_plain || !out_len) return -1;
    if (cipher_len == 0 || (cipher_len % BLOCK_SIZE) != 0) return -2;

    unsigned char *out = malloc(cipher_len);
    if (!out) return -2;

    AES_KEY aes_dec;
    if (AES_set_decrypt_key(key, 128, &aes_dec) < 0) {
        free(out); return -4;
    }

    unsigned char prev[BLOCK_SIZE];
    memcpy(prev, iv, BLOCK_SIZE);

    for (size_t off = 0; off < cipher_len; off += BLOCK_SIZE) {
        unsigned char decrypted[BLOCK_SIZE];
        AES_decrypt(ciphertext + off, decrypted, &aes_dec);
        for (size_t i = 0; i < BLOCK_SIZE; ++i) {
            out[off + i] = decrypted[i] ^ prev[i];
        }
        memcpy(prev, ciphertext + off, BLOCK_SIZE);
    }

    size_t unp_len = 0;
    int ures = pkcs7_unpad(out, cipher_len, &unp_len);
    if (ures != 0) {
        free(out);
        return -5;
    }

    unsigned char *shrunk = realloc(out, unp_len ? unp_len : 1);
    if (shrunk) out = shrunk;

    *out_plain = out;
    *out_len = unp_len;
    return 0;
}
