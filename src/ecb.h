#ifndef ECB_H
#define ECB_H

#include <stddef.h>

int hex_to_bytes(const char *hex, unsigned char *out, size_t out_len);

int encrypt_ecb(const unsigned char *plaintext, size_t plaintext_len,
                const unsigned char *key, unsigned char **out_cipher, size_t *out_len);

int decrypt_ecb(const unsigned char *ciphertext, size_t cipher_len,
                const unsigned char *key, unsigned char **out_plain, size_t *out_len);

#endif 
