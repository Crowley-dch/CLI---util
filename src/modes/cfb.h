#ifndef MODES_OFB_H
#define MODES_OFB_H
#include <stddef.h>
#include <stdint.h>

int encrypt_ofb(const unsigned char *plaintext, size_t plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **out_cipher, size_t *out_len);

int decrypt_ofb(const unsigned char *ciphertext, size_t cipher_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **out_plain, size_t *out_len);

#endif 
