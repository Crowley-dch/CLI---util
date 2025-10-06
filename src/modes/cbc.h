#ifndef MODES_CBC_H
#define MODES_CBC_H

#include <stddef.h>

int encrypt_cbc(const unsigned char *plaintext, size_t plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **out_cipher, size_t *out_len);

int decrypt_cbc(const unsigned char *ciphertext, size_t cipher_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **out_plain, size_t *out_len);

#endif 
