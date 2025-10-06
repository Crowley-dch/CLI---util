#ifndef MODES_CTR_H
#define MODES_CTR_H
#include <stddef.h>

int encrypt_ctr(const unsigned char *plaintext, size_t plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **out_cipher, size_t *out_len);

int decrypt_ctr(const unsigned char *ciphertext, size_t cipher_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **out_plain, size_t *out_len);

#endif // MODES_CTR_H
