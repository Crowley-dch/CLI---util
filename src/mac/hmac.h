#ifndef HMAC_H
#define HMAC_H

#include <stdint.h>
#include <stddef.h>

int hmac_sha256(const uint8_t *key, size_t key_len,
                const uint8_t *data, size_t data_len,
                uint8_t *output);

int hmac_sha256_file(const char *filename, 
                    const uint8_t *key, size_t key_len,
                    uint8_t *output);

int compare_hmac(const uint8_t *hmac1, const uint8_t *hmac2);

#endif