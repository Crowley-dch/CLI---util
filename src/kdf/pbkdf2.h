#ifndef PBKDF2_H
#define PBKDF2_H

#include <stddef.h>
#include <stdint.h>

int pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
                       const uint8_t *salt, size_t salt_len,
                       uint32_t iterations, size_t dklen,
                       uint8_t *derived_key);

int generate_random_salt(uint8_t *salt, size_t salt_len);

#endif 