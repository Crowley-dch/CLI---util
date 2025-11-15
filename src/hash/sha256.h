#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t buffer[64];
    size_t buffer_length;
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t length);
void sha256_transform(SHA256_CTX *ctx, const uint8_t block[64]);
void sha256_final(SHA256_CTX *ctx, uint8_t hash[32]);
void sha256_hash(const uint8_t *data, size_t length, uint8_t hash[32]);
char* sha256_hash_hex(const uint8_t *data, size_t length);

#endif