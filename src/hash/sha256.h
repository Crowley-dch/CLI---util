#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_LENGTH 32
#define SHA256_BLOCK_SIZE 64

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;            
    uint8_t data[SHA256_BLOCK_SIZE];
    size_t datalen;             
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t hash[SHA256_DIGEST_LENGTH]);

void sha256(const uint8_t *data, size_t len, uint8_t out_hash[SHA256_DIGEST_LENGTH]);

void sha256_to_hex(const uint8_t hash[SHA256_DIGEST_LENGTH], char hex_out[SHA256_DIGEST_LENGTH*2 + 1]);

#endif 
