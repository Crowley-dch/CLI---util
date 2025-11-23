#include "hmac.h"
#include "../hash/sha256.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define SHA256_BLOCK_SIZE 64
#define SHA256_OUTPUT_SIZE 32

static void hmac_prepare_key(const uint8_t *key, size_t key_len, uint8_t *prepared_key) {
    SHA256_CTX ctx;
    
    if (key_len > SHA256_BLOCK_SIZE) {
        sha256_hash(key, key_len, prepared_key);
        key_len = SHA256_OUTPUT_SIZE;
    } else {
        memcpy(prepared_key, key, key_len);
    }
    
    if (key_len < SHA256_BLOCK_SIZE) {
        memset(prepared_key + key_len, 0, SHA256_BLOCK_SIZE - key_len);
    }
}

int hmac_sha256(const uint8_t *key, size_t key_len,
                const uint8_t *data, size_t data_len,
                uint8_t *output) {
    uint8_t prepared_key[SHA256_BLOCK_SIZE];
    uint8_t inner_hash[SHA256_OUTPUT_SIZE];
    SHA256_CTX ctx;
    
    hmac_prepare_key(key, key_len, prepared_key);
    
    uint8_t inner_key[SHA256_BLOCK_SIZE];
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        inner_key[i] = prepared_key[i] ^ 0x36;
    }
    
    sha256_init(&ctx);
    sha256_update(&ctx, inner_key, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner_hash);
    
    uint8_t outer_key[SHA256_BLOCK_SIZE];
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        outer_key[i] = prepared_key[i] ^ 0x5c; 
    }
    
    sha256_init(&ctx);
    sha256_update(&ctx, outer_key, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, inner_hash, SHA256_OUTPUT_SIZE);
    sha256_final(&ctx, output);
    
    return 0; 
}

int hmac_sha256_file(const char *filename, 
                    const uint8_t *key, size_t key_len,
                    uint8_t *output) {
    FILE*file = fopen(filename, "rb");
    if (!file) {
        return -1;
    }
    
    uint8_t prepared_key[SHA256_BLOCK_SIZE];
    uint8_t inner_hash[SHA256_OUTPUT_SIZE];
    SHA256_CTX ctx;
    
    hmac_prepare_key(key, key_len, prepared_key);
    
    uint8_t inner_key[SHA256_BLOCK_SIZE];
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        inner_key[i] = prepared_key[i] ^ 0x36;
    }
    
    sha256_init(&ctx);
    sha256_update(&ctx, inner_key, SHA256_BLOCK_SIZE);
    
    const size_t BUFFER_SIZE = 8192;
    uint8_t buffer[BUFFER_SIZE];
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        sha256_update(&ctx, buffer, bytes_read);
    }
    
    if (ferror(file)) {
        fclose(file);
        return -2;
    }
    
    sha256_final(&ctx, inner_hash);
    fclose(file);
    
    uint8_t outer_key[SHA256_BLOCK_SIZE];
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        outer_key[i] = prepared_key[i] ^ 0x5c;
    }
    
    sha256_init(&ctx);
    sha256_update(&ctx, outer_key, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, inner_hash, SHA256_OUTPUT_SIZE);
    sha256_final(&ctx, output);
    
    return 0;
}

int compare_hmac(const uint8_t *hmac1, const uint8_t *hmac2) {
    return memcmp(hmac1, hmac2, SHA256_OUTPUT_SIZE) == 0;
}