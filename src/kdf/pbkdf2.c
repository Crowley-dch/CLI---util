#include "pbkdf2.h"
#include "../mac/hmac.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h> 
#include <sys/random.h>

static void pbkdf2_f(const uint8_t *password, size_t password_len,
                     const uint8_t *salt, size_t salt_len,
                     uint32_t iterations, uint32_t block_index,
                     uint8_t *output) {
    uint8_t u[32];  
    uint8_t salt_with_index[salt_len + 4]; 
    memcpy(salt_with_index, salt, salt_len);
    salt_with_index[salt_len] = (block_index >> 24) & 0xFF;
    salt_with_index[salt_len + 1] = (block_index >> 16) & 0xFF;
    salt_with_index[salt_len + 2] = (block_index >> 8) & 0xFF;
    salt_with_index[salt_len + 3] = block_index & 0xFF;
    
    hmac_sha256(password, password_len, 
                salt_with_index, salt_len + 4, 
                u);
    
    memcpy(output, u, 32);
    
    for (uint32_t j = 2; j <= iterations; j++) {
        hmac_sha256(password, password_len, u, 32, u);
        
        for (int k = 0; k < 32; k++) {
            output[k] ^= u[k];
        }
    }
}

int pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len,
                       const uint8_t *salt, size_t salt_len,
                       uint32_t iterations, size_t dklen,
                       uint8_t *derived_key) {
    if (password == NULL || salt == NULL || derived_key == NULL ||
        iterations == 0 || dklen == 0) {
        return -1;
    }
    
    if (dklen > 1024 * 1024) { 
        return -1;
    }
    
    size_t blocks_needed = (dklen + 31) / 32;
    
    for (uint32_t i = 1; i <= blocks_needed; i++) {
        uint8_t block[32];
        pbkdf2_f(password, password_len, salt, salt_len, iterations, i, block);
        
        size_t bytes_to_copy = 32;
        size_t offset = (i - 1) * 32;
        
        if (dklen - offset < 32) {
            bytes_to_copy = dklen - offset;
        }
        
        memcpy(derived_key + offset, block, bytes_to_copy);
    }
    
    return 0;
}

int generate_random_salt(uint8_t *salt, size_t salt_len) {
    if (salt == NULL || salt_len == 0) {
        return -1;
    }
    
    ssize_t result = getrandom(salt, salt_len, 0);
    
    if (result < 0 || (size_t)result != salt_len) {
        FILE *urandom = fopen("/dev/urandom", "rb");
        if (urandom == NULL) {
            srand(time(NULL) ^ getpid());
            for (size_t i = 0; i < salt_len; i++) {
                salt[i] = rand() % 256;
            }
            return 0;
        }
        
        if (fread(salt, 1, salt_len, urandom) != salt_len) {
            fclose(urandom);
            return -1;
        }
        fclose(urandom);
    }
    
    return 0;
}