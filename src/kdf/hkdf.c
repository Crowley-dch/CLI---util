#include "hkdf.h"
#include "../mac/hmac.h"
#include <string.h>
#include <stdint.h>

int derive_key(const uint8_t *master_key, size_t master_len,
               const uint8_t *context, size_t context_len,
               size_t length, uint8_t *derived_key) {
    if (!master_key || !context || !derived_key || length == 0) {
        return -1;
    }
    
    uint32_t counter = 1;
    size_t bytes_generated = 0;
    uint8_t block[32]; 
    
    while (bytes_generated < length) {
        uint8_t message[context_len + 4];
        memcpy(message, context, context_len);
        message[context_len] = (counter >> 24) & 0xFF;
        message[context_len + 1] = (counter >> 16) & 0xFF;
        message[context_len + 2] = (counter >> 8) & 0xFF;
        message[context_len + 3] = counter & 0xFF;
        
        hmac_sha256(master_key, master_len,
                   message, context_len + 4,
                   block);
        
        size_t bytes_needed = length - bytes_generated;
        size_t bytes_to_copy = (bytes_needed > 32) ? 32 : bytes_needed;
        
        memcpy(derived_key + bytes_generated, block, bytes_to_copy);
        bytes_generated += bytes_to_copy;
        counter++;
    }
    
    return 0;
}

int derive_key_str(const uint8_t *master_key, size_t master_len,
                   const char *context,
                   size_t length, uint8_t *derived_key) {
    return derive_key(master_key, master_len,
                     (const uint8_t*)context, strlen(context),
                     length, derived_key);
}