#include "gcm.h"
#include <string.h>
#include <stdlib.h>
#include "../ecb.h"  

static const uint64_t GCM_REDUCTION_POLY = 0xE100000000000000ULL;

static void bytes_to_block(const uint8_t *bytes, uint64_t *high, uint64_t *low) {
    *high = ((uint64_t)bytes[0] << 56) | ((uint64_t)bytes[1] << 48) |
            ((uint64_t)bytes[2] << 40) | ((uint64_t)bytes[3] << 32) |
            ((uint64_t)bytes[4] << 24) | ((uint64_t)bytes[5] << 16) |
            ((uint64_t)bytes[6] << 8)  | ((uint64_t)bytes[7]);
    *low = ((uint64_t)bytes[8] << 56) | ((uint64_t)bytes[9] << 48) |
           ((uint64_t)bytes[10] << 40) | ((uint64_t)bytes[11] << 32) |
           ((uint64_t)bytes[12] << 24) | ((uint64_t)bytes[13] << 16) |
           ((uint64_t)bytes[14] << 8)  | ((uint64_t)bytes[15]);
}

static void block_to_bytes(uint64_t high, uint64_t low, uint8_t *bytes) {
    for (int i = 0; i < 8; i++) {
        bytes[i] = (high >> (56 - 8*i)) & 0xFF;
        bytes[8 + i] = (low >> (56 - 8*i)) & 0xFF;
    }
}

static void gf_multiply(const uint8_t x[16], const uint8_t y[16], uint8_t result[16]) {
    uint8_t v[16];
    uint8_t z[16] = {0};
    
    memcpy(v, y, 16);
    
    for (int i = 0; i < 128; i++) {
        int byte_idx = i / 8;
        int bit_idx = 7 - (i % 8);
        
        if ((x[byte_idx] >> bit_idx) & 1) {
            for (int j = 0; j < 16; j++) {
                z[j] ^= v[j];
            }
        }
        
        uint8_t carry = v[15] & 1;  
        
        for (int j = 15; j > 0; j--) {
            v[j] = (v[j] >> 1) | ((v[j-1] & 1) << 7);
        }
        v[0] >>= 1;
        
        if (carry) {
            v[0] ^= 0xE1;  
        }
    }
    
    memcpy(result, z, 16);
}

void ghash(const uint8_t *h_key,
           const uint8_t *aad, size_t aad_len,
           const uint8_t *ciphertext, size_t ciphertext_len,
           uint8_t *tag) {
    
    uint8_t h[16];
    memcpy(h, h_key, 16);
    
    uint8_t y[16] = {0};
    
    size_t aad_blocks = (aad_len + 15) / 16;
    for (size_t i = 0; i < aad_blocks; i++) {
        uint8_t block[16] = {0};
        size_t bytes_to_copy = (i == aad_blocks - 1) ? 
                              aad_len - i*16 : 16;
        memcpy(block, aad + i*16, bytes_to_copy);
        
        for (int j = 0; j < 16; j++) {
            y[j] ^= block[j];
        }
        
        gf_multiply(y, h, y);
    }
    
    size_t cipher_blocks = (ciphertext_len + 15) / 16;
    for (size_t i = 0; i < cipher_blocks; i++) {
        uint8_t block[16] = {0};
        size_t bytes_to_copy = (i == cipher_blocks - 1) ? 
                              ciphertext_len - i*16 : 16;
        memcpy(block, ciphertext + i*16, bytes_to_copy);
        
        for (int j = 0; j < 16; j++) {
            y[j] ^= block[j];
        }
        
        gf_multiply(y, h, y);
    }
    
    uint64_t len_bits_aad = (uint64_t)aad_len * 8;
    uint64_t len_bits_cipher = (uint64_t)ciphertext_len * 8;
    
    uint8_t len_block[16];
    for (int i = 0; i < 8; i++) {
        len_block[i] = (len_bits_aad >> (56 - 8*i)) & 0xFF;
        len_block[8 + i] = (len_bits_cipher >> (56 - 8*i)) & 0xFF;
    }
    
    for (int j = 0; j < 16; j++) {
        y[j] ^= len_block[j];
    }
    
    gf_multiply(y, h, tag);
}

static void increment_counter(uint8_t counter[16]) {
    for (int i = 15; i >= 12; i--) {
        counter[i]++;
        if (counter[i] != 0) break; 
    }
}

static void generate_j0(const uint8_t *nonce, size_t nonce_len, uint8_t j0[16]) {
    if (nonce_len == 12) {
        memcpy(j0, nonce, 12);
        j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    } else {
        uint8_t h[16] = {0}; 
        uint8_t len_block[16] = {0};
        uint64_t len_bits = (uint64_t)nonce_len * 8;
        
        uint8_t block[16];
        size_t blocks = (nonce_len + 15) / 16;
        
        for (size_t i = 0; i < blocks; i++) {
            memset(block, 0, 16);
            size_t copy_len = (i == blocks - 1) ? nonce_len - i*16 : 16;
            memcpy(block, nonce + i*16, copy_len);
        }
        memset(j0, 0, 16);
        if (nonce_len <= 12) {
            memcpy(j0, nonce, nonce_len);
            j0[15] = 1;
        }
    }
}

int gcm_encrypt(const uint8_t *key, size_t key_len,
                const uint8_t *nonce, size_t nonce_len,
                const uint8_t *plaintext, size_t plaintext_len,
                const uint8_t *aad, size_t aad_len,
                uint8_t *ciphertext, uint8_t *tag) {
    
    if (key_len != 16) return -1; 
    
    uint8_t j0[16];
    generate_j0(nonce, nonce_len, j0);
    
    uint8_t h[16] = {0};
    
    uint8_t counter[16];
    memcpy(counter, j0, 16);
    increment_counter(counter); 
    
    for (size_t i = 0; i < plaintext_len; i++) {
        ciphertext[i] = plaintext[i] ^ counter[i % 16];
    }
    
    ghash(h, aad, aad_len, ciphertext, plaintext_len, tag);
    
    uint8_t ek_j0[16] = {0}; 
    for (int i = 0; i < 16; i++) {
        tag[i] ^= ek_j0[i];
    }
    
    return 0;
}

int gcm_decrypt(const uint8_t *key, size_t key_len,
                const uint8_t *nonce, size_t nonce_len,
                const uint8_t *ciphertext, size_t ciphertext_len,
                const uint8_t *aad, size_t aad_len,
                const uint8_t *tag,
                uint8_t *plaintext) {
    
    uint8_t j0[16];
    generate_j0(nonce, nonce_len, j0);
    
    uint8_t h[16] = {0}; 
    
    uint8_t computed_tag[16];
    ghash(h, aad, aad_len, ciphertext, ciphertext_len, computed_tag);
    
    uint8_t ek_j0[16] = {0}; 
    for (int i = 0; i < 16; i++) {
        computed_tag[i] ^= ek_j0[i];
    }
    
    if (memcmp(computed_tag, tag, 16) != 0) {
        return -1; 
    }
    
    uint8_t counter[16];
    memcpy(counter, j0, 16);
    increment_counter(counter);
    
    for (size_t i = 0; i < ciphertext_len; i++) {
        plaintext[i] = ciphertext[i] ^ counter[i % 16];
    }
    
    return 0;
}