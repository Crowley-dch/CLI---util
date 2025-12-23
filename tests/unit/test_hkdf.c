#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "src/kdf/hkdf.h"

int main() {
    printf("=== HKDF Tests ===\n\n");
    
    uint8_t master_key[32];
    for (int i = 0; i < 32; i++) {
        master_key[i] = i;
    }
    
    {
        uint8_t key_enc[32], key_auth[32], key_mac[32];
        
        assert(derive_key_str(master_key, 32, "encryption", 32, key_enc) == 0);
        assert(derive_key_str(master_key, 32, "authentication", 32, key_auth) == 0);
        assert(derive_key_str(master_key, 32, "mac", 32, key_mac) == 0);
        
        assert(memcmp(key_enc, key_auth, 32) != 0);
        assert(memcmp(key_enc, key_mac, 32) != 0);
        assert(memcmp(key_auth, key_mac, 32) != 0);
        
        printf("Test 1 (context separation): ✓ PASS\n");
    }
    
    {
        uint8_t key1[32], key2[32];
        
        assert(derive_key_str(master_key, 32, "test_context", 32, key1) == 0);
        assert(derive_key_str(master_key, 32, "test_context", 32, key2) == 0);
        
        assert(memcmp(key1, key2, 32) == 0);
        
        printf("Test 2 (deterministic): ✓ PASS\n");
    }
    
    {
        uint8_t key16[16], key32[32], key64[64];
        
        assert(derive_key_str(master_key, 32, "length_test", 16, key16) == 0);
        assert(derive_key_str(master_key, 32, "length_test", 32, key32) == 0);
        assert(derive_key_str(master_key, 32, "length_test", 64, key64) == 0);
        
        assert(memcmp(key16, key32, 16) == 0);
        assert(memcmp(key16, key64, 16) == 0);
        
        printf("Test 3 (various lengths): ✓ PASS\n");
    }
    
    printf("\nAll HKDF tests passed!\n");
    return 0;
}