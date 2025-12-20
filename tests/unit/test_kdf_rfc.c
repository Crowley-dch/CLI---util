#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../src/kdf/pbkdf2.h"

void test_rfc_6070() {
    printf("=== PBKDF2 RFC 6070 Tests ===\n\n");
    
    {
        const char *password = "password";
        const char *salt = "salt";
        
        uint8_t derived_key[20];
        int result = pbkdf2_hmac_sha256(
            (uint8_t*)password, strlen(password),
            (uint8_t*)salt, strlen(salt),
            1, 20, derived_key);
        
        assert(result == 0);
        
        uint8_t expected[] = {
            0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
            0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
            0x2f, 0xe0, 0x37, 0xa6
        };
        
        printf("Test 1 (iterations=1): ");
        if (memcmp(derived_key, expected, 20) == 0) {
            printf("✓ PASS\n");
        } else {
            printf("✗ FAIL\n");
            printf("Got:      ");
            for (int i = 0; i < 20; i++) printf("%02x", derived_key[i]);
            printf("\nExpected: ");
            for (int i = 0; i < 20; i++) printf("%02x", expected[i]);
            printf("\n");
            assert(0);
        }
    }
    
    {
        const char *password = "password";
        const char *salt = "salt";
        
        uint8_t derived_key[20];
        int result = pbkdf2_hmac_sha256(
            (uint8_t*)password, strlen(password),
            (uint8_t*)salt, strlen(salt),
            2, 20, derived_key);
        
        assert(result == 0);
        
        uint8_t expected[] = {
            0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c,
            0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0,
            0xd8, 0xde, 0x89, 0x57
        };
        
        printf("Test 2 (iterations=2): ");
        if (memcmp(derived_key, expected, 20) == 0) {
            printf("✓ PASS\n");
        } else {
            printf("✗ FAIL\n");
            assert(0);
        }
    }
    
    printf("\nAll RFC 6070 tests passed!\n");
}

int main() {
    test_rfc_6070();
    return 0;
}