#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include "../src/kdf/pbkdf2.h"
#include "../src/kdf/hkdf.h"

#define NUM_SALTS 1000
#define MAX_SALT_LEN 32

void test_salt_uniqueness() {
    printf("Testing salt uniqueness (%d generations)...\n", NUM_SALTS);
    
    uint8_t salts[NUM_SALTS][MAX_SALT_LEN];
    int collisions = 0;
    
    for (int i = 0; i < NUM_SALTS; i++) {
        assert(generate_random_salt(salts[i], 16) == 0);
    }
    
    for (int i = 0; i < NUM_SALTS; i++) {
        for (int j = i + 1; j < NUM_SALTS; j++) {
            if (memcmp(salts[i], salts[j], 16) == 0) {
                collisions++;
                printf("Collision found between salt %d and %d\n", i, j);
            }
        }
    }
    
    if (collisions == 0) {
        printf("✓ All %d salts are unique\n", NUM_SALTS);
    } else {
        printf("✗ Found %d collisions\n", collisions);
        assert(collisions == 0);
    }
}

void test_performance() {
    printf("\nTesting performance...\n");
    
    const char *password = "PerformanceTestPassword123!";
    const char *salt = "PerformanceTestSalt";
    
    uint32_t iterations[] = {10000, 100000, 1000000};
    const char *labels[] = {"10k", "100k", "1M"};
    size_t num_tests = sizeof(iterations) / sizeof(iterations[0]);
    
    uint8_t derived_key[32];
    
    for (size_t i = 0; i < num_tests; i++) {
        clock_t start = clock();
        
        int result = pbkdf2_hmac_sha256(
            (uint8_t*)password, strlen(password),
            (uint8_t*)salt, strlen(salt),
            iterations[i], 32, derived_key);
        
        clock_t end = clock();
        double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
        
        assert(result == 0);
        
        printf("  %s iterations: %.3f seconds (%.0f iterations/second)\n",
               labels[i], elapsed, iterations[i] / elapsed);
    }
}

void test_key_hierarchy() {
    printf("\nTesting key hierarchy function...\n");
    
    uint8_t master_key[32];
    for (int i = 0; i < 32; i++) {
        master_key[i] = i;
    }
    
    uint8_t key_enc[32], key_auth[32], key_mac[32];
    
    assert(derive_key_str(master_key, 32, "encryption", 32, key_enc) == 0);
    assert(derive_key_str(master_key, 32, "authentication", 32, key_auth) == 0);
    assert(derive_key_str(master_key, 32, "mac", 32, key_mac) == 0);
    
    assert(memcmp(key_enc, key_auth, 32) != 0);
    assert(memcmp(key_enc, key_mac, 32) != 0);
    assert(memcmp(key_auth, key_mac, 32) != 0);
    
    uint8_t key_enc2[32];
    assert(derive_key_str(master_key, 32, "encryption", 32, key_enc2) == 0);
    assert(memcmp(key_enc, key_enc2, 32) == 0);
    
    printf("✓ Key hierarchy: different contexts produce different keys\n");
    printf("✓ Key hierarchy: deterministic (same input = same output)\n");
}

void test_various_lengths() {
    printf("\nTesting various key lengths...\n");
    
    const char *password = "test";
    const char *salt = "salt";
    
    size_t lengths[] = {1, 16, 31, 32, 33, 64, 100, 255, 256};
    size_t num_lengths = sizeof(lengths) / sizeof(lengths[0]);
    
    for (size_t i = 0; i < num_lengths; i++) {
        uint8_t *key = malloc(lengths[i]);
        assert(key != NULL);
        
        int result = pbkdf2_hmac_sha256(
            (uint8_t*)password, strlen(password),
            (uint8_t*)salt, strlen(salt),
            100, lengths[i], key);
        
        assert(result == 0);
        
        int all_zero = 1;
        for (size_t j = 0; j < lengths[i]; j++) {
            if (key[j] != 0) {
                all_zero = 0;
                break;
            }
        }
        assert(all_zero == 0);
        
        free(key);
    }
    
    printf("✓ All lengths (1-256 bytes) work correctly\n");
}

int main() {
    printf("=== Comprehensive KDF Tests ===\n\n");
    
    test_salt_uniqueness();
    test_performance();
    test_key_hierarchy();
    test_various_lengths();
    
    printf("\n=== All tests passed! ===\n");
    return 0;
}