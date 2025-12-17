#include "aead.h"
#include "modes/ctr.h"
#include "mac/hmac.h"
#include "hash/sha256.h"
#include "csprng.h"  
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static void derive_keys(const uint8_t* master_key, size_t key_len,
                        uint8_t* enc_key, uint8_t* mac_key) {
    if (key_len >= 32) {
        memcpy(enc_key, master_key, 16);
        memcpy(mac_key, master_key + 16, 16);
    } else {
        memcpy(enc_key, master_key, key_len);
        memcpy(enc_key + key_len, master_key, 16 - key_len);
        memcpy(mac_key, master_key, key_len);
        memcpy(mac_key + key_len, master_key, 16 - key_len);
    }
}

int etm_encrypt(const uint8_t* plaintext, size_t plaintext_len,
                const uint8_t* key, size_t key_len,
                const uint8_t* iv, size_t iv_len,
                const uint8_t* aad, size_t aad_len,
                uint8_t** ciphertext, size_t* ciphertext_len,
                uint8_t** tag, size_t* tag_len) {
    
    (void)iv_len;  
    
    if (!plaintext || !key || !iv || !ciphertext || !ciphertext_len || !tag || !tag_len) {
        return -1;
    }
    
    uint8_t enc_key[16], mac_key[16];
    derive_keys(key, key_len, enc_key, mac_key);
    
    int rc = encrypt_ctr(plaintext, plaintext_len, enc_key, iv, ciphertext, ciphertext_len);
    if (rc != 0) {
        fprintf(stderr, "ETM: Encryption failed\n");
        return -2;
    }
    
    *tag_len = 32;  
    size_t mac_input_len = *ciphertext_len + aad_len;
    uint8_t* mac_input = malloc(mac_input_len);
    if (!mac_input) {
        free(*ciphertext);
        return -3;
    }
    
    memcpy(mac_input, *ciphertext, *ciphertext_len);
    if (aad_len > 0) {
        memcpy(mac_input + *ciphertext_len, aad, aad_len);
    }
    
    *tag = malloc(*tag_len);
    if (!*tag) {
        free(mac_input);
        free(*ciphertext);
        return -4;
    }
    
    uint8_t hmac_result[32];
    if (hmac_sha256(mac_input, mac_input_len, mac_key, 16, hmac_result) != 0) {
        free(mac_input);
        free(*ciphertext);
        free(*tag);
        return -5;
    }
    
    memcpy(*tag, hmac_result, *tag_len);
    
    free(mac_input);
    return 0;
}

int etm_decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
                const uint8_t* key, size_t key_len,
                const uint8_t* iv, size_t iv_len,
                const uint8_t* aad, size_t aad_len,
                const uint8_t* tag, size_t tag_len,
                uint8_t** plaintext, size_t* plaintext_len) {
    
    (void)iv_len;  
    
    if (!ciphertext || !key || !iv || !tag || !plaintext || !plaintext_len) {
        return -1;
    }
    
    uint8_t enc_key[16], mac_key[16];
    derive_keys(key, key_len, enc_key, mac_key);
    
    size_t mac_input_len = ciphertext_len + aad_len;
    uint8_t* mac_input = malloc(mac_input_len);
    if (!mac_input) {
        return -2;
    }
    
    memcpy(mac_input, ciphertext, ciphertext_len);
    if (aad_len > 0) {
        memcpy(mac_input + ciphertext_len, aad, aad_len);
    }
    
    uint8_t computed_tag[32];
    if (hmac_sha256(mac_input, mac_input_len, mac_key, 16, computed_tag) != 0) {
        free(mac_input);
        return -3;
    }
    
    free(mac_input);
    
    if (tag_len != 32 || memcmp(computed_tag, tag, 32) != 0) {
        fprintf(stderr, "ETM: Authentication failed - invalid tag\n");
        return -4;  
    }
    
    int rc = decrypt_ctr(ciphertext, ciphertext_len, enc_key, iv, plaintext, plaintext_len);
    if (rc != 0) {
        fprintf(stderr, "ETM: Decryption failed after authentication\n");
        return -5;
    }
    
    return 0;
}

int etm_encrypt_file(const char* input_file, const char* output_file,
                     const uint8_t* key, size_t key_len,
                     const uint8_t* aad, size_t aad_len) {
    
    FILE* in = fopen(input_file, "rb");
    if (!in) return -1;
    
    fseek(in, 0, SEEK_END);
    long file_size = ftell(in);
    fseek(in, 0, SEEK_SET);
    
    uint8_t* plaintext = malloc(file_size);
    if (!plaintext) {
        fclose(in);
        return -2;
    }
    
    size_t bytes_read = fread(plaintext, 1, file_size, in);
    if (bytes_read != (size_t)file_size) {
        free(plaintext);
        fclose(in);
        return -3;
    }
    
    fclose(in);
    
    uint8_t iv[16];
    if (generate_random_bytes(iv, 16) != 0) {
        free(plaintext);
        return -4;
    }
    
    uint8_t* ciphertext = NULL;
    size_t ciphertext_len = 0;
    uint8_t* tag = NULL;
    size_t tag_len = 0;
    
    int rc = etm_encrypt(plaintext, file_size, key, key_len,
                        iv, 16, aad, aad_len,
                        &ciphertext, &ciphertext_len,
                        &tag, &tag_len);
    
    free(plaintext);
    
    if (rc == 0) {
        FILE* out = fopen(output_file, "wb");
        if (out) {
            fwrite(iv, 1, 16, out);
            fwrite(ciphertext, 1, ciphertext_len, out);
            fwrite(tag, 1, tag_len, out);
            fclose(out);
        } else {
            rc = -5;
        }
    }
    
    free(ciphertext);
    free(tag);
    
    return rc;
}