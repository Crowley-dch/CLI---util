#include "gcm.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int gcm_encrypt(const uint8_t* plaintext, size_t plaintext_len,
                const uint8_t* key, size_t key_len,
                const uint8_t* nonce, size_t nonce_len,
                const uint8_t* aad, size_t aad_len,
                uint8_t* ciphertext,
                uint8_t* tag, size_t tag_len) {
    (void)key_len; 
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP context\n");
        return -1;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "Failed to init AES-GCM\n");
        EVP_CIPHER_CTX_free(ctx);
        return -2;
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1) {
        fprintf(stderr, "Failed to set IV length\n");
        EVP_CIPHER_CTX_free(ctx);
        return -3;
    }
    
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        fprintf(stderr, "Failed to set key and IV\n");
        EVP_CIPHER_CTX_free(ctx);
        return -4;
    }
    
    int len;
    
    if (aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
            fprintf(stderr, "Failed to process AAD\n");
            EVP_CIPHER_CTX_free(ctx);
            return -5;
        }
    }
    
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        fprintf(stderr, "Failed to encrypt\n");
        EVP_CIPHER_CTX_free(ctx);
        return -6;
    }
    int ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        fprintf(stderr, "Failed to finalize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return -7;
    }
    ciphertext_len += len;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag) != 1) {
        fprintf(stderr, "Failed to get authentication tag\n");
        EVP_CIPHER_CTX_free(ctx);
        return -8;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int gcm_decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
                const uint8_t* key, size_t key_len,
                const uint8_t* nonce, size_t nonce_len,
                const uint8_t* aad, size_t aad_len,
                const uint8_t* tag, size_t tag_len,
                uint8_t* plaintext) {
    (void)key_len; 
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP context\n");
        return -1;
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "Failed to init AES-GCM\n");
        EVP_CIPHER_CTX_free(ctx);
        return -2;
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1) {
        fprintf(stderr, "Failed to set IV length\n");
        EVP_CIPHER_CTX_free(ctx);
        return -3;
    }
    
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        fprintf(stderr, "Failed to set key and IV\n");
        EVP_CIPHER_CTX_free(ctx);
        return -4;
    }
    
    int len;
    
    if (aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
            fprintf(stderr, "Failed to process AAD\n");
            EVP_CIPHER_CTX_free(ctx);
            return -5;
        }
    }
    
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        fprintf(stderr, "Failed to decrypt\n");
        EVP_CIPHER_CTX_free(ctx);
        return -6;
    }
    int plaintext_len = len;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, (void*)tag) != 1) {
        fprintf(stderr, "Failed to set authentication tag\n");
        EVP_CIPHER_CTX_free(ctx);
        return -7;
    }
    
    int final_len;
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &final_len) != 1) {
        fprintf(stderr, "Authentication failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -8;  
    }
    
    plaintext_len += final_len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}