#include "blake2b.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* blake2b_hash_file_openssl(const char *filename, size_t outlen) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        return NULL;
    }
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_blake2b512(); 
    
    if (!md || !ctx || EVP_DigestInit_ex(ctx, md, NULL) != 1) {
        if (ctx) EVP_MD_CTX_free(ctx);
        fclose(file);
        return NULL;
    }
    
    const size_t BUFFER_SIZE = 8192;
    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, bytes_read) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(file);
            return NULL;
        }
    }
    
    if (ferror(file)) {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return NULL;
    }
    
    unsigned char hash[64];
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return NULL;
    }
    
    EVP_MD_CTX_free(ctx);
    fclose(file);
    
    if (outlen > hash_len) outlen = hash_len;
    
    char *hex_hash = malloc(outlen * 2 + 1);
    if (!hex_hash) {
        return NULL;
    }
    
    for (size_t i = 0; i < outlen; i++) {
        sprintf(hex_hash + i * 2, "%02x", hash[i]);
    }
    hex_hash[outlen * 2] = '\0';
    
    return hex_hash;
}