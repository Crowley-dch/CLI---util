#include "file_io.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mac/hmac.h" 
#include <openssl/rand.h>
#include <errno.h>

#define AES_BLOCK_SIZE 16
#define HASH_BUFFER_SIZE 8192  

int read_file(const char *path, unsigned char **data, size_t *len) {
    if (!path || !data || !len) return -1;
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror("[ERROR] Could not open input file");
        return -2;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -3;
    }
    long fsize = ftell(fp);
    if (fsize < 0) {
        fclose(fp);
        return -4;
    }
    rewind(fp);
    *data = malloc(fsize);
    if (!*data) {
        fclose(fp);
        return -5;
    }
    size_t n = fread(*data, 1, fsize, fp);
    fclose(fp);
    if (n != (size_t)fsize) {
        free(*data);
        return -6;
    }
    *len = n;
    return 0;
}

int write_file_atomic(const char *path, const unsigned char *data, size_t len) {
    if (!path || !data) return -1;
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        perror("[ERROR] Could not open output file");
        return -2;
    }
    size_t n = fwrite(data, 1, len, fp);
    fclose(fp);
    if (n != len) return -3;
    printf("[INFO] Wrote %zu bytes to %s (atomic)\n", len, path);
    return 0;
}

int write_file_with_iv(const char *path, const unsigned char *iv,
                       const unsigned char *ciphertext, size_t cipher_len) {
    if (!path || !iv || !ciphertext) return -1;
    FILE *fp = fopen(path, "wb");
    if (!fp) return -2;
    fwrite(iv, 1, AES_BLOCK_SIZE, fp);
    fwrite(ciphertext, 1, cipher_len, fp);
    fclose(fp);
    printf("[INFO] Wrote %zu bytes (IV + ciphertext) to %s\n",
           cipher_len + AES_BLOCK_SIZE, path);
    return 0;
}

int read_file_with_iv(const char *path, unsigned char iv[16],
                      unsigned char **ciphertext, size_t *cipher_len) {
    if (!path || !iv || !ciphertext || !cipher_len) return -1;
    FILE *fp = fopen(path, "rb");
    if (!fp) return -2;

    fseek(fp, 0, SEEK_END);
    long total = ftell(fp);
    rewind(fp);
    if (total < AES_BLOCK_SIZE) {
        fclose(fp);
        fprintf(stderr, "[ERROR] File too short to contain IV\n");
        return -3;
    }

    size_t bytes_read = fread(iv, 1, AES_BLOCK_SIZE, fp);
    if (bytes_read != AES_BLOCK_SIZE) {
        fclose(fp);
        fprintf(stderr, "[ERROR] Failed to read IV from file\n");
        return -4;
    }

    size_t payload_len = total - AES_BLOCK_SIZE;
    *ciphertext = malloc(payload_len);
    if (!*ciphertext) {
        fclose(fp);
        return -5;
    }

    bytes_read = fread(*ciphertext, 1, payload_len, fp);
    fclose(fp);
    
    if (bytes_read != payload_len) {
        free(*ciphertext);
        fprintf(stderr, "[ERROR] Failed to read ciphertext from file\n");
        return -6;
    }
    
    *cipher_len = payload_len;
    printf("[INFO] Read file %s (%ld bytes, IV + ciphertext)\n", path, total);
    return 0;
}

int write_hash_to_file(const char *output_path, const char *hash_value, const char *input_file) {
    if (!output_path || !hash_value || !input_file) {
        fprintf(stderr, "[ERROR] Invalid parameters for hash output\n");
        return -1;
    }
    
    FILE *fp = fopen(output_path, "w");
    if (!fp) {
        fprintf(stderr, "[ERROR] Cannot create output file '%s': %s\n", 
                output_path, strerror(errno));
        return -2;
    }
    
    if (fprintf(fp, "%s  %s\n", hash_value, input_file) < 0) {
        fclose(fp);
        fprintf(stderr, "[ERROR] Write failed to '%s'\n", output_path);
        return -3;
    }
    
    fclose(fp);
    printf("[INFO] Hash written to: %s\n", output_path);
    return 0;
}

const char* get_hash_error_message(int error_code) {
    switch (error_code) {
        case HASH_ERROR_FILE_OPEN:
            return "Cannot open input file";
        case HASH_ERROR_FILE_READ:
            return "Read error from input file";
        case HASH_ERROR_FILE_WRITE:
            return "Write error to output file";
        case HASH_ERROR_UNSUPPORTED_ALGORITHM:
            return "Unsupported hash algorithm";
        case HASH_ERROR_EMPTY_FILE:
            return "Empty input file";
        case HASH_ERROR_MEMORY:
            return "Memory allocation failed";
        case HASH_ERROR_OPENSSL:
            return "OpenSSL internal error";
        default:
            return "Unknown hash error";
    }
}

void print_hash_error(const char *context, int error_code, const char *filename) {
    fprintf(stderr, "[ERROR] %s: %s", context, get_hash_error_message(error_code));
    if (filename) {
        fprintf(stderr, " (file: %s)", filename);
    }
    fprintf(stderr, "\n");
    
    if (error_code == HASH_ERROR_FILE_OPEN || error_code == HASH_ERROR_FILE_READ) {
        fprintf(stderr, "       System error: %s\n", strerror(errno));
    }
}

int file_exists(const char *filename) {
    if (!filename) return 0;
    FILE *fp = fopen(filename, "rb");
    if (fp) {
        fclose(fp);
        return 1;
    }
    return 0;
}

int compute_file_hash_stream(const char *filename, 
                           const char *algorithm,
                           char **hex_hash,
                           int (*update_func)(const unsigned char *, size_t),
                           int (*final_func)(unsigned char *)) {
    if (!filename || !algorithm || !update_func || !final_func) {
        return HASH_ERROR_INVALID_PARAMS;
    }
    
    if (!file_exists(filename)) {
        return HASH_ERROR_FILE_OPEN;
    }
    
    FILE *file = fopen(filename, "rb"); 
    if (!file) {
        return HASH_ERROR_FILE_OPEN;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    
    // ИСПРАВЛЕНО: используем fseek вместо rewind после fclose
    fseek(file, 0, SEEK_SET);
    
    if (file_size == 0) {
        // Для пустого файла - просто закрываем
        fclose(file);
        // Не вызываем rewind после fclose!
    }
    
    unsigned char buffer[HASH_BUFFER_SIZE];
    size_t bytes_read;
    int result = HASH_SUCCESS;
    
    while ((bytes_read = fread(buffer, 1, HASH_BUFFER_SIZE, file)) > 0) {
        if (update_func(buffer, bytes_read) != 0) {
            result = HASH_ERROR_OPENSSL;
            break;
        }
    }
    
    if (ferror(file)) {
        result = HASH_ERROR_FILE_READ;
    }
    
    if (result == HASH_SUCCESS) {
        unsigned char hash[64];
        if (final_func(hash) != 0) {
            result = HASH_ERROR_OPENSSL;
        } else {
            size_t hash_len = (strcmp(algorithm, "sha256") == 0) ? 32 : 32; 
            *hex_hash = malloc(hash_len * 2 + 1);
            if (!*hex_hash) {
                result = HASH_ERROR_MEMORY;
            } else {
                for (size_t i = 0; i < hash_len; i++) {
                    sprintf(*hex_hash + i * 2, "%02x", hash[i]); 
                }
                (*hex_hash)[hash_len * 2] = '\0';
            }
        }
    }
    
    fclose(file);
    return result;
}

int read_hmac_from_file(const char *filename, char *hmac_buffer, size_t buffer_size) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        return -1;
    }
    
    if (fgets(hmac_buffer, buffer_size, file) == NULL) {
        fclose(file);
        return -2;
    }
    
    fclose(file);
    
    size_t len = strlen(hmac_buffer);
    if (len > 0 && hmac_buffer[len-1] == '\n') {
        hmac_buffer[len-1] = '\0';
    }
    
    return 0;
}

int verify_hmac_file(const char *input_file, const char *hmac_file, 
                    const uint8_t *key, size_t key_len, int *verification_result) {
    uint8_t computed_hmac[32];
    char expected_hmac_hex[65];
    
    if (hmac_sha256_file(input_file, key, key_len, computed_hmac) != 0) {
        return -1; 
    }
    
    if (read_hmac_from_file(hmac_file, expected_hmac_hex, sizeof(expected_hmac_hex)) != 0) {
        return -2; 
    }
    
    char expected_hash_part[65];
    strncpy(expected_hash_part, expected_hmac_hex, 64);
    expected_hash_part[64] = '\0';
    
    char computed_hmac_hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(computed_hmac_hex + i*2, "%02x", computed_hmac[i]);
    }
    computed_hmac_hex[64] = '\0';
    

    *verification_result = (strcmp(computed_hmac_hex, expected_hash_part) == 0);
    
    return 0; 
}