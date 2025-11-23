#include "file_io.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

    fread(iv, 1, AES_BLOCK_SIZE, fp);
    size_t payload_len = total - AES_BLOCK_SIZE;
    *ciphertext = malloc(payload_len);
    if (!*ciphertext) {
        fclose(fp);
        return -4;
    }

    fread(*ciphertext, 1, payload_len, fp);
    fclose(fp);
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
    rewind(file);
    
    if (file_size == 0) {
        fclose(file);
        rewind(file);
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