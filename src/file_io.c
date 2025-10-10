#include "file_io.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

#define AES_BLOCK_SIZE 16

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
