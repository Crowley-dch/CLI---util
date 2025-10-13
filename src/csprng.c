#define _POSIX_C_SOURCE 200809L
#include "csprng.h"
#include <openssl/rand.h>
#include <stdio.h>

int generate_random_bytes(unsigned char *buffer, size_t num_bytes) {
    if (!buffer || num_bytes == 0) return -1;
    if (RAND_bytes(buffer, (int)num_bytes) != 1) {
        fprintf(stderr, "[ERROR] RAND_bytes() failed to generate secure random data.\n");
        return -2;
    }
    return 0;
}