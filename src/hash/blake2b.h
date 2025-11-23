#ifndef BLAKE2B_H
#define BLAKE2B_H

#include <stdint.h>
#include <stddef.h>

char* blake2b_hash_hex(const uint8_t *data, size_t len, size_t outlen);
char* blake2b_hash_file_openssl(const char *filename, size_t outlen);

#endif