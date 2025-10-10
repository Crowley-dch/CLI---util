#ifndef FILE_IO_H
#define FILE_IO_H

#include <stddef.h>

int read_file(const char *path, unsigned char **data, size_t *len);
int write_file_atomic(const char *path, const unsigned char *data, size_t len);

int write_file_with_iv(const char *path, const unsigned char *iv,
                       const unsigned char *ciphertext, size_t cipher_len);
int read_file_with_iv(const char *path, unsigned char iv[16],
                      unsigned char **ciphertext, size_t *cipher_len);

#endif
