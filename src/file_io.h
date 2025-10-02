#ifndef FILE_IO_H
#define FILE_IO_H

#include <stddef.h>

int read_file(const char *path, unsigned char **out_buf, size_t *out_len);
int write_file_atomic(const char *path, const unsigned char *data, size_t data_len);

#endif 