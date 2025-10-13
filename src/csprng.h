#ifndef CSPRNG_H
#define CSPRNG_H

#include <stddef.h>

int generate_random_bytes(unsigned char *buffer, size_t num_bytes);

#endif 
