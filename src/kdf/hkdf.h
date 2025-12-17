#ifndef HKDF_H
#define HKDF_H

#include <stddef.h>
#include <stdint.h>


int derive_key(const uint8_t *master_key, size_t master_len,
               const uint8_t *context, size_t context_len,
               size_t length, uint8_t *derived_key);


int derive_key_str(const uint8_t *master_key, size_t master_len,
                   const char *context,
                   size_t length, uint8_t *derived_key);

#endif 