#ifndef FILE_IO_H
#define FILE_IO_H

#include <stddef.h>
#include <stdint.h>

#define AES_BLOCK_SIZE 16

int read_file(const char *path, unsigned char **data, size_t *len);
int write_file_atomic(const char *path, const unsigned char *data, size_t len);
int write_file_with_iv(const char *path, const unsigned char *iv,
                      const unsigned char *ciphertext, size_t cipher_len);
int read_file_with_iv(const char *path, unsigned char iv[16],
                     unsigned char **ciphertext, size_t *cipher_len);


#define HASH_SUCCESS 0
#define HASH_ERROR_INVALID_PARAMS -1
#define HASH_ERROR_FILE_OPEN -2
#define HASH_ERROR_FILE_READ -3
#define HASH_ERROR_FILE_WRITE -4
#define HASH_ERROR_UNSUPPORTED_ALGORITHM -5
#define HASH_ERROR_EMPTY_FILE -6
#define HASH_ERROR_MEMORY -7
#define HASH_ERROR_OPENSSL -8

int write_hash_to_file(const char *output_path, const char *hash_value, const char *input_file);

const char* get_hash_error_message(int error_code);
void print_hash_error(const char *context, int error_code, const char *filename);
int file_exists(const char *filename);

int compute_file_hash_stream(const char *filename, 
                           const char *algorithm,
                           char **hex_hash,
                           int (*update_func)(const unsigned char *, size_t),
                           int (*final_func)(unsigned char *));

int read_hmac_from_file(const char *filename, char *hmac_buffer, size_t buffer_size); // IO-2
int verify_hmac_file(const char *input_file, const char *hmac_file, 
                    const uint8_t *key, size_t key_len, int *verification_result); 
#endif