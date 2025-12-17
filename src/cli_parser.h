#ifndef CLI_PARSER_H
#define CLI_PARSER_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

typedef enum {
    SUBCMD_NONE,    
    SUBCMD_DGST, 
    SUBCMD_DERIVE 
} subcommand_t;

typedef struct {
    char *algorithm;
    char *input;
    char *output;
    subcommand_t subcommand;
    
    char *mode;           
    bool encrypt;
    bool decrypt;
    char *key_hex;
    char *iv_hex;       
    char *aad_hex;      
    bool hmac_mode;
    bool cmac_mode;
    char *verify_file;
    bool digest_mode;
    char *password;      
    char *salt_hex;      
    uint32_t iterations;
    size_t key_length;   
    bool generate_salt; 
    char *password_file;
} cli_args_t;

int parse_cli_args(int argc, char **argv, cli_args_t *out);
void free_cli_args(cli_args_t *args);

int validate_dgst_arguments(cli_args_t *args, const char *prog_name);
int validate_crypto_arguments(cli_args_t *args, const char *prog_name);
char *derive_hash_output_filename(const char *input, const char *algorithm);
int validate_derive_arguments(cli_args_t *args, const char *prog_name); 
int is_gcm_mode(const cli_args_t *args);
int is_etm_mode(const cli_args_t *args);
int get_aad_bytes(const cli_args_t *args, uint8_t **aad, size_t *aad_len);
int validate_gcm_nonce(const cli_args_t *args, const char *prog_name);

#endif