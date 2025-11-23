#ifndef CLI_PARSER_H
#define CLI_PARSER_H

#include <stdbool.h>

typedef enum {
    SUBCMD_NONE,    
    SUBCMD_DGST     
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
    
    bool digest_mode;
} cli_args_t;

int parse_cli_args(int argc, char **argv, cli_args_t *out);
void free_cli_args(cli_args_t *args);

int validate_dgst_arguments(cli_args_t *args, const char *prog_name);
int validate_crypto_arguments(cli_args_t *args, const char *prog_name);
char *derive_hash_output_filename(const char *input, const char *algorithm);

#endif