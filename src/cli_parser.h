#ifndef CLI_PARSER_H
#define CLI_PARSER_H

#include <stdbool.h>

typedef struct {
    char *algorithm;   
    char *mode;       
    bool encrypt;
    bool decrypt;
    char *key_hex;     
    char *input_path;
    char *output_path; 
} cli_args_t;

int parse_cli_args(int argc, char **argv, cli_args_t *out);
void free_cli_args(cli_args_t *args);
char *derive_output_filename(const char *input, int is_encrypt);

#endif 
