#define _POSIX_C_SOURCE 200809L
#include "cli_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>

int is_gcm_mode(const cli_args_t *args) {
    return args->mode && strcmp(args->mode, "gcm") == 0;
}

int is_etm_mode(const cli_args_t *args) {
    return args->mode && strcmp(args->mode, "etm") == 0;
}

int get_aad_bytes(const cli_args_t *args, uint8_t **aad, size_t *aad_len) {
    if (!args->aad_hex) {
        *aad = NULL;
        *aad_len = 0;
        return 0; 
    }
    
    size_t hex_len = strlen(args->aad_hex);
    if (hex_len % 2 != 0) {
        return -1; 
    }
    
    *aad_len = hex_len / 2;
    *aad = malloc(*aad_len);
    if (!*aad) {
        return -2;
    }
    
    for (size_t i = 0; i < *aad_len; i++) {
        unsigned int byte;
        if (sscanf(args->aad_hex + i*2, "%2x", &byte) != 1) {
            free(*aad);
            return -3;
        }
        (*aad)[i] = (uint8_t)byte;
    }
    
    return 0;
}

int validate_gcm_nonce(const cli_args_t *args, const char *prog_name) {
    (void)prog_name;
    
    if (!args->iv_hex) {
        return 0; 
    }
    
    size_t iv_len = strlen(args->iv_hex);
    
    if (iv_len != 24) {
        fprintf(stderr, "Warning: GCM typically uses 12-byte nonce (24 hex chars)\n");
        fprintf(stderr, "Got %zu hex chars, which is %zu bytes\n", iv_len, iv_len/2);
    }
    
    for (size_t i = 0; i < iv_len; ++i) {
        char c = args->iv_hex[i];
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) {
            fprintf(stderr, "Error: Invalid nonce format. Must be hexadecimal.\n");
            return -1;
        }
    }
    
    return 0;
}

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  Encryption/decryption:\n"
        "    %s --algorithm aes --mode <ecb|cbc|cfb|ofb|ctr|gcm|etm> (--encrypt | --decrypt)\n"
        "       --key <hex32> [--iv <hex16/hex24>] [--aad <hex>] --input <file> [--output <file>]\n\n"
        "  Hashing (dgst command):\n"
        "    %s dgst --algorithm <sha256|blake2b> --input <file> [--output <file>]\n"
        "    %s dgst --algorithm sha256 --hmac --key <hex> --input <file> [--verify <file>]\n\n"
        "Notes:\n"
        "  key: 32 hex chars (16 bytes). Leading '@' optionally allowed.\n"
        "  iv: 32 hex chars (16 bytes) for CBC/CFB/OFB/CTR\n"
        "  iv: 24 hex chars (12 bytes) for GCM (nonce, optional)\n"
        "  aad: hex string for GCM/ETM modes (optional, authenticated but not encrypted)\n"
        "  modes: ecb, cbc, cfb, ofb, ctr, gcm, etm\n"
        "  hash algorithms: sha256, blake2b\n",
        prog, prog, prog
    );
}

char *derive_output_filename(const char *input, int is_encrypt) {
    size_t len = strlen(input);

    if (is_encrypt) {
        char *out = malloc(len + 5);
        if (!out) return NULL;
        sprintf(out, "%s.enc", input);
        return out;
    } else {
        const char *suf = ".enc";
        size_t suf_len = strlen(suf);

        if (len > suf_len && strcmp(input + len - suf_len, suf) == 0) {
            char *out = malloc(len - suf_len + 5);
            if (!out) return NULL;

            strncpy(out, input, len - suf_len);
            out[len - suf_len] = '\0';
            strcat(out, ".dec");
            return out;
        } else {
            char *out = malloc(len + 5);
            if (!out) return NULL;
            sprintf(out, "%s.dec", input);
            return out;
        }
    }
}

char *derive_hash_output_filename(const char *input, const char *algorithm) {
    size_t len = strlen(input);
    char *out = malloc(len + 10); 
    
    if (!out) return NULL;
    
    if (strcmp(algorithm, "sha256") == 0) {
        sprintf(out, "%s.sha256", input);
    } else if (strcmp(algorithm, "blake2b") == 0) {
        sprintf(out, "%s.blake2b", input);
    } else {
        sprintf(out, "%s.hash", input); 
    }
    
    return out;
}

static int is_hex_string(const char *s, size_t expect_len) {
    if (!s) return 0;
    if (strlen(s) != expect_len) return 0;

    for (size_t i = 0; i < expect_len; ++i) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) {
            return 0;
        }
    }
    return 1;
}

int parse_cli_args(int argc, char **argv, cli_args_t *out) {
    if (!out) return -1;

    out->algorithm = NULL;
    out->mode = NULL;
    out->encrypt = false;
    out->decrypt = false;
    out->key_hex = NULL;
    out->iv_hex = NULL;
    out->aad_hex = NULL;  
    out->input = NULL;
    out->output = NULL;
    out->digest_mode = false;
    out->subcommand = SUBCMD_NONE;
    out->hmac_mode = false;
    out->cmac_mode = false;
    out->verify_file = NULL;

    if (argc >= 2 && strcmp(argv[1], "dgst") == 0) {
        out->subcommand = SUBCMD_DGST;
        argc--;
        argv++;
    }

    static struct option long_options[] = {
        {"algorithm", required_argument, 0, 0},
        {"mode", required_argument, 0, 0},
        {"encrypt", no_argument, 0, 0},
        {"decrypt", no_argument, 0, 0},
        {"key", required_argument, 0, 0},
        {"iv", required_argument, 0, 0},
        {"aad", required_argument, 0, 0},      
        {"input", required_argument, 0, 0},
        {"output", required_argument, 0, 0},
        {"help", no_argument, 0, 0},
        {"hmac", no_argument, 0, 0},           
        {"cmac", no_argument, 0, 0},           
        {"verify", required_argument, 0, 0}, 
        {0, 0, 0, 0}
    };

    int opt_index = 0;
    optind = 1; 

    while (1) {
        int c = getopt_long(argc, argv, "", long_options, &opt_index);
        if (c == -1) break;
        if (c != 0) continue;

        const char *name = long_options[opt_index].name;

        if (strcmp(name, "algorithm") == 0) {
            out->algorithm = strdup(optarg);
        } else if (strcmp(name, "mode") == 0) {
            out->mode = strdup(optarg);
        } else if (strcmp(name, "encrypt") == 0) {
            out->encrypt = true;
        } else if (strcmp(name, "decrypt") == 0) {
            out->decrypt = true;
        } else if (strcmp(name, "key") == 0) {
            if (optarg[0] == '@') out->key_hex = strdup(optarg + 1);
            else out->key_hex = strdup(optarg);
        } else if (strcmp(name, "iv") == 0) {
            if (optarg[0] == '@') out->iv_hex = strdup(optarg + 1);
            else out->iv_hex = strdup(optarg);
        } else if (strcmp(name, "aad") == 0) {
            out->aad_hex = strdup(optarg);
        } else if (strcmp(name, "input") == 0) {
            out->input = strdup(optarg);
        } else if (strcmp(name, "output") == 0) {
            out->output = strdup(optarg);
        } else if (strcmp(name, "hmac") == 0) {
            out->hmac_mode = true;
        } else if (strcmp(name, "cmac") == 0) {
            out->cmac_mode = true;
        } else if (strcmp(name, "verify") == 0) {
            out->verify_file = strdup(optarg);
        } else if (strcmp(name, "help") == 0) {
            print_usage(argv[0]);
            return 1;
        }
    }

    if (out->subcommand == SUBCMD_DGST) {
        return validate_dgst_arguments(out, argv[0]);
    }

    return validate_crypto_arguments(out, argv[0]);
}

int validate_dgst_arguments(cli_args_t *args, const char *prog_name) {
    (void)prog_name;
    
    if (args->hmac_mode && !args->key_hex) {
        fprintf(stderr, "Error: --key is required when using --hmac\n");
        return 2;
    }
    
    if (args->verify_file) {
        FILE *test = fopen(args->verify_file, "r");
        if (!test) {
            fprintf(stderr, "Error: Verify file '%s' cannot be opened\n", args->verify_file);
            return 2;
        }
        fclose(test);
    }
    
    if (!args->algorithm) {
        fprintf(stderr, "Error: --algorithm is required for dgst command\n");
        fprintf(stderr, "Supported algorithms: sha256, blake2b\n");
        return 2;
    }

    if (strcmp(args->algorithm, "sha256") != 0 && 
        strcmp(args->algorithm, "blake2b") != 0) {
        fprintf(stderr, "Error: Unsupported hash algorithm '%s'\n", args->algorithm);
        fprintf(stderr, "Supported algorithms: sha256, blake2b\n");
        return 2;
    }

    if (args->mode) {
        fprintf(stderr, "Error: --mode cannot be used with dgst command\n");
        return 2;
    }
    
    if (args->encrypt || args->decrypt) {
        fprintf(stderr, "Error: --encrypt/--decrypt cannot be used with dgst command\n");
        return 2;
    }
    
    if (args->key_hex && !args->hmac_mode) {
        fprintf(stderr, "Error: --key cannot be used without --hmac flag\n");
        return 2;
    }
    
    if (args->iv_hex) {
        fprintf(stderr, "Error: --iv cannot be used with dgst command\n");
        return 2;
    }
    
    if (args->aad_hex) {
        fprintf(stderr, "Error: --aad cannot be used with dgst command\n");
        return 2;
    }

    if (!args->input) {
        fprintf(stderr, "Error: --input is required for dgst command\n");
        return 2;
    }

    if (!args->output) {
        args->output = derive_hash_output_filename(args->input, args->algorithm);
        if (!args->output) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            return 2;
        }
    }

    return 0;
}

int validate_crypto_arguments(cli_args_t *args, const char *prog_name) {
    if (!args->algorithm || strcmp(args->algorithm, "aes") != 0) {
        fprintf(stderr, "Error: --algorithm must be 'aes'\n");
        print_usage(prog_name);
        return 2;
    }

    if (!args->mode) {
        fprintf(stderr, "Error: --mode is required\n");
        print_usage(prog_name);
        return 2;
    } else {
        const char *m = args->mode;
        if (!(strcmp(m,"ecb")==0 || strcmp(m,"cbc")==0 || 
              strcmp(m,"cfb")==0 || strcmp(m,"ofb")==0 || 
              strcmp(m,"ctr")==0 || strcmp(m,"gcm")==0 ||
              strcmp(m,"etm")==0)) {
            fprintf(stderr, "Error: invalid mode '%s'\n", m);
            fprintf(stderr, "Supported modes: ecb, cbc, cfb, ofb, ctr, gcm, etm\n");
            return 2;
        }
    }
    
    if (args->aad_hex && !is_gcm_mode(args) && !is_etm_mode(args)) {
        fprintf(stderr, "Error: --aad can only be used with --mode gcm or etm\n");
        return 2;
    }

    if (args->encrypt == args->decrypt) {
        fprintf(stderr, "Error: specify exactly one of --encrypt or --decrypt\n");
        return 2;
    }

    if (!args->key_hex && args->decrypt) {
        fprintf(stderr, "Error: --key required for decryption\n");
        return 2;
    }

    if (args->key_hex) {
        if (!is_hex_string(args->key_hex, 32)) {
            fprintf(stderr, "Error: key must be exactly 32 hex chars\n");
            return 2;
        }
    }

    if (args->iv_hex) {
        if (is_gcm_mode(args)) {
            if (validate_gcm_nonce(args, prog_name) != 0) {
                return 2;
            }
        } else {
            if (!is_hex_string(args->iv_hex, 32)) {
                fprintf(stderr, "Error: iv must be 32 hex chars\n");
                return 2;
            }
            if (args->encrypt) {
                fprintf(stderr, "Warning: --iv ignored during encryption\n");
                free(args->iv_hex);
                args->iv_hex = NULL;
            }
        }
    }

    if (!args->input) {
        fprintf(stderr, "Error: --input required\n");
        return 2;
    }

    if (!args->output) {
        args->output = derive_output_filename(args->input, args->encrypt);
        if (!args->output) {
            fprintf(stderr, "Error: memory\n");
            return 2;
        }
    }

    return 0;
}

void free_cli_args(cli_args_t *args) {
    if (!args) return;
    free(args->algorithm);
    free(args->mode);
    free(args->key_hex);
    free(args->iv_hex);
    free(args->aad_hex);  
    free(args->input);
    free(args->output);
    if (args->verify_file) free(args->verify_file);
}