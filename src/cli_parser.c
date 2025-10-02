#define _POSIX_C_SOURCE 200809L
#include "cli_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s --algorithm aes --mode <ecb|cbc|cfb|ofb|ctr> (--encrypt | --decrypt)\n"
        "          --key <hex32> [--iv <hex16>] --input <file> [--output <file>]\n\n"
        "Notes:\n"
        "  key: 32 hex chars (16 bytes). Leading '@' optionally allowed.\n"
        "  iv: 32 hex chars (16 bytes). Only meaningful for decryption; for encryption IV is\n"
        "      generated automatically and prepended to the output file. If provided during\n"
        "      encryption it will be ignored (warning).\n",
        prog);
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
    out->input_path = NULL;
    out->output_path = NULL;

    static struct option long_options[] = {
        {"algorithm", required_argument, 0, 0},
        {"mode", required_argument, 0, 0},
        {"encrypt", no_argument, 0, 0},
        {"decrypt", no_argument, 0, 0},
        {"key", required_argument, 0, 0},
        {"iv", required_argument, 0, 0},
        {"input", required_argument, 0, 0},
        {"output", required_argument, 0, 0},
        {"help", no_argument, 0, 0},
        {0,0,0,0}
    };

    int opt_index = 0;
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
        } else if (strcmp(name, "input") == 0) {
            out->input_path = strdup(optarg);
        } else if (strcmp(name, "output") == 0) {
            out->output_path = strdup(optarg);
        } else if (strcmp(name, "help") == 0) {
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!out->algorithm || strcmp(out->algorithm, "aes") != 0) {
        fprintf(stderr, "Error: --algorithm must be 'aes'\n");
        print_usage(argv[0]); return 2;
    }
    if (!out->mode) {
        fprintf(stderr, "Error: --mode is required\n");
        print_usage(argv[0]); return 2;
    } else {
        const char *m = out->mode;
        if (! (strcmp(m,"ecb")==0 || strcmp(m,"cbc")==0 || strcmp(m,"cfb")==0 ||
               strcmp(m,"ofb")==0 || strcmp(m,"ctr")==0) ) {
            fprintf(stderr, "Error: --mode must be one of: ecb, cbc, cfb, ofb, ctr\n");
            return 2;
        }
    }

    if (out->encrypt == out->decrypt) {
        fprintf(stderr, "Error: specify exactly one of --encrypt or --decrypt\n");
        print_usage(argv[0]); return 2;
    }

    if (!out->key_hex) {
        fprintf(stderr, "Error: --key required\n"); print_usage(argv[0]); return 2;
    }
    if (strlen(out->key_hex) != 32) {
        fprintf(stderr, "Error: key must be 32 hex characters (16 bytes)\n"); return 2;
    }
    if (!is_hex_string(out->key_hex, 32)) {
        fprintf(stderr, "Error: key contains non-hex characters\n"); return 2;
    }

    if (out->iv_hex) {
        if (strlen(out->iv_hex) != 32) {
            fprintf(stderr, "Error: iv must be 32 hex characters (16 bytes) if provided\n"); return 2;
        }
        if (!is_hex_string(out->iv_hex, 32)) {
            fprintf(stderr, "Error: iv contains non-hex characters\n"); return 2;
        }
        if (out->encrypt) {
            fprintf(stderr, "Warning: --iv provided for encryption; it will be ignored (IV is auto-generated).\n");
            free(out->iv_hex);
            out->iv_hex = NULL;
        }
    }

    if (!out->input_path) {
        fprintf(stderr, "Error: --input required\n"); print_usage(argv[0]); return 2;
    }

    if (!out->output_path) {
        out->output_path = derive_output_filename(out->input_path, out->encrypt);
        if (!out->output_path) { fprintf(stderr, "Error: memory\n"); return 2; }
    }

    return 0;
}

void free_cli_args(cli_args_t *args) {
    if (!args) return;
    free(args->algorithm);
    free(args->mode);
    free(args->key_hex);
    free(args->iv_hex);
    free(args->input_path);
    free(args->output_path);
}
