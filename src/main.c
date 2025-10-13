#define _POSIX_C_SOURCE 200809L

#include "cli_parser.h"
#include "file_io.h"
#include "ecb.h"
#include "modes/cbc.h"
#include "modes/cfb.h"
#include "modes/ofb.h"
#include "modes/ctr.h"
#include "csprng.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AES_BLOCK_SIZE 16

static int hex_to_bytes_local(const char *hex, unsigned char *out, size_t out_len);
static void print_hex(const unsigned char *data, size_t len);

int main(int argc, char **argv) {
    int rc = 0;

    cli_args_t args;
    memset(&args, 0, sizeof(args));

    if (parse_cli_args(argc, argv, &args) != 0) {
        return 1;
    }

    unsigned char key[16];
    int key_from_user = 0;
    if (args.key_hex) {
        if (hex_to_bytes_local(args.key_hex, key, sizeof(key)) != 0) {
            fprintf(stderr, "[ERROR] Invalid key hex\n");
            free_cli_args(&args);
            return 2;
        }
        key_from_user = 1;
    } else {
    }

    unsigned char iv[AES_BLOCK_SIZE];
    int iv_from_user = 0;
    if (args.iv_hex) {
        if (hex_to_bytes_local(args.iv_hex, iv, AES_BLOCK_SIZE) != 0) {
            fprintf(stderr, "[ERROR] Invalid IV hex\n");
            free_cli_args(&args);
            return 3;
        }
        iv_from_user = 1;
    }

    unsigned char *inbuf = NULL;
    size_t inlen = 0;
    unsigned char *cipher_in = NULL;
    size_t cipher_in_len = 0;
    unsigned char *outbuf = NULL;
    size_t outlen = 0;

    if (args.encrypt) {
        if (read_file(args.input, &inbuf, &inlen) != 0) {
            fprintf(stderr, "[ERROR] Failed to read input file '%s'\n", args.input);
            rc = 10;
            goto cleanup;
        }

        if (!key_from_user) {
            if (generate_random_bytes(key, sizeof(key)) != 0) {
                fprintf(stderr, "[ERROR] Failed to generate random key\n");
                rc = 11;
                goto cleanup;
            }
            printf("[INFO] Generated random key: ");
            print_hex(key, sizeof(key));
            printf("\n");
            key_from_user = 1;
        }

        if (strcmp(args.mode, "ecb") == 0) {
            rc = encrypt_ecb(inbuf, inlen, key, &outbuf, &outlen);
            if (rc == 0)
                rc = write_file_atomic(args.output, outbuf, outlen);
        } else {
            if (generate_random_bytes(iv, AES_BLOCK_SIZE) != 0) {
                fprintf(stderr, "[ERROR] Failed to generate IV\n");
                rc = 12;
                goto cleanup;
            }

            if (strcmp(args.mode, "cbc") == 0) {
                rc = encrypt_cbc(inbuf, inlen, key, iv, &outbuf, &outlen);
            } else if (strcmp(args.mode, "cfb") == 0) {
                rc = encrypt_cfb(inbuf, inlen, key, iv, &outbuf, &outlen);
            } else if (strcmp(args.mode, "ofb") == 0) {
                rc = encrypt_ofb(inbuf, inlen, key, iv, &outbuf, &outlen);
            } else if (strcmp(args.mode, "ctr") == 0) {
                rc = encrypt_ctr(inbuf, inlen, key, iv, &outbuf, &outlen);
            } else {
                fprintf(stderr, "[ERROR] Unknown mode: %s\n", args.mode);
                rc = 13;
            }

            if (rc == 0) {
                rc = write_file_with_iv(args.output, iv, outbuf, outlen);
            }
        }
    }
    else if (args.decrypt) {
        if (strcmp(args.mode, "ecb") == 0) {
            if (read_file(args.input, &inbuf, &inlen) != 0) {
                fprintf(stderr, "[ERROR] Failed to read input file '%s'\n", args.input);
                rc = 20;
                goto cleanup;
            }
            rc = decrypt_ecb(inbuf, inlen, key, &outbuf, &outlen);
            if (rc == 0) rc = write_file_atomic(args.output, outbuf, outlen);
        } else {
            if (iv_from_user) {
                if (read_file(args.input, &cipher_in, &cipher_in_len) != 0) {
                    fprintf(stderr, "[ERROR] Failed to read input file '%s'\n", args.input);
                    rc = 21;
                    goto cleanup;
                }
            } else {
                if (read_file_with_iv(args.input, iv, &cipher_in, &cipher_in_len) != 0) {
                    fprintf(stderr, "[ERROR] Failed to read IV + ciphertext from '%s'\n", args.input);
                    rc = 22;
                    goto cleanup;
                }
            }

            if (strcmp(args.mode, "cbc") == 0) {
                rc = decrypt_cbc(cipher_in, cipher_in_len, key, iv, &outbuf, &outlen);
            } else if (strcmp(args.mode, "cfb") == 0) {
                rc = decrypt_cfb(cipher_in, cipher_in_len, key, iv, &outbuf, &outlen);
            } else if (strcmp(args.mode, "ofb") == 0) {
                rc = decrypt_ofb(cipher_in, cipher_in_len, key, iv, &outbuf, &outlen);
            } else if (strcmp(args.mode, "ctr") == 0) {
                rc = decrypt_ctr(cipher_in, cipher_in_len, key, iv, &outbuf, &outlen);
            } else {
                fprintf(stderr, "[ERROR] Unknown mode: %s\n", args.mode);
                rc = 23;
            }

            if (rc == 0) {
                rc = write_file_atomic(args.output, outbuf, outlen);
            }

            if (cipher_in) { free(cipher_in); cipher_in = NULL; }
        }
    } else {
        fprintf(stderr, "[ERROR] Neither encrypt nor decrypt selected\n");
        rc = 30;
    }

cleanup:
    if (inbuf) { free(inbuf); inbuf = NULL; }
    if (outbuf) { free(outbuf); outbuf = NULL; }

    free_cli_args(&args);
    return rc;
}

static int hex_to_bytes_local(const char *hex, unsigned char *out, size_t out_len) {
    if (!hex || !out) return -1;
    size_t hlen = strlen(hex);
    if (hlen != out_len * 2) return -2;
    for (size_t i = 0; i < out_len; ++i) {
        unsigned int byte = 0;
        if (sscanf(hex + 2*i, "%2x", &byte) != 1) return -3;
        out[i] = (unsigned char)byte;
    }
    return 0;
}

static void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
}
