#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <openssl/rand.h>

#include "cli_parser.h"
#include "file_io.h"
#include "ecb.h"

#include "modes/cbc.h"
#include "modes/cfb.h"
#include "modes/ofb.h"
#include "modes/ctr.h"

#define IV_LEN 16

static void log_info(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[INFO] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

static void log_error(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[ERROR] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

int main(int argc, char **argv) {
    int rc = 0;
    cli_args_t args;
    if ((rc = parse_cli_args(argc, argv, &args)) != 0) {
        return rc;
    }

    unsigned char key[16];
    if (hex_to_bytes(args.key_hex, key, sizeof(key)) != 0) {
        log_error("Invalid key hex");
        free_cli_args(&args);
        return 3;
    }

    unsigned char *inbuf = NULL;
    size_t inlen = 0;
    rc = read_file(args.input_path, &inbuf, &inlen);
    if (rc != 0) {
        log_error("Failed to read input file '%s' (code %d)", args.input_path, rc);
        free_cli_args(&args);
        return 4;
    }

    unsigned char iv[IV_LEN];
    unsigned char *cipher_in = NULL;
    size_t cipher_in_len = 0;

    if (args.decrypt) {
        if (args.iv_hex) {
            if (hex_to_bytes(args.iv_hex, iv, IV_LEN) != 0) {
                log_error("Invalid IV hex");
                free(inbuf);
                free_cli_args(&args);
                return 5;
            }
            cipher_in = inbuf;
            cipher_in_len = inlen;
        } else {
            if (inlen < IV_LEN) {
                log_error("Input file too short to contain IV (need %d bytes, got %zu)", IV_LEN, inlen);
                free(inbuf);
                free_cli_args(&args);
                return 6;
            }
            memcpy(iv, inbuf, IV_LEN);
            cipher_in = inbuf + IV_LEN;
            cipher_in_len = inlen - IV_LEN;
        }
    }

    unsigned char *outbuf = NULL;
    size_t outlen = 0;

    const char *mode = args.mode;

    if (args.encrypt) {
        if (strcmp(mode, "ecb") != 0) {
            if (RAND_bytes(iv, IV_LEN) != 1) {
                log_error("Failed to generate IV via RAND_bytes()");
                free(inbuf);
                free_cli_args(&args);
                return 7;
            }
        }
    }

#define CALL_ENC_DEC(mode_name, enc_fn, dec_fn) \
    do { \
        if (strcmp(mode, mode_name) == 0) { \
            if (args.encrypt) { \
                rc = enc_fn(inbuf, inlen, key, iv, &outbuf, &outlen); \
            } else { \
                rc = dec_fn(cipher_in, cipher_in_len, key, iv, &outbuf, &outlen); \
            } \
            break; \
        } \
    } while (0)


    rc = -1; 
    if (strcmp(mode, "ecb") == 0) {
        if (args.encrypt) {
            rc = encrypt_ecb(inbuf, inlen, key, &outbuf, &outlen);
        } else {
            rc = decrypt_ecb(cipher_in, cipher_in_len, key, &outbuf, &outlen);
        }
    } else if (strcmp(mode, "cbc") == 0) {
        
        rc = -1;
        if (args.encrypt) {
            rc = encrypt_cbc(inbuf, inlen, key, iv, &outbuf, &outlen);
        } else {
            rc = decrypt_cbc(cipher_in, cipher_in_len, key, iv, &outbuf, &outlen);
        }
    } else if (strcmp(mode, "cfb") == 0) {
        if (args.encrypt) {
            rc = encrypt_cfb(inbuf, inlen, key, iv, &outbuf, &outlen);
        } else {
            rc = decrypt_cfb(cipher_in, cipher_in_len, key, iv, &outbuf, &outlen);
        }
    } else if (strcmp(mode, "ofb") == 0) {
        if (args.encrypt) {
            rc = encrypt_ofb(inbuf, inlen, key, iv, &outbuf, &outlen);
        } else {
            rc = decrypt_ofb(cipher_in, cipher_in_len, key, iv, &outbuf, &outlen);
        }
    } else if (strcmp(mode, "ctr") == 0) {
        if (args.encrypt) {
            rc = encrypt_ctr(inbuf, inlen, key, iv, &outbuf, &outlen);
        } else {
            rc = decrypt_ctr(cipher_in, cipher_in_len, key, iv, &outbuf, &outlen);
        }
    } else {
        log_error("Unsupported mode: %s", mode);
        free(inbuf);
        free_cli_args(&args);
        return 8;
    }

    if (rc != 0) {
        log_error("Crypto operation failed (code %d)", rc);
        free(inbuf);
        free(outbuf);
        free_cli_args(&args);
        return 9;
    }

    if (args.encrypt) {
        if (strcmp(mode, "ecb") == 0) {
            rc = write_file_atomic(args.output_path, outbuf, outlen);
        } else {
            size_t tot = IV_LEN + outlen;
            unsigned char *buf_with_iv = malloc(tot);
            if (!buf_with_iv) {
                log_error("Memory allocation failed");
                free(inbuf); free(outbuf); free_cli_args(&args);
                return 10;
            }
            memcpy(buf_with_iv, iv, IV_LEN);
            memcpy(buf_with_iv + IV_LEN, outbuf, outlen);
            rc = write_file_atomic(args.output_path, buf_with_iv, tot);
            free(buf_with_iv);
        }
        if (rc != 0) {
            log_error("Failed to write output file (code %d)", rc);
            free(inbuf); free(outbuf); free_cli_args(&args);
            return 11;
        }
    } else {
        rc = write_file_atomic(args.output_path, outbuf, outlen);
        if (rc != 0) {
            log_error("Failed to write output file (code %d)", rc);
            free(inbuf); free(outbuf); free_cli_args(&args);
            return 12;
        }
    }

    log_info("Operation completed successfully.");
    free(inbuf);
    free(outbuf);
    free_cli_args(&args);
    return 0;
}
