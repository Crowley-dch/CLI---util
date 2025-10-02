#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "cli_parser.h"
#include "file_io.h"
#include "ecb.h"

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
    cli_args_t args;
    int res = parse_cli_args(argc, argv, &args);
    if (res != 0) {
        return res;
    }

    unsigned char key[16];
    if (hex_to_bytes(args.key_hex, key, sizeof(key)) != 0) {
        log_error("Invalid key hex");
        free_cli_args(&args);
        return 3;
    }

    unsigned char *inbuf = NULL;
    size_t inlen = 0;
    res = read_file(args.input_path, &inbuf, &inlen);
    if (res != 0) {
        log_error("Failed to read input file");
        free_cli_args(&args);
        return 4;
    }

    unsigned char *outbuf = NULL;
    size_t outlen = 0;
    if (args.encrypt) {
        log_info("Encrypting %s -> %s (AES-128-ECB)", args.input_path, args.output_path);
        res = encrypt_ecb(inbuf, inlen, key, &outbuf, &outlen);
        if (res != 0) {
            log_error("Encryption failed (code %d)", res);
            free(inbuf);
            free_cli_args(&args);
            return 6;
        }
    } else {
        log_info("Decrypting %s -> %s (AES-128-ECB)", args.input_path, args.output_path);
        res = decrypt_ecb(inbuf, inlen, key, &outbuf, &outlen);
        if (res != 0) {
            log_error("Decryption failed (padding or corrupted ciphertext) (code %d)", res);
            free(inbuf);
            free_cli_args(&args);
            return 7;
        }
    }

    res = write_file_atomic(args.output_path, outbuf, outlen);
    if (res != 0) {
        log_error("Failed to write output file (code %d)", res);
        free(inbuf); free(outbuf);
        free_cli_args(&args);
        return 8;
    }

    log_info("Operation completed successfully.");
    free(inbuf); free(outbuf); free_cli_args(&args);
    return 0;
}
