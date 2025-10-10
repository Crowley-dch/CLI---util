#include "cli_parser.h"
#include "file_io.h"
#include "ecb.h"
#include "modes/cbc.h"
#include "modes/cfb.h"
#include "modes/ofb.h"
#include "modes/ctr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

#define AES_BLOCK_SIZE 16

int main(int argc, char *argv[]) {
    cli_args_t args;
    if (parse_cli_args(argc, argv, &args) != 0) {
        fprintf(stderr, "Usage: %s --algorithm aes --mode <ecb|cbc|cfb|ofb|ctr> "
                        "(--encrypt|--decrypt) --key <hex32> [--iv <hex32>] "
                        "--input <file> [--output <file>]\n", argv[0]);
        return 1;
    }

    unsigned char key[16];
    if (hex_to_bytes(args.key_hex, key, sizeof(key)) != 0) {
        fprintf(stderr, "[ERROR] Invalid key format\n");
        return 2;
    }

    unsigned char iv[AES_BLOCK_SIZE];
    int iv_from_user = 0;
    if (args.iv_hex && strlen(args.iv_hex) == 32) {
        if (hex_to_bytes(args.iv_hex, iv, AES_BLOCK_SIZE) != 0) {
            fprintf(stderr, "[ERROR] Invalid IV hex\n");
            return 3;
        }
        iv_from_user = 1;
    }

    unsigned char *inbuf = NULL, *outbuf = NULL;
    size_t inlen = 0, outlen = 0;
    int rc = 0;

    if (read_file(args.input, &inbuf, &inlen) != 0) {
        fprintf(stderr, "[ERROR] Failed to read input file '%s'\n", args.input);
        return 4;
    }

    if (args.encrypt) {
        if (!strcmp(args.mode, "ecb")) {
            rc = encrypt_ecb(inbuf, inlen, key, &outbuf, &outlen);
            if (rc == 0) rc = write_file_atomic(args.output, outbuf, outlen);
        }
        else {
            if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
                fprintf(stderr, "[ERROR] RAND_bytes failed\n");
                return 5;
            }

            if (!strcmp(args.mode, "cbc"))
                rc = encrypt_cbc(inbuf, inlen, key, iv, &outbuf, &outlen);
            else if (!strcmp(args.mode, "cfb"))
                rc = encrypt_cfb(inbuf, inlen, key, iv, &outbuf, &outlen);
            else if (!strcmp(args.mode, "ofb"))
                rc = encrypt_ofb(inbuf, inlen, key, iv, &outbuf, &outlen);
            else if (!strcmp(args.mode, "ctr"))
                rc = encrypt_ctr(inbuf, inlen, key, iv, &outbuf, &outlen);
            else {
                fprintf(stderr, "[ERROR] Unknown mode: %s\n", args.mode);
                return 6;
            }

            if (rc == 0)
                rc = write_file_with_iv(args.output, iv, outbuf, outlen);
        }
    }

else if (args.decrypt) {
    unsigned char *cipher_in = NULL;
    size_t cipher_in_len = 0;

    if (!strcmp(args.mode, "ecb")) {
        rc = decrypt_ecb(inbuf, inlen, key, &outbuf, &outlen);
    } else {
        if (!iv_from_user) {
            if (read_file_with_iv(args.input, iv, &cipher_in, &cipher_in_len) != 0) {
                fprintf(stderr, "[ERROR] Failed to read IV + ciphertext from %s\n", args.input);
                rc = 7;
                goto decrypt_cleanup;
            }
        } else {
            cipher_in = inbuf;
            cipher_in_len = inlen;
        }

        if (!strcmp(args.mode, "cbc"))
            rc = decrypt_cbc(cipher_in, cipher_in_len, key, iv, &outbuf, &outlen);
        else if (!strcmp(args.mode, "cfb"))
            rc = decrypt_cfb(cipher_in, cipher_in_len, key, iv, &outbuf, &outlen);
        else if (!strcmp(args.mode, "ofb"))
            rc = decrypt_ofb(cipher_in, cipher_in_len, key, iv, &outbuf, &outlen);
        else if (!strcmp(args.mode, "ctr"))
            rc = decrypt_ctr(cipher_in, cipher_in_len, key, iv, &outbuf, &outlen);
        else {
            fprintf(stderr, "[ERROR] Unknown mode: %s\n", args.mode);
            rc = 8;
        }

        if (!iv_from_user) {
            free(cipher_in);
            cipher_in = NULL;
        }
    }

    if (rc == 0)
        rc = write_file_atomic(args.output, outbuf, outlen);
}

decrypt_cleanup:
    ;


    if (rc == 0)
        printf("[INFO] Operation completed successfully.\n");
    else
        fprintf(stderr, "[ERROR] Crypto operation failed (code %d)\n", rc);

    free(inbuf);
    free(outbuf);
    return rc;

if (inbuf) {
    free(inbuf);
    inbuf = NULL;
}
if (outbuf) {
    free(outbuf);
    outbuf = NULL;
}
}