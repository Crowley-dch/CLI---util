#define _POSIX_C_SOURCE 200809L

#include "cli_parser.h"
#include "file_io.h"
#include "ecb.h"
#include "modes/cbc.h"
#include "modes/cfb.h"
#include "modes/ofb.h"
#include "modes/ctr.h"
#include "csprng.h"
#include "hash/sha256.h"
#include "hash/blake2b.h"
#include "mac/hmac.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AES_BLOCK_SIZE 16

static int hex_to_bytes_local(const char *hex, unsigned char *out, size_t out_len);
static void print_hex(const unsigned char *data, size_t len);

static int handle_hmac_command(const cli_args_t *args) {
    uint8_t key_bytes[1024]; 
    size_t key_len;
    uint8_t hmac_result[32];
    int rc;
    
    if (hex_to_bytes_local(args->key_hex, key_bytes, sizeof(key_bytes)) != 0) {
        fprintf(stderr, "[ERROR] Invalid key format. Must be hexadecimal.\n");
        return 60;
    }
    
    key_len = strlen(args->key_hex) / 2;
    
    printf("[INFO] Computing HMAC-%s for '%s' with key length %zu bytes\n", 
           args->algorithm, args->input, key_len);
    
    if (strcmp(args->algorithm, "sha256") == 0) {
        rc = hmac_sha256_file(args->input, key_bytes, key_len, hmac_result);
    } else {
        fprintf(stderr, "[ERROR] HMAC only supported with sha256 algorithm\n");
        return 61;
    }
    
    if (rc != 0) {
        fprintf(stderr, "[ERROR] Failed to compute HMAC\n");
        return 62;
    }
    
    char hmac_hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(hmac_hex + i*2, "%02x", hmac_result[i]);
    }
    hmac_hex[64] = '\0';
    
    if (args->verify_file) {
        int verification_result;
        
        if (verify_hmac_file(args->input, args->verify_file, key_bytes, key_len, &verification_result) != 0) {
            fprintf(stderr, "[ERROR] Failed to verify HMAC\n");
            return 63;
        }
        
        if (verification_result) {
            printf("[OK] HMAC verification successful\n");
            return 0;
        } else {
            printf("[ERROR] HMAC verification failed\n");
            return 64;
        }
    }
    
    if (args->output) {
        if (write_hash_to_file(args->output, hmac_hex, args->input) != 0) {
            fprintf(stderr, "[ERROR] Failed to write HMAC to file\n");
            return 65;
        }
        printf("[INFO] HMAC written to: %s\n", args->output);
    } else {
        printf("%s  %s\n", hmac_hex, args->input);
    }
    
    return 0;
}

static int handle_dgst_command(const cli_args_t *args) {
    if (args->hmac_mode) {
        return handle_hmac_command(args);
    }
    
    char *hash_value = NULL;
    int result = 0;
    
    printf("[INFO] Computing %s hash for '%s'\n", args->algorithm, args->input);
    
    if (strcmp(args->algorithm, "sha256") == 0) {
        unsigned char *file_data = NULL;
        size_t file_len = 0;
        
        if (read_file(args->input, &file_data, &file_len) != 0) {
            fprintf(stderr, "[ERROR] Failed to read input file '%s'\n", args->input);
            return 50;
        }
        
        unsigned char digest[32];
        sha256_hash(file_data, file_len, digest);
        
        hash_value = malloc(65);
        if (!hash_value) {
            free(file_data);
            return 51;
        }
        
        for (int i = 0; i < 32; i++) {
            sprintf(hash_value + i*2, "%02x", digest[i]);
        }
        hash_value[64] = '\0';
        
        free(file_data);
        
    } else if (strcmp(args->algorithm, "blake2b") == 0) {
        hash_value = blake2b_hash_file_openssl(args->input, 32);
        
        if (!hash_value) {
            fprintf(stderr, "[ERROR] Failed to compute BLAKE2b hash for '%s'\n", args->input);
            return 52;
        }
    } else {
        fprintf(stderr, "[ERROR] Unsupported algorithm: %s\n", args->algorithm);
        return 53;
    }
    
    if (args->output) {
        if (write_hash_to_file(args->output, hash_value, args->input) != 0) {
            fprintf(stderr, "[ERROR] Failed to write hash to '%s'\n", args->output);
            result = 54;
        } else {
            printf("[INFO] Hash written to: %s\n", args->output);
            printf("%s  %s\n", hash_value, args->input);
        }
    } else {
        printf("%s  %s\n", hash_value, args->input);
    }
    
    free(hash_value);
    return result;
}

int main(int argc, char **argv) {
    int rc = 0;
    cli_args_t args;
    memset(&args, 0, sizeof(args));

    if (parse_cli_args(argc, argv, &args) != 0) {
        return 1;
    }

    if (args.subcommand == SUBCMD_DGST) {
        rc = handle_dgst_command(&args);
        free_cli_args(&args);
        return rc;
    }

    if (args.digest_mode) {
        printf("[WARNING] Using deprecated digest mode. Use 'dgst' subcommand instead.\n");
        cli_args_t dgst_args = {
            .algorithm = args.algorithm ? strdup(args.algorithm) : strdup("sha256"),
            .input = strdup(args.input),
            .output = args.output ? strdup(args.output) : NULL,
            .subcommand = SUBCMD_DGST
        };
        
        rc = handle_dgst_command(&dgst_args);
        
        free(dgst_args.algorithm);
        free(dgst_args.input);
        if (dgst_args.output) free(dgst_args.output);
        free_cli_args(&args);
        return rc;
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

            printf("[INFO] Generated IV: ");
            print_hex(iv, AES_BLOCK_SIZE);
            printf("\n");

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

            if (rc == 0)
                rc = write_file_with_iv(args.output, iv, outbuf, outlen);
        }
    } else if (args.decrypt) {
        if (strcmp(args.mode, "ecb") == 0) {
            if (read_file(args.input, &inbuf, &inlen) != 0) {
                fprintf(stderr, "[ERROR] Failed to read input file '%s'\n", args.input);
                rc = 20;
                goto cleanup;
            }

            rc = decrypt_ecb(inbuf, inlen, key, &outbuf, &outlen);
            if (rc == 0)
                rc = write_file_atomic(args.output, outbuf, outlen);
        } else {
            if (iv_from_user) {
                if (read_file(args.input, &cipher_in, &cipher_in_len) != 0) {
                    fprintf(stderr, "[ERROR] Failed to read input file '%s'\n", args.input);
                    rc = 21;
                    goto cleanup;
                }
            } else {
                if (read_file_with_iv(args.input, iv, &cipher_in, &cipher_in_len) != 0) {
                    fprintf(stderr, "[ERROR] Failed to read IV+ciphertext from '%s'\n", args.input);
                    rc = 22;
                    goto cleanup;
                }

                printf("[INFO] Extracted IV from file: ");
                print_hex(iv, AES_BLOCK_SIZE);
                printf("\n");
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

            if (rc == 0)
                rc = write_file_atomic(args.output, outbuf, outlen);

            free(cipher_in);
            cipher_in = NULL;
        }
    } else {
        fprintf(stderr, "[ERROR] Neither encrypt nor decrypt selected\n");
        rc = 30;
    }

cleanup:
    free(inbuf);
    free(outbuf);
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
    for (size_t i = 0; i < len; ++i)
        printf("%02x", data[i]);
}