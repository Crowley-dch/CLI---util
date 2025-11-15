#define _POSIX_C_SOURCE 200809L
#include "sha256.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>

static const uint32_t k[64] = {
  0x428a2f98ul,0x71374491ul,0xb5c0fbcful,0xe9b5dba5ul,0x3956c25bul,0x59f111f1ul,0x923f82a4ul,0xab1c5ed5ul,
  0xd807aa98ul,0x12835b01ul,0x243185beul,0x550c7dc3ul,0x72be5d74ul,0x80deb1feul,0x9bdc06a7ul,0xc19bf174ul,
  0xe49b69c1ul,0xefbe4786ul,0x0fc19dc6ul,0x240ca1ccul,0x2de92c6ful,0x4a7484aaul,0x5cb0a9dcul,0x76f988daul,
  0x983e5152ul,0xa831c66dul,0xb00327c8ul,0xbf597fc7ul,0xc6e00bf3ul,0xd5a79147ul,0x06ca6351ul,0x14292967ul,
  0x27b70a85ul,0x2e1b2138ul,0x4d2c6dfcul,0x53380d13ul,0x650a7354ul,0x766a0abbul,0x81c2c92eul,0x92722c85ul,
  0xa2bfe8a1ul,0xa81a664bul,0xc24b8b70ul,0xc76c51a3ul,0xd192e819ul,0xd6990624ul,0xf40e3585ul,0x106aa070ul,
  0x19a4c116ul,0x1e376c08ul,0x2748774cul,0x34b0bcb5ul,0x391c0cb3ul,0x4ed8aa4aul,0x5b9cca4ful,0x682e6ff3ul,
  0x748f82eeul,0x78a5636ful,0x84c87814ul,0x8cc70208ul,0x90befffaul,0xa4506cebul,0xbef9a3f7ul,0xc67178f2ul
};

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x,n)  ((x) >> (n))

#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIG0(x) (ROTR((x),2) ^ ROTR((x),13) ^ ROTR((x),22))
#define SIG1(x) (ROTR((x),6) ^ ROTR((x),11) ^ ROTR((x),25))
#define theta0(x) (ROTR((x),7) ^ ROTR((x),18) ^ SHR((x),3))
#define theta1(x) (ROTR((x),17) ^ ROTR((x),19) ^ SHR((x),10))

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t m[64];
    uint32_t a,b,c,d,e,f,g,h;
    size_t t;

    for (t = 0; t < 16; ++t) {
        m[t] = (uint32_t)data[t*4] << 24 |
               (uint32_t)data[t*4 + 1] << 16 |
               (uint32_t)data[t*4 + 2] << 8 |
               (uint32_t)data[t*4 + 3];
    }
    for (t = 16; t < 64; ++t) {
        m[t] = theta1(m[t-2]) + m[t-7] + theta0(m[t-15]) + m[t-16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (t = 0; t < 64; ++t) {
        uint32_t T1 = h + SIG1(e) + CH(e,f,g) + k[t] + m[t];
        uint32_t T2 = SIG0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;

    memset(m, 0, sizeof(m));
}

void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667ul;
    ctx->state[1] = 0xbb67ae85ul;
    ctx->state[2] = 0x3c6ef372ul;
    ctx->state[3] = 0xa54ff53aul;
    ctx->state[4] = 0x510e527ful;
    ctx->state[5] = 0x9b05688cul;
    ctx->state[6] = 0x1f83d9abul;
    ctx->state[7] = 0x5be0cd19ul;
}

void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    size_t i = 0;

    while (len > 0) {
        size_t to_copy = SHA256_BLOCK_SIZE - ctx->datalen;
        if (to_copy > len) to_copy = len;
        memcpy(ctx->data + ctx->datalen, data + i, to_copy);
        ctx->datalen += to_copy;
        i += to_copy;
        len -= to_copy;

        if (ctx->datalen == SHA256_BLOCK_SIZE) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void sha256_final(SHA256_CTX *ctx, uint8_t hash[SHA256_DIGEST_LENGTH]) {
    size_t i = ctx->datalen;

    ctx->data[i++] = 0x80;

    if (i > 56) {
        while (i < SHA256_BLOCK_SIZE) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        ctx->bitlen += 512;
        i = 0;
    }

    while (i < 56) ctx->data[i++] = 0x00;

    uint64_t bitlen_be = ctx->bitlen + (ctx->datalen * 8);
    ctx->data[56] = (uint8_t)(bitlen_be >> 56);
    ctx->data[57] = (uint8_t)(bitlen_be >> 48);
    ctx->data[58] = (uint8_t)(bitlen_be >> 40);
    ctx->data[59] = (uint8_t)(bitlen_be >> 32);
    ctx->data[60] = (uint8_t)(bitlen_be >> 24);
    ctx->data[61] = (uint8_t)(bitlen_be >> 16);
    ctx->data[62] = (uint8_t)(bitlen_be >> 8);
    ctx->data[63] = (uint8_t)(bitlen_be);

    sha256_transform(ctx, ctx->data);
    ctx->bitlen += 512;

    for (i = 0; i < 8; ++i) {
        hash[i*4    ] = (uint8_t)(ctx->state[i] >> 24);
        hash[i*4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        hash[i*4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        hash[i*4 + 3] = (uint8_t)(ctx->state[i]);
    }

    memset(ctx, 0, sizeof(*ctx));
}

void sha256(const uint8_t *data, size_t len, uint8_t out_hash[SHA256_DIGEST_LENGTH]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out_hash);
}

void sha256_to_hex(const uint8_t hash[SHA256_DIGEST_LENGTH], char hex_out[SHA256_DIGEST_LENGTH*2 + 1]) {
    static const char hexchars[] = "0123456789abcdef";
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        uint8_t v = hash[i];
        hex_out[i*2]     = hexchars[v >> 4];
        hex_out[i*2 + 1] = hexchars[v & 0x0F];
    }
    hex_out[SHA256_DIGEST_LENGTH*2] = '\0';
}
