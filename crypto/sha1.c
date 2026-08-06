/*
 * rinTLS - SHA-1 Hash Implementation
 * RFC 3174 compliant
 */

#include "sha1.h"

/* SHA-1 constants */
#define SHA1_K0 0x5A827999
#define SHA1_K1 0x6ED9EBA1
#define SHA1_K2 0x8F1BBCDC
#define SHA1_K3 0xCA62C1D6

/* Rotate left */
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* SHA-1 transform - process one block */
static void sha1_transform(sha1_ctx_t* ctx, const u8* block)
{
    u32 w[80];
    u32 a, b, c, d, e;
    u32 temp;
    int t;

    /* Prepare message schedule */
    for (t = 0; t < 16; t++) {
        w[t] = ((u32)block[t * 4 + 0] << 24) |
               ((u32)block[t * 4 + 1] << 16) |
               ((u32)block[t * 4 + 2] << 8) |
               ((u32)block[t * 4 + 3]);
    }

    for (t = 16; t < 80; t++) {
        w[t] = ROTL32(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16], 1);
    }

    /* Initialize working variables */
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

    /* Main loop */
    for (t = 0; t < 20; t++) {
        temp = ROTL32(a, 5) + ((b & c) | ((~b) & d)) + e + w[t] + SHA1_K0;
        e = d;
        d = c;
        c = ROTL32(b, 30);
        b = a;
        a = temp;
    }

    for (t = 20; t < 40; t++) {
        temp = ROTL32(a, 5) + (b ^ c ^ d) + e + w[t] + SHA1_K1;
        e = d;
        d = c;
        c = ROTL32(b, 30);
        b = a;
        a = temp;
    }

    for (t = 40; t < 60; t++) {
        temp = ROTL32(a, 5) + ((b & c) | (b & d) | (c & d)) + e + w[t] + SHA1_K2;
        e = d;
        d = c;
        c = ROTL32(b, 30);
        b = a;
        a = temp;
    }

    for (t = 60; t < 80; t++) {
        temp = ROTL32(a, 5) + (b ^ c ^ d) + e + w[t] + SHA1_K3;
        e = d;
        d = c;
        c = ROTL32(b, 30);
        b = a;
        a = temp;
    }

    /* Update state */
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;

    /* Clear sensitive data */
    rintls_memzero(w, sizeof(w));
}

void sha1_init(sha1_ctx_t* ctx)
{
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count = 0;
}

void sha1_update(sha1_ctx_t* ctx, const u8* data, rin_size_t len)
{
    rin_size_t buf_used = (rin_size_t)(ctx->count % SHA1_BLOCK_SIZE);
    ctx->count += len;

    /* If we have buffered data, fill the buffer first */
    if (buf_used > 0) {
        rin_size_t buf_free = SHA1_BLOCK_SIZE - buf_used;
        if (len < buf_free) {
            rintls_memcpy(ctx->buffer + buf_used, data, len);
            return;
        }
        rintls_memcpy(ctx->buffer + buf_used, data, buf_free);
        sha1_transform(ctx, ctx->buffer);
        data += buf_free;
        len -= buf_free;
    }

    /* Process full blocks */
    while (len >= SHA1_BLOCK_SIZE) {
        sha1_transform(ctx, data);
        data += SHA1_BLOCK_SIZE;
        len -= SHA1_BLOCK_SIZE;
    }

    /* Buffer remaining data */
    if (len > 0) {
        rintls_memcpy(ctx->buffer, data, len);
    }
}

void sha1_final(sha1_ctx_t* ctx, u8* digest)
{
    u64 total_bits = ctx->count * 8;
    rin_size_t buf_used = (rin_size_t)(ctx->count % SHA1_BLOCK_SIZE);

    /* Padding: 0x80 followed by zeros, then 64-bit length (big-endian) */
    ctx->buffer[buf_used++] = 0x80;

    /* If not enough room for length, fill with zeros and process */
    if (buf_used > 56) {
        rintls_memset(ctx->buffer + buf_used, 0, SHA1_BLOCK_SIZE - buf_used);
        sha1_transform(ctx, ctx->buffer);
        buf_used = 0;
    }

    /* Fill with zeros up to length field */
    rintls_memset(ctx->buffer + buf_used, 0, 56 - buf_used);

    /* Append length in big-endian */
    ctx->buffer[56] = (u8)(total_bits >> 56);
    ctx->buffer[57] = (u8)(total_bits >> 48);
    ctx->buffer[58] = (u8)(total_bits >> 40);
    ctx->buffer[59] = (u8)(total_bits >> 32);
    ctx->buffer[60] = (u8)(total_bits >> 24);
    ctx->buffer[61] = (u8)(total_bits >> 16);
    ctx->buffer[62] = (u8)(total_bits >> 8);
    ctx->buffer[63] = (u8)(total_bits);

    sha1_transform(ctx, ctx->buffer);

    /* Output digest in big-endian */
    for (int i = 0; i < 5; i++) {
        digest[i * 4 + 0] = (u8)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (u8)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (u8)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (u8)(ctx->state[i]);
    }

    /* Clear sensitive data */
    rintls_memzero(ctx, sizeof(sha1_ctx_t));
}

void sha1_hash(const u8* data, rin_size_t len, u8* digest)
{
    sha1_ctx_t ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data, len);
    sha1_final(&ctx, digest);
}
