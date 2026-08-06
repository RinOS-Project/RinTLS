/*
 * rinTLS - SHA-256 Hash Function
 * SHA-256ハッシュ関数
 */

#ifndef RINTLS_SHA256_H
#define RINTLS_SHA256_H

#include "../platform/rin_platform.h"

#define SHA256_DIGEST_SIZE  32
#define SHA256_BLOCK_SIZE   64

typedef struct {
    u32 state[8];       /* Hash state */
    u64 count;          /* Number of bits processed */
    u8  buffer[64];     /* Input buffer */
} sha256_ctx;

/* Initialize SHA-256 context */
void sha256_init(sha256_ctx* ctx);

/* Update hash with data */
void sha256_update(sha256_ctx* ctx, const u8* data, rin_size_t len);

/* Finalize and output hash */
void sha256_final(sha256_ctx* ctx, u8* digest);

/* One-shot hash */
void sha256(const u8* data, rin_size_t len, u8* digest);

/* SHA-384/512 for TLS 1.2 cipher suites */
#define SHA384_DIGEST_SIZE  48
#define SHA384_BLOCK_SIZE   128
#define SHA512_DIGEST_SIZE  64
#define SHA512_BLOCK_SIZE   128

typedef struct {
    u64 state[8];
    u64 count[2];
    u8  buffer[128];
} sha512_ctx;

typedef sha512_ctx sha384_ctx;

void sha384_init(sha384_ctx* ctx);
void sha384_update(sha384_ctx* ctx, const u8* data, rin_size_t len);
void sha384_final(sha384_ctx* ctx, u8* digest);
void sha384(const u8* data, rin_size_t len, u8* digest);

void sha512_init(sha512_ctx* ctx);
void sha512_update(sha512_ctx* ctx, const u8* data, rin_size_t len);
void sha512_final(sha512_ctx* ctx, u8* digest);
void sha512(const u8* data, rin_size_t len, u8* digest);

#endif /* RINTLS_SHA256_H */
