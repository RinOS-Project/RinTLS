/*
 * rinTLS - SHA-1 Hash Implementation
 * RFC 3174 compliant (for legacy TLS compatibility)
 */

#ifndef RINTLS_SHA1_H
#define RINTLS_SHA1_H

#include "../platform/rin_platform.h"

#define SHA1_DIGEST_SIZE    20
#define SHA1_BLOCK_SIZE     64

typedef struct {
    u32 state[5];
    u64 count;
    u8 buffer[SHA1_BLOCK_SIZE];
} sha1_ctx_t;

/* SHA-1 functions */
void sha1_init(sha1_ctx_t* ctx);
void sha1_update(sha1_ctx_t* ctx, const u8* data, rin_size_t len);
void sha1_final(sha1_ctx_t* ctx, u8* digest);

/* One-shot hash */
void sha1_hash(const u8* data, rin_size_t len, u8* digest);

#endif /* RINTLS_SHA1_H */
