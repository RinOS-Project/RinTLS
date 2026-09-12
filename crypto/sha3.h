/*
 * rinTLS - SHA-3 hash functions
 * FIPS 202 SHA3-256/384/512, with bounded streaming state.
 */

#ifndef RINTLS_SHA3_H
#define RINTLS_SHA3_H

#include "../platform/rin_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SHA3_256_DIGEST_SIZE 32u
#define SHA3_384_DIGEST_SIZE 48u
#define SHA3_512_DIGEST_SIZE 64u

typedef struct {
    u64 state[25];
    u8 buffer[200];
    u32 rate;
    u32 digest_size;
    u32 position;
} sha3_ctx;

void sha3_256_init(sha3_ctx* ctx);
void sha3_384_init(sha3_ctx* ctx);
void sha3_512_init(sha3_ctx* ctx);
void sha3_update(sha3_ctx* ctx, const u8* data, rin_size_t len);
void sha3_final(sha3_ctx* ctx, u8* digest);
void sha3_256(const u8* data, rin_size_t len, u8* digest);
void sha3_384(const u8* data, rin_size_t len, u8* digest);
void sha3_512(const u8* data, rin_size_t len, u8* digest);

#ifdef __cplusplus
}
#endif

#endif /* RINTLS_SHA3_H */
