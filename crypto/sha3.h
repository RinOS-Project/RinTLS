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
    u8 domain;
    u8 squeezing;
} sha3_ctx;

void sha3_256_init(sha3_ctx* ctx);
void sha3_384_init(sha3_ctx* ctx);
void sha3_512_init(sha3_ctx* ctx);
void sha3_update(sha3_ctx* ctx, const u8* data, rin_size_t len);
void sha3_final(sha3_ctx* ctx, u8* digest);
void sha3_256(const u8* data, rin_size_t len, u8* digest);
void sha3_384(const u8* data, rin_size_t len, u8* digest);
void sha3_512(const u8* data, rin_size_t len, u8* digest);

/* FIPS 202 / SP 800-185 extendable-output primitives. */
void sha3_xof_init(sha3_ctx* ctx, u32 rate, u8 domain);
int sha3_xof_squeeze(sha3_ctx* ctx, u8* output, rin_size_t output_len);

/* SP 800-185 KMAC/KMACXOF.  The returned context is resettable and can be
 * updated incrementally; output length is selected by the final operation. */
int sha3_kmac_init(sha3_ctx* ctx, u32 rate, const u8* key, rin_size_t key_len,
                   const u8* customization, rin_size_t customization_len,
                   int xof);
int sha3_kmac_finalize(sha3_ctx* ctx, u8* output, rin_size_t output_len,
                       int xof);

#ifdef __cplusplus
}
#endif

#endif /* RINTLS_SHA3_H */
