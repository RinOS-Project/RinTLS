/*
 * rinTLS - HMAC (Hash-based Message Authentication Code)
 * HMAC実装
 */

#ifndef RINTLS_HMAC_H
#define RINTLS_HMAC_H

#include "../platform/rin_platform.h"
#include "sha256.h"
#include "sha3.h"

/* HMAC-SHA256 */
#define HMAC_SHA256_SIZE    32

typedef struct {
    sha256_ctx inner;
    sha256_ctx outer;
    u8 key_block[SHA256_BLOCK_SIZE];
} hmac_sha256_ctx;

void hmac_sha256_init(hmac_sha256_ctx* ctx, const u8* key, rin_size_t key_len);
void hmac_sha256_update(hmac_sha256_ctx* ctx, const u8* data, rin_size_t len);
void hmac_sha256_final(hmac_sha256_ctx* ctx, u8* mac);
void hmac_sha256(const u8* key, rin_size_t key_len, const u8* data, rin_size_t data_len, u8* mac);

/* HMAC-SHA384 */
#define HMAC_SHA384_SIZE    48

typedef struct {
    sha384_ctx inner;
    sha384_ctx outer;
    u8 key_block[SHA384_BLOCK_SIZE];
} hmac_sha384_ctx;

void hmac_sha384_init(hmac_sha384_ctx* ctx, const u8* key, rin_size_t key_len);
void hmac_sha384_update(hmac_sha384_ctx* ctx, const u8* data, rin_size_t len);
void hmac_sha384_final(hmac_sha384_ctx* ctx, u8* mac);
void hmac_sha384(const u8* key, rin_size_t key_len, const u8* data, rin_size_t data_len, u8* mac);

/* HMAC-SHA512 */
#define HMAC_SHA512_SIZE    64

typedef struct {
    sha512_ctx inner;
    sha512_ctx outer;
    u8 key_block[SHA512_BLOCK_SIZE];
} hmac_sha512_ctx;

void hmac_sha512_init(hmac_sha512_ctx* ctx, const u8* key, rin_size_t key_len);
void hmac_sha512_update(hmac_sha512_ctx* ctx, const u8* data, rin_size_t len);
void hmac_sha512_final(hmac_sha512_ctx* ctx, u8* mac);
void hmac_sha512(const u8* key, rin_size_t key_len, const u8* data, rin_size_t data_len, u8* mac);

/* HMAC-SHA3 (RFC 2104 construction over FIPS 202 SHA3). */
#define HMAC_SHA3_256_SIZE SHA3_256_DIGEST_SIZE
#define HMAC_SHA3_384_SIZE SHA3_384_DIGEST_SIZE
#define HMAC_SHA3_512_SIZE SHA3_512_DIGEST_SIZE

typedef struct {
    sha3_ctx inner;
    sha3_ctx outer;
    u8 key_block[SHA3_256_RATE];
} hmac_sha3_256_ctx;

typedef struct {
    sha3_ctx inner;
    sha3_ctx outer;
    u8 key_block[SHA3_384_RATE];
} hmac_sha3_384_ctx;

typedef struct {
    sha3_ctx inner;
    sha3_ctx outer;
    u8 key_block[SHA3_512_RATE];
} hmac_sha3_512_ctx;

void hmac_sha3_256_init(hmac_sha3_256_ctx* ctx, const u8* key, rin_size_t key_len);
void hmac_sha3_256_update(hmac_sha3_256_ctx* ctx, const u8* data, rin_size_t len);
void hmac_sha3_256_final(hmac_sha3_256_ctx* ctx, u8* mac);

void hmac_sha3_384_init(hmac_sha3_384_ctx* ctx, const u8* key, rin_size_t key_len);
void hmac_sha3_384_update(hmac_sha3_384_ctx* ctx, const u8* data, rin_size_t len);
void hmac_sha3_384_final(hmac_sha3_384_ctx* ctx, u8* mac);

void hmac_sha3_512_init(hmac_sha3_512_ctx* ctx, const u8* key, rin_size_t key_len);
void hmac_sha3_512_update(hmac_sha3_512_ctx* ctx, const u8* data, rin_size_t len);
void hmac_sha3_512_final(hmac_sha3_512_ctx* ctx, u8* mac);

/* ═══════════════════════════════════════
 * HKDF (HMAC-based Key Derivation Function)
 * RFC 5869
 * ═══════════════════════════════════════ */

/* HKDF-SHA256 */
void hkdf_sha256_extract(const u8* salt, rin_size_t salt_len,
                         const u8* ikm, rin_size_t ikm_len,
                         u8* prk);

void hkdf_sha256_expand(const u8* prk,
                        const u8* info, rin_size_t info_len,
                        u8* okm, rin_size_t okm_len);

void hkdf_sha256(const u8* salt, rin_size_t salt_len,
                 const u8* ikm, rin_size_t ikm_len,
                 const u8* info, rin_size_t info_len,
                 u8* okm, rin_size_t okm_len);

/* HKDF-SHA384 */
void hkdf_sha384_extract(const u8* salt, rin_size_t salt_len,
                         const u8* ikm, rin_size_t ikm_len,
                         u8* prk);

void hkdf_sha384_expand(const u8* prk,
                        const u8* info, rin_size_t info_len,
                        u8* okm, rin_size_t okm_len);

void hkdf_sha384(const u8* salt, rin_size_t salt_len,
                 const u8* ikm, rin_size_t ikm_len,
                 const u8* info, rin_size_t info_len,
                 u8* okm, rin_size_t okm_len);

#endif /* RINTLS_HMAC_H */
