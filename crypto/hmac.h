/*
 * rinTLS - HMAC (Hash-based Message Authentication Code)
 * HMAC実装
 */

#ifndef RINTLS_HMAC_H
#define RINTLS_HMAC_H

#include "../platform/rin_platform.h"
#include "sha256.h"

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
