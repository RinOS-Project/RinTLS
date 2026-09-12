/*
 * rinTLS - HMAC (Hash-based Message Authentication Code)
 * RFC 2104 準拠
 */

#include "hmac.h"
#include "../platform/rin_platform.h"

/* ═══════════════════════════════════════
 * HMAC-SHA256
 * ═══════════════════════════════════════ */

void hmac_sha256_init(hmac_sha256_ctx* ctx, const u8* key, rin_size_t key_len)
{
    /* volatile で最適化による破壊を防止 */
    volatile u8 key_pad[SHA256_BLOCK_SIZE];
    volatile u8 ipad[SHA256_BLOCK_SIZE];
    volatile u8 opad[SHA256_BLOCK_SIZE];
    rin_size_t i;

    /* キーの前処理 */
    for (i = 0; i < SHA256_BLOCK_SIZE; i++) key_pad[i] = 0;

    if (key_len > SHA256_BLOCK_SIZE) {
        /* キーが長すぎる場合はハッシュする */
        u8 tmp[SHA256_DIGEST_SIZE];
        sha256(key, key_len, tmp);
        for (i = 0; i < SHA256_DIGEST_SIZE; i++) key_pad[i] = tmp[i];
        rintls_secure_zero(tmp, sizeof(tmp));
    } else {
        for (i = 0; i < key_len; i++) key_pad[i] = key[i];
    }

    /* key_blockを保存 */
    for (i = 0; i < SHA256_BLOCK_SIZE; i++) ctx->key_block[i] = key_pad[i];

    /* inner pad (key XOR 0x36) */
    for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
        ipad[i] = key_pad[i] ^ 0x36;
    }

    /* outer pad (key XOR 0x5c) */
    for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
        opad[i] = key_pad[i] ^ 0x5c;
    }

    /* inner hashを初期化してipadを処理 - 非volatileコピーを使用 */
    {
        u8 ipad_copy[SHA256_BLOCK_SIZE];
        for (i = 0; i < SHA256_BLOCK_SIZE; i++) ipad_copy[i] = ipad[i];
        sha256_init(&ctx->inner);
        sha256_update(&ctx->inner, ipad_copy, SHA256_BLOCK_SIZE);
        rintls_secure_zero(ipad_copy, sizeof(ipad_copy));
    }

    /* outer hashを初期化してopadを処理 - 非volatileコピーを使用 */
    {
        u8 opad_copy[SHA256_BLOCK_SIZE];
        for (i = 0; i < SHA256_BLOCK_SIZE; i++) opad_copy[i] = opad[i];
        sha256_init(&ctx->outer);
        sha256_update(&ctx->outer, opad_copy, SHA256_BLOCK_SIZE);
        rintls_secure_zero(opad_copy, sizeof(opad_copy));
    }

    /* セキュリティのためパディングをクリア */
    for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
        key_pad[i] = 0;
        ipad[i] = 0;
        opad[i] = 0;
    }
}

void hmac_sha256_update(hmac_sha256_ctx* ctx, const u8* data, rin_size_t len)
{
    sha256_update(&ctx->inner, data, len);
}

void hmac_sha256_final(hmac_sha256_ctx* ctx, u8* mac)
{
    u8 inner_hash[SHA256_DIGEST_SIZE];

    /* inner hashを完了 */
    sha256_final(&ctx->inner, inner_hash);

    /* outer hashにinner hashを追加して完了 */
    sha256_update(&ctx->outer, inner_hash, SHA256_DIGEST_SIZE);
    sha256_final(&ctx->outer, mac);

    /* クリーンアップ */
    rintls_secure_zero(inner_hash, sizeof(inner_hash));
}

void hmac_sha256(const u8* key, rin_size_t key_len,
                 const u8* data, rin_size_t data_len,
                 u8* mac)
{
    hmac_sha256_ctx ctx;

    hmac_sha256_init(&ctx, key, key_len);
    hmac_sha256_update(&ctx, data, data_len);
    hmac_sha256_final(&ctx, mac);

    /* コンテキストをクリア */
    rintls_secure_zero(&ctx, sizeof(ctx));
}

/* ═══════════════════════════════════════
 * HMAC-SHA384
 * ═══════════════════════════════════════ */

void hmac_sha384_init(hmac_sha384_ctx* ctx, const u8* key, rin_size_t key_len)
{
    u8 key_pad[SHA384_BLOCK_SIZE];
    rin_size_t i;

    /* キーの前処理 */
    rintls_memset(key_pad, 0, SHA384_BLOCK_SIZE);

    if (key_len > SHA384_BLOCK_SIZE) {
        /* キーが長すぎる場合はハッシュする */
        sha384(key, key_len, key_pad);
    } else {
        rintls_memcpy(key_pad, key, key_len);
    }

    /* key_blockを保存 */
    rintls_memcpy(ctx->key_block, key_pad, SHA384_BLOCK_SIZE);

    /* inner pad (key XOR 0x36) */
    u8 ipad[SHA384_BLOCK_SIZE];
    for (i = 0; i < SHA384_BLOCK_SIZE; i++) {
        ipad[i] = key_pad[i] ^ 0x36;
    }

    /* outer pad (key XOR 0x5c) */
    u8 opad[SHA384_BLOCK_SIZE];
    for (i = 0; i < SHA384_BLOCK_SIZE; i++) {
        opad[i] = key_pad[i] ^ 0x5c;
    }

    /* inner hashを初期化してipadを処理 */
    sha384_init(&ctx->inner);
    sha384_update(&ctx->inner, ipad, SHA384_BLOCK_SIZE);

    /* outer hashを初期化してopadを処理 */
    sha384_init(&ctx->outer);
    sha384_update(&ctx->outer, opad, SHA384_BLOCK_SIZE);

    /* セキュリティのためパディングをクリア */
    rintls_memset(key_pad, 0, SHA384_BLOCK_SIZE);
    rintls_memset(ipad, 0, SHA384_BLOCK_SIZE);
    rintls_memset(opad, 0, SHA384_BLOCK_SIZE);
}

void hmac_sha384_update(hmac_sha384_ctx* ctx, const u8* data, rin_size_t len)
{
    sha384_update(&ctx->inner, data, len);
}

void hmac_sha384_final(hmac_sha384_ctx* ctx, u8* mac)
{
    u8 inner_hash[SHA384_DIGEST_SIZE];

    /* inner hashを完了 */
    sha384_final(&ctx->inner, inner_hash);

    /* outer hashにinner hashを追加して完了 */
    sha384_update(&ctx->outer, inner_hash, SHA384_DIGEST_SIZE);
    sha384_final(&ctx->outer, mac);

    /* クリーンアップ */
    rintls_memset(inner_hash, 0, SHA384_DIGEST_SIZE);
}

void hmac_sha384(const u8* key, rin_size_t key_len,
                 const u8* data, rin_size_t data_len,
                 u8* mac)
{
    hmac_sha384_ctx ctx;
    hmac_sha384_init(&ctx, key, key_len);
    hmac_sha384_update(&ctx, data, data_len);
    hmac_sha384_final(&ctx, mac);

    /* コンテキストをクリア */
    rintls_secure_zero(&ctx, sizeof(ctx));
}

/* ═══════════════════════════════════════
 * HMAC-SHA512
 * ═══════════════════════════════════════ */

void hmac_sha512_init(hmac_sha512_ctx* ctx, const u8* key, rin_size_t key_len)
{
    u8 key_pad[SHA512_BLOCK_SIZE];
    u8 ipad[SHA512_BLOCK_SIZE];
    u8 opad[SHA512_BLOCK_SIZE];
    rin_size_t i;

    rintls_memset(key_pad, 0, SHA512_BLOCK_SIZE);
    if (key_len > SHA512_BLOCK_SIZE) {
        sha512(key, key_len, key_pad);
    } else {
        rintls_memcpy(key_pad, key, key_len);
    }

    rintls_memcpy(ctx->key_block, key_pad, SHA512_BLOCK_SIZE);
    for (i = 0; i < SHA512_BLOCK_SIZE; i++) {
        ipad[i] = key_pad[i] ^ 0x36;
        opad[i] = key_pad[i] ^ 0x5c;
    }

    sha512_init(&ctx->inner);
    sha512_update(&ctx->inner, ipad, SHA512_BLOCK_SIZE);
    sha512_init(&ctx->outer);
    sha512_update(&ctx->outer, opad, SHA512_BLOCK_SIZE);

    rintls_secure_zero(key_pad, sizeof(key_pad));
    rintls_secure_zero(ipad, sizeof(ipad));
    rintls_secure_zero(opad, sizeof(opad));
}

void hmac_sha512_update(hmac_sha512_ctx* ctx, const u8* data, rin_size_t len)
{
    sha512_update(&ctx->inner, data, len);
}

void hmac_sha512_final(hmac_sha512_ctx* ctx, u8* mac)
{
    u8 inner_hash[SHA512_DIGEST_SIZE];

    sha512_final(&ctx->inner, inner_hash);
    sha512_update(&ctx->outer, inner_hash, SHA512_DIGEST_SIZE);
    sha512_final(&ctx->outer, mac);
    rintls_secure_zero(inner_hash, sizeof(inner_hash));
}

void hmac_sha512(const u8* key, rin_size_t key_len,
                 const u8* data, rin_size_t data_len,
                 u8* mac)
{
    hmac_sha512_ctx ctx;
    hmac_sha512_init(&ctx, key, key_len);
    hmac_sha512_update(&ctx, data, data_len);
    hmac_sha512_final(&ctx, mac);
    rintls_secure_zero(&ctx, sizeof(ctx));
}

/* ═══════════════════════════════════════
 * HKDF-SHA256 (RFC 5869)
 * ═══════════════════════════════════════ */

/*
 * HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
 */
void hkdf_sha256_extract(const u8* salt, rin_size_t salt_len,
                         const u8* ikm, rin_size_t ikm_len,
                         u8* prk)
{
    /* saltがNULLまたは0の場合、HashLen個のゼロを使用 */
    u8 default_salt[HMAC_SHA256_SIZE];
    if (salt == RIN_NULL || salt_len == 0) {
        rintls_memset(default_salt, 0, HMAC_SHA256_SIZE);
        salt = default_salt;
        salt_len = HMAC_SHA256_SIZE;
    }

    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    rintls_secure_zero(default_salt, sizeof(default_salt));
}

/*
 * HKDF-Expand: OKM = HKDF-Expand(PRK, info, L)
 *
 * T(0) = empty string
 * T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
 * T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
 * T(N) = HMAC-Hash(PRK, T(N-1) | info | N)
 * OKM = T(1) | T(2) | ... | T(N)
 */
/* Note: volatile prevents compiler optimizations that cause incorrect results */
void hkdf_sha256_expand(const u8* prk,
                        const u8* info, rin_size_t info_len,
                        u8* okm, rin_size_t okm_len)
{
    volatile u8 t[HMAC_SHA256_SIZE];
    volatile u8 counter;
    rin_size_t t_len = 0;
    rin_size_t pos = 0;
    rin_size_t copy_len;

    /* N = ceil(L / HashLen) */
    /* N <= 255 */

    for (counter = 1; pos < okm_len; counter++) {
        hmac_sha256_ctx ctx;
        hmac_sha256_init(&ctx, prk, HMAC_SHA256_SIZE);

        /* T(N-1) を追加 (最初は空) */
        if (t_len > 0) {
            /* Copy from volatile to pass to function */
            u8 t_copy[HMAC_SHA256_SIZE];
            for (int i = 0; i < HMAC_SHA256_SIZE; i++) t_copy[i] = t[i];
            hmac_sha256_update(&ctx, t_copy, t_len);
            rintls_secure_zero(t_copy, sizeof(t_copy));
        }

        /* info を追加 */
        if (info != RIN_NULL && info_len > 0) {
            hmac_sha256_update(&ctx, info, info_len);
        }

        /* counter を追加 */
        u8 cnt = counter;
        hmac_sha256_update(&ctx, &cnt, 1);

        /* T(N) を計算 */
        u8 t_result[HMAC_SHA256_SIZE];
        hmac_sha256_final(&ctx, t_result);
        for (int i = 0; i < HMAC_SHA256_SIZE; i++) t[i] = t_result[i];
        rintls_secure_zero(t_result, sizeof(t_result));
        t_len = HMAC_SHA256_SIZE;

        /* OKM にコピー */
        copy_len = okm_len - pos;
        if (copy_len > HMAC_SHA256_SIZE) {
            copy_len = HMAC_SHA256_SIZE;
        }
        for (rin_size_t i = 0; i < copy_len; i++) {
            okm[pos + i] = t[i];
        }
        pos += copy_len;

        /* コンテキストをクリア */
        rintls_secure_zero(&ctx, sizeof(ctx));
    }

    /* クリーンアップ */
    for (int i = 0; i < HMAC_SHA256_SIZE; i++) t[i] = 0;
}

/*
 * HKDF: Extract-then-Expand
 */
void hkdf_sha256(const u8* salt, rin_size_t salt_len,
                 const u8* ikm, rin_size_t ikm_len,
                 const u8* info, rin_size_t info_len,
                 u8* okm, rin_size_t okm_len)
{
    u8 prk[HMAC_SHA256_SIZE];

    hkdf_sha256_extract(salt, salt_len, ikm, ikm_len, prk);
    hkdf_sha256_expand(prk, info, info_len, okm, okm_len);

    /* クリーンアップ */
    rintls_secure_zero(prk, sizeof(prk));
}

/* ═══════════════════════════════════════
 * HKDF-SHA384 (RFC 5869)
 * ═══════════════════════════════════════ */

void hkdf_sha384_extract(const u8* salt, rin_size_t salt_len,
                         const u8* ikm, rin_size_t ikm_len,
                         u8* prk)
{
    u8 default_salt[HMAC_SHA384_SIZE];
    if (salt == RIN_NULL || salt_len == 0) {
        rintls_memset(default_salt, 0, HMAC_SHA384_SIZE);
        salt = default_salt;
        salt_len = HMAC_SHA384_SIZE;
    }

    hmac_sha384(salt, salt_len, ikm, ikm_len, prk);
}

void hkdf_sha384_expand(const u8* prk,
                        const u8* info, rin_size_t info_len,
                        u8* okm, rin_size_t okm_len)
{
    u8 t[HMAC_SHA384_SIZE];
    u8 counter;
    rin_size_t t_len = 0;
    rin_size_t pos = 0;
    rin_size_t copy_len;

    for (counter = 1; pos < okm_len; counter++) {
        hmac_sha384_ctx ctx;
        hmac_sha384_init(&ctx, prk, HMAC_SHA384_SIZE);

        if (t_len > 0) {
            hmac_sha384_update(&ctx, t, t_len);
        }

        if (info != RIN_NULL && info_len > 0) {
            hmac_sha384_update(&ctx, info, info_len);
        }

        hmac_sha384_update(&ctx, &counter, 1);
        hmac_sha384_final(&ctx, t);
        t_len = HMAC_SHA384_SIZE;

        copy_len = okm_len - pos;
        if (copy_len > HMAC_SHA384_SIZE) {
            copy_len = HMAC_SHA384_SIZE;
        }
        rintls_memcpy(okm + pos, t, copy_len);
        pos += copy_len;

        rintls_memset(&ctx, 0, sizeof(ctx));
    }

    rintls_memset(t, 0, HMAC_SHA384_SIZE);
}

void hkdf_sha384(const u8* salt, rin_size_t salt_len,
                 const u8* ikm, rin_size_t ikm_len,
                 const u8* info, rin_size_t info_len,
                 u8* okm, rin_size_t okm_len)
{
    u8 prk[HMAC_SHA384_SIZE];

    hkdf_sha384_extract(salt, salt_len, ikm, ikm_len, prk);
    hkdf_sha384_expand(prk, info, info_len, okm, okm_len);

    rintls_memset(prk, 0, HMAC_SHA384_SIZE);
}
