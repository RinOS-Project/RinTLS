/*
 * rinTLS - AES Block Cipher & GCM Mode Implementation
 * AES暗号化とGCMモード実装
 */

#include "aes.h"

/* Freestanding RinOS uses a 32-bit rin_size_t, so every representable input
 * length fits the 64-bit GCM length field. Hosted LP64 builds retain the
 * explicit bound; avoid an always-false comparison on narrower size_t. */
#if !defined(RIN_FREESTANDING) && SIZE_MAX > UINT64_MAX / 8u
#define AES_GCM_LENGTH_EXCEEDS_BIT_LIMIT(length) \
    ((u64)(length) > UINT64_MAX / 8u)
#else
#define AES_GCM_LENGTH_EXCEEDS_BIT_LIMIT(length) 0
#endif

/* Fixed-work GF(2^8) arithmetic avoids secret-indexed substitution tables. */
static u8 aes_gf_mul(u8 left, u8 right)
{
    u8 result = 0u;
    u32 bit;
    for (bit = 0u; bit < 8u; ++bit) {
        u8 select = (u8)(0u - (u32)(right & 1u));
        u8 high = (u8)(0u - (u32)(left >> 7));
        result ^= (u8)(left & select);
        left = (u8)((left << 1) ^ (0x1bu & high));
        right >>= 1;
    }
    return result;
}

static u8 aes_gf_inverse(u8 value)
{
    u8 x2 = aes_gf_mul(value, value);
    u8 x4 = aes_gf_mul(x2, x2);
    u8 x8 = aes_gf_mul(x4, x4);
    u8 x16 = aes_gf_mul(x8, x8);
    u8 x32 = aes_gf_mul(x16, x16);
    u8 x64 = aes_gf_mul(x32, x32);
    u8 x128 = aes_gf_mul(x64, x64);
    u8 inverse = aes_gf_mul(x128, x64);
    inverse = aes_gf_mul(inverse, x32);
    inverse = aes_gf_mul(inverse, x16);
    inverse = aes_gf_mul(inverse, x8);
    inverse = aes_gf_mul(inverse, x4);
    return aes_gf_mul(inverse, x2);
}

static u8 aes_rotl8(u8 value, u32 shift)
{
    return (u8)((value << shift) | (value >> (8u - shift)));
}

static u8 aes_sub_byte(u8 value)
{
    u8 inverse = aes_gf_inverse(value);
    return (u8)(inverse ^ aes_rotl8(inverse, 1u) ^
                aes_rotl8(inverse, 2u) ^ aes_rotl8(inverse, 3u) ^
                aes_rotl8(inverse, 4u) ^ 0x63u);
}

static u8 aes_inv_sub_byte(u8 value)
{
    u8 inverse_affine = (u8)(aes_rotl8(value, 1u) ^
                             aes_rotl8(value, 3u) ^
                             aes_rotl8(value, 6u) ^ 0x05u);
    return aes_gf_inverse(inverse_affine);
}

/* Round constants */
static const u8 rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* GF(2^8) multiplication for MixColumns */
static u8 xtime(u8 x) {
    return (u8)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}


/* Key expansion */
int aes_init(aes_ctx* ctx, const u8* key, int key_size) {
    int nk, i;
    u8 temp[4];
    u8 key_copy[AES256_KEY_SIZE] = {0};

    if (!ctx) return -1;
    if (!key || (key_size != AES128_KEY_SIZE &&
                 key_size != AES192_KEY_SIZE &&
                 key_size != AES256_KEY_SIZE)) {
        rintls_secure_zero(ctx, sizeof(*ctx));
        return -1;
    }
    rintls_memcpy(key_copy, key, (rin_size_t)key_size);
    rintls_secure_zero(ctx, sizeof(*ctx));

    if (key_size == 16) {
        ctx->nr = 10;
        nk = 4;
    } else if (key_size == 24) {
        ctx->nr = 12;
        nk = 6;
    } else if (key_size == 32) {
        ctx->nr = 14;
        nk = 8;
    } else {
        rintls_secure_zero(key_copy, sizeof(key_copy));
        return -1;
    }

    /* Copy key to first nk words */
    for (i = 0; i < nk; i++) {
        ctx->rk[i] = rintls_read_be32(key_copy + i * 4);
    }

    /* Expand key */
    for (i = nk; i < 4 * (ctx->nr + 1); i++) {
        u32 tmp = ctx->rk[i - 1];

        if (i % nk == 0) {
            /* RotWord + SubWord + Rcon */
            temp[0] = aes_sub_byte((u8)((tmp >> 16) & 0xFF)) ^ rcon[i / nk];
            temp[1] = aes_sub_byte((u8)((tmp >> 8) & 0xFF));
            temp[2] = aes_sub_byte((u8)(tmp & 0xFF));
            temp[3] = aes_sub_byte((u8)((tmp >> 24) & 0xFF));
            tmp = ((u32)temp[0] << 24) | ((u32)temp[1] << 16) | ((u32)temp[2] << 8) | temp[3];
        } else if (nk > 6 && i % nk == 4) {
            /* SubWord only for AES-256 */
            temp[0] = aes_sub_byte((u8)((tmp >> 24) & 0xFF));
            temp[1] = aes_sub_byte((u8)((tmp >> 16) & 0xFF));
            temp[2] = aes_sub_byte((u8)((tmp >> 8) & 0xFF));
            temp[3] = aes_sub_byte((u8)(tmp & 0xFF));
            tmp = ((u32)temp[0] << 24) | ((u32)temp[1] << 16) | ((u32)temp[2] << 8) | temp[3];
        }

        ctx->rk[i] = ctx->rk[i - nk] ^ tmp;
    }

    rintls_secure_zero(temp, sizeof(temp));
    rintls_secure_zero(key_copy, sizeof(key_copy));
    return 0;
}

/* AES encrypt block */
void aes_encrypt_block(const aes_ctx* ctx, const u8* in, u8* out) {
    u8 state[16];
    int i, round;

    /* Copy input to state */
    rintls_memcpy(state, in, 16);

    /* Initial AddRoundKey */
    for (i = 0; i < 4; i++) {
        u32 rk = ctx->rk[i];
        state[i*4+0] ^= (rk >> 24) & 0xFF;
        state[i*4+1] ^= (rk >> 16) & 0xFF;
        state[i*4+2] ^= (rk >> 8) & 0xFF;
        state[i*4+3] ^= rk & 0xFF;
    }

    /* Main rounds */
    for (round = 1; round < ctx->nr; round++) {
        u8 tmp[16];

        /* SubBytes + ShiftRows */
        tmp[0]  = aes_sub_byte((u8)(state[0]));
        tmp[1]  = aes_sub_byte((u8)(state[5]));
        tmp[2]  = aes_sub_byte((u8)(state[10]));
        tmp[3]  = aes_sub_byte((u8)(state[15]));
        tmp[4]  = aes_sub_byte((u8)(state[4]));
        tmp[5]  = aes_sub_byte((u8)(state[9]));
        tmp[6]  = aes_sub_byte((u8)(state[14]));
        tmp[7]  = aes_sub_byte((u8)(state[3]));
        tmp[8]  = aes_sub_byte((u8)(state[8]));
        tmp[9]  = aes_sub_byte((u8)(state[13]));
        tmp[10] = aes_sub_byte((u8)(state[2]));
        tmp[11] = aes_sub_byte((u8)(state[7]));
        tmp[12] = aes_sub_byte((u8)(state[12]));
        tmp[13] = aes_sub_byte((u8)(state[1]));
        tmp[14] = aes_sub_byte((u8)(state[6]));
        tmp[15] = aes_sub_byte((u8)(state[11]));

        /* MixColumns */
        for (i = 0; i < 4; i++) {
            u8 a = tmp[i*4+0], b = tmp[i*4+1], c = tmp[i*4+2], d = tmp[i*4+3];
            u8 e = a ^ b ^ c ^ d;
            state[i*4+0] = a ^ e ^ xtime(a ^ b);
            state[i*4+1] = b ^ e ^ xtime(b ^ c);
            state[i*4+2] = c ^ e ^ xtime(c ^ d);
            state[i*4+3] = d ^ e ^ xtime(d ^ a);
        }

        /* AddRoundKey */
        for (i = 0; i < 4; i++) {
            u32 rk = ctx->rk[round * 4 + i];
            state[i*4+0] ^= (rk >> 24) & 0xFF;
            state[i*4+1] ^= (rk >> 16) & 0xFF;
            state[i*4+2] ^= (rk >> 8) & 0xFF;
            state[i*4+3] ^= rk & 0xFF;
        }
    }

    /* Final round (no MixColumns) */
    {
        u8 tmp[16];
        tmp[0]  = aes_sub_byte((u8)(state[0]));
        tmp[1]  = aes_sub_byte((u8)(state[5]));
        tmp[2]  = aes_sub_byte((u8)(state[10]));
        tmp[3]  = aes_sub_byte((u8)(state[15]));
        tmp[4]  = aes_sub_byte((u8)(state[4]));
        tmp[5]  = aes_sub_byte((u8)(state[9]));
        tmp[6]  = aes_sub_byte((u8)(state[14]));
        tmp[7]  = aes_sub_byte((u8)(state[3]));
        tmp[8]  = aes_sub_byte((u8)(state[8]));
        tmp[9]  = aes_sub_byte((u8)(state[13]));
        tmp[10] = aes_sub_byte((u8)(state[2]));
        tmp[11] = aes_sub_byte((u8)(state[7]));
        tmp[12] = aes_sub_byte((u8)(state[12]));
        tmp[13] = aes_sub_byte((u8)(state[1]));
        tmp[14] = aes_sub_byte((u8)(state[6]));
        tmp[15] = aes_sub_byte((u8)(state[11]));

        for (i = 0; i < 4; i++) {
            u32 rk = ctx->rk[ctx->nr * 4 + i];
            out[i*4+0] = tmp[i*4+0] ^ ((rk >> 24) & 0xFF);
            out[i*4+1] = tmp[i*4+1] ^ ((rk >> 16) & 0xFF);
            out[i*4+2] = tmp[i*4+2] ^ ((rk >> 8) & 0xFF);
            out[i*4+3] = tmp[i*4+3] ^ (rk & 0xFF);
        }
    }
}

/* AES decrypt block */
void aes_decrypt_block(const aes_ctx* ctx, const u8* in, u8* out) {
    u8 state[16];
    int i, round;

    rintls_memcpy(state, in, 16);

    /* Initial AddRoundKey */
    for (i = 0; i < 4; i++) {
        u32 rk = ctx->rk[ctx->nr * 4 + i];
        state[i*4+0] ^= (rk >> 24) & 0xFF;
        state[i*4+1] ^= (rk >> 16) & 0xFF;
        state[i*4+2] ^= (rk >> 8) & 0xFF;
        state[i*4+3] ^= rk & 0xFF;
    }

    /* Main rounds (reverse) */
    for (round = ctx->nr - 1; round > 0; round--) {
        u8 tmp[16];

        /* InvShiftRows + InvSubBytes */
        tmp[0]  = aes_inv_sub_byte((u8)(state[0]));
        tmp[1]  = aes_inv_sub_byte((u8)(state[13]));
        tmp[2]  = aes_inv_sub_byte((u8)(state[10]));
        tmp[3]  = aes_inv_sub_byte((u8)(state[7]));
        tmp[4]  = aes_inv_sub_byte((u8)(state[4]));
        tmp[5]  = aes_inv_sub_byte((u8)(state[1]));
        tmp[6]  = aes_inv_sub_byte((u8)(state[14]));
        tmp[7]  = aes_inv_sub_byte((u8)(state[11]));
        tmp[8]  = aes_inv_sub_byte((u8)(state[8]));
        tmp[9]  = aes_inv_sub_byte((u8)(state[5]));
        tmp[10] = aes_inv_sub_byte((u8)(state[2]));
        tmp[11] = aes_inv_sub_byte((u8)(state[15]));
        tmp[12] = aes_inv_sub_byte((u8)(state[12]));
        tmp[13] = aes_inv_sub_byte((u8)(state[9]));
        tmp[14] = aes_inv_sub_byte((u8)(state[6]));
        tmp[15] = aes_inv_sub_byte((u8)(state[3]));

        /* AddRoundKey */
        for (i = 0; i < 4; i++) {
            u32 rk = ctx->rk[round * 4 + i];
            tmp[i*4+0] ^= (rk >> 24) & 0xFF;
            tmp[i*4+1] ^= (rk >> 16) & 0xFF;
            tmp[i*4+2] ^= (rk >> 8) & 0xFF;
            tmp[i*4+3] ^= rk & 0xFF;
        }

        /* InvMixColumns */
        for (i = 0; i < 4; i++) {
            u8 a = tmp[i*4+0], b = tmp[i*4+1], c = tmp[i*4+2], d = tmp[i*4+3];
            state[i*4+0] = aes_gf_mul(a, 0x0e) ^ aes_gf_mul(b, 0x0b) ^ aes_gf_mul(c, 0x0d) ^ aes_gf_mul(d, 0x09);
            state[i*4+1] = aes_gf_mul(a, 0x09) ^ aes_gf_mul(b, 0x0e) ^ aes_gf_mul(c, 0x0b) ^ aes_gf_mul(d, 0x0d);
            state[i*4+2] = aes_gf_mul(a, 0x0d) ^ aes_gf_mul(b, 0x09) ^ aes_gf_mul(c, 0x0e) ^ aes_gf_mul(d, 0x0b);
            state[i*4+3] = aes_gf_mul(a, 0x0b) ^ aes_gf_mul(b, 0x0d) ^ aes_gf_mul(c, 0x09) ^ aes_gf_mul(d, 0x0e);
        }
    }

    /* Final round */
    {
        u8 tmp[16];
        tmp[0]  = aes_inv_sub_byte((u8)(state[0]));
        tmp[1]  = aes_inv_sub_byte((u8)(state[13]));
        tmp[2]  = aes_inv_sub_byte((u8)(state[10]));
        tmp[3]  = aes_inv_sub_byte((u8)(state[7]));
        tmp[4]  = aes_inv_sub_byte((u8)(state[4]));
        tmp[5]  = aes_inv_sub_byte((u8)(state[1]));
        tmp[6]  = aes_inv_sub_byte((u8)(state[14]));
        tmp[7]  = aes_inv_sub_byte((u8)(state[11]));
        tmp[8]  = aes_inv_sub_byte((u8)(state[8]));
        tmp[9]  = aes_inv_sub_byte((u8)(state[5]));
        tmp[10] = aes_inv_sub_byte((u8)(state[2]));
        tmp[11] = aes_inv_sub_byte((u8)(state[15]));
        tmp[12] = aes_inv_sub_byte((u8)(state[12]));
        tmp[13] = aes_inv_sub_byte((u8)(state[9]));
        tmp[14] = aes_inv_sub_byte((u8)(state[6]));
        tmp[15] = aes_inv_sub_byte((u8)(state[3]));

        for (i = 0; i < 4; i++) {
            u32 rk = ctx->rk[i];
            out[i*4+0] = tmp[i*4+0] ^ ((rk >> 24) & 0xFF);
            out[i*4+1] = tmp[i*4+1] ^ ((rk >> 16) & 0xFF);
            out[i*4+2] = tmp[i*4+2] ^ ((rk >> 8) & 0xFF);
            out[i*4+3] = tmp[i*4+3] ^ (rk & 0xFF);
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * GCM Mode Implementation
 * ═══════════════════════════════════════════════════════════════════════════ */

/* GF(2^128) multiplication for GHASH
 * Note: volatile prevents compiler optimizations that cause incorrect results */
static void gcm_mult(u8* x, const u8* h) {
    volatile u8 z[16] = {0};
    volatile u8 v[16];
    int i, j;

    for (i = 0; i < 16; i++) v[i] = h[i];

    for (i = 0; i < 16; i++) {
        for (j = 0; j < 8; j++) {
            if (x[i] & (1 << (7 - j))) {
                for (int k = 0; k < 16; k++) z[k] ^= v[k];
            }

            /* v = v >> 1 in GF(2^128) */
            int carry = v[15] & 1;
            for (int k = 15; k > 0; k--) {
                v[k] = (u8)((v[k] >> 1) | ((v[k-1] & 1) << 7));
            }
            v[0] >>= 1;
            if (carry) v[0] ^= 0xe1;
        }
    }

    for (i = 0; i < 16; i++) x[i] = z[i];
}

/* GHASH update */
static void ghash_update(aes_gcm_ctx* ctx, const u8* data, rin_size_t len) {
    while (len >= 16) {
        for (int i = 0; i < 16; i++) {
            ctx->ghash[i] ^= data[i];
        }
        gcm_mult(ctx->ghash, ctx->h);
        data += 16;
        len -= 16;
    }

    if (len > 0) {
        for (rin_size_t i = 0; i < len; i++) {
            ctx->ghash[i] ^= data[i];
        }
        gcm_mult(ctx->ghash, ctx->h);
    }
}

/* Increment counter */
static void gcm_inc_counter(u8* counter) {
    u32 c = rintls_read_be32(counter + 12);
    c++;
    rintls_write_be32(counter + 12, c);
}

#define AES_GCM_PHASE_UNKEYED 0u
#define AES_GCM_PHASE_AAD 1u
#define AES_GCM_PHASE_DATA 2u
#define AES_GCM_PHASE_FINISHED 3u
#define AES_GCM_MODE_UNSET 0u
#define AES_GCM_MODE_ENCRYPT 1u
#define AES_GCM_MODE_DECRYPT 2u
#define AES_GCM_MAX_CIPHERTEXT_BITS ((UINT64_C(1) << 39) - UINT64_C(256))

static int aes_gcm_lengths_valid(rin_size_t aad_len, rin_size_t ct_len) {
    u64 aad_bytes = (u64)aad_len;
    u64 ct_bytes = (u64)ct_len;
    return aad_bytes <= UINT64_MAX / 8u &&
           ct_bytes <= AES_GCM_MAX_CIPHERTEXT_BITS / 8u;
}

static void ghash_block(aes_gcm_ctx* ctx, const u8 block[16]) {
    for (int i = 0; i < 16; ++i) ctx->ghash[i] ^= block[i];
    gcm_mult(ctx->ghash, ctx->h);
}

static void ghash_stream_update(aes_gcm_ctx* ctx, u8 partial[16],
                                u8* partial_len, const u8* data,
                                rin_size_t len) {
    while (len != 0u) {
        rin_size_t available = (rin_size_t)(16u - *partial_len);
        rin_size_t take = len < available ? len : available;
        rintls_memcpy(partial + *partial_len, data, take);
        *partial_len = (u8)(*partial_len + take);
        data += take;
        len -= take;
        if (*partial_len == 16u) {
            ghash_block(ctx, partial);
            rintls_memzero(partial, 16u);
            *partial_len = 0u;
        }
    }
}

static void ghash_stream_finish(aes_gcm_ctx* ctx, u8 partial[16],
                                u8* partial_len) {
    if (*partial_len == 0u) return;
    ghash_block(ctx, partial);
    rintls_memzero(partial, 16u);
    *partial_len = 0u;
}

static int aes_gcm_fail(aes_gcm_ctx* ctx) {
    if (ctx != NULL) ctx->error = 1u;
    return -1;
}

static int aes_gcm_crypt_inplace(aes_gcm_ctx* ctx, u8* data,
                                 rin_size_t len, u8 mode) {
    u64 bytes = (u64)len;
    if (ctx == NULL || ctx->initialized == 0u || ctx->error != 0u ||
        (ctx->phase != AES_GCM_PHASE_AAD &&
         ctx->phase != AES_GCM_PHASE_DATA) ||
        (len != 0u && data == NULL))
        return aes_gcm_fail(ctx);
    if (len == 0u) return 0;
    if ((ctx->mode != AES_GCM_MODE_UNSET && ctx->mode != mode) ||
        ctx->ct_len > AES_GCM_MAX_CIPHERTEXT_BITS ||
        bytes > (AES_GCM_MAX_CIPHERTEXT_BITS - ctx->ct_len) / 8u)
        return aes_gcm_fail(ctx);

    if (ctx->phase == AES_GCM_PHASE_AAD) {
        ghash_stream_finish(ctx, ctx->aad_partial,
                            &ctx->aad_partial_len);
        ctx->phase = AES_GCM_PHASE_DATA;
    }
    ctx->mode = mode;
    ctx->ct_len += bytes * 8u;
    for (rin_size_t index = 0; index < len; ++index) {
        u8 ciphertext;
        if (ctx->keystream_offset == 16u) {
            aes_encrypt_block(&ctx->aes, ctx->counter, ctx->keystream);
            gcm_inc_counter(ctx->counter);
            ctx->keystream_offset = 0u;
        }
        if (mode == AES_GCM_MODE_ENCRYPT) {
            data[index] ^= ctx->keystream[ctx->keystream_offset];
            ciphertext = data[index];
        } else {
            ciphertext = data[index];
            data[index] ^= ctx->keystream[ctx->keystream_offset];
        }
        ++ctx->keystream_offset;
        ghash_stream_update(ctx, ctx->ct_partial, &ctx->ct_partial_len,
                            &ciphertext, 1u);
    }
    return 0;
}

int aes_gcm_init(aes_gcm_ctx* ctx, const u8* key, int key_size) {
    if (!ctx || !key) return -1;
    rintls_secure_zero(ctx, sizeof(*ctx));

    if (aes_init(&ctx->aes, key, key_size) != 0) {
        rintls_secure_zero(ctx, sizeof(*ctx));
        return -1;
    }

    /* Compute hash subkey H = AES(K, 0^128) */
    u8 zero[16] = {0};
    aes_encrypt_block(&ctx->aes, zero, ctx->h);
    ctx->phase = AES_GCM_PHASE_UNKEYED;
    ctx->initialized = 1u;

    return 0;
}

int aes_gcm_set_iv(aes_gcm_ctx* ctx, const u8* iv, rin_size_t iv_len) {
    if (ctx == NULL || ctx->initialized == 0u || iv == NULL ||
        iv_len == 0u || AES_GCM_LENGTH_EXCEEDS_BIT_LIMIT(iv_len))
        return aes_gcm_fail(ctx);
    rintls_memset(ctx->ghash, 0, 16);
    rintls_memset(ctx->aad_partial, 0, sizeof(ctx->aad_partial));
    rintls_memset(ctx->ct_partial, 0, sizeof(ctx->ct_partial));
    rintls_memset(ctx->keystream, 0, sizeof(ctx->keystream));
    ctx->aad_len = 0;
    ctx->ct_len = 0;
    ctx->aad_partial_len = 0u;
    ctx->ct_partial_len = 0u;
    ctx->keystream_offset = 16u;
    ctx->mode = AES_GCM_MODE_UNSET;
    ctx->error = 0u;

    if (iv_len == 12) {
        /* Standard 96-bit IV */
        rintls_memcpy(ctx->j0, iv, 12);
        ctx->j0[12] = 0;
        ctx->j0[13] = 0;
        ctx->j0[14] = 0;
        ctx->j0[15] = 1;
    } else {
        /* Non-standard IV: GHASH it */
        u8 len_block[16] = {0};
        rintls_memset(ctx->j0, 0, 16);

        /* Process IV through GHASH */
        ghash_update(ctx, iv, iv_len);

        /* ghash_update zero-pads its final partial IV block. */
        rintls_write_be64(len_block + 8, (u64)iv_len * 8);
        ghash_update(ctx, len_block, 16);

        rintls_memcpy(ctx->j0, ctx->ghash, 16);
        rintls_memset(ctx->ghash, 0, 16);
        rintls_memzero(len_block, sizeof(len_block));
    }

    rintls_memcpy(ctx->counter, ctx->j0, 16);
    gcm_inc_counter(ctx->counter);
    ctx->phase = AES_GCM_PHASE_AAD;
    return 0;
}

int aes_gcm_aad(aes_gcm_ctx* ctx, const u8* aad, rin_size_t aad_len) {
    u64 bytes = (u64)aad_len;
    if (ctx == NULL || ctx->initialized == 0u || ctx->error != 0u ||
        ctx->phase != AES_GCM_PHASE_AAD ||
        (aad_len != 0u && aad == NULL))
        return aes_gcm_fail(ctx);
    if (bytes > (UINT64_MAX - ctx->aad_len) / 8u)
        return aes_gcm_fail(ctx);
    if (aad_len == 0u) return 0;
    ctx->aad_len += bytes * 8u;
    ghash_stream_update(ctx, ctx->aad_partial, &ctx->aad_partial_len,
                        aad, aad_len);
    return 0;
}

int aes_gcm_encrypt_inplace(aes_gcm_ctx* ctx, u8* data, rin_size_t len) {
    return aes_gcm_crypt_inplace(ctx, data, len, AES_GCM_MODE_ENCRYPT);
}

int aes_gcm_decrypt_inplace(aes_gcm_ctx* ctx, u8* data, rin_size_t len) {
    return aes_gcm_crypt_inplace(ctx, data, len, AES_GCM_MODE_DECRYPT);
}

int aes_gcm_finish(aes_gcm_ctx* ctx, u8* tag) {
    if (ctx == NULL || tag == NULL || ctx->initialized == 0u ||
        ctx->error != 0u ||
        (ctx->phase != AES_GCM_PHASE_AAD &&
         ctx->phase != AES_GCM_PHASE_DATA)) {
        if (tag != NULL) rintls_memzero(tag, AES_GCM_TAG_SIZE);
        return aes_gcm_fail(ctx);
    }
    ghash_stream_finish(ctx, ctx->aad_partial, &ctx->aad_partial_len);
    ghash_stream_finish(ctx, ctx->ct_partial, &ctx->ct_partial_len);
    u8 len_block[16];
    u8 s[16];
    rintls_write_be64(len_block, ctx->aad_len);
    rintls_write_be64(len_block + 8, ctx->ct_len);
    ghash_block(ctx, len_block);

    aes_encrypt_block(&ctx->aes, ctx->j0, s);
    for (int i = 0; i < 16; i++) tag[i] = ctx->ghash[i] ^ s[i];
    ctx->phase = AES_GCM_PHASE_FINISHED;
    rintls_memzero(ctx->aad_partial, sizeof(ctx->aad_partial));
    rintls_memzero(ctx->ct_partial, sizeof(ctx->ct_partial));
    rintls_memzero(ctx->keystream, sizeof(ctx->keystream));
    rintls_memzero(len_block, sizeof(len_block));
    rintls_memzero(s, sizeof(s));
    return 0;
}

int aes_gcm_verify(aes_gcm_ctx* ctx, const u8* tag) {
    u8 computed_tag[AES_GCM_TAG_SIZE] = {0};
    if (tag == NULL || aes_gcm_finish(ctx, computed_tag) != 0) {
        rintls_memzero(computed_tag, sizeof(computed_tag));
        return -1;
    }
    int result = rintls_secure_compare(computed_tag, tag, 16);
    rintls_memzero(computed_tag, sizeof(computed_tag));
    return result;
}

/* One-shot functions */
int aes_gcm_encrypt_full(
    const u8* key, int key_size,
    const u8* iv, rin_size_t iv_len,
    const u8* aad, rin_size_t aad_len,
    const u8* plaintext, rin_size_t pt_len,
    u8* ciphertext,
    u8* tag
) {
    aes_gcm_ctx ctx;

    if (!key || !iv || iv_len == 0 ||
        AES_GCM_LENGTH_EXCEEDS_BIT_LIMIT(iv_len) ||
        !aes_gcm_lengths_valid(aad_len, pt_len) ||
        (aad_len != 0 && !aad) || !tag ||
        (pt_len != 0 && (!plaintext || !ciphertext)))
        return -1;

    if (aes_gcm_init(&ctx, key, key_size) != 0) return -1;

    if (aes_gcm_set_iv(&ctx, iv, iv_len) != 0) {
        rintls_memzero(&ctx, sizeof(ctx));
        return -1;
    }

    if (aad && aad_len > 0) {
        if (aes_gcm_aad(&ctx, aad, aad_len) != 0) {
            rintls_memzero(&ctx, sizeof(ctx));
            return -1;
        }
    }

    if (pt_len != 0) {
        if (ciphertext != plaintext)
            rintls_memcpy(ciphertext, plaintext, pt_len);
        if (aes_gcm_encrypt_inplace(&ctx, ciphertext, pt_len) != 0) {
            rintls_memzero(ciphertext, pt_len);
            rintls_memzero(&ctx, sizeof(ctx));
            return -1;
        }
    }

    if (aes_gcm_finish(&ctx, tag) != 0) {
        if (pt_len != 0u) rintls_memzero(ciphertext, pt_len);
        rintls_memzero(&ctx, sizeof(ctx));
        return -1;
    }

    rintls_memzero(&ctx, sizeof(ctx));
    return 0;
}

int aes_gcm_decrypt_full(
    const u8* key, int key_size,
    const u8* iv, rin_size_t iv_len,
    const u8* aad, rin_size_t aad_len,
    const u8* ciphertext, rin_size_t ct_len,
    u8* plaintext,
    const u8* tag
) {
    aes_gcm_ctx ctx;

    if (!key || !iv || iv_len == 0 ||
        AES_GCM_LENGTH_EXCEEDS_BIT_LIMIT(iv_len) ||
        !aes_gcm_lengths_valid(aad_len, ct_len) ||
        (aad_len != 0 && !aad) || !tag ||
        (ct_len != 0 && (!ciphertext || !plaintext)))
        return -1;

    if (aes_gcm_init(&ctx, key, key_size) != 0) return -1;

    if (aes_gcm_set_iv(&ctx, iv, iv_len) != 0) {
        rintls_memzero(&ctx, sizeof(ctx));
        return -1;
    }

    if (aad && aad_len > 0) {
        if (aes_gcm_aad(&ctx, aad, aad_len) != 0) {
            rintls_memzero(&ctx, sizeof(ctx));
            return -1;
        }
    }

    if (ct_len != 0) {
        rintls_memcpy(plaintext, ciphertext, ct_len);
        if (aes_gcm_decrypt_inplace(&ctx, plaintext, ct_len) != 0) {
            rintls_memzero(plaintext, ct_len);
            rintls_memzero(&ctx, sizeof(ctx));
            return -1;
        }
    }

    int result = aes_gcm_verify(&ctx, tag);

    if (result != 0) {
        /* Authentication failed - clear plaintext */
        if (ct_len != 0) rintls_memzero(plaintext, ct_len);
    }

    rintls_memzero(&ctx, sizeof(ctx));
    return result;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Context-based GCM Functions for TLS (using pre-initialized aes_ctx)
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * AES-GCM encrypt using pre-initialized aes_ctx
 * This is the signature expected by TLS record layer
 */
int aes_gcm_encrypt(
    aes_ctx* ctx,
    const u8* nonce, rin_size_t nonce_len,
    const u8* aad, rin_size_t aad_len,
    const u8* plaintext, rin_size_t pt_len,
    u8* ciphertext, rin_size_t* ct_len,
    u8* tag, rin_size_t tag_len
) {
    aes_gcm_ctx gcm;
    if (ct_len) *ct_len = 0;
    if (!ctx || !nonce || nonce_len == 0 ||
        AES_GCM_LENGTH_EXCEEDS_BIT_LIMIT(nonce_len) || !ct_len || !tag ||
        tag_len != AES_GCM_TAG_SIZE || (aad_len != 0 && !aad) ||
        !aes_gcm_lengths_valid(aad_len, pt_len) ||
        (pt_len != 0 && (!plaintext || !ciphertext)))
        return -1;

    rintls_memset(&gcm, 0, sizeof(gcm));
    rintls_memcpy(&gcm.aes, ctx, sizeof(aes_ctx));

    /* Compute hash subkey H = AES(K, 0^128) */
    u8 zero[16] = {0};
    aes_encrypt_block(&gcm.aes, zero, gcm.h);

    /* Set IV */
    if (nonce_len == 12) {
        rintls_memcpy(gcm.j0, nonce, 12);
        gcm.j0[12] = 0;
        gcm.j0[13] = 0;
        gcm.j0[14] = 0;
        gcm.j0[15] = 1;
    } else {
        /* Non-standard IV length - GHASH it */
        rintls_memset(gcm.j0, 0, 16);
        ghash_update(&gcm, nonce, nonce_len);
        u8 len_block[16] = {0};
        rintls_write_be64(len_block + 8, (u64)nonce_len * 8);
        ghash_update(&gcm, len_block, 16);
        rintls_memcpy(gcm.j0, gcm.ghash, 16);
        rintls_memset(gcm.ghash, 0, 16);
        rintls_memzero(len_block, sizeof(len_block));
    }

    rintls_memcpy(gcm.counter, gcm.j0, 16);
    gcm_inc_counter(gcm.counter);

    /* Process AAD */
    /* NOTE: ghash_update handles partial blocks with implicit zero padding */
    if (aad && aad_len > 0) {
        gcm.aad_len = (u64)aad_len * 8u;
        ghash_update(&gcm, aad, aad_len);
    }

    /* Encrypt */
    if (pt_len != 0 && ciphertext != plaintext)
        rintls_memcpy(ciphertext, plaintext, pt_len);
    gcm.ct_len = (u64)pt_len * 8u;

    u8 keystream[16];
    u8* data = ciphertext;
    rin_size_t len = pt_len;

    while (len >= 16) {
        aes_encrypt_block(&gcm.aes, gcm.counter, keystream);
        gcm_inc_counter(gcm.counter);
        for (int i = 0; i < 16; i++) data[i] ^= keystream[i];
        for (int i = 0; i < 16; i++) gcm.ghash[i] ^= data[i];
        gcm_mult(gcm.ghash, gcm.h);
        data += 16;
        len -= 16;
    }
    if (len > 0) {
        aes_encrypt_block(&gcm.aes, gcm.counter, keystream);
        gcm_inc_counter(gcm.counter);
        for (rin_size_t i = 0; i < len; i++) data[i] ^= keystream[i];
        for (rin_size_t i = 0; i < len; i++) gcm.ghash[i] ^= data[i];
        gcm_mult(gcm.ghash, gcm.h);
    }

    *ct_len = pt_len;

    /* Compute tag */
    /* NOTE: No additional padding needed - short blocks already processed
     * with implicit zero padding in the loop above */
    u8 len_block[16];
    rintls_write_be64(len_block, gcm.aad_len);
    rintls_write_be64(len_block + 8, gcm.ct_len);
    ghash_update(&gcm, len_block, 16);

    u8 s[16];
    aes_encrypt_block(&gcm.aes, gcm.j0, s);
    for (int i = 0; i < 16; i++) tag[i] = gcm.ghash[i] ^ s[i];

    rintls_memzero(keystream, sizeof(keystream));
    rintls_memzero(len_block, sizeof(len_block));
    rintls_memzero(s, sizeof(s));
    rintls_memzero(&gcm, sizeof(gcm));
    return 0;
}

/*
 * AES-GCM decrypt using pre-initialized aes_ctx
 * Returns 0 on success, -1 on authentication failure
 */
int aes_gcm_decrypt(
    aes_ctx* ctx,
    const u8* nonce, rin_size_t nonce_len,
    const u8* aad, rin_size_t aad_len,
    const u8* ciphertext, rin_size_t ct_len,
    const u8* tag, rin_size_t tag_len,
    u8* plaintext, rin_size_t* pt_len
) {
    aes_gcm_ctx gcm;
    if (pt_len) *pt_len = 0;
    if (!ctx || !nonce || nonce_len == 0 ||
        AES_GCM_LENGTH_EXCEEDS_BIT_LIMIT(nonce_len) ||
        !tag || tag_len != 16 ||
        !aes_gcm_lengths_valid(aad_len, ct_len) ||
        !plaintext || !pt_len || (aad_len != 0 && !aad) ||
        (ct_len != 0 && !ciphertext)) {
        return -1;
    }

    rintls_memset(&gcm, 0, sizeof(gcm));
    rintls_memcpy(&gcm.aes, ctx, sizeof(aes_ctx));

    /* Compute hash subkey H */
    u8 zero[16] = {0};
    aes_encrypt_block(&gcm.aes, zero, gcm.h);

    /* Set IV */
    if (nonce_len == 12) {
        rintls_memcpy(gcm.j0, nonce, 12);
        gcm.j0[12] = 0;
        gcm.j0[13] = 0;
        gcm.j0[14] = 0;
        gcm.j0[15] = 1;
    } else {
        rintls_memset(gcm.j0, 0, 16);
        ghash_update(&gcm, nonce, nonce_len);
        u8 len_block[16] = {0};
        rintls_write_be64(len_block + 8, (u64)nonce_len * 8);
        ghash_update(&gcm, len_block, 16);
        rintls_memcpy(gcm.j0, gcm.ghash, 16);
        rintls_memset(gcm.ghash, 0, 16);
        rintls_memzero(len_block, sizeof(len_block));
    }

    rintls_memcpy(gcm.counter, gcm.j0, 16);
    gcm_inc_counter(gcm.counter);

    /* Process AAD */
    /* NOTE: ghash_update handles partial blocks with implicit zero padding,
     * so no explicit padding is needed here */
    if (aad && aad_len > 0) {
        gcm.aad_len = (u64)aad_len * 8u;
        ghash_update(&gcm, aad, aad_len);
    }

    /* Decrypt and compute GHASH */
    if (ct_len != 0) rintls_memcpy(plaintext, ciphertext, ct_len);
    gcm.ct_len = (u64)ct_len * 8u;

    u8 keystream[16];
    u8* data = plaintext;
    rin_size_t len = ct_len;
    const u8* ct_ptr = ciphertext;
    while (len >= 16) {
        /* GHASH with ciphertext first */
        for (int i = 0; i < 16; i++) gcm.ghash[i] ^= ct_ptr[i];
        gcm_mult(gcm.ghash, gcm.h);

        aes_encrypt_block(&gcm.aes, gcm.counter, keystream);
        gcm_inc_counter(gcm.counter);
        for (int i = 0; i < 16; i++) data[i] ^= keystream[i];

        data += 16;
        ct_ptr += 16;
        len -= 16;
    }
    if (len > 0) {
        for (rin_size_t i = 0; i < len; i++) gcm.ghash[i] ^= ct_ptr[i];

        gcm_mult(gcm.ghash, gcm.h);

        aes_encrypt_block(&gcm.aes, gcm.counter, keystream);
        gcm_inc_counter(gcm.counter);
        for (rin_size_t i = 0; i < len; i++) data[i] ^= keystream[i];
    }

    *pt_len = ct_len;

    /* Compute expected tag */
    /* NOTE: No additional padding needed here - short blocks are already
     * processed with implicit zero padding in the loop above (gcm_mult
     * is called once per block, including partial blocks) */
    u8 len_block[16];
    rintls_write_be64(len_block, gcm.aad_len);
    rintls_write_be64(len_block + 8, gcm.ct_len);

    ghash_update(&gcm, len_block, 16);

    u8 s[16];
    aes_encrypt_block(&gcm.aes, gcm.j0, s);

    u8 computed_tag[16];
    for (int i = 0; i < 16; i++) computed_tag[i] = gcm.ghash[i] ^ s[i];

    int result = rintls_secure_compare(computed_tag, tag, 16);

    if (result != 0) {
        rintls_memzero(plaintext, ct_len);
        *pt_len = 0;
    }

    rintls_memzero(keystream, sizeof(keystream));
    rintls_memzero(len_block, sizeof(len_block));
    rintls_memzero(s, sizeof(s));
    rintls_memzero(computed_tag, sizeof(computed_tag));
    rintls_memzero(&gcm, sizeof(gcm));
    return result;
}
