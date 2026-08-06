/*
 * rinTLS - AES Block Cipher & GCM Mode Implementation
 * AES暗号化とGCMモード実装
 */

#include "aes.h"

/* AES S-box */
static const u8 sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/* Inverse S-box */
static const u8 rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

/* Round constants */
static const u8 rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* GF(2^8) multiplication for MixColumns */
static u8 xtime(u8 x) {
    return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
}

static u8 mul(u8 a, u8 b) {
    u8 result = 0;
    while (b) {
        if (b & 1) result ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return result;
}

/* Key expansion */
int aes_init(aes_ctx* ctx, const u8* key, int key_size) {
    int nk, i;
    u8 temp[4];

    if (key_size == 16) {
        ctx->nr = 10;
        nk = 4;
    } else if (key_size == 32) {
        ctx->nr = 14;
        nk = 8;
    } else {
        return -1;
    }

    /* Copy key to first nk words */
    for (i = 0; i < nk; i++) {
        ctx->rk[i] = rintls_read_be32(key + i * 4);
    }

    /* Expand key */
    for (i = nk; i < 4 * (ctx->nr + 1); i++) {
        u32 tmp = ctx->rk[i - 1];

        if (i % nk == 0) {
            /* RotWord + SubWord + Rcon */
            temp[0] = sbox[(tmp >> 16) & 0xFF] ^ rcon[i / nk];
            temp[1] = sbox[(tmp >> 8) & 0xFF];
            temp[2] = sbox[tmp & 0xFF];
            temp[3] = sbox[(tmp >> 24) & 0xFF];
            tmp = ((u32)temp[0] << 24) | ((u32)temp[1] << 16) | ((u32)temp[2] << 8) | temp[3];
        } else if (nk > 6 && i % nk == 4) {
            /* SubWord only for AES-256 */
            temp[0] = sbox[(tmp >> 24) & 0xFF];
            temp[1] = sbox[(tmp >> 16) & 0xFF];
            temp[2] = sbox[(tmp >> 8) & 0xFF];
            temp[3] = sbox[tmp & 0xFF];
            tmp = ((u32)temp[0] << 24) | ((u32)temp[1] << 16) | ((u32)temp[2] << 8) | temp[3];
        }

        ctx->rk[i] = ctx->rk[i - nk] ^ tmp;
    }

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
        tmp[0]  = sbox[state[0]];
        tmp[1]  = sbox[state[5]];
        tmp[2]  = sbox[state[10]];
        tmp[3]  = sbox[state[15]];
        tmp[4]  = sbox[state[4]];
        tmp[5]  = sbox[state[9]];
        tmp[6]  = sbox[state[14]];
        tmp[7]  = sbox[state[3]];
        tmp[8]  = sbox[state[8]];
        tmp[9]  = sbox[state[13]];
        tmp[10] = sbox[state[2]];
        tmp[11] = sbox[state[7]];
        tmp[12] = sbox[state[12]];
        tmp[13] = sbox[state[1]];
        tmp[14] = sbox[state[6]];
        tmp[15] = sbox[state[11]];

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
        tmp[0]  = sbox[state[0]];
        tmp[1]  = sbox[state[5]];
        tmp[2]  = sbox[state[10]];
        tmp[3]  = sbox[state[15]];
        tmp[4]  = sbox[state[4]];
        tmp[5]  = sbox[state[9]];
        tmp[6]  = sbox[state[14]];
        tmp[7]  = sbox[state[3]];
        tmp[8]  = sbox[state[8]];
        tmp[9]  = sbox[state[13]];
        tmp[10] = sbox[state[2]];
        tmp[11] = sbox[state[7]];
        tmp[12] = sbox[state[12]];
        tmp[13] = sbox[state[1]];
        tmp[14] = sbox[state[6]];
        tmp[15] = sbox[state[11]];

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
        tmp[0]  = rsbox[state[0]];
        tmp[1]  = rsbox[state[13]];
        tmp[2]  = rsbox[state[10]];
        tmp[3]  = rsbox[state[7]];
        tmp[4]  = rsbox[state[4]];
        tmp[5]  = rsbox[state[1]];
        tmp[6]  = rsbox[state[14]];
        tmp[7]  = rsbox[state[11]];
        tmp[8]  = rsbox[state[8]];
        tmp[9]  = rsbox[state[5]];
        tmp[10] = rsbox[state[2]];
        tmp[11] = rsbox[state[15]];
        tmp[12] = rsbox[state[12]];
        tmp[13] = rsbox[state[9]];
        tmp[14] = rsbox[state[6]];
        tmp[15] = rsbox[state[3]];

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
            state[i*4+0] = mul(a, 0x0e) ^ mul(b, 0x0b) ^ mul(c, 0x0d) ^ mul(d, 0x09);
            state[i*4+1] = mul(a, 0x09) ^ mul(b, 0x0e) ^ mul(c, 0x0b) ^ mul(d, 0x0d);
            state[i*4+2] = mul(a, 0x0d) ^ mul(b, 0x09) ^ mul(c, 0x0e) ^ mul(d, 0x0b);
            state[i*4+3] = mul(a, 0x0b) ^ mul(b, 0x0d) ^ mul(c, 0x09) ^ mul(d, 0x0e);
        }
    }

    /* Final round */
    {
        u8 tmp[16];
        tmp[0]  = rsbox[state[0]];
        tmp[1]  = rsbox[state[13]];
        tmp[2]  = rsbox[state[10]];
        tmp[3]  = rsbox[state[7]];
        tmp[4]  = rsbox[state[4]];
        tmp[5]  = rsbox[state[1]];
        tmp[6]  = rsbox[state[14]];
        tmp[7]  = rsbox[state[11]];
        tmp[8]  = rsbox[state[8]];
        tmp[9]  = rsbox[state[5]];
        tmp[10] = rsbox[state[2]];
        tmp[11] = rsbox[state[15]];
        tmp[12] = rsbox[state[12]];
        tmp[13] = rsbox[state[9]];
        tmp[14] = rsbox[state[6]];
        tmp[15] = rsbox[state[3]];

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
                v[k] = (v[k] >> 1) | ((v[k-1] & 1) << 7);
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

int aes_gcm_init(aes_gcm_ctx* ctx, const u8* key, int key_size) {
    rintls_memset(ctx, 0, sizeof(aes_gcm_ctx));

    if (aes_init(&ctx->aes, key, key_size) != 0) {
        return -1;
    }

    /* Compute hash subkey H = AES(K, 0^128) */
    u8 zero[16] = {0};
    aes_encrypt_block(&ctx->aes, zero, ctx->h);

    return 0;
}

void aes_gcm_set_iv(aes_gcm_ctx* ctx, const u8* iv, rin_size_t iv_len) {
    rintls_memset(ctx->ghash, 0, 16);
    ctx->aad_len = 0;
    ctx->ct_len = 0;

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

        /* Pad and add length */
        rin_size_t padlen = (16 - (iv_len % 16)) % 16;
        u8 pad[16] = {0};
        if (padlen) ghash_update(ctx, pad, padlen);

        rintls_write_be64(len_block + 8, (u64)iv_len * 8);
        ghash_update(ctx, len_block, 16);

        rintls_memcpy(ctx->j0, ctx->ghash, 16);
        rintls_memset(ctx->ghash, 0, 16);
    }

    rintls_memcpy(ctx->counter, ctx->j0, 16);
    gcm_inc_counter(ctx->counter);
}

void aes_gcm_aad(aes_gcm_ctx* ctx, const u8* aad, rin_size_t aad_len) {
    /* NOTE: ghash_update handles partial blocks with implicit zero padding.
     * Caller should pass all AAD in one call, or ensure 16-byte alignment
     * between calls. */
    ctx->aad_len += aad_len * 8;
    ghash_update(ctx, aad, aad_len);
}

void aes_gcm_encrypt_inplace(aes_gcm_ctx* ctx, u8* data, rin_size_t len) {
    u8 keystream[16];

    ctx->ct_len += len * 8;

    while (len >= 16) {
        aes_encrypt_block(&ctx->aes, ctx->counter, keystream);
        gcm_inc_counter(ctx->counter);

        for (int i = 0; i < 16; i++) {
            data[i] ^= keystream[i];
        }

        /* Update GHASH with ciphertext */
        for (int i = 0; i < 16; i++) {
            ctx->ghash[i] ^= data[i];
        }
        gcm_mult(ctx->ghash, ctx->h);

        data += 16;
        len -= 16;
    }

    if (len > 0) {
        aes_encrypt_block(&ctx->aes, ctx->counter, keystream);
        gcm_inc_counter(ctx->counter);

        for (rin_size_t i = 0; i < len; i++) {
            data[i] ^= keystream[i];
        }

        for (rin_size_t i = 0; i < len; i++) {
            ctx->ghash[i] ^= data[i];
        }
        gcm_mult(ctx->ghash, ctx->h);
    }
}

void aes_gcm_decrypt_inplace(aes_gcm_ctx* ctx, u8* data, rin_size_t len) {
    u8 keystream[16];

    ctx->ct_len += len * 8;

    while (len >= 16) {
        /* Update GHASH with ciphertext first */
        for (int i = 0; i < 16; i++) {
            ctx->ghash[i] ^= data[i];
        }
        gcm_mult(ctx->ghash, ctx->h);

        aes_encrypt_block(&ctx->aes, ctx->counter, keystream);
        gcm_inc_counter(ctx->counter);

        for (int i = 0; i < 16; i++) {
            data[i] ^= keystream[i];
        }

        data += 16;
        len -= 16;
    }

    if (len > 0) {
        for (rin_size_t i = 0; i < len; i++) {
            ctx->ghash[i] ^= data[i];
        }
        gcm_mult(ctx->ghash, ctx->h);

        aes_encrypt_block(&ctx->aes, ctx->counter, keystream);
        gcm_inc_counter(ctx->counter);

        for (rin_size_t i = 0; i < len; i++) {
            data[i] ^= keystream[i];
        }
    }
}

void aes_gcm_finish(aes_gcm_ctx* ctx, u8* tag) {
    u8 len_block[16];
    u8 s[16];

    /* NOTE: No additional padding needed - short blocks are processed with
     * implicit zero padding in encrypt/decrypt_inplace functions */

    /* Add lengths block */
    rintls_write_be64(len_block, ctx->aad_len);
    rintls_write_be64(len_block + 8, ctx->ct_len);
    ghash_update(ctx, len_block, 16);

    /* Encrypt J0 and XOR with GHASH */
    aes_encrypt_block(&ctx->aes, ctx->j0, s);
    for (int i = 0; i < 16; i++) {
        tag[i] = ctx->ghash[i] ^ s[i];
    }
}

int aes_gcm_verify(aes_gcm_ctx* ctx, const u8* tag) {
    u8 computed_tag[16];
    aes_gcm_finish(ctx, computed_tag);
    return rintls_secure_compare(computed_tag, tag, 16);
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

    if (aes_gcm_init(&ctx, key, key_size) != 0) return -1;

    aes_gcm_set_iv(&ctx, iv, iv_len);

    if (aad && aad_len > 0) {
        aes_gcm_aad(&ctx, aad, aad_len);
    }

    rintls_memcpy(ciphertext, plaintext, pt_len);
    aes_gcm_encrypt_inplace(&ctx, ciphertext, pt_len);

    aes_gcm_finish(&ctx, tag);

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

    if (aes_gcm_init(&ctx, key, key_size) != 0) return -1;

    aes_gcm_set_iv(&ctx, iv, iv_len);

    if (aad && aad_len > 0) {
        aes_gcm_aad(&ctx, aad, aad_len);
    }

    rintls_memcpy(plaintext, ciphertext, ct_len);
    aes_gcm_decrypt_inplace(&ctx, plaintext, ct_len);

    int result = aes_gcm_verify(&ctx, tag);

    if (result != 0) {
        /* Authentication failed - clear plaintext */
        rintls_memzero(plaintext, ct_len);
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
    (void)tag_len;  /* We always use 16-byte tags */

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
        rin_size_t padlen = (16 - (nonce_len % 16)) % 16;
        if (padlen) {
            u8 pad[16] = {0};
            ghash_update(&gcm, pad, padlen);
        }
        u8 len_block[16] = {0};
        rintls_write_be64(len_block + 8, (u64)nonce_len * 8);
        ghash_update(&gcm, len_block, 16);
        rintls_memcpy(gcm.j0, gcm.ghash, 16);
        rintls_memset(gcm.ghash, 0, 16);
    }

    rintls_memcpy(gcm.counter, gcm.j0, 16);
    gcm_inc_counter(gcm.counter);

    /* Process AAD */
    /* NOTE: ghash_update handles partial blocks with implicit zero padding */
    if (aad && aad_len > 0) {
        gcm.aad_len = aad_len * 8;
        ghash_update(&gcm, aad, aad_len);
    }

    /* Encrypt */
    rintls_memcpy(ciphertext, plaintext, pt_len);
    gcm.ct_len = pt_len * 8;

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
    (void)tag_len;

    rintls_memset(&gcm, 0, sizeof(gcm));
    rintls_memcpy(&gcm.aes, ctx, sizeof(aes_ctx));

    /* Compute hash subkey H */
    u8 zero[16] = {0};
    aes_encrypt_block(&gcm.aes, zero, gcm.h);

    rintls_debug("[GCM] H[0-3]: ");
    rintls_debug_hex(gcm.h[0]);
    rintls_debug(" ");
    rintls_debug_hex(gcm.h[1]);
    rintls_debug(" ");
    rintls_debug_hex(gcm.h[2]);
    rintls_debug(" ");
    rintls_debug_hex(gcm.h[3]);
    rintls_debug("\n");

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
        rin_size_t padlen = (16 - (nonce_len % 16)) % 16;
        if (padlen) {
            u8 pad[16] = {0};
            ghash_update(&gcm, pad, padlen);
        }
        u8 len_block[16] = {0};
        rintls_write_be64(len_block + 8, (u64)nonce_len * 8);
        ghash_update(&gcm, len_block, 16);
        rintls_memcpy(gcm.j0, gcm.ghash, 16);
        rintls_memset(gcm.ghash, 0, 16);
    }

    rintls_memcpy(gcm.counter, gcm.j0, 16);
    gcm_inc_counter(gcm.counter);

    /* Process AAD */
    /* NOTE: ghash_update handles partial blocks with implicit zero padding,
     * so no explicit padding is needed here */
    if (aad && aad_len > 0) {
        gcm.aad_len = aad_len * 8;
        ghash_update(&gcm, aad, aad_len);
    }

    rintls_debug("[GCM] after AAD ghash[0-3]: ");
    rintls_debug_hex(gcm.ghash[0]);
    rintls_debug(" ");
    rintls_debug_hex(gcm.ghash[1]);
    rintls_debug(" ");
    rintls_debug_hex(gcm.ghash[2]);
    rintls_debug(" ");
    rintls_debug_hex(gcm.ghash[3]);
    rintls_debug("\n");

    /* Decrypt and compute GHASH */
    rintls_memcpy(plaintext, ciphertext, ct_len);
    gcm.ct_len = ct_len * 8;

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

        /* Debug: dump full ghash BEFORE gcm_mult */
        rintls_debug("[GCM_DEBUG] before gcm_mult ghash: ");
        for (int dbg = 0; dbg < 16; dbg++) {
            rintls_debug_hex(gcm.ghash[dbg]);
            rintls_debug(" ");
        }
        rintls_debug("\n");
        rintls_debug("[GCM_DEBUG] H: ");
        for (int dbg = 0; dbg < 16; dbg++) {
            rintls_debug_hex(gcm.h[dbg]);
            rintls_debug(" ");
        }
        rintls_debug("\n");

        gcm_mult(gcm.ghash, gcm.h);

        /* Debug: dump full ghash AFTER gcm_mult */
        rintls_debug("[GCM_DEBUG] after gcm_mult ghash: ");
        for (int dbg = 0; dbg < 16; dbg++) {
            rintls_debug_hex(gcm.ghash[dbg]);
            rintls_debug(" ");
        }
        rintls_debug("\n");

        aes_encrypt_block(&gcm.aes, gcm.counter, keystream);
        gcm_inc_counter(gcm.counter);
        for (rin_size_t i = 0; i < len; i++) data[i] ^= keystream[i];
    }

    *pt_len = ct_len;

    rintls_debug("[GCM] after CT ghash[0-3]: ");
    rintls_debug_hex(gcm.ghash[0]);
    rintls_debug(" ");
    rintls_debug_hex(gcm.ghash[1]);
    rintls_debug(" ");
    rintls_debug_hex(gcm.ghash[2]);
    rintls_debug(" ");
    rintls_debug_hex(gcm.ghash[3]);
    rintls_debug("\n");

    /* Compute expected tag */
    /* NOTE: No additional padding needed here - short blocks are already
     * processed with implicit zero padding in the loop above (gcm_mult
     * is called once per block, including partial blocks) */
    u8 len_block[16];
    rintls_write_be64(len_block, gcm.aad_len);
    rintls_write_be64(len_block + 8, gcm.ct_len);

    rintls_debug("[GCM] len_block: aad_len=");
    rintls_debug_hex((u32)gcm.aad_len);
    rintls_debug(" ct_len=");
    rintls_debug_hex((u32)gcm.ct_len);
    rintls_debug("\n");

    ghash_update(&gcm, len_block, 16);

    rintls_debug("[GCM] after len ghash[0-3]: ");
    rintls_debug_hex(gcm.ghash[0]);
    rintls_debug(" ");
    rintls_debug_hex(gcm.ghash[1]);
    rintls_debug(" ");
    rintls_debug_hex(gcm.ghash[2]);
    rintls_debug(" ");
    rintls_debug_hex(gcm.ghash[3]);
    rintls_debug("\n");

    u8 s[16];
    aes_encrypt_block(&gcm.aes, gcm.j0, s);

    rintls_debug("[GCM] J0[0-3]: ");
    rintls_debug_hex(gcm.j0[0]);
    rintls_debug(" ");
    rintls_debug_hex(gcm.j0[1]);
    rintls_debug(" ");
    rintls_debug_hex(gcm.j0[2]);
    rintls_debug(" ");
    rintls_debug_hex(gcm.j0[3]);
    rintls_debug("\n");
    rintls_debug("[GCM] E(K,J0)[0-3]: ");
    rintls_debug_hex(s[0]);
    rintls_debug(" ");
    rintls_debug_hex(s[1]);
    rintls_debug(" ");
    rintls_debug_hex(s[2]);
    rintls_debug(" ");
    rintls_debug_hex(s[3]);
    rintls_debug("\n");

    u8 computed_tag[16];
    for (int i = 0; i < 16; i++) computed_tag[i] = gcm.ghash[i] ^ s[i];

    /* デバッグ: 計算タグ vs 受信タグ (完全な16バイト) */
    rintls_debug("[GCM] computed_tag: ");
    for (int i = 0; i < 16; i++) {
        rintls_debug_hex(computed_tag[i]);
        rintls_debug(" ");
    }
    rintls_debug("\n");
    rintls_debug("[GCM] received_tag: ");
    for (int i = 0; i < 16; i++) {
        rintls_debug_hex(tag[i]);
        rintls_debug(" ");
    }
    rintls_debug("\n");

    int result = rintls_secure_compare(computed_tag, tag, 16);

    if (result != 0) {
        rintls_debug("[GCM] !!! TAG MISMATCH !!! ct_len=");
        rintls_debug_hex((u32)ct_len);
        rintls_debug(" aad_len=");
        rintls_debug_hex((u32)gcm.aad_len);
        rintls_debug("\n");
        /* Compute ciphertext checksum for debugging */
        u32 ct_sum = 0;
        for (rin_size_t i = 0; i < ct_len; i++) ct_sum += ciphertext[i];
        (void)ct_sum;
        rintls_debug("[GCM] ct_checksum=");
        rintls_debug_hex(ct_sum);
        u32 tag_sum = 0;
        for (int i = 0; i < 16; i++) tag_sum += tag[i];
        (void)tag_sum;
        rintls_debug(" tag_checksum=");
        rintls_debug_hex(tag_sum);
        rintls_debug("\n");
        rintls_memzero(plaintext, ct_len);
    }

    rintls_memzero(&gcm, sizeof(gcm));
    return result;
}
