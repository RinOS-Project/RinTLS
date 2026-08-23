/*
 * rinTLS - ECDH (Elliptic Curve Diffie-Hellman)
 * X25519 および P-256 (secp256r1) 実装
 */

#include "ecdh.h"
#include "bignum.h"
#include "hmac.h"
#include "../platform/rin_platform.h"

/* ═══════════════════════════════════════
 * X25519 (Curve25519)
 * RFC 7748準拠
 * ═══════════════════════════════════════ */

/* X25519ベースポイント (u = 9) */
const u8 X25519_BASEPOINT[32] = {
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * フィールド要素 (mod p where p = 2^255 - 19)
 * 5個の51ビットリムで表現
 */
typedef struct {
    u64 v[5];
} fe25519;

/* p = 2^255 - 19 */
static const u64 P25519[5] __attribute__((unused)) = {
    0x7FFFFFFFFFFED,
    0x7FFFFFFFFFFFF,
    0x7FFFFFFFFFFFF,
    0x7FFFFFFFFFFFF,
    0x7FFFFFFFFFFFF
};

/* 128-bit accumulator for portable multiplication */
typedef struct {
    u64 lo;
    u64 hi;
} u128_t;

static inline void __attribute__((unused)) u128_zero(u128_t* r) {
    r->lo = 0;
    r->hi = 0;
}

static inline void u128_add64(u128_t* r, u64 a) {
    u64 old = r->lo;
    r->lo += a;
    if (r->lo < old) r->hi++;
}

/* a * b -> 128-bit result using 32x32->64 multiplications */
static inline void u128_mul64(u128_t* r, u64 a, u64 b) {
    u32 a0 = (u32)a;
    u32 a1 = (u32)(a >> 32);
    u32 b0 = (u32)b;
    u32 b1 = (u32)(b >> 32);

    u64 p00 = (u64)a0 * b0;
    u64 p01 = (u64)a0 * b1;
    u64 p10 = (u64)a1 * b0;
    u64 p11 = (u64)a1 * b1;

    u64 mid = p01 + p10;
    u64 carry = (mid < p01) ? ((u64)1 << 32) : 0;

    r->lo = p00 + (mid << 32);
    carry += (r->lo < p00) ? 1 : 0;
    r->hi = p11 + (mid >> 32) + carry;
}

/* r += a * b */
static inline void u128_addmul(u128_t* r, u64 a, u64 b) {
    u128_t t;
    u128_mul64(&t, a, b);
    u64 old = r->lo;
    r->lo += t.lo;
    r->hi += t.hi + ((r->lo < old) ? 1 : 0);
}

static inline u64 u128_rshift51(u128_t* r) {
    return (r->lo >> 51) | (r->hi << 13);
}

static inline u64 u128_lo_mask51(u128_t* r) {
    return r->lo & 0x7FFFFFFFFFFFF;
}

/* フィールド演算 */

static void fe_zero(fe25519* h)
{
    h->v[0] = 0;
    h->v[1] = 0;
    h->v[2] = 0;
    h->v[3] = 0;
    h->v[4] = 0;
}

static void fe_one(fe25519* h)
{
    h->v[0] = 1;
    h->v[1] = 0;
    h->v[2] = 0;
    h->v[3] = 0;
    h->v[4] = 0;
}

static void fe_copy(fe25519* h, const fe25519* f)
{
    h->v[0] = f->v[0];
    h->v[1] = f->v[1];
    h->v[2] = f->v[2];
    h->v[3] = f->v[3];
    h->v[4] = f->v[4];
}

/* リダクション */
static void fe_reduce(fe25519* h)
{
    u64 c;

    /* キャリー伝播 */
    c = h->v[0] >> 51; h->v[0] &= 0x7FFFFFFFFFFFF; h->v[1] += c;
    c = h->v[1] >> 51; h->v[1] &= 0x7FFFFFFFFFFFF; h->v[2] += c;
    c = h->v[2] >> 51; h->v[2] &= 0x7FFFFFFFFFFFF; h->v[3] += c;
    c = h->v[3] >> 51; h->v[3] &= 0x7FFFFFFFFFFFF; h->v[4] += c;
    c = h->v[4] >> 51; h->v[4] &= 0x7FFFFFFFFFFFF; h->v[0] += c * 19;

    /* もう一度 */
    c = h->v[0] >> 51; h->v[0] &= 0x7FFFFFFFFFFFF; h->v[1] += c;
}

/* 加算: h = f + g */
static void fe_add(fe25519* h, const fe25519* f, const fe25519* g)
{
    h->v[0] = f->v[0] + g->v[0];
    h->v[1] = f->v[1] + g->v[1];
    h->v[2] = f->v[2] + g->v[2];
    h->v[3] = f->v[3] + g->v[3];
    h->v[4] = f->v[4] + g->v[4];
}

/* 減算: h = f - g */
static void fe_sub(fe25519* h, const fe25519* f, const fe25519* g)
{
    /* 2p を加えてから減算（負にならないように） */
    h->v[0] = f->v[0] + 0xFFFFFFFFFFFDA - g->v[0];
    h->v[1] = f->v[1] + 0xFFFFFFFFFFFFE - g->v[1];
    h->v[2] = f->v[2] + 0xFFFFFFFFFFFFE - g->v[2];
    h->v[3] = f->v[3] + 0xFFFFFFFFFFFFE - g->v[3];
    h->v[4] = f->v[4] + 0xFFFFFFFFFFFFE - g->v[4];
    fe_reduce(h);
}

/* 乗算: h = f * g (portable, no __int128) */
static void fe_mul(fe25519* h, const fe25519* f, const fe25519* g)
{
    u128_t t[5];
    u64 f0 = f->v[0], f1 = f->v[1], f2 = f->v[2], f3 = f->v[3], f4 = f->v[4];
    u64 g0 = g->v[0], g1 = g->v[1], g2 = g->v[2], g3 = g->v[3], g4 = g->v[4];
    u64 g1_19 = g1 * 19, g2_19 = g2 * 19, g3_19 = g3 * 19, g4_19 = g4 * 19;

    /* t[0] = f0*g0 + f1*g4_19 + f2*g3_19 + f3*g2_19 + f4*g1_19 */
    u128_mul64(&t[0], f0, g0);
    u128_addmul(&t[0], f1, g4_19);
    u128_addmul(&t[0], f2, g3_19);
    u128_addmul(&t[0], f3, g2_19);
    u128_addmul(&t[0], f4, g1_19);

    /* t[1] = f0*g1 + f1*g0 + f2*g4_19 + f3*g3_19 + f4*g2_19 */
    u128_mul64(&t[1], f0, g1);
    u128_addmul(&t[1], f1, g0);
    u128_addmul(&t[1], f2, g4_19);
    u128_addmul(&t[1], f3, g3_19);
    u128_addmul(&t[1], f4, g2_19);

    /* t[2] = f0*g2 + f1*g1 + f2*g0 + f3*g4_19 + f4*g3_19 */
    u128_mul64(&t[2], f0, g2);
    u128_addmul(&t[2], f1, g1);
    u128_addmul(&t[2], f2, g0);
    u128_addmul(&t[2], f3, g4_19);
    u128_addmul(&t[2], f4, g3_19);

    /* t[3] = f0*g3 + f1*g2 + f2*g1 + f3*g0 + f4*g4_19 */
    u128_mul64(&t[3], f0, g3);
    u128_addmul(&t[3], f1, g2);
    u128_addmul(&t[3], f2, g1);
    u128_addmul(&t[3], f3, g0);
    u128_addmul(&t[3], f4, g4_19);

    /* t[4] = f0*g4 + f1*g3 + f2*g2 + f3*g1 + f4*g0 */
    u128_mul64(&t[4], f0, g4);
    u128_addmul(&t[4], f1, g3);
    u128_addmul(&t[4], f2, g2);
    u128_addmul(&t[4], f3, g1);
    u128_addmul(&t[4], f4, g0);

    /* キャリー伝播 */
    u64 c;
    c = u128_rshift51(&t[0]); h->v[0] = u128_lo_mask51(&t[0]); u128_add64(&t[1], c);
    c = u128_rshift51(&t[1]); h->v[1] = u128_lo_mask51(&t[1]); u128_add64(&t[2], c);
    c = u128_rshift51(&t[2]); h->v[2] = u128_lo_mask51(&t[2]); u128_add64(&t[3], c);
    c = u128_rshift51(&t[3]); h->v[3] = u128_lo_mask51(&t[3]); u128_add64(&t[4], c);
    c = u128_rshift51(&t[4]); h->v[4] = u128_lo_mask51(&t[4]); h->v[0] += c * 19;

    c = h->v[0] >> 51; h->v[0] &= 0x7FFFFFFFFFFFF; h->v[1] += c;
}

/* 二乗: h = f^2 */
static void fe_sq(fe25519* h, const fe25519* f)
{
    fe_mul(h, f, f);
}

/* 逆元: h = f^(-1) = f^(p-2) mod p */
static void fe_invert(fe25519* h, const fe25519* f)
{
    fe25519 t0, t1, t2, t3;
    int i;

    /* f^(2^1) */
    fe_sq(&t0, f);
    /* f^(2^2) */
    fe_sq(&t1, &t0);
    fe_sq(&t1, &t1);
    /* f^(2^2 + 2^0) = f^5 */
    fe_mul(&t1, f, &t1);
    /* f^(2^2 + 2^1 + 2^0) = f^7 */
    fe_mul(&t0, &t0, &t1);
    /* f^(2^3 + 2^2 + 2^1 + 2^0) */
    fe_sq(&t2, &t0);
    fe_mul(&t1, &t1, &t2);
    /* f^(2^10 - 1) */
    fe_sq(&t2, &t1);
    for (i = 0; i < 4; i++) fe_sq(&t2, &t2);
    fe_mul(&t1, &t2, &t1);
    /* f^(2^20 - 1) */
    fe_sq(&t2, &t1);
    for (i = 0; i < 9; i++) fe_sq(&t2, &t2);
    fe_mul(&t2, &t2, &t1);
    /* f^(2^40 - 1) */
    fe_sq(&t3, &t2);
    for (i = 0; i < 19; i++) fe_sq(&t3, &t3);
    fe_mul(&t2, &t3, &t2);
    /* f^(2^50 - 1) */
    for (i = 0; i < 10; i++) fe_sq(&t2, &t2);
    fe_mul(&t1, &t2, &t1);
    /* f^(2^100 - 1) */
    fe_sq(&t2, &t1);
    for (i = 0; i < 49; i++) fe_sq(&t2, &t2);
    fe_mul(&t2, &t2, &t1);
    /* f^(2^200 - 1) */
    fe_sq(&t3, &t2);
    for (i = 0; i < 99; i++) fe_sq(&t3, &t3);
    fe_mul(&t2, &t3, &t2);
    /* f^(2^250 - 1) */
    for (i = 0; i < 50; i++) fe_sq(&t2, &t2);
    fe_mul(&t1, &t2, &t1);
    /* f^(2^255 - 21) */
    for (i = 0; i < 5; i++) fe_sq(&t1, &t1);
    /* f^(p-2) = f^(2^255 - 19 - 2) */
    fe_mul(h, &t1, &t0);
}

/* バイト配列からフィールド要素へ変換 (リトルエンディアン) */
static void fe_frombytes(fe25519* h, const u8* s)
{
    u64 h0 = ((u64)s[0]) | ((u64)s[1] << 8) | ((u64)s[2] << 16) |
             ((u64)s[3] << 24) | ((u64)s[4] << 32) | ((u64)s[5] << 40) |
             ((u64)(s[6] & 0x07) << 48);

    u64 h1 = ((u64)(s[6] >> 3)) | ((u64)s[7] << 5) | ((u64)s[8] << 13) |
             ((u64)s[9] << 21) | ((u64)s[10] << 29) | ((u64)s[11] << 37) |
             ((u64)(s[12] & 0x3F) << 45);

    u64 h2 = ((u64)(s[12] >> 6)) | ((u64)s[13] << 2) | ((u64)s[14] << 10) |
             ((u64)s[15] << 18) | ((u64)s[16] << 26) | ((u64)s[17] << 34) |
             ((u64)s[18] << 42) | ((u64)(s[19] & 0x01) << 50);

    u64 h3 = ((u64)(s[19] >> 1)) | ((u64)s[20] << 7) | ((u64)s[21] << 15) |
             ((u64)s[22] << 23) | ((u64)s[23] << 31) | ((u64)s[24] << 39) |
             ((u64)(s[25] & 0x0F) << 47);

    u64 h4 = ((u64)(s[25] >> 4)) | ((u64)s[26] << 4) | ((u64)s[27] << 12) |
             ((u64)s[28] << 20) | ((u64)s[29] << 28) | ((u64)s[30] << 36) |
             ((u64)(s[31] & 0x7F) << 44);

    h->v[0] = h0;
    h->v[1] = h1;
    h->v[2] = h2;
    h->v[3] = h3;
    h->v[4] = h4;
}

/* フィールド要素をバイト配列へ変換 */
static void fe_tobytes(u8* s, const fe25519* h)
{
    fe25519 t;
    fe_copy(&t, h);
    fe_reduce(&t);

    /* 完全リダクション */
    u64 c = (t.v[0] + 19) >> 51;
    c = (t.v[1] + c) >> 51;
    c = (t.v[2] + c) >> 51;
    c = (t.v[3] + c) >> 51;
    c = (t.v[4] + c) >> 51;

    t.v[0] += 19 * c;
    c = t.v[0] >> 51; t.v[0] &= 0x7FFFFFFFFFFFF;
    t.v[1] += c; c = t.v[1] >> 51; t.v[1] &= 0x7FFFFFFFFFFFF;
    t.v[2] += c; c = t.v[2] >> 51; t.v[2] &= 0x7FFFFFFFFFFFF;
    t.v[3] += c; c = t.v[3] >> 51; t.v[3] &= 0x7FFFFFFFFFFFF;
    t.v[4] += c; t.v[4] &= 0x7FFFFFFFFFFFF;

    /* リトルエンディアンで出力 */
    u64 v0 = t.v[0], v1 = t.v[1], v2 = t.v[2], v3 = t.v[3], v4 = t.v[4];

    s[0] = (u8)v0;
    s[1] = (u8)(v0 >> 8);
    s[2] = (u8)(v0 >> 16);
    s[3] = (u8)(v0 >> 24);
    s[4] = (u8)(v0 >> 32);
    s[5] = (u8)(v0 >> 40);
    s[6] = (u8)((v0 >> 48) | (v1 << 3));
    s[7] = (u8)(v1 >> 5);
    s[8] = (u8)(v1 >> 13);
    s[9] = (u8)(v1 >> 21);
    s[10] = (u8)(v1 >> 29);
    s[11] = (u8)(v1 >> 37);
    s[12] = (u8)((v1 >> 45) | (v2 << 6));
    s[13] = (u8)(v2 >> 2);
    s[14] = (u8)(v2 >> 10);
    s[15] = (u8)(v2 >> 18);
    s[16] = (u8)(v2 >> 26);
    s[17] = (u8)(v2 >> 34);
    s[18] = (u8)(v2 >> 42);
    s[19] = (u8)((v2 >> 50) | (v3 << 1));
    s[20] = (u8)(v3 >> 7);
    s[21] = (u8)(v3 >> 15);
    s[22] = (u8)(v3 >> 23);
    s[23] = (u8)(v3 >> 31);
    s[24] = (u8)(v3 >> 39);
    s[25] = (u8)((v3 >> 47) | (v4 << 4));
    s[26] = (u8)(v4 >> 4);
    s[27] = (u8)(v4 >> 12);
    s[28] = (u8)(v4 >> 20);
    s[29] = (u8)(v4 >> 28);
    s[30] = (u8)(v4 >> 36);
    s[31] = (u8)(v4 >> 44);
}

/*
 * X25519スカラー乗算 (Montgomery ladder)
 * RFC 7748に従う
 */
int x25519_scalarmult(u8* out, const u8* scalar, const u8* point)
{
    u8 e[32];
    fe25519 x1, x2, z2, x3, z3, tmp0;
    int swap = 0;
    int b;

    /* スカラーをクランプ */
    rintls_memcpy(e, scalar, 32);
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;

    /* 初期化 */
    fe_frombytes(&x1, point);
    fe_one(&x2);
    fe_zero(&z2);
    fe_copy(&x3, &x1);
    fe_one(&z3);

    /* Montgomery ladder (RFC 7748) */
    for (int pos = 254; pos >= 0; pos--) {
        b = (e[pos >> 3] >> (pos & 7)) & 1;

        /* 条件付きスワップ */
        swap ^= b;
        if (swap) {
            fe25519 t;
            fe_copy(&t, &x2); fe_copy(&x2, &x3); fe_copy(&x3, &t);
            fe_copy(&t, &z2); fe_copy(&z2, &z3); fe_copy(&z3, &t);
        }
        swap = b;

        fe25519 A, B, C, D, AA, BB, E, DA, CB;

        /* A = x2 + z2 */
        fe_add(&A, &x2, &z2);
        /* B = x2 - z2 */
        fe_sub(&B, &x2, &z2);
        /* C = x3 + z3 */
        fe_add(&C, &x3, &z3);
        /* D = x3 - z3 */
        fe_sub(&D, &x3, &z3);
        /* DA = D * A */
        fe_mul(&DA, &D, &A);
        /* CB = C * B */
        fe_mul(&CB, &C, &B);
        /* AA = A^2 */
        fe_sq(&AA, &A);
        /* BB = B^2 */
        fe_sq(&BB, &B);
        /* E = AA - BB */
        fe_sub(&E, &AA, &BB);

        /* x3 = (DA + CB)^2 */
        fe_add(&tmp0, &DA, &CB);
        fe_sq(&x3, &tmp0);

        /* z3 = x1 * (DA - CB)^2 */
        fe_sub(&tmp0, &DA, &CB);
        fe_sq(&tmp0, &tmp0);
        fe_mul(&z3, &x1, &tmp0);

        /* x2 = AA * BB */
        fe_mul(&x2, &AA, &BB);

        /* z2 = E * (AA + a24 * E) where a24 = (486662-2)/4 = 121665 */
        fe25519 a24;
        fe_zero(&a24);
        a24.v[0] = 121665;
        fe_mul(&tmp0, &a24, &E);   /* a24 * E */
        fe_add(&tmp0, &AA, &tmp0); /* AA + a24 * E */
        fe_mul(&z2, &E, &tmp0);    /* E * (AA + a24 * E) */
    }

    /* 最終スワップ */
    if (swap) {
        fe25519 t;
        fe_copy(&t, &x2); fe_copy(&x2, &x3); fe_copy(&x3, &t);
        fe_copy(&t, &z2); fe_copy(&z2, &z3); fe_copy(&z3, &t);
    }

    /* x2 / z2 */
    fe_invert(&z2, &z2);
    fe_mul(&x2, &x2, &z2);
    fe_tobytes(out, &x2);

    return ECDH_OK;
}

int x25519_compute_public(u8* public_key, const u8* private_key)
{
    return x25519_scalarmult(public_key, private_key, X25519_BASEPOINT);
}

int x25519_keygen(x25519_keypair_t* keypair)
{
    u8 nonzero = 0;

    if (!keypair) return ECDH_ERR_INVALID;

    /* ランダムな秘密鍵を生成 */
    if (rintls_random_bytes(keypair->private_key, 32) != 0) {
        rintls_secure_zero(keypair, sizeof(*keypair));
        return ECDH_ERR_KEY;
    }
    for (rin_size_t i = 0; i < 32; ++i) nonzero |= keypair->private_key[i];
    if (nonzero == 0) {
        rintls_secure_zero(keypair, sizeof(*keypair));
        return ECDH_ERR_KEY;
    }

    /* RFC 7748: クランプは scalarmult 内で行う */

    /* 公開鍵を計算 */
    int result = x25519_compute_public(keypair->public_key, keypair->private_key);
    if (result != ECDH_OK) {
        rintls_secure_zero(keypair, sizeof(*keypair));
    }
    return result;
}

int x25519_ecdh(u8* shared_secret,
                const u8* private_key,
                const u8* peer_public)
{
    u8 zero[32] = {0};
    int ret;

    /* The caller may reuse this buffer after an error, so never leave a
     * previous shared secret in it. */
    if (!shared_secret) return ECDH_ERR_INVALID;
    rintls_secure_zero(shared_secret, X25519_KEY_SIZE);

    if (!private_key || !peer_public) return ECDH_ERR_INVALID;

    ret = x25519_scalarmult(shared_secret, private_key, peer_public);
    if (ret != ECDH_OK) {
        rintls_secure_zero(shared_secret, X25519_KEY_SIZE);
        return ret;
    }

    /* 全ゼロチェック (low-order point対策) */
    if (rintls_secure_cmp(shared_secret, zero, X25519_KEY_SIZE)) {
        rintls_secure_zero(shared_secret, X25519_KEY_SIZE);
        return ECDH_ERR_POINT;
    }

    return ECDH_OK;
}

/* ═══════════════════════════════════════
 * X25519 自己テスト (RFC 7748)
 * ═══════════════════════════════════════ */

int x25519_selftest(void)
{
    /* RFC 7748 テストベクター */
    /* Alice's private key (already clamped in test vector) */
    static const u8 alice_priv[32] = {
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
    };
    /* Alice's expected public key */
    static const u8 alice_pub_expected[32] = {
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
        0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
        0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
        0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a
    };

    u8 alice_pub[32];

    rintls_debug("[X25519_TEST] Testing with RFC 7748 vectors...\n");

    /* Compute Alice's public key */
    x25519_scalarmult(alice_pub, alice_priv, X25519_BASEPOINT);

    rintls_debug("[X25519_TEST] alice_pub computed: ");
    for (int i = 0; i < 32; i++) {
        rintls_debug_hex(alice_pub[i]);
        rintls_debug(" ");
    }
    rintls_debug("\n");

    rintls_debug("[X25519_TEST] alice_pub expected: ");
    for (int i = 0; i < 32; i++) {
        rintls_debug_hex(alice_pub_expected[i]);
        rintls_debug(" ");
    }
    rintls_debug("\n");

    /* Compare */
    int match = 1;
    for (int i = 0; i < 32; i++) {
        if (alice_pub[i] != alice_pub_expected[i]) {
            match = 0;
            rintls_debug("[X25519_TEST] MISMATCH at byte ");
            rintls_debug_hex(i);
            rintls_debug(": got ");
            rintls_debug_hex(alice_pub[i]);
            rintls_debug(" expected ");
            rintls_debug_hex(alice_pub_expected[i]);
            rintls_debug("\n");
        }
    }

    if (match) {
        rintls_debug("[X25519_TEST] PASS!\n");
        return 0;
    } else {
        rintls_debug("[X25519_TEST] FAIL!\n");
        return -1;
    }
}

/* ═══════════════════════════════════════
 * P-256 (secp256r1)
 * 簡易実装 - bignum使用
 * ═══════════════════════════════════════ */

/* P-256曲線パラメータ (16進数) */
static const u8 P256_P[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static const u8 P256_N[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
};

static const u8 P256_GX[] = {
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
    0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
    0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96
};

static const u8 P256_GY[] = {
    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
    0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
    0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
    0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
};

/* P-256点 (アフィン座標) */
typedef struct {
    bignum_t x;
    bignum_t y;
    int infinity;
} p256_point_t;

/* モジュラスを取得 */
static void p256_get_p(bignum_t* p)
{
    bn_from_bytes(p, P256_P, 32);
}

static void p256_get_n(bignum_t* n)
{
    bn_from_bytes(n, P256_N, 32);
}

int p256_validate_private(const u8* private_key, rin_size_t len)
{
    bignum_t private_value;
    bignum_t order;
    int valid;
    if (!private_key || len != P256_KEY_SIZE) return ECDH_ERR_INVALID;
    bn_from_bytes(&private_value, private_key, P256_KEY_SIZE);
    p256_get_n(&order);
    valid = !bn_is_zero(&private_value) &&
            bn_cmp(&private_value, &order) < 0;
    bn_clear(&private_value);
    bn_clear(&order);
    return valid ? ECDH_OK : ECDH_ERR_KEY;
}

/* 点のダブリング: R = 2P */
static void p256_double(p256_point_t* r, const p256_point_t* p, const bignum_t* prime)
{
    if (p->infinity || bn_is_zero(&p->y)) {
        r->infinity = 1;
        return;
    }

    bignum_t s, t, x3, y3, three, two;

    bn_set_u32(&three, 3);
    bn_set_u32(&two, 2);

    /* s = (3*x^2 + a) / (2*y), where a = -3 for P-256 */
    /* s = (3*x^2 - 3) / (2*y) = 3*(x^2 - 1) / (2*y) */
    bignum_t x2, num, denom;
    bn_mod_mul(&x2, &p->x, &p->x, prime);        /* x^2 */
    bn_mod_mul(&num, &three, &x2, prime);         /* 3*x^2 */
    bn_mod_sub(&num, &num, &three, prime);        /* 3*x^2 - 3 */
    bn_mod_mul(&denom, &two, &p->y, prime);       /* 2*y */
    bn_mod_inv(&t, &denom, prime);
    bn_mod_mul(&s, &num, &t, prime);

    /* x3 = s^2 - 2*x */
    bn_mod_mul(&t, &s, &s, prime);
    bn_mod_mul(&x3, &two, &p->x, prime);
    bn_mod_sub(&x3, &t, &x3, prime);

    /* y3 = s*(x - x3) - y */
    bn_mod_sub(&t, &p->x, &x3, prime);
    bn_mod_mul(&y3, &s, &t, prime);
    bn_mod_sub(&y3, &y3, &p->y, prime);

    bn_copy(&r->x, &x3);
    bn_copy(&r->y, &y3);
    r->infinity = 0;
}

/* 点の加算: R = P + Q */
static void p256_add(p256_point_t* r, const p256_point_t* p, const p256_point_t* q, const bignum_t* prime)
{
    if (p->infinity) {
        bn_copy(&r->x, &q->x);
        bn_copy(&r->y, &q->y);
        r->infinity = q->infinity;
        return;
    }
    if (q->infinity) {
        bn_copy(&r->x, &p->x);
        bn_copy(&r->y, &p->y);
        r->infinity = p->infinity;
        return;
    }

    /* P == Q の場合はダブリング */
    if (bn_cmp(&p->x, &q->x) == 0) {
        if (bn_cmp(&p->y, &q->y) == 0) {
            p256_double(r, p, prime);
            return;
        } else {
            /* P == -Q */
            r->infinity = 1;
            return;
        }
    }

    bignum_t s, t, x3, y3;

    /* s = (y2 - y1) / (x2 - x1) */
    bn_mod_sub(&t, &q->y, &p->y, prime);
    bignum_t dx;
    bn_mod_sub(&dx, &q->x, &p->x, prime);
    bn_mod_inv(&s, &dx, prime);
    bn_mod_mul(&s, &t, &s, prime);

    /* x3 = s^2 - x1 - x2 */
    bn_mod_mul(&x3, &s, &s, prime);
    bn_mod_sub(&x3, &x3, &p->x, prime);
    bn_mod_sub(&x3, &x3, &q->x, prime);

    /* y3 = s*(x1 - x3) - y1 */
    bn_mod_sub(&t, &p->x, &x3, prime);
    bn_mod_mul(&y3, &s, &t, prime);
    bn_mod_sub(&y3, &y3, &p->y, prime);

    bn_copy(&r->x, &x3);
    bn_copy(&r->y, &y3);
    r->infinity = 0;
}

/* スカラー乗算: R = k * P */
static void p256_scalar_mult(p256_point_t* r, const bignum_t* k, const p256_point_t* p, const bignum_t* prime)
{
    p256_point_t result, temp;
    result.infinity = 1;
    bn_copy(&temp.x, &p->x);
    bn_copy(&temp.y, &p->y);
    temp.infinity = p->infinity;

    rin_size_t bits = bn_bitlen(k);

    for (rin_size_t i = 0; i < bits; i++) {
        if (bn_get_bit(k, i)) {
            p256_add(&result, &result, &temp, prime);
        }
        p256_double(&temp, &temp, prime);
    }

    bn_copy(&r->x, &result.x);
    bn_copy(&r->y, &result.y);
    r->infinity = result.infinity;
}

int p256_keygen(p256_keypair_t* keypair)
{
    bignum_t k, n, prime;
    p256_point_t G, Q;
    u32 attempts = 0;

    if (!keypair) return ECDH_ERR_INVALID;

    p256_get_p(&prime);
    p256_get_n(&n);

    /* ベースポイントG */
    bn_from_bytes(&G.x, P256_GX, 32);
    bn_from_bytes(&G.y, P256_GY, 32);
    G.infinity = 0;

    /* ランダムな秘密鍵 k (1 <= k < n) */
    do {
        if (attempts++ >= 128 ||
            rintls_random_bytes(keypair->private_key, 32) != 0) {
            bn_clear(&k);
            rintls_secure_zero(keypair, sizeof(*keypair));
            return ECDH_ERR_KEY;
        }
        bn_from_bytes(&k, keypair->private_key, 32);
    } while (bn_is_zero(&k) || bn_cmp(&k, &n) >= 0);

    /* Q = k * G */
    p256_scalar_mult(&Q, &k, &G, &prime);

    /* 公開鍵をエンコード (非圧縮形式) */
    keypair->public_key[0] = 0x04;
    bn_to_bytes(&Q.x, keypair->public_key + 1, 32);
    bn_to_bytes(&Q.y, keypair->public_key + 33, 32);

    bn_clear(&k);
    return ECDH_OK;
}

int p256_compute_public(u8* public_key, const u8* private_key)
{
    bignum_t k, prime;
    p256_point_t G, Q;

    if (!public_key ||
        p256_validate_private(private_key, P256_KEY_SIZE) != ECDH_OK)
        return ECDH_ERR_KEY;

    p256_get_p(&prime);

    bn_from_bytes(&G.x, P256_GX, 32);
    bn_from_bytes(&G.y, P256_GY, 32);
    G.infinity = 0;

    bn_from_bytes(&k, private_key, 32);

    p256_scalar_mult(&Q, &k, &G, &prime);

    public_key[0] = 0x04;
    bn_to_bytes(&Q.x, public_key + 1, 32);
    bn_to_bytes(&Q.y, public_key + 33, 32);

    bn_clear(&k);
    return ECDH_OK;
}

int p256_validate_public(const u8* public_key, rin_size_t len)
{
    if (len == 65 && public_key[0] == 0x04) {
        /* 非圧縮形式 - 点が曲線上にあるか検証 */
        bignum_t x, y, prime, lhs, rhs, t;

        p256_get_p(&prime);
        bn_from_bytes(&x, public_key + 1, 32);
        bn_from_bytes(&y, public_key + 33, 32);

        /* y^2 = x^3 - 3x + b (mod p) */
        bn_mod_mul(&lhs, &y, &y, &prime);  /* y^2 */

        bn_mod_mul(&t, &x, &x, &prime);    /* x^2 */
        bn_mod_mul(&rhs, &t, &x, &prime);  /* x^3 */

        bignum_t three;
        bn_set_u32(&three, 3);
        bn_mod_mul(&t, &three, &x, &prime);  /* 3x */
        bn_mod_sub(&rhs, &rhs, &t, &prime);  /* x^3 - 3x */

        /* b for P-256 */
        static const u8 P256_B[] = {
            0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7,
            0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
            0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
            0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B
        };
        bignum_t b;
        bn_from_bytes(&b, P256_B, 32);
        bn_mod_add(&rhs, &rhs, &b, &prime);  /* x^3 - 3x + b */

        if (bn_cmp(&lhs, &rhs) == 0) {
            return ECDH_OK;
        }
    } else if (len == 33 && (public_key[0] == 0x02 || public_key[0] == 0x03)) {
        /* 圧縮形式 - 基本検証のみ */
        return ECDH_OK;
    }

    return ECDH_ERR_POINT;
}

int p256_ecdh(u8* shared_secret,
              const u8* private_key,
              const u8* peer_public, rin_size_t peer_public_len)
{
    if (p256_validate_public(peer_public, peer_public_len) != ECDH_OK) {
        return ECDH_ERR_POINT;
    }

    bignum_t k, prime;
    p256_point_t Q, R;

    p256_get_p(&prime);
    bn_from_bytes(&k, private_key, 32);

    /* 相手の公開鍵をパース */
    if (peer_public[0] == 0x04 && peer_public_len == 65) {
        bn_from_bytes(&Q.x, peer_public + 1, 32);
        bn_from_bytes(&Q.y, peer_public + 33, 32);
        Q.infinity = 0;
    } else {
        return ECDH_ERR_POINT;  /* 圧縮形式は未サポート */
    }

    /* R = k * Q */
    p256_scalar_mult(&R, &k, &Q, &prime);

    if (R.infinity) {
        return ECDH_ERR_POINT;
    }

    /* 共有秘密はx座標 */
    bn_to_bytes(&R.x, shared_secret, 32);

    bn_clear(&k);
    return ECDH_OK;
}

/* ═══════════════════════════════════════
 * ECDSA P-256 署名検証
 * ═══════════════════════════════════════ */

static void p256_rfc6979_hmac(u8 output[32], const u8 key[32],
                              const u8* first, rin_size_t first_size,
                              const u8* second, rin_size_t second_size,
                              const u8* third, rin_size_t third_size,
                              const u8* fourth, rin_size_t fourth_size)
{
    hmac_sha256_ctx hmac;
    hmac_sha256_init(&hmac, key, 32u);
    if (first_size != 0u) hmac_sha256_update(&hmac, first, first_size);
    if (second_size != 0u) hmac_sha256_update(&hmac, second, second_size);
    if (third_size != 0u) hmac_sha256_update(&hmac, third, third_size);
    if (fourth_size != 0u) hmac_sha256_update(&hmac, fourth, fourth_size);
    hmac_sha256_final(&hmac, output);
    rintls_secure_zero(&hmac, sizeof(hmac));
}

static void p256_rfc6979_reject(u8 key[32], u8 value[32])
{
    static const u8 zero = 0u;
    u8 next_key[32];
    u8 next_value[32];
    p256_rfc6979_hmac(next_key, key, value, 32u, &zero, 1u,
                      NULL, 0u, NULL, 0u);
    p256_rfc6979_hmac(next_value, next_key, value, 32u, NULL, 0u,
                      NULL, 0u, NULL, 0u);
    rintls_memcpy(key, next_key, sizeof(next_key));
    rintls_memcpy(value, next_value, sizeof(next_value));
    rintls_secure_zero(next_key, sizeof(next_key));
    rintls_secure_zero(next_value, sizeof(next_value));
}

static int p256_rfc6979_init(u8 key[32], u8 value[32],
                             const u8 private_key[32],
                             const u8 hash[32])
{
    static const u8 zero = 0u;
    static const u8 one = 1u;
    bignum_t hash_value;
    bignum_t order;
    bignum_t reduced_hash;
    u8 hash_octets[32];
    u8 next_key[32];
    u8 next_value[32];
    int result = ECDH_ERR_INVALID;
    rintls_memset(hash_octets, 0, sizeof(hash_octets));
    rintls_memset(next_key, 0, sizeof(next_key));
    rintls_memset(next_value, 0, sizeof(next_value));
    bn_from_bytes(&hash_value, hash, 32u);
    p256_get_n(&order);
    if (bn_mod(&reduced_hash, &hash_value, &order) != BIGNUM_OK ||
        bn_to_bytes(&reduced_hash, hash_octets, sizeof(hash_octets)) !=
            BIGNUM_OK)
        goto done;

    rintls_memset(key, 0, 32u);
    rintls_memset(value, 1, 32u);
    p256_rfc6979_hmac(next_key, key, value, 32u, &zero, 1u,
                      private_key, 32u, hash_octets, 32u);
    rintls_memcpy(key, next_key, 32u);
    p256_rfc6979_hmac(next_value, key, value, 32u, NULL, 0u,
                      NULL, 0u, NULL, 0u);
    rintls_memcpy(value, next_value, 32u);
    p256_rfc6979_hmac(next_key, key, value, 32u, &one, 1u,
                      private_key, 32u, hash_octets, 32u);
    rintls_memcpy(key, next_key, 32u);
    p256_rfc6979_hmac(next_value, key, value, 32u, NULL, 0u,
                      NULL, 0u, NULL, 0u);
    rintls_memcpy(value, next_value, 32u);
    result = ECDH_OK;
done:
    bn_clear(&hash_value);
    bn_clear(&order);
    bn_clear(&reduced_hash);
    rintls_secure_zero(hash_octets, sizeof(hash_octets));
    rintls_secure_zero(next_key, sizeof(next_key));
    rintls_secure_zero(next_value, sizeof(next_value));
    return result;
}

int ecdsa_p256_sign(u8 signature[64], const u8 hash[32],
                    const u8 private_key[32])
{
    bignum_t private_value;
    bignum_t hash_value;
    bignum_t order;
    bignum_t prime;
    bignum_t nonce;
    bignum_t nonce_inverse;
    bignum_t r;
    bignum_t s;
    bignum_t product;
    bignum_t sum;
    p256_point_t generator;
    p256_point_t nonce_point;
    u8 key[32];
    u8 value[32];
    u32 attempts = 0u;
    int result = ECDH_ERR_KEY;
    if (signature) rintls_secure_zero(signature, 64u);
    rintls_memset(key, 0, sizeof(key));
    rintls_memset(value, 0, sizeof(value));
    if (!signature || !hash ||
        p256_validate_private(private_key, P256_KEY_SIZE) != ECDH_OK)
        goto done;
    if (p256_rfc6979_init(key, value, private_key, hash) != ECDH_OK)
        goto done;

    bn_from_bytes(&private_value, private_key, 32u);
    bn_from_bytes(&hash_value, hash, 32u);
    p256_get_n(&order);
    p256_get_p(&prime);
    bn_from_bytes(&generator.x, P256_GX, 32u);
    bn_from_bytes(&generator.y, P256_GY, 32u);
    generator.infinity = 0;
    while (attempts++ < 128u) {
        p256_rfc6979_hmac(value, key, value, 32u, NULL, 0u,
                          NULL, 0u, NULL, 0u);
        bn_from_bytes(&nonce, value, 32u);
        if (bn_is_zero(&nonce) || bn_cmp(&nonce, &order) >= 0) {
            p256_rfc6979_reject(key, value);
            continue;
        }
        p256_scalar_mult(&nonce_point, &nonce, &generator, &prime);
        if (nonce_point.infinity ||
            bn_mod(&r, &nonce_point.x, &order) != BIGNUM_OK ||
            bn_is_zero(&r) ||
            bn_mod_inv(&nonce_inverse, &nonce, &order) != BIGNUM_OK ||
            bn_mod_mul(&product, &r, &private_value, &order) !=
                BIGNUM_OK ||
            bn_mod_add(&sum, &hash_value, &product, &order) !=
                BIGNUM_OK ||
            bn_mod_mul(&s, &nonce_inverse, &sum, &order) !=
                BIGNUM_OK ||
            bn_is_zero(&s)) {
            p256_rfc6979_reject(key, value);
            continue;
        }
        if (bn_to_bytes(&r, signature, 32u) != BIGNUM_OK ||
            bn_to_bytes(&s, signature + 32u, 32u) != BIGNUM_OK) {
            rintls_secure_zero(signature, 64u);
            result = ECDH_ERR_INVALID;
            goto done;
        }
        result = ECDH_OK;
        goto done;
    }
done:
    bn_clear(&private_value);
    bn_clear(&hash_value);
    bn_clear(&order);
    bn_clear(&prime);
    bn_clear(&nonce);
    bn_clear(&nonce_inverse);
    bn_clear(&r);
    bn_clear(&s);
    bn_clear(&product);
    bn_clear(&sum);
    bn_clear(&generator.x);
    bn_clear(&generator.y);
    bn_clear(&nonce_point.x);
    bn_clear(&nonce_point.y);
    rintls_secure_zero(key, sizeof(key));
    rintls_secure_zero(value, sizeof(value));
    if (result != ECDH_OK && signature)
        rintls_secure_zero(signature, 64u);
    return result;
}

int ecdsa_sig_from_der(u8* r, u8* s, const u8* der, rin_size_t der_len)
{
    const u8* p = der;
    const u8* end = der + der_len;

    /* SEQUENCE */
    if (p >= end || *p++ != 0x30) return ECDH_ERR_INVALID;

    /* 長さ */
    if (p >= end) return ECDH_ERR_INVALID;
    rin_size_t seq_len = *p++;
    if (seq_len > 0x80) {
        int len_bytes = seq_len & 0x7F;
        seq_len = 0;
        for (int i = 0; i < len_bytes && p < end; i++) {
            seq_len = (seq_len << 8) | *p++;
        }
    }

    /* r INTEGER */
    if (p >= end || *p++ != 0x02) return ECDH_ERR_INVALID;
    if (p >= end) return ECDH_ERR_INVALID;
    rin_size_t r_len = *p++;

    /* 先頭の0を除去して32バイトにパディング */
    rintls_memset(r, 0, 32);
    const u8* r_data = p;
    if (r_len > 0 && *r_data == 0x00) {
        r_data++;
        r_len--;
    }
    if (r_len > 32) return ECDH_ERR_INVALID;
    rintls_memcpy(r + (32 - r_len), r_data, r_len);
    p += (r_data - p) + r_len;

    /* s INTEGER */
    if (p >= end || *p++ != 0x02) return ECDH_ERR_INVALID;
    if (p >= end) return ECDH_ERR_INVALID;
    rin_size_t s_len = *p++;

    rintls_memset(s, 0, 32);
    const u8* s_data = p;
    if (s_len > 0 && *s_data == 0x00) {
        s_data++;
        s_len--;
    }
    if (s_len > 32) return ECDH_ERR_INVALID;
    rintls_memcpy(s + (32 - s_len), s_data, s_len);

    return ECDH_OK;
}

int ecdsa_p256_verify(const u8* signature, rin_size_t sig_len,
                      const u8* hash, rin_size_t hash_len,
                      const u8* public_key, rin_size_t pubkey_len)
{
    bignum_t r, s, z, n, prime;
    bignum_t w, u1, u2;
    p256_point_t G, Q, R1, R2, R;

    /* 署名をパース */
    u8 r_bytes[32], s_bytes[32];
    if (sig_len == 64) {
        /* r || s 形式 */
        rintls_memcpy(r_bytes, signature, 32);
        rintls_memcpy(s_bytes, signature + 32, 32);
    } else {
        /* DER形式 */
        if (ecdsa_sig_from_der(r_bytes, s_bytes, signature, sig_len) != ECDH_OK) {
            return ECDH_ERR_INVALID;
        }
    }

    bn_from_bytes(&r, r_bytes, 32);
    bn_from_bytes(&s, s_bytes, 32);

    /* 曲線パラメータ */
    p256_get_p(&prime);
    p256_get_n(&n);

    /* 1 <= r, s < n をチェック */
    if (bn_is_zero(&r) || bn_cmp(&r, &n) >= 0) return ECDH_ERR_INVALID;
    if (bn_is_zero(&s) || bn_cmp(&s, &n) >= 0) return ECDH_ERR_INVALID;

    /* ハッシュを数値に変換 */
    if (hash_len > 32) hash_len = 32;
    bn_from_bytes(&z, hash, hash_len);

    /* w = s^(-1) mod n */
    if (bn_mod_inv(&w, &s, &n) != BIGNUM_OK) return ECDH_ERR_INVALID;

    /* u1 = z * w mod n */
    bn_mod_mul(&u1, &z, &w, &n);

    /* u2 = r * w mod n */
    bn_mod_mul(&u2, &r, &w, &n);

    /* G (ベースポイント) */
    bn_from_bytes(&G.x, P256_GX, 32);
    bn_from_bytes(&G.y, P256_GY, 32);
    G.infinity = 0;

    /* Q (公開鍵) */
    if (pubkey_len != 65 || public_key[0] != 0x04) {
        return ECDH_ERR_KEY;
    }
    bn_from_bytes(&Q.x, public_key + 1, 32);
    bn_from_bytes(&Q.y, public_key + 33, 32);
    Q.infinity = 0;

    /* R = u1*G + u2*Q */
    p256_scalar_mult(&R1, &u1, &G, &prime);
    p256_scalar_mult(&R2, &u2, &Q, &prime);
    p256_add(&R, &R1, &R2, &prime);

    if (R.infinity) {
        return ECDH_ERR_VERIFY;
    }

    /* v = R.x mod n */
    bignum_t v;
    bn_mod(&v, &R.x, &n);

    /* v == r をチェック */
    if (bn_cmp(&v, &r) != 0) {
        return ECDH_ERR_VERIFY;
    }

    return ECDH_OK;
}

/* P-384 and P-521 reuse the affine NIST-curve arithmetic above. All three
 * supported curves use a = -3; only the field/order/base point differ. */
static const u8 P384_P[] = {
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,0xff,0xff,0xff,0xff,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff
};
static const u8 P384_N[] = {
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xc7,0x63,0x4d,0x81,0xf4,0x37,0x2d,0xdf,0x58,0x1a,0x0d,0xb2,
    0x48,0xb0,0xa7,0x7a,0xec,0xec,0x19,0x6a,0xcc,0xc5,0x29,0x73
};
static const u8 P384_B[] = {
    0xb3,0x31,0x2f,0xa7,0xe2,0x3e,0xe7,0xe4,0x98,0x8e,0x05,0x6b,
    0xe3,0xf8,0x2d,0x19,0x18,0x1d,0x9c,0x6e,0xfe,0x81,0x41,0x12,
    0x03,0x14,0x08,0x8f,0x50,0x13,0x87,0x5a,0xc6,0x56,0x39,0x8d,
    0x8a,0x2e,0xd1,0x9d,0x2a,0x85,0xc8,0xed,0xd3,0xec,0x2a,0xef
};
static const u8 P384_GX[] = {
    0xaa,0x87,0xca,0x22,0xbe,0x8b,0x05,0x37,0x8e,0xb1,0xc7,0x1e,
    0xf3,0x20,0xad,0x74,0x6e,0x1d,0x3b,0x62,0x8b,0xa7,0x9b,0x98,
    0x59,0xf7,0x41,0xe0,0x82,0x54,0x2a,0x38,0x55,0x02,0xf2,0x5d,
    0xbf,0x55,0x29,0x6c,0x3a,0x54,0x5e,0x38,0x72,0x76,0x0a,0xb7
};
static const u8 P384_GY[] = {
    0x36,0x17,0xde,0x4a,0x96,0x26,0x2c,0x6f,0x5d,0x9e,0x98,0xbf,
    0x92,0x92,0xdc,0x29,0xf8,0xf4,0x1d,0xbd,0x28,0x9a,0x14,0x7c,
    0xe9,0xda,0x31,0x13,0xb5,0xf0,0xb8,0xc0,0x0a,0x60,0xb1,0xce,
    0x1d,0x7e,0x81,0x9d,0x7a,0x43,0x1d,0x7c,0x90,0xea,0x0e,0x5f
};

static const u8 P521_P[] = {
    0x01,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
};
static const u8 P521_N[] = {
    0x01,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xfa,0x51,0x86,0x87,0x83,0xbf,0x2f,0x96,0x6b,0x7f,0xcc,
    0x01,0x48,0xf7,0x09,0xa5,0xd0,0x3b,0xb5,0xc9,0xb8,0x89,
    0x9c,0x47,0xae,0xbb,0x6f,0xb7,0x1e,0x91,0x38,0x64,0x09
};
static const u8 P521_B[] = {
    0x51,0x95,0x3e,0xb9,0x61,0x8e,0x1c,0x9a,0x1f,0x92,0x9a,
    0x21,0xa0,0xb6,0x85,0x40,0xee,0xa2,0xda,0x72,0x5b,0x99,
    0xb3,0x15,0xf3,0xb8,0xb4,0x89,0x91,0x8e,0xf1,0x09,0xe1,
    0x56,0x19,0x39,0x51,0xec,0x7e,0x93,0x7b,0x16,0x52,0xc0,
    0xbd,0x3b,0xb1,0xbf,0x07,0x35,0x73,0xdf,0x88,0x3d,0x2c,
    0x34,0xf1,0xef,0x45,0x1f,0xd4,0x6b,0x50,0x3f,0x00
};
static const u8 P521_GX[] = {
    0x00,0xc6,0x85,0x8e,0x06,0xb7,0x04,0x04,0xe9,0xcd,0x9e,
    0x3e,0xcb,0x66,0x23,0x95,0xb4,0x42,0x9c,0x64,0x81,0x39,
    0x05,0x3f,0xb5,0x21,0xf8,0x28,0xaf,0x60,0x6b,0x4d,0x3d,
    0xba,0xa1,0x4b,0x5e,0x77,0xef,0xe7,0x59,0x28,0xfe,0x1d,
    0xc1,0x27,0xa2,0xff,0xa8,0xde,0x33,0x48,0xb3,0xc1,0x85,
    0x6a,0x42,0x9b,0xf9,0x7e,0x7e,0x31,0xc2,0xe5,0xbd,0x66
};
static const u8 P521_GY[] = {
    0x01,0x18,0x39,0x29,0x6a,0x78,0x9a,0x3b,0xc0,0x04,0x5c,
    0x8a,0x5f,0xb4,0x2c,0x7d,0x1b,0xd9,0x98,0xf5,0x44,0x49,
    0x57,0x9b,0x44,0x68,0x17,0xaf,0xbd,0x17,0x27,0x3e,0x66,
    0x2c,0x97,0xee,0x72,0x99,0x5e,0xf4,0x26,0x40,0xc5,0x50,
    0xb9,0x01,0x3f,0xad,0x07,0x61,0x35,0x3c,0x70,0x86,0xa2,
    0x72,0xc2,0x40,0x88,0xbe,0x94,0x76,0x9f,0xd1,0x66,0x50
};

typedef struct {
    rin_size_t coordinate_size;
    const u8* p;
    const u8* n;
    const u8* b;
    rin_size_t b_size;
    const u8* gx;
    const u8* gy;
} nist_curve_t;

static int nist_curve_parameters(int curve, nist_curve_t* parameters)
{
    if (!parameters) return ECDH_ERR_INVALID;
    if (curve == ECDSA_CURVE_P384) {
        parameters->coordinate_size = 48;
        parameters->p = P384_P;
        parameters->n = P384_N;
        parameters->b = P384_B;
        parameters->b_size = sizeof(P384_B);
        parameters->gx = P384_GX;
        parameters->gy = P384_GY;
        return ECDH_OK;
    }
    if (curve == ECDSA_CURVE_P521) {
        parameters->coordinate_size = 66;
        parameters->p = P521_P;
        parameters->n = P521_N;
        parameters->b = P521_B;
        parameters->b_size = sizeof(P521_B);
        parameters->gx = P521_GX;
        parameters->gy = P521_GY;
        return ECDH_OK;
    }
    return ECDH_ERR_INVALID;
}

static int ecdsa_read_der_length(const u8** cursor, const u8* end,
                                 rin_size_t* length)
{
    u8 first;
    rin_size_t value = 0;
    rin_size_t count;
    if (!cursor || !*cursor || *cursor >= end || !length) return ECDH_ERR_INVALID;
    first = *(*cursor)++;
    if (first < 0x80) {
        *length = first;
        return ECDH_OK;
    }
    count = first & 0x7fu;
    if (count == 0 || count > sizeof(rin_size_t) || (rin_size_t)(end - *cursor) < count)
        return ECDH_ERR_INVALID;
    if (**cursor == 0) return ECDH_ERR_INVALID;
    while (count--) value = (value << 8) | *(*cursor)++;
    if (value < 0x80 || value > (rin_size_t)(end - *cursor)) return ECDH_ERR_INVALID;
    *length = value;
    return ECDH_OK;
}

static int ecdsa_component_from_der(u8* output, rin_size_t width,
                                    const u8** cursor, const u8* end)
{
    rin_size_t length;
    const u8* value;
    if (*cursor >= end || *(*cursor)++ != 0x02 ||
        ecdsa_read_der_length(cursor, end, &length) != ECDH_OK ||
        length == 0 || length > (rin_size_t)(end - *cursor)) {
        return ECDH_ERR_INVALID;
    }
    value = *cursor;
    *cursor += length;
    if (value[0] & 0x80) return ECDH_ERR_INVALID;
    if (length > 1 && value[0] == 0) {
        if ((value[1] & 0x80) == 0) return ECDH_ERR_INVALID;
        value++;
        length--;
    }
    if (length > width) return ECDH_ERR_INVALID;
    rintls_memset(output, 0, width);
    rintls_memcpy(output + width - length, value, length);
    return ECDH_OK;
}

static int ecdsa_signature_components(u8* r, u8* s, rin_size_t width,
                                      const u8* signature, rin_size_t sig_len)
{
    const u8* cursor;
    const u8* end;
    rin_size_t sequence_length;
    if (sig_len == width * 2) {
        rintls_memcpy(r, signature, width);
        rintls_memcpy(s, signature + width, width);
        return ECDH_OK;
    }
    cursor = signature;
    end = signature + sig_len;
    if (cursor >= end || *cursor++ != 0x30 ||
        ecdsa_read_der_length(&cursor, end, &sequence_length) != ECDH_OK ||
        sequence_length != (rin_size_t)(end - cursor)) {
        return ECDH_ERR_INVALID;
    }
    if (ecdsa_component_from_der(r, width, &cursor, end) != ECDH_OK ||
        ecdsa_component_from_der(s, width, &cursor, end) != ECDH_OK || cursor != end) {
        return ECDH_ERR_INVALID;
    }
    return ECDH_OK;
}

static int nist_public_point_is_valid(const p256_point_t* point,
                                      const bignum_t* prime,
                                      const u8* b_bytes, rin_size_t b_size)
{
    bignum_t lhs, rhs, temporary, three, b;
    if (bn_cmp(&point->x, prime) >= 0 || bn_cmp(&point->y, prime) >= 0)
        return 0;
    bn_mod_mul(&lhs, &point->y, &point->y, prime);
    bn_mod_mul(&temporary, &point->x, &point->x, prime);
    bn_mod_mul(&rhs, &temporary, &point->x, prime);
    bn_set_u32(&three, 3);
    bn_mod_mul(&temporary, &three, &point->x, prime);
    bn_mod_sub(&rhs, &rhs, &temporary, prime);
    bn_from_bytes(&b, b_bytes, b_size);
    bn_mod_add(&rhs, &rhs, &b, prime);
    return bn_cmp(&lhs, &rhs) == 0;
}

int ecdsa_nist_verify(int curve,
                      const u8* signature, rin_size_t sig_len,
                      const u8* hash, rin_size_t hash_len,
                      const u8* public_key, rin_size_t pubkey_len)
{
    nist_curve_t parameters;
    u8 r_bytes[66], s_bytes[66];
    bignum_t r, s, z, n, prime, w, u1, u2, v;
    p256_point_t G, Q, R1, R2, R;
    rin_size_t width;

    if (curve == ECDSA_CURVE_P256) {
        return ecdsa_p256_verify(signature, sig_len, hash, hash_len,
                                 public_key, pubkey_len);
    }
    if (!signature || !hash || !public_key ||
        nist_curve_parameters(curve, &parameters) != ECDH_OK) {
        return ECDH_ERR_INVALID;
    }
    width = parameters.coordinate_size;
    if (pubkey_len != 1 + width * 2 || public_key[0] != 0x04 ||
        ecdsa_signature_components(r_bytes, s_bytes, width,
                                   signature, sig_len) != ECDH_OK) {
        return ECDH_ERR_INVALID;
    }
    bn_from_bytes(&r, r_bytes, width);
    bn_from_bytes(&s, s_bytes, width);
    bn_from_bytes(&prime, parameters.p, width);
    bn_from_bytes(&n, parameters.n, width);
    if (bn_is_zero(&r) || bn_cmp(&r, &n) >= 0 ||
        bn_is_zero(&s) || bn_cmp(&s, &n) >= 0) {
        return ECDH_ERR_INVALID;
    }

    bn_from_bytes(&Q.x, public_key + 1, width);
    bn_from_bytes(&Q.y, public_key + 1 + width, width);
    Q.infinity = 0;
    if (!nist_public_point_is_valid(&Q, &prime, parameters.b, parameters.b_size))
        return ECDH_ERR_POINT;

    if (hash_len > width) hash_len = width;
    bn_from_bytes(&z, hash, hash_len);
    if (bn_mod_inv(&w, &s, &n) != BIGNUM_OK) return ECDH_ERR_INVALID;
    bn_mod_mul(&u1, &z, &w, &n);
    bn_mod_mul(&u2, &r, &w, &n);

    bn_from_bytes(&G.x, parameters.gx, width);
    bn_from_bytes(&G.y, parameters.gy, width);
    G.infinity = 0;
    p256_scalar_mult(&R1, &u1, &G, &prime);
    p256_scalar_mult(&R2, &u2, &Q, &prime);
    p256_add(&R, &R1, &R2, &prime);
    if (R.infinity) return ECDH_ERR_VERIFY;
    bn_mod(&v, &R.x, &n);
    return bn_cmp(&v, &r) == 0 ? ECDH_OK : ECDH_ERR_VERIFY;
}
