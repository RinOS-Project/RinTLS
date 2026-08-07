/*
 * rinTLS - Big Number (多倍長整数演算)
 * RSA/ECDHに必要な演算を提供
 */

#include "bignum.h"
#include "../platform/rin_platform.h"

/* ═══════════════════════════════════════
 * 内部ヘルパー関数
 * ═══════════════════════════════════════ */

/* 64ビット乗算結果を取得 */
static inline u64 mul_u32(u32 a, u32 b)
{
    return (u64)a * (u64)b;
}

/* ═══════════════════════════════════════
 * 初期化・代入
 * ═══════════════════════════════════════ */

void bn_init(bignum_t* n)
{
    rintls_memset(n->limbs, 0, sizeof(n->limbs));
    n->used = 0;
    n->sign = 0;
}

void bn_set_u32(bignum_t* n, u32 val)
{
    bn_init(n);
    if (val != 0) {
        n->limbs[0] = val;
        n->used = 1;
    }
}

void bn_set_u64(bignum_t* n, u64 val)
{
    bn_init(n);
    if (val != 0) {
        n->limbs[0] = (u32)val;
        n->limbs[1] = (u32)(val >> 32);
        n->used = (n->limbs[1] != 0) ? 2 : 1;
    }
}

void bn_copy(bignum_t* dest, const bignum_t* src)
{
    rintls_memcpy(dest->limbs, src->limbs, src->used * sizeof(u32));
    rintls_memset(dest->limbs + src->used, 0,
                  (BIGNUM_MAX_LIMBS - src->used) * sizeof(u32));
    dest->used = src->used;
    dest->sign = src->sign;
}

int bn_from_bytes(bignum_t* n, const u8* data, rin_size_t len)
{
    bn_init(n);

    if (len == 0) return BIGNUM_OK;

    /* 最大サイズチェック */
    if (len > BIGNUM_MAX_LIMBS * 4) {
        return BIGNUM_ERR_OVERFLOW;
    }

    /* ビッグエンディアンからリトルエンディアンへ変換 */
    rin_size_t limb_idx = 0;
    rin_size_t i = len;

    while (i > 0) {
        u32 limb = 0;
        rin_size_t bytes_in_limb = (i >= 4) ? 4 : i;

        for (rin_size_t j = 0; j < bytes_in_limb; j++) {
            limb |= ((u32)data[i - bytes_in_limb + j]) << (8 * (bytes_in_limb - 1 - j));
        }

        n->limbs[limb_idx++] = limb;
        i -= bytes_in_limb;
    }

    n->used = limb_idx;
    bn_normalize(n);

    return BIGNUM_OK;
}

int bn_to_bytes(const bignum_t* n, u8* data, rin_size_t len)
{
    rintls_memset(data, 0, len);

    if (n->used == 0) return BIGNUM_OK;

    /* リトルエンディアンからビッグエンディアンへ変換 */
    rin_size_t byte_len = n->used * 4;
    rin_size_t start = (len > byte_len) ? (len - byte_len) : 0;

    for (rin_size_t i = 0; i < n->used && (start + (n->used - 1 - i) * 4) < len; i++) {
        u32 limb = n->limbs[n->used - 1 - i];
        rin_size_t pos = start + i * 4;

        for (int j = 0; j < 4 && (pos + j) < len; j++) {
            data[pos + j] = (u8)(limb >> (24 - 8 * j));
        }
    }

    return BIGNUM_OK;
}

/* ═══════════════════════════════════════
 * 比較
 * ═══════════════════════════════════════ */

int bn_is_zero(const bignum_t* n)
{
    return (n->used == 0);
}

int bn_is_one(const bignum_t* n)
{
    return (n->used == 1 && n->limbs[0] == 1 && n->sign == 0);
}

int bn_is_even(const bignum_t* n)
{
    if (n->used == 0) return 1;
    return (n->limbs[0] & 1) == 0;
}

int bn_is_odd(const bignum_t* n)
{
    if (n->used == 0) return 0;
    return (n->limbs[0] & 1) == 1;
}

int bn_cmp_abs(const bignum_t* a, const bignum_t* b)
{
    if (a->used > b->used) return 1;
    if (a->used < b->used) return -1;

    /* 同じ長さの場合、上位から比較 */
    for (rin_size_t i = a->used; i > 0; i--) {
        if (a->limbs[i-1] > b->limbs[i-1]) return 1;
        if (a->limbs[i-1] < b->limbs[i-1]) return -1;
    }

    return 0;
}

int bn_cmp(const bignum_t* a, const bignum_t* b)
{
    /* 符号が異なる場合 */
    if (a->sign != b->sign) {
        if (bn_is_zero(a) && bn_is_zero(b)) return 0;
        return a->sign ? -1 : 1;
    }

    int cmp = bn_cmp_abs(a, b);
    return a->sign ? -cmp : cmp;
}

int bn_cmp_u32(const bignum_t* a, u32 b)
{
    if (a->sign) return -1;  /* 負は常に小さい */
    if (a->used == 0) return (b == 0) ? 0 : -1;
    if (a->used > 1) return 1;
    if (a->limbs[0] > b) return 1;
    if (a->limbs[0] < b) return -1;
    return 0;
}

/* ═══════════════════════════════════════
 * ビット操作
 * ═══════════════════════════════════════ */

rin_size_t bn_bitlen(const bignum_t* n)
{
    if (n->used == 0) return 0;

    rin_size_t bits = (n->used - 1) * 32;
    u32 top = n->limbs[n->used - 1];

    while (top != 0) {
        bits++;
        top >>= 1;
    }

    return bits;
}

int bn_get_bit(const bignum_t* n, rin_size_t pos)
{
    rin_size_t limb_idx = pos / 32;
    rin_size_t bit_idx = pos % 32;

    if (limb_idx >= n->used) return 0;

    return (n->limbs[limb_idx] >> bit_idx) & 1;
}

int bn_lshift(bignum_t* r, const bignum_t* a, rin_size_t bits)
{
    if (bits == 0 || bn_is_zero(a)) {
        bn_copy(r, a);
        return BIGNUM_OK;
    }

    rin_size_t limb_shift = bits / 32;
    rin_size_t bit_shift = bits % 32;

    /* A whole-limb shift does not need a carry limb.  The previous
     * unconditional +1 rejected the exact-width 4096-bit intermediates used
     * by RSA-2048 reduction.  bn_div ignored that error and compared an
     * uninitialized shifted value, making valid signatures key-dependent. */
    rin_size_t carry_limbs = 0;
    if (bit_shift != 0 &&
        (a->limbs[a->used - 1] >> (32 - bit_shift)) != 0) {
        carry_limbs = 1;
    }
    if (a->used + limb_shift + carry_limbs > BIGNUM_MAX_LIMBS) {
        return BIGNUM_ERR_OVERFLOW;
    }

    bignum_t tmp;
    bn_init(&tmp);

    if (bit_shift == 0) {
        for (rin_size_t i = 0; i < a->used; i++) {
            tmp.limbs[i + limb_shift] = a->limbs[i];
        }
        tmp.used = a->used + limb_shift;
    } else {
        u32 carry = 0;
        for (rin_size_t i = 0; i < a->used; i++) {
            tmp.limbs[i + limb_shift] = (a->limbs[i] << bit_shift) | carry;
            carry = a->limbs[i] >> (32 - bit_shift);
        }
        if (carry != 0) {
            tmp.limbs[a->used + limb_shift] = carry;
            tmp.used = a->used + limb_shift + 1;
        } else {
            tmp.used = a->used + limb_shift;
        }
    }

    tmp.sign = a->sign;
    bn_copy(r, &tmp);
    return BIGNUM_OK;
}

int bn_rshift(bignum_t* r, const bignum_t* a, rin_size_t bits)
{
    if (bits == 0) {
        bn_copy(r, a);
        return BIGNUM_OK;
    }

    rin_size_t limb_shift = bits / 32;
    rin_size_t bit_shift = bits % 32;

    if (limb_shift >= a->used) {
        bn_init(r);
        return BIGNUM_OK;
    }

    bignum_t tmp;
    bn_init(&tmp);

    if (bit_shift == 0) {
        for (rin_size_t i = limb_shift; i < a->used; i++) {
            tmp.limbs[i - limb_shift] = a->limbs[i];
        }
        tmp.used = a->used - limb_shift;
    } else {
        for (rin_size_t i = limb_shift; i < a->used; i++) {
            tmp.limbs[i - limb_shift] = a->limbs[i] >> bit_shift;
            if (i + 1 < a->used) {
                tmp.limbs[i - limb_shift] |= a->limbs[i + 1] << (32 - bit_shift);
            }
        }
        tmp.used = a->used - limb_shift;
    }

    tmp.sign = a->sign;
    bn_normalize(&tmp);
    bn_copy(r, &tmp);
    return BIGNUM_OK;
}

/* ═══════════════════════════════════════
 * 基本演算
 * ═══════════════════════════════════════ */

/* 絶対値の加算 */
static int bn_add_abs(bignum_t* r, const bignum_t* a, const bignum_t* b)
{
    rin_size_t max_used = (a->used > b->used) ? a->used : b->used;

    if (max_used + 1 > BIGNUM_MAX_LIMBS) {
        return BIGNUM_ERR_OVERFLOW;
    }

    u64 carry = 0;
    for (rin_size_t i = 0; i < max_used || carry; i++) {
        u64 sum = carry;
        if (i < a->used) sum += a->limbs[i];
        if (i < b->used) sum += b->limbs[i];

        r->limbs[i] = (u32)sum;
        carry = sum >> 32;

        if (i >= r->used && r->limbs[i] != 0) {
            r->used = i + 1;
        }
    }

    if (carry) {
        r->limbs[max_used] = (u32)carry;
        r->used = max_used + 1;
    } else {
        r->used = max_used;
    }

    bn_normalize(r);
    return BIGNUM_OK;
}

/* 絶対値の減算 (|a| >= |b| を仮定) */
static int bn_sub_abs(bignum_t* r, const bignum_t* a, const bignum_t* b)
{
    u64 borrow = 0;

    for (rin_size_t i = 0; i < a->used; i++) {
        u64 diff = (u64)a->limbs[i] - borrow;
        if (i < b->used) diff -= b->limbs[i];

        if (diff > (u64)a->limbs[i]) {
            /* アンダーフロー発生 */
            diff += ((u64)1 << 32);
            borrow = 1;
        } else {
            borrow = 0;
        }

        r->limbs[i] = (u32)diff;
    }

    r->used = a->used;
    bn_normalize(r);
    return BIGNUM_OK;
}

int bn_add(bignum_t* r, const bignum_t* a, const bignum_t* b)
{
    bignum_t tmp;
    bn_init(&tmp);

    if (a->sign == b->sign) {
        /* 同符号: 絶対値を加算 */
        int ret = bn_add_abs(&tmp, a, b);
        if (ret != BIGNUM_OK) return ret;
        tmp.sign = a->sign;
    } else {
        /* 異符号: 絶対値を減算 */
        int cmp = bn_cmp_abs(a, b);
        if (cmp >= 0) {
            bn_sub_abs(&tmp, a, b);
            tmp.sign = a->sign;
        } else {
            bn_sub_abs(&tmp, b, a);
            tmp.sign = b->sign;
        }
    }

    if (bn_is_zero(&tmp)) tmp.sign = 0;
    bn_copy(r, &tmp);
    return BIGNUM_OK;
}

int bn_sub(bignum_t* r, const bignum_t* a, const bignum_t* b)
{
    bignum_t neg_b;
    bn_copy(&neg_b, b);
    neg_b.sign = !b->sign;
    return bn_add(r, a, &neg_b);
}

int bn_mul(bignum_t* r, const bignum_t* a, const bignum_t* b)
{
    if (bn_is_zero(a) || bn_is_zero(b)) {
        bn_init(r);
        return BIGNUM_OK;
    }

    if (a->used + b->used > BIGNUM_MAX_LIMBS) {
        return BIGNUM_ERR_OVERFLOW;
    }

    bignum_t tmp;
    bn_init(&tmp);

    for (rin_size_t i = 0; i < a->used; i++) {
        u64 carry = 0;
        for (rin_size_t j = 0; j < b->used || carry; j++) {
            u64 prod = (u64)tmp.limbs[i + j] + carry;
            if (j < b->used) {
                prod += mul_u32(a->limbs[i], b->limbs[j]);
            }
            tmp.limbs[i + j] = (u32)prod;
            carry = prod >> 32;
        }
    }

    tmp.used = a->used + b->used;
    tmp.sign = a->sign ^ b->sign;
    bn_normalize(&tmp);

    if (bn_is_zero(&tmp)) tmp.sign = 0;
    bn_copy(r, &tmp);
    return BIGNUM_OK;
}

int bn_mul_u32(bignum_t* r, const bignum_t* a, u32 b)
{
    bignum_t bn_b;
    bn_set_u32(&bn_b, b);
    return bn_mul(r, a, &bn_b);
}

/* 除算 (Knuthの長除算アルゴリズム) */
int bn_div(bignum_t* q, bignum_t* rem, const bignum_t* a, const bignum_t* b)
{
    if (bn_is_zero(b)) {
        return BIGNUM_ERR_DIVZERO;
    }

    int cmp = bn_cmp_abs(a, b);
    if (cmp < 0) {
        /* a < b: 商=0, 余り=a */
        if (q) bn_init(q);
        if (rem) bn_copy(rem, a);
        return BIGNUM_OK;
    }

    if (cmp == 0) {
        /* a == b: 商=1, 余り=0 */
        if (q) bn_set_u32(q, 1);
        if (rem) bn_init(rem);
        return BIGNUM_OK;
    }

    /* 簡易版の長除算 */
    bignum_t quotient, remainder;
    bn_init(&quotient);
    bn_copy(&remainder, a);
    remainder.sign = 0;

    rin_size_t a_bits = bn_bitlen(a);
    rin_size_t b_bits = bn_bitlen(b);

    /* ビットごとに処理 */
    for (rin_size_t i = a_bits - b_bits + 1; i > 0; i--) {
        bignum_t shifted_b;
        int shift_result = bn_lshift(&shifted_b, b, i - 1);
        if (shift_result != BIGNUM_OK) {
            return shift_result;
        }
        shifted_b.sign = 0;

        if (bn_cmp_abs(&remainder, &shifted_b) >= 0) {
            bn_sub_abs(&remainder, &remainder, &shifted_b);
            /* quotientのビットをセット */
            rin_size_t limb_idx = (i - 1) / 32;
            rin_size_t bit_idx = (i - 1) % 32;
            quotient.limbs[limb_idx] |= (1U << bit_idx);
            if (limb_idx >= quotient.used) {
                quotient.used = limb_idx + 1;
            }
        }
    }

    bn_normalize(&quotient);
    bn_normalize(&remainder);

    /* 符号を設定 */
    if (q) {
        quotient.sign = a->sign ^ b->sign;
        if (bn_is_zero(&quotient)) quotient.sign = 0;
        bn_copy(q, &quotient);
    }
    if (rem) {
        remainder.sign = a->sign;
        if (bn_is_zero(&remainder)) remainder.sign = 0;
        bn_copy(rem, &remainder);
    }

    return BIGNUM_OK;
}

int bn_mod(bignum_t* r, const bignum_t* a, const bignum_t* m)
{
    return bn_div(RIN_NULL, r, a, m);
}

/* ═══════════════════════════════════════
 * モジュラ演算
 * ═══════════════════════════════════════ */

int bn_mod_add(bignum_t* r, const bignum_t* a, const bignum_t* b, const bignum_t* m)
{
    bignum_t tmp;
    int ret = bn_add(&tmp, a, b);
    if (ret != BIGNUM_OK) return ret;

    return bn_mod(r, &tmp, m);
}

int bn_mod_sub(bignum_t* r, const bignum_t* a, const bignum_t* b, const bignum_t* m)
{
    bignum_t tmp;
    int ret = bn_sub(&tmp, a, b);
    if (ret != BIGNUM_OK) return ret;

    /* 負の場合はmを加算 */
    if (tmp.sign) {
        tmp.sign = 0;
        bn_sub(&tmp, m, &tmp);
    }

    return bn_mod(r, &tmp, m);
}

int bn_mod_mul(bignum_t* r, const bignum_t* a, const bignum_t* b, const bignum_t* m)
{
    bignum_t tmp;
    int ret = bn_mul(&tmp, a, b);
    if (ret != BIGNUM_OK) return ret;

    return bn_mod(r, &tmp, m);
}

/* モジュラ冪乗 (二乗-乗算法) */
int bn_mod_exp(bignum_t* r, const bignum_t* base, const bignum_t* exp, const bignum_t* m)
{
    if (bn_is_zero(m)) {
        return BIGNUM_ERR_DIVZERO;
    }

    if (bn_is_zero(exp)) {
        bn_set_u32(r, 1);
        return BIGNUM_OK;
    }

    bignum_t result, b;
    bn_set_u32(&result, 1);
    bn_mod(&b, base, m);

    rin_size_t exp_bits = bn_bitlen(exp);

    for (rin_size_t i = 0; i < exp_bits; i++) {
        if (bn_get_bit(exp, i)) {
            bn_mod_mul(&result, &result, &b, m);
        }
        bn_mod_mul(&b, &b, &b, m);
    }

    bn_copy(r, &result);
    return BIGNUM_OK;
}

/* 拡張ユークリッドアルゴリズム */
int bn_mod_inv(bignum_t* r, const bignum_t* a, const bignum_t* m)
{
    if (bn_is_zero(a) || bn_is_zero(m)) {
        return BIGNUM_ERR_INVALID;
    }

    bignum_t u, v, x1, x2, q, tmp;

    bn_copy(&u, a);
    bn_copy(&v, m);
    bn_set_u32(&x1, 1);
    bn_init(&x2);

    while (!bn_is_zero(&u) && !bn_is_one(&u)) {
        if (bn_is_zero(&v)) {
            return BIGNUM_ERR_INVALID;  /* 逆元なし */
        }

        bn_div(&q, &tmp, &u, &v);

        /* u, v を更新 */
        bn_copy(&u, &v);
        bn_copy(&v, &tmp);

        /* x1, x2 を更新 */
        bignum_t qx2;
        bn_mul(&qx2, &q, &x2);
        bn_sub(&tmp, &x1, &qx2);
        bn_copy(&x1, &x2);
        bn_copy(&x2, &tmp);
    }

    if (!bn_is_one(&u)) {
        return BIGNUM_ERR_INVALID;  /* 逆元なし */
    }

    /* 結果を正に */
    if (x1.sign) {
        bn_add(r, &x1, m);
    } else {
        bn_mod(r, &x1, m);
    }

    return BIGNUM_OK;
}

/* ═══════════════════════════════════════
 * GCD
 * ═══════════════════════════════════════ */

int bn_gcd(bignum_t* r, const bignum_t* a, const bignum_t* b)
{
    bignum_t u, v, tmp;

    bn_copy(&u, a);
    bn_copy(&v, b);
    u.sign = 0;
    v.sign = 0;

    while (!bn_is_zero(&v)) {
        bn_mod(&tmp, &u, &v);
        bn_copy(&u, &v);
        bn_copy(&v, &tmp);
    }

    bn_copy(r, &u);
    return BIGNUM_OK;
}

/* ═══════════════════════════════════════
 * Montgomery乗算
 * ═══════════════════════════════════════ */

int bn_mont_init(bn_mont_ctx* ctx, const bignum_t* n)
{
    bn_copy(&ctx->n, n);
    ctx->n_bits = bn_bitlen(n);

    /* R = 2^(32*n->used) */
    /* R^2 mod n を計算 */
    bignum_t r2;
    bn_set_u32(&r2, 1);
    bn_lshift(&r2, &r2, 2 * 32 * n->used);
    bn_mod(&ctx->r2, &r2, n);

    /* -n^(-1) mod 2^32 を計算 */
    /* Newton-Raphson法 */
    u32 n0 = n->limbs[0];
    u32 x = 1;
    for (int i = 0; i < 5; i++) {
        x = x * (2 - n0 * x);
    }
    ctx->n_inv = (u32)(-(i32)x);

    return BIGNUM_OK;
}

/* Montgomery簡約 */
static void bn_mont_reduce(bignum_t* r, bignum_t* t, const bn_mont_ctx* ctx)
{
    for (rin_size_t i = 0; i < ctx->n.used; i++) {
        u32 m = t->limbs[i] * ctx->n_inv;

        u64 carry = 0;
        for (rin_size_t j = 0; j < ctx->n.used; j++) {
            u64 prod = mul_u32(m, ctx->n.limbs[j]) + t->limbs[i + j] + carry;
            t->limbs[i + j] = (u32)prod;
            carry = prod >> 32;
        }

        for (rin_size_t j = ctx->n.used; carry && (i + j) < BIGNUM_MAX_LIMBS; j++) {
            u64 sum = (u64)t->limbs[i + j] + carry;
            t->limbs[i + j] = (u32)sum;
            carry = sum >> 32;
        }
    }

    /* t >> (32 * n.used) */
    bn_rshift(r, t, 32 * ctx->n.used);

    /* r >= n なら r -= n */
    if (bn_cmp_abs(r, &ctx->n) >= 0) {
        bn_sub_abs(r, r, &ctx->n);
    }
}

int bn_mont_mul(bignum_t* r, const bignum_t* a, const bignum_t* b, const bn_mont_ctx* ctx)
{
    bignum_t t;
    bn_mul(&t, a, b);
    bn_mont_reduce(r, &t, ctx);
    return BIGNUM_OK;
}

int bn_mont_exp(bignum_t* r, const bignum_t* base, const bignum_t* exp, const bn_mont_ctx* ctx)
{
    if (bn_is_zero(exp)) {
        bn_set_u32(r, 1);
        return BIGNUM_OK;
    }

    /* baseをMontgomery形式に変換: a' = a * R mod n */
    bignum_t a_mont, result;
    bn_mod_mul(&a_mont, base, &ctx->r2, &ctx->n);

    /* result = R mod n (1のMontgomery表現) */
    bignum_t one;
    bn_set_u32(&one, 1);
    bn_mod_mul(&result, &one, &ctx->r2, &ctx->n);

    rin_size_t exp_bits = bn_bitlen(exp);

    /* 二乗-乗算法 */
    for (rin_size_t i = exp_bits; i > 0; i--) {
        bn_mont_mul(&result, &result, &result, ctx);
        if (bn_get_bit(exp, i - 1)) {
            bn_mont_mul(&result, &result, &a_mont, ctx);
        }
    }

    /* Montgomery形式から通常形式に変換 */
    bn_mont_mul(r, &result, &one, ctx);

    return BIGNUM_OK;
}

/* ═══════════════════════════════════════
 * ユーティリティ
 * ═══════════════════════════════════════ */

void bn_normalize(bignum_t* n)
{
    while (n->used > 0 && n->limbs[n->used - 1] == 0) {
        n->used--;
    }
    if (n->used == 0) {
        n->sign = 0;
    }
}

void bn_clear(bignum_t* n)
{
    rintls_secure_zero(n, sizeof(bignum_t));
}
