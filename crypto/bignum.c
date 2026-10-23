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
    rin_size_t byte_len;
    rin_size_t source_offset;
    rin_size_t destination_offset;
    rin_size_t copy_len;
    rin_size_t index;

    if (n == NULL || data == NULL) return BIGNUM_ERR_INVALID;
    rintls_memset(data, 0, len);
    if (n->used == 0 || len == 0u) return BIGNUM_OK;

    /* The most significant limb may be only partially occupied (for example,
     * P-521 uses 66 bytes but 17 32-bit limbs occupy a 68-byte container).
     * Select the least-significant bytes before converting each limb; the old
     * loop truncated the low bytes whenever len was not a multiple of four. */
    byte_len = n->used * 4u;
    source_offset = byte_len > len ? byte_len - len : 0u;
    destination_offset = len > byte_len ? len - byte_len : 0u;
    copy_len = byte_len < len ? byte_len : len;
    for (index = 0u; index < copy_len; ++index) {
        rin_size_t source_position = source_offset + index;
        rin_size_t limb_index = n->used - 1u - source_position / 4u;
        rin_size_t byte_in_limb = source_position % 4u;
        data[destination_offset + index] =
            (u8)(n->limbs[limb_index] >> (24u - 8u * byte_in_limb));
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

    if (max_used > BIGNUM_MAX_LIMBS) {
        return BIGNUM_ERR_OVERFLOW;
    }

    u64 carry = 0;
    for (rin_size_t i = 0; i < max_used; i++) {
        u64 sum = carry;
        if (i < a->used) sum += a->limbs[i];
        if (i < b->used) sum += b->limbs[i];

        r->limbs[i] = (u32)sum;
        carry = sum >> 32;
    }

    if (carry) {
        if (max_used == BIGNUM_MAX_LIMBS) {
            return BIGNUM_ERR_OVERFLOW;
        }
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

/* Add two already-reduced, non-negative values without ever materializing a
 * value wider than the modulus.  This is the primitive used by the wide
 * modular-multiplication fallback below. */
static int bn_mod_add_reduced(bignum_t* r, const bignum_t* a,
                              const bignum_t* b, const bignum_t* m)
{
    bignum_t gap;
    int ret;

    if (!r || !a || !b || !m || a->sign || b->sign || m->sign ||
        bn_is_zero(m) || bn_cmp_abs(a, m) >= 0 || bn_cmp_abs(b, m) >= 0) {
        return BIGNUM_ERR_INVALID;
    }

    /* If a >= m-b, a+b would reach the modulus.  Compute the equivalent
     * a-(m-b) instead, which remains within the fixed-width representation. */
    ret = bn_sub(&gap, m, b);
    if (ret != BIGNUM_OK) return ret;
    if (bn_cmp_abs(a, &gap) >= 0)
        return bn_sub(r, a, &gap);
    return bn_add(r, a, b);
}

int bn_mod_mul(bignum_t* r, const bignum_t* a, const bignum_t* b, const bignum_t* m)
{
    bignum_t tmp;
    int ret;

    if (!r || !a || !b || !m || a->sign || b->sign || m->sign ||
        bn_is_zero(m)) {
        return BIGNUM_ERR_INVALID;
    }

    /* Preserve the existing fast path whenever the complete product fits. */
    if (a->used + b->used <= BIGNUM_MAX_LIMBS) {
        ret = bn_mul(&tmp, a, b);
        if (ret != BIGNUM_OK) return ret;
        return bn_mod(r, &tmp, m);
    }

    /* A 4096-bit RSA residue squared needs an 8192-bit temporary.  Keep the
     * public bignum bound at 4096 bits and form the product modulo m using
     * interleaved addition/doubling instead. */
    bignum_t multiplicand, multiplier, result;
    ret = bn_mod(&multiplicand, a, m);
    if (ret != BIGNUM_OK) return ret;
    ret = bn_mod(&multiplier, b, m);
    if (ret != BIGNUM_OK) return ret;
    bn_init(&result);

    rin_size_t multiplier_bits = bn_bitlen(&multiplier);
    for (rin_size_t i = 0; i < multiplier_bits; ++i) {
        if (bn_get_bit(&multiplier, i)) {
            ret = bn_mod_add_reduced(&result, &result, &multiplicand, m);
            if (ret != BIGNUM_OK) return ret;
        }
        if (i + 1 < multiplier_bits) {
            ret = bn_mod_add_reduced(&multiplicand, &multiplicand,
                                     &multiplicand, m);
            if (ret != BIGNUM_OK) return ret;
        }
    }

    bn_copy(r, &result);
    return BIGNUM_OK;
}

/* モジュラ冪乗 (二乗-乗算法) */
int bn_mod_exp(bignum_t* r, const bignum_t* base, const bignum_t* exp, const bignum_t* m)
{
    int ret;

    if (!r || !base || !exp || !m || base->used > BIGNUM_MAX_LIMBS ||
        exp->used > BIGNUM_MAX_LIMBS || m->used > BIGNUM_MAX_LIMBS) {
        return BIGNUM_ERR_INVALID;
    }

    if (bn_is_zero(m)) {
        return BIGNUM_ERR_DIVZERO;
    }
    if (m->sign) return BIGNUM_ERR_INVALID;

    /* Odd moduli, including RSA keys, use bounded Montgomery arithmetic.
     * Keep the division-based path for even moduli and modulus one. */
    if (!base->sign && !exp->sign && bn_is_odd(m) && !bn_is_one(m)) {
        bn_mont_ctx mont;
        ret = bn_mont_init(&mont, m);
        if (ret == BIGNUM_OK) ret = bn_mont_exp(r, base, exp, &mont);
        rintls_secure_zero(&mont, sizeof(mont));
        return ret;
    }

    if (bn_is_zero(exp)) {
        bignum_t one;
        bn_set_u32(&one, 1);
        return bn_mod(r, &one, m);
    }

    bignum_t result, b;
    bn_set_u32(&result, 1);
    ret = bn_mod(&b, base, m);
    if (ret != BIGNUM_OK) return ret;

    rin_size_t exp_bits = bn_bitlen(exp);

    for (rin_size_t i = 0; i < exp_bits; i++) {
        if (bn_get_bit(exp, i)) {
            ret = bn_mod_mul(&result, &result, &b, m);
            if (ret != BIGNUM_OK) return ret;
        }
        if (i + 1 < exp_bits) {
            ret = bn_mod_mul(&b, &b, &b, m);
            if (ret != BIGNUM_OK) return ret;
        }
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

static u32 bn_mont_n_inv(u32 low_limb)
{
    u32 inverse = 1u;
    int iteration;

    /* Newton iteration doubles the number of correct low bits each round. */
    for (iteration = 0; iteration < 5; ++iteration)
        inverse *= 2u - low_limb * inverse;
    return (u32)(0u - inverse);
}

static int bn_mont_context_valid(const bn_mont_ctx* ctx)
{
    return ctx && ctx->n.used != 0u &&
           ctx->n.used <= BIGNUM_MAX_LIMBS && !ctx->n.sign &&
           !bn_is_one(&ctx->n) && !bn_is_even(&ctx->n) &&
           ctx->n_bits == bn_bitlen(&ctx->n) &&
           ctx->r2.used != 0u && ctx->r2.used <= BIGNUM_MAX_LIMBS &&
           !ctx->r2.sign && bn_cmp_abs(&ctx->r2, &ctx->n) < 0 &&
           !bn_is_zero(&ctx->r2) &&
           ctx->n_inv == bn_mont_n_inv(ctx->n.limbs[0]);
}

int bn_mont_init(bn_mont_ctx* ctx, const bignum_t* n)
{
    bignum_t modulus;
    rin_size_t bit;

    if (!ctx) return BIGNUM_ERR_INVALID;
    if (!n || n->used == 0u || n->used > BIGNUM_MAX_LIMBS || n->sign) {
        rintls_secure_zero(ctx, sizeof(*ctx));
        return BIGNUM_ERR_INVALID;
    }

    /* Copy before clearing ctx so initializing from ctx->n is safe. */
    bn_copy(&modulus, n);
    bn_normalize(&modulus);
    rintls_secure_zero(ctx, sizeof(*ctx));
    if (bn_is_zero(&modulus) || bn_is_one(&modulus) ||
        bn_is_even(&modulus)) {
        bn_clear(&modulus);
        return BIGNUM_ERR_INVALID;
    }

    bn_copy(&ctx->n, &modulus);
    ctx->n_bits = bn_bitlen(&ctx->n);
    ctx->n_inv = bn_mont_n_inv(ctx->n.limbs[0]);

    /* R^2 mod n = 2^(64 * n.used) mod n.  Build it with bounded modular
     * doublings because the value itself does not fit in bignum_t. */
    bn_set_u32(&ctx->r2, 1u);
    for (bit = 0u; bit < 64u * ctx->n.used; ++bit) {
        int ret = bn_mod_add_reduced(&ctx->r2, &ctx->r2, &ctx->r2,
                                     &ctx->n);
        if (ret != BIGNUM_OK) {
            rintls_secure_zero(ctx, sizeof(*ctx));
            bn_clear(&modulus);
            return ret;
        }
    }
    bn_clear(&modulus);
    return BIGNUM_OK;
}

/* Montgomery-reduce a full-width product in place. */
static int bn_mont_reduce(u32* product, rin_size_t product_limb_count,
                          const bn_mont_ctx* ctx)
{
    rin_size_t i;
    rin_size_t limb_count = ctx->n.used;

    for (i = 0u; i < limb_count; ++i) {
        u32 multiple = product[i] * ctx->n_inv;
        u64 carry = 0u;
        rin_size_t j;

        for (j = 0u; j < limb_count; ++j) {
            rin_size_t index = i + j;
            u64 sum = mul_u32(multiple, ctx->n.limbs[j]) +
                      product[index] + carry;
            product[index] = (u32)sum;
            carry = sum >> 32;
        }
        for (j = i + limb_count; carry; ++j) {
            u64 sum;
            if (j >= product_limb_count) return BIGNUM_ERR_OVERFLOW;
            sum = (u64)product[j] + carry;
            product[j] = (u32)sum;
            carry = sum >> 32;
        }
    }
    return BIGNUM_OK;
}

int bn_mont_mul(bignum_t* r, const bignum_t* a, const bignum_t* b,
                const bn_mont_ctx* ctx)
{
    u32 product[BIGNUM_MAX_LIMBS * 2u + 2u];
    bignum_t left;
    bignum_t right;
    bignum_t reduced;
    rin_size_t i;
    rin_size_t limb_count;
    rin_size_t product_limb_count = BIGNUM_MAX_LIMBS * 2u + 2u;
    int ret = BIGNUM_OK;

    if (!r || !a || !b || a->used > BIGNUM_MAX_LIMBS ||
        b->used > BIGNUM_MAX_LIMBS || a->sign || b->sign ||
        !bn_mont_context_valid(ctx)) {
        return BIGNUM_ERR_INVALID;
    }

    rintls_memset(product, 0, sizeof(product));
    bn_init(&left);
    bn_init(&right);
    bn_init(&reduced);
    limb_count = ctx->n.used;
    if (bn_cmp_abs(a, &ctx->n) >= 0)
        ret = bn_mod(&left, a, &ctx->n);
    else
        bn_copy(&left, a);
    if (ret != BIGNUM_OK) goto cleanup;
    if (bn_cmp_abs(b, &ctx->n) >= 0)
        ret = bn_mod(&right, b, &ctx->n);
    else
        bn_copy(&right, b);
    if (ret != BIGNUM_OK) goto cleanup;

    /* Preserve the full 2N-limb product and its carry before reduction. */
    for (i = 0u; i < left.used; ++i) {
        u64 carry = 0u;
        rin_size_t j;
        for (j = 0u; j < right.used; ++j) {
            rin_size_t index = i + j;
            u64 sum = mul_u32(left.limbs[i], right.limbs[j]) +
                      product[index] + carry;
            product[index] = (u32)sum;
            carry = sum >> 32;
        }
        for (j = i + right.used; carry; ++j) {
            u64 sum;
            if (j >= product_limb_count) {
                ret = BIGNUM_ERR_OVERFLOW;
                goto cleanup;
            }
            sum = (u64)product[j] + carry;
            product[j] = (u32)sum;
            carry = sum >> 32;
        }
    }

    ret = bn_mont_reduce(product, product_limb_count, ctx);
    if (ret != BIGNUM_OK) goto cleanup;

    /* REDC is < 2n.  When its high limb is one, subtract n from the low
     * limbs and consume the borrow instead of truncating a 4097-bit value. */
    reduced.used = limb_count;
    for (i = 0u; i < limb_count; ++i)
        reduced.limbs[i] = product[limb_count + i];
    bn_normalize(&reduced);
    if (product[limb_count * 2u] != 0u) {
        u32 high = product[limb_count * 2u];
        u64 borrow = 0u;
        if (high != 1u) {
            ret = BIGNUM_ERR_OVERFLOW;
            goto cleanup;
        }
        for (i = 0u; i < limb_count; ++i) {
            u64 subtrahend = (u64)ctx->n.limbs[i] + borrow;
            u64 value = reduced.limbs[i];
            reduced.limbs[i] = (u32)(value - subtrahend);
            borrow = value < subtrahend ? 1u : 0u;
        }
        if (borrow != high) {
            ret = BIGNUM_ERR_OVERFLOW;
            goto cleanup;
        }
        bn_normalize(&reduced);
    } else if (bn_cmp_abs(&reduced, &ctx->n) >= 0) {
        bn_sub_abs(&reduced, &reduced, &ctx->n);
    }
    for (i = limb_count * 2u + 1u; i < product_limb_count; ++i) {
        if (product[i] != 0u) {
            ret = BIGNUM_ERR_OVERFLOW;
            goto cleanup;
        }
    }
    bn_copy(r, &reduced);

cleanup:
    bn_clear(&left);
    bn_clear(&right);
    bn_clear(&reduced);
    rintls_secure_zero(product, sizeof(product));
    return ret;
}

int bn_mont_exp(bignum_t* r, const bignum_t* base, const bignum_t* exp,
                const bn_mont_ctx* ctx)
{
    bignum_t reduced_base;
    bignum_t base_mont;
    bignum_t result;
    bignum_t one;
    bignum_t normal_result;
    rin_size_t bit;
    int ret;

    if (!r || !base || !exp || base->used > BIGNUM_MAX_LIMBS ||
        exp->used > BIGNUM_MAX_LIMBS || base->sign || exp->sign ||
        !bn_mont_context_valid(ctx)) {
        return BIGNUM_ERR_INVALID;
    }
    bn_init(&reduced_base);
    bn_init(&base_mont);
    bn_init(&result);
    bn_init(&one);
    bn_init(&normal_result);

    ret = bn_mod(&reduced_base, base, &ctx->n);
    if (ret != BIGNUM_OK) goto cleanup;
    bn_set_u32(&one, 1u);
    ret = bn_mont_mul(&base_mont, &reduced_base, &ctx->r2, ctx);
    if (ret != BIGNUM_OK) goto cleanup;
    ret = bn_mont_mul(&result, &one, &ctx->r2, ctx);
    if (ret != BIGNUM_OK) goto cleanup;

    for (bit = bn_bitlen(exp); bit > 0u; --bit) {
        ret = bn_mont_mul(&result, &result, &result, ctx);
        if (ret != BIGNUM_OK) goto cleanup;
        if (bn_get_bit(exp, bit - 1u)) {
            ret = bn_mont_mul(&result, &result, &base_mont, ctx);
            if (ret != BIGNUM_OK) goto cleanup;
        }
    }
    ret = bn_mont_mul(&normal_result, &result, &one, ctx);
    if (ret == BIGNUM_OK) bn_copy(r, &normal_result);

cleanup:
    bn_clear(&reduced_base);
    bn_clear(&base_mont);
    bn_clear(&result);
    bn_clear(&one);
    bn_clear(&normal_result);
    return ret;
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
