/*
 * rinTLS private P-256 constant-time field and scalar multiplication helpers.
 * The field uses fixed-width little-endian 32-bit limbs in canonical form.
 */
#ifndef RINTLS_P256_CT_H
#define RINTLS_P256_CT_H

#include "bignum.h"

typedef struct {
    u32 limb[8];
} p256_ct_fe;

typedef struct {
    p256_ct_fe x;
    p256_ct_fe y;
    p256_ct_fe z;
} p256_ct_point;

static const p256_ct_fe p256_ct_prime = {{
    UINT32_C(0xffffffff), UINT32_C(0xffffffff),
    UINT32_C(0xffffffff), UINT32_C(0x00000000),
    UINT32_C(0x00000000), UINT32_C(0x00000000),
    UINT32_C(0x00000001), UINT32_C(0xffffffff)
}};

static const u32 p256_ct_inverse_exponent[8] = {
    UINT32_C(0xfffffffd), UINT32_C(0xffffffff),
    UINT32_C(0xffffffff), UINT32_C(0x00000000),
    UINT32_C(0x00000000), UINT32_C(0x00000000),
    UINT32_C(0x00000001), UINT32_C(0xffffffff)
};

static void p256_ct_fe_zero(p256_ct_fe* out)
{
    u32 i;
    for (i = 0; i < 8u; ++i) out->limb[i] = 0u;
}

static void p256_ct_fe_one(p256_ct_fe* out)
{
    p256_ct_fe_zero(out);
    out->limb[0] = 1u;
}

static u32 p256_ct_fe_is_zero(const p256_ct_fe* value)
{
    u32 aggregate = 0u;
    u32 i;
    for (i = 0; i < 8u; ++i) aggregate |= value->limb[i];
    return ((aggregate | (0u - aggregate)) >> 31) ^ 1u;
}

static u32 p256_ct_select_u32(u32 left, u32 right, u32 choose_right)
{
    u32 mask = 0u - (choose_right & 1u);
    return (left & ~mask) | (right & mask);
}

static void p256_ct_fe_select(p256_ct_fe* out,
                              const p256_ct_fe* left,
                              const p256_ct_fe* right,
                              u32 choose_right)
{
    u32 i;
    for (i = 0; i < 8u; ++i)
        out->limb[i] = p256_ct_select_u32(
            left->limb[i], right->limb[i], choose_right);
}

static void p256_ct_fe_add(p256_ct_fe* out,
                           const p256_ct_fe* left,
                           const p256_ct_fe* right)
{
    u32 sum[9];
    u32 difference[9];
    u64 carry = 0u;
    u32 borrow = 0u;
    u32 i;
    u32 use_difference;

    for (i = 0; i < 8u; ++i) {
        u64 value = (u64)left->limb[i] + right->limb[i] + carry;
        sum[i] = (u32)value;
        carry = value >> 32;
    }
    sum[8] = (u32)carry;

    for (i = 0; i < 8u; ++i) {
        u64 subtrahend = (u64)p256_ct_prime.limb[i] + borrow;
        u64 value = (u64)sum[i] - subtrahend;
        difference[i] = (u32)value;
        borrow = (u32)((u64)sum[i] < subtrahend);
    }
    difference[8] = sum[8] - borrow;
    borrow = (u32)(sum[8] < borrow);
    use_difference = borrow ^ 1u;

    for (i = 0; i < 8u; ++i)
        out->limb[i] = p256_ct_select_u32(
            sum[i], difference[i], use_difference);
    rintls_secure_zero(sum, sizeof(sum));
    rintls_secure_zero(difference, sizeof(difference));
}

static void p256_ct_fe_sub(p256_ct_fe* out,
                           const p256_ct_fe* left,
                           const p256_ct_fe* right)
{
    u32 difference[8];
    u32 borrow = 0u;
    u32 mask;
    u64 carry = 0u;
    u32 i;

    for (i = 0; i < 8u; ++i) {
        u64 subtrahend = (u64)right->limb[i] + borrow;
        u64 value = (u64)left->limb[i] - subtrahend;
        difference[i] = (u32)value;
        borrow = (u32)((u64)left->limb[i] < subtrahend);
    }

    mask = 0u - borrow;
    for (i = 0; i < 8u; ++i) {
        u64 value = (u64)difference[i] +
                    (p256_ct_prime.limb[i] & mask) + carry;
        out->limb[i] = (u32)value;
        carry = value >> 32;
    }
    rintls_secure_zero(difference, sizeof(difference));
}

static void p256_ct_fe_mul(p256_ct_fe* out,
                           const p256_ct_fe* left,
                           const p256_ct_fe* right)
{
    p256_ct_fe accumulator;
    p256_ct_fe doubled;
    p256_ct_fe added;
    u32 bit;

    p256_ct_fe_zero(&accumulator);
    for (bit = 256u; bit != 0u; --bit) {
        u32 position = bit - 1u;
        u32 selected = (right->limb[position >> 5] >>
                        (position & 31u)) & 1u;
        p256_ct_fe_add(&doubled, &accumulator, &accumulator);
        p256_ct_fe_add(&added, &doubled, left);
        p256_ct_fe_select(&accumulator, &doubled, &added, selected);
    }
    *out = accumulator;
    rintls_secure_zero(&accumulator, sizeof(accumulator));
    rintls_secure_zero(&doubled, sizeof(doubled));
    rintls_secure_zero(&added, sizeof(added));
}

static void p256_ct_fe_square(p256_ct_fe* out, const p256_ct_fe* value)
{
    p256_ct_fe_mul(out, value, value);
}

static void p256_ct_fe_inverse(p256_ct_fe* out, const p256_ct_fe* value)
{
    p256_ct_fe result;
    p256_ct_fe squared;
    p256_ct_fe multiplied;
    u32 bit;

    p256_ct_fe_one(&result);
    for (bit = 256u; bit != 0u; --bit) {
        u32 position = bit - 1u;
        u32 exponent_bit =
            (p256_ct_inverse_exponent[position >> 5] >>
             (position & 31u)) & 1u;
        p256_ct_fe_square(&squared, &result);
        p256_ct_fe_mul(&multiplied, &squared, value);
        p256_ct_fe_select(&result, &squared, &multiplied, exponent_bit);
    }
    *out = result;
    rintls_secure_zero(&result, sizeof(result));
    rintls_secure_zero(&squared, sizeof(squared));
    rintls_secure_zero(&multiplied, sizeof(multiplied));
}

static void p256_ct_point_select(p256_ct_point* out,
                                 const p256_ct_point* left,
                                 const p256_ct_point* right,
                                 u32 choose_right)
{
    p256_ct_fe_select(&out->x, &left->x, &right->x, choose_right);
    p256_ct_fe_select(&out->y, &left->y, &right->y, choose_right);
    p256_ct_fe_select(&out->z, &left->z, &right->z, choose_right);
}

static void p256_ct_point_swap(p256_ct_point* left,
                               p256_ct_point* right,
                               u32 swap)
{
    u32 mask = 0u - (swap & 1u);
    u32 i;
    for (i = 0; i < 8u; ++i) {
        u32 value = (left->x.limb[i] ^ right->x.limb[i]) & mask;
        left->x.limb[i] ^= value;
        right->x.limb[i] ^= value;
        value = (left->y.limb[i] ^ right->y.limb[i]) & mask;
        left->y.limb[i] ^= value;
        right->y.limb[i] ^= value;
        value = (left->z.limb[i] ^ right->z.limb[i]) & mask;
        left->z.limb[i] ^= value;
        right->z.limb[i] ^= value;
    }
}

static void p256_ct_point_double(p256_ct_point* out,
                                 const p256_ct_point* point)
{
    p256_ct_fe t[14];
    p256_ct_point result;

    p256_ct_fe_square(&t[0], &point->z);             /* delta */
    p256_ct_fe_square(&t[1], &point->y);             /* gamma */
    p256_ct_fe_mul(&t[2], &point->x, &t[1]);         /* beta */
    p256_ct_fe_sub(&t[3], &point->x, &t[0]);
    p256_ct_fe_add(&t[4], &point->x, &t[0]);
    p256_ct_fe_mul(&t[5], &t[3], &t[4]);
    p256_ct_fe_add(&t[6], &t[5], &t[5]);
    p256_ct_fe_add(&t[7], &t[6], &t[5]);             /* alpha = 3*... */
    p256_ct_fe_square(&t[8], &t[7]);
    p256_ct_fe_add(&t[9], &t[2], &t[2]);
    p256_ct_fe_add(&t[9], &t[9], &t[9]);
    p256_ct_fe_add(&t[9], &t[9], &t[9]);             /* 8*beta */
    p256_ct_fe_sub(&result.x, &t[8], &t[9]);
    p256_ct_fe_add(&t[10], &t[2], &t[2]);
    p256_ct_fe_add(&t[10], &t[10], &t[10]);          /* 4*beta */
    p256_ct_fe_sub(&t[11], &t[10], &result.x);
    p256_ct_fe_mul(&t[12], &t[7], &t[11]);
    p256_ct_fe_square(&t[13], &t[1]);
    p256_ct_fe_add(&t[10], &t[13], &t[13]);
    p256_ct_fe_add(&t[10], &t[10], &t[10]);
    p256_ct_fe_add(&t[10], &t[10], &t[10]);          /* 8*gamma^2 */
    p256_ct_fe_sub(&result.y, &t[12], &t[10]);
    p256_ct_fe_add(&t[11], &point->y, &point->z);
    p256_ct_fe_square(&t[11], &t[11]);
    p256_ct_fe_sub(&t[11], &t[11], &t[1]);
    p256_ct_fe_sub(&result.z, &t[11], &t[0]);

    *out = result;
    rintls_secure_zero(t, sizeof(t));
    rintls_secure_zero(&result, sizeof(result));
}

static void p256_ct_point_add(p256_ct_point* out,
                              const p256_ct_point* left,
                              const p256_ct_point* right)
{
    p256_ct_fe t[16];
    p256_ct_point result;
    u32 left_is_infinity;
    u32 right_is_infinity;

    p256_ct_fe_square(&t[0], &left->z);                /* z1z1 */
    p256_ct_fe_square(&t[1], &right->z);               /* z2z2 */
    p256_ct_fe_mul(&t[2], &left->x, &t[1]);             /* u1 */
    p256_ct_fe_mul(&t[3], &right->x, &t[0]);            /* u2 */
    p256_ct_fe_mul(&t[4], &right->z, &t[1]);
    p256_ct_fe_mul(&t[4], &left->y, &t[4]);             /* s1 */
    p256_ct_fe_mul(&t[5], &left->z, &t[0]);
    p256_ct_fe_mul(&t[5], &right->y, &t[5]);            /* s2 */
    p256_ct_fe_sub(&t[6], &t[3], &t[2]);                 /* h */
    p256_ct_fe_add(&t[7], &t[6], &t[6]);
    p256_ct_fe_square(&t[8], &t[7]);                     /* i */
    p256_ct_fe_mul(&t[9], &t[6], &t[8]);                 /* j */
    p256_ct_fe_sub(&t[10], &t[5], &t[4]);
    p256_ct_fe_add(&t[10], &t[10], &t[10]);              /* r */
    p256_ct_fe_mul(&t[11], &t[2], &t[8]);                /* v */
    p256_ct_fe_square(&t[12], &t[10]);
    p256_ct_fe_sub(&t[12], &t[12], &t[9]);
    p256_ct_fe_add(&t[13], &t[11], &t[11]);
    p256_ct_fe_sub(&result.x, &t[12], &t[13]);
    p256_ct_fe_sub(&t[14], &t[11], &result.x);
    p256_ct_fe_mul(&t[14], &t[10], &t[14]);
    p256_ct_fe_mul(&t[15], &t[4], &t[9]);
    p256_ct_fe_add(&t[15], &t[15], &t[15]);
    p256_ct_fe_sub(&result.y, &t[14], &t[15]);
    p256_ct_fe_add(&t[14], &left->z, &right->z);
    p256_ct_fe_square(&t[14], &t[14]);
    p256_ct_fe_sub(&t[14], &t[14], &t[0]);
    p256_ct_fe_sub(&t[14], &t[14], &t[1]);
    p256_ct_fe_mul(&result.z, &t[14], &t[6]);

    /*
     * The ladder inputs are consecutive multiples of a validated non-infinity
     * P-256 point, so they are never equal or inverse. Its initial infinity
     * operand is handled with fixed-time coordinate selection.
     */
    left_is_infinity = p256_ct_fe_is_zero(&left->z);
    right_is_infinity = p256_ct_fe_is_zero(&right->z);
    p256_ct_point_select(&result, &result, right, left_is_infinity);
    p256_ct_point_select(&result, &result, left, right_is_infinity);
    *out = result;

    rintls_secure_zero(t, sizeof(t));
    rintls_secure_zero(&result, sizeof(result));
}

static void p256_ct_scalar_mult(bignum_t* out_x,
                                bignum_t* out_y,
                                int* out_infinity,
                                const bignum_t* scalar,
                                const bignum_t* input_x,
                                const bignum_t* input_y,
                                int input_infinity)
{
    p256_ct_point r0, r1, sum, doubled;
    p256_ct_fe z_inverse, z_inverse_squared, z_inverse_cubed;
    p256_ct_fe affine_x, affine_y;
    u32 bit;
    u32 limb;

    p256_ct_fe_zero(&r0.x);
    p256_ct_fe_one(&r0.y);
    p256_ct_fe_zero(&r0.z);

    p256_ct_fe_zero(&r1.x);
    p256_ct_fe_zero(&r1.y);
    p256_ct_fe_zero(&r1.z);
    if (input_infinity) {
        p256_ct_fe_one(&r1.y);
    } else {
        for (limb = 0; limb < 8u; ++limb) {
            r1.x.limb[limb] = input_x->limbs[limb];
            r1.y.limb[limb] = input_y->limbs[limb];
        }
        p256_ct_fe_one(&r1.z);
    }

    for (bit = 256u; bit != 0u; --bit) {
        u32 position = bit - 1u;
        u32 scalar_bit =
            (scalar->limbs[position >> 5] >> (position & 31u)) & 1u;
        p256_ct_point_swap(&r0, &r1, scalar_bit);
        p256_ct_point_add(&sum, &r0, &r1);
        p256_ct_point_double(&doubled, &r0);
        r0 = doubled;
        r1 = sum;
        p256_ct_point_swap(&r0, &r1, scalar_bit);
    }

    p256_ct_fe_inverse(&z_inverse, &r0.z);
    p256_ct_fe_square(&z_inverse_squared, &z_inverse);
    p256_ct_fe_mul(&z_inverse_cubed, &z_inverse_squared, &z_inverse);
    p256_ct_fe_mul(&affine_x, &r0.x, &z_inverse_squared);
    p256_ct_fe_mul(&affine_y, &r0.y, &z_inverse_cubed);

    bn_init(out_x);
    bn_init(out_y);
    for (limb = 0; limb < 8u; ++limb) {
        out_x->limbs[limb] = affine_x.limb[limb];
        out_y->limbs[limb] = affine_y.limb[limb];
    }
    out_x->used = 8u;
    out_y->used = 8u;
    out_x->sign = 0;
    out_y->sign = 0;
    *out_infinity = (int)p256_ct_fe_is_zero(&r0.z);

    rintls_secure_zero(&r0, sizeof(r0));
    rintls_secure_zero(&r1, sizeof(r1));
    rintls_secure_zero(&sum, sizeof(sum));
    rintls_secure_zero(&doubled, sizeof(doubled));
    rintls_secure_zero(&z_inverse, sizeof(z_inverse));
    rintls_secure_zero(&z_inverse_squared, sizeof(z_inverse_squared));
    rintls_secure_zero(&z_inverse_cubed, sizeof(z_inverse_cubed));
    rintls_secure_zero(&affine_x, sizeof(affine_x));
    rintls_secure_zero(&affine_y, sizeof(affine_y));
}

#endif /* RINTLS_P256_CT_H */
