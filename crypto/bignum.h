/*
 * rinTLS - Big Number (多倍長整数演算)
 * RSA/ECDHに必要な演算を提供
 */

#ifndef RINTLS_BIGNUM_H
#define RINTLS_BIGNUM_H

#include "../platform/rin_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════
 * 定数定義
 * ═══════════════════════════════════════ */

/* 最大4096ビットをサポート (RSA-4096) */
#define BIGNUM_MAX_BITS     4096
#define BIGNUM_MAX_LIMBS    (BIGNUM_MAX_BITS / 32)  /* 128 limbs */

/* エラーコード */
#define BIGNUM_OK           0
#define BIGNUM_ERR_OVERFLOW -1
#define BIGNUM_ERR_DIVZERO  -2
#define BIGNUM_ERR_NEGATIVE -3
#define BIGNUM_ERR_INVALID  -4

/* ═══════════════════════════════════════
 * データ構造
 * ═══════════════════════════════════════ */

/*
 * bignum_t - 多倍長整数
 * リトルエンディアン形式: limbs[0]が最下位
 */
typedef struct {
    u32 limbs[BIGNUM_MAX_LIMBS];
    rin_size_t used;    /* 使用中のlimb数 */
    int sign;           /* 0=正, 1=負 */
} bignum_t;

/* ═══════════════════════════════════════
 * 初期化・代入
 * ═══════════════════════════════════════ */

/* ゼロで初期化 */
void bn_init(bignum_t* n);

/* 32ビット値で初期化 */
void bn_set_u32(bignum_t* n, u32 val);

/* 64ビット値で初期化 */
void bn_set_u64(bignum_t* n, u64 val);

/* コピー */
void bn_copy(bignum_t* dest, const bignum_t* src);

/* バイト配列から設定 (ビッグエンディアン) */
int bn_from_bytes(bignum_t* n, const u8* data, rin_size_t len);

/* バイト配列へ出力 (ビッグエンディアン) */
int bn_to_bytes(const bignum_t* n, u8* data, rin_size_t len);

/* ═══════════════════════════════════════
 * 比較
 * ═══════════════════════════════════════ */

/* ゼロかどうか */
int bn_is_zero(const bignum_t* n);

/* 1かどうか */
int bn_is_one(const bignum_t* n);

/* 偶数かどうか */
int bn_is_even(const bignum_t* n);

/* 奇数かどうか */
int bn_is_odd(const bignum_t* n);

/* 比較: -1 (a<b), 0 (a==b), 1 (a>b) */
int bn_cmp(const bignum_t* a, const bignum_t* b);

/* 絶対値比較 */
int bn_cmp_abs(const bignum_t* a, const bignum_t* b);

/* u32との比較 */
int bn_cmp_u32(const bignum_t* a, u32 b);

/* ═══════════════════════════════════════
 * ビット操作
 * ═══════════════════════════════════════ */

/* ビット数を取得 */
rin_size_t bn_bitlen(const bignum_t* n);

/* 特定のビットを取得 */
int bn_get_bit(const bignum_t* n, rin_size_t pos);

/* 左シフト */
int bn_lshift(bignum_t* r, const bignum_t* a, rin_size_t bits);

/* 右シフト */
int bn_rshift(bignum_t* r, const bignum_t* a, rin_size_t bits);

/* ═══════════════════════════════════════
 * 基本演算
 * ═══════════════════════════════════════ */

/* 加算: r = a + b */
int bn_add(bignum_t* r, const bignum_t* a, const bignum_t* b);

/* 減算: r = a - b */
int bn_sub(bignum_t* r, const bignum_t* a, const bignum_t* b);

/* 乗算: r = a * b */
int bn_mul(bignum_t* r, const bignum_t* a, const bignum_t* b);

/* u32との乗算: r = a * b */
int bn_mul_u32(bignum_t* r, const bignum_t* a, u32 b);

/* 除算: q = a / b, r = a % b */
int bn_div(bignum_t* q, bignum_t* r, const bignum_t* a, const bignum_t* b);

/* 剰余: r = a % b */
int bn_mod(bignum_t* r, const bignum_t* a, const bignum_t* b);

/* ═══════════════════════════════════════
 * モジュラ演算 (RSA/ECDHに必須)
 * ═══════════════════════════════════════ */

/* モジュラ加算: r = (a + b) mod m */
int bn_mod_add(bignum_t* r, const bignum_t* a, const bignum_t* b, const bignum_t* m);

/* モジュラ減算: r = (a - b) mod m */
int bn_mod_sub(bignum_t* r, const bignum_t* a, const bignum_t* b, const bignum_t* m);

/* モジュラ乗算: r = (a * b) mod m */
int bn_mod_mul(bignum_t* r, const bignum_t* a, const bignum_t* b, const bignum_t* m);

/* モジュラ冪乗: r = (base^exp) mod m (RSA署名検証に使用) */
int bn_mod_exp(bignum_t* r, const bignum_t* base, const bignum_t* exp, const bignum_t* m);

/* モジュラ逆元: r = a^(-1) mod m */
int bn_mod_inv(bignum_t* r, const bignum_t* a, const bignum_t* m);

/* ═══════════════════════════════════════
 * GCD (最大公約数)
 * ═══════════════════════════════════════ */

/* GCD: r = gcd(a, b) */
int bn_gcd(bignum_t* r, const bignum_t* a, const bignum_t* b);

/* ═══════════════════════════════════════
 * Montgomery乗算 (高速化用)
 * ═══════════════════════════════════════ */

typedef struct {
    bignum_t n;         /* モジュラス */
    bignum_t r2;        /* R^2 mod n */
    u32 n_inv;          /* -n^(-1) mod 2^32 */
    rin_size_t n_bits;  /* nのビット数 */
} bn_mont_ctx;

/* Montgomeryコンテキスト初期化 */
int bn_mont_init(bn_mont_ctx* ctx, const bignum_t* n);

/* Montgomery乗算: r = (a * b * R^(-1)) mod n */
int bn_mont_mul(bignum_t* r, const bignum_t* a, const bignum_t* b, const bn_mont_ctx* ctx);

/* Montgomery冪乗: r = (base^exp) mod n */
int bn_mont_exp(bignum_t* r, const bignum_t* base, const bignum_t* exp, const bn_mont_ctx* ctx);

/* ═══════════════════════════════════════
 * ユーティリティ
 * ═══════════════════════════════════════ */

/* usedを正規化（先頭のゼロを除去） */
void bn_normalize(bignum_t* n);

/* ゼロにクリア（セキュア） */
void bn_clear(bignum_t* n);

#ifdef __cplusplus
}
#endif

#endif /* RINTLS_BIGNUM_H */
