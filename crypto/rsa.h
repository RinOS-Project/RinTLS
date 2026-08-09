/*
 * rinTLS - RSA暗号化・署名検証
 * PKCS#1 v1.5 および RSA-OAEP対応
 */

#ifndef RINTLS_RSA_H
#define RINTLS_RSA_H

#include "../platform/rin_platform.h"
#include "bignum.h"
#include "sha256.h"

/* ═══════════════════════════════════════
 * 定数定義
 * ═══════════════════════════════════════ */

/* 最大鍵サイズ (バイト単位) */
#define RSA_MAX_KEY_SIZE    512     /* 4096ビット */

/* エラーコード */
#define RSA_OK              0
#define RSA_ERR_INVALID     -1
#define RSA_ERR_VERIFY      -2
#define RSA_ERR_PADDING     -3
#define RSA_ERR_KEY         -4
#define RSA_ERR_SIZE        -5

/* ═══════════════════════════════════════
 * RSA公開鍵
 * ═══════════════════════════════════════ */

typedef struct {
    bignum_t n;         /* モジュラス */
    bignum_t e;         /* 公開指数 */
    rin_size_t bits;    /* 鍵サイズ (ビット) */
} rsa_pubkey_t;

/* ═══════════════════════════════════════
 * RSA秘密鍵 (署名生成用 - TLSクライアントでは通常不要)
 * ═══════════════════════════════════════ */

typedef struct {
    bignum_t n;         /* モジュラス */
    bignum_t e;         /* 公開指数 */
    bignum_t d;         /* 秘密指数 */
    bignum_t p;         /* 素因数p */
    bignum_t q;         /* 素因数q */
    bignum_t dp;        /* d mod (p-1) */
    bignum_t dq;        /* d mod (q-1) */
    bignum_t qinv;      /* q^(-1) mod p */
    rin_size_t bits;
} rsa_privkey_t;

/* ═══════════════════════════════════════
 * 公開鍵操作
 * ═══════════════════════════════════════ */

/* 公開鍵を初期化 */
void rsa_pubkey_init(rsa_pubkey_t* key);

/* 公開鍵をクリア */
void rsa_pubkey_clear(rsa_pubkey_t* key);

/* DERエンコードされたRSA公開鍵をパース */
int rsa_pubkey_from_der(rsa_pubkey_t* key, const u8* der, rin_size_t len);

/* モジュラスと公開指数から公開鍵を設定 */
int rsa_pubkey_set(rsa_pubkey_t* key,
                   const u8* n, rin_size_t n_len,
                   const u8* e, rin_size_t e_len);

/* ═══════════════════════════════════════
 * RSA基本演算
 * ═══════════════════════════════════════ */

/*
 * RSA公開鍵演算: result = message^e mod n
 * 署名検証や暗号化に使用
 */
int rsa_public(u8* result, rin_size_t* result_len,
               const u8* message, rin_size_t message_len,
               const rsa_pubkey_t* key);

/* ═══════════════════════════════════════
 * PKCS#1 v1.5 署名検証
 * ═══════════════════════════════════════ */

/*
 * PKCS#1 v1.5署名を検証
 * signature: 署名データ
 * sig_len: 署名長
 * hash: メッセージのハッシュ
 * hash_len: ハッシュ長 (SHA-256なら32)
 * hash_alg: ハッシュアルゴリズム識別子
 * key: RSA公開鍵
 *
 * 戻り値: RSA_OK なら検証成功
 */
#define RSA_HASH_SHA1       1
#define RSA_HASH_SHA256     2
#define RSA_HASH_SHA384     3
#define RSA_HASH_SHA512     4

int rsa_pkcs1_verify(const u8* signature, rin_size_t sig_len,
                     const u8* hash, rin_size_t hash_len,
                     int hash_alg,
                     const rsa_pubkey_t* key);

/* ═══════════════════════════════════════
 * RSA-PSS 署名検証 (TLS 1.3で使用)
 * ═══════════════════════════════════════ */

/*
 * RSA-PSS署名を検証 (SHA-256)
 * RFC 8017準拠
 */
int rsa_pss_verify_sha256(const u8* signature, rin_size_t sig_len,
                          const u8* message_hash,
                          const rsa_pubkey_t* key);

/* ═══════════════════════════════════════
 * RSA暗号化 (PKCS#1 v1.5)
 * ═══════════════════════════════════════ */

/*
 * PKCS#1 v1.5暗号化
 * TLS 1.2の鍵交換で使用
 */
int rsa_pkcs1_encrypt(u8* output, rin_size_t* output_len,
                      const u8* input, rin_size_t input_len,
                      const rsa_pubkey_t* key);

/* ═══════════════════════════════════════
 * DigestInfo構造 (PKCS#1 署名用)
 * ═══════════════════════════════════════ */

/* SHA-256のDigestInfo DERプレフィックス */
extern const u8 RSA_DIGESTINFO_SHA256[];
extern const rin_size_t RSA_DIGESTINFO_SHA256_LEN;

/* SHA-384のDigestInfo DERプレフィックス */
extern const u8 RSA_DIGESTINFO_SHA384[];
extern const rin_size_t RSA_DIGESTINFO_SHA384_LEN;

/* SHA-512のDigestInfo DERプレフィックス */
extern const u8 RSA_DIGESTINFO_SHA512[];
extern const rin_size_t RSA_DIGESTINFO_SHA512_LEN;

/* SHA-1のDigestInfo DERプレフィックス */
extern const u8 RSA_DIGESTINFO_SHA1[];
extern const rin_size_t RSA_DIGESTINFO_SHA1_LEN;

#endif /* RINTLS_RSA_H */
