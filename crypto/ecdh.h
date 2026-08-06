/*
 * rinTLS - ECDH (Elliptic Curve Diffie-Hellman)
 * P-256 (secp256r1) および X25519 対応
 */

#ifndef RINTLS_ECDH_H
#define RINTLS_ECDH_H

#include "../platform/rin_platform.h"

/* ═══════════════════════════════════════
 * 定数定義
 * ═══════════════════════════════════════ */

/* P-256 (secp256r1) */
#define P256_KEY_SIZE       32      /* 256ビット = 32バイト */
#define P256_POINT_SIZE     65      /* 非圧縮: 0x04 + x(32) + y(32) */
#define P256_POINT_COMPRESSED_SIZE  33  /* 圧縮: 0x02/0x03 + x(32) */

/* X25519 */
#define X25519_KEY_SIZE     32      /* 256ビット = 32バイト */
#define X25519_POINT_SIZE   32      /* Montgomeryスカラー */

/* エラーコード */
#define ECDH_OK             0
#define ECDH_ERR_INVALID    -1
#define ECDH_ERR_KEY        -2
#define ECDH_ERR_POINT      -3
#define ECDH_ERR_VERIFY     -4

/* ═══════════════════════════════════════
 * P-256 (secp256r1) ECDH
 * ═══════════════════════════════════════ */

/*
 * P-256パラメータ (NIST)
 * y^2 = x^3 - 3x + b (mod p)
 *
 * p = 2^256 - 2^224 + 2^192 + 2^96 - 1
 */

/* P-256鍵ペア */
typedef struct {
    u8 private_key[P256_KEY_SIZE];
    u8 public_key[P256_POINT_SIZE];  /* 非圧縮形式 */
} p256_keypair_t;

/* P-256鍵ペアを生成 */
int p256_keygen(p256_keypair_t* keypair);

/* P-256秘密鍵から公開鍵を計算 */
int p256_compute_public(u8* public_key, const u8* private_key);

/*
 * P-256 ECDH共有秘密を計算
 * shared_secret: 出力 (32バイト)
 * private_key: 自分の秘密鍵 (32バイト)
 * peer_public: 相手の公開鍵 (65バイト、非圧縮)
 */
int p256_ecdh(u8* shared_secret,
              const u8* private_key,
              const u8* peer_public, rin_size_t peer_public_len);

/* P-256公開鍵の検証 */
int p256_validate_public(const u8* public_key, rin_size_t len);

/* ═══════════════════════════════════════
 * ECDSA P-256 署名検証
 * ═══════════════════════════════════════ */

/*
 * ECDSA署名を検証 (P-256, SHA-256)
 * signature: 署名 (r || s, 各32バイト = 64バイト)
 * hash: メッセージハッシュ (32バイト)
 * public_key: 公開鍵 (65バイト、非圧縮)
 */
int ecdsa_p256_verify(const u8* signature, rin_size_t sig_len,
                      const u8* hash, rin_size_t hash_len,
                      const u8* public_key, rin_size_t pubkey_len);

/* DER形式のECDSA署名をパース (r, sを抽出) */
int ecdsa_sig_from_der(u8* r, u8* s, const u8* der, rin_size_t der_len);

/* ═══════════════════════════════════════
 * X25519 (Curve25519) ECDH
 * TLS 1.3で推奨
 * ═══════════════════════════════════════ */

/*
 * Curve25519パラメータ
 * Montgomery曲線: y^2 = x^3 + 486662x^2 + x (mod p)
 * p = 2^255 - 19
 */

/* X25519鍵ペア */
typedef struct {
    u8 private_key[X25519_KEY_SIZE];
    u8 public_key[X25519_KEY_SIZE];
} x25519_keypair_t;

/* X25519鍵ペアを生成 */
int x25519_keygen(x25519_keypair_t* keypair);

/* X25519秘密鍵から公開鍵を計算 */
int x25519_compute_public(u8* public_key, const u8* private_key);

/*
 * X25519 ECDH共有秘密を計算
 * shared_secret: 出力 (32バイト)
 * private_key: 自分の秘密鍵 (32バイト)
 * peer_public: 相手の公開鍵 (32バイト)
 */
int x25519_ecdh(u8* shared_secret,
                const u8* private_key,
                const u8* peer_public);

/*
 * X25519スカラー乗算
 * out = scalar * point
 */
int x25519_scalarmult(u8* out, const u8* scalar, const u8* point);

/* X25519ベースポイント */
extern const u8 X25519_BASEPOINT[32];

/* X25519自己テスト (RFC 7748テストベクター使用) */
int x25519_selftest(void);

/* ═══════════════════════════════════════
 * Ed25519 署名検証 (オプション)
 * ═══════════════════════════════════════ */

#ifdef RINTLS_ENABLE_ED25519

#define ED25519_SIG_SIZE    64
#define ED25519_PUBKEY_SIZE 32

/* Ed25519署名を検証 */
int ed25519_verify(const u8* signature,
                   const u8* message, rin_size_t message_len,
                   const u8* public_key);

#endif /* RINTLS_ENABLE_ED25519 */

#endif /* RINTLS_ECDH_H */
