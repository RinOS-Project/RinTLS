/*
 * rinTLS - X.509証明書パーサー
 * RFC 5280準拠
 */

#ifndef RINTLS_X509_CERT_H
#define RINTLS_X509_CERT_H

#include "../platform/rin_platform.h"
#include "../crypto/rsa.h"
#include "../crypto/ecdh.h"

/* ═══════════════════════════════════════
 * 定数定義
 * ═══════════════════════════════════════ */

/* 最大サイズ */
#define X509_MAX_CN_SIZE        256
#define X509_MAX_SAN_SIZE       256
#define X509_MAX_CHAIN_DEPTH    10

/* エラーコード */
#define X509_OK                 0
#define X509_ERR_PARSE          -1
#define X509_ERR_UNSUPPORTED    -2
#define X509_ERR_EXPIRED        -3
#define X509_ERR_SIGNATURE      -4
#define X509_ERR_CA             -5
#define X509_ERR_NAME           -6
#define X509_ERR_CHAIN          -7

/* 公開鍵タイプ */
#define X509_KEY_RSA            1
#define X509_KEY_ECDSA          2

/* 署名アルゴリズム */
#define X509_SIG_RSA_SHA256     1
#define X509_SIG_RSA_SHA384     2
#define X509_SIG_RSA_SHA512     3
#define X509_SIG_ECDSA_SHA256   4
#define X509_SIG_ECDSA_SHA384   5

/* ═══════════════════════════════════════
 * ASN.1 タグ
 * ═══════════════════════════════════════ */

#define ASN1_BOOLEAN            0x01
#define ASN1_INTEGER            0x02
#define ASN1_BIT_STRING         0x03
#define ASN1_OCTET_STRING       0x04
#define ASN1_NULL               0x05
#define ASN1_OID                0x06
#define ASN1_UTF8_STRING        0x0C
#define ASN1_PRINTABLE_STRING   0x13
#define ASN1_IA5_STRING         0x16
#define ASN1_UTC_TIME           0x17
#define ASN1_GENERALIZED_TIME   0x18
#define ASN1_SEQUENCE           0x30
#define ASN1_SET                0x31
#define ASN1_CONTEXT_0          0xA0
#define ASN1_CONTEXT_3          0xA3

/* ═══════════════════════════════════════
 * X.509証明書構造
 * ═══════════════════════════════════════ */

/* 有効期間 */
typedef struct {
    int year;
    int month;
    int day;
    int hour;
    int minute;
    int second;
} x509_time_t;

/* X.509証明書 */
typedef struct {
    /* Version */
    int version;

    /* Serial Number */
    u8 serial[32];
    rin_size_t serial_len;

    /* 署名アルゴリズム */
    int sig_alg;

    /* 発行者 (Issuer) */
    char issuer_cn[X509_MAX_CN_SIZE];

    /* サブジェクト (Subject) */
    char subject_cn[X509_MAX_CN_SIZE];

    /* 有効期間 */
    x509_time_t not_before;
    x509_time_t not_after;

    /* Subject Alternative Name (SAN) */
    char san[X509_MAX_SAN_SIZE];

    /* 公開鍵 */
    int key_type;
    union {
        rsa_pubkey_t rsa;
        struct {
            u8 point[65];
            rin_size_t point_len;
        } ecdsa;
    } pubkey;

    /* CA証明書フラグ */
    int is_ca;
    int path_len_constraint;

    /* TBSCertificate (署名対象) の位置 */
    const u8* tbs_data;
    rin_size_t tbs_len;

    /* 署名 */
    u8 signature[512];
    rin_size_t signature_len;

    /* 生データ参照 */
    const u8* raw_data;
    rin_size_t raw_len;
} x509_cert_t;

/* ═══════════════════════════════════════
 * 証明書パース
 * ═══════════════════════════════════════ */

/* DER形式の証明書をパース */
int x509_parse_cert(x509_cert_t* cert, const u8* der, rin_size_t len);

/* 証明書をクリア */
void x509_cert_clear(x509_cert_t* cert);

/* ═══════════════════════════════════════
 * 証明書検証
 * ═══════════════════════════════════════ */

/* 証明書の署名を検証 (issuerの公開鍵で) */
int x509_verify_signature(const x509_cert_t* cert, const x509_cert_t* issuer);

/* 自己署名証明書かチェック */
int x509_is_self_signed(const x509_cert_t* cert);

/* 有効期間をチェック */
int x509_check_validity(const x509_cert_t* cert);

/* ホスト名をチェック (CNまたはSAN) */
int x509_check_hostname(const x509_cert_t* cert, const char* hostname);

/* ═══════════════════════════════════════
 * 証明書チェーン検証
 * ═══════════════════════════════════════ */

/*
 * 証明書チェーンを検証
 * certs: 証明書配列 (リーフ証明書が最初)
 * cert_count: 証明書数
 * hostname: 検証するホスト名 (リーフ証明書用)
 *
 * 戻り値: X509_OK なら成功
 */
int x509_verify_chain(x509_cert_t* certs, int cert_count, const char* hostname);

/* ═══════════════════════════════════════
 * ルートCA
 * ═══════════════════════════════════════ */

/* 組み込みルートCAで証明書を検証 */
int x509_verify_with_root_ca(const x509_cert_t* cert);

/* ═══════════════════════════════════════
 * ユーティリティ
 * ═══════════════════════════════════════ */

/* ASN.1タグと長さを読み取り */
int asn1_read_tag(const u8** p, const u8* end, u8* tag, rin_size_t* len);

/* ASN.1 INTEGERを読み取り */
int asn1_read_integer(const u8** p, const u8* end, u8* out, rin_size_t* out_len, rin_size_t max_len);

/* ASN.1 OIDを読み取り・比較 */
int asn1_read_oid(const u8** p, const u8* end, const u8* expected_oid, rin_size_t oid_len);

/* ASN.1 時刻を読み取り */
int asn1_read_time(const u8** p, const u8* end, x509_time_t* time);

/* 時刻を比較 (-1: a < b, 0: a == b, 1: a > b) */
int x509_time_cmp(const x509_time_t* a, const x509_time_t* b);

/* 現在時刻を取得 */
void x509_get_current_time(x509_time_t* time);

#endif /* RINTLS_X509_CERT_H */
