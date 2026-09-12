/*
 * rinTLS - TLSハンドシェイク
 * RFC 5246 (TLS 1.2) および RFC 8446 (TLS 1.3) 準拠
 */

#ifndef RINTLS_HANDSHAKE_H
#define RINTLS_HANDSHAKE_H

#include "../platform/rin_platform.h"
#include "../crypto/sha256.h"
#include "../crypto/ecdh.h"
#include "../crypto/rsa.h"
#include "../x509/cert.h"
#include "record.h"

/* ═══════════════════════════════════════
 * ハンドシェイクメッセージタイプ
 * ═══════════════════════════════════════ */

#define TLS_HS_CLIENT_HELLO         1
#define TLS_HS_SERVER_HELLO         2
#define TLS_HS_NEW_SESSION_TICKET   4
#define TLS_HS_END_OF_EARLY_DATA    5
#define TLS_HS_ENCRYPTED_EXTENSIONS 8
#define TLS_HS_CERTIFICATE          11
#define TLS_HS_SERVER_KEY_EXCHANGE  12
#define TLS_HS_CERTIFICATE_REQUEST  13
#define TLS_HS_SERVER_HELLO_DONE    14
#define TLS_HS_CERTIFICATE_VERIFY   15
#define TLS_HS_CLIENT_KEY_EXCHANGE  16
#define TLS_HS_FINISHED             20
#define TLS_HS_KEY_UPDATE           24
#define TLS_HS_MESSAGE_HASH         254

/* ═══════════════════════════════════════
 * 暗号スイート
 * ═══════════════════════════════════════ */

/* TLS 1.2 */
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   0xC02F
#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   0xC030
#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 0xC02B
#define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 0xC02C

/* TLS 1.3 */
#define TLS13_AES_128_GCM_SHA256        0x1301
#define TLS13_AES_256_GCM_SHA384        0x1302
#define TLS13_CHACHA20_POLY1305_SHA256  0x1303

/* ═══════════════════════════════════════
 * 拡張タイプ
 * ═══════════════════════════════════════ */

#define TLS_EXT_SERVER_NAME             0
#define TLS_EXT_MAX_FRAGMENT_LENGTH     1
#define TLS_EXT_STATUS_REQUEST          5
#define TLS_EXT_SUPPORTED_GROUPS        10
#define TLS_EXT_EC_POINT_FORMATS        11
#define TLS_EXT_SIGNATURE_ALGORITHMS    13
#define TLS_EXT_ALPN                    16
#define TLS_EXT_SCT                     18
#define TLS_EXT_ENCRYPT_THEN_MAC        22
#define TLS_EXT_EXTENDED_MASTER_SECRET  23
#define TLS_EXT_SESSION_TICKET          35
#define TLS_EXT_PRE_SHARED_KEY          41
#define TLS_EXT_EARLY_DATA              42
#define TLS_EXT_SUPPORTED_VERSIONS      43
#define TLS_EXT_COOKIE                  44
#define TLS_EXT_PSK_KEY_EXCHANGE_MODES  45
#define TLS_EXT_CERTIFICATE_AUTHORITIES 47
#define TLS_EXT_OID_FILTERS             48
#define TLS_EXT_POST_HANDSHAKE_AUTH     49
#define TLS_EXT_SIGNATURE_ALGORITHMS_CERT   50
#define TLS_EXT_KEY_SHARE               51
#define TLS_EXT_RENEGOTIATION_INFO      0xFF01

/* ═══════════════════════════════════════
 * Named Groups (楕円曲線)
 * ═══════════════════════════════════════ */

#define TLS_GROUP_SECP256R1     23
#define TLS_GROUP_SECP384R1     24
#define TLS_GROUP_SECP521R1     25
#define TLS_GROUP_X25519        29
#define TLS_GROUP_X448          30

/* ═══════════════════════════════════════
 * 署名アルゴリズム
 * ═══════════════════════════════════════ */

#define TLS_SIG_RSA_PKCS1_SHA256        0x0401
#define TLS_SIG_RSA_PKCS1_SHA384        0x0501
#define TLS_SIG_RSA_PKCS1_SHA512        0x0601
#define TLS_SIG_ECDSA_SECP256R1_SHA256  0x0403
#define TLS_SIG_ECDSA_SECP384R1_SHA384  0x0503
#define TLS_SIG_ECDSA_SECP521R1_SHA512  0x0603
#define TLS_SIG_RSA_PSS_RSAE_SHA256     0x0804
#define TLS_SIG_RSA_PSS_RSAE_SHA384     0x0805
#define TLS_SIG_RSA_PSS_RSAE_SHA512     0x0806

/* ═══════════════════════════════════════
 * ハンドシェイク状態
 * ═══════════════════════════════════════ */

typedef enum {
    TLS_STATE_INIT,
    TLS_STATE_CLIENT_HELLO_SENT,
    TLS_STATE_SERVER_HELLO_RECEIVED,
    TLS_STATE_ENCRYPTED_EXTENSIONS,     /* TLS 1.3 */
    TLS_STATE_CERTIFICATE_RECEIVED,
    TLS_STATE_CERTIFICATE_VERIFY,       /* TLS 1.3 */
    TLS_STATE_CLIENT_CERTIFICATE,       /* TLS 1.3 mutual authentication */
    TLS_STATE_CLIENT_CERTIFICATE_VERIFY,
    TLS_STATE_SERVER_KEY_EXCHANGE,      /* TLS 1.2 */
    TLS_STATE_SERVER_HELLO_DONE,        /* TLS 1.2 */
    TLS_STATE_CLIENT_KEY_EXCHANGE_SENT, /* TLS 1.2 */
    TLS_STATE_CHANGE_CIPHER_SPEC,       /* TLS 1.2 */
    TLS_STATE_FINISHED_SENT,
    TLS_STATE_FINISHED_RECEIVED,
    TLS_STATE_CONNECTED,
    TLS_STATE_CLOSED,
    TLS_STATE_ERROR
} tls_state_t;

/* ═══════════════════════════════════════
 * ハンドシェイクコンテキスト
 * ═══════════════════════════════════════ */

#define TLS_MAX_PENDING_HANDSHAKE_SEND  16384
#define TLS_MAX_PENDING_HANDSHAKE_RECV  16384
#define TLS_MAX_NEGOTIATED_ALPN        32u
#define TLS_MAX_CLIENT_CERTIFICATE_CHAIN (16u * 1024u)
#define TLS_MAX_CLIENT_SIGNATURE_BYTES 512u
#define TLS_MAX_CLIENT_CERTIFICATE_BYTES (16u * 1024u)

typedef int (*tls_trust_anchor_verify_func)(void* opaque,
                                            const x509_cert_t* chain_top);

typedef int (*tls_client_certificate_sign_func)(
    void* opaque, u16 signature_scheme, const u8* message,
    rin_size_t message_len, u8* signature, rin_size_t signature_capacity,
    rin_size_t* signature_len);

typedef struct {
    /* 状態 */
    tls_state_t state;
    int is_tls13;

    /* RINTLS_OPT_VERIFY_NONE: 証明書チェーン/署名検証をスキップ */
    int verify_none;

    /* The TLS parser verifies links inside the peer-provided chain.  This
     * callback must additionally terminate that chain at a locally trusted
     * anchor.  A missing callback is a verification failure. */
    tls_trust_anchor_verify_func trust_anchor_verify;
    void* trust_anchor_opaque;

    /* Nonzero only when the caller supplied authenticated wall-clock state
     * before the first handshake step. */
    u64 trusted_unix_time;

    /* ネゴシエートされた値 */
    u16 version;
    u16 cipher_suite;
    u16 named_group;
    u8 negotiated_alpn[TLS_MAX_NEGOTIATED_ALPN];
    u8 negotiated_alpn_len;

    /* ランダム値 */
    u8 client_random[32];
    u8 server_random[32];
    int entropy_ready;

    /* 鍵交換 */
    x25519_keypair_t x25519_keypair;
    p256_keypair_t p256_keypair;
    u8 peer_public_key[65];
    rin_size_t peer_public_key_len;

    /* 共有秘密 */
    u8 shared_secret[48];   /* 最大サイズ */
    rin_size_t shared_secret_len;

    /* ハンドシェイクハッシュ (Transcript Hash) */
    sha256_ctx transcript_hash;
    sha384_ctx transcript_hash_384;  /* TLS 1.3 SHA-384 */
    int use_sha384;

    /* TLS 1.3: server Finishedまでのトランスクリプトハッシュ
     * (アプリケーション鍵導出に使用 - client Finishedを含まない) */
    u8 server_finished_transcript[32];

    /* 鍵マテリアル */
    u8 master_secret[48];           /* TLS 1.2 */
    u8 handshake_secret[48];        /* TLS 1.3 */
    u8 client_handshake_traffic_secret[48];
    u8 server_handshake_traffic_secret[48];
    u8 client_application_traffic_secret[48];
    u8 server_application_traffic_secret[48];

    /* 証明書 */
    u8* server_cert;
    rin_size_t server_cert_len;
    rsa_pubkey_t server_rsa_key;
    u8 server_ecdsa_key[ECDSA_MAX_POINT_SIZE];
    rin_size_t server_ecdsa_key_len;
    int server_ecdsa_curve;
    int server_key_type;    /* 0=RSA, 1=ECDSA */

    /* Mutual-TLS client identity.  certificate_list is the bounded TLS 1.3
     * wire certificate_list (3-byte total length + CertificateEntry records
     * with DER and extensions lengths); the private key remains behind the
     * signer callback. */
    u8* client_certificate_list;
    rin_size_t client_certificate_list_len;
    tls_client_certificate_sign_func client_certificate_sign;
    void* client_certificate_sign_opaque;
    int client_certificate_requested;
    int client_certificate_sent;
    u16 client_signature_scheme;

    /* SNI */
    char server_name[256];

    /* レコード層 */
    tls_record_ctx_t* record;

    /* 送信途中のハンドシェイクメッセージ */
    u8 pending_send_kind;
    u8 pending_send_use_tls_record;
    u8 pending_send_content_type;
    u16 pending_send_version;
    u8 pending_send_update_transcript;
    u8 pending_send_next_state;
    u8 pending_send_msg[TLS_MAX_PENDING_HANDSHAKE_SEND];
    rin_size_t pending_send_msg_len;

    /* 受信途中のハンドシェイクメッセージ。TLS record境界で分割された
     * header／payloadを、bounded ownerへ再構成してから各stateへ渡す。 */
    u8 pending_recv_msg[TLS_MAX_PENDING_HANDSHAKE_RECV];
    rin_size_t pending_recv_msg_len;

    /* エラー情報 */
    int last_error;
    u8 alert_level;
    u8 alert_desc;
} tls_handshake_ctx_t;

/* ═══════════════════════════════════════
 * 初期化・終了
 * ═══════════════════════════════════════ */

/* ハンドシェイクコンテキストを初期化 */
void tls_handshake_init(tls_handshake_ctx_t* ctx, tls_record_ctx_t* record);

/* ハンドシェイクコンテキストをクリア */
void tls_handshake_clear(tls_handshake_ctx_t* ctx);

/* サーバー名を設定 (SNI) */
void tls_handshake_set_server_name(tls_handshake_ctx_t* ctx, const char* name);

void tls_handshake_set_trust_anchor_verifier(tls_handshake_ctx_t* ctx,
                                             tls_trust_anchor_verify_func verify,
                                             void* opaque);

void tls_handshake_set_trusted_time(tls_handshake_ctx_t* ctx,
                                    u64 trusted_unix_time);

int tls_handshake_set_client_certificate(
    tls_handshake_ctx_t* ctx, const void* certificate_list,
    rin_size_t certificate_list_len,
    tls_client_certificate_sign_func signer, void* signer_opaque);

int tls_handshake_client_certificate_requested(const tls_handshake_ctx_t* ctx);

/* ═══════════════════════════════════════
 * ハンドシェイク実行
 * ═══════════════════════════════════════ */

/*
 * TLSハンドシェイクを実行
 * クライアントモードのみ
 *
 * 戻り値: 成功時 TLS_ERR_OK、エラー時 < 0
 */
int tls_handshake_client(tls_handshake_ctx_t* ctx);

/* ═══════════════════════════════════════
 * 個別メッセージ処理 (内部用)
 * ═══════════════════════════════════════ */

/* ClientHelloを送信 */
int tls_send_client_hello(tls_handshake_ctx_t* ctx);

/* ServerHelloを受信・処理 */
int tls_recv_server_hello(tls_handshake_ctx_t* ctx);

/* Certificateを受信・処理 */
int tls_recv_certificate(tls_handshake_ctx_t* ctx);

/* Parse an optional CertificateRequest and emit the client Certificate and
 * CertificateVerify messages when a configured signer is available. */
int tls_recv_certificate_request(tls_handshake_ctx_t* ctx,
                                 const u8* msg, rin_size_t len);
int tls_send_client_certificate(tls_handshake_ctx_t* ctx);
int tls_send_client_certificate_verify(tls_handshake_ctx_t* ctx);

/* CertificateVerifyを受信・処理 (TLS 1.3) */
int tls_recv_certificate_verify(tls_handshake_ctx_t* ctx);

/* ServerKeyExchangeを受信・処理 (TLS 1.2) */
int tls_recv_server_key_exchange(tls_handshake_ctx_t* ctx);

/* ServerHelloDoneを受信 (TLS 1.2) */
int tls_recv_server_hello_done(tls_handshake_ctx_t* ctx);

/* ClientKeyExchangeを送信 (TLS 1.2) */
int tls_send_client_key_exchange(tls_handshake_ctx_t* ctx);

/* ChangeCipherSpecを送信 (TLS 1.2) */
int tls_send_change_cipher_spec(tls_handshake_ctx_t* ctx);

/* ChangeCipherSpecを受信 (TLS 1.2) */
int tls_recv_change_cipher_spec(tls_handshake_ctx_t* ctx);

/* Finishedを送信 */
int tls_send_finished(tls_handshake_ctx_t* ctx);

/* Finishedを受信・検証 */
int tls_recv_finished(tls_handshake_ctx_t* ctx);

/* EncryptedExtensionsを受信 (TLS 1.3) */
int tls_recv_encrypted_extensions(tls_handshake_ctx_t* ctx);

/* ═══════════════════════════════════════
 * 鍵導出
 * ═══════════════════════════════════════ */

/* TLS 1.2 マスターシークレットを導出 */
int tls12_derive_master_secret(tls_handshake_ctx_t* ctx);

/* TLS 1.2 鍵を導出・設定 */
int tls12_derive_keys(tls_handshake_ctx_t* ctx);

/* TLS 1.3 ハンドシェイク鍵を導出 */
int tls13_derive_handshake_keys(tls_handshake_ctx_t* ctx);

/* TLS 1.3 アプリケーション鍵を導出 */
int tls13_derive_application_keys(tls_handshake_ctx_t* ctx);

/* ═══════════════════════════════════════
 * ユーティリティ
 * ═══════════════════════════════════════ */

/* ハンドシェイクメッセージをTranscriptに追加 */
void tls_transcript_update(tls_handshake_ctx_t* ctx, const u8* data, rin_size_t len);

/* Transcript Hashを取得 */
void tls_transcript_hash(tls_handshake_ctx_t* ctx, u8* hash);

/* Verify Dataを計算 */
int tls_compute_verify_data(tls_handshake_ctx_t* ctx, int is_client, u8* verify_data);

/* ═══════════════════════════════════════
 * エラーコード
 * ═══════════════════════════════════════ */

#define TLS_HS_ERR_OK               0
#define TLS_HS_ERR_IO               -1
#define TLS_HS_ERR_UNEXPECTED       -2
#define TLS_HS_ERR_VERSION          -3
#define TLS_HS_ERR_CIPHER           -4
#define TLS_HS_ERR_CERTIFICATE      -5
#define TLS_HS_ERR_SIGNATURE        -6
#define TLS_HS_ERR_KEY_EXCHANGE     -7
#define TLS_HS_ERR_VERIFY           -8
#define TLS_HS_ERR_ALERT            -9
#define TLS_HS_ERR_WANT_READ        -10
#define TLS_HS_ERR_WANT_WRITE       -11
#define TLS_HS_ERR_RANDOM            -12
#define TLS_HS_ERR_HOSTNAME          -13
#define TLS_HS_ERR_TRUST             -14

#endif /* RINTLS_HANDSHAKE_H */
