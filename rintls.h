/*
 * rinTLS - RinOS用TLS/SSLライブラリ
 * TLS 1.2/1.3対応
 *
 * 使用例:
 *   rintls_ctx* ctx = rintls_new();
 *   rintls_set_hostname(ctx, "example.com");
 *   rintls_set_socket(ctx, sock_fd);
 *   if (rintls_handshake(ctx) == RINTLS_OK) {
 *       rintls_send(ctx, "GET / HTTP/1.1\r\n...", len);
 *       rintls_recv(ctx, buf, sizeof(buf));
 *   }
 *   rintls_free(ctx);
 */

#ifndef RINTLS_H
#define RINTLS_H

#include "platform/rin_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════
 * エラーコード
 * ═══════════════════════════════════════ */

#define RINTLS_OK               0
#define RINTLS_ERR_MEMORY       -1
#define RINTLS_ERR_IO           -2
#define RINTLS_ERR_HANDSHAKE    -3
#define RINTLS_ERR_CERTIFICATE  -4
#define RINTLS_ERR_HOSTNAME     -5
#define RINTLS_ERR_CLOSED       -6
#define RINTLS_ERR_VERSION      -7
#define RINTLS_ERR_DECRYPT      -8
#define RINTLS_ERR_RANDOM       -9
#define RINTLS_ERR_WANT_READ    -10
#define RINTLS_ERR_WANT_WRITE   -11
#define RINTLS_ERR_TRUST        -12

#define RINTLS_PEER_EVIDENCE_VERSION 0x00010000u
#define RINTLS_PEER_EVIDENCE_CHAIN_VERIFIED 0x00000001u
#define RINTLS_PEER_EVIDENCE_HOSTNAME_VERIFIED 0x00000002u
#define RINTLS_PEER_EVIDENCE_TRUSTED_TIME 0x00000004u
#define RINTLS_PEER_EVIDENCE_REQUIRED 0x00000007u

typedef struct rintls_peer_evidence {
    u32 struct_size;
    u32 version;
    u32 evidence_flags;
    u32 tls_version;
    u32 cipher_suite;
    u32 reserved0;
    u64 trusted_unix_time;
    u8 peer_certificate_sha256[32];
    char peer_dns_name[256];
    u64 reserved[2];
} rintls_peer_evidence;

/* ═══════════════════════════════════════
 * オプションフラグ
 * ═══════════════════════════════════════ */

#define RINTLS_OPT_VERIFY_NONE          0x0001  /* 開発専用。通常ビルドでは拒否 */
#define RINTLS_OPT_TLS_1_2_ONLY         0x0002  /* TLS 1.2のみ */
#define RINTLS_OPT_TLS_1_3_ONLY         0x0004  /* TLS 1.3のみ */

/* ═══════════════════════════════════════
 * コンテキスト (不透明型)
 * ═══════════════════════════════════════ */

typedef struct rintls_ctx rintls_ctx;
typedef struct rintls_trust_store rintls_trust_store;

/* Client-certificate signing is deliberately callback based.  The private
 * key never enters rintls or crosses the transport boundary; the owner keeps
 * it in a key-capable process and signs only the bounded TLS transcript that
 * rintls supplies.  The callback returns the TLS signature bytes (not a
 * CertificateVerify message). */
typedef int (*rintls_client_certificate_sign_func)(
    void* opaque, u16 signature_scheme, const u8* message,
    rin_size_t message_len, u8* signature, rin_size_t signature_capacity,
    rin_size_t* signature_len);

/* Optional authenticated provider invoked exactly once after a TLS 1.3
 * CertificateRequest is received. The provider must call
 * rintls_set_client_certificate() with a validated public certificate_list
 * and signer capability; private key material never enters RinTLS. */
typedef int (*rintls_client_certificate_provider_func)(
    rintls_ctx* ctx, void* opaque);

#define RINTLS_MAX_CLIENT_CERTIFICATE_CHAIN (16u * 1024u)
#define RINTLS_MAX_CLIENT_CERTIFICATE_BYTES (16u * 1024u)
#define RINTLS_MAX_CLIENT_SIGNATURE_BYTES  512u

/* ═══════════════════════════════════════
 * I/Oコールバック型
 * ═══════════════════════════════════════ */

/*
 * 送信コールバック
 * ctx: ユーザーコンテキスト
 * data: 送信データ
 * len: データ長
 * 戻り値: 送信バイト数、エラー時 < 0
 */
typedef int (*rintls_send_func)(void* ctx, const u8* data, rin_size_t len);

/*
 * 受信コールバック
 * ctx: ユーザーコンテキスト
 * data: 受信バッファ
 * len: バッファサイズ
 * 戻り値: 受信バイト数、エラー時 < 0
 */
typedef int (*rintls_recv_func)(void* ctx, u8* data, rin_size_t len);

/* ═══════════════════════════════════════
 * コンテキスト管理
 * ═══════════════════════════════════════ */

/*
 * TLSコンテキストを作成
 * 戻り値: 新しいコンテキスト、失敗時 NULL
 */
rintls_ctx* rintls_new(void);

/*
 * TLSコンテキストを解放
 */
void rintls_free(rintls_ctx* ctx);

/* ═══════════════════════════════════════
 * 設定
 * ═══════════════════════════════════════ */

/*
 * ホスト名を設定 (SNI用)
 * TLS接続前に設定必須
 */
int rintls_set_hostname(rintls_ctx* ctx, const char* hostname);

/*
 * I/Oコールバックを設定
 * send_func: 送信関数
 * recv_func: 受信関数
 * io_ctx: コールバックに渡すユーザーコンテキスト
 */
int rintls_set_io(rintls_ctx* ctx,
                  rintls_send_func send_func,
                  rintls_recv_func recv_func,
                  void* io_ctx);

/*
 * オプションを設定
 * options: RINTLS_OPT_* フラグの組み合わせ
 */
int rintls_set_options(rintls_ctx* ctx, u32 options);

/* Bind authenticated wall-clock state to this handshake.  Configuration is
 * immutable after the first handshake step. */
int rintls_set_trusted_time(rintls_ctx* ctx, u64 trusted_unix_time);

/* Configure a bounded TLS 1.3 Certificate message certificate_list for mutual
 * TLS.  The input is the wire-format certificate_list: a 3-byte total length
 * followed by repeated 3-byte DER length + DER certificate + 2-byte
 * CertificateEntry extensions length (and extension bytes) records.  The
 * signer is invoked after the server's CertificateRequest and must be
 * authenticated by the caller; passing a raw private key is unsupported. */
int rintls_set_client_certificate(
    rintls_ctx* ctx, const void* certificate_list,
    rin_size_t certificate_list_len,
    rintls_client_certificate_sign_func signer, void* signer_opaque);

/* Bind a one-shot CertificateRequest provider before the handshake. */
int rintls_set_client_certificate_provider(
    rintls_ctx* ctx, rintls_client_certificate_provider_func provider,
    void* provider_opaque);

/* Whether the peer requested a client certificate during this handshake. */
int rintls_client_certificate_requested(const rintls_ctx* ctx);

/* Add one DER-encoded CA certificate to this context's trust store. */
int rintls_add_trust_anchor_der(rintls_ctx* ctx,
                                const void* certificate_der,
                                rin_size_t certificate_len);

/* Load a Rin CA bundle: "RCA1", little-endian entry count, followed by
 * repeated little-endian DER length + DER certificate records. */
int rintls_load_trust_store(rintls_ctx* ctx,
                            const void* bundle,
                            rin_size_t bundle_len);

/* Parse an immutable Rin CA bundle once so it can be shared safely by many
 * TLS contexts.  The returned store owns one reference. */
int rintls_trust_store_from_bundle(const void* bundle,
                                   rin_size_t bundle_len,
                                   rintls_trust_store** store_out);
void rintls_trust_store_retain(rintls_trust_store* store);
void rintls_trust_store_release(rintls_trust_store* store);
u32 rintls_trust_store_anchor_count(const rintls_trust_store* store);

/* Replace the context's current anchors with a retained reference to store. */
int rintls_set_trust_store(rintls_ctx* ctx, rintls_trust_store* store);

void rintls_clear_trust_anchors(rintls_ctx* ctx);
u32 rintls_trust_anchor_count(rintls_ctx* ctx);

/* ═══════════════════════════════════════
 * 接続
 * ═══════════════════════════════════════ */

/*
 * TLSハンドシェイクを実行
 * 事前にhostnameとI/Oを設定しておく必要あり
 *
 * 戻り値: RINTLS_OK で成功
 */
int rintls_handshake(rintls_ctx* ctx);
int rintls_handshake_step(rintls_ctx* ctx);

/*
 * TLS接続を終了
 * Close Notifyアラートを送信
 */
int rintls_close(rintls_ctx* ctx);

/* ═══════════════════════════════════════
 * データ送受信
 * ═══════════════════════════════════════ */

/*
 * 暗号化データを送信
 * data: 平文データ
 * len: データ長
 *
 * 戻り値: 送信バイト数、エラー時 < 0
 */
int rintls_send(rintls_ctx* ctx, const void* data, rin_size_t len);

/*
 * 暗号化データを受信
 * buf: 受信バッファ
 * maxlen: バッファサイズ
 *
 * 戻り値: 受信バイト数、エラー時 < 0
 */
int rintls_recv(rintls_ctx* ctx, void* buf, rin_size_t maxlen);

/* ═══════════════════════════════════════
 * 情報取得
 * ═══════════════════════════════════════ */

/*
 * ネゴシエートされたTLSバージョンを取得
 * 戻り値: 0x0303 (TLS 1.2) or 0x0304 (TLS 1.3)
 */
u16 rintls_get_version(rintls_ctx* ctx);

/*
 * 選択された暗号スイートを取得
 */
u16 rintls_get_cipher_suite(rintls_ctx* ctx);

/*
 * 最後のエラーを取得
 */
int rintls_get_error(rintls_ctx* ctx);

/* Returns evidence only for a completed, default-verification handshake that
 * used a hostname, a non-empty trust store, and explicit trusted time. */
int rintls_get_peer_evidence(rintls_ctx* ctx,
                             rintls_peer_evidence* evidence);

/*
 * エラーメッセージを取得
 */
const char* rintls_strerror(int error);

/* ═══════════════════════════════════════
 * 便利関数
 * ═══════════════════════════════════════ */

/*
 * ソケットに対してTLS接続を確立
 * (I/Oコールバックを内部で設定)
 *
 * sock: ソケットディスクリプタ
 * hostname: 接続先ホスト名
 *
 * 戻り値: RINTLS_OK で成功
 */
int rintls_connect(rintls_ctx* ctx, int sock, const char* hostname);

#ifdef __cplusplus
}
#endif

#endif /* RINTLS_H */
