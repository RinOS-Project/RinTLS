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
#define RINTLS_ERR_WANT_CREDENTIALS -13
#define RINTLS_ERR_CIPHER       -14
#define RINTLS_ERR_UNSUPPORTED  -15

#define RINTLS_PEER_EVIDENCE_VERSION 0x00010000u
#define RINTLS_PEER_EVIDENCE_CHAIN_VERIFIED 0x00000001u
#define RINTLS_PEER_EVIDENCE_HOSTNAME_VERIFIED 0x00000002u
#define RINTLS_PEER_EVIDENCE_TRUSTED_TIME 0x00000004u
#define RINTLS_PEER_EVIDENCE_REQUIRED 0x00000007u
#define RINTLS_PEER_CERTIFICATE_BINDING_VERSION 0x00010000u
#define RINTLS_PEER_CERTIFICATE_BINDING_LEAF 0x00000001u
#define RINTLS_PEER_CERTIFICATE_BINDING_ISSUER 0x00000002u
#define RINTLS_PEER_CERTIFICATE_BINDING_REQUIRED \
    (RINTLS_PEER_CERTIFICATE_BINDING_LEAF | \
     RINTLS_PEER_CERTIFICATE_BINDING_ISSUER)
#define RINTLS_REVOCATION_ENDPOINTS_VERSION 0x00010000u
#define RINTLS_REVOCATION_EVIDENCE_VERSION 0x00010000u
#define RINTLS_MAX_CRL_SIZE (256u * 1024u)
#define RINTLS_MAX_OCSP_SIZE (256u * 1024u)
#define RINTLS_REVOCATION_SOURCE_OCSP 1u
#define RINTLS_REVOCATION_SOURCE_CRL 2u
#define RINTLS_REVOCATION_STATUS_GOOD 1u
#define RINTLS_REVOCATION_STATUS_REVOKED 2u
#define RINTLS_REVOCATION_EVIDENCE_SIGNATURE_VERIFIED 0x00000001u
#define RINTLS_REVOCATION_EVIDENCE_CERTIFICATE_MATCHED 0x00000002u
#define RINTLS_REVOCATION_EVIDENCE_ISSUER_MATCHED 0x00000004u
#define RINTLS_REVOCATION_EVIDENCE_AUTHORITY_AUTHORIZED 0x00000008u
#define RINTLS_REVOCATION_EVIDENCE_REQUIRED \
    (RINTLS_REVOCATION_EVIDENCE_SIGNATURE_VERIFIED | \
     RINTLS_REVOCATION_EVIDENCE_CERTIFICATE_MATCHED | \
     RINTLS_REVOCATION_EVIDENCE_ISSUER_MATCHED | \
     RINTLS_REVOCATION_EVIDENCE_AUTHORITY_AUTHORIZED)
#define RINTLS_MAX_REVOCATION_URL_BYTES 256u

/* Maximum DNS hostname text length is 253 bytes.  The public C-string
 * boundary scans at most 254 bytes so a 253-byte hostname may still carry
 * its terminating NUL; longer or unterminated input is rejected. */
#define RINTLS_MAX_HOSTNAME_BYTES 254u
#define RINTLS_MAX_CIPHER_SUITES 8u

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

/* Cryptographic scope for revocation evidence.  The issuer is only returned
 * when it was present in the authenticated peer chain; callers must reject
 * revocation evidence when this binding is unavailable rather than guessing
 * from a trust anchor or subject name. */
typedef struct rintls_peer_certificate_binding {
    u32 struct_size;
    u32 version;
    u32 binding_flags;
    u32 reserved0;
    u8 leaf_sha256[32];
    u8 issuer_sha256[32];
    u64 reserved[2];
} rintls_peer_certificate_binding;

/* Revocation locations advertised by the authenticated peer certificate.
 * These are discovery data only: an endpoint response must still be fetched
 * by a product-owned transport and validated against the same leaf, issuer,
 * authorization, and trusted-time policy before it can affect a connection. */
typedef struct rintls_revocation_endpoints {
    u32 struct_size;
    u32 version;
    char ocsp_url[RINTLS_MAX_REVOCATION_URL_BYTES];
    char crl_url[RINTLS_MAX_REVOCATION_URL_BYTES];
    u64 reserved[2];
} rintls_revocation_endpoints;

/* Revocation evidence produced by the product-owned fetcher after it has
 * retrieved the endpoint advertised by the peer certificate. The verifier
 * binds signed OCSP/CRL data to the exact leaf and immediate issuer retained
 * by this TLS session; it never infers an issuer from the trust store. */
typedef struct rintls_revocation_evidence {
    u32 struct_size;
    u32 version;
    u32 status;
    u32 source;
    u32 evidence_flags;
    u32 reserved0;
    u64 this_update_unix_time;
    u64 next_update_unix_time;
    u64 produced_at_unix_time;
    u8 certificate_sha256[32];
    u8 issuer_sha256[32];
    u64 sequence;
    u64 reserved[2];
} rintls_revocation_evidence;

#if defined(__cplusplus)
static_assert(sizeof(rintls_revocation_endpoints) == 536u,
              "rintls_revocation_endpoints ABI drift");
static_assert(sizeof(rintls_peer_certificate_binding) == 96u,
              "rintls_peer_certificate_binding ABI drift");
static_assert(sizeof(rintls_revocation_evidence) == 136u,
              "rintls_revocation_evidence ABI drift");
#else
_Static_assert(sizeof(rintls_revocation_endpoints) == 536u,
               "rintls_revocation_endpoints ABI drift");
_Static_assert(sizeof(rintls_peer_certificate_binding) == 96u,
               "rintls_peer_certificate_binding ABI drift");
_Static_assert(sizeof(rintls_revocation_evidence) == 136u,
               "rintls_revocation_evidence ABI drift");
#endif

/* ═══════════════════════════════════════
 * オプションフラグ
 * ═══════════════════════════════════════ */

#define RINTLS_OPT_VERIFY_NONE          0x0001  /* 開発専用。通常ビルドでは拒否 */
#define RINTLS_OPT_TLS_1_2_ONLY         0x0002  /* TLS 1.2のみ */
#define RINTLS_OPT_TLS_1_3_ONLY         0x0004  /* TLS 1.3のみ */
#define RINTLS_OPT_SERVER               0x0008  /* TLS server endpoint */

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
 * CertificateRequest is received. The provider reads the bounded request
 * constraints with rintls_get_client_certificate_request(), then installs
 * its public certificate_list and signer with an offered scheme via
 * rintls_set_client_certificate_for_scheme(); private key material never
 * enters RinTLS. */
typedef int (*rintls_client_certificate_provider_func)(
    rintls_ctx* ctx, void* opaque);

typedef rintls_client_certificate_sign_func
    rintls_server_certificate_sign_func;

/* Bounded ClientHello selection input exposed to a server certificate
 * provider. All pointers are borrowed from the context and remain valid
 * until the provider returns or the context is freed. */
typedef struct rintls_server_client_hello {
    u32 struct_size;
    u32 version;
    const char* server_name;
    u32 server_name_size;
    const u16* cipher_suites;
    u32 cipher_suite_count;
    const u16* supported_versions;
    u32 supported_version_count;
    const u16* signature_schemes;
    u32 signature_scheme_count;
    u16 key_share_group;
    const u8* key_share;
    u32 key_share_size;
    u32 offered_features;
    u64 reserved[2];
} rintls_server_client_hello;

#define RINTLS_SERVER_CLIENT_HELLO_VERSION 1u
#define RINTLS_SERVER_CLIENT_HELLO_HTTP11 0x00000001u

typedef int (*rintls_server_certificate_provider_func)(
    rintls_ctx* ctx, const rintls_server_client_hello* client_hello,
    void* opaque);

#define RINTLS_MAX_CLIENT_CERTIFICATE_CHAIN (16u * 1024u)
#define RINTLS_MAX_CLIENT_CERTIFICATE_BYTES (16u * 1024u)
#define RINTLS_MAX_CLIENT_SIGNATURE_BYTES  512u
#define RINTLS_CLIENT_CERTIFICATE_REQUEST_VERSION 1u
#define RINTLS_MAX_CLIENT_SIGNATURE_SCHEMES 64u
#define RINTLS_MAX_CLIENT_SIGNATURE_ALGORITHMS_BYTES (2u + 64u * 2u)
#define RINTLS_MAX_CLIENT_CERTIFICATE_AUTHORITIES_BYTES 4098u

/* Borrowed TLS 1.3 CertificateRequest constraints. Each vector uses its TLS
 * wire encoding (uint16 vector length followed by uint16 schemes or uint16
 * DistinguishedName length + DER bytes). Pointers remain owned by ctx and
 * are valid until ctx is freed. */
typedef struct rintls_client_certificate_request {
    u32 struct_size;
    u32 version;
    const u8* signature_algorithms;
    u32 signature_algorithms_size;
    const u8* signature_algorithms_cert;
    u32 signature_algorithms_cert_size;
    const u8* certificate_authorities;
    u32 certificate_authorities_size;
    u16 default_signature_scheme;
    u16 reserved;
} rintls_client_certificate_request;

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

/* Configure the bounded client cipher-suite offer before the handshake.
 * RinTLS accepts only the cipher suites implemented by its record and
 * handshake paths; an empty list, duplicate, unknown, or oversized list is
 * rejected without changing the existing configuration. */
int rintls_set_cipher_suites(rintls_ctx* ctx, const u16* cipher_suites,
                             rin_size_t cipher_suite_count);

/* Bind authenticated wall-clock state to this handshake.  Configuration is
 * immutable after the first handshake step. */
int rintls_set_trusted_time(rintls_ctx* ctx, u64 trusted_unix_time);

/* Configure a bounded TLS 1.3 Certificate message certificate_list for mutual
 * TLS.  The input is the wire-format certificate_list: a 3-byte total length
 * followed by repeated 3-byte DER length + DER certificate + 2-byte
 * CertificateEntry extensions length (and extension bytes) records.  The
 * signer is invoked after the server's CertificateRequest and must be
 * authenticated by the caller; passing a raw private key is unsupported.
 * For TLS 1.3, a null list with length zero and a null signer explicitly
 * declines the optional request and emits an empty Certificate message. */
int rintls_set_client_certificate(
    rintls_ctx* ctx, const void* certificate_list,
    rin_size_t certificate_list_len,
    rintls_client_certificate_sign_func signer, void* signer_opaque);

/* Select a CertificateVerify scheme explicitly. It must be offered by the
 * peer and implemented by RinTLS. This is the identity-provider path: the
 * selected certificate/key pair determines the scheme, not server ordering. */
int rintls_set_client_certificate_for_scheme(
    rintls_ctx* ctx, const void* certificate_list,
    rin_size_t certificate_list_len,
    rintls_client_certificate_sign_func signer, void* signer_opaque,
    u16 signature_scheme);

/* Bind a one-shot CertificateRequest provider before the handshake. */
int rintls_set_client_certificate_provider(
    rintls_ctx* ctx, rintls_client_certificate_provider_func provider,
    void* provider_opaque);

/* Configure a TLS 1.3 server certificate_list and an opaque-key signer.
 * The list uses the TLS wire format: a 3-byte total length followed by
 * DER length/certificate/entry-extension records. */
int rintls_set_server_certificate(
    rintls_ctx* ctx, const void* certificate_list,
    rin_size_t certificate_list_len,
    rintls_server_certificate_sign_func signer, void* signer_opaque);
int rintls_set_server_certificate_for_scheme(
    rintls_ctx* ctx, const void* certificate_list,
    rin_size_t certificate_list_len,
    rintls_server_certificate_sign_func signer, void* signer_opaque,
    u16 signature_scheme);

/* Bind a one-shot SNI/signature-scheme based server identity provider. */
int rintls_set_server_certificate_provider(
    rintls_ctx* ctx, rintls_server_certificate_provider_func provider,
    void* provider_opaque);
int rintls_get_server_client_hello(
    const rintls_ctx* ctx, rintls_server_client_hello* client_hello);

/* Whether the peer requested a client certificate during this handshake. */
int rintls_client_certificate_requested(const rintls_ctx* ctx);

/* Return the authenticated TLS 1.3 CertificateRequest constraints to the
 * one-shot provider. The returned vectors are borrowed from ctx. */
int rintls_get_client_certificate_request(
    const rintls_ctx* ctx, rintls_client_certificate_request* request);

/* Whether the application has answered the client-certificate request. */
int rintls_client_certificate_configured(const rintls_ctx* ctx);

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

/* Copy the selected ALPN protocol from a completed handshake.  The required
 * size is returned through length even when buffer is NULL or too small. */
int rintls_get_application_protocol(const rintls_ctx* ctx, void* buffer,
                                    rin_size_t capacity, rin_size_t* length);

/*
 * 最後のエラーを取得
 */
int rintls_get_error(rintls_ctx* ctx);

/* Returns evidence only for a completed, default-verification handshake that
 * used a hostname, a non-empty trust store, and explicit trusted time. */
int rintls_get_peer_evidence(rintls_ctx* ctx,
                             rintls_peer_evidence* evidence);

int rintls_get_peer_certificate_binding(
    rintls_ctx* ctx, rintls_peer_certificate_binding* binding);

/* Copy the DER-encoded leaf certificate retained by a completed handshake.
 * The required size is returned through length even when buffer is NULL or
 * too small, so callers can perform a bounded two-pass copy. */
int rintls_get_peer_certificate(rintls_ctx* ctx, void* buffer,
                                rin_size_t capacity, rin_size_t* length);

/* Copy the bounded, authenticated peer certificate chain. The blob starts
 * with a little-endian u32 count, followed by count little-endian u32 DER
 * lengths and DER values. Entry zero is the leaf; remaining entries are the
 * certificates sent by the peer in order. The required size is returned
 * through length even when buffer is NULL or too small. */
int rintls_get_peer_certificate_chain(rintls_ctx* ctx, void* buffer,
                                      rin_size_t capacity, rin_size_t* length);

/* Extract the first OCSP AIA and CRL Distribution Point URI from the peer
 * leaf certificate. The output is valid only for the current connection and
 * is zeroed on failure; an empty URI means that extension was not advertised. */
int rintls_get_peer_revocation_endpoints(
    rintls_ctx* ctx, rintls_revocation_endpoints* endpoints);

/* Extract revocation endpoints from a certificate in the authenticated peer
 * chain.  Index zero is the leaf and the remaining entries are sent by the
 * peer in certificate-list order. */
int rintls_get_peer_revocation_endpoints_at(
    rintls_ctx* ctx, u32 certificate_index,
    rintls_revocation_endpoints* endpoints);

/* Extract revocation endpoints from a caller-owned DER certificate.  This
 * form is used for a managed trust anchor that is not present in the peer's
 * TLS Certificate message.  The certificate is parsed and the output is
 * zeroed on failure; no network I/O occurs here. */
int rintls_get_certificate_revocation_endpoints(
    const void* certificate_der, rin_size_t certificate_len,
    rintls_revocation_endpoints* endpoints);

/* Validate a fetched DER CRL against the authenticated peer leaf and the
 * immediate issuer sent in the same TLS Certificate message.  `sequence`
 * must be supplied by the owner that controls its bounded evidence/cache
 * generation.  No network I/O occurs in this function. */
int rintls_verify_peer_crl(rintls_ctx* ctx, const void* crl,
                           rin_size_t crl_len, u64 sequence,
                           rintls_revocation_evidence* evidence);

/* The indexed form validates the certificate at `certificate_index` against
 * its immediate issuer in the same peer certificate list. */
int rintls_verify_peer_crl_at(
    rintls_ctx* ctx, u32 certificate_index, const void* crl,
    rin_size_t crl_len, u64 sequence, rintls_revocation_evidence* evidence);

/* Validate a fetched DER CRL against caller-owned certificate and issuer DER.
 * Both certificates are parsed and the certificate signature is verified
 * with the issuer key before CRL status is accepted.  `trusted_unix_time`
 * must be non-zero and bound to the same authenticated time source used by
 * the caller.  No network I/O occurs in this function. */
int rintls_verify_certificate_crl(
    const void* certificate_der, rin_size_t certificate_len,
    const void* issuer_der, rin_size_t issuer_len,
    const void* crl, rin_size_t crl_len, u64 trusted_unix_time,
    u64 sequence, rintls_revocation_evidence* evidence);

/* Validate a fetched DER OCSPResponse against the authenticated peer leaf
 * and the immediate issuer sent in the same TLS Certificate message.
 * `sequence` is supplied by the bounded evidence owner; no network I/O
 * occurs here. */
int rintls_verify_peer_ocsp(rintls_ctx* ctx, const void* response,
                            rin_size_t response_len, u64 sequence,
                            rintls_revocation_evidence* evidence);

/* The indexed form validates the certificate at `certificate_index` against
 * its immediate issuer in the same peer certificate list. */
int rintls_verify_peer_ocsp_at(
    rintls_ctx* ctx, u32 certificate_index, const void* response,
    rin_size_t response_len, u64 sequence, rintls_revocation_evidence* evidence);

/* Validate a fetched DER OCSP response against caller-owned certificate and
 * issuer DER.  Certificate signature, issuer binding, response signature,
 * status and trusted-time bounds are all required before evidence is
 * returned.  No network I/O occurs in this function. */
int rintls_verify_certificate_ocsp(
    const void* certificate_der, rin_size_t certificate_len,
    const void* issuer_der, rin_size_t issuer_len,
    const void* response, rin_size_t response_len, u64 trusted_unix_time,
    u64 sequence, rintls_revocation_evidence* evidence);

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
 * sock: プラットフォームのソケットハンドル
 * hostname: 接続先ホスト名
 *
 * 戻り値: RINTLS_OK で成功
 */
int rintls_connect(rintls_ctx* ctx, rintls_socket_handle sock,
                   const char* hostname);

#ifdef __cplusplus
}
#endif

#endif /* RINTLS_H */
