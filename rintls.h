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
#define RINTLS_ERR_WANT_READ    -10
#define RINTLS_ERR_WANT_WRITE   -11

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

/* Add one DER-encoded CA certificate to this context's trust store. */
int rintls_add_trust_anchor_der(rintls_ctx* ctx,
                                const void* certificate_der,
                                rin_size_t certificate_len);

/* Load a Rin CA bundle: "RCA1", little-endian entry count, followed by
 * repeated little-endian DER length + DER certificate records. */
int rintls_load_trust_store(rintls_ctx* ctx,
                            const void* bundle,
                            rin_size_t bundle_len);

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
