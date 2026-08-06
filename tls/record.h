/*
 * rinTLS - TLSレコード層
 * RFC 5246 (TLS 1.2) および RFC 8446 (TLS 1.3) 準拠
 */

#ifndef RINTLS_RECORD_H
#define RINTLS_RECORD_H

#include "../platform/rin_platform.h"
#include "../crypto/aes.h"
#include "../crypto/sha256.h"
#include "../crypto/hmac.h"

/* ═══════════════════════════════════════
 * TLS定数
 * ═══════════════════════════════════════ */

/* TLSバージョン */
#define TLS_VERSION_1_0     0x0301
#define TLS_VERSION_1_1     0x0302
#define TLS_VERSION_1_2     0x0303
#define TLS_VERSION_1_3     0x0304

/* コンテントタイプ */
#define TLS_CONTENT_CHANGE_CIPHER_SPEC  20
#define TLS_CONTENT_ALERT               21
#define TLS_CONTENT_HANDSHAKE           22
#define TLS_CONTENT_APPLICATION_DATA    23

/* TLS 1.3 追加 */
#define TLS13_CONTENT_INNER_TYPE        24  /* 内部コンテントタイプ */

/* アラートレベル */
#define TLS_ALERT_WARNING   1
#define TLS_ALERT_FATAL     2

/* アラート記述 */
#define TLS_ALERT_CLOSE_NOTIFY              0
#define TLS_ALERT_UNEXPECTED_MESSAGE        10
#define TLS_ALERT_BAD_RECORD_MAC            20
#define TLS_ALERT_DECRYPTION_FAILED         21
#define TLS_ALERT_RECORD_OVERFLOW           22
#define TLS_ALERT_HANDSHAKE_FAILURE         40
#define TLS_ALERT_BAD_CERTIFICATE           42
#define TLS_ALERT_UNSUPPORTED_CERTIFICATE   43
#define TLS_ALERT_CERTIFICATE_REVOKED       44
#define TLS_ALERT_CERTIFICATE_EXPIRED       45
#define TLS_ALERT_CERTIFICATE_UNKNOWN       46
#define TLS_ALERT_ILLEGAL_PARAMETER         47
#define TLS_ALERT_UNKNOWN_CA                48
#define TLS_ALERT_ACCESS_DENIED             49
#define TLS_ALERT_DECODE_ERROR              50
#define TLS_ALERT_DECRYPT_ERROR             51
#define TLS_ALERT_PROTOCOL_VERSION          70
#define TLS_ALERT_INSUFFICIENT_SECURITY     71
#define TLS_ALERT_INTERNAL_ERROR            80
#define TLS_ALERT_INAPPROPRIATE_FALLBACK    86
#define TLS_ALERT_USER_CANCELED             90
#define TLS_ALERT_MISSING_EXTENSION         109
#define TLS_ALERT_UNSUPPORTED_EXTENSION     110
#define TLS_ALERT_UNRECOGNIZED_NAME         112
#define TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE   113
#define TLS_ALERT_UNKNOWN_PSK_IDENTITY      115
#define TLS_ALERT_CERTIFICATE_REQUIRED      116
#define TLS_ALERT_NO_APPLICATION_PROTOCOL   120

/* 最大レコードサイズ */
#define TLS_MAX_RECORD_SIZE         16384   /* 2^14 */
#define TLS_MAX_CIPHERTEXT_SIZE     (TLS_MAX_RECORD_SIZE + 2048)  /* 暗号化後 */
/* TLS 1.3復号後: 平文 + コンテンツタイプ(1) + パディング(最大255) */
#define TLS_MAX_PLAINTEXT_BUFFER    (TLS_MAX_RECORD_SIZE + 256 + 1)

/* ═══════════════════════════════════════
 * TLSレコードヘッダー
 * ═══════════════════════════════════════ */

typedef struct {
    u8 content_type;
    u16 version;
    u16 length;
} tls_record_header_t;

#define TLS_RECORD_HEADER_SIZE  5

/* ═══════════════════════════════════════
 * 暗号化コンテキスト
 * ═══════════════════════════════════════ */

typedef enum {
    TLS_CIPHER_NULL,
    TLS_CIPHER_AES_128_GCM,
    TLS_CIPHER_AES_256_GCM,
    TLS_CIPHER_CHACHA20_POLY1305
} tls_cipher_type_t;

typedef struct {
    tls_cipher_type_t type;

    /* 鍵マテリアル */
    u8 key[32];         /* 暗号化鍵 */
    u8 iv[12];          /* 暗黙的IV (TLS 1.2) / base IV (TLS 1.3) */
    rin_size_t key_len;
    rin_size_t iv_len;

    /* シーケンス番号 */
    u64 seq_num;

    /* AES-GCMコンテキスト */
    aes_ctx aes;
} tls_cipher_ctx_t;

/* ═══════════════════════════════════════
 * TLSレコード層コンテキスト
 * ═══════════════════════════════════════ */

typedef struct {
    u16 version;        /* ネゴシエートされたバージョン */
    int is_tls13;       /* TLS 1.3フラグ */

    /* 読み書き用の暗号化コンテキスト */
    tls_cipher_ctx_t read_cipher;
    tls_cipher_ctx_t write_cipher;

    /* バッファ */
    u8 read_buffer[TLS_MAX_CIPHERTEXT_SIZE];
    rin_size_t read_buffer_len;
    u8 write_buffer[TLS_RECORD_HEADER_SIZE + TLS_MAX_CIPHERTEXT_SIZE];
    rin_size_t write_buffer_len;
    rin_size_t write_buffer_pos;
    rin_size_t write_payload_len;
    u8 write_in_progress;
    u8 write_pending_seq_advance;

    /* 生レコード受信の途中状態 */
    u8 raw_recv_header[TLS_RECORD_HEADER_SIZE];
    rin_size_t raw_recv_header_len;
    u8 raw_recv_content_type;
    u16 raw_recv_version;
    u16 raw_recv_expected_len;
    u8 raw_recv_phase;

    /* 復号後プレーンテキストバッファ (TLS 1.3マルチメッセージ対応) */
    u8 plaintext_buffer[TLS_MAX_PLAINTEXT_BUFFER];
    rin_size_t plaintext_len;      /* バッファ内のデータ長 */
    rin_size_t plaintext_pos;      /* 読み取り位置 */
    u8 plaintext_content_type;     /* コンテンツタイプ */

    /* ソケット送受信コールバック */
    int (*send_func)(void* ctx, const u8* data, rin_size_t len);
    int (*recv_func)(void* ctx, u8* data, rin_size_t len);
    void* io_ctx;

    /* 最後のアラート */
    u8 last_alert_level;
    u8 last_alert_desc;
} tls_record_ctx_t;

/* ═══════════════════════════════════════
 * 初期化・設定
 * ═══════════════════════════════════════ */

/* レコード層コンテキストを初期化 */
void tls_record_init(tls_record_ctx_t* ctx);

/* I/Oコールバックを設定 */
void tls_record_set_io(tls_record_ctx_t* ctx,
                       int (*send_func)(void*, const u8*, rin_size_t),
                       int (*recv_func)(void*, u8*, rin_size_t),
                       void* io_ctx);

/* 暗号化を有効化 (TLS 1.2) */
int tls_record_enable_cipher_1_2(tls_record_ctx_t* ctx,
                                  tls_cipher_type_t type,
                                  const u8* key, rin_size_t key_len,
                                  const u8* iv, rin_size_t iv_len,
                                  int is_write);

/* 暗号化を有効化 (TLS 1.3) */
int tls_record_enable_cipher_1_3(tls_record_ctx_t* ctx,
                                  tls_cipher_type_t type,
                                  const u8* key, rin_size_t key_len,
                                  const u8* iv, rin_size_t iv_len,
                                  int is_write);

/* ═══════════════════════════════════════
 * レコード送受信
 * ═══════════════════════════════════════ */

/*
 * TLSレコードを送信
 * content_type: コンテントタイプ
 * data: 平文データ
 * len: データ長
 *
 * 戻り値: 成功時 >= 0、エラー時 < 0
 */
int tls_record_send(tls_record_ctx_t* ctx,
                    u8 content_type,
                    const u8* data, rin_size_t len);

/*
 * TLSレコードを受信
 * content_type: 受信したコンテントタイプ (出力)
 * data: 復号された平文 (出力バッファ)
 * max_len: バッファサイズ
 *
 * 戻り値: 受信バイト数、エラー時 < 0
 */
int tls_record_recv(tls_record_ctx_t* ctx,
                    u8* content_type,
                    u8* data, rin_size_t max_len);

/* ═══════════════════════════════════════
 * アラート
 * ═══════════════════════════════════════ */

/* アラートを送信 */
int tls_record_send_alert(tls_record_ctx_t* ctx, u8 level, u8 description);

/* Close Notifyを送信 */
int tls_record_close(tls_record_ctx_t* ctx);

/* ═══════════════════════════════════════
 * 内部関数 (ハンドシェイク用に公開)
 * ═══════════════════════════════════════ */

/* 生データを送信 (暗号化なし) */
int tls_record_send_raw(tls_record_ctx_t* ctx,
                        u8 content_type, u16 version,
                        const u8* data, rin_size_t len);

/* 生データを受信 (暗号化なし) */
int tls_record_recv_raw(tls_record_ctx_t* ctx,
                        u8* content_type, u16* version,
                        u8* data, rin_size_t max_len);

/* シーケンス番号をリセット */
void tls_cipher_reset_seq(tls_cipher_ctx_t* cipher);

/* ═══════════════════════════════════════
 * エラーコード
 * ═══════════════════════════════════════ */

#define TLS_ERR_OK              0
#define TLS_ERR_IO              -1      /* I/Oエラー */
#define TLS_ERR_BUFFER          -2      /* バッファサイズ不足 */
#define TLS_ERR_DECRYPT         -3      /* 復号エラー */
#define TLS_ERR_MAC             -4      /* MAC検証失敗 */
#define TLS_ERR_RECORD_SIZE     -5      /* レコードサイズ不正 */
#define TLS_ERR_VERSION         -6      /* バージョン不一致 */
#define TLS_ERR_ALERT           -7      /* アラート受信 */
#define TLS_ERR_CLOSED          -8      /* 接続終了 */
#define TLS_ERR_UNEXPECTED      -9      /* 予期しないデータ */
#define TLS_ERR_WANT_READ       -10     /* 読み込み待ち */
#define TLS_ERR_WANT_WRITE      -11     /* 書き込み待ち */

#endif /* RINTLS_RECORD_H */
