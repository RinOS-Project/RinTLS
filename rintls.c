/*
 * rinTLS - RinOS用TLS/SSLライブラリ
 * メインAPI実装
 */

#include "rintls.h"
#include "tls/record.h"
#include "tls/handshake.h"
#include "x509/cert.h"
#include "platform/rin_platform.h"
#if !defined(RIN_FREESTANDING) || defined(RIN_USERSPACE)
#include "../libc/errno.h"
#endif

/* ═══════════════════════════════════════
 * 内部コンテキスト構造
 * ═══════════════════════════════════════ */

struct rintls_ctx {
    /* レコード層 */
    tls_record_ctx_t record;

    /* ハンドシェイク */
    tls_handshake_ctx_t handshake;

    /* 設定 */
    char hostname[256];
    u32 options;

    /* 状態 */
    int connected;
    int last_error;

    /* I/O */
    rintls_send_func send_func;
    rintls_recv_func recv_func;
    void* io_ctx;
    void* owned_io_ctx;
    int   owns_io_ctx;
};

static void rintls_release_owned_io(rintls_ctx* ctx)
{
    if (!ctx) return;
    if (ctx->owns_io_ctx && ctx->owned_io_ctx) {
        rintls_mem_free(ctx->owned_io_ctx);
    }
    ctx->owned_io_ctx = RIN_NULL;
    ctx->owns_io_ctx = 0;
}

/* ═══════════════════════════════════════
 * コンテキスト管理
 * ═══════════════════════════════════════ */

rintls_ctx* rintls_new(void)
{
    rintls_ctx* ctx = (rintls_ctx*)rintls_malloc(sizeof(rintls_ctx));
    if (!ctx) return RIN_NULL;

    rintls_memset(ctx, 0, sizeof(rintls_ctx));

    tls_record_init(&ctx->record);
    tls_handshake_init(&ctx->handshake, &ctx->record);

    ctx->connected = 0;
    ctx->last_error = RINTLS_OK;
    ctx->owned_io_ctx = RIN_NULL;
    ctx->owns_io_ctx = 0;

    return ctx;
}

void rintls_free(rintls_ctx* ctx)
{
    if (!ctx) return;

    if (ctx->connected) {
        rintls_close(ctx);
    }

    rintls_release_owned_io(ctx);
    tls_handshake_clear(&ctx->handshake);
    rintls_secure_zero(ctx, sizeof(rintls_ctx));
    rintls_mem_free(ctx);
}

/* ═══════════════════════════════════════
 * 設定
 * ═══════════════════════════════════════ */

int rintls_set_hostname(rintls_ctx* ctx, const char* hostname)
{
    if (!ctx || !hostname) return RINTLS_ERR_MEMORY;

    rin_size_t len = 0;
    while (hostname[len] && len < sizeof(ctx->hostname) - 1) {
        ctx->hostname[len] = hostname[len];
        len++;
    }
    ctx->hostname[len] = '\0';

    tls_handshake_set_server_name(&ctx->handshake, hostname);

    return RINTLS_OK;
}

int rintls_set_io(rintls_ctx* ctx,
                  rintls_send_func send_func,
                  rintls_recv_func recv_func,
                  void* io_ctx)
{
    if (!ctx) return RINTLS_ERR_MEMORY;

    ctx->send_func = send_func;
    ctx->recv_func = recv_func;
    ctx->io_ctx = io_ctx;

    tls_record_set_io(&ctx->record,
                      (int (*)(void*, const u8*, rin_size_t))send_func,
                      (int (*)(void*, u8*, rin_size_t))recv_func,
                      io_ctx);

    return RINTLS_OK;
}

int rintls_set_options(rintls_ctx* ctx, u32 options)
{
    if (!ctx) return RINTLS_ERR_MEMORY;
    ctx->options = options;
    ctx->handshake.verify_none = (options & RINTLS_OPT_VERIFY_NONE) ? 1 : 0;
    return RINTLS_OK;
}

/* ═══════════════════════════════════════
 * 接続
 * ═══════════════════════════════════════ */

int rintls_handshake(rintls_ctx* ctx)
{
    if (!ctx) return RINTLS_ERR_MEMORY;
    if (!ctx->send_func || !ctx->recv_func) return RINTLS_ERR_IO;

    while (1) {
        int ret = rintls_handshake_step(ctx);
        if (ret == RINTLS_OK) {
            return RINTLS_OK;
        }
        if (ret != RINTLS_ERR_WANT_READ && ret != RINTLS_ERR_WANT_WRITE) {
            return ret;
        }
    }
}

int rintls_handshake_step(rintls_ctx* ctx)
{
    int ret;

    if (!ctx) return RINTLS_ERR_MEMORY;
    if (!ctx->send_func || !ctx->recv_func) return RINTLS_ERR_IO;

    switch (ctx->handshake.state) {
    case TLS_STATE_INIT:
        ret = tls_send_client_hello(&ctx->handshake);
        break;
    case TLS_STATE_CLIENT_HELLO_SENT:
        ret = tls_recv_server_hello(&ctx->handshake);
        break;
    case TLS_STATE_SERVER_HELLO_RECEIVED:
        ret = ctx->handshake.is_tls13
            ? tls_recv_encrypted_extensions(&ctx->handshake)
            : tls_recv_certificate(&ctx->handshake);
        break;
    case TLS_STATE_ENCRYPTED_EXTENSIONS:
        ret = tls_recv_certificate(&ctx->handshake);
        break;
    case TLS_STATE_CERTIFICATE_RECEIVED:
        ret = ctx->handshake.is_tls13
            ? tls_recv_certificate_verify(&ctx->handshake)
            : tls_recv_server_key_exchange(&ctx->handshake);
        break;
    case TLS_STATE_CERTIFICATE_VERIFY:
        ret = tls_recv_finished(&ctx->handshake);
        break;
    case TLS_STATE_SERVER_KEY_EXCHANGE:
        ret = tls_recv_server_hello_done(&ctx->handshake);
        break;
    case TLS_STATE_SERVER_HELLO_DONE:
        ret = tls_send_client_key_exchange(&ctx->handshake);
        break;
    case TLS_STATE_CLIENT_KEY_EXCHANGE_SENT:
        ret = tls12_derive_master_secret(&ctx->handshake);
        if (ret == TLS_HS_ERR_OK) ret = tls12_derive_keys(&ctx->handshake);
        if (ret == TLS_HS_ERR_OK) ret = tls_send_change_cipher_spec(&ctx->handshake);
        if (ret == TLS_HS_ERR_OK) ret = tls_send_finished(&ctx->handshake);
        break;
    case TLS_STATE_FINISHED_RECEIVED:
        ret = tls_send_change_cipher_spec(&ctx->handshake);
        break;
    case TLS_STATE_CHANGE_CIPHER_SPEC:
        if (ctx->handshake.pending_send_kind != 0) {
            ret = tls_send_finished(&ctx->handshake);
        } else {
            ret = ctx->handshake.is_tls13
                ? tls_send_finished(&ctx->handshake)
                : tls_recv_finished(&ctx->handshake);
        }
        break;
    case TLS_STATE_FINISHED_SENT:
        if (ctx->handshake.is_tls13) {
            ret = tls13_derive_application_keys(&ctx->handshake);
            if (ret == TLS_HS_ERR_OK) {
                ctx->handshake.state = TLS_STATE_CONNECTED;
            }
        } else {
            ret = tls_recv_change_cipher_spec(&ctx->handshake);
            if (ret == TLS_HS_ERR_OK) {
                ctx->handshake.state = TLS_STATE_CHANGE_CIPHER_SPEC;
            }
        }
        break;
    case TLS_STATE_CONNECTED:
        ctx->connected = 1;
        ctx->last_error = RINTLS_OK;
        return RINTLS_OK;
    default:
        ret = TLS_HS_ERR_UNEXPECTED;
        break;
    }

    if (ret == TLS_HS_ERR_OK && ctx->handshake.state == TLS_STATE_CONNECTED) {
        ctx->connected = 1;
        ctx->last_error = RINTLS_OK;
        return RINTLS_OK;
    }

    if (ret == TLS_HS_ERR_OK) {
        ctx->last_error = RINTLS_OK;
        return RINTLS_ERR_WANT_READ;
    }

    /* エラーを変換 */
    switch (ret) {
    case TLS_HS_ERR_WANT_READ:
        ctx->last_error = RINTLS_ERR_WANT_READ;
        break;
    case TLS_HS_ERR_WANT_WRITE:
        ctx->last_error = RINTLS_ERR_WANT_WRITE;
        break;
    case TLS_HS_ERR_IO:
        ctx->last_error = RINTLS_ERR_IO;
        break;
    case TLS_HS_ERR_VERSION:
        ctx->last_error = RINTLS_ERR_VERSION;
        break;
    case TLS_HS_ERR_CERTIFICATE:
    case TLS_HS_ERR_SIGNATURE:
        ctx->last_error = RINTLS_ERR_CERTIFICATE;
        break;
    case TLS_HS_ERR_VERIFY:
        ctx->last_error = RINTLS_ERR_HOSTNAME;
        break;
    default:
        ctx->last_error = RINTLS_ERR_HANDSHAKE;
    }

    return ctx->last_error;
}

static int rintls_map_tls_error(rintls_ctx* ctx, int ret, const char* op)
{
    (void)op;
    if (!ctx) return RINTLS_ERR_IO;

    if (ret == TLS_ERR_WANT_READ) {
        ctx->last_error = RINTLS_ERR_WANT_READ;
        return RINTLS_ERR_WANT_READ;
    }
    if (ret == TLS_ERR_WANT_WRITE) {
        ctx->last_error = RINTLS_ERR_WANT_WRITE;
        return RINTLS_ERR_WANT_WRITE;
    }
    if (ret == TLS_ERR_CLOSED) {
        ctx->connected = 0;
        ctx->last_error = RINTLS_ERR_CLOSED;
        return RINTLS_ERR_CLOSED;
    }
    if (ret == TLS_ERR_DECRYPT || ret == TLS_ERR_MAC) {
        rintls_debug("[RINTLS] ");
        rintls_debug(op);
        rintls_debug(" decrypt/mac error ret=");
        rintls_debug_hex(ret);
        rintls_debug(" alert_level=");
        rintls_debug_hex(ctx->record.last_alert_level);
        rintls_debug(" alert_desc=");
        rintls_debug_hex(ctx->record.last_alert_desc);
        rintls_debug("\n");
        ctx->last_error = RINTLS_ERR_DECRYPT;
        return RINTLS_ERR_DECRYPT;
    }
    if (ret == TLS_ERR_ALERT) {
        rintls_debug("[RINTLS] ");
        rintls_debug(op);
        rintls_debug(" alert received level=");
        rintls_debug_hex(ctx->record.last_alert_level);
        rintls_debug(" desc=");
        rintls_debug_hex(ctx->record.last_alert_desc);
        rintls_debug("\n");
        ctx->last_error = RINTLS_ERR_IO;
        return RINTLS_ERR_IO;
    }
    if (ret < 0) {
        rintls_debug("[RINTLS] ");
        rintls_debug(op);
        rintls_debug(" error ret=");
        rintls_debug_hex(ret);
        rintls_debug(" alert_level=");
        rintls_debug_hex(ctx->record.last_alert_level);
        rintls_debug(" alert_desc=");
        rintls_debug_hex(ctx->record.last_alert_desc);
        rintls_debug("\n");
        ctx->last_error = RINTLS_ERR_IO;
        return RINTLS_ERR_IO;
    }
    return ret;
}

int rintls_close(rintls_ctx* ctx)
{
    if (!ctx) return RINTLS_ERR_MEMORY;

    if (ctx->connected) {
        tls_record_close(&ctx->record);
        ctx->connected = 0;
    }
    rintls_release_owned_io(ctx);

    return RINTLS_OK;
}

/* ═══════════════════════════════════════
 * データ送受信
 * ═══════════════════════════════════════ */

int rintls_send(rintls_ctx* ctx, const void* data, rin_size_t len)
{
    if (!ctx) return RINTLS_ERR_MEMORY;
    if (!ctx->connected) return RINTLS_ERR_IO;

    int ret = tls_record_send(&ctx->record, TLS_CONTENT_APPLICATION_DATA,
                               (const u8*)data, len);
    return rintls_map_tls_error(ctx, ret, "send");
}

int rintls_recv(rintls_ctx* ctx, void* buf, rin_size_t maxlen)
{
    if (!ctx) return RINTLS_ERR_MEMORY;
    if (!ctx->connected) return RINTLS_ERR_IO;

    /* アプリケーションデータを受信するまでループ
     * (TLS 1.3ではNewSessionTicket等のハンドシェイクメッセージが
     *  アプリケーションデータと混在することがある) */
    while (1) {
        u8 content_type;
        int ret = tls_record_recv(&ctx->record, &content_type, (u8*)buf, maxlen);
        if (ret < 0) {
            int mapped = rintls_map_tls_error(ctx, ret, "recv");
            if (mapped == RINTLS_ERR_CLOSED) {
                return 0;
            }
            return mapped;
        }

        /* アプリケーションデータならそのまま返す */
        if (content_type == TLS_CONTENT_APPLICATION_DATA) {
            return ret;
        }

        /* それ以外(NewSessionTicket等)は無視して次を読む */
        rintls_debug("[TLS] Skipping non-app data, type=");
        rintls_debug_hex(content_type);
        rintls_debug("\n");
    }
}

/* ═══════════════════════════════════════
 * 情報取得
 * ═══════════════════════════════════════ */

u16 rintls_get_version(rintls_ctx* ctx)
{
    if (!ctx) return 0;
    return ctx->handshake.version;
}

u16 rintls_get_cipher_suite(rintls_ctx* ctx)
{
    if (!ctx) return 0;
    return ctx->handshake.cipher_suite;
}

int rintls_get_error(rintls_ctx* ctx)
{
    if (!ctx) return RINTLS_ERR_MEMORY;
    return ctx->last_error;
}

const char* rintls_strerror(int error)
{
    switch (error) {
    case RINTLS_OK:             return "Success";
    case RINTLS_ERR_MEMORY:     return "Memory allocation failed";
    case RINTLS_ERR_IO:         return "I/O error";
    case RINTLS_ERR_HANDSHAKE:  return "Handshake failed";
    case RINTLS_ERR_CERTIFICATE: return "Certificate verification failed";
    case RINTLS_ERR_HOSTNAME:   return "Hostname verification failed";
    case RINTLS_ERR_CLOSED:     return "Connection closed";
    case RINTLS_ERR_VERSION:    return "TLS version not supported";
    case RINTLS_ERR_DECRYPT:    return "Decryption failed";
    case RINTLS_ERR_WANT_READ:  return "Need more readable socket data";
    case RINTLS_ERR_WANT_WRITE: return "Need writable socket";
    default:                    return "Unknown error";
    }
}

/* ═══════════════════════════════════════
 * 便利関数
 * ═══════════════════════════════════════ */

/* ソケット用I/Oラッパー (カーネル統合用) */
typedef struct {
    int sock;
} socket_io_ctx;

static int socket_send(void* ctx, const u8* data, rin_size_t len)
{
    socket_io_ctx* sctx = (socket_io_ctx*)ctx;
    if (!sctx || sctx->sock < 0 || !data || len == 0) return RINTLS_ERR_IO;
    {
        int ret = rintls_tcp_send(sctx->sock, data, len);
#if !defined(RIN_FREESTANDING) || defined(RIN_USERSPACE)
        if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS)) {
            return TLS_ERR_WANT_WRITE;
        }
#else
        if (ret == -11 || ret == -115) {
            return TLS_ERR_WANT_WRITE;
        }
#endif
        return ret;
    }
}

static int socket_recv(void* ctx, u8* data, rin_size_t len)
{
    socket_io_ctx* sctx = (socket_io_ctx*)ctx;
    if (!sctx || sctx->sock < 0 || !data || len == 0) return RINTLS_ERR_IO;
    {
        int ret = rintls_tcp_recv(sctx->sock, data, len);
#if !defined(RIN_FREESTANDING) || defined(RIN_USERSPACE)
        if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS)) {
            return TLS_ERR_WANT_READ;
        }
#else
        if (ret == -11 || ret == -115) {
            return TLS_ERR_WANT_READ;
        }
#endif
        return ret;
    }
}

int rintls_connect(rintls_ctx* ctx, int sock, const char* hostname)
{
    if (!ctx || sock < 0) return RINTLS_ERR_MEMORY;

    rintls_release_owned_io(ctx);

    /* ソケットI/Oを設定 */
    socket_io_ctx* sctx = (socket_io_ctx*)rintls_malloc(sizeof(socket_io_ctx));
    if (!sctx) return RINTLS_ERR_MEMORY;
    sctx->sock = sock;
    ctx->owned_io_ctx = sctx;
    ctx->owns_io_ctx = 1;

    if (hostname && hostname[0]) {
        int set_host_ret = rintls_set_hostname(ctx, hostname);
        if (set_host_ret != RINTLS_OK) {
            rintls_release_owned_io(ctx);
            return set_host_ret;
        }
    }
    if (rintls_set_io(ctx, socket_send, socket_recv, sctx) != RINTLS_OK) {
        rintls_release_owned_io(ctx);
        return RINTLS_ERR_IO;
    }

    int hs = rintls_handshake(ctx);
    if (hs != RINTLS_OK) {
        rintls_release_owned_io(ctx);
    }
    return hs;
}

