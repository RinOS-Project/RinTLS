/*
 * rinTLS - TLSハンドシェイク
 * RFC 5246 (TLS 1.2) および RFC 8446 (TLS 1.3) 準拠
 */

#include "handshake.h"
#include "../crypto/hmac.h"
#include "../crypto/ecdh.h"
#include "../platform/rin_platform.h"
#include "../x509/cert.h"

/* 前方宣言 */
static void tls12_prf_sha256(const u8* secret, rin_size_t secret_len,
                              const u8* label, rin_size_t label_len,
                              const u8* seed, rin_size_t seed_len,
                              u8* out, rin_size_t out_len);

/* ═══════════════════════════════════════
 * 内部定数
 * ═══════════════════════════════════════ */

/* TLS 1.3 ラベル */
static const u8 TLS13_LABEL_DERIVED[] = "derived";
static const u8 TLS13_LABEL_C_HS_TRAFFIC[] = "c hs traffic";
static const u8 TLS13_LABEL_S_HS_TRAFFIC[] = "s hs traffic";
static const u8 TLS13_LABEL_C_AP_TRAFFIC[] = "c ap traffic";
static const u8 TLS13_LABEL_S_AP_TRAFFIC[] = "s ap traffic";
static const u8 TLS13_LABEL_FINISHED[] = "finished";
static const u8 TLS13_LABEL_KEY[] = "key";
static const u8 TLS13_LABEL_IV[] = "iv";

/* ═══════════════════════════════════════
 * ヘルパー関数
 * ═══════════════════════════════════════ */

/* 16ビット値をビッグエンディアンで書き込み */
static void write_u16(u8* p, u16 val)
{
    p[0] = (u8)(val >> 8);
    p[1] = (u8)(val & 0xFF);
}

/* 24ビット値をビッグエンディアンで書き込み */
static void write_u24(u8* p, u32 val)
{
    p[0] = (u8)(val >> 16);
    p[1] = (u8)(val >> 8);
    p[2] = (u8)(val & 0xFF);
}

/* 16ビット値をビッグエンディアンから読み取り */
static u16 read_u16(const u8* p)
{
    return ((u16)p[0] << 8) | p[1];
}

/* 24ビット値をビッグエンディアンから読み取り */
static u32 read_u24(const u8* p)
{
    return ((u32)p[0] << 16) | ((u32)p[1] << 8) | p[2];
}

static int tls_handshake_map_io_error(int ret)
{
    if (ret == TLS_ERR_WANT_READ) return TLS_HS_ERR_WANT_READ;
    if (ret == TLS_ERR_WANT_WRITE) return TLS_HS_ERR_WANT_WRITE;
    return TLS_HS_ERR_IO;
}

#define TLS_PENDING_SEND_NONE                0
#define TLS_PENDING_SEND_CLIENT_HELLO        1
#define TLS_PENDING_SEND_FINISHED            2
#define TLS_PENDING_SEND_CLIENT_KEY_EXCHANGE 3
#define TLS_PENDING_SEND_CHANGE_CIPHER_SPEC  4
#define TLS_PENDING_SEND_CLIENT_CERTIFICATE  5
#define TLS_PENDING_SEND_CLIENT_CERTIFICATE_VERIFY 6

static void tls_handshake_clear_pending_send(tls_handshake_ctx_t* ctx)
{
    ctx->pending_send_kind = TLS_PENDING_SEND_NONE;
    ctx->pending_send_use_tls_record = 0;
    ctx->pending_send_content_type = 0;
    ctx->pending_send_version = 0;
    ctx->pending_send_update_transcript = 0;
    ctx->pending_send_next_state = 0;
    ctx->pending_send_msg_len = 0;
}

static int tls_handshake_stage_pending_send(tls_handshake_ctx_t* ctx,
                                            u8 kind,
                                            int use_tls_record,
                                            u8 content_type,
                                            u16 version,
                                            const u8* msg,
                                            rin_size_t msg_len,
                                            int update_transcript,
                                            tls_state_t next_state)
{
    if (msg_len > sizeof(ctx->pending_send_msg)) {
        return TLS_HS_ERR_IO;
    }

    ctx->pending_send_kind = kind;
    ctx->pending_send_use_tls_record = use_tls_record ? 1 : 0;
    ctx->pending_send_content_type = content_type;
    ctx->pending_send_version = version;
    ctx->pending_send_update_transcript = update_transcript ? 1 : 0;
    ctx->pending_send_next_state = (u8)next_state;
    ctx->pending_send_msg_len = msg_len;
    rintls_memcpy(ctx->pending_send_msg, msg, msg_len);
    return TLS_HS_ERR_OK;
}

static int tls_handshake_flush_pending_send(tls_handshake_ctx_t* ctx, u8 expected_kind)
{
    int ret;

    if (ctx->pending_send_kind == TLS_PENDING_SEND_NONE) {
        return TLS_HS_ERR_UNEXPECTED;
    }
    if (ctx->pending_send_kind != expected_kind) {
        return TLS_HS_ERR_UNEXPECTED;
    }

    if (ctx->pending_send_use_tls_record) {
        ret = tls_record_send(ctx->record,
                              ctx->pending_send_content_type,
                              ctx->pending_send_msg,
                              ctx->pending_send_msg_len);
    } else {
        ret = tls_record_send_raw(ctx->record,
                                  ctx->pending_send_content_type,
                                  ctx->pending_send_version,
                                  ctx->pending_send_msg,
                                  ctx->pending_send_msg_len);
    }

    if (ret < 0) {
        int mapped = tls_handshake_map_io_error(ret);
        if (mapped != TLS_HS_ERR_WANT_READ && mapped != TLS_HS_ERR_WANT_WRITE) {
            tls_handshake_clear_pending_send(ctx);
        }
        return mapped;
    }

    if (ctx->pending_send_update_transcript) {
        tls_transcript_update(ctx, ctx->pending_send_msg, ctx->pending_send_msg_len);
    }
    ctx->state = (tls_state_t)ctx->pending_send_next_state;
    tls_handshake_clear_pending_send(ctx);
    return TLS_HS_ERR_OK;
}

/* ═══════════════════════════════════════
 * 初期化・終了
 * ═══════════════════════════════════════ */

void tls_handshake_init(tls_handshake_ctx_t* ctx, tls_record_ctx_t* record)
{
    if (!ctx) return;

    /* X25519自己テスト (一度だけ実行) */
    static int selftest_done = 0;
    if (!selftest_done) {
        x25519_selftest();
        selftest_done = 1;
    }

    rintls_memset(ctx, 0, sizeof(tls_handshake_ctx_t));
    ctx->state = TLS_STATE_INIT;
    ctx->record = record;
    ctx->is_tls13 = 0;
    ctx->version = TLS_VERSION_1_2;
    ctx->use_sha384 = 0;

    sha256_init(&ctx->transcript_hash);

    /* クライアントランダムを生成 */
    ctx->entropy_ready =
        rintls_random_bytes(ctx->client_random, 32) == 0;
    if (!ctx->entropy_ready) {
        rintls_secure_zero(ctx->client_random, sizeof(ctx->client_random));
        ctx->last_error = TLS_HS_ERR_RANDOM;
    }
}

void tls_handshake_clear(tls_handshake_ctx_t* ctx)
{
    if (ctx->server_cert) {
        rintls_mem_free(ctx->server_cert);
        ctx->server_cert = RIN_NULL;
    }
    if (ctx->client_certificate_list) {
        rintls_secure_zero(ctx->client_certificate_list,
                           ctx->client_certificate_list_len);
        rintls_mem_free(ctx->client_certificate_list);
        ctx->client_certificate_list = RIN_NULL;
    }
    rsa_pubkey_clear(&ctx->server_rsa_key);
    rintls_secure_zero(ctx, sizeof(tls_handshake_ctx_t));
}

void tls_handshake_set_server_name(tls_handshake_ctx_t* ctx, const char* name)
{
    rin_size_t len = 0;
    while (name[len] && len < sizeof(ctx->server_name) - 1) {
        ctx->server_name[len] = name[len];
        len++;
    }
    ctx->server_name[len] = '\0';
}

void tls_handshake_set_trust_anchor_verifier(tls_handshake_ctx_t* ctx,
                                             tls_trust_anchor_verify_func verify,
                                             void* opaque)
{
    if (!ctx) return;
    ctx->trust_anchor_verify = verify;
    ctx->trust_anchor_opaque = opaque;
}

void tls_handshake_set_trusted_time(tls_handshake_ctx_t* ctx,
                                    u64 trusted_unix_time)
{
    if (!ctx) return;
    ctx->trusted_unix_time = trusted_unix_time;
}

int tls_handshake_set_client_certificate(
    tls_handshake_ctx_t* ctx, const void* certificate_list,
    rin_size_t certificate_list_len,
    tls_client_certificate_sign_func signer, void* signer_opaque)
{
    const u8* bytes = (const u8*)certificate_list;
    if (!ctx || !bytes || !signer || certificate_list_len < 3u ||
        certificate_list_len > TLS_MAX_CLIENT_CERTIFICATE_CHAIN)
        return TLS_HS_ERR_CERTIFICATE;
    if (ctx->state != TLS_STATE_INIT || ctx->client_certificate_list)
        return TLS_HS_ERR_UNEXPECTED;

    u32 list_len = read_u24(bytes);
    if (list_len != certificate_list_len - 3u || list_len == 0u)
        return TLS_HS_ERR_CERTIFICATE;

    /* Validate every DER record before retaining any caller bytes.  This
     * bounds parsing and prevents a malformed list from being emitted during
     * a later handshake. */
    const u8* p = bytes + 3u;
    const u8* end = bytes + certificate_list_len;
    u32 count = 0u;
    while (p < end) {
        if ((size_t)(end - p) < 3u)
            return TLS_HS_ERR_CERTIFICATE;
        u32 cert_len = read_u24(p);
        p += 3u;
        if (cert_len == 0u || cert_len > TLS_MAX_CLIENT_CERTIFICATE_BYTES ||
            (size_t)(end - p) < cert_len)
            return TLS_HS_ERR_CERTIFICATE;
        p += cert_len;
        ++count;
        if (count > RINTLS_MAX_CERT_CHAIN)
            return TLS_HS_ERR_CERTIFICATE;
    }
    if (p != end || count == 0u)
        return TLS_HS_ERR_CERTIFICATE;

    ctx->client_certificate_list = rintls_malloc(certificate_list_len);
    if (!ctx->client_certificate_list)
        return TLS_HS_ERR_IO;
    rintls_memcpy(ctx->client_certificate_list, bytes, certificate_list_len);
    ctx->client_certificate_list_len = certificate_list_len;
    ctx->client_certificate_sign = signer;
    ctx->client_certificate_sign_opaque = signer_opaque;
    return TLS_HS_ERR_OK;
}

int tls_handshake_client_certificate_requested(const tls_handshake_ctx_t* ctx)
{
    return ctx ? ctx->client_certificate_requested : 0;
}

/* ═══════════════════════════════════════
 * Transcript Hash
 * ═══════════════════════════════════════ */

void tls_transcript_update(tls_handshake_ctx_t* ctx, const u8* data, rin_size_t len)
{
    /* バイト合計を計算 (データ整合性チェック) */
    u32 byte_sum = 0;
    for (rin_size_t i = 0; i < len; i++) {
        byte_sum += data[i];
    }

    rintls_debug("[TLS_TR] type=");
    rintls_debug_hex(data[0]);
    rintls_debug(" len=");
    rintls_debug_hex((u32)len);
    rintls_debug(" sum=");
    rintls_debug_hex(byte_sum);
    rintls_debug("\n");

    /* 最初の16バイト */
    rintls_debug("[TLS_TR] data[0-15]: ");
    for (int i = 0; i < 16 && i < (int)len; i++) {
        rintls_debug_hex(data[i]);
        rintls_debug(" ");
    }
    rintls_debug("\n");

    /* 末尾16バイト */
    if (len > 16) {
        rintls_debug("[TLS_TR] data[end-15..end]: ");
        rin_size_t start = len - 16;
        for (rin_size_t i = start; i < len; i++) {
            rintls_debug_hex(data[i]);
            rintls_debug(" ");
        }
        rintls_debug("\n");
    }

    sha256_update(&ctx->transcript_hash, data, len);
    if (ctx->use_sha384) {
        sha384_update(&ctx->transcript_hash_384, data, len);
    }

    /* 更新後の完全なハッシュを出力 */
    u8 current_hash[32];
    tls_transcript_hash(ctx, current_hash);
    rintls_debug("[TLS_TR] hash after: ");
    for (int i = 0; i < 32; i++) {
        rintls_debug_hex(current_hash[i]);
        rintls_debug(" ");
    }
    rintls_debug("\n");
}

void tls_transcript_hash(tls_handshake_ctx_t* ctx, u8* hash)
{
    /* volatile を一切使わない版 - sha256_finalはctxを変更するので非volatile必須 */
    if (ctx->use_sha384) {
        sha384_ctx tmp;
        /* 明示的にバイト単位でコピー */
        const u8* src = (const u8*)&ctx->transcript_hash_384;
        u8* dst = (u8*)&tmp;
        for (rin_size_t i = 0; i < sizeof(sha384_ctx); i++) {
            dst[i] = src[i];
        }
        sha384_final(&tmp, hash);
    } else {
        sha256_ctx tmp;

        /* デバッグ: コピー前の状態を表示 */
        rintls_debug("[TR_HASH] ctx->transcript_hash.state[0-1]: ");
        rintls_debug_hex(ctx->transcript_hash.state[0]);
        rintls_debug(" ");
        rintls_debug_hex(ctx->transcript_hash.state[1]);
        rintls_debug(" count=");
        rintls_debug_hex((u32)ctx->transcript_hash.count);
        rintls_debug("\n");

        /* 明示的にバイト単位でコピー */
        const u8* src = (const u8*)&ctx->transcript_hash;
        u8* dst = (u8*)&tmp;
        for (rin_size_t i = 0; i < sizeof(sha256_ctx); i++) {
            dst[i] = src[i];
        }

        /* デバッグ: コピー後の状態を表示 */
        rintls_debug("[TR_HASH] tmp.state[0-1]: ");
        rintls_debug_hex(tmp.state[0]);
        rintls_debug(" ");
        rintls_debug_hex(tmp.state[1]);
        rintls_debug("\n");

        sha256_final(&tmp, hash);

        /* デバッグ: 結果を表示 */
        rintls_debug("[TR_HASH] result[0-3]: ");
        rintls_debug_hex(hash[0]);
        rintls_debug(" ");
        rintls_debug_hex(hash[1]);
        rintls_debug(" ");
        rintls_debug_hex(hash[2]);
        rintls_debug(" ");
        rintls_debug_hex(hash[3]);
        rintls_debug("\n");
    }
}

/* ═══════════════════════════════════════
 * TLS 1.3 HKDF-Expand-Label
 * ═══════════════════════════════════════ */

/* Note: volatile prevents compiler optimizations that cause incorrect results */
static void tls13_hkdf_expand_label(const u8* secret,
                                     const u8* label, rin_size_t label_len,
                                     const u8* context, rin_size_t context_len,
                                     u8* out, rin_size_t out_len)
{
    /* HkdfLabel構造:
     * uint16 length = out_len
     * opaque label<7..255> = "tls13 " + label
     * opaque context<0..255> = context
     */
    volatile u8 hkdf_label[256];  /* Reduced size, volatile to prevent optimization bugs */
    rin_size_t pos = 0;

    /* length (2 bytes) */
    hkdf_label[pos++] = (u8)(out_len >> 8);
    hkdf_label[pos++] = (u8)(out_len & 0xFF);

    /* label */
    rin_size_t full_label_len = 6 + label_len;  /* "tls13 " + label */
    hkdf_label[pos++] = (u8)full_label_len;

    /* Copy "tls13 " manually (volatile-safe) */
    hkdf_label[pos++] = 't';
    hkdf_label[pos++] = 'l';
    hkdf_label[pos++] = 's';
    hkdf_label[pos++] = '1';
    hkdf_label[pos++] = '3';
    hkdf_label[pos++] = ' ';

    /* Copy label manually */
    for (rin_size_t i = 0; i < label_len; i++) {
        hkdf_label[pos++] = label[i];
    }

    /* context */
    hkdf_label[pos++] = (u8)context_len;
    if (context_len > 0) {
        for (rin_size_t i = 0; i < context_len; i++) {
            hkdf_label[pos++] = context[i];
        }
    }

    /* Copy to non-volatile for hkdf_sha256_expand */
    u8 label_copy[256];
    for (rin_size_t i = 0; i < pos; i++) {
        label_copy[i] = hkdf_label[i];
    }

    hkdf_sha256_expand(secret, label_copy, pos, out, out_len);
}

/* ═══════════════════════════════════════
 * ClientHello送信
 * ═══════════════════════════════════════ */

int tls_send_client_hello(tls_handshake_ctx_t* ctx)
{
    if (!ctx || !ctx->entropy_ready) return TLS_HS_ERR_RANDOM;

    if (ctx->pending_send_kind != TLS_PENDING_SEND_NONE) {
        int ret = tls_handshake_flush_pending_send(ctx, TLS_PENDING_SEND_CLIENT_HELLO);
        if (ret == TLS_HS_ERR_OK) {
            u8 ch_hash[32];
            tls_transcript_hash(ctx, ch_hash);
            rintls_debug("[TLS] After CH transcript hash: ");
            for (int i = 0; i < 32; i++) {
                rintls_debug_hex(ch_hash[i]);
                rintls_debug(" ");
            }
            rintls_debug("\n");
            rintls_debug("[TLS] ClientHello sent OK\n");
        }
        return ret;
    }

    u8 msg[1024];
    rin_size_t pos = 0;

    /* ハンドシェイクヘッダー (後で長さを埋める) */
    msg[pos++] = TLS_HS_CLIENT_HELLO;
    rin_size_t length_pos = pos;
    pos += 3;  /* 長さ (3バイト) */

    rin_size_t client_hello_start = pos;

    /* クライアントバージョン (TLS 1.2) */
    write_u16(msg + pos, TLS_VERSION_1_2);
    pos += 2;

    /* クライアントランダム */
    rintls_memcpy(msg + pos, ctx->client_random, 32);
    pos += 32;

    /* セッションID (空) */
    msg[pos++] = 0;

    /* 暗号スイート */
    write_u16(msg + pos, 6);  /* 長さ: 3スイート * 2バイト */
    pos += 2;
    write_u16(msg + pos, TLS13_AES_128_GCM_SHA256);
    pos += 2;
    write_u16(msg + pos, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    pos += 2;
    write_u16(msg + pos, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    pos += 2;

    /* 圧縮メソッド (nullのみ) */
    msg[pos++] = 1;  /* 長さ */
    msg[pos++] = 0;  /* null */

    /* 拡張開始 */
    rin_size_t ext_length_pos = pos;
    pos += 2;  /* 拡張長 (後で埋める) */
    rin_size_t ext_start = pos;

    /* 拡張: supported_versions (TLS 1.3 + TLS 1.2) */
    write_u16(msg + pos, TLS_EXT_SUPPORTED_VERSIONS);
    pos += 2;
    write_u16(msg + pos, 5);  /* 拡張長: 1 + 2 + 2 */
    pos += 2;
    msg[pos++] = 4;  /* バージョンリスト長: 2 versions * 2 bytes */
    write_u16(msg + pos, TLS_VERSION_1_3);
    pos += 2;
    write_u16(msg + pos, TLS_VERSION_1_2);
    pos += 2;

    /* 拡張: supported_groups */
    write_u16(msg + pos, TLS_EXT_SUPPORTED_GROUPS);
    pos += 2;
    write_u16(msg + pos, 6);  /* 拡張長 */
    pos += 2;
    write_u16(msg + pos, 4);  /* グループリスト長 */
    pos += 2;
    write_u16(msg + pos, TLS_GROUP_X25519);
    pos += 2;
    write_u16(msg + pos, TLS_GROUP_SECP256R1);
    pos += 2;

    /* 拡張: ec_point_formats (TLS 1.2互換性) */
    write_u16(msg + pos, TLS_EXT_EC_POINT_FORMATS);
    pos += 2;
    write_u16(msg + pos, 2);  /* 拡張長 */
    pos += 2;
    msg[pos++] = 1;  /* フォーマットリスト長 */
    msg[pos++] = 0;  /* uncompressed */

    /* 拡張: key_share (TLS 1.3) */
    /* X25519鍵ペアを生成 */
    if (x25519_keygen(&ctx->x25519_keypair) != ECDH_OK) {
        return TLS_HS_ERR_RANDOM;
    }

    write_u16(msg + pos, TLS_EXT_KEY_SHARE);
    pos += 2;
    write_u16(msg + pos, 38);  /* 拡張長: 2 (entries_len) + 36 (entry) */
    pos += 2;
    write_u16(msg + pos, 36);  /* key_share entries長: 2 (group) + 2 (key_len) + 32 (key) */
    pos += 2;
    write_u16(msg + pos, TLS_GROUP_X25519);  /* group */
    pos += 2;
    write_u16(msg + pos, 32);  /* key_exchange長 */
    pos += 2;
    rintls_memcpy(msg + pos, ctx->x25519_keypair.public_key, 32);
    pos += 32;

    /* 拡張: signature_algorithms */
    write_u16(msg + pos, TLS_EXT_SIGNATURE_ALGORITHMS);
    pos += 2;
    write_u16(msg + pos, 12);  /* 拡張長 */
    pos += 2;
    write_u16(msg + pos, 10);  /* アルゴリズムリスト長 */
    pos += 2;
    write_u16(msg + pos, TLS_SIG_RSA_PSS_RSAE_SHA256);
    pos += 2;
    write_u16(msg + pos, TLS_SIG_RSA_PKCS1_SHA256);
    pos += 2;
    write_u16(msg + pos, TLS_SIG_ECDSA_SECP256R1_SHA256);
    pos += 2;
    write_u16(msg + pos, TLS_SIG_ECDSA_SECP384R1_SHA384);
    pos += 2;
    write_u16(msg + pos, TLS_SIG_ECDSA_SECP521R1_SHA512);
    pos += 2;

    /* 拡張: server_name (SNI) */
    if (ctx->server_name[0]) {
        rin_size_t name_len = 0;
        while (ctx->server_name[name_len]) name_len++;

        write_u16(msg + pos, TLS_EXT_SERVER_NAME);
        pos += 2;
        write_u16(msg + pos, name_len + 5);  /* 拡張長 */
        pos += 2;
        write_u16(msg + pos, name_len + 3);  /* サーバー名リスト長 */
        pos += 2;
        msg[pos++] = 0;  /* ホスト名タイプ */
        write_u16(msg + pos, name_len);
        pos += 2;
        rintls_memcpy(msg + pos, ctx->server_name, name_len);
        pos += name_len;
    }

    /* 拡張: ALPN (Application-Layer Protocol Negotiation) */
    write_u16(msg + pos, TLS_EXT_ALPN);
    pos += 2;
    write_u16(msg + pos, 11);  /* 拡張データ長: 2 + 1 + 8 = 11 */
    pos += 2;
    write_u16(msg + pos, 9);   /* プロトコル名リスト長: 1 + 8 = 9 */
    pos += 2;
    msg[pos++] = 8;            /* "http/1.1" の長さ */
    rintls_memcpy(msg + pos, "http/1.1", 8);
    pos += 8;

    /* 拡張長を埋める */
    write_u16(msg + ext_length_pos, pos - ext_start);

    /* ハンドシェイク長を埋める */
    write_u24(msg + length_pos, pos - client_hello_start);

    /* デバッグ: ClientHelloの全バイト合計とハッシュ */
    {
        u32 ch_sum = 0;
        for (rin_size_t i = 0; i < pos; i++) {
            ch_sum += msg[i];
        }
        rintls_debug("[TLS] CH byte_sum=");
        rintls_debug_hex(ch_sum);
        rintls_debug(" len=");
        rintls_debug_hex((u32)pos);
        rintls_debug("\n");
    }

    /* デバッグ出力 */
    rintls_debug("[TLS] Sending ClientHello, size=");
    rintls_debug_hex(pos);
    rintls_debug("\n");

    /* 完全なClientHelloダンプ (Wireshark比較用) */
    rintls_debug("[CH_DUMP] Full ClientHello bytes:\n");
    for (rin_size_t i = 0; i < pos; i += 16) {
        rintls_debug("[CH_DUMP] ");
        rintls_debug_hex((u32)i);
        rintls_debug(": ");
        for (rin_size_t j = i; j < i + 16 && j < pos; j++) {
            rintls_debug_hex(msg[j]);
            rintls_debug(" ");
        }
        rintls_debug("\n");
    }

    int ret = tls_handshake_stage_pending_send(ctx,
                                               TLS_PENDING_SEND_CLIENT_HELLO,
                                               0,
                                               TLS_CONTENT_HANDSHAKE,
                                               TLS_VERSION_1_0,
                                               msg,
                                               pos,
                                               1,
                                               TLS_STATE_CLIENT_HELLO_SENT);
    if (ret != TLS_HS_ERR_OK) {
        return ret;
    }

    ret = tls_handshake_flush_pending_send(ctx, TLS_PENDING_SEND_CLIENT_HELLO);
    if (ret != TLS_HS_ERR_OK) {
        if (ret != TLS_HS_ERR_WANT_READ && ret != TLS_HS_ERR_WANT_WRITE) {
            rintls_debug("[TLS] ClientHello send failed, ret=");
            rintls_debug_hex(ret);
            rintls_debug("\n");
        }
        return ret;
    }

    {
        u8 ch_hash[32];
        tls_transcript_hash(ctx, ch_hash);
        rintls_debug("[TLS] After CH transcript hash: ");
        for (int i = 0; i < 32; i++) {
            rintls_debug_hex(ch_hash[i]);
            rintls_debug(" ");
        }
        rintls_debug("\n");
    }

    rintls_debug("[TLS] ClientHello sent OK\n");
    return TLS_HS_ERR_OK;
}

/* ═══════════════════════════════════════
 * ServerHello受信
 * ═══════════════════════════════════════ */

int tls_recv_server_hello(tls_handshake_ctx_t* ctx)
{
    u8 msg[1024];
    u8 content_type;
    u16 record_version;

    rintls_debug("[TLS] Waiting for ServerHello...\n");

    int len = tls_record_recv_raw(ctx->record, &content_type, &record_version,
                                   msg, sizeof(msg));
    if (len < 0) {
        rintls_debug("[TLS] ServerHello recv failed, ret=");
        rintls_debug_hex(len);
        rintls_debug("\n");
        return tls_handshake_map_io_error(len);
    }

    rintls_debug("[TLS] Received record type=");
    rintls_debug_hex(content_type);
    rintls_debug(" len=");
    rintls_debug_hex(len);
    rintls_debug("\n");

    if (content_type != TLS_CONTENT_HANDSHAKE) {
        /* アラートの場合、詳細を出力 */
        if (content_type == 0x15 && len >= 2) {
            rintls_debug("[TLS] ALERT: level=");
            rintls_debug_hex(msg[0]);
            rintls_debug(" desc=");
            rintls_debug_hex(msg[1]);
            rintls_debug("\n");
        }
        return TLS_HS_ERR_UNEXPECTED;
    }

    /* ハンドシェイクヘッダー */
    if (len < 4) return TLS_HS_ERR_UNEXPECTED;
    if (msg[0] != TLS_HS_SERVER_HELLO) return TLS_HS_ERR_UNEXPECTED;

    u32 msg_len = read_u24(msg + 1);
    if (msg_len + 4 > (u32)len) return TLS_HS_ERR_UNEXPECTED;

    /* Transcriptに追加 */
    tls_transcript_update(ctx, msg, 4 + msg_len);

    /* デバッグ: ServerHelloの全バイト合計とハッシュ */
    {
        u32 sh_sum = 0;
        rin_size_t sh_len = 4 + msg_len;
        for (rin_size_t i = 0; i < sh_len; i++) {
            sh_sum += msg[i];
        }
        rintls_debug("[TLS] SH byte_sum=");
        rintls_debug_hex(sh_sum);
        rintls_debug(" len=");
        rintls_debug_hex((u32)sh_len);
        rintls_debug("\n");

        /* 完全なServerHelloダンプ (Wireshark比較用) */
        rintls_debug("[SH_DUMP] Full ServerHello bytes:\n");
        for (rin_size_t i = 0; i < sh_len; i += 16) {
            rintls_debug("[SH_DUMP] ");
            rintls_debug_hex((u32)i);
            rintls_debug(": ");
            for (rin_size_t j = i; j < i + 16 && j < sh_len; j++) {
                rintls_debug_hex(msg[j]);
                rintls_debug(" ");
            }
            rintls_debug("\n");
        }

        u8 sh_hash[32];
        tls_transcript_hash(ctx, sh_hash);
        rintls_debug("[TLS] After SH transcript hash: ");
        for (int i = 0; i < 32; i++) {
            rintls_debug_hex(sh_hash[i]);
            rintls_debug(" ");
        }
        rintls_debug("\n");
    }

    const u8* p = msg + 4;
    const u8* end = p + msg_len;

    /* サーバーバージョン */
    if (p + 2 > end) return TLS_HS_ERR_UNEXPECTED;
    u16 server_version = read_u16(p);
    p += 2;

    /* サーバーランダム */
    if (p + 32 > end) return TLS_HS_ERR_UNEXPECTED;
    rintls_memcpy(ctx->server_random, p, 32);
    p += 32;

    /* セッションID */
    if (p + 1 > end) return TLS_HS_ERR_UNEXPECTED;
    u8 session_id_len = *p++;
    if (p + session_id_len > end) return TLS_HS_ERR_UNEXPECTED;
    p += session_id_len;

    /* 暗号スイート */
    if (p + 2 > end) return TLS_HS_ERR_UNEXPECTED;
    ctx->cipher_suite = read_u16(p);
    p += 2;

    /* 圧縮メソッド */
    if (p + 1 > end) return TLS_HS_ERR_UNEXPECTED;
    p++;

    /* TLS 1.3チェック */
    ctx->is_tls13 = 0;
    ctx->version = server_version;

    /* 拡張をパース */
    if (p + 2 <= end) {
        u16 ext_len = read_u16(p);
        p += 2;
        const u8* ext_end = p + ext_len;
        if (ext_end > end) ext_end = end;

        while (p + 4 <= ext_end) {
            u16 ext_type = read_u16(p);
            p += 2;
            u16 ext_data_len = read_u16(p);
            p += 2;

            if (p + ext_data_len > ext_end) break;

            if (ext_type == TLS_EXT_SUPPORTED_VERSIONS && ext_data_len >= 2) {
                u16 selected_version = read_u16(p);
                if (selected_version == TLS_VERSION_1_3) {
                    ctx->is_tls13 = 1;
                    ctx->version = TLS_VERSION_1_3;
                }
            } else if (ext_type == TLS_EXT_KEY_SHARE && ext_data_len >= 4) {
                ctx->named_group = read_u16(p);
                u16 key_len = read_u16(p + 2);
                if (key_len <= sizeof(ctx->peer_public_key) && p + 4 + key_len <= ext_end) {
                    rintls_memcpy(ctx->peer_public_key, p + 4, key_len);
                    ctx->peer_public_key_len = key_len;
                }
            }

            p += ext_data_len;
        }
    }

    ctx->record->version = ctx->version;
    ctx->record->is_tls13 = ctx->is_tls13;
    ctx->state = TLS_STATE_SERVER_HELLO_RECEIVED;

    rintls_debug("[TLS] ServerHello parsed: is_tls13=");
    rintls_debug_hex(ctx->is_tls13);
    rintls_debug(" version=");
    rintls_debug_hex(ctx->version);
    rintls_debug(" cipher=");
    rintls_debug_hex(ctx->cipher_suite);
    rintls_debug("\n");

    /* TLS 1.3の場合、共有秘密を計算してハンドシェイク鍵を導出 */
    if (ctx->is_tls13) {
        rintls_debug("[TLS] TLS 1.3 detected, named_group=");
        rintls_debug_hex(ctx->named_group);
        rintls_debug(" peer_key_len=");
        rintls_debug_hex(ctx->peer_public_key_len);
        rintls_debug("\n");

        if (ctx->named_group == TLS_GROUP_X25519) {
            /* デバッグ: サーバーの公開鍵全体を出力 (全32バイト) */
            rintls_debug("[TLS] peer_pubkey: ");
            for (int i = 0; i < 32; i++) {
                rintls_debug_hex(ctx->peer_public_key[i]);
                rintls_debug(" ");
            }
            rintls_debug("\n");

            if (x25519_ecdh(ctx->shared_secret,
                            ctx->x25519_keypair.private_key,
                            ctx->peer_public_key) != ECDH_OK) {
                return TLS_HS_ERR_KEY_EXCHANGE;
            }
            ctx->shared_secret_len = 32;
            rintls_debug("[TLS] X25519 ECDH computed\n");
        } else {
            rintls_debug("[TLS] Unsupported named_group!\n");
            return TLS_HS_ERR_KEY_EXCHANGE;
        }

        /* ハンドシェイク鍵を導出 */
        rintls_debug("[TLS] Deriving handshake keys...\n");
        int ret = tls13_derive_handshake_keys(ctx);
        if (ret != TLS_HS_ERR_OK) {
            rintls_debug("[TLS] Key derivation failed, ret=");
            rintls_debug_hex(ret);
            rintls_debug("\n");
            return ret;
        }
        rintls_debug("[TLS] Handshake keys derived OK\n");
    }

    return TLS_HS_ERR_OK;
}

/* ═══════════════════════════════════════
 * TLS 1.3 鍵導出
 * ═══════════════════════════════════════ */

int tls13_derive_handshake_keys(tls_handshake_ctx_t* ctx)
{
    /* volatile で最適化による破壊を防止 */
    volatile u8 early_secret[32];
    volatile u8 derived_secret[32];
    volatile u8 transcript[32];
    volatile u8 empty_hash[32];
    int i;

    /* 重要: Transcript HashをHKDF操作の前に取得する
     * HKDF内部のsha256がctx->transcript_hashのbufferを破壊するため */
    {
        u8 tmp[32];
        tls_transcript_hash(ctx, tmp);
        for (i = 0; i < 32; i++) transcript[i] = tmp[i];
    }

    rintls_debug("[TLS] transcript[0-3] (pre-HKDF): ");
    rintls_debug_hex(transcript[0]);
    rintls_debug(" ");
    rintls_debug_hex(transcript[1]);
    rintls_debug(" ");
    rintls_debug_hex(transcript[2]);
    rintls_debug(" ");
    rintls_debug_hex(transcript[3]);
    rintls_debug("\n");

    /* Early Secret = HKDF-Extract(salt=0, IKM=0) - No PSK */
    /* RFC 8446 A.1: salt=0 (all zero octets), IKM=0 (all zero octets) */
    {
        u8 zeros[32] = {0};
        u8 tmp[32];
        hkdf_sha256_extract(RIN_NULL, 0, zeros, 32, tmp);
        for (i = 0; i < 32; i++) early_secret[i] = tmp[i];
    }

    /* RFC 8446 A.1: early_secret should be 33 ad 0a 1c 60 7e c0 3b ... */
    /* Derived Secret = Derive-Secret(Early Secret, "derived", "") */
    {
        u8 tmp[32];
        sha256(RIN_NULL, 0, tmp);
        for (i = 0; i < 32; i++) empty_hash[i] = tmp[i];
    }

    /* empty_hash = SHA-256("") should be e3b0c442... */
    rintls_debug("[TLS] empty_hash[0-3]: ");
    rintls_debug_hex(empty_hash[0]);
    rintls_debug(" ");
    rintls_debug_hex(empty_hash[1]);
    rintls_debug(" ");
    rintls_debug_hex(empty_hash[2]);
    rintls_debug(" ");
    rintls_debug_hex(empty_hash[3]);
    rintls_debug("\n");

    {
        u8 es_copy[32], eh_copy[32], tmp[32];
        for (i = 0; i < 32; i++) { es_copy[i] = early_secret[i]; eh_copy[i] = empty_hash[i]; }
        tls13_hkdf_expand_label(es_copy,
                                 TLS13_LABEL_DERIVED, 7,
                                 eh_copy, 32,
                                 tmp, 32);
        for (i = 0; i < 32; i++) derived_secret[i] = tmp[i];
    }

    /* Handshake Secret = HKDF-Extract(Derived Secret, shared_secret) */
    {
        u8 ds_copy[32];
        for (i = 0; i < 32; i++) ds_copy[i] = derived_secret[i];
        hkdf_sha256_extract(ds_copy, 32,
                             ctx->shared_secret, ctx->shared_secret_len,
                             ctx->handshake_secret);
    }

    /* Transcript hash は関数冒頭で既に計算済み */

    /* client_handshake_traffic_secret */
    {
        u8 tr_copy[32];
        for (i = 0; i < 32; i++) tr_copy[i] = transcript[i];
        tls13_hkdf_expand_label(ctx->handshake_secret,
                                 TLS13_LABEL_C_HS_TRAFFIC, 12,
                                 tr_copy, 32,
                                 ctx->client_handshake_traffic_secret, 32);
    }

    /* server_handshake_traffic_secret */
    {
        u8 tr_copy[32];
        for (i = 0; i < 32; i++) tr_copy[i] = transcript[i];
        tls13_hkdf_expand_label(ctx->handshake_secret,
                                 TLS13_LABEL_S_HS_TRAFFIC, 12,
                                 tr_copy, 32,
                                 ctx->server_handshake_traffic_secret, 32);
    }

    /* 鍵とIVを導出 - volatile で最適化による破壊を防止 */
    volatile u8 server_key[16], server_iv[12];
    volatile u8 client_key[16], client_iv[12];

    {
        u8 tmp_key[16], tmp_iv[12];
        tls13_hkdf_expand_label(ctx->server_handshake_traffic_secret,
                                 TLS13_LABEL_KEY, 3, RIN_NULL, 0,
                                 tmp_key, 16);
        for (i = 0; i < 16; i++) server_key[i] = tmp_key[i];
        tls13_hkdf_expand_label(ctx->server_handshake_traffic_secret,
                                 TLS13_LABEL_IV, 2, RIN_NULL, 0,
                                 tmp_iv, 12);
        for (i = 0; i < 12; i++) server_iv[i] = tmp_iv[i];
    }

    {
        u8 tmp_key[16], tmp_iv[12];
        tls13_hkdf_expand_label(ctx->client_handshake_traffic_secret,
                                 TLS13_LABEL_KEY, 3, RIN_NULL, 0,
                                 tmp_key, 16);
        for (i = 0; i < 16; i++) client_key[i] = tmp_key[i];
        tls13_hkdf_expand_label(ctx->client_handshake_traffic_secret,
                                 TLS13_LABEL_IV, 2, RIN_NULL, 0,
                                 tmp_iv, 12);
        for (i = 0; i < 12; i++) client_iv[i] = tmp_iv[i];
    }

    /* レコード層に暗号化を設定 - volatileからコピー */
    {
        u8 sk[16], si[12], ck[16], ci[12];
        for (i = 0; i < 16; i++) { sk[i] = server_key[i]; ck[i] = client_key[i]; }
        for (i = 0; i < 12; i++) { si[i] = server_iv[i]; ci[i] = client_iv[i]; }
        tls_record_enable_cipher_1_3(ctx->record, TLS_CIPHER_AES_128_GCM,
                                      sk, 16, si, 12, 0);
        tls_record_enable_cipher_1_3(ctx->record, TLS_CIPHER_AES_128_GCM,
                                      ck, 16, ci, 12, 1);
    }

    return TLS_HS_ERR_OK;
}

int tls13_derive_application_keys(tls_handshake_ctx_t* ctx)
{
    /* volatile で最適化による破壊を防止 */
    volatile u8 derived_secret[32];
    volatile u8 master_secret[32];
    volatile u8 empty_hash[32];
    int i;

    {
        u8 tmp[32];
        sha256(RIN_NULL, 0, tmp);
        for (i = 0; i < 32; i++) empty_hash[i] = tmp[i];
    }

    /* Derived Secret */
    {
        u8 eh_copy[32], tmp[32];
        for (i = 0; i < 32; i++) eh_copy[i] = empty_hash[i];
        tls13_hkdf_expand_label(ctx->handshake_secret,
                                 TLS13_LABEL_DERIVED, 7,
                                 eh_copy, 32,
                                 tmp, 32);
        for (i = 0; i < 32; i++) derived_secret[i] = tmp[i];
    }

    /* Master Secret = HKDF-Extract(Derived Secret, 0) */
    {
        u8 ds_copy[32], zeros[32] = {0}, tmp[32];
        for (i = 0; i < 32; i++) ds_copy[i] = derived_secret[i];
        hkdf_sha256_extract(ds_copy, 32, zeros, 32, tmp);
        for (i = 0; i < 32; i++) master_secret[i] = tmp[i];
    }

    /* RFC 8446: アプリケーション鍵は ClientHello...server Finished の
     * トランスクリプトハッシュで導出 (client Finished を含まない)
     * server_finished_transcript はこの関数呼び出し前に保存済み */
    rintls_debug("[TLS_APP] full transcript hash: ");
    for (i = 0; i < 32; i++) {
        rintls_debug_hex(ctx->server_finished_transcript[i]);
        rintls_debug(" ");
    }
    rintls_debug("\n");
    /* Application Traffic Secrets */
    {
        u8 ms_copy[32];
        for (i = 0; i < 32; i++) ms_copy[i] = master_secret[i];
        tls13_hkdf_expand_label(ms_copy,
                                 TLS13_LABEL_C_AP_TRAFFIC, 12,
                                 ctx->server_finished_transcript, 32,
                                 ctx->client_application_traffic_secret, 32);
    }

    {
        u8 ms_copy[32];
        for (i = 0; i < 32; i++) ms_copy[i] = master_secret[i];
        tls13_hkdf_expand_label(ms_copy,
                                 TLS13_LABEL_S_AP_TRAFFIC, 12,
                                 ctx->server_finished_transcript, 32,
                                 ctx->server_application_traffic_secret, 32);
    }

    /* 鍵とIVを導出 - volatile で最適化による破壊を防止 */
    volatile u8 server_key[16], server_iv[12];
    volatile u8 client_key[16], client_iv[12];

    {
        u8 tmp_key[16], tmp_iv[12];
        tls13_hkdf_expand_label(ctx->server_application_traffic_secret,
                                 TLS13_LABEL_KEY, 3, RIN_NULL, 0,
                                 tmp_key, 16);
        for (i = 0; i < 16; i++) server_key[i] = tmp_key[i];
        tls13_hkdf_expand_label(ctx->server_application_traffic_secret,
                                 TLS13_LABEL_IV, 2, RIN_NULL, 0,
                                 tmp_iv, 12);
        for (i = 0; i < 12; i++) server_iv[i] = tmp_iv[i];
    }

    {
        u8 tmp_key[16], tmp_iv[12];
        tls13_hkdf_expand_label(ctx->client_application_traffic_secret,
                                 TLS13_LABEL_KEY, 3, RIN_NULL, 0,
                                 tmp_key, 16);
        for (i = 0; i < 16; i++) client_key[i] = tmp_key[i];
        tls13_hkdf_expand_label(ctx->client_application_traffic_secret,
                                 TLS13_LABEL_IV, 2, RIN_NULL, 0,
                                 tmp_iv, 12);
        for (i = 0; i < 12; i++) client_iv[i] = tmp_iv[i];
    }

    /* レコード層に暗号化を設定 - volatileからコピー */
    rintls_debug("[TLS_APP] *** SWITCHING TO APPLICATION KEYS ***\n");
    rintls_debug("[TLS_APP] seq_num will reset to 0 for both read and write\n");

    {
        u8 sk[16], si[12], ck[16], ci[12];
        for (i = 0; i < 16; i++) { sk[i] = server_key[i]; ck[i] = client_key[i]; }
        for (i = 0; i < 12; i++) { si[i] = server_iv[i]; ci[i] = client_iv[i]; }
        tls_record_enable_cipher_1_3(ctx->record, TLS_CIPHER_AES_128_GCM,
                                      sk, 16, si, 12, 0);
        tls_record_enable_cipher_1_3(ctx->record, TLS_CIPHER_AES_128_GCM,
                                      ck, 16, ci, 12, 1);
    }

    rintls_debug("[TLS_APP] Application keys enabled successfully\n");
    return TLS_HS_ERR_OK;
}

/* ═══════════════════════════════════════
 * TLS 1.3 メッセージ処理
 * ═══════════════════════════════════════ */

int tls_recv_encrypted_extensions(tls_handshake_ctx_t* ctx)
{
    u8 msg[16384];  /* TLS_MAX_RECORD_SIZE */
    u8 content_type;

retry_recv:;
    int len = tls_record_recv(ctx->record, &content_type, msg, sizeof(msg));
    if (len < 0) return tls_handshake_map_io_error(len);

    /* TLS 1.3 middlebox互換性: ChangeCipherSpecを無視 */
    if (content_type == TLS_CONTENT_CHANGE_CIPHER_SPEC) {
        rintls_debug("[TLS] Ignoring ChangeCipherSpec (middlebox compat)\n");
        goto retry_recv;
    }

    if (content_type != TLS_CONTENT_HANDSHAKE) {
        rintls_debug("[TLS] EncryptedExtensions: unexpected type=");
        rintls_debug_hex(content_type);
        rintls_debug("\n");
        return TLS_HS_ERR_UNEXPECTED;
    }

    if (len < 4 || msg[0] != TLS_HS_ENCRYPTED_EXTENSIONS) {
        return TLS_HS_ERR_UNEXPECTED;
    }

    /* 長さ検証: 受信したデータがメッセージ全体を含むか確認 */
    u32 msg_len = read_u24(msg + 1);
    if ((u32)len < 4 + msg_len) {
        rintls_debug("[TLS] EncryptedExtensions fragmented! len=");
        rintls_debug_hex((u32)len);
        rintls_debug(" expected=");
        rintls_debug_hex(4 + msg_len);
        rintls_debug("\n");
        /* TODO: ハンドシェイク断片化対応 - 現在はエラー */
        return TLS_HS_ERR_UNEXPECTED;
    }

    /* Transcriptに追加 */
    tls_transcript_update(ctx, msg, 4 + msg_len);

    ctx->state = TLS_STATE_ENCRYPTED_EXTENSIONS;
    return TLS_HS_ERR_OK;
}

int tls_recv_certificate_request(tls_handshake_ctx_t* ctx,
                                 const u8* msg, rin_size_t len)
{
    if (!ctx || !msg || len < 4u || msg[0] != TLS_HS_CERTIFICATE_REQUEST)
        return TLS_HS_ERR_UNEXPECTED;
    u32 msg_len = read_u24(msg + 1u);
    if (msg_len + 4u > len)
        return TLS_HS_ERR_UNEXPECTED;

    const u8* p = msg + 4u;
    const u8* end = p + msg_len;
    if (ctx->is_tls13) {
        if (p >= end) return TLS_HS_ERR_UNEXPECTED;
        u8 context_len = *p++;
        if (p + context_len + 2u > end) return TLS_HS_ERR_UNEXPECTED;
        p += context_len;
        u16 extensions_len = read_u16(p);
        p += 2u;
        if (p + extensions_len > end) return TLS_HS_ERR_UNEXPECTED;
        const u8* ext_end = p + extensions_len;
        while (p + 4u <= ext_end) {
            u16 ext_type = read_u16(p);
            u16 ext_len = read_u16(p + 2u);
            p += 4u;
            if (p + ext_len > ext_end) return TLS_HS_ERR_UNEXPECTED;
            if (ext_type == TLS_EXT_SIGNATURE_ALGORITHMS && ext_len >= 2u) {
                u16 list_len = read_u16(p);
                if (list_len + 2u > ext_len || (list_len & 1u))
                    return TLS_HS_ERR_UNEXPECTED;
                const u8* sig_end = p + 2u + list_len;
                for (const u8* sig = p + 2u; sig + 2u <= sig_end; sig += 2u) {
                    u16 scheme = read_u16(sig);
                    if (scheme == TLS_SIG_ECDSA_SECP256R1_SHA256 ||
                        scheme == TLS_SIG_ECDSA_SECP384R1_SHA384 ||
                        scheme == TLS_SIG_ECDSA_SECP521R1_SHA512 ||
                        scheme == TLS_SIG_RSA_PSS_RSAE_SHA256 ||
                        scheme == TLS_SIG_RSA_PSS_RSAE_SHA384 ||
                        scheme == TLS_SIG_RSA_PSS_RSAE_SHA512) {
                        ctx->client_signature_scheme = scheme;
                        break;
                    }
                }
            }
            p += ext_len;
        }
        if (p != ext_end)
            return TLS_HS_ERR_UNEXPECTED;
    } else {
        /* TLS 1.2 CertificateRequest starts with certificate_types and a
         * certificate_authorities vector.  SignatureAlgorithms is optional;
         * the callback may still select the implementation's default. */
        if (p + 1u > end) return TLS_HS_ERR_UNEXPECTED;
        u8 certificate_types_len = *p++;
        if (p + certificate_types_len + 2u > end) return TLS_HS_ERR_UNEXPECTED;
        p += certificate_types_len;
        u16 authorities_len = read_u16(p);
        p += 2u;
        if (p + authorities_len > end) return TLS_HS_ERR_UNEXPECTED;
    }

    tls_transcript_update(ctx, msg, 4u + msg_len);
    ctx->client_certificate_requested = 1;
    if (!ctx->is_tls13) {
        /* TLS 1.2 CertificateVerify requires a legacy MD5/SHA transcript
         * construction that this transport intentionally does not expose to
         * the signer capability.  Refuse the challenge instead of sending a
         * certificate without proof of possession. */
        ctx->state = TLS_STATE_ERROR;
        return TLS_HS_ERR_CERTIFICATE;
    }
    if (ctx->client_signature_scheme == 0)
        ctx->client_signature_scheme = TLS_SIG_ECDSA_SECP256R1_SHA256;
    ctx->state = TLS_STATE_CLIENT_CERTIFICATE;
    return TLS_HS_ERR_OK;
}

int tls_send_client_certificate(tls_handshake_ctx_t* ctx)
{
    if (!ctx || !ctx->client_certificate_requested ||
        !ctx->client_certificate_list || !ctx->client_certificate_sign)
        return TLS_HS_ERR_CERTIFICATE;

    u8 msg[TLS_MAX_PENDING_HANDSHAKE_SEND];
    rin_size_t pos = 0u;
    rin_size_t context_len = ctx->is_tls13 ? 1u : 0u;
    if (ctx->client_certificate_list_len > sizeof(msg) - 4u - context_len)
        return TLS_HS_ERR_CERTIFICATE;
    msg[pos++] = TLS_HS_CERTIFICATE;
    write_u24(msg + pos, ctx->client_certificate_list_len + context_len);
    pos += 3u;
    if (ctx->is_tls13)
        msg[pos++] = 0u; /* CertificateRequestContext */
    rintls_memcpy(msg + pos, ctx->client_certificate_list,
                  ctx->client_certificate_list_len);
    pos += ctx->client_certificate_list_len;

    if (ctx->pending_send_kind != TLS_PENDING_SEND_NONE) {
        return tls_handshake_flush_pending_send(
            ctx, TLS_PENDING_SEND_CLIENT_CERTIFICATE);
    }
    int ret = tls_handshake_stage_pending_send(
        ctx, TLS_PENDING_SEND_CLIENT_CERTIFICATE, ctx->is_tls13,
        TLS_CONTENT_HANDSHAKE, ctx->version, msg, pos, 1,
        TLS_STATE_CLIENT_CERTIFICATE_VERIFY);
    if (ret != TLS_HS_ERR_OK) return ret;
    ret = tls_handshake_flush_pending_send(ctx,
                                           TLS_PENDING_SEND_CLIENT_CERTIFICATE);
    if (ret == TLS_HS_ERR_OK) ctx->client_certificate_sent = 1;
    return ret;
}

int tls_send_client_certificate_verify(tls_handshake_ctx_t* ctx)
{
    if (!ctx || !ctx->client_certificate_sent ||
        !ctx->client_certificate_sign)
        return TLS_HS_ERR_CERTIFICATE;
    if (ctx->pending_send_kind != TLS_PENDING_SEND_NONE) {
        return tls_handshake_flush_pending_send(
            ctx, TLS_PENDING_SEND_CLIENT_CERTIFICATE_VERIFY);
    }

    u8 transcript_hash[48];
    rin_size_t hash_len = ctx->use_sha384 ? 48u : 32u;
    tls_transcript_hash(ctx, transcript_hash);
    static const u8 label[] = "TLS 1.3, client CertificateVerify";
    u8 signed_data[64u + sizeof(label) - 1u + 1u + 48u];
    rin_size_t signed_len = 64u;
    rintls_memset(signed_data, 0x20, 64u);
    rintls_memcpy(signed_data + signed_len, label, sizeof(label) - 1u);
    signed_len += sizeof(label) - 1u;
    signed_data[signed_len++] = 0u;
    rintls_memcpy(signed_data + signed_len, transcript_hash, hash_len);
    signed_len += hash_len;

    u8 signature[TLS_MAX_CLIENT_SIGNATURE_BYTES];
    rin_size_t signature_len = 0u;
    int sign_result = ctx->client_certificate_sign(
        ctx->client_certificate_sign_opaque, ctx->client_signature_scheme,
        signed_data, signed_len, signature, sizeof(signature), &signature_len);
    if (sign_result != 0 || signature_len == 0u || signature_len > sizeof(signature))
        return TLS_HS_ERR_SIGNATURE;

    u8 msg[TLS_MAX_PENDING_HANDSHAKE_SEND];
    rin_size_t pos = 0u;
    msg[pos++] = TLS_HS_CERTIFICATE_VERIFY;
    write_u24(msg + pos, 4u + signature_len);
    pos += 3u;
    write_u16(msg + pos, ctx->client_signature_scheme);
    pos += 2u;
    write_u16(msg + pos, signature_len);
    pos += 2u;
    rintls_memcpy(msg + pos, signature, signature_len);
    pos += signature_len;
    rintls_secure_zero(signature, sizeof(signature));

    int ret = tls_handshake_stage_pending_send(
        ctx, TLS_PENDING_SEND_CLIENT_CERTIFICATE_VERIFY, ctx->is_tls13,
        TLS_CONTENT_HANDSHAKE, ctx->version, msg, pos, 1,
        TLS_STATE_ENCRYPTED_EXTENSIONS);
    if (ret != TLS_HS_ERR_OK) return ret;
    return tls_handshake_flush_pending_send(
        ctx, TLS_PENDING_SEND_CLIENT_CERTIFICATE_VERIFY);
}

int tls_recv_certificate(tls_handshake_ctx_t* ctx)
{
    u8 msg[16384];  /* TLS_MAX_RECORD_SIZE */
    u8 content_type;

    int len = tls_record_recv(ctx->record, &content_type, msg, sizeof(msg));
    if (len < 0) return tls_handshake_map_io_error(len);

    if (content_type != TLS_CONTENT_HANDSHAKE) {
        return TLS_HS_ERR_UNEXPECTED;
    }

    if (len < 4) {
        return TLS_HS_ERR_UNEXPECTED;
    }

    /* TLS 1.3 sends CertificateRequest between EncryptedExtensions and the
     * server Certificate.  Consume it as its own transcript message and let
     * the state machine emit the client authentication messages before
     * reading the server certificate. */
    if (msg[0] == TLS_HS_CERTIFICATE_REQUEST && ctx->is_tls13) {
        return tls_recv_certificate_request(ctx, msg, (rin_size_t)len);
    }
    if (msg[0] != TLS_HS_CERTIFICATE) {
        return TLS_HS_ERR_UNEXPECTED;
    }

    /* 長さ検証: 受信したデータがメッセージ全体を含むか確認 */
    u32 msg_len = read_u24(msg + 1);
    if ((u32)len < 4 + msg_len) {
        rintls_debug("[TLS] Certificate fragmented! len=");
        rintls_debug_hex((u32)len);
        rintls_debug(" expected=");
        rintls_debug_hex(4 + msg_len);
        rintls_debug("\n");
        /* TODO: ハンドシェイク断片化対応 - 現在はエラー */
        return TLS_HS_ERR_UNEXPECTED;
    }

    tls_transcript_update(ctx, msg, 4 + msg_len);

    const u8* p = msg + 4;
    const u8* end = p + msg_len;

    /* TLS 1.3: Certificate Request Context (0バイトであるべき) */
    if (ctx->is_tls13) {
        if (p >= end) return TLS_HS_ERR_UNEXPECTED;
        u8 ctx_len = *p++;
        p += ctx_len;
    }

    /* Certificate List */
    if (p + 3 > end) return TLS_HS_ERR_UNEXPECTED;
    u32 cert_list_len = read_u24(p);
    p += 3;
    if (p + cert_list_len > end) return TLS_HS_ERR_UNEXPECTED;
    const u8* list_end = p + cert_list_len;

    if (cert_list_len == 0) {
        rintls_debug("[TLS] Certificate list is empty\n");
        return TLS_HS_ERR_CERTIFICATE;
    }

    /* リーフ証明書と直前の証明書だけを保持するピンポンバッファ。
     * チェーンの長さによらずスタック使用量を一定(2枠分)に保つ。 */
    x509_cert_t cert_buf[2];
    x509_cert_t* prev = RIN_NULL;
    int cert_index = 0;
    int chain_err = TLS_HS_ERR_OK;

    while (p < list_end) {
        if (p + 3 > list_end) { chain_err = TLS_HS_ERR_CERTIFICATE; break; }
        u32 cert_len = read_u24(p);
        p += 3;
        if (p + cert_len > list_end) { chain_err = TLS_HS_ERR_CERTIFICATE; break; }

        const u8* cert_der = p;
        p += cert_len;

        /* TLS 1.3: CertificateEntryごとのextensions (2バイト長 + データ) */
        if (ctx->is_tls13) {
            if (p + 2 > list_end) { chain_err = TLS_HS_ERR_CERTIFICATE; break; }
            u16 ext_len = read_u16(p);
            p += 2;
            if (p + ext_len > list_end) { chain_err = TLS_HS_ERR_CERTIFICATE; break; }
            p += ext_len;
        }

        if (cert_index == 0) {
            /* リーフ証明書のDERを保存 (API/デバッグ用) */
            ctx->server_cert = rintls_malloc(cert_len);
            if (!ctx->server_cert) return TLS_HS_ERR_IO;
            rintls_memcpy(ctx->server_cert, cert_der, cert_len);
            ctx->server_cert_len = cert_len;
        }

        if (ctx->verify_none) {
            /* RINTLS_OPT_VERIFY_NONE: パース/検証をスキップ */
            cert_index++;
            continue;
        }

        if (cert_index >= RINTLS_MAX_CERT_CHAIN) {
            /* これ以上のCA証明書は無視 (エラーにはしない) */
            break;
        }

        x509_cert_t* cur = &cert_buf[cert_index & 1];
        if (x509_parse_cert(cur, cert_der, cert_len) != X509_OK) {
            rintls_debug("[TLS] Failed to parse certificate in chain\n");
            chain_err = TLS_HS_ERR_CERTIFICATE;
            break;
        }
        if ((ctx->trusted_unix_time != 0u
                 ? x509_check_validity_at(cur, ctx->trusted_unix_time)
                 : x509_check_validity(cur)) != X509_OK) {
            rintls_debug("[TLS] Certificate is not within its validity period\n");
            chain_err = TLS_HS_ERR_CERTIFICATE;
            break;
        }

        if (cert_index == 0) {
            if (ctx->server_name[0] != '\0' &&
                x509_check_hostname(cur, ctx->server_name) != X509_OK) {
                rintls_debug("[TLS] Certificate hostname mismatch\n");
                chain_err = TLS_HS_ERR_HOSTNAME;
                break;
            }
            /* CertificateVerify/ServerKeyExchangeの署名検証用に公開鍵を保持 */
            if (cur->key_type == X509_KEY_RSA) {
                ctx->server_key_type = 0;
                rintls_memcpy(&ctx->server_rsa_key, &cur->pubkey.rsa, sizeof(rsa_pubkey_t));
            } else if (cur->key_type == X509_KEY_ECDSA) {
                ctx->server_key_type = 1;
                rintls_memcpy(ctx->server_ecdsa_key, cur->pubkey.ecdsa.point,
                              cur->pubkey.ecdsa.point_len);
                ctx->server_ecdsa_key_len = cur->pubkey.ecdsa.point_len;
                ctx->server_ecdsa_curve = cur->pubkey.ecdsa.curve;
            } else {
                chain_err = TLS_HS_ERR_CERTIFICATE;
                break;
            }
        } else {
            /* 直前の証明書(prev)がこの証明書(cur)の鍵で発行されたことを検証 */
            if (x509_verify_signature(prev, cur) != X509_OK) {
                rintls_debug("[TLS] Certificate chain signature is invalid\n");
                chain_err = TLS_HS_ERR_CERTIFICATE;
                break;
            }
            if (!cur->is_ca) {
                rintls_debug("[TLS] Intermediate certificate is missing the CA flag\n");
                chain_err = TLS_HS_ERR_CERTIFICATE;
                break;
            }
            /* Every certificate in the chain must be checked against the
             * same authenticated clock snapshot as the leaf.  Falling back
             * to x509_check_validity() here would consult ambient wall-clock
             * state for intermediates and make the TLS evidence mixed. */
            if ((ctx->trusted_unix_time != 0u
                     ? x509_check_validity_at(cur, ctx->trusted_unix_time)
                     : x509_check_validity(cur)) != X509_OK) {
                rintls_debug("[TLS] Intermediate certificate is not within its validity period\n");
                chain_err = TLS_HS_ERR_CERTIFICATE;
                break;
            }
        }

        prev = cur;
        cert_index++;
    }

    if (chain_err == TLS_HS_ERR_OK && !ctx->verify_none) {
        if (!prev || !ctx->trust_anchor_verify ||
            ctx->trust_anchor_verify(ctx->trust_anchor_opaque, prev) != 1) {
            rintls_debug("[TLS] Certificate chain has no trusted Rin anchor\n");
            chain_err = TLS_HS_ERR_TRUST;
        }
    }

    if (chain_err != TLS_HS_ERR_OK) {
        ctx->last_error = chain_err;
        ctx->state = TLS_STATE_ERROR;
        return chain_err;
    }

    ctx->state = TLS_STATE_CERTIFICATE_RECEIVED;
    return TLS_HS_ERR_OK;
}

int tls_recv_certificate_verify(tls_handshake_ctx_t* ctx)
{
    u8 msg[16384];  /* TLS_MAX_RECORD_SIZE */
    u8 content_type;

    int len = tls_record_recv(ctx->record, &content_type, msg, sizeof(msg));
    if (len < 0) return tls_handshake_map_io_error(len);

    if (content_type != TLS_CONTENT_HANDSHAKE) {
        return TLS_HS_ERR_UNEXPECTED;
    }

    if (len < 4 || msg[0] != TLS_HS_CERTIFICATE_VERIFY) {
        return TLS_HS_ERR_UNEXPECTED;
    }

    /* 長さ検証: 受信したデータがメッセージ全体を含むか確認 */
    u32 msg_len = read_u24(msg + 1);
    if ((u32)len < 4 + msg_len) {
        rintls_debug("[TLS] CertificateVerify fragmented! len=");
        rintls_debug_hex((u32)len);
        rintls_debug(" expected=");
        rintls_debug_hex(4 + msg_len);
        rintls_debug("\n");
        /* TODO: ハンドシェイク断片化対応 - 現在はエラー */
        return TLS_HS_ERR_UNEXPECTED;
    }

    const u8* p = msg + 4;
    const u8* end = p + msg_len;

    if (p + 4 > end) return TLS_HS_ERR_UNEXPECTED;
    u16 sig_scheme = read_u16(p);
    p += 2;
    u16 sig_len = read_u16(p);
    p += 2;
    if (p + sig_len > end || sig_len > 512) return TLS_HS_ERR_UNEXPECTED;
    const u8* sig = p;

    /* RFC 8446 4.4.3: 署名対象はこのメッセージ自身を含まないTranscript-Hash
     * (このメッセージをTranscriptに加える前に取得する必要がある) */
    u8 transcript_hash[48];
    rin_size_t hash_len = ctx->use_sha384 ? 48 : 32;
    tls_transcript_hash(ctx, transcript_hash);

    /* Finished計算のためTranscriptにこのメッセージを追加 */
    tls_transcript_update(ctx, msg, 4 + msg_len);

    int verify_ok = ctx->verify_none;

    if (!verify_ok) {
        static const u8 ctx_str[] = "TLS 1.3, server CertificateVerify";
        u8 signed_data[64 + sizeof(ctx_str) - 1 + 1 + 48];
        rin_size_t pos = 64;

        rintls_memset(signed_data, 0x20, 64);
        rintls_memcpy(signed_data + pos, ctx_str, sizeof(ctx_str) - 1);
        pos += sizeof(ctx_str) - 1;
        signed_data[pos++] = 0x00;
        rintls_memcpy(signed_data + pos, transcript_hash, hash_len);
        pos += hash_len;

        u8 msg_hash[64];
        switch (sig_scheme) {
        case TLS_SIG_RSA_PSS_RSAE_SHA256:
            if (ctx->server_key_type == 0) {
                sha256(signed_data, pos, msg_hash);
                verify_ok = (rsa_pss_verify_sha256(sig, sig_len, msg_hash,
                                                    &ctx->server_rsa_key) == RSA_OK);
            }
            break;
        case TLS_SIG_ECDSA_SECP256R1_SHA256:
            if (ctx->server_key_type == 1 &&
                ctx->server_ecdsa_curve == ECDSA_CURVE_P256) {
                sha256(signed_data, pos, msg_hash);
                verify_ok = (ecdsa_nist_verify(ECDSA_CURVE_P256,
                                               sig, sig_len, msg_hash, 32,
                                               ctx->server_ecdsa_key,
                                               ctx->server_ecdsa_key_len) == ECDH_OK);
            }
            break;
        case TLS_SIG_ECDSA_SECP384R1_SHA384:
            if (ctx->server_key_type == 1 &&
                ctx->server_ecdsa_curve == ECDSA_CURVE_P384) {
                sha384(signed_data, pos, msg_hash);
                verify_ok = (ecdsa_nist_verify(ECDSA_CURVE_P384,
                                               sig, sig_len, msg_hash, 48,
                                               ctx->server_ecdsa_key,
                                               ctx->server_ecdsa_key_len) == ECDH_OK);
            }
            break;
        case TLS_SIG_ECDSA_SECP521R1_SHA512:
            if (ctx->server_key_type == 1 &&
                ctx->server_ecdsa_curve == ECDSA_CURVE_P521) {
                sha512(signed_data, pos, msg_hash);
                verify_ok = (ecdsa_nist_verify(ECDSA_CURVE_P521,
                                               sig, sig_len, msg_hash, 64,
                                               ctx->server_ecdsa_key,
                                               ctx->server_ecdsa_key_len) == ECDH_OK);
            }
            break;
        default:
            rintls_debug("[TLS] Unsupported CertificateVerify signature scheme: ");
            rintls_debug_hex(sig_scheme);
            rintls_debug("\n");
            break;
        }
    }

    if (!verify_ok) {
        rintls_debug("[TLS] CertificateVerify signature check failed\n");
        ctx->last_error = TLS_HS_ERR_SIGNATURE;
        ctx->state = TLS_STATE_ERROR;
        return TLS_HS_ERR_SIGNATURE;
    }

    ctx->state = TLS_STATE_CERTIFICATE_VERIFY;
    return TLS_HS_ERR_OK;
}

int tls_recv_finished(tls_handshake_ctx_t* ctx)
{
    u8 msg[16384];  /* TLS_MAX_RECORD_SIZE - multiple msgs may be in one record */
    u8 content_type;
    int len;

    /* Both TLS 1.2 and TLS 1.3 use tls_record_recv which handles decryption */
    len = tls_record_recv(ctx->record, &content_type, msg, sizeof(msg));

    if (len < 0) return tls_handshake_map_io_error(len);

    if (content_type != TLS_CONTENT_HANDSHAKE) {
        return TLS_HS_ERR_UNEXPECTED;
    }

    if (len < 4 || msg[0] != TLS_HS_FINISHED) {
        rintls_debug("[TLS] Expected Finished, got type=");
        rintls_debug_hex(msg[0]);
        rintls_debug("\n");
        return TLS_HS_ERR_UNEXPECTED;
    }

    u32 msg_len = read_u24(msg + 1);

    /* 長さ検証: 受信したデータがメッセージ全体を含むか確認 */
    if ((u32)len < 4 + msg_len) {
        rintls_debug("[TLS] Finished fragmented! len=");
        rintls_debug_hex((u32)len);
        rintls_debug(" expected=");
        rintls_debug_hex(4 + msg_len);
        rintls_debug("\n");
        /* TODO: ハンドシェイク断片化対応 - 現在はエラー */
        return TLS_HS_ERR_UNEXPECTED;
    }
    if (msg_len != (ctx->is_tls13 ? 32u : 12u)) {
        return TLS_HS_ERR_VERIFY;
    }

    if (ctx->is_tls13) {
        /* TLS 1.3: ServerFinished検証 (トランスクリプトに追加する前に検証)
         * volatile を使用してコンパイラ最適化による破壊を防止 */
        volatile u8 finished_key[32];
        volatile u8 transcript_hash[32];
        volatile u8 expected_verify_data[32];

        /* HKDF前にトランスクリプトハッシュを取得して保存 (最適化防止) */
        {
            u8 pre_hash[32];
            tls_transcript_hash(ctx, pre_hash);
            /* volatileにバイト単位でコピー */
            for (int i = 0; i < 32; i++) {
                transcript_hash[i] = pre_hash[i];
            }
        }

        /* finished_key = HKDF-Expand-Label(server_hs_traffic_secret, "finished", "", 32)
         * 一時バッファに出力してからvolatileにコピー */
        {
            u8 tmp_key[32];
            tls13_hkdf_expand_label(ctx->server_handshake_traffic_secret,
                                     TLS13_LABEL_FINISHED, 8,
                                     RIN_NULL, 0,
                                     tmp_key, 32);
            /* volatileにバイト単位でコピー */
            for (int i = 0; i < 32; i++) {
                finished_key[i] = tmp_key[i];
            }
        }

        /* expected_verify_data = HMAC(finished_key, transcript_hash)
         * volatileから非volatileにコピーしてHMAC呼び出し */
        {
            u8 key_copy[32];
            u8 hash_copy[32];
            u8 tmp_verify[32];
            for (int i = 0; i < 32; i++) {
                key_copy[i] = finished_key[i];
                hash_copy[i] = transcript_hash[i];
            }
            hmac_sha256(key_copy, 32, hash_copy, 32, tmp_verify);
            /* 結果をvolatileにコピー */
            for (int i = 0; i < 32; i++) {
                expected_verify_data[i] = tmp_verify[i];
            }
        }

        /* 検証: 受信したverify_dataと期待値を比較 */
        u8 difference = 0;
        for (int i = 0; i < 32; i++) {
            difference |= (u8)(msg[4 + i] ^ expected_verify_data[i]);
        }

        if (difference != 0) {
            rintls_debug("[TLS] ServerFinished VERIFY FAILED!\n");
            return TLS_HS_ERR_VERIFY;
        }
        rintls_debug("[TLS] ServerFinished VERIFY OK!\n");
    } else {
        /* TLS 1.2: verify_data = PRF(master_secret, "server finished", Hash(handshake_messages))[0..11] */
        u8 transcript_hash[32];
        u8 expected_verify_data[12];

        tls_transcript_hash(ctx, transcript_hash);

        tls12_prf_sha256(ctx->master_secret, 48,
                          (const u8*)"server finished", 15,
                          transcript_hash, 32,
                          expected_verify_data, 12);

        /* 検証 */
        u8 difference = 0;
        for (int i = 0; i < 12; i++) {
            difference |= (u8)(msg[4 + i] ^ expected_verify_data[i]);
        }

        if (difference != 0) {
            rintls_debug("[TLS12] ServerFinished VERIFY FAILED!\n");
            return TLS_HS_ERR_VERIFY;
        }
        rintls_debug("[TLS12] ServerFinished VERIFY OK!\n");
    }

    tls_transcript_update(ctx, msg, 4 + msg_len);

    ctx->state = TLS_STATE_FINISHED_RECEIVED;
    return TLS_HS_ERR_OK;
}

int tls_send_finished(tls_handshake_ctx_t* ctx)
{
    if (ctx->pending_send_kind != TLS_PENDING_SEND_NONE) {
        return tls_handshake_flush_pending_send(ctx, TLS_PENDING_SEND_FINISHED);
    }

    u8 msg[256];
    rin_size_t pos = 0;
    rin_size_t verify_data_len;

    /* Verify Dataを計算 */
    u8 verify_data[32];
    u8 finished_key[32];
    u8 transcript[32];

    if (ctx->is_tls13) {
        tls_transcript_hash(ctx, ctx->server_finished_transcript);

        tls13_hkdf_expand_label(ctx->client_handshake_traffic_secret,
                                 TLS13_LABEL_FINISHED, 8,
                                 RIN_NULL, 0,
                                 finished_key, 32);

        tls_transcript_hash(ctx, transcript);

        hmac_sha256(finished_key, 32, transcript, 32, verify_data);
        verify_data_len = 32;
    } else {
        /* TLS 1.2: verify_data = PRF(master_secret, "client finished", Hash(handshake_messages))[0..11] */
        tls_transcript_hash(ctx, transcript);

        tls12_prf_sha256(ctx->master_secret, 48,
                          (const u8*)"client finished", 15,
                          transcript, 32,
                          verify_data, 12);
        verify_data_len = 12;

    }

    /* Finishedメッセージを構築 */
    msg[pos++] = TLS_HS_FINISHED;
    write_u24(msg + pos, verify_data_len);
    pos += 3;
    rintls_memcpy(msg + pos, verify_data, verify_data_len);
    pos += verify_data_len;

    int ret = tls_handshake_stage_pending_send(ctx,
                                               TLS_PENDING_SEND_FINISHED,
                                               1,
                                               TLS_CONTENT_HANDSHAKE,
                                               ctx->version,
                                               msg,
                                               pos,
                                               1,
                                               TLS_STATE_FINISHED_SENT);
    if (ret != TLS_HS_ERR_OK) {
        return ret;
    }

    return tls_handshake_flush_pending_send(ctx, TLS_PENDING_SEND_FINISHED);
}

/* ═══════════════════════════════════════
 * TLSハンドシェイク実行
 * ═══════════════════════════════════════ */

int tls_handshake_client(tls_handshake_ctx_t* ctx)
{
    int ret;

    /* ClientHello送信 */
    ret = tls_send_client_hello(ctx);
    if (ret != TLS_HS_ERR_OK) return ret;

    /* ServerHello受信 */
    ret = tls_recv_server_hello(ctx);
    if (ret != TLS_HS_ERR_OK) return ret;

    if (ctx->is_tls13) {
        /* TLS 1.3ハンドシェイク */

        /* EncryptedExtensions受信 */
        ret = tls_recv_encrypted_extensions(ctx);
        if (ret != TLS_HS_ERR_OK) return ret;

        /* CertificateRequest is optional and precedes the server
         * Certificate.  When present, answer it before continuing. */
        ret = tls_recv_certificate(ctx);
        if (ret != TLS_HS_ERR_OK) return ret;
        if (ctx->state == TLS_STATE_CLIENT_CERTIFICATE) {
            ret = tls_send_client_certificate(ctx);
            if (ret != TLS_HS_ERR_OK) return ret;
            ret = tls_send_client_certificate_verify(ctx);
            if (ret != TLS_HS_ERR_OK) return ret;
            ret = tls_recv_certificate(ctx);
            if (ret != TLS_HS_ERR_OK) return ret;
        }

        /* CertificateVerify受信 */
        ret = tls_recv_certificate_verify(ctx);
        if (ret != TLS_HS_ERR_OK) return ret;

        /* Finished受信 */
        ret = tls_recv_finished(ctx);
        if (ret != TLS_HS_ERR_OK) return ret;

        /* アプリケーション鍵導出用のトランスクリプトハッシュを保存
         * (RFC 8446: ClientHello...server Finished、client Finishedを含まない) */
        tls_transcript_hash(ctx, ctx->server_finished_transcript);
        rintls_debug("[TLS] Saved server_finished_transcript[0-3]: ");
        rintls_debug_hex(ctx->server_finished_transcript[0]);
        rintls_debug(" ");
        rintls_debug_hex(ctx->server_finished_transcript[1]);
        rintls_debug(" ");
        rintls_debug_hex(ctx->server_finished_transcript[2]);
        rintls_debug(" ");
        rintls_debug_hex(ctx->server_finished_transcript[3]);
        rintls_debug("\n");

        /* CCS送信 (TLS 1.3 middlebox互換性 - RFC 8446 Appendix D.4) */
        ret = tls_send_change_cipher_spec(ctx);
        if (ret != TLS_HS_ERR_OK) return ret;

        /* Finished送信 (ハンドシェイク鍵で暗号化) */
        ret = tls_send_finished(ctx);
        if (ret != TLS_HS_ERR_OK) return ret;

        /* アプリケーション鍵を導出 (保存したトランスクリプトを使用) */
        ret = tls13_derive_application_keys(ctx);
        if (ret != TLS_HS_ERR_OK) return ret;

    } else {
        /* TLS 1.2ハンドシェイク */
        rintls_debug("[TLS] TLS 1.2 handshake starting...\n");

        /* Certificate受信 */
        ret = tls_recv_certificate(ctx);
        if (ret != TLS_HS_ERR_OK) {
            rintls_debug("[TLS12] Certificate recv failed, ret=");
            rintls_debug_hex(ret);
            rintls_debug("\n");
            return ret;
        }

        /* ServerKeyExchange受信 */
        ret = tls_recv_server_key_exchange(ctx);
        if (ret != TLS_HS_ERR_OK) {
            rintls_debug("[TLS12] ServerKeyExchange recv failed, ret=");
            rintls_debug_hex(ret);
            rintls_debug("\n");
            return ret;
        }

        /* ServerHelloDone受信 */
        ret = tls_recv_server_hello_done(ctx);
        if (ret != TLS_HS_ERR_OK) {
            rintls_debug("[TLS12] ServerHelloDone recv failed, ret=");
            rintls_debug_hex(ret);
            rintls_debug("\n");
            return ret;
        }

        /* ClientKeyExchange送信 */
        ret = tls_send_client_key_exchange(ctx);
        if (ret != TLS_HS_ERR_OK) {
            rintls_debug("[TLS12] ClientKeyExchange send failed, ret=");
            rintls_debug_hex(ret);
            rintls_debug("\n");
            return ret;
        }

        /* マスターシークレット導出 */
        ret = tls12_derive_master_secret(ctx);
        if (ret != TLS_HS_ERR_OK) {
            rintls_debug("[TLS12] Master secret derivation failed, ret=");
            rintls_debug_hex(ret);
            rintls_debug("\n");
            return ret;
        }

        /* 鍵導出・設定 */
        ret = tls12_derive_keys(ctx);
        if (ret != TLS_HS_ERR_OK) {
            rintls_debug("[TLS12] Key derivation failed, ret=");
            rintls_debug_hex(ret);
            rintls_debug("\n");
            return ret;
        }

        /* ChangeCipherSpec送信 */
        ret = tls_send_change_cipher_spec(ctx);
        if (ret != TLS_HS_ERR_OK) {
            rintls_debug("[TLS12] ChangeCipherSpec send failed, ret=");
            rintls_debug_hex(ret);
            rintls_debug("\n");
            return ret;
        }

        /* Finished送信 */
        ret = tls_send_finished(ctx);
        if (ret != TLS_HS_ERR_OK) {
            rintls_debug("[TLS12] Finished send failed, ret=");
            rintls_debug_hex(ret);
            rintls_debug("\n");
            return ret;
        }

        /* ChangeCipherSpec受信 */
        ret = tls_recv_change_cipher_spec(ctx);
        if (ret != TLS_HS_ERR_OK) {
            rintls_debug("[TLS12] ChangeCipherSpec recv failed, ret=");
            rintls_debug_hex(ret);
            rintls_debug("\n");
            return ret;
        }

        /* Finished受信 */
        ret = tls_recv_finished(ctx);
        if (ret != TLS_HS_ERR_OK) {
            rintls_debug("[TLS12] Finished recv failed, ret=");
            rintls_debug_hex(ret);
            rintls_debug("\n");
            return ret;
        }

        rintls_debug("[TLS12] Handshake completed!\n");
    }

    ctx->state = TLS_STATE_CONNECTED;
    return TLS_HS_ERR_OK;
}

/* ═══════════════════════════════════════
 * TLS 1.2 PRF (Pseudo-Random Function)
 * RFC 5246 Section 5
 * ═══════════════════════════════════════ */

/*
 * P_SHA256(secret, seed) = HMAC(secret, A(1) + seed) +
 *                          HMAC(secret, A(2) + seed) + ...
 * A(0) = seed
 * A(i) = HMAC(secret, A(i-1))
 */
static void tls12_prf_sha256(const u8* secret, rin_size_t secret_len,
                              const u8* label, rin_size_t label_len,
                              const u8* seed, rin_size_t seed_len,
                              u8* out, rin_size_t out_len)
{
    u8 a[32];  /* A(i) */
    u8 p[32];  /* P_SHA256 output block */
    u8 seed_full[256];  /* label + seed */
    rin_size_t seed_full_len;
    rin_size_t pos = 0;

    /* seed_full = label + seed */
    seed_full_len = label_len + seed_len;
    rintls_memcpy(seed_full, label, label_len);
    rintls_memcpy(seed_full + label_len, seed, seed_len);

    /* A(1) = HMAC(secret, seed_full) */
    hmac_sha256(secret, secret_len, seed_full, seed_full_len, a);

    while (pos < out_len) {
        /* P = HMAC(secret, A(i) + seed_full) */
        u8 a_seed[256 + 32];
        rintls_memcpy(a_seed, a, 32);
        rintls_memcpy(a_seed + 32, seed_full, seed_full_len);
        hmac_sha256(secret, secret_len, a_seed, 32 + seed_full_len, p);

        /* Copy to output */
        rin_size_t copy_len = out_len - pos;
        if (copy_len > 32) copy_len = 32;
        rintls_memcpy(out + pos, p, copy_len);
        pos += copy_len;

        /* A(i+1) = HMAC(secret, A(i)) */
        hmac_sha256(secret, secret_len, a, 32, a);
    }
}

/* ═══════════════════════════════════════
 * TLS 1.2 ServerKeyExchange受信
 * ═══════════════════════════════════════ */

int tls_recv_server_key_exchange(tls_handshake_ctx_t* ctx)
{
    u8 msg[4096];
    u8 content_type;
    u16 record_version;

    int len = tls_record_recv_raw(ctx->record, &content_type, &record_version,
                                   msg, sizeof(msg));
    if (len < 0) return tls_handshake_map_io_error(len);

    if (content_type != TLS_CONTENT_HANDSHAKE) {
        return TLS_HS_ERR_UNEXPECTED;
    }

    if (len < 4 || msg[0] != TLS_HS_SERVER_KEY_EXCHANGE) {
        rintls_debug("[TLS12] Expected ServerKeyExchange, got type=");
        rintls_debug_hex(msg[0]);
        rintls_debug("\n");
        return TLS_HS_ERR_UNEXPECTED;
    }

    u32 msg_len = read_u24(msg + 1);
    if ((u32)len < 4 + msg_len) return TLS_HS_ERR_UNEXPECTED;

    /* Transcriptに追加 */
    tls_transcript_update(ctx, msg, 4 + msg_len);

    const u8* p = msg + 4;
    const u8* end = p + msg_len;
    const u8* params_start = p;

    /* ECDHE ServerKeyExchange structure:
     * - curve_type (1 byte) = 0x03 (named_curve)
     * - named_curve (2 bytes)
     * - public_key_length (1 byte)
     * - public_key (variable)
     * - signature_algorithm (2 bytes) - TLS 1.2
     * - signature_length (2 bytes)
     * - signature (variable)
     */

    if (p + 1 > end) return TLS_HS_ERR_UNEXPECTED;
    u8 curve_type = *p++;
    if (curve_type != 0x03) {  /* named_curve */
        rintls_debug("[TLS12] Unsupported curve type: ");
        rintls_debug_hex(curve_type);
        rintls_debug("\n");
        return TLS_HS_ERR_KEY_EXCHANGE;
    }

    if (p + 2 > end) return TLS_HS_ERR_UNEXPECTED;
    ctx->named_group = read_u16(p);
    p += 2;

    rintls_debug("[TLS12] ServerKeyExchange named_group=");
    rintls_debug_hex(ctx->named_group);
    rintls_debug("\n");

    if (p + 1 > end) return TLS_HS_ERR_UNEXPECTED;
    u8 pubkey_len = *p++;

    if (p + pubkey_len > end) return TLS_HS_ERR_UNEXPECTED;
    if (pubkey_len > sizeof(ctx->peer_public_key)) return TLS_HS_ERR_KEY_EXCHANGE;

    rintls_memcpy(ctx->peer_public_key, p, pubkey_len);
    ctx->peer_public_key_len = pubkey_len;
    p += pubkey_len;

    rintls_debug("[TLS12] Server pubkey len=");
    rintls_debug_hex(pubkey_len);
    rintls_debug(" data: ");
    for (int i = 0; i < 8 && i < pubkey_len; i++) {
        rintls_debug_hex(ctx->peer_public_key[i]);
        rintls_debug(" ");
    }
    rintls_debug("...\n");

    const u8* params_end = p;

    if (p + 4 > end) return TLS_HS_ERR_UNEXPECTED;
    u16 sig_alg = read_u16(p);
    p += 2;
    u16 sig_len = read_u16(p);
    p += 2;
    if (p + sig_len > end || sig_len > 512) return TLS_HS_ERR_UNEXPECTED;
    const u8* sig = p;

    int verify_ok = ctx->verify_none;

    if (!verify_ok) {
        /* 署名対象: client_random || server_random || ServerECDHParams (RFC 5246 7.4.3) */
        u8 hash[64];

        switch (sig_alg) {
        case TLS_SIG_RSA_PKCS1_SHA256:
            if (ctx->server_key_type == 0) {
                sha256_ctx h;
                sha256_init(&h);
                sha256_update(&h, ctx->client_random, 32);
                sha256_update(&h, ctx->server_random, 32);
                sha256_update(&h, params_start, (rin_size_t)(params_end - params_start));
                sha256_final(&h, hash);
                verify_ok = (rsa_pkcs1_verify(sig, sig_len, hash, 32, RSA_HASH_SHA256,
                                               &ctx->server_rsa_key) == RSA_OK);
            }
            break;
        case TLS_SIG_RSA_PSS_RSAE_SHA256:
            if (ctx->server_key_type == 0) {
                sha256_ctx h;
                sha256_init(&h);
                sha256_update(&h, ctx->client_random, 32);
                sha256_update(&h, ctx->server_random, 32);
                sha256_update(&h, params_start, (rin_size_t)(params_end - params_start));
                sha256_final(&h, hash);
                verify_ok = (rsa_pss_verify_sha256(sig, sig_len, hash,
                                                    &ctx->server_rsa_key) == RSA_OK);
            }
            break;
        case TLS_SIG_ECDSA_SECP256R1_SHA256:
            if (ctx->server_key_type == 1 &&
                ctx->server_ecdsa_curve == ECDSA_CURVE_P256) {
                sha256_ctx h;
                sha256_init(&h);
                sha256_update(&h, ctx->client_random, 32);
                sha256_update(&h, ctx->server_random, 32);
                sha256_update(&h, params_start, (rin_size_t)(params_end - params_start));
                sha256_final(&h, hash);
                verify_ok = (ecdsa_nist_verify(ECDSA_CURVE_P256,
                                               sig, sig_len, hash, 32,
                                               ctx->server_ecdsa_key,
                                               ctx->server_ecdsa_key_len) == ECDH_OK);
            }
            break;
        case TLS_SIG_ECDSA_SECP384R1_SHA384:
            if (ctx->server_key_type == 1 &&
                ctx->server_ecdsa_curve == ECDSA_CURVE_P384) {
                sha384_ctx h;
                sha384_init(&h);
                sha384_update(&h, ctx->client_random, 32);
                sha384_update(&h, ctx->server_random, 32);
                sha384_update(&h, params_start, (rin_size_t)(params_end - params_start));
                sha384_final(&h, hash);
                verify_ok = (ecdsa_nist_verify(ECDSA_CURVE_P384,
                                               sig, sig_len, hash, 48,
                                               ctx->server_ecdsa_key,
                                               ctx->server_ecdsa_key_len) == ECDH_OK);
            }
            break;
        case TLS_SIG_ECDSA_SECP521R1_SHA512:
            if (ctx->server_key_type == 1 &&
                ctx->server_ecdsa_curve == ECDSA_CURVE_P521) {
                sha512_ctx h;
                sha512_init(&h);
                sha512_update(&h, ctx->client_random, 32);
                sha512_update(&h, ctx->server_random, 32);
                sha512_update(&h, params_start, (rin_size_t)(params_end - params_start));
                sha512_final(&h, hash);
                verify_ok = (ecdsa_nist_verify(ECDSA_CURVE_P521,
                                               sig, sig_len, hash, 64,
                                               ctx->server_ecdsa_key,
                                               ctx->server_ecdsa_key_len) == ECDH_OK);
            }
            break;
        default:
            rintls_debug("[TLS12] Unsupported ServerKeyExchange signature algorithm: ");
            rintls_debug_hex(sig_alg);
            rintls_debug("\n");
            break;
        }
    }

    if (!verify_ok) {
        rintls_debug("[TLS12] ServerKeyExchange signature verification failed\n");
        ctx->last_error = TLS_HS_ERR_SIGNATURE;
        ctx->state = TLS_STATE_ERROR;
        return TLS_HS_ERR_SIGNATURE;
    }

    ctx->state = TLS_STATE_SERVER_KEY_EXCHANGE;
    return TLS_HS_ERR_OK;
}

/* ═══════════════════════════════════════
 * TLS 1.2 ServerHelloDone受信
 * ═══════════════════════════════════════ */

int tls_recv_server_hello_done(tls_handshake_ctx_t* ctx)
{
    u8 msg[256];
    u8 content_type;
    u16 record_version;

    int len = tls_record_recv_raw(ctx->record, &content_type, &record_version,
                                   msg, sizeof(msg));
    if (len < 0) return tls_handshake_map_io_error(len);

    if (content_type != TLS_CONTENT_HANDSHAKE) {
        return TLS_HS_ERR_UNEXPECTED;
    }

    if (len >= 4 && msg[0] == TLS_HS_CERTIFICATE_REQUEST) {
        /* Parse and fail closed for TLS 1.2 mutual authentication.  The
         * parser records the request in the transcript so diagnostics remain
         * faithful, but no unauthenticated client certificate is emitted. */
        return tls_recv_certificate_request(ctx, msg, (rin_size_t)len);
    }
    if (len < 4 || msg[0] != TLS_HS_SERVER_HELLO_DONE) {
        rintls_debug("[TLS12] Expected ServerHelloDone, got type=");
        rintls_debug_hex(msg[0]);
        rintls_debug("\n");
        return TLS_HS_ERR_UNEXPECTED;
    }

    u32 msg_len = read_u24(msg + 1);
    /* ServerHelloDone should have 0 length */

    /* Transcriptに追加 */
    tls_transcript_update(ctx, msg, 4 + msg_len);

    rintls_debug("[TLS12] ServerHelloDone received\n");

    ctx->state = TLS_STATE_SERVER_HELLO_DONE;
    return TLS_HS_ERR_OK;
}

/* ═══════════════════════════════════════
 * TLS 1.2 ClientKeyExchange送信
 * ═══════════════════════════════════════ */

int tls_send_client_key_exchange(tls_handshake_ctx_t* ctx)
{
    if (ctx->pending_send_kind != TLS_PENDING_SEND_NONE) {
        return tls_handshake_flush_pending_send(ctx, TLS_PENDING_SEND_CLIENT_KEY_EXCHANGE);
    }

    u8 msg[256];
    rin_size_t pos = 0;

    /* ECDHE ClientKeyExchange:
     * - public_key_length (1 byte)
     * - public_key (variable)
     */

    u8 pubkey[65];
    rin_size_t pubkey_len = 0;

    if (ctx->named_group == TLS_GROUP_X25519) {
        /* X25519鍵ペアを生成 */
        if (x25519_keygen(&ctx->x25519_keypair) != ECDH_OK) {
            return TLS_HS_ERR_RANDOM;
        }
        rintls_memcpy(pubkey, ctx->x25519_keypair.public_key, 32);
        pubkey_len = 32;

        /* 共有秘密を計算 */
        if (x25519_ecdh(ctx->shared_secret,
                        ctx->x25519_keypair.private_key,
                        ctx->peer_public_key) != ECDH_OK) {
            return TLS_HS_ERR_KEY_EXCHANGE;
        }
        ctx->shared_secret_len = 32;

        rintls_debug("[TLS12] X25519 ECDH computed\n");
    } else if (ctx->named_group == TLS_GROUP_SECP256R1) {
        /* P-256鍵ペアを生成 */
        if (p256_keygen(&ctx->p256_keypair) != ECDH_OK) {
            return TLS_HS_ERR_RANDOM;
        }
        rintls_memcpy(pubkey, ctx->p256_keypair.public_key, 65);
        pubkey_len = 65;

        /* 共有秘密を計算 */
        /* P-256 peer public keyは04 || X || Y形式 */
        if (ctx->peer_public_key[0] != 0x04 || ctx->peer_public_key_len != 65) {
            rintls_debug("[TLS12] Invalid P-256 peer public key format\n");
            return TLS_HS_ERR_KEY_EXCHANGE;
        }
        if (p256_ecdh(ctx->shared_secret,
                      ctx->p256_keypair.private_key,
                      ctx->peer_public_key,
                      ctx->peer_public_key_len) != ECDH_OK) {
            return TLS_HS_ERR_KEY_EXCHANGE;
        }
        ctx->shared_secret_len = 32;

        rintls_debug("[TLS12] P-256 ECDH computed\n");
    } else {
        rintls_debug("[TLS12] Unsupported named_group: ");
        rintls_debug_hex(ctx->named_group);
        rintls_debug("\n");
        return TLS_HS_ERR_KEY_EXCHANGE;
    }

    /* ClientKeyExchangeメッセージを構築 */
    msg[pos++] = TLS_HS_CLIENT_KEY_EXCHANGE;
    write_u24(msg + pos, pubkey_len + 1);  /* length */
    pos += 3;
    msg[pos++] = (u8)pubkey_len;  /* public key length */
    rintls_memcpy(msg + pos, pubkey, pubkey_len);
    pos += pubkey_len;

    int ret = tls_handshake_stage_pending_send(ctx,
                                               TLS_PENDING_SEND_CLIENT_KEY_EXCHANGE,
                                               0,
                                               TLS_CONTENT_HANDSHAKE,
                                               TLS_VERSION_1_2,
                                               msg,
                                               pos,
                                               1,
                                               TLS_STATE_CLIENT_KEY_EXCHANGE_SENT);
    if (ret != TLS_HS_ERR_OK) {
        return ret;
    }

    ret = tls_handshake_flush_pending_send(ctx, TLS_PENDING_SEND_CLIENT_KEY_EXCHANGE);
    if (ret != TLS_HS_ERR_OK) {
        return ret;
    }

    rintls_debug("[TLS12] ClientKeyExchange sent, pubkey_len=");
    rintls_debug_hex(pubkey_len);
    rintls_debug("\n");

    return TLS_HS_ERR_OK;
}

/* ═══════════════════════════════════════
 * TLS 1.2 マスターシークレット導出
 * ═══════════════════════════════════════ */

int tls12_derive_master_secret(tls_handshake_ctx_t* ctx)
{
    /* master_secret = PRF(pre_master_secret, "master secret",
     *                     ClientHello.random + ServerHello.random)[0..47] */
    u8 seed[64];
    rintls_memcpy(seed, ctx->client_random, 32);
    rintls_memcpy(seed + 32, ctx->server_random, 32);

    tls12_prf_sha256(ctx->shared_secret, ctx->shared_secret_len,
                      (const u8*)"master secret", 13,
                      seed, 64,
                      ctx->master_secret, 48);

    return TLS_HS_ERR_OK;
}

/* ═══════════════════════════════════════
 * TLS 1.2 鍵導出・設定
 * ═══════════════════════════════════════ */

int tls12_derive_keys(tls_handshake_ctx_t* ctx)
{
    /* key_block = PRF(master_secret, "key expansion",
     *                 ServerHello.random + ClientHello.random)
     *
     * For AES-128-GCM:
     * - client_write_key (16 bytes)
     * - server_write_key (16 bytes)
     * - client_write_iv (4 bytes) - implicit IV
     * - server_write_iv (4 bytes) - implicit IV
     */
    u8 seed[64];
    u8 key_block[72];  /* 16 + 16 + 4 + 4 = 40, but PRF outputs in 32-byte blocks */

    rintls_memcpy(seed, ctx->server_random, 32);
    rintls_memcpy(seed + 32, ctx->client_random, 32);

    tls12_prf_sha256(ctx->master_secret, 48,
                      (const u8*)"key expansion", 13,
                      seed, 64,
                      key_block, 40);

    u8* client_write_key = key_block;
    u8* server_write_key = key_block + 16;
    u8* client_write_iv = key_block + 32;
    u8* server_write_iv = key_block + 36;

    /* レコード層に暗号化を設定 */
    tls_record_enable_cipher_1_2(ctx->record, TLS_CIPHER_AES_128_GCM,
                                  server_write_key, 16, server_write_iv, 4, 0);
    tls_record_enable_cipher_1_2(ctx->record, TLS_CIPHER_AES_128_GCM,
                                  client_write_key, 16, client_write_iv, 4, 1);

    return TLS_HS_ERR_OK;
}

/* ═══════════════════════════════════════
 * TLS 1.2 ChangeCipherSpec送受信
 * ═══════════════════════════════════════ */

int tls_send_change_cipher_spec(tls_handshake_ctx_t* ctx)
{
    if (ctx->pending_send_kind != TLS_PENDING_SEND_NONE) {
        return tls_handshake_flush_pending_send(ctx, TLS_PENDING_SEND_CHANGE_CIPHER_SPEC);
    }

    u8 ccs[1] = {0x01};

    int ret = tls_handshake_stage_pending_send(ctx,
                                               TLS_PENDING_SEND_CHANGE_CIPHER_SPEC,
                                               0,
                                               TLS_CONTENT_CHANGE_CIPHER_SPEC,
                                               TLS_VERSION_1_2,
                                               ccs,
                                               1,
                                               0,
                                               TLS_STATE_CHANGE_CIPHER_SPEC);
    if (ret != TLS_HS_ERR_OK) {
        return ret;
    }

    ret = tls_handshake_flush_pending_send(ctx, TLS_PENDING_SEND_CHANGE_CIPHER_SPEC);
    if (ret != TLS_HS_ERR_OK) {
        return ret;
    }

    rintls_debug("[TLS12] ChangeCipherSpec sent\n");
    return TLS_HS_ERR_OK;
}

int tls_recv_change_cipher_spec(tls_handshake_ctx_t* ctx)
{
    u8 msg[16];
    u8 content_type;
    u16 record_version;

    int len = tls_record_recv_raw(ctx->record, &content_type, &record_version,
                                   msg, sizeof(msg));
    if (len < 0) return tls_handshake_map_io_error(len);

    if (content_type != TLS_CONTENT_CHANGE_CIPHER_SPEC) {
        rintls_debug("[TLS12] Expected ChangeCipherSpec, got type=");
        rintls_debug_hex(content_type);
        rintls_debug("\n");
        return TLS_HS_ERR_UNEXPECTED;
    }

    if (len != 1 || msg[0] != 0x01) {
        return TLS_HS_ERR_UNEXPECTED;
    }

    rintls_debug("[TLS12] ChangeCipherSpec received\n");

    return TLS_HS_ERR_OK;
}
