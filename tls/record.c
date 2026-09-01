/*
 * rinTLS - TLSレコード層
 * RFC 5246 (TLS 1.2) および RFC 8446 (TLS 1.3) 準拠
 */

#include "record.h"
#include "../platform/rin_platform.h"

#define TLS_RAW_RECV_PHASE_IDLE    0
#define TLS_RAW_RECV_PHASE_HEADER  1
#define TLS_RAW_RECV_PHASE_BODY    2

/* ═══════════════════════════════════════
 * 初期化
 * ═══════════════════════════════════════ */

static void tls_cipher_init(tls_cipher_ctx_t* cipher)
{
    rintls_memset(cipher, 0, sizeof(tls_cipher_ctx_t));
    cipher->type = TLS_CIPHER_NULL;
    cipher->seq_num = 0;
}

static void tls_record_reset_raw_recv_state(tls_record_ctx_t* ctx)
{
    ctx->raw_recv_phase = TLS_RAW_RECV_PHASE_IDLE;
    ctx->raw_recv_header_len = 0;
    ctx->raw_recv_content_type = 0;
    ctx->raw_recv_version = 0;
    ctx->raw_recv_expected_len = 0;
    ctx->read_buffer_len = 0;
}

static void tls_record_reset_raw_send_state(tls_record_ctx_t* ctx)
{
    ctx->write_buffer_len = 0;
    ctx->write_buffer_pos = 0;
    ctx->write_payload_len = 0;
    ctx->write_in_progress = 0;
    ctx->write_pending_seq_advance = 0;
}

static int tls_record_flush_pending_send(tls_record_ctx_t* ctx)
{
    while (ctx->write_buffer_pos < ctx->write_buffer_len) {
        int ret = ctx->send_func(ctx->io_ctx,
                                 ctx->write_buffer + ctx->write_buffer_pos,
                                 ctx->write_buffer_len - ctx->write_buffer_pos);
        if (ret == TLS_ERR_WANT_READ || ret == TLS_ERR_WANT_WRITE) {
            return ret;
        }
        if (ret <= 0) {
            rintls_debug("[TLS_REC] send failed, ret=");
            rintls_debug_hex(ret);
            rintls_debug(" off=");
            rintls_debug_hex((u32)ctx->write_buffer_pos);
            rintls_debug("\n");
            tls_record_reset_raw_send_state(ctx);
            return TLS_ERR_IO;
        }
        ctx->write_buffer_pos += ret;
    }

    {
        int sent_len = (int)ctx->write_payload_len;
        u8 advance_seq = ctx->write_pending_seq_advance;
        tls_record_reset_raw_send_state(ctx);
        if (advance_seq) {
            ctx->write_cipher.seq_num++;
        }
        return sent_len;
    }
}

void tls_record_init(tls_record_ctx_t* ctx)
{
    rintls_memset(ctx, 0, sizeof(tls_record_ctx_t));
    ctx->version = TLS_VERSION_1_2;
    ctx->is_tls13 = 0;

    tls_cipher_init(&ctx->read_cipher);
    tls_cipher_init(&ctx->write_cipher);

    tls_record_reset_raw_recv_state(ctx);
    tls_record_reset_raw_send_state(ctx);
    ctx->send_func = RIN_NULL;
    ctx->recv_func = RIN_NULL;
    ctx->io_ctx = RIN_NULL;

    ctx->last_alert_level = 0;
    ctx->last_alert_desc = 0;
}

void tls_record_set_io(tls_record_ctx_t* ctx,
                       int (*send_func)(void*, const u8*, rin_size_t),
                       int (*recv_func)(void*, u8*, rin_size_t),
                       void* io_ctx)
{
    ctx->send_func = send_func;
    ctx->recv_func = recv_func;
    ctx->io_ctx = io_ctx;
}

void tls_cipher_reset_seq(tls_cipher_ctx_t* cipher)
{
    cipher->seq_num = 0;
}

/* ═══════════════════════════════════════
 * 暗号化設定
 * ═══════════════════════════════════════ */

int tls_record_enable_cipher_1_2(tls_record_ctx_t* ctx,
                                  tls_cipher_type_t type,
                                  const u8* key, rin_size_t key_len,
                                  const u8* iv, rin_size_t iv_len,
                                  int is_write)
{
    tls_cipher_ctx_t* cipher = is_write ? &ctx->write_cipher : &ctx->read_cipher;

    cipher->type = type;
    cipher->seq_num = 0;

    if (type == TLS_CIPHER_AES_128_GCM) {
        if (key_len != 16 || iv_len != 4) return TLS_ERR_BUFFER;
        aes_init(&cipher->aes, key, 16);
    } else if (type == TLS_CIPHER_AES_256_GCM) {
        if (key_len != 32 || iv_len != 4) return TLS_ERR_BUFFER;
        aes_init(&cipher->aes, key, 32);
    } else if (type == TLS_CIPHER_NULL) {
        /* 暗号化なし */
    } else {
        return TLS_ERR_UNEXPECTED;
    }

    rintls_memcpy(cipher->key, key, key_len);
    rintls_memcpy(cipher->iv, iv, iv_len);
    cipher->key_len = key_len;
    cipher->iv_len = iv_len;

    return TLS_ERR_OK;
}

int tls_record_enable_cipher_1_3(tls_record_ctx_t* ctx,
                                  tls_cipher_type_t type,
                                  const u8* key, rin_size_t key_len,
                                  const u8* iv, rin_size_t iv_len,
                                  int is_write)
{
    tls_cipher_ctx_t* cipher = is_write ? &ctx->write_cipher : &ctx->read_cipher;

    cipher->type = type;
    cipher->seq_num = 0;

    if (type == TLS_CIPHER_AES_128_GCM) {
        if (key_len != 16 || iv_len != 12) return TLS_ERR_BUFFER;
        aes_init(&cipher->aes, key, 16);
    } else if (type == TLS_CIPHER_AES_256_GCM) {
        if (key_len != 32 || iv_len != 12) return TLS_ERR_BUFFER;
        aes_init(&cipher->aes, key, 32);
    } else if (type == TLS_CIPHER_NULL) {
        /* 暗号化なし */
    } else {
        return TLS_ERR_UNEXPECTED;
    }

    rintls_memcpy(cipher->key, key, key_len);
    rintls_memcpy(cipher->iv, iv, iv_len);
    cipher->key_len = key_len;
    cipher->iv_len = iv_len;

    ctx->is_tls13 = 1;

    return TLS_ERR_OK;
}

/* ═══════════════════════════════════════
 * 生データ送受信
 * ═══════════════════════════════════════ */

int tls_record_send_raw(tls_record_ctx_t* ctx,
                        u8 content_type, u16 version,
                        const u8* data, rin_size_t len)
{
    if (ctx->send_func == RIN_NULL) return TLS_ERR_IO;
    if (len > TLS_MAX_CIPHERTEXT_SIZE) return TLS_ERR_RECORD_SIZE;

    if (!ctx->write_in_progress) {
        ctx->write_buffer[0] = content_type;
        ctx->write_buffer[1] = (u8)(version >> 8);
        ctx->write_buffer[2] = (u8)(version & 0xFF);
        ctx->write_buffer[3] = (u8)(len >> 8);
        ctx->write_buffer[4] = (u8)(len & 0xFF);
        if (len > 0) {
            rintls_memcpy(ctx->write_buffer + TLS_RECORD_HEADER_SIZE, data, len);
        }
        ctx->write_buffer_len = TLS_RECORD_HEADER_SIZE + len;
        ctx->write_buffer_pos = 0;
        ctx->write_payload_len = len;
        ctx->write_in_progress = 1;
        ctx->write_pending_seq_advance = 0;

        rintls_debug("[TLS_REC] send_raw type=");
        rintls_debug_hex(content_type);
        rintls_debug(" len=");
        rintls_debug_hex(len);
        rintls_debug("\n");
    }
    return tls_record_flush_pending_send(ctx);
}

int tls_record_recv_raw(tls_record_ctx_t* ctx,
                        u8* content_type, u16* version,
                        u8* data, rin_size_t max_len)
{
    if (ctx->recv_func == RIN_NULL) return TLS_ERR_IO;

    rintls_debug("[TLS_REC] recv_raw waiting...\n");

    if (ctx->raw_recv_phase == TLS_RAW_RECV_PHASE_IDLE) {
        ctx->raw_recv_phase = TLS_RAW_RECV_PHASE_HEADER;
        ctx->raw_recv_header_len = 0;
        ctx->read_buffer_len = 0;
    }

    while (ctx->raw_recv_phase == TLS_RAW_RECV_PHASE_HEADER) {
        int ret = ctx->recv_func(ctx->io_ctx,
                                 ctx->raw_recv_header + ctx->raw_recv_header_len,
                                 TLS_RECORD_HEADER_SIZE - ctx->raw_recv_header_len);
        if (ret == TLS_ERR_WANT_READ || ret == TLS_ERR_WANT_WRITE) {
            return ret;
        }
        if (ret <= 0) {
            rintls_debug("[TLS_REC] header recv failed, ret=");
            rintls_debug_hex(ret);
            rintls_debug("\n");
            if (ret == 0 && ctx->raw_recv_header_len == 0) {
                tls_record_reset_raw_recv_state(ctx);
                return TLS_ERR_CLOSED;
            }
            tls_record_reset_raw_recv_state(ctx);
            return TLS_ERR_IO;
        }
        ctx->raw_recv_header_len += ret;
        if (ctx->raw_recv_header_len < TLS_RECORD_HEADER_SIZE) {
            continue;
        }

        ctx->raw_recv_content_type = ctx->raw_recv_header[0];
        ctx->raw_recv_version =
            ((u16)ctx->raw_recv_header[1] << 8) | ctx->raw_recv_header[2];
        ctx->raw_recv_expected_len =
            ((u16)ctx->raw_recv_header[3] << 8) | ctx->raw_recv_header[4];

        rintls_debug("[TLS_REC] recv type=");
        rintls_debug_hex(ctx->raw_recv_content_type);
        rintls_debug(" ver=");
        rintls_debug_hex(ctx->raw_recv_version);
        rintls_debug(" len=");
        rintls_debug_hex(ctx->raw_recv_expected_len);
        rintls_debug("\n");

        if (ctx->raw_recv_expected_len > TLS_MAX_CIPHERTEXT_SIZE) {
            tls_record_reset_raw_recv_state(ctx);
            return TLS_ERR_RECORD_SIZE;
        }
        if (ctx->raw_recv_expected_len > max_len) {
            tls_record_reset_raw_recv_state(ctx);
            return TLS_ERR_BUFFER;
        }

        ctx->raw_recv_phase = TLS_RAW_RECV_PHASE_BODY;
        ctx->read_buffer_len = 0;
        if (ctx->raw_recv_expected_len == 0) {
            if (content_type != RIN_NULL) *content_type = ctx->raw_recv_content_type;
            if (version != RIN_NULL) *version = ctx->raw_recv_version;
            tls_record_reset_raw_recv_state(ctx);
            return 0;
        }
    }

    if (ctx->raw_recv_phase == TLS_RAW_RECV_PHASE_BODY) {
        int chunk_count = 0;
        while (ctx->read_buffer_len < ctx->raw_recv_expected_len) {
            int ret = ctx->recv_func(ctx->io_ctx,
                                     ctx->read_buffer + ctx->read_buffer_len,
                                     ctx->raw_recv_expected_len - ctx->read_buffer_len);
            if (ret == TLS_ERR_WANT_READ || ret == TLS_ERR_WANT_WRITE) {
                return ret;
            }
            if (ret <= 0) {
                rintls_debug("[TLS_REC] data recv failed, ret=");
                rintls_debug_hex(ret);
                rintls_debug(" received=");
                rintls_debug_hex((u32)ctx->read_buffer_len);
                rintls_debug(" expected=");
                rintls_debug_hex(ctx->raw_recv_expected_len);
                rintls_debug("\n");
                tls_record_reset_raw_recv_state(ctx);
                return TLS_ERR_IO;
            }
            chunk_count++;
            rintls_debug("[TLS_REC] chunk #");
            rintls_debug_hex(chunk_count);
            rintls_debug(": got ");
            rintls_debug_hex(ret);
            rintls_debug(" bytes at offset ");
            rintls_debug_hex((u32)ctx->read_buffer_len);
            rintls_debug("\n");
            ctx->read_buffer_len += ret;
        }

        /* 受信データの最初と最後をダンプ */
        if (ctx->raw_recv_expected_len >= 8) {
            rintls_debug("[TLS_REC] data[0-3]: ");
            rintls_debug_hex(ctx->read_buffer[0]); rintls_debug(" ");
            rintls_debug_hex(ctx->read_buffer[1]); rintls_debug(" ");
            rintls_debug_hex(ctx->read_buffer[2]); rintls_debug(" ");
            rintls_debug_hex(ctx->read_buffer[3]); rintls_debug("\n");
            rintls_debug("[TLS_REC] data[end-3..end]: ");
            rintls_debug_hex(ctx->read_buffer[ctx->raw_recv_expected_len - 4]); rintls_debug(" ");
            rintls_debug_hex(ctx->read_buffer[ctx->raw_recv_expected_len - 3]); rintls_debug(" ");
            rintls_debug_hex(ctx->read_buffer[ctx->raw_recv_expected_len - 2]); rintls_debug(" ");
            rintls_debug_hex(ctx->read_buffer[ctx->raw_recv_expected_len - 1]); rintls_debug("\n");
            /* TCP受信直後のチェックサム */
            u32 tcp_sum = 0;
            for (rin_size_t i = 0; i < ctx->raw_recv_expected_len; i++) {
                tcp_sum += ctx->read_buffer[i];
            }
            rintls_debug("[TLS_REC] tcp_checksum=");
            rintls_debug_hex(tcp_sum);
            rintls_debug("\n");
        }
    }

    if (content_type != RIN_NULL) *content_type = ctx->raw_recv_content_type;
    if (version != RIN_NULL) *version = ctx->raw_recv_version;
    if (ctx->raw_recv_expected_len > 0) {
        rintls_memcpy(data, ctx->read_buffer, ctx->raw_recv_expected_len);
    }
    {
        int record_len = (int)ctx->raw_recv_expected_len;
        tls_record_reset_raw_recv_state(ctx);
        return record_len;
    }
}

/* ═══════════════════════════════════════
 * TLS 1.2 暗号化・復号
 * ═══════════════════════════════════════ */

/*
 * TLS 1.2 AES-GCM暗号化
 *
 * Nonce: implicit_iv (4バイト) || explicit_nonce (8バイト)
 * AAD: seq_num (8バイト) || content_type (1バイト) || version (2バイト) || length (2バイト)
 * 出力: explicit_nonce (8バイト) || ciphertext || tag (16バイト)
 */
static int tls12_encrypt_gcm(tls_cipher_ctx_t* cipher,
                             u8 content_type, u16 version,
                             const u8* plaintext, rin_size_t plaintext_len,
                             u8* output, rin_size_t* output_len)
{
    u8 nonce[12];
    u8 aad[13];
    u8 explicit_nonce[8];

    /* 明示的Nonceを生成 (シーケンス番号を使用) */
    explicit_nonce[0] = (u8)(cipher->seq_num >> 56);
    explicit_nonce[1] = (u8)(cipher->seq_num >> 48);
    explicit_nonce[2] = (u8)(cipher->seq_num >> 40);
    explicit_nonce[3] = (u8)(cipher->seq_num >> 32);
    explicit_nonce[4] = (u8)(cipher->seq_num >> 24);
    explicit_nonce[5] = (u8)(cipher->seq_num >> 16);
    explicit_nonce[6] = (u8)(cipher->seq_num >> 8);
    explicit_nonce[7] = (u8)(cipher->seq_num);

    /* Nonce = implicit_iv || explicit_nonce */
    rintls_memcpy(nonce, cipher->iv, 4);
    rintls_memcpy(nonce + 4, explicit_nonce, 8);

    /* AAD */
    aad[0] = (u8)(cipher->seq_num >> 56);
    aad[1] = (u8)(cipher->seq_num >> 48);
    aad[2] = (u8)(cipher->seq_num >> 40);
    aad[3] = (u8)(cipher->seq_num >> 32);
    aad[4] = (u8)(cipher->seq_num >> 24);
    aad[5] = (u8)(cipher->seq_num >> 16);
    aad[6] = (u8)(cipher->seq_num >> 8);
    aad[7] = (u8)(cipher->seq_num);
    aad[8] = content_type;
    aad[9] = (u8)(version >> 8);
    aad[10] = (u8)(version & 0xFF);
    aad[11] = (u8)(plaintext_len >> 8);
    aad[12] = (u8)(plaintext_len & 0xFF);

    /* 出力: explicit_nonce || ciphertext || tag */
    rintls_memcpy(output, explicit_nonce, 8);

    rin_size_t ciphertext_len;
    int ret = aes_gcm_encrypt(&cipher->aes, nonce, 12,
                               aad, 13,
                               plaintext, plaintext_len,
                               output + 8, &ciphertext_len,
                               output + 8 + plaintext_len, 16);

    if (ret != 0) return TLS_ERR_DECRYPT;

    *output_len = 8 + plaintext_len + 16;

    return TLS_ERR_OK;
}

/*
 * TLS 1.2 AES-GCM復号
 */
static int tls12_decrypt_gcm(tls_cipher_ctx_t* cipher,
                             u8 content_type, u16 version,
                             const u8* input, rin_size_t input_len,
                             u8* plaintext, rin_size_t* plaintext_len)
{
    if (input_len < 8 + 16) return TLS_ERR_DECRYPT;  /* explicit_nonce + tag */

    u8 nonce[12];
    u8 aad[13];

    rin_size_t ciphertext_len = input_len - 8 - 16;

    /* Nonce = implicit_iv || explicit_nonce */
    rintls_memcpy(nonce, cipher->iv, 4);
    rintls_memcpy(nonce + 4, input, 8);  /* explicit_nonce */

    /* AAD */
    aad[0] = (u8)(cipher->seq_num >> 56);
    aad[1] = (u8)(cipher->seq_num >> 48);
    aad[2] = (u8)(cipher->seq_num >> 40);
    aad[3] = (u8)(cipher->seq_num >> 32);
    aad[4] = (u8)(cipher->seq_num >> 24);
    aad[5] = (u8)(cipher->seq_num >> 16);
    aad[6] = (u8)(cipher->seq_num >> 8);
    aad[7] = (u8)(cipher->seq_num);
    aad[8] = content_type;
    aad[9] = (u8)(version >> 8);
    aad[10] = (u8)(version & 0xFF);
    aad[11] = (u8)(ciphertext_len >> 8);
    aad[12] = (u8)(ciphertext_len & 0xFF);

    int ret = aes_gcm_decrypt(&cipher->aes, nonce, 12,
                               aad, 13,
                               input + 8, ciphertext_len,
                               input + 8 + ciphertext_len, 16,
                               plaintext, plaintext_len);

    if (ret != 0) return TLS_ERR_MAC;

    cipher->seq_num++;

    return TLS_ERR_OK;
}

/* ═══════════════════════════════════════
 * TLS 1.3 暗号化・復号
 * ═══════════════════════════════════════ */

/*
 * TLS 1.3 AES-GCM暗号化
 *
 * Nonce: base_iv XOR padded_seq_num
 * AAD: record_header (5バイト) - application_dataタイプ, バージョン0x0303, 暗号文長
 * 平文に内部コンテントタイプを追加
 */
static int tls13_encrypt_gcm(tls_cipher_ctx_t* cipher,
                             u8 inner_content_type,
                             const u8* plaintext, rin_size_t plaintext_len,
                             u8* output, rin_size_t* output_len)
{
    u8 nonce[12];
    u8 aad[5];
    u8* inner_plaintext;

    /* 内部平文 = plaintext || inner_content_type */
    rin_size_t inner_len = plaintext_len + 1;
    inner_plaintext = (u8*)rintls_malloc(inner_len);
    if (!inner_plaintext) return TLS_ERR_BUFFER;

    rintls_memcpy(inner_plaintext, plaintext, plaintext_len);
    inner_plaintext[plaintext_len] = inner_content_type;

    /* Nonce = base_iv XOR padded_seq_num */
    rintls_memcpy(nonce, cipher->iv, 12);
    for (int i = 0; i < 8; i++) {
        nonce[12 - 8 + i] ^= (u8)(cipher->seq_num >> (56 - 8 * i));
    }

    /* 出力長 = 内部平文 + tag */
    rin_size_t ciphertext_len = inner_len + 16;

    /* AAD = レコードヘッダー */
    aad[0] = TLS_CONTENT_APPLICATION_DATA;  /* 外部タイプは常にapplication_data */
    aad[1] = 0x03;
    aad[2] = 0x03;  /* legacy version = TLS 1.2 */
    aad[3] = (u8)(ciphertext_len >> 8);
    aad[4] = (u8)(ciphertext_len & 0xFF);

    int ret = aes_gcm_encrypt(&cipher->aes, nonce, 12,
                               aad, 5,
                               inner_plaintext, inner_len,
                               output, &ciphertext_len,
                               output + inner_len, 16);

    rintls_mem_free(inner_plaintext);

    if (ret != 0) return TLS_ERR_DECRYPT;

    *output_len = inner_len + 16;

    return TLS_ERR_OK;
}

/*
 * TLS 1.3 AES-GCM復号
 */
static int tls13_decrypt_gcm(tls_cipher_ctx_t* cipher,
                             const u8* input, rin_size_t input_len,
                             u8* plaintext, rin_size_t* plaintext_len,
                             u8* inner_content_type)
{
    if (input_len < 16 + 1) return TLS_ERR_DECRYPT;  /* tag + content_type */

    u8 nonce[12];
    u8 aad[5];

    /* Nonce = base_iv XOR padded_seq_num */
    rintls_memcpy(nonce, cipher->iv, 12);
    for (int i = 0; i < 8; i++) {
        nonce[12 - 8 + i] ^= (u8)(cipher->seq_num >> (56 - 8 * i));
    }

    rintls_debug("[TLS_DEC] seq_num=");
    rintls_debug_hex((u32)cipher->seq_num);
    rintls_debug("\n");

    rin_size_t ciphertext_len = input_len - 16;

    /* AAD = レコードヘッダー */
    aad[0] = TLS_CONTENT_APPLICATION_DATA;
    aad[1] = 0x03;
    aad[2] = 0x03;
    aad[3] = (u8)(input_len >> 8);
    aad[4] = (u8)(input_len & 0xFF);

    rintls_debug("[TLS_DEC] AAD: ");
    rintls_debug_hex(aad[0]); rintls_debug(" ");
    rintls_debug_hex(aad[1]); rintls_debug(" ");
    rintls_debug_hex(aad[2]); rintls_debug(" ");
    rintls_debug_hex(aad[3]); rintls_debug(" ");
    rintls_debug_hex(aad[4]); rintls_debug("\n");

    /* 入力データのチェックサム */
    u32 input_sum = 0;
    for (rin_size_t i = 0; i < input_len; i++) {
        input_sum += input[i];
    }
    rintls_debug("[TLS_DEC] input_len=");
    rintls_debug_hex((u32)input_len);
    rintls_debug(" input_sum=");
    rintls_debug_hex(input_sum);
    rintls_debug("\n");

    /* 暗号文の最初と最後の16バイト */
    rintls_debug("[TLS_DEC] ciphertext[0-15]: ");
    for (int i = 0; i < 16 && i < (int)ciphertext_len; i++) {
        rintls_debug_hex(input[i]);
        rintls_debug(" ");
    }
    rintls_debug("\n");
    if (ciphertext_len > 16) {
        rintls_debug("[TLS_DEC] ciphertext[end-15..end]: ");
        for (rin_size_t i = ciphertext_len - 16; i < ciphertext_len; i++) {
            rintls_debug_hex(input[i]);
            rintls_debug(" ");
        }
        rintls_debug("\n");
    }

    u8* inner_plaintext = (u8*)rintls_malloc(ciphertext_len);
    if (!inner_plaintext) return TLS_ERR_BUFFER;

    rin_size_t decrypted_len;

    /* Debug: verify tag position */
    rintls_debug("[TLS_DEC] tag_ptr offset=");
    rintls_debug_hex((u32)ciphertext_len);
    rintls_debug(" tag[0-3]=");
    rintls_debug_hex(input[ciphertext_len]);
    rintls_debug(" ");
    rintls_debug_hex(input[ciphertext_len + 1]);
    rintls_debug(" ");
    rintls_debug_hex(input[ciphertext_len + 2]);
    rintls_debug(" ");
    rintls_debug_hex(input[ciphertext_len + 3]);
    rintls_debug(" tag[12-15]=");
    rintls_debug_hex(input[ciphertext_len + 12]);
    rintls_debug(" ");
    rintls_debug_hex(input[ciphertext_len + 13]);
    rintls_debug(" ");
    rintls_debug_hex(input[ciphertext_len + 14]);
    rintls_debug(" ");
    rintls_debug_hex(input[ciphertext_len + 15]);
    rintls_debug("\n");

    int ret = aes_gcm_decrypt(&cipher->aes, nonce, 12,
                               aad, 5,
                               input, ciphertext_len,
                               input + ciphertext_len, 16,
                               inner_plaintext, &decrypted_len);

    if (ret != 0) {
        rintls_debug("[TLS_DEC] MAC verify failed!\n");
        rintls_mem_free(inner_plaintext);
        return TLS_ERR_MAC;
    }

    /* 末尾のパディング（0x00）を除去して内部コンテントタイプを取得 */
    while (decrypted_len > 0 && inner_plaintext[decrypted_len - 1] == 0x00) {
        decrypted_len--;
    }

    if (decrypted_len == 0) {
        rintls_mem_free(inner_plaintext);
        return TLS_ERR_DECRYPT;
    }

    *inner_content_type = inner_plaintext[decrypted_len - 1];
    *plaintext_len = decrypted_len - 1;
    rintls_memcpy(plaintext, inner_plaintext, *plaintext_len);

    rintls_mem_free(inner_plaintext);
    cipher->seq_num++;

    return TLS_ERR_OK;
}

/* ═══════════════════════════════════════
 * レコード送受信
 * ═══════════════════════════════════════ */

int tls_record_send(tls_record_ctx_t* ctx,
                    u8 content_type,
                    const u8* data, rin_size_t len)
{
    if (len > TLS_MAX_RECORD_SIZE) return TLS_ERR_RECORD_SIZE;

    if (ctx->write_in_progress) {
        return tls_record_flush_pending_send(ctx);
    }

    if (ctx->write_cipher.type == TLS_CIPHER_NULL) {
        /* 暗号化なし */
        return tls_record_send_raw(ctx, content_type, ctx->version, data, len);
    }
    rin_size_t ciphertext_len;
    int ret;

    if (ctx->is_tls13) {
        /* TLS 1.3 */
        ret = tls13_encrypt_gcm(&ctx->write_cipher, content_type,
                                 data, len,
                                 ctx->write_buffer + TLS_RECORD_HEADER_SIZE,
                                 &ciphertext_len);
        if (ret != TLS_ERR_OK) return ret;

        ctx->write_buffer[0] = TLS_CONTENT_APPLICATION_DATA;
        ctx->write_buffer[1] = 0x03;
        ctx->write_buffer[2] = 0x03;
    } else {
        /* TLS 1.2 */
        ret = tls12_encrypt_gcm(&ctx->write_cipher, content_type, ctx->version,
                                 data, len,
                                 ctx->write_buffer + TLS_RECORD_HEADER_SIZE,
                                 &ciphertext_len);
        if (ret != TLS_ERR_OK) return ret;
        ctx->write_buffer[0] = content_type;
        ctx->write_buffer[1] = (u8)(ctx->version >> 8);
        ctx->write_buffer[2] = (u8)(ctx->version & 0xFF);
    }

    ctx->write_buffer[3] = (u8)(ciphertext_len >> 8);
    ctx->write_buffer[4] = (u8)(ciphertext_len & 0xFF);
    ctx->write_buffer_len = TLS_RECORD_HEADER_SIZE + ciphertext_len;
    ctx->write_buffer_pos = 0;
    ctx->write_payload_len = len;
    ctx->write_in_progress = 1;
    ctx->write_pending_seq_advance = 1;

    return tls_record_flush_pending_send(ctx);
}

int tls_record_recv(tls_record_ctx_t* ctx,
                    u8* content_type,
                    u8* data, rin_size_t max_len)
{
    u8 record[TLS_MAX_CIPHERTEXT_SIZE];
    u8 outer_type;
    u16 version;

    /* バッファにデータがあればそこから返す */
    if (ctx->plaintext_len > ctx->plaintext_pos) {
        rin_size_t remaining = ctx->plaintext_len - ctx->plaintext_pos;
        u8* buf_ptr = ctx->plaintext_buffer + ctx->plaintext_pos;

        /* ハンドシェイクメッセージの場合は1つずつ返す */
        if (!ctx->handshake_fragment_passthrough &&
            ctx->plaintext_content_type == TLS_CONTENT_HANDSHAKE &&
            remaining >= 4) {
            u32 msg_len = ((u32)buf_ptr[1] << 16) |
                          ((u32)buf_ptr[2] << 8) |
                          ((u32)buf_ptr[3]);
            rin_size_t full_msg_len = 4 + msg_len;

            if (full_msg_len <= remaining) {
                rin_size_t copy_len = (full_msg_len > max_len) ? max_len : full_msg_len;

                rintls_debug("[TLS_REC] Returning buffered handshake msg type=");
                rintls_debug_hex(buf_ptr[0]);
                rintls_debug(" len=");
                rintls_debug_hex(full_msg_len);
                rintls_debug(" remaining=");
                rintls_debug_hex(remaining - full_msg_len);
                rintls_debug("\n");

                rintls_memcpy(data, buf_ptr, copy_len);
                ctx->plaintext_pos += full_msg_len;
                *content_type = ctx->plaintext_content_type;
                return (int)copy_len;
            }
        }

        /* 非ハンドシェイクまたは残り全部を返す */
        rin_size_t copy_len = (remaining > max_len) ? max_len : remaining;

        rintls_debug("[TLS_REC] Returning buffered data: ");
        rintls_debug_hex(copy_len);
        rintls_debug(" bytes (remaining=");
        rintls_debug_hex(remaining);
        rintls_debug(")\n");

        rintls_memcpy(data, buf_ptr, copy_len);
        ctx->plaintext_pos += copy_len;
        *content_type = ctx->plaintext_content_type;
        return (int)copy_len;
    }

    /* バッファが空なので新しいレコードを読む */
    ctx->plaintext_len = 0;
    ctx->plaintext_pos = 0;

retry_recv:;
    int record_len = tls_record_recv_raw(ctx, &outer_type, &version, record, sizeof(record));
    if (record_len < 0) return record_len;

    /* TLS 1.3 middlebox互換性: ChangeCipherSpecを無視 */
    /* これは暗号化が有効でも暗号化されていない特別なレコード */
    if (outer_type == TLS_CONTENT_CHANGE_CIPHER_SPEC) {
        rintls_debug("[TLS_REC] Ignoring ChangeCipherSpec\n");
        goto retry_recv;
    }

    /* アラートチェック */
    if (outer_type == TLS_CONTENT_ALERT && record_len >= 2) {
        ctx->last_alert_level = record[0];
        ctx->last_alert_desc = record[1];
        rintls_debug("[TLS_ALERT] level=");
        rintls_debug_hex(ctx->last_alert_level);
        rintls_debug(" desc=");
        rintls_debug_hex(ctx->last_alert_desc);
        rintls_debug("\n");

        if (ctx->last_alert_desc == TLS_ALERT_CLOSE_NOTIFY) {
            return TLS_ERR_CLOSED;
        }
        return TLS_ERR_ALERT;
    }

    if (ctx->read_cipher.type == TLS_CIPHER_NULL) {
        /* 暗号化なし */
        if ((rin_size_t)record_len > max_len) return TLS_ERR_BUFFER;
        rintls_memcpy(data, record, record_len);
        *content_type = outer_type;
        return record_len;
    }

    rin_size_t plaintext_len;
    int ret;

    if (ctx->is_tls13) {
        /* TLS 1.3 - 内部バッファに復号 */
        rintls_debug("[TLS_REC] TLS 1.3 decrypt: cipher_type=");
        rintls_debug_hex(ctx->read_cipher.type);
        rintls_debug(" record_len=");
        rintls_debug_hex(record_len);
        rintls_debug("\n");

        /* 暗号化レコードの最初と最後をダンプ (Wireshark比較用) */
        rintls_debug("[ENC_REC] First 32 bytes:\n");
        for (int i = 0; i < 32 && i < record_len; i += 16) {
            rintls_debug("[ENC_REC] ");
            rintls_debug_hex((u32)i);
            rintls_debug(": ");
            for (int j = i; j < i + 16 && j < 32 && j < record_len; j++) {
                rintls_debug_hex(record[j]);
                rintls_debug(" ");
            }
            rintls_debug("\n");
        }
        if (record_len > 32) {
            rintls_debug("[ENC_REC] Last 32 bytes (offset ");
            rintls_debug_hex((u32)(record_len - 32));
            rintls_debug("):\n");
            for (int i = record_len - 32; i < record_len; i += 16) {
                rintls_debug("[ENC_REC] ");
                rintls_debug_hex((u32)i);
                rintls_debug(": ");
                for (int j = i; j < i + 16 && j < record_len; j++) {
                    rintls_debug_hex(record[j]);
                    rintls_debug(" ");
                }
                rintls_debug("\n");
            }
        }

        /* 復号前にバッファサイズをチェック (TLS 1.3: 平文+コンテンツタイプ+パディング) */
        if ((rin_size_t)(record_len - 16) > TLS_MAX_PLAINTEXT_BUFFER) {
            rintls_debug("[TLS_REC] Record too large\n");
            return TLS_ERR_BUFFER;
        }

        u8 inner_type;
        ret = tls13_decrypt_gcm(&ctx->read_cipher, record, record_len,
                                 ctx->plaintext_buffer, &plaintext_len, &inner_type);
        if (ret != TLS_ERR_OK) {
            rintls_debug("[TLS_REC] Decrypt failed, ret=");
            rintls_debug_hex(ret);
            rintls_debug("\n");
            return ret;
        }

        /* バッファに保存 */
        ctx->plaintext_len = plaintext_len;
        ctx->plaintext_pos = 0;
        ctx->plaintext_content_type = inner_type;

        rintls_debug("[TLS_REC] Decrypted ");
        rintls_debug_hex(plaintext_len);
        rintls_debug(" bytes, inner_type=");
        rintls_debug_hex(inner_type);
        rintls_debug("\n");

        /* 復号後のアラートチェック */
        if (inner_type == TLS_CONTENT_ALERT && plaintext_len >= 2) {
            ctx->last_alert_level = ctx->plaintext_buffer[0];
            ctx->last_alert_desc = ctx->plaintext_buffer[1];
            rintls_debug("[TLS_ALERT] level=");
            rintls_debug_hex(ctx->last_alert_level);
            rintls_debug(" desc=");
            rintls_debug_hex(ctx->last_alert_desc);
            rintls_debug("\n");
            if (ctx->last_alert_desc == TLS_ALERT_CLOSE_NOTIFY) {
                return TLS_ERR_CLOSED;
            }
            return TLS_ERR_ALERT;
        }

        /* TLS 1.3 ハンドシェイク: 1つのメッセージのみを返す */
        /* 複数のハンドシェイクメッセージが1つの暗号化レコードに含まれる場合がある */
        if (!ctx->handshake_fragment_passthrough &&
            inner_type == TLS_CONTENT_HANDSHAKE && plaintext_len >= 4) {
            /* ハンドシェイクヘッダー: type(1) + length(3) */
            u32 msg_len = ((u32)ctx->plaintext_buffer[1] << 16) |
                          ((u32)ctx->plaintext_buffer[2] << 8) |
                          ((u32)ctx->plaintext_buffer[3]);
            rin_size_t full_msg_len = 4 + msg_len;

            /* 1つのメッセージのみを返す */
            if (full_msg_len <= plaintext_len) {
                rin_size_t copy_len = (full_msg_len > max_len) ? max_len : full_msg_len;
                rintls_memcpy(data, ctx->plaintext_buffer, copy_len);
                ctx->plaintext_pos = full_msg_len;  /* 次回は次のメッセージから */

                rintls_debug("[TLS_REC] Returning handshake msg type=");
                rintls_debug_hex(ctx->plaintext_buffer[0]);
                rintls_debug(" len=");
                rintls_debug_hex(full_msg_len);
                rintls_debug(" remaining=");
                rintls_debug_hex(plaintext_len - full_msg_len);
                rintls_debug("\n");

                *content_type = inner_type;
                return (int)copy_len;
            }
        }

        /* 非ハンドシェイク、または単一メッセージ: 要求されたサイズ分をコピー */
        rin_size_t copy_len = (plaintext_len > max_len) ? max_len : plaintext_len;
        rintls_memcpy(data, ctx->plaintext_buffer, copy_len);
        ctx->plaintext_pos = copy_len;
        *content_type = inner_type;
        return (int)copy_len;
    } else {
        /* TLS 1.2 */
        ret = tls12_decrypt_gcm(&ctx->read_cipher, outer_type, version,
                                 record, record_len, data, &plaintext_len);
        if (ret != TLS_ERR_OK) return ret;

        *content_type = outer_type;
        return (int)plaintext_len;
    }
}

/* ═══════════════════════════════════════
 * アラート
 * ═══════════════════════════════════════ */

int tls_record_send_alert(tls_record_ctx_t* ctx, u8 level, u8 description)
{
    u8 alert[2] = {level, description};
    return tls_record_send(ctx, TLS_CONTENT_ALERT, alert, 2);
}

int tls_record_close(tls_record_ctx_t* ctx)
{
    /* close_notify送信を試みるが、既に接続が閉じていても無視する
     * (サーバーが先にFINを送信した場合など) */
    int ret = tls_record_send_alert(ctx, TLS_ALERT_WARNING, TLS_ALERT_CLOSE_NOTIFY);
    (void)ret;  /* 失敗しても問題ない */
    return TLS_ERR_OK;
}
