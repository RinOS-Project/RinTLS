/*
 * rinTLS - RSA暗号化・署名検証
 * PKCS#1 v1.5 および RSA-PSS対応
 */

#include "rsa.h"
#include "../platform/rin_platform.h"

/* ═══════════════════════════════════════
 * DigestInfo DERプレフィックス
 * ═══════════════════════════════════════ */

/* SHA-256 DigestInfo */
const u8 RSA_DIGESTINFO_SHA256[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20
};
const rin_size_t RSA_DIGESTINFO_SHA256_LEN = 19;

/* SHA-384 DigestInfo */
const u8 RSA_DIGESTINFO_SHA384[] = {
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30
};
const rin_size_t RSA_DIGESTINFO_SHA384_LEN = 19;

/* SHA-512 DigestInfo */
const u8 RSA_DIGESTINFO_SHA512[] = {
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40
};
const rin_size_t RSA_DIGESTINFO_SHA512_LEN = 19;

/* SHA-1 DigestInfo */
const u8 RSA_DIGESTINFO_SHA1[] = {
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
    0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
};
const rin_size_t RSA_DIGESTINFO_SHA1_LEN = 15;

/* ═══════════════════════════════════════
 * 公開鍵操作
 * ═══════════════════════════════════════ */

void rsa_pubkey_init(rsa_pubkey_t* key)
{
    bn_init(&key->n);
    bn_init(&key->e);
    key->bits = 0;
}

void rsa_pubkey_clear(rsa_pubkey_t* key)
{
    bn_clear(&key->n);
    bn_clear(&key->e);
    key->bits = 0;
}

int rsa_pubkey_set(rsa_pubkey_t* key,
                   const u8* n, rin_size_t n_len,
                   const u8* e, rin_size_t e_len)
{
    if (!key) {
        return RSA_ERR_KEY;
    }
    rsa_pubkey_clear(key);
    if (!n || !e) return RSA_ERR_KEY;

    /* 先頭のゼロをスキップ */
    while (n_len > 0 && *n == 0) {
        n++;
        n_len--;
    }
    while (e_len > 0 && *e == 0) {
        e++;
        e_len--;
    }

    if (n_len == 0 || e_len == 0 || n_len > RSA_MAX_KEY_SIZE ||
        e_len > BIGNUM_MAX_BITS / 8) {
        return RSA_ERR_KEY;
    }

    if (bn_from_bytes(&key->n, n, n_len) != BIGNUM_OK) {
        goto invalid_key;
    }
    if (bn_from_bytes(&key->e, e, e_len) != BIGNUM_OK) {
        goto invalid_key;
    }

    key->bits = bn_bitlen(&key->n);
    if (key->bits < 512 || key->bits > BIGNUM_MAX_BITS ||
        !bn_is_odd(&key->n) || !bn_is_odd(&key->e) ||
        bn_cmp_u32(&key->e, 3) < 0)
        goto invalid_key;
    return RSA_OK;

invalid_key:
    rsa_pubkey_clear(key);
    return RSA_ERR_KEY;
}

/* ═══════════════════════════════════════
 * DERパーサーヘルパー
 * ═══════════════════════════════════════ */

/* DER長さを読み取り */
static int der_read_length(const u8** p, const u8* end, rin_size_t* len)
{
    if (*p >= end) return -1;

    u8 first = **p;
    (*p)++;

    if (first < 0x80) {
        *len = first;
        return 0;
    }

    int bytes = first & 0x7f;
    if (bytes > 4 || *p + bytes > end) return -1;

    *len = 0;
    for (int i = 0; i < bytes; i++) {
        *len = (*len << 8) | **p;
        (*p)++;
    }

    return 0;
}

/* DERタグを読み取り */
static int der_read_tag(const u8** p, const u8* end, u8 expected)
{
    if (*p >= end || **p != expected) return -1;
    (*p)++;
    return 0;
}

/* RSAPublicKey ::= SEQUENCE {
 *   modulus         INTEGER,
 *   publicExponent  INTEGER
 * }
 */
int rsa_pubkey_from_der(rsa_pubkey_t* key, const u8* der, rin_size_t len)
{
    const u8* p;
    const u8* end;
    const u8* sequence_end;
    rin_size_t seq_len, int_len;

    if (!key || !der || len == 0) return RSA_ERR_INVALID;
    p = der;
    end = der + len;
    rsa_pubkey_init(key);

    /* SEQUENCE */
    if (der_read_tag(&p, end, 0x30) < 0) return RSA_ERR_INVALID;
    if (der_read_length(&p, end, &seq_len) < 0) return RSA_ERR_INVALID;
    if (seq_len > (rin_size_t)(end - p)) return RSA_ERR_INVALID;
    sequence_end = p + seq_len;
    if (sequence_end != end) return RSA_ERR_INVALID;

    /* modulus INTEGER */
    if (der_read_tag(&p, sequence_end, 0x02) < 0) return RSA_ERR_INVALID;
    if (der_read_length(&p, sequence_end, &int_len) < 0 || int_len == 0 ||
        int_len > (rin_size_t)(sequence_end - p))
        return RSA_ERR_INVALID;

    /* 先頭の0x00（符号バイト）をスキップ */
    const u8* n_data = p;
    rin_size_t n_len = int_len;
    if (*n_data == 0x00) {
        if (n_len == 1 || (n_data[1] & 0x80) == 0)
            return RSA_ERR_INVALID;
        n_data++;
        n_len--;
    } else if ((*n_data & 0x80) != 0) {
        return RSA_ERR_INVALID;
    }
    p += int_len;

    /* publicExponent INTEGER */
    if (der_read_tag(&p, sequence_end, 0x02) < 0) return RSA_ERR_INVALID;
    if (der_read_length(&p, sequence_end, &int_len) < 0 || int_len == 0 ||
        int_len > (rin_size_t)(sequence_end - p))
        return RSA_ERR_INVALID;

    const u8* e_data = p;
    rin_size_t e_len = int_len;
    if (*e_data == 0x00) {
        if (e_len == 1 || (e_data[1] & 0x80) == 0)
            return RSA_ERR_INVALID;
        e_data++;
        e_len--;
    } else if ((*e_data & 0x80) != 0) {
        return RSA_ERR_INVALID;
    }
    p += int_len;
    if (p != sequence_end) return RSA_ERR_INVALID;

    return rsa_pubkey_set(key, n_data, n_len, e_data, e_len);
}

/* ═══════════════════════════════════════
 * RSA基本演算
 * ═══════════════════════════════════════ */

int rsa_public(u8* result, rin_size_t* result_len,
               const u8* message, rin_size_t message_len,
               const rsa_pubkey_t* key)
{
    bignum_t m, c;
    rin_size_t key_bytes;
    int status = RSA_ERR_INVALID;
    bn_init(&m);
    bn_init(&c);
    if (result_len) *result_len = 0;
    if (!result || !result_len || !message || !key || message_len == 0 ||
        key->bits < 512 || key->bits > BIGNUM_MAX_BITS ||
        key->bits != bn_bitlen(&key->n) || !bn_is_odd(&key->n) ||
        !bn_is_odd(&key->e) || bn_cmp_u32(&key->e, 3) < 0)
        goto cleanup;
    key_bytes = (key->bits + 7) / 8;
    if (message_len > key_bytes) {
        status = RSA_ERR_SIZE;
        goto cleanup;
    }

    /* メッセージを数値に変換 */
    if (bn_from_bytes(&m, message, message_len) != BIGNUM_OK) {
        goto cleanup;
    }

    /* m >= n のチェック */
    if (bn_cmp(&m, &key->n) >= 0) {
        status = RSA_ERR_SIZE;
        goto cleanup;
    }

    /* c = m^e mod n */
    if (bn_mod_exp(&c, &m, &key->e, &key->n) != BIGNUM_OK) {
        goto cleanup;
    }

    /* 結果をバイト配列に変換 */
    if (bn_to_bytes(&c, result, key_bytes) != BIGNUM_OK) {
        goto cleanup;
    }

    *result_len = key_bytes;
    status = RSA_OK;

cleanup:
    bn_clear(&m);
    bn_clear(&c);
    return status;
}

/* ═══════════════════════════════════════
 * PKCS#1 v1.5 署名検証
 * ═══════════════════════════════════════ */

int rsa_pkcs1_verify(const u8* signature, rin_size_t sig_len,
                     const u8* hash, rin_size_t hash_len,
                     int hash_alg,
                     const rsa_pubkey_t* key)
{
    u8 decrypted[RSA_MAX_KEY_SIZE];
    rin_size_t decrypted_len;
    const u8* digest_info;
    rin_size_t digest_info_len;
    rin_size_t key_bytes;

    if (!signature || !hash || !key || key->bits < 512 ||
        key->bits > BIGNUM_MAX_BITS)
        return RSA_ERR_INVALID;
    key_bytes = (key->bits + 7) / 8;

    /* DigestInfoを選択 */
    switch (hash_alg) {
    case RSA_HASH_SHA256:
        digest_info = RSA_DIGESTINFO_SHA256;
        digest_info_len = RSA_DIGESTINFO_SHA256_LEN;
        if (hash_len != 32) return RSA_ERR_INVALID;
        break;
    case RSA_HASH_SHA384:
        digest_info = RSA_DIGESTINFO_SHA384;
        digest_info_len = RSA_DIGESTINFO_SHA384_LEN;
        if (hash_len != 48) return RSA_ERR_INVALID;
        break;
    case RSA_HASH_SHA512:
        digest_info = RSA_DIGESTINFO_SHA512;
        digest_info_len = RSA_DIGESTINFO_SHA512_LEN;
        if (hash_len != 64) return RSA_ERR_INVALID;
        break;
    case RSA_HASH_SHA1:
        digest_info = RSA_DIGESTINFO_SHA1;
        digest_info_len = RSA_DIGESTINFO_SHA1_LEN;
        if (hash_len != 20) return RSA_ERR_INVALID;
        break;
    default:
        return RSA_ERR_INVALID;
    }

    /* 署名長チェック */
    if (sig_len != key_bytes) {
        return RSA_ERR_SIZE;
    }

    /* RSA復号: signature^e mod n */
    if (rsa_public(decrypted, &decrypted_len, signature, sig_len, key) != RSA_OK) {
        return RSA_ERR_VERIFY;
    }

    /*
     * PKCS#1 v1.5 パディング形式:
     * 0x00 0x01 [0xFF...] 0x00 [DigestInfo] [Hash]
     */
    rin_size_t expected_len = 3 + digest_info_len + hash_len;
    if (decrypted_len < expected_len + 8) {  /* 最低8バイトの0xFF */
        return RSA_ERR_PADDING;
    }

    const u8* p = decrypted;

    /* 0x00 0x01 チェック */
    if (p[0] != 0x00 || p[1] != 0x01) {
        return RSA_ERR_PADDING;
    }
    p += 2;

    /* 0xFFパディングをスキップ */
    rin_size_t ff_count = 0;
    while (p < decrypted + decrypted_len && *p == 0xFF) {
        p++;
        ff_count++;
    }

    /* 最低8バイトの0xFFが必要 */
    if (ff_count < 8) {
        return RSA_ERR_PADDING;
    }

    /* 0x00区切り */
    if (p >= decrypted + decrypted_len || *p != 0x00) {
        return RSA_ERR_PADDING;
    }
    p++;

    /* DigestInfoを検証 */
    if (p + digest_info_len + hash_len > decrypted + decrypted_len) {
        return RSA_ERR_PADDING;
    }

    if (!rintls_secure_cmp(p, digest_info, digest_info_len)) {
        return RSA_ERR_VERIFY;
    }
    p += digest_info_len;

    /* ハッシュを検証 */
    if (!rintls_secure_cmp(p, hash, hash_len)) {
        return RSA_ERR_VERIFY;
    }

    /* クリーンアップ */
    rintls_secure_zero(decrypted, sizeof(decrypted));

    return RSA_OK;
}

/* ═══════════════════════════════════════
 * RSA-PSS 署名検証 (TLS 1.3用)
 * ═══════════════════════════════════════ */

/*
 * MGF1 (Mask Generation Function 1)
 * RFC 8017 B.2.1
 */
static void mgf1_sha256(u8* mask, rin_size_t mask_len,
                        const u8* seed, rin_size_t seed_len)
{
    u8 counter[4] = {0, 0, 0, 0};
    u8 hash[SHA256_DIGEST_SIZE];
    rin_size_t pos = 0;

    for (u32 i = 0; pos < mask_len; i++) {
        counter[0] = (u8)(i >> 24);
        counter[1] = (u8)(i >> 16);
        counter[2] = (u8)(i >> 8);
        counter[3] = (u8)i;

        sha256_ctx ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, seed, seed_len);
        sha256_update(&ctx, counter, 4);
        sha256_final(&ctx, hash);

        rin_size_t copy_len = (mask_len - pos < SHA256_DIGEST_SIZE) ?
                              (mask_len - pos) : SHA256_DIGEST_SIZE;
        rintls_memcpy(mask + pos, hash, copy_len);
        pos += copy_len;
    }

    rintls_secure_zero(hash, sizeof(hash));
}

static int rsa_oaep_default_random(void* context, u8* output,
                                   rin_size_t output_len)
{
    (void)context;
    return rintls_random_bytes(output, output_len);
}

int rsa_oaep_sha256_encrypt_with_rng(
    u8* output, rin_size_t* output_len,
    const u8* input, rin_size_t input_len,
    const u8* label, rin_size_t label_len,
    const rsa_pubkey_t* key,
    rsa_random_bytes_fn random_bytes, void* random_context)
{
    u8 encoded[RSA_MAX_KEY_SIZE];
    u8 data_block[RSA_MAX_KEY_SIZE];
    u8 data_mask[RSA_MAX_KEY_SIZE];
    u8 seed[SHA256_DIGEST_SIZE];
    u8 seed_mask[SHA256_DIGEST_SIZE];
    u8 label_hash[SHA256_DIGEST_SIZE];
    u8 ciphertext[RSA_MAX_KEY_SIZE];
    rin_size_t output_capacity = output_len ? *output_len : 0;
    rin_size_t key_bytes;
    rin_size_t data_block_len;
    rin_size_t padding_len;
    rin_size_t ciphertext_len = 0;
    rin_size_t i;
    int result = RSA_ERR_INVALID;

    rintls_secure_zero(encoded, sizeof(encoded));
    rintls_secure_zero(data_block, sizeof(data_block));
    rintls_secure_zero(data_mask, sizeof(data_mask));
    rintls_secure_zero(seed, sizeof(seed));
    rintls_secure_zero(seed_mask, sizeof(seed_mask));
    rintls_secure_zero(label_hash, sizeof(label_hash));
    rintls_secure_zero(ciphertext, sizeof(ciphertext));
    if (output_len) *output_len = 0;

    if (!output || !output_len || !key || !random_bytes ||
        (!input && input_len != 0) || (!label && label_len != 0) ||
        key->bits == 0 || key->bits > BIGNUM_MAX_BITS)
        goto cleanup;
    key_bytes = (key->bits + 7) / 8;
    if (key_bytes > RSA_MAX_KEY_SIZE ||
        key_bytes < 2 * SHA256_DIGEST_SIZE + 2) {
        result = RSA_ERR_KEY;
        goto cleanup;
    }
    if (output_capacity < key_bytes ||
        input_len > key_bytes - 2 * SHA256_DIGEST_SIZE - 2) {
        result = RSA_ERR_SIZE;
        goto cleanup;
    }

    data_block_len = key_bytes - SHA256_DIGEST_SIZE - 1;
    padding_len = data_block_len - SHA256_DIGEST_SIZE - input_len - 1;
    sha256(label, label_len, label_hash);
    rintls_memcpy(data_block, label_hash, SHA256_DIGEST_SIZE);
    data_block[SHA256_DIGEST_SIZE + padding_len] = 0x01;
    if (input_len != 0)
        rintls_memcpy(data_block + data_block_len - input_len, input,
                      input_len);
    if (random_bytes(random_context, seed, sizeof(seed)) != 0) {
        result = RSA_ERR_KEY;
        goto cleanup;
    }

    mgf1_sha256(data_mask, data_block_len, seed, sizeof(seed));
    for (i = 0; i < data_block_len; ++i)
        encoded[1 + SHA256_DIGEST_SIZE + i] =
            (u8)(data_block[i] ^ data_mask[i]);
    mgf1_sha256(seed_mask, sizeof(seed_mask),
                encoded + 1 + SHA256_DIGEST_SIZE, data_block_len);
    for (i = 0; i < SHA256_DIGEST_SIZE; ++i)
        encoded[1 + i] = (u8)(seed[i] ^ seed_mask[i]);

    result = rsa_public(ciphertext, &ciphertext_len, encoded, key_bytes, key);
    if (result != RSA_OK || ciphertext_len != key_bytes) {
        if (result == RSA_OK) result = RSA_ERR_KEY;
        goto cleanup;
    }
    rintls_memcpy(output, ciphertext, key_bytes);
    *output_len = key_bytes;
    result = RSA_OK;

cleanup:
    if (result != RSA_OK && output && output_capacity != 0 &&
        output_capacity <= RSA_MAX_KEY_SIZE)
        rintls_secure_zero(output, output_capacity);
    rintls_secure_zero(encoded, sizeof(encoded));
    rintls_secure_zero(data_block, sizeof(data_block));
    rintls_secure_zero(data_mask, sizeof(data_mask));
    rintls_secure_zero(seed, sizeof(seed));
    rintls_secure_zero(seed_mask, sizeof(seed_mask));
    rintls_secure_zero(label_hash, sizeof(label_hash));
    rintls_secure_zero(ciphertext, sizeof(ciphertext));
    return result;
}

int rsa_oaep_sha256_encrypt(
    u8* output, rin_size_t* output_len,
    const u8* input, rin_size_t input_len,
    const u8* label, rin_size_t label_len,
    const rsa_pubkey_t* key)
{
    return rsa_oaep_sha256_encrypt_with_rng(
        output, output_len, input, input_len, label, label_len, key,
        rsa_oaep_default_random, NULL);
}

int rsa_pss_verify_sha256(const u8* signature, rin_size_t sig_len,
                          const u8* message_hash,
                          const rsa_pubkey_t* key)
{
    u8 em[RSA_MAX_KEY_SIZE];
    rin_size_t em_len;
    rin_size_t key_bytes;
    rin_size_t em_bits;
    rin_size_t hash_len = SHA256_DIGEST_SIZE;  /* 32 */
    rin_size_t salt_len = hash_len;  /* 通常saltLen == hashLen */

    if (!signature || !message_hash || !key || key->bits < 512 ||
        key->bits > BIGNUM_MAX_BITS)
        return RSA_ERR_INVALID;
    key_bytes = (key->bits + 7) / 8;
    em_bits = key->bits - 1;

    /* 署名長チェック */
    if (sig_len != key_bytes) {
        return RSA_ERR_SIZE;
    }

    /* emLen = ceil((emBits) / 8) */
    em_len = (em_bits + 7) / 8;
    if (em_len < hash_len + salt_len + 2) {
        return RSA_ERR_SIZE;
    }

    /* RSA復号: signature^e mod n */
    if (rsa_public(em, &em_len, signature, sig_len, key) != RSA_OK) {
        return RSA_ERR_VERIFY;
    }

    /*
     * EMSA-PSS-VERIFY
     *
     * EM = maskedDB || H || 0xbc
     *
     * maskedDB (emLen - hLen - 1 bytes)
     * H (hLen bytes)
     * 0xbc (1 byte)
     */

    /* 最後のバイトは0xbc */
    if (em[em_len - 1] != 0xbc) {
        return RSA_ERR_PADDING;
    }

    rin_size_t db_len = em_len - hash_len - 1;
    u8* masked_db = em;
    u8* h = em + db_len;

    /* 最上位ビットのマスクチェック */
    u8 top_mask = 0xFF >> (8 * em_len - em_bits);
    if ((masked_db[0] & ~top_mask) != 0) {
        return RSA_ERR_PADDING;
    }

    /* DB = maskedDB XOR MGF1(H, dbLen) */
    u8 db_mask[RSA_MAX_KEY_SIZE];
    mgf1_sha256(db_mask, db_len, h, hash_len);

    u8 db[RSA_MAX_KEY_SIZE];
    for (rin_size_t i = 0; i < db_len; i++) {
        db[i] = masked_db[i] ^ db_mask[i];
    }

    /* 最上位ビットをクリア */
    db[0] &= top_mask;

    /*
     * DB = padding || 0x01 || salt
     * padding: (emLen - hLen - sLen - 2) bytes of 0x00
     */
    rin_size_t padding_len = em_len - hash_len - salt_len - 2;

    /* パディングが0x00であることを検証 */
    for (rin_size_t i = 0; i < padding_len; i++) {
        if (db[i] != 0x00) {
            return RSA_ERR_PADDING;
        }
    }

    /* 0x01区切り */
    if (db[padding_len] != 0x01) {
        return RSA_ERR_PADDING;
    }

    /* salt */
    u8* salt = db + padding_len + 1;

    /*
     * M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
     * H' = Hash(M')
     */
    u8 m_prime[8 + SHA256_DIGEST_SIZE + SHA256_DIGEST_SIZE];
    rintls_memset(m_prime, 0, 8);
    rintls_memcpy(m_prime + 8, message_hash, hash_len);
    rintls_memcpy(m_prime + 8 + hash_len, salt, salt_len);

    u8 h_prime[SHA256_DIGEST_SIZE];
    sha256(m_prime, 8 + hash_len + salt_len, h_prime);

    /* H == H' を検証 */
    if (!rintls_secure_cmp(h, h_prime, hash_len)) {
        return RSA_ERR_VERIFY;
    }

    /* クリーンアップ */
    rintls_secure_zero(em, sizeof(em));
    rintls_secure_zero(db, sizeof(db));
    rintls_secure_zero(db_mask, sizeof(db_mask));
    rintls_secure_zero(m_prime, sizeof(m_prime));
    rintls_secure_zero(h_prime, sizeof(h_prime));

    return RSA_OK;
}

/* ═══════════════════════════════════════
 * RSA暗号化 (PKCS#1 v1.5)
 * ═══════════════════════════════════════ */

int rsa_pkcs1_encrypt(u8* output, rin_size_t* output_len,
                      const u8* input, rin_size_t input_len,
                      const rsa_pubkey_t* key)
{
    rin_size_t key_bytes;
    if (output_len) *output_len = 0;
    if (!output || !output_len || !key || (!input && input_len != 0) ||
        key->bits < 512 || key->bits > BIGNUM_MAX_BITS)
        return RSA_ERR_INVALID;
    key_bytes = (key->bits + 7) / 8;

    /* メッセージ長チェック: input_len <= key_bytes - 11 */
    if (key_bytes < 11 || input_len > key_bytes - 11) {
        return RSA_ERR_SIZE;
    }

    u8 em[RSA_MAX_KEY_SIZE];

    /*
     * PKCS#1 v1.5暗号化パディング:
     * 0x00 0x02 [random non-zero bytes] 0x00 [message]
     */
    em[0] = 0x00;
    em[1] = 0x02;

    /* ランダムパディング (最低8バイト、非ゼロ) */
    rin_size_t ps_len = key_bytes - 3 - input_len;
    for (rin_size_t i = 0; i < ps_len; i++) {
        u8 r;
        u32 attempts = 0;
        do {
            if (attempts++ >= 128 || rintls_random_bytes(&r, 1) != 0) {
                rintls_secure_zero(&r, sizeof(r));
                rintls_secure_zero(em, sizeof(em));
                return RSA_ERR_KEY;
            }
        } while (r == 0);
        em[2 + i] = r;
        rintls_secure_zero(&r, sizeof(r));
    }

    /* 区切りの0x00 */
    em[2 + ps_len] = 0x00;

    /* メッセージ */
    rintls_memcpy(em + 3 + ps_len, input, input_len);

    /* RSA暗号化 */
    int ret = rsa_public(output, output_len, em, key_bytes, key);

    /* クリーンアップ */
    rintls_secure_zero(em, sizeof(em));

    return ret;
}
