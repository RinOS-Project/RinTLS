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
    if (!key || !n || !e) {
        return RSA_ERR_KEY;
    }

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
        return RSA_ERR_KEY;
    }
    if (bn_from_bytes(&key->e, e, e_len) != BIGNUM_OK) {
        return RSA_ERR_KEY;
    }

    key->bits = bn_bitlen(&key->n);
    return RSA_OK;
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
    const u8* p = der;
    const u8* end = der + len;
    rin_size_t seq_len, int_len;

    rsa_pubkey_init(key);

    /* SEQUENCE */
    if (der_read_tag(&p, end, 0x30) < 0) return RSA_ERR_INVALID;
    if (der_read_length(&p, end, &seq_len) < 0) return RSA_ERR_INVALID;

    /* modulus INTEGER */
    if (der_read_tag(&p, end, 0x02) < 0) return RSA_ERR_INVALID;
    if (der_read_length(&p, end, &int_len) < 0) return RSA_ERR_INVALID;

    /* 先頭の0x00（符号バイト）をスキップ */
    const u8* n_data = p;
    rin_size_t n_len = int_len;
    if (n_len > 0 && *n_data == 0x00) {
        n_data++;
        n_len--;
    }
    p += int_len;

    /* publicExponent INTEGER */
    if (der_read_tag(&p, end, 0x02) < 0) return RSA_ERR_INVALID;
    if (der_read_length(&p, end, &int_len) < 0) return RSA_ERR_INVALID;

    const u8* e_data = p;
    rin_size_t e_len = int_len;
    if (e_len > 0 && *e_data == 0x00) {
        e_data++;
        e_len--;
    }

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
    rin_size_t key_bytes = (key->bits + 7) / 8;

    /* メッセージを数値に変換 */
    if (bn_from_bytes(&m, message, message_len) != BIGNUM_OK) {
        return RSA_ERR_INVALID;
    }

    /* m >= n のチェック */
    if (bn_cmp(&m, &key->n) >= 0) {
        return RSA_ERR_SIZE;
    }

    /* c = m^e mod n */
    if (bn_mod_exp(&c, &m, &key->e, &key->n) != BIGNUM_OK) {
        return RSA_ERR_INVALID;
    }

    /* 結果をバイト配列に変換 */
    if (bn_to_bytes(&c, result, key_bytes) != BIGNUM_OK) {
        return RSA_ERR_INVALID;
    }

    *result_len = key_bytes;

    /* クリーンアップ */
    bn_clear(&m);
    bn_clear(&c);

    return RSA_OK;
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
    rin_size_t key_bytes = (key->bits + 7) / 8;

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
    while (*p == 0xFF && p < decrypted + decrypted_len) {
        p++;
        ff_count++;
    }

    /* 最低8バイトの0xFFが必要 */
    if (ff_count < 8) {
        return RSA_ERR_PADDING;
    }

    /* 0x00区切り */
    if (*p != 0x00) {
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

int rsa_pss_verify_sha256(const u8* signature, rin_size_t sig_len,
                          const u8* message_hash,
                          const rsa_pubkey_t* key)
{
    u8 em[RSA_MAX_KEY_SIZE];
    rin_size_t em_len;
    rin_size_t key_bytes = (key->bits + 7) / 8;
    rin_size_t em_bits = key->bits - 1;
    rin_size_t hash_len = SHA256_DIGEST_SIZE;  /* 32 */
    rin_size_t salt_len = hash_len;  /* 通常saltLen == hashLen */

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
    rin_size_t key_bytes = (key->bits + 7) / 8;

    /* メッセージ長チェック: input_len <= key_bytes - 11 */
    if (input_len > key_bytes - 11) {
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
