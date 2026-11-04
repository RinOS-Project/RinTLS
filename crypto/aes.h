/*
 * rinTLS - AES Block Cipher & GCM Mode
 * AES暗号化とGCMモード
 */

#ifndef RINTLS_AES_H
#define RINTLS_AES_H

#include "../platform/rin_platform.h"

/* AES key sizes */
#define AES128_KEY_SIZE     16
#define AES192_KEY_SIZE     24
#define AES256_KEY_SIZE     32
#define AES_BLOCK_SIZE      16

/* GCM parameters */
#define AES_GCM_IV_SIZE     12
#define AES_GCM_TAG_SIZE    16

/* AES context */
typedef struct {
    u32 rk[60];         /* Round keys (max for AES-256) */
    int nr;             /* Number of rounds */
} aes_ctx;

/* AES-GCM context */
typedef struct {
    aes_ctx aes;
    u8  h[16];          /* Hash subkey */
    u8  j0[16];         /* Pre-counter block */
    u8  counter[16];    /* Current counter */
    u8  ghash[16];      /* GHASH accumulator */
    u64 aad_len;        /* AAD length in bits */
    u64 ct_len;         /* Ciphertext length in bits */
    u8 aad_partial[16]; /* Unprocessed AAD block */
    u8 ct_partial[16];  /* Unprocessed ciphertext block */
    u8 keystream[16];   /* Current CTR block across updates */
    u8 aad_partial_len;
    u8 ct_partial_len;
    u8 keystream_offset;
    u8 phase;           /* 0=unkeyed, 1=AAD, 2=data, 3=finished */
    u8 mode;            /* 0=unset, 1=encrypt, 2=decrypt */
    u8 error;
    u8 initialized;
} aes_gcm_ctx;

/* ═══════════════════════════════════════
 * AES Core Functions
 * ═══════════════════════════════════════ */

/* Initialize AES context with key */
int aes_init(aes_ctx* ctx, const u8* key, int key_size);

/* Encrypt single block (16 bytes) */
void aes_encrypt_block(const aes_ctx* ctx, const u8* in, u8* out);

/* Decrypt single block (16 bytes) */
void aes_decrypt_block(const aes_ctx* ctx, const u8* in, u8* out);

/* ═══════════════════════════════════════
 * AES-GCM Functions
 * ═══════════════════════════════════════ */

/* Initialize GCM context */
int aes_gcm_init(aes_gcm_ctx* ctx, const u8* key, int key_size);

/* Set IV/nonce (12 bytes recommended). Returns 0 or -1. A successful call
 * starts a fresh operation and clears a previous operation error. */
int aes_gcm_set_iv(aes_gcm_ctx* ctx, const u8* iv, rin_size_t iv_len);

/* Add AAD before the first non-empty data update. All streaming calls return
 * 0 on success and -1 on invalid state, pointer, or GCM length. An error is
 * sticky until aes_gcm_set_iv() successfully starts a new operation. */
int aes_gcm_aad(aes_gcm_ctx* ctx, const u8* aad, rin_size_t aad_len);

/* Encrypt data in place (streaming API). Returns 0 or -1. */
int aes_gcm_encrypt_inplace(aes_gcm_ctx* ctx, u8* data, rin_size_t len);

/* Decrypt data in place (streaming API). Returns 0 or -1. */
int aes_gcm_decrypt_inplace(aes_gcm_ctx* ctx, u8* data, rin_size_t len);

/* Generate authentication tag; returns 0 or -1 and zeros the tag on failure. */
int aes_gcm_finish(aes_gcm_ctx* ctx, u8* tag);

/* Verify authentication tag (returns 0 on success) */
int aes_gcm_verify(aes_gcm_ctx* ctx, const u8* tag);

/* ═══════════════════════════════════════
 * Context-based GCM Functions (for TLS)
 * ═══════════════════════════════════════ */

/* Encrypt with GCM using pre-initialized AES context */
int aes_gcm_encrypt(
    aes_ctx* ctx,
    const u8* nonce, rin_size_t nonce_len,
    const u8* aad, rin_size_t aad_len,
    const u8* plaintext, rin_size_t pt_len,
    u8* ciphertext, rin_size_t* ct_len,
    u8* tag, rin_size_t tag_len
);

/* Decrypt with GCM using pre-initialized AES context (returns 0 on success) */
int aes_gcm_decrypt(
    aes_ctx* ctx,
    const u8* nonce, rin_size_t nonce_len,
    const u8* aad, rin_size_t aad_len,
    const u8* ciphertext, rin_size_t ct_len,
    const u8* tag, rin_size_t tag_len,
    u8* plaintext, rin_size_t* pt_len
);

/* ═══════════════════════════════════════
 * One-shot GCM Functions
 * ═══════════════════════════════════════ */

/* Encrypt with GCM (all-in-one) */
int aes_gcm_encrypt_full(
    const u8* key, int key_size,
    const u8* iv, rin_size_t iv_len,
    const u8* aad, rin_size_t aad_len,
    const u8* plaintext, rin_size_t pt_len,
    u8* ciphertext,
    u8* tag
);

/* Decrypt with GCM (all-in-one, returns 0 on success) */
int aes_gcm_decrypt_full(
    const u8* key, int key_size,
    const u8* iv, rin_size_t iv_len,
    const u8* aad, rin_size_t aad_len,
    const u8* ciphertext, rin_size_t ct_len,
    u8* plaintext,
    const u8* tag
);

#endif /* RINTLS_AES_H */
