/* SPDX-License-Identifier: MIT */
/*
 * Exercise entropy failures at the real rintls provider boundary.  This is a
 * freestanding-style host test: rin_get_random_bytes() is the sole entropy
 * source and can be made to fail without adding a test hook to production.
 */

#include "crypto/modern.h"
#include "crypto/pqc.h"

#include <stdio.h>
#include <string.h>

#define CHECK(expression)                                                     \
    do {                                                                      \
        if (!(expression)) {                                                  \
            fprintf(stderr, "%s:%d: %s\\n", __FILE__, __LINE__, #expression); \
            return 1;                                                         \
        }                                                                     \
    } while (0)

enum test_random_mode {
    TEST_RANDOM_FAIL,
    TEST_RANDOM_FIXED,
};

static enum test_random_mode test_random_mode;
static unsigned int test_random_calls;

void* platform_memset(void* destination, int value, u32 size)
{
    return memset(destination, value, size);
}

void* platform_memcpy(void* destination, const void* source, u32 size)
{
    return memcpy(destination, source, size);
}

int platform_memcmp(const void* left, const void* right, u32 size)
{
    return memcmp(left, right, size);
}

void* platform_kmalloc(size_t size)
{
    (void)size;
    return NULL;
}

void platform_kfree(void* pointer)
{
    (void)pointer;
}

int rin_get_random_bytes(void* output, u32 length)
{
    ++test_random_calls;
    if (test_random_mode == TEST_RANDOM_FAIL)
        return -1;
    if (!output)
        return length == 0u ? 0 : -1;
    memset(output, 0x5a, length);
    return 0;
}

static int all_zero(const u8* bytes, size_t size)
{
    size_t index;
    u8 combined = 0;

    for (index = 0; index < size; ++index)
        combined |= bytes[index];
    return combined == 0u;
}

static int all_value(const u8* bytes, size_t size, u8 value)
{
    size_t index;

    for (index = 0; index < size; ++index) {
        if (bytes[index] != value)
            return 0;
    }
    return 1;
}

static int test_nist_entropy_failure(u32 curve, u32 hash_algorithm,
                                     rin_size_t private_size,
                                     rin_size_t public_size)
{
    u8 private_key[RINTLS_P521_PRIVATE_KEY_SIZE];
    u8 public_key[RINTLS_P521_PUBLIC_KEY_SIZE];
    u8 signature[RINTLS_P521_PRIVATE_KEY_SIZE * 2u];
    u8 digest[64];
    static const u8 message[] = "rintls entropy failure injection";

    memset(private_key, 0xa5, sizeof(private_key));
    memset(public_key, 0xa5, sizeof(public_key));
    memset(digest, 0x5a, sizeof(digest));
    test_random_mode = TEST_RANDOM_FAIL;
    test_random_calls = 0u;
    CHECK(rintls_nist_keygen(curve, private_key, public_key) != 0);
    CHECK(test_random_calls != 0u);
    CHECK(all_zero(private_key, private_size));
    CHECK(all_zero(public_key, public_size));

    test_random_mode = TEST_RANDOM_FIXED;
    CHECK(rintls_nist_keygen(curve, private_key, public_key) == 0);
    memset(signature, 0xa5, sizeof(signature));
    test_random_mode = TEST_RANDOM_FAIL;
    test_random_calls = 0u;
    CHECK(rintls_nist_ecdsa_sign(curve, hash_algorithm, message,
                                 sizeof(message) - 1u, private_key,
                                 signature) != 0);
    CHECK(test_random_calls != 0u);
    CHECK(all_zero(signature, private_size * 2u));

    memset(signature, 0xa5, sizeof(signature));
    test_random_calls = 0u;
    CHECK(rintls_nist_ecdsa_sign_digest(curve, digest, sizeof(digest),
                                        private_key, signature) != 0);
    CHECK(test_random_calls != 0u);
    CHECK(all_zero(signature, private_size * 2u));
    return 0;
}

static int test_edwards_and_x448_entropy_failure(void)
{
    u8 ed25519_private[RINTLS_ED25519_PRIVATE_KEY_SIZE];
    u8 ed25519_public[RINTLS_ED25519_PUBLIC_KEY_SIZE];
    u8 ed448_private[RINTLS_ED448_PRIVATE_KEY_SIZE];
    u8 ed448_public[RINTLS_ED448_PUBLIC_KEY_SIZE];
    u8 x448_private[RINTLS_X448_KEY_SIZE];
    u8 x448_public[RINTLS_X448_KEY_SIZE];

    memset(ed25519_private, 0xa5, sizeof(ed25519_private));
    memset(ed25519_public, 0xa5, sizeof(ed25519_public));
    test_random_mode = TEST_RANDOM_FAIL;
    test_random_calls = 0u;
    CHECK(rintls_ed25519_keygen(ed25519_private, ed25519_public) != 0);
    CHECK(test_random_calls == 1u);
    CHECK(all_zero(ed25519_private, sizeof(ed25519_private)));
    CHECK(all_zero(ed25519_public, sizeof(ed25519_public)));

    memset(ed448_private, 0xa5, sizeof(ed448_private));
    memset(ed448_public, 0xa5, sizeof(ed448_public));
    test_random_calls = 0u;
    CHECK(rintls_ed448_keygen(ed448_private, ed448_public) != 0);
    CHECK(test_random_calls == 1u);
    CHECK(all_zero(ed448_private, sizeof(ed448_private)));
    CHECK(all_zero(ed448_public, sizeof(ed448_public)));

    memset(x448_private, 0xa5, sizeof(x448_private));
    memset(x448_public, 0xa5, sizeof(x448_public));
    test_random_calls = 0u;
    CHECK(rintls_x448_keygen(x448_private, x448_public) != 0);
    CHECK(test_random_calls == 1u);
    CHECK(all_zero(x448_private, sizeof(x448_private)));
    CHECK(all_zero(x448_public, sizeof(x448_public)));
    return 0;
}

static int test_mldsa_entropy_failure(u32 level)
{
    rin_size_t public_size;
    rin_size_t private_size;
    rin_size_t signature_size;
    u8 seed[RINTLS_MLDSA_SEED_SIZE];
    u8 public_key[2592];
    u8 private_key[4896];
    u8 signature[4627];
    static const u8 message[] = "ML-DSA entropy failure injection";

    CHECK(rintls_mldsa_sizes(level, &public_size, &private_size,
                             &signature_size) == 0);
    memset(seed, 0xa5, sizeof(seed));
    memset(public_key, 0xa5, sizeof(public_key));
    memset(private_key, 0xa5, sizeof(private_key));
    test_random_mode = TEST_RANDOM_FAIL;
    test_random_calls = 0u;
    CHECK(rintls_mldsa_keygen(level, seed, public_key, private_key) != 0);
    CHECK(test_random_calls == 1u);
    CHECK(all_zero(seed, sizeof(seed)));
    CHECK(all_zero(public_key, public_size));
    CHECK(all_zero(private_key, private_size));

    memset(seed, (int)level, sizeof(seed));
    test_random_mode = TEST_RANDOM_FIXED;
    CHECK(rintls_mldsa_keygen_from_seed(level, seed, public_key, private_key) == 0);
    memset(signature, 0xa5, sizeof(signature));
    test_random_mode = TEST_RANDOM_FAIL;
    test_random_calls = 0u;
    CHECK(rintls_mldsa_sign(level, signature, message, sizeof(message) - 1u,
                            NULL, 0u, private_key) != 0);
    CHECK(test_random_calls != 0u);
    CHECK(all_zero(signature, signature_size));
    return 0;
}

static int test_mlkem_entropy_failure(u32 level)
{
    rin_size_t public_size;
    rin_size_t private_size;
    rin_size_t ciphertext_size;
    u8 seed[RINTLS_MLKEM_SEED_SIZE];
    u8 public_key[1568];
    u8 private_key[3168];
    u8 ciphertext[1568];
    u8 shared_secret[RINTLS_MLKEM_SHARED_SECRET_SIZE];

    CHECK(rintls_mlkem_sizes(level, &public_size, &private_size,
                             &ciphertext_size) == 0);
    memset(seed, 0xa5, sizeof(seed));
    memset(public_key, 0xa5, sizeof(public_key));
    memset(private_key, 0xa5, sizeof(private_key));
    test_random_mode = TEST_RANDOM_FAIL;
    test_random_calls = 0u;
    CHECK(rintls_mlkem_keygen(level, seed, public_key, private_key) != 0);
    CHECK(test_random_calls == 1u);
    CHECK(all_zero(seed, sizeof(seed)));
    CHECK(all_zero(public_key, public_size));
    CHECK(all_zero(private_key, private_size));

    memset(seed, (int)(level >> 8), sizeof(seed));
    test_random_mode = TEST_RANDOM_FIXED;
    CHECK(rintls_mlkem_keygen_from_seed(level, seed, public_key, private_key) == 0);
    memset(ciphertext, 0xa5, sizeof(ciphertext));
    memset(shared_secret, 0xa5, sizeof(shared_secret));
    test_random_mode = TEST_RANDOM_FAIL;
    test_random_calls = 0u;
    CHECK(rintls_mlkem_encapsulate(level, ciphertext, shared_secret,
                                   public_key) != 0);
    CHECK(test_random_calls != 0u);
    CHECK(all_zero(ciphertext, ciphertext_size));
    CHECK(all_zero(shared_secret, sizeof(shared_secret)));
    return 0;
}

static int test_invalid_inputs_clear_known_outputs(void)
{
    u8 nist_private[RINTLS_P521_PRIVATE_KEY_SIZE];
    u8 nist_public[RINTLS_P521_PUBLIC_KEY_SIZE];
    u8 nist_signature[RINTLS_P521_PRIVATE_KEY_SIZE * 2u];
    u8 nist_secret[RINTLS_P521_PRIVATE_KEY_SIZE];
    u8 ed25519_public[RINTLS_ED25519_PUBLIC_KEY_SIZE];
    u8 ed25519_signature[RINTLS_ED25519_SIGNATURE_SIZE];
    u8 ed448_public[RINTLS_ED448_PUBLIC_KEY_SIZE];
    u8 ed448_signature[RINTLS_ED448_SIGNATURE_SIZE];
    u8 x448_public[RINTLS_X448_KEY_SIZE];
    u8 x448_secret[RINTLS_X448_KEY_SIZE];
    u8 mldsa_seed[RINTLS_MLDSA_SEED_SIZE];
    u8 mldsa_public[2592];
    u8 mldsa_private[4896];
    u8 mldsa_signature[4627];
    u8 mlkem_seed[RINTLS_MLKEM_SEED_SIZE];
    u8 mlkem_public[1568];
    u8 mlkem_private[3168];
    u8 mlkem_ciphertext[1568];
    u8 mlkem_secret[RINTLS_MLKEM_SHARED_SECRET_SIZE];
    rin_size_t public_size = 0xa5a5a5a5u;
    rin_size_t private_size = 0xa5a5a5a5u;
    rin_size_t third_size = 0xa5a5a5a5u;

    memset(nist_public, 0xa5, sizeof(nist_public));
    CHECK(rintls_nist_keygen(RINTLS_EC_P521, NULL, nist_public) != 0);
    CHECK(all_zero(nist_public, sizeof(nist_public)));
    memset(nist_public, 0xa5, sizeof(nist_public));
    CHECK(rintls_nist_public_from_private(RINTLS_EC_P521, NULL, nist_public) != 0);
    CHECK(all_zero(nist_public, sizeof(nist_public)));
    memset(nist_secret, 0xa5, sizeof(nist_secret));
    CHECK(rintls_nist_ecdh(RINTLS_EC_P521, nist_secret, NULL, nist_public,
                           sizeof(nist_public)) != 0);
    CHECK(all_zero(nist_secret, sizeof(nist_secret)));
    memset(nist_signature, 0xa5, sizeof(nist_signature));
    CHECK(rintls_nist_ecdsa_sign(RINTLS_EC_P521, RINTLS_HASH_SHA512, NULL, 1u,
                                 nist_private, nist_signature) != 0);
    CHECK(all_zero(nist_signature, sizeof(nist_signature)));
    CHECK(rintls_nist_private_key_size(0xffffffffu, &private_size) != 0);
    CHECK(private_size == 0u);
    CHECK(rintls_nist_public_key_size(0xffffffffu, &public_size) != 0);
    CHECK(public_size == 0u);

    memset(ed25519_public, 0xa5, sizeof(ed25519_public));
    CHECK(rintls_ed25519_keygen(NULL, ed25519_public) != 0);
    CHECK(all_zero(ed25519_public, sizeof(ed25519_public)));
    memset(ed25519_public, 0xa5, sizeof(ed25519_public));
    CHECK(rintls_ed25519_public_from_private(NULL, ed25519_public) != 0);
    CHECK(all_zero(ed25519_public, sizeof(ed25519_public)));
    memset(ed25519_signature, 0xa5, sizeof(ed25519_signature));
    CHECK(rintls_ed25519_sign(ed25519_signature, NULL, NULL, 1u) != 0);
    CHECK(all_zero(ed25519_signature, sizeof(ed25519_signature)));

    memset(ed448_public, 0xa5, sizeof(ed448_public));
    CHECK(rintls_ed448_keygen(NULL, ed448_public) != 0);
    CHECK(all_zero(ed448_public, sizeof(ed448_public)));
    memset(ed448_public, 0xa5, sizeof(ed448_public));
    CHECK(rintls_ed448_public_from_private(NULL, ed448_public) != 0);
    CHECK(all_zero(ed448_public, sizeof(ed448_public)));
    memset(ed448_signature, 0xa5, sizeof(ed448_signature));
    CHECK(rintls_ed448_sign(ed448_signature, NULL, NULL, 1u, NULL, 0u) != 0);
    CHECK(all_zero(ed448_signature, sizeof(ed448_signature)));

    memset(x448_public, 0xa5, sizeof(x448_public));
    CHECK(rintls_x448_keygen(NULL, x448_public) != 0);
    CHECK(all_zero(x448_public, sizeof(x448_public)));
    memset(x448_public, 0xa5, sizeof(x448_public));
    CHECK(rintls_x448_public_from_private(NULL, x448_public) != 0);
    CHECK(all_zero(x448_public, sizeof(x448_public)));
    memset(x448_secret, 0xa5, sizeof(x448_secret));
    CHECK(rintls_x448_ecdh(x448_secret, NULL, x448_public) != 0);
    CHECK(all_zero(x448_secret, sizeof(x448_secret)));

    CHECK(rintls_mldsa_sizes(0xffffffffu, &public_size, &private_size,
                             &third_size) != 0);
    CHECK(public_size == 0u && private_size == 0u && third_size == 0u);
    memset(mldsa_public, 0xa5, sizeof(mldsa_public));
    memset(mldsa_private, 0xa5, sizeof(mldsa_private));
    CHECK(rintls_mldsa_keygen(RINTLS_MLDSA_87, NULL, mldsa_public,
                              mldsa_private) != 0);
    CHECK(all_zero(mldsa_public, sizeof(mldsa_public)));
    CHECK(all_zero(mldsa_private, sizeof(mldsa_private)));
    memset(mldsa_public, 0xa5, sizeof(mldsa_public));
    memset(mldsa_private, 0xa5, sizeof(mldsa_private));
    CHECK(rintls_mldsa_keygen_from_seed(RINTLS_MLDSA_87, NULL, mldsa_public,
                                        mldsa_private) != 0);
    CHECK(all_zero(mldsa_public, sizeof(mldsa_public)));
    CHECK(all_zero(mldsa_private, sizeof(mldsa_private)));
    memset(mldsa_public, 0xa5, sizeof(mldsa_public));
    CHECK(rintls_mldsa_public_from_private(RINTLS_MLDSA_87, mldsa_public,
                                            NULL) != 0);
    CHECK(all_zero(mldsa_public, sizeof(mldsa_public)));
    memset(mldsa_signature, 0xa5, sizeof(mldsa_signature));
    CHECK(rintls_mldsa_sign(RINTLS_MLDSA_87, mldsa_signature, NULL, 1u, NULL,
                            0u, NULL) != 0);
    CHECK(all_zero(mldsa_signature, sizeof(mldsa_signature)));
    memset(mldsa_seed, 0xa5, sizeof(mldsa_seed));
    CHECK(rintls_mldsa_keygen(0xffffffffu, mldsa_seed, NULL, NULL) != 0);
    CHECK(all_zero(mldsa_seed, sizeof(mldsa_seed)));

    public_size = private_size = third_size = 0xa5a5a5a5u;
    CHECK(rintls_mlkem_sizes(0xffffffffu, &public_size, &private_size,
                             &third_size) != 0);
    CHECK(public_size == 0u && private_size == 0u && third_size == 0u);
    memset(mlkem_public, 0xa5, sizeof(mlkem_public));
    memset(mlkem_private, 0xa5, sizeof(mlkem_private));
    CHECK(rintls_mlkem_keygen(RINTLS_MLKEM_1024, NULL, mlkem_public,
                              mlkem_private) != 0);
    CHECK(all_zero(mlkem_public, sizeof(mlkem_public)));
    CHECK(all_zero(mlkem_private, sizeof(mlkem_private)));
    memset(mlkem_public, 0xa5, sizeof(mlkem_public));
    memset(mlkem_private, 0xa5, sizeof(mlkem_private));
    CHECK(rintls_mlkem_keygen_from_seed(RINTLS_MLKEM_1024, NULL, mlkem_public,
                                        mlkem_private) != 0);
    CHECK(all_zero(mlkem_public, sizeof(mlkem_public)));
    CHECK(all_zero(mlkem_private, sizeof(mlkem_private)));
    memset(mlkem_public, 0xa5, sizeof(mlkem_public));
    CHECK(rintls_mlkem_public_from_private(RINTLS_MLKEM_1024, mlkem_public,
                                            NULL) != 0);
    CHECK(all_zero(mlkem_public, sizeof(mlkem_public)));
    memset(mlkem_ciphertext, 0xa5, sizeof(mlkem_ciphertext));
    memset(mlkem_secret, 0xa5, sizeof(mlkem_secret));
    CHECK(rintls_mlkem_encapsulate(RINTLS_MLKEM_1024, mlkem_ciphertext,
                                   mlkem_secret, NULL) != 0);
    CHECK(all_zero(mlkem_ciphertext, sizeof(mlkem_ciphertext)));
    CHECK(all_zero(mlkem_secret, sizeof(mlkem_secret)));
    memset(mlkem_secret, 0xa5, sizeof(mlkem_secret));
    CHECK(rintls_mlkem_decapsulate(RINTLS_MLKEM_1024, mlkem_secret, NULL,
                                   NULL) != 0);
    CHECK(all_zero(mlkem_secret, sizeof(mlkem_secret)));
    memset(mlkem_seed, 0xa5, sizeof(mlkem_seed));
    CHECK(rintls_mlkem_keygen(0xffffffffu, mlkem_seed, NULL, NULL) != 0);
    CHECK(all_zero(mlkem_seed, sizeof(mlkem_seed)));
    return 0;
}

static int test_overlapping_buffers_are_rejected_without_mutation(void)
{
    static const u8 message[] = "overlap must not erase input";
    static u8 nist_keygen[RINTLS_P521_PUBLIC_KEY_SIZE];
    static u8 nist_derive[199];
    static u8 nist_secret[199];
    static u8 nist_sign[198];
    static u8 nist_digest[198];
    static u8 peer_public[RINTLS_P521_PUBLIC_KEY_SIZE];
    static u8 digest[64];
    static u8 ed25519_key[RINTLS_ED25519_PRIVATE_KEY_SIZE];
    static u8 ed25519_sign[96];
    static u8 ed448_key[RINTLS_ED448_PRIVATE_KEY_SIZE];
    static u8 ed448_sign[171];
    static u8 x448_key[RINTLS_X448_KEY_SIZE];
    static u8 mldsa_keygen[4896];
    static u8 mldsa_seed_overlap[2600];
    static u8 mldsa_private[4896];
    static u8 mldsa_sign[8000];
    static u8 mldsa_seed[RINTLS_MLDSA_SEED_SIZE];
    static u8 mlkem_seed[RINTLS_MLKEM_SEED_SIZE];
    static u8 mlkem_keygen[3168];
    static u8 mlkem_seed_overlap[1600];
    static u8 mlkem_private[3168];
    static u8 mlkem_public[1568];
    static u8 mlkem_encapsulate[1568];
    static u8 mlkem_shared[RINTLS_MLKEM_SHARED_SECRET_SIZE];
    static u8 mlkem_decapsulate[3200];
    static u8 ciphertext[1568];

    test_random_mode = TEST_RANDOM_FAIL;
    test_random_calls = 0u;
    memset(peer_public, 0xa5, sizeof(peer_public));
    peer_public[0] = 0x04u;
    memset(digest, 0xa5, sizeof(digest));

    memset(nist_keygen, 0xa5, sizeof(nist_keygen));
    CHECK(rintls_nist_keygen(RINTLS_EC_P521, nist_keygen, nist_keygen) != 0);
    CHECK(all_value(nist_keygen, sizeof(nist_keygen), 0xa5));
    memset(nist_derive, 0xa5, sizeof(nist_derive));
    CHECK(rintls_nist_public_from_private(RINTLS_EC_P521, nist_derive + 66u,
                                          nist_derive) != 0);
    CHECK(all_value(nist_derive, sizeof(nist_derive), 0xa5));
    memset(nist_secret, 0xa5, sizeof(nist_secret));
    CHECK(rintls_nist_ecdh(RINTLS_EC_P521, nist_secret, nist_secret + 32u,
                           peer_public, sizeof(peer_public)) != 0);
    CHECK(all_value(nist_secret, sizeof(nist_secret), 0xa5));
    memset(nist_sign, 0xa5, sizeof(nist_sign));
    CHECK(rintls_nist_ecdsa_sign(RINTLS_EC_P521, RINTLS_HASH_SHA512, message,
                                 sizeof(message) - 1u, nist_sign + 66u,
                                 nist_sign) != 0);
    CHECK(all_value(nist_sign, sizeof(nist_sign), 0xa5));
    memset(nist_digest, 0xa5, sizeof(nist_digest));
    CHECK(rintls_nist_ecdsa_sign_digest(RINTLS_EC_P521, digest, sizeof(digest),
                                        nist_digest + 66u, nist_digest) != 0);
    CHECK(all_value(nist_digest, sizeof(nist_digest), 0xa5));

    memset(ed25519_key, 0xa5, sizeof(ed25519_key));
    CHECK(rintls_ed25519_keygen(ed25519_key, ed25519_key) != 0);
    CHECK(all_value(ed25519_key, sizeof(ed25519_key), 0xa5));
    CHECK(rintls_ed25519_public_from_private(ed25519_key, ed25519_key) != 0);
    CHECK(all_value(ed25519_key, sizeof(ed25519_key), 0xa5));
    memset(ed25519_sign, 0xa5, sizeof(ed25519_sign));
    CHECK(rintls_ed25519_sign(ed25519_sign, ed25519_sign + 32u, message,
                              sizeof(message) - 1u) != 0);
    CHECK(all_value(ed25519_sign, sizeof(ed25519_sign), 0xa5));

    memset(ed448_key, 0xa5, sizeof(ed448_key));
    CHECK(rintls_ed448_keygen(ed448_key, ed448_key) != 0);
    CHECK(all_value(ed448_key, sizeof(ed448_key), 0xa5));
    CHECK(rintls_ed448_public_from_private(ed448_key, ed448_key) != 0);
    CHECK(all_value(ed448_key, sizeof(ed448_key), 0xa5));
    memset(ed448_sign, 0xa5, sizeof(ed448_sign));
    CHECK(rintls_ed448_sign(ed448_sign, ed448_sign + 57u, message,
                            sizeof(message) - 1u, NULL, 0u) != 0);
    CHECK(all_value(ed448_sign, sizeof(ed448_sign), 0xa5));

    memset(x448_key, 0xa5, sizeof(x448_key));
    CHECK(rintls_x448_keygen(x448_key, x448_key) != 0);
    CHECK(all_value(x448_key, sizeof(x448_key), 0xa5));
    CHECK(rintls_x448_public_from_private(x448_key, x448_key) != 0);
    CHECK(all_value(x448_key, sizeof(x448_key), 0xa5));
    CHECK(rintls_x448_ecdh(x448_key, x448_key, peer_public) != 0);
    CHECK(all_value(x448_key, sizeof(x448_key), 0xa5));

    memset(mldsa_seed, 0xa5, sizeof(mldsa_seed));
    memset(mldsa_keygen, 0xa5, sizeof(mldsa_keygen));
    CHECK(rintls_mldsa_keygen(RINTLS_MLDSA_87, mldsa_seed, mldsa_keygen,
                              mldsa_keygen) != 0);
    CHECK(all_value(mldsa_seed, sizeof(mldsa_seed), 0xa5));
    CHECK(all_value(mldsa_keygen, sizeof(mldsa_keygen), 0xa5));
    memset(mldsa_seed_overlap, 0xa5, sizeof(mldsa_seed_overlap));
    memset(mldsa_private, 0xa5, sizeof(mldsa_private));
    CHECK(rintls_mldsa_keygen_from_seed(RINTLS_MLDSA_87,
                                        mldsa_seed_overlap,
                                        mldsa_seed_overlap,
                                        mldsa_private) != 0);
    CHECK(all_value(mldsa_seed_overlap, sizeof(mldsa_seed_overlap), 0xa5));
    CHECK(all_value(mldsa_private, sizeof(mldsa_private), 0xa5));
    memset(mldsa_private, 0xa5, sizeof(mldsa_private));
    CHECK(rintls_mldsa_public_from_private(RINTLS_MLDSA_87, mldsa_private,
                                            mldsa_private) != 0);
    CHECK(all_value(mldsa_private, sizeof(mldsa_private), 0xa5));
    memset(mldsa_sign, 0xa5, sizeof(mldsa_sign));
    CHECK(rintls_mldsa_sign(RINTLS_MLDSA_87, mldsa_sign, message,
                            sizeof(message) - 1u, NULL, 0u,
                            mldsa_sign + 3000u) != 0);
    CHECK(all_value(mldsa_sign, sizeof(mldsa_sign), 0xa5));

    memset(mlkem_keygen, 0xa5, sizeof(mlkem_keygen));
    memset(mlkem_seed, 0xa5, sizeof(mlkem_seed));
    CHECK(rintls_mlkem_keygen(RINTLS_MLKEM_1024, mlkem_seed, mlkem_keygen,
                              mlkem_keygen) != 0);
    CHECK(all_value(mlkem_seed, sizeof(mlkem_seed), 0xa5));
    CHECK(all_value(mlkem_keygen, sizeof(mlkem_keygen), 0xa5));
    memset(mlkem_seed_overlap, 0xa5, sizeof(mlkem_seed_overlap));
    memset(mlkem_private, 0xa5, sizeof(mlkem_private));
    CHECK(rintls_mlkem_keygen_from_seed(RINTLS_MLKEM_1024,
                                        mlkem_seed_overlap,
                                        mlkem_seed_overlap,
                                        mlkem_private) != 0);
    CHECK(all_value(mlkem_seed_overlap, sizeof(mlkem_seed_overlap), 0xa5));
    CHECK(all_value(mlkem_private, sizeof(mlkem_private), 0xa5));
    memset(mlkem_private, 0xa5, sizeof(mlkem_private));
    CHECK(rintls_mlkem_public_from_private(RINTLS_MLKEM_1024, mlkem_private,
                                            mlkem_private) != 0);
    CHECK(all_value(mlkem_private, sizeof(mlkem_private), 0xa5));
    memset(mlkem_encapsulate, 0xa5, sizeof(mlkem_encapsulate));
    memset(mlkem_shared, 0xa5, sizeof(mlkem_shared));
    memset(mlkem_public, 0xa5, sizeof(mlkem_public));
    CHECK(rintls_mlkem_encapsulate(RINTLS_MLKEM_1024, mlkem_encapsulate,
                                   mlkem_shared, mlkem_encapsulate) != 0);
    CHECK(all_value(mlkem_encapsulate, sizeof(mlkem_encapsulate), 0xa5));
    CHECK(all_value(mlkem_shared, sizeof(mlkem_shared), 0xa5));
    CHECK(rintls_mlkem_encapsulate(RINTLS_MLKEM_1024, mlkem_encapsulate,
                                   mlkem_encapsulate + 32u,
                                   mlkem_public) != 0);
    CHECK(all_value(mlkem_encapsulate, sizeof(mlkem_encapsulate), 0xa5));
    memset(mlkem_decapsulate, 0xa5, sizeof(mlkem_decapsulate));
    memset(ciphertext, 0xa5, sizeof(ciphertext));
    CHECK(rintls_mlkem_decapsulate(RINTLS_MLKEM_1024, mlkem_decapsulate,
                                   ciphertext, mlkem_decapsulate) != 0);
    CHECK(all_value(mlkem_decapsulate, sizeof(mlkem_decapsulate), 0xa5));
    CHECK(test_random_calls == 0u);
    return 0;
}

int main(void)
{
    CHECK(test_nist_entropy_failure(RINTLS_EC_P256, RINTLS_HASH_SHA256,
                                    RINTLS_P256_PRIVATE_KEY_SIZE,
                                    RINTLS_P256_PUBLIC_KEY_SIZE) == 0);
    CHECK(test_nist_entropy_failure(RINTLS_EC_P384, RINTLS_HASH_SHA384,
                                    RINTLS_P384_PRIVATE_KEY_SIZE,
                                    RINTLS_P384_PUBLIC_KEY_SIZE) == 0);
    CHECK(test_nist_entropy_failure(RINTLS_EC_P521, RINTLS_HASH_SHA512,
                                    RINTLS_P521_PRIVATE_KEY_SIZE,
                                    RINTLS_P521_PUBLIC_KEY_SIZE) == 0);
    CHECK(test_edwards_and_x448_entropy_failure() == 0);
    CHECK(test_mldsa_entropy_failure(RINTLS_MLDSA_44) == 0);
    CHECK(test_mldsa_entropy_failure(RINTLS_MLDSA_65) == 0);
    CHECK(test_mldsa_entropy_failure(RINTLS_MLDSA_87) == 0);
    CHECK(test_mlkem_entropy_failure(RINTLS_MLKEM_512) == 0);
    CHECK(test_mlkem_entropy_failure(RINTLS_MLKEM_768) == 0);
    CHECK(test_mlkem_entropy_failure(RINTLS_MLKEM_1024) == 0);
    CHECK(test_invalid_inputs_clear_known_outputs() == 0);
    CHECK(test_overlapping_buffers_are_rejected_without_mutation() == 0);
    return 0;
}
