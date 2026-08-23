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
    return 0;
}
