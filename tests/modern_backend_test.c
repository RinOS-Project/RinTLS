/* SPDX-License-Identifier: MIT */
/*
 * Runtime coverage for the rintls modern-provider boundary.  The CMake
 * target is deliberately a host-only test: it exercises the exact libecc and
 * FIPS 203/204 translation units linked into RinTLSShim, not a mock backend.
 */

#include "crypto/modern.h"
#include "crypto/pqc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expression)                                                     \
    do {                                                                      \
        if (!(expression)) {                                                  \
            fprintf(stderr, "%s:%d: %s\\n", __FILE__, __LINE__, #expression); \
            return 1;                                                         \
        }                                                                     \
    } while (0)

static int all_zero(const u8* bytes, size_t size)
{
    size_t index;

    for (index = 0; index < size; ++index) {
        if (bytes[index] != 0)
            return 0;
    }
    return 1;
}

static int decode_hex(const char* text, u8* output, size_t output_size)
{
    size_t index;

    for (index = 0; index < output_size; ++index) {
        unsigned int byte;
        if (sscanf(text + index * 2u, "%2x", &byte) != 1)
            return -1;
        output[index] = (u8)byte;
    }
    return text[output_size * 2u] == '\0' ? 0 : -1;
}

static int test_nist_curve(u32 curve, rin_size_t scalar_size,
                           rin_size_t public_size)
{
    u8 private_a[RINTLS_P521_PRIVATE_KEY_SIZE];
    u8 private_b[RINTLS_P521_PRIVATE_KEY_SIZE];
    u8 public_a[RINTLS_P521_PUBLIC_KEY_SIZE];
    u8 public_b[RINTLS_P521_PUBLIC_KEY_SIZE];
    u8 derived_public[RINTLS_P521_PUBLIC_KEY_SIZE];
    u8 secret_a[RINTLS_P521_PRIVATE_KEY_SIZE];
    u8 secret_b[RINTLS_P521_PRIVATE_KEY_SIZE];
    u8 signature[RINTLS_P521_PRIVATE_KEY_SIZE * 2u];
    u8 digest[64];
    static const u8 message[] = "rintls P-384/P-521 backend test";

    memset(private_a, 0, sizeof(private_a));
    memset(private_b, 0, sizeof(private_b));
    memset(public_a, 0, sizeof(public_a));
    memset(public_b, 0, sizeof(public_b));
    memset(derived_public, 0, sizeof(derived_public));
    memset(secret_a, 0, sizeof(secret_a));
    memset(secret_b, 0, sizeof(secret_b));
    memset(signature, 0, sizeof(signature));
    memset(digest, 0x5a, sizeof(digest));

    CHECK(rintls_nist_keygen(curve, private_a, public_a) == 0);
    CHECK(rintls_nist_keygen(curve, private_b, public_b) == 0);
    CHECK(rintls_nist_validate_public(curve, public_a, public_size) == 0);
    CHECK(rintls_nist_public_from_private(curve, private_a, derived_public) == 0);
    CHECK(memcmp(public_a, derived_public, public_size) == 0);
    CHECK(rintls_nist_ecdh(curve, secret_a, private_a, public_b, public_size) == 0);
    CHECK(rintls_nist_ecdh(curve, secret_b, private_b, public_a, public_size) == 0);
    CHECK(memcmp(secret_a, secret_b, scalar_size) == 0);
    CHECK(rintls_nist_ecdsa_sign(curve, RINTLS_HASH_SHA384, message,
                                 sizeof(message) - 1u, private_a, signature) == 0);
    CHECK(rintls_nist_ecdsa_verify(curve, RINTLS_HASH_SHA384, message,
                                   sizeof(message) - 1u, public_a, public_size,
                                   signature, scalar_size * 2u) == 0);
    signature[0] ^= 1u;
    CHECK(rintls_nist_ecdsa_verify(curve, RINTLS_HASH_SHA384, message,
                                   sizeof(message) - 1u, public_a, public_size,
                                   signature, scalar_size * 2u) != 0);
    CHECK(rintls_nist_ecdsa_sign_digest(curve, digest, sizeof(digest),
                                        private_a, signature) == 0);
    CHECK(rintls_nist_ecdsa_verify_digest(curve, digest, sizeof(digest),
                                          public_a, public_size, signature,
                                          scalar_size * 2u) == 0);
    digest[0] ^= 1u;
    CHECK(rintls_nist_ecdsa_verify_digest(curve, digest, sizeof(digest),
                                          public_a, public_size, signature,
                                          scalar_size * 2u) != 0);
    memset(signature, 0xa5, sizeof(signature));
    CHECK(rintls_nist_ecdsa_sign_digest(curve, digest, 1u, private_a,
                                        signature) != 0);
    CHECK(all_zero(signature, scalar_size * 2u));
    public_a[0] = 0x02;
    CHECK(rintls_nist_validate_public(curve, public_a, public_size) != 0);
    return 0;
}

static int test_ed25519_vector(void)
{
    static const char private_hex[] =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    static const char public_hex[] =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    static const char signature_hex[] =
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
    u8 private_key[RINTLS_ED25519_PRIVATE_KEY_SIZE];
    u8 public_key[RINTLS_ED25519_PUBLIC_KEY_SIZE];
    u8 signature[RINTLS_ED25519_SIGNATURE_SIZE];
    u8 expected_public_key[RINTLS_ED25519_PUBLIC_KEY_SIZE];
    u8 expected_signature[RINTLS_ED25519_SIGNATURE_SIZE];

    CHECK(decode_hex(private_hex, private_key, sizeof(private_key)) == 0);
    CHECK(decode_hex(public_hex, public_key, sizeof(public_key)) == 0);
    CHECK(decode_hex(signature_hex, signature, sizeof(signature)) == 0);
    CHECK(decode_hex(public_hex, expected_public_key, sizeof(expected_public_key)) == 0);
    CHECK(decode_hex(signature_hex, expected_signature, sizeof(expected_signature)) == 0);
    CHECK(rintls_ed25519_verify(signature, public_key, NULL, 0) == 0);
    CHECK(rintls_ed25519_public_from_private(private_key, public_key) == 0);
    CHECK(memcmp(public_key, expected_public_key, sizeof(public_key)) == 0);
    CHECK(rintls_ed25519_sign(signature, private_key, NULL, 0) == 0);
    CHECK(memcmp(signature, expected_signature, sizeof(signature)) == 0);
    signature[0] ^= 1u;
    CHECK(rintls_ed25519_verify(signature, public_key, NULL, 0) != 0);
    return 0;
}

static int test_ed448_vector(void)
{
    static const char private_hex[] =
        "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3"
        "528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b";
    static const char public_hex[] =
        "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778"
        "edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180";
    static const char signature_hex[] =
        "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f"
        "2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a"
        "9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4db"
        "b61149f05a7363268c71d95808ff2e652600";
    u8 private_key[RINTLS_ED448_PRIVATE_KEY_SIZE];
    u8 public_key[RINTLS_ED448_PUBLIC_KEY_SIZE];
    u8 signature[RINTLS_ED448_SIGNATURE_SIZE];
    u8 expected_public_key[RINTLS_ED448_PUBLIC_KEY_SIZE];
    u8 expected_signature[RINTLS_ED448_SIGNATURE_SIZE];

    CHECK(decode_hex(private_hex, private_key, sizeof(private_key)) == 0);
    CHECK(decode_hex(public_hex, public_key, sizeof(public_key)) == 0);
    CHECK(decode_hex(signature_hex, signature, sizeof(signature)) == 0);
    CHECK(decode_hex(public_hex, expected_public_key, sizeof(expected_public_key)) == 0);
    CHECK(decode_hex(signature_hex, expected_signature, sizeof(expected_signature)) == 0);
    CHECK(rintls_ed448_verify(signature, public_key, NULL, 0, NULL, 0) == 0);
    CHECK(rintls_ed448_public_from_private(private_key, public_key) == 0);
    CHECK(memcmp(public_key, expected_public_key, sizeof(public_key)) == 0);
    CHECK(rintls_ed448_sign(signature, private_key, NULL, 0, NULL, 0) == 0);
    CHECK(memcmp(signature, expected_signature, sizeof(signature)) == 0);
    signature[0] ^= 1u;
    CHECK(rintls_ed448_verify(signature, public_key, NULL, 0, NULL, 0) != 0);
    return 0;
}

static int test_x448_vector(void)
{
    static const char private_hex[] =
        "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf5"
        "74a9419744897391006382a6f127ab1d9ac2d8c0a598726b";
    static const char public_hex[] =
        "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bb"
        "c836647241d953d40c5b12da88120d53177f80e532c41fa0";
    static const char peer_public_hex[] =
        "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972"
        "fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609";
    static const char secret_hex[] =
        "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56"
        "fd2464c335543936521c24403085d59a449a5037514a879d";
    u8 private_key[RINTLS_X448_KEY_SIZE];
    u8 public_key[RINTLS_X448_KEY_SIZE];
    u8 peer_public_key[RINTLS_X448_KEY_SIZE];
    u8 shared_secret[RINTLS_X448_KEY_SIZE];
    u8 expected_secret[RINTLS_X448_KEY_SIZE];

    CHECK(decode_hex(private_hex, private_key, sizeof(private_key)) == 0);
    CHECK(decode_hex(public_hex, public_key, sizeof(public_key)) == 0);
    CHECK(decode_hex(peer_public_hex, peer_public_key, sizeof(peer_public_key)) == 0);
    CHECK(decode_hex(secret_hex, expected_secret, sizeof(expected_secret)) == 0);
    CHECK(rintls_x448_public_from_private(private_key, public_key) == 0);
    CHECK(rintls_x448_ecdh(shared_secret, private_key, peer_public_key) == 0);
    CHECK(memcmp(shared_secret, expected_secret, sizeof(shared_secret)) == 0);
    memset(peer_public_key, 0, sizeof(peer_public_key));
    memset(shared_secret, 0xa5, sizeof(shared_secret));
    CHECK(rintls_x448_ecdh(shared_secret, private_key, peer_public_key) != 0);
    CHECK(all_zero(shared_secret, sizeof(shared_secret)));
    return 0;
}

static int test_mldsa(u32 level)
{
    rin_size_t public_size;
    rin_size_t private_size;
    rin_size_t signature_size;
    u8 seed[RINTLS_MLDSA_SEED_SIZE];
    u8* public_key;
    u8* derived_public_key;
    u8* private_key;
    u8* signature;
    static const u8 message[] = "ML-DSA rintls backend";
    static const u8 context[] = "rinos";

    CHECK(rintls_mldsa_sizes(level, &public_size, &private_size, &signature_size) == 0);
    memset(seed, (int)level, sizeof(seed));
    public_key = malloc(public_size);
    derived_public_key = malloc(public_size);
    private_key = malloc(private_size);
    signature = malloc(signature_size);
    CHECK(public_key && derived_public_key && private_key && signature);
    CHECK(rintls_mldsa_keygen_from_seed(level, seed, public_key, private_key) == 0);
    CHECK(rintls_mldsa_public_from_private(level, derived_public_key, private_key) == 0);
    CHECK(memcmp(public_key, derived_public_key, public_size) == 0);
    CHECK(rintls_mldsa_sign(level, signature, message, sizeof(message) - 1u,
                            context, sizeof(context) - 1u, private_key) == 0);
    CHECK(rintls_mldsa_verify(level, signature, message, sizeof(message) - 1u,
                              context, sizeof(context) - 1u, public_key) ==
          RINTLS_PQC_VERIFY_VALID);
    signature[0] ^= 1u;
    CHECK(rintls_mldsa_verify(level, signature, message, sizeof(message) - 1u,
                              context, sizeof(context) - 1u, public_key) ==
          RINTLS_PQC_VERIFY_INVALID);
    free(signature);
    free(private_key);
    free(derived_public_key);
    free(public_key);
    return 0;
}

static int test_mlkem(u32 level)
{
    rin_size_t public_size;
    rin_size_t private_size;
    rin_size_t ciphertext_size;
    u8 seed[RINTLS_MLKEM_SEED_SIZE];
    u8 shared_secret[RINTLS_MLKEM_SHARED_SECRET_SIZE];
    u8 recovered_secret[RINTLS_MLKEM_SHARED_SECRET_SIZE];
    u8 rejected_secret[RINTLS_MLKEM_SHARED_SECRET_SIZE];
    u8* public_key;
    u8* derived_public_key;
    u8* private_key;
    u8* ciphertext;

    CHECK(rintls_mlkem_sizes(level, &public_size, &private_size, &ciphertext_size) == 0);
    memset(seed, (int)(level >> 8), sizeof(seed));
    public_key = malloc(public_size);
    derived_public_key = malloc(public_size);
    private_key = malloc(private_size);
    ciphertext = malloc(ciphertext_size);
    CHECK(public_key && derived_public_key && private_key && ciphertext);
    CHECK(rintls_mlkem_keygen_from_seed(level, seed, public_key, private_key) == 0);
    CHECK(rintls_mlkem_public_from_private(level, derived_public_key, private_key) == 0);
    CHECK(memcmp(public_key, derived_public_key, public_size) == 0);
    CHECK(rintls_mlkem_encapsulate(level, ciphertext, shared_secret, public_key) == 0);
    CHECK(rintls_mlkem_decapsulate(level, recovered_secret, ciphertext, private_key) == 0);
    CHECK(memcmp(shared_secret, recovered_secret, sizeof(shared_secret)) == 0);
    ciphertext[0] ^= 1u;
    CHECK(rintls_mlkem_decapsulate(level, rejected_secret, ciphertext, private_key) == 0);
    CHECK(memcmp(shared_secret, rejected_secret, sizeof(shared_secret)) != 0);
    /* sk = s || pk || H(pk) || z: z is deliberately independent, whereas
     * corrupting H(pk) must make public-key extraction reject the key. */
    private_key[private_size - RINTLS_MLKEM_SHARED_SECRET_SIZE - 1u] ^= 1u;
    CHECK(rintls_mlkem_public_from_private(level, derived_public_key, private_key) != 0);
    memset(rejected_secret, 0xa5, sizeof(rejected_secret));
    CHECK(rintls_mlkem_decapsulate(level, rejected_secret, ciphertext, private_key) != 0);
    CHECK(all_zero(rejected_secret, sizeof(rejected_secret)));
    free(ciphertext);
    free(private_key);
    free(derived_public_key);
    free(public_key);
    return 0;
}

int main(void)
{
    CHECK(test_nist_curve(RINTLS_EC_P384, RINTLS_P384_PRIVATE_KEY_SIZE,
                          RINTLS_P384_PUBLIC_KEY_SIZE) == 0);
    CHECK(test_nist_curve(RINTLS_EC_P521, RINTLS_P521_PRIVATE_KEY_SIZE,
                          RINTLS_P521_PUBLIC_KEY_SIZE) == 0);
    CHECK(test_ed25519_vector() == 0);
    CHECK(test_ed448_vector() == 0);
    CHECK(test_x448_vector() == 0);
    CHECK(test_mldsa(RINTLS_MLDSA_44) == 0);
    CHECK(test_mldsa(RINTLS_MLDSA_65) == 0);
    CHECK(test_mldsa(RINTLS_MLDSA_87) == 0);
    CHECK(test_mlkem(RINTLS_MLKEM_512) == 0);
    CHECK(test_mlkem(RINTLS_MLKEM_768) == 0);
    CHECK(test_mlkem(RINTLS_MLKEM_1024) == 0);
    return 0;
}
