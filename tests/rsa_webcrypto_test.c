#include "../crypto/rsa_webcrypto.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

enum random_mode {
    RANDOM_MODE_FAIL,
    RANDOM_MODE_FIXED,
};

static enum random_mode test_random_mode;
static unsigned int test_random_calls;

void* platform_memset(void* destination, int value, u32 length)
{
    return memset(destination, value, length);
}

void* platform_memcpy(void* destination, const void* source, u32 length)
{
    return memcpy(destination, source, length);
}

int platform_memcmp(const void* left, const void* right, u32 length)
{
    return memcmp(left, right, length);
}

int rin_get_random_bytes(void* buffer, u32 length)
{
    ++test_random_calls;
    if (test_random_mode == RANDOM_MODE_FAIL)
        return -1;
    memset(buffer, 0x5a, length);
    return 0;
}

static int bytes_are_zero(const void* bytes, size_t length)
{
    const u8* cursor = bytes;
    size_t index;

    for (index = 0; index < length; ++index) {
        if (cursor[index] != 0)
            return 0;
    }
    return 1;
}

static int bytes_have_value(const void* bytes, size_t length, u8 value)
{
    const u8* cursor = bytes;
    size_t index;

    for (index = 0; index < length; ++index) {
        if (cursor[index] != value)
            return 0;
    }
    return 1;
}

static void test_keygen_and_oaep_fail_closed(void)
{
    rintls_rsa_private_key key;
    u8 ciphertext[RINTLS_RSA_MAX_MODULUS_BYTES];
    u8 too_small[255];
    rin_size_t ciphertext_length = 0;
    static const u8 message[] = "rintls rsa oaep round trip";

    memset(&key, 0xa5, sizeof(key));
    test_random_mode = RANDOM_MODE_FAIL;
    test_random_calls = 0;
    assert(rintls_rsa_generate_keypair(2048u, 65537u, &key) != 0);
    assert(test_random_calls == 1u);
    assert(bytes_are_zero(&key, sizeof(key)));

    test_random_mode = RANDOM_MODE_FIXED;
    assert(rintls_rsa_generate_keypair(2048u, 65537u, &key) == 0);
    assert(key.public_key.modulus_len == 256u);
    assert(key.public_key.public_exponent_len == 3u);
    assert(key.private_exponent_len != 0);

    memset(too_small, 0xa5, sizeof(too_small));
    ciphertext_length = 1;
    assert(rintls_rsa_oaep_encrypt(RINTLS_RSA_HASH_SHA256, &key.public_key,
                                   NULL, 0, message, sizeof(message) - 1u,
                                   too_small, sizeof(too_small),
                                   &ciphertext_length) != 0);
    assert(bytes_are_zero(too_small, sizeof(too_small)));
    assert(ciphertext_length == 0);

    memset(ciphertext, 0xa5, sizeof(ciphertext));
    test_random_mode = RANDOM_MODE_FAIL;
    assert(rintls_rsa_oaep_encrypt(RINTLS_RSA_HASH_SHA256, &key.public_key,
                                   NULL, 0, message, sizeof(message) - 1u,
                                   ciphertext, sizeof(ciphertext),
                                   &ciphertext_length) != 0);
    assert(bytes_are_zero(ciphertext, sizeof(ciphertext)));
    assert(ciphertext_length == 0);
}

static void test_oaep_and_pkcs1(void)
{
    rintls_rsa_private_key key;
    u8 ciphertext[RINTLS_RSA_MAX_MODULUS_BYTES];
    u8 plaintext[RINTLS_RSA_MAX_MODULUS_BYTES];
    u8 compact_plaintext[32];
    u8 signature[RINTLS_RSA_MAX_MODULUS_BYTES];
    rin_size_t ciphertext_length = 0;
    rin_size_t plaintext_length = 0;
    rin_size_t signature_length = 0;
    static const u8 label[] = "rintls-label";
    static const u8 message[] = "rintls pkcs1 v1.5 message";

    test_random_mode = RANDOM_MODE_FIXED;
    assert(rintls_rsa_generate_keypair(2048u, 65537u, &key) == 0);
    assert(rintls_rsa_oaep_encrypt(RINTLS_RSA_HASH_SHA256, &key.public_key,
                                   label, sizeof(label) - 1u, message,
                                   sizeof(message) - 1u, ciphertext,
                                   sizeof(ciphertext), &ciphertext_length) == 0);
    assert(ciphertext_length == key.public_key.modulus_len);
    assert(rintls_rsa_oaep_decrypt(RINTLS_RSA_HASH_SHA256, &key, ciphertext,
                                   ciphertext_length, label, sizeof(label) - 1u,
                                   plaintext, sizeof(plaintext),
                                   &plaintext_length) == 0);
    assert(plaintext_length == sizeof(message) - 1u);
    assert(memcmp(plaintext, message, plaintext_length) == 0);

    /* Decryption output capacity describes the plaintext buffer, not the
     * modulus-sized ciphertext scratch used internally by the provider. */
    memset(compact_plaintext, 0xa5, sizeof(compact_plaintext));
    plaintext_length = (rin_size_t)0xa5a5a5a5u;
    assert(rintls_rsa_oaep_decrypt(RINTLS_RSA_HASH_SHA256, &key,
                                   ciphertext, ciphertext_length, label,
                                   sizeof(label) - 1u, compact_plaintext,
                                   sizeof(compact_plaintext),
                                   &plaintext_length) == 0);
    assert(plaintext_length == sizeof(message) - 1u);
    assert(memcmp(compact_plaintext, message, plaintext_length) == 0);

    /* A capacity smaller than the recovered message remains failure-atomic. */
    memset(compact_plaintext, 0xa5, sizeof(compact_plaintext));
    plaintext_length = (rin_size_t)0xa5a5a5a5u;
    assert(rintls_rsa_oaep_decrypt(RINTLS_RSA_HASH_SHA256, &key,
                                   ciphertext, ciphertext_length, label,
                                   sizeof(label) - 1u, compact_plaintext, 8u,
                                   &plaintext_length) != 0);
    assert(bytes_are_zero(compact_plaintext, 8u));
    assert(plaintext_length == 0u);

    assert(rintls_rsa_pkcs1_sign(RINTLS_RSA_HASH_SHA256, &key, message,
                                 sizeof(message) - 1u, signature, sizeof(signature),
                                 &signature_length) == 0);
    assert(signature_length == key.public_key.modulus_len);
    assert(rintls_rsa_pkcs1_verify(RINTLS_RSA_HASH_SHA256, &key.public_key,
                                   message, sizeof(message) - 1u, signature,
                                   signature_length) == RINTLS_RSA_VERIFY_VALID);
    signature[0] ^= 1u;
    assert(rintls_rsa_pkcs1_verify(RINTLS_RSA_HASH_SHA256, &key.public_key,
                                   message, sizeof(message) - 1u, signature,
                                   signature_length) == RINTLS_RSA_VERIFY_INVALID);
}

static void test_raw_rsa_and_generic_emsa(void)
{
    rintls_rsa_private_key key;
    u8 encoded[RINTLS_RSA_MAX_MODULUS_BYTES];
    u8 signature[RINTLS_RSA_MAX_MODULUS_BYTES];
    u8 recovered[RINTLS_RSA_MAX_MODULUS_BYTES];
    u8 too_small[255];
    u8 representative[RINTLS_RSA_MAX_MODULUS_BYTES];
    rin_size_t encoded_length = 0;
    rin_size_t signature_length = 0;
    rin_size_t recovered_length = 0;
    static const u8 message[] = "generic emsa payload";

    test_random_mode = RANDOM_MODE_FIXED;
    assert(rintls_rsa_generate_keypair(2048u, 65537u, &key) == 0);
    assert(rintls_rsa_emsa_pkcs1_encode(
               message, sizeof(message) - 1u, key.public_key.modulus_len,
               encoded, sizeof(encoded), &encoded_length) == 0);
    assert(encoded_length == key.public_key.modulus_len);
    assert(rintls_rsa_emsa_pkcs1_verify(
               message, sizeof(message) - 1u, key.public_key.modulus_len,
               encoded, encoded_length) == RINTLS_RSA_VERIFY_VALID);
    encoded[2] = 0u;
    assert(rintls_rsa_emsa_pkcs1_verify(
               message, sizeof(message) - 1u, key.public_key.modulus_len,
               encoded, encoded_length) == RINTLS_RSA_VERIFY_INVALID);
    encoded[2] = 0xffu;

    assert(rintls_rsa_raw_private(&key, encoded, encoded_length, signature,
                                  sizeof(signature), &signature_length) == 0);
    assert(signature_length == key.public_key.modulus_len);
    assert(rintls_rsa_raw_public(&key.public_key, signature, signature_length,
                                 recovered, sizeof(recovered),
                                 &recovered_length) == 0);
    assert(recovered_length == encoded_length);
    assert(memcmp(recovered, encoded, encoded_length) == 0);
    assert(rintls_rsa_emsa_pkcs1_verify(
               message, sizeof(message) - 1u, key.public_key.modulus_len,
               recovered, recovered_length) == RINTLS_RSA_VERIFY_VALID);

    memset(representative, 0xff, sizeof(representative));
    memset(recovered, 0xa5, sizeof(recovered));
    recovered_length = (rin_size_t)0xa5a5a5a5u;
    assert(rintls_rsa_raw_public(&key.public_key, representative,
                                 sizeof(representative), recovered,
                                 sizeof(recovered), &recovered_length) != 0);
    assert(bytes_are_zero(recovered, sizeof(recovered)));
    assert(recovered_length == 0u);

    memset(too_small, 0xa5, sizeof(too_small));
    encoded_length = (rin_size_t)0xa5a5a5a5u;
    assert(rintls_rsa_emsa_pkcs1_encode(
               message, sizeof(message) - 1u, key.public_key.modulus_len,
               too_small, sizeof(too_small), &encoded_length) != 0);
    assert(bytes_are_zero(too_small, sizeof(too_small)));
    assert(encoded_length == 0u);

    assert(rintls_rsa_emsa_pkcs1_verify(
               message, sizeof(message) - 1u, key.public_key.modulus_len,
               encoded, key.public_key.modulus_len - 1u) ==
           RINTLS_RSA_VERIFY_INVALID);
}

static void test_pss(void)
{
    rintls_rsa_private_key key;
    u8 signature[RINTLS_RSA_MAX_MODULUS_BYTES];
    u8 exact_signature[256];
    u8 too_small[255];
    rin_size_t signature_length = 0;
    static const u8 message[] = "rintls pss message";

    test_random_mode = RANDOM_MODE_FIXED;
    assert(rintls_rsa_generate_keypair(2048u, 65537u, &key) == 0);

    assert(rintls_rsa_pss_sign(RINTLS_RSA_HASH_SHA256, &key, message,
                               sizeof(message) - 1u, 32u, signature,
                               sizeof(signature), &signature_length) == 0);
    assert(signature_length == key.public_key.modulus_len);
    assert(rintls_rsa_pss_verify(RINTLS_RSA_HASH_SHA256, &key.public_key,
                                 message, sizeof(message) - 1u, 32u,
                                 signature, signature_length) ==
           RINTLS_RSA_VERIFY_VALID);
    assert(rintls_rsa_pss_sign(RINTLS_RSA_HASH_SHA256, &key, message,
                               sizeof(message) - 1u, 32u, exact_signature,
                               sizeof(exact_signature), &signature_length) == 0);
    assert(signature_length == sizeof(exact_signature));
    assert(rintls_rsa_pss_verify(RINTLS_RSA_HASH_SHA256, &key.public_key,
                                 message, sizeof(message) - 1u, 32u,
                                 exact_signature, signature_length) ==
           RINTLS_RSA_VERIFY_VALID);
    signature[0] ^= 1u;
    assert(rintls_rsa_pss_verify(RINTLS_RSA_HASH_SHA256, &key.public_key,
                                 message, sizeof(message) - 1u, 32u,
                                 signature, signature_length) ==
           RINTLS_RSA_VERIFY_INVALID);

    assert(rintls_rsa_pss_sign(RINTLS_RSA_HASH_SHA256, &key, message,
                               sizeof(message) - 1u,
                               RINTLS_RSA_PSS_SALT_LENGTH_MAX, signature,
                               sizeof(signature), &signature_length) == 0);
    assert(rintls_rsa_pss_verify(RINTLS_RSA_HASH_SHA256, &key.public_key,
                                 message, sizeof(message) - 1u,
                                 RINTLS_RSA_PSS_SALT_LENGTH_MAX, signature,
                                 signature_length) == RINTLS_RSA_VERIFY_VALID);

    memset(too_small, 0xa5, sizeof(too_small));
    signature_length = 1;
    assert(rintls_rsa_pss_sign(RINTLS_RSA_HASH_SHA256, &key, message,
                               sizeof(message) - 1u, 32u, too_small,
                               sizeof(too_small), &signature_length) != 0);
    assert(bytes_are_zero(too_small, sizeof(too_small)));
    assert(signature_length == 0);

    memset(signature, 0xa5, sizeof(signature));
    signature_length = 1;
    test_random_mode = RANDOM_MODE_FAIL;
    test_random_calls = 0;
    assert(rintls_rsa_pss_sign(RINTLS_RSA_HASH_SHA256, &key, message,
                               sizeof(message) - 1u, 32u, signature,
                               sizeof(signature), &signature_length) != 0);
    assert(test_random_calls == 1u);
    assert(bytes_are_zero(signature, sizeof(signature)));
    assert(signature_length == 0);
}

static void test_overlapping_result_buffers_are_immutable(void)
{
    rintls_rsa_private_key key;
    u8 overlap[RINTLS_RSA_MAX_MODULUS_BYTES];
    u8 label[] = "rsa overlap label";
    rin_size_t result_length = (rin_size_t)0xa5a5a5a5u;
    union {
        rin_size_t length;
        u8 bytes[RINTLS_RSA_MAX_MODULUS_BYTES];
    } output_and_length;

    test_random_mode = RANDOM_MODE_FIXED;
    assert(rintls_rsa_generate_keypair(2048u, 65537u, &key) == 0);
    test_random_mode = RANDOM_MODE_FAIL;
    test_random_calls = 0u;

    memset(overlap, 0xa5, sizeof(overlap));
    assert(rintls_rsa_oaep_encrypt(RINTLS_RSA_HASH_SHA256, &key.public_key,
                                   label, sizeof(label) - 1u, overlap + 32u,
                                   16u, overlap, sizeof(overlap),
                                   &result_length) != 0);
    assert(bytes_have_value(overlap, sizeof(overlap), 0xa5));
    assert(result_length == (rin_size_t)0xa5a5a5a5u);
    assert(test_random_calls == 0u);

    memset(overlap, 0xa5, sizeof(overlap));
    result_length = (rin_size_t)0xa5a5a5a5u;
    assert(rintls_rsa_oaep_decrypt(RINTLS_RSA_HASH_SHA256, &key, overlap,
                                   256u, label, sizeof(label) - 1u, overlap,
                                   sizeof(overlap), &result_length) != 0);
    assert(bytes_have_value(overlap, sizeof(overlap), 0xa5));
    assert(result_length == (rin_size_t)0xa5a5a5a5u);

    memset(overlap, 0xa5, sizeof(overlap));
    result_length = (rin_size_t)0xa5a5a5a5u;
    assert(rintls_rsa_pkcs1_sign(RINTLS_RSA_HASH_SHA256, &key, overlap + 32u,
                                 16u, overlap, sizeof(overlap),
                                 &result_length) != 0);
    assert(bytes_have_value(overlap, sizeof(overlap), 0xa5));
    assert(result_length == (rin_size_t)0xa5a5a5a5u);

    memset(overlap, 0xa5, sizeof(overlap));
    result_length = (rin_size_t)0xa5a5a5a5u;
    assert(rintls_rsa_pss_sign(RINTLS_RSA_HASH_SHA256, &key, overlap + 32u,
                               16u, 32u, overlap, sizeof(overlap),
                               &result_length) != 0);
    assert(bytes_have_value(overlap, sizeof(overlap), 0xa5));
    assert(result_length == (rin_size_t)0xa5a5a5a5u);

    memset(&output_and_length, 0xa5, sizeof(output_and_length));
    assert(rintls_rsa_oaep_encrypt(RINTLS_RSA_HASH_SHA256, &key.public_key,
                                   label, sizeof(label) - 1u, label,
                                   sizeof(label) - 1u, output_and_length.bytes,
                                   sizeof(output_and_length.bytes),
                                   &output_and_length.length) != 0);
    assert(bytes_have_value(output_and_length.bytes,
                            sizeof(output_and_length.bytes), 0xa5));
    assert(test_random_calls == 0u);
}

int main(void)
{
    test_keygen_and_oaep_fail_closed();
    test_oaep_and_pkcs1();
    test_raw_rsa_and_generic_emsa();
    test_pss();
    test_overlapping_result_buffers_are_immutable();
    puts("rsa_webcrypto_test: OK");
    return 0;
}
