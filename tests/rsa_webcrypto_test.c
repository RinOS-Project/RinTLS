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

int main(void)
{
    test_keygen_and_oaep_fail_closed();
    test_oaep_and_pkcs1();
    test_pss();
    puts("rsa_webcrypto_test: OK");
    return 0;
}
