/*
 * rinTLS modern public-key provider boundary.
 *
 * libecc supplies the constant-time curve implementations.  This file keeps
 * its variable-size objects and entropy callback private to rintls, while the
 * caller sees only the fixed-width encodings standardized by WebCrypto.
 */

#include "modern.h"

#include <libecc/curves/ec_params.h>
#include <libecc/curves/known/ec_params_secp256r1.h>
#include <libecc/curves/known/ec_params_secp384r1.h>
#include <libecc/curves/known/ec_params_secp521r1.h>
#include <libecc/curves/known/ec_params_wei25519.h>
#include <libecc/curves/known/ec_params_wei448.h>
#include <libecc/ecdh/ecccdh.h>
#include <libecc/ecdh/x25519_448.h>
#include <libecc/sig/ec_key.h>
#include <libecc/sig/ecdsa.h>
#include <libecc/sig/eddsa.h>
#include <libecc/sig/sig_algs.h>

#define RINTLS_NIST_MAX_PRIVATE_KEY_SIZE RINTLS_P521_PRIVATE_KEY_SIZE
#define RINTLS_NIST_MAX_AFFINE_POINT_SIZE (RINTLS_P521_PUBLIC_KEY_SIZE - 1u)

/* This is called by libecc's patched external_deps/rand.c. */
int rintls_libecc_get_random(unsigned char* buffer, u16 length)
{
    return rintls_get_random((u8*)buffer, (rin_size_t)length);
}

static int rintls_message_is_valid(const u8* message, rin_size_t message_len)
{
    return (message != NULL || message_len == 0) && message_len <= 0xffffffffu;
}

static int rintls_context_is_valid(const u8* context, rin_size_t context_len)
{
    return (context != NULL || context_len == 0) && context_len <= 255u;
}

/* A caller may reuse an output buffer after an admission failure.  Clear every
 * output whose fixed size is known before inspecting the other inputs, so an
 * invalid peer/key/message cannot make a prior key, signature, or secret look
 * like the result of this operation. */
static void rintls_clear_output(void* output, rin_size_t output_size)
{
    if (output)
        rintls_memset(output, 0, output_size);
}

static void rintls_clear_size_output(rin_size_t* output)
{
    if (output)
        *output = 0;
}

static int rintls_nist_parameters(u32 curve, const ec_str_params** params_out,
                                  rin_size_t* scalar_size_out,
                                  rin_size_t* public_size_out)
{
    if (!params_out || !scalar_size_out || !public_size_out)
        return -1;

    switch (curve) {
    case RINTLS_EC_P256:
        *params_out = &secp256r1_str_params;
        *scalar_size_out = RINTLS_P256_PRIVATE_KEY_SIZE;
        *public_size_out = RINTLS_P256_PUBLIC_KEY_SIZE;
        return 0;
    case RINTLS_EC_P384:
        *params_out = &secp384r1_str_params;
        *scalar_size_out = RINTLS_P384_PRIVATE_KEY_SIZE;
        *public_size_out = RINTLS_P384_PUBLIC_KEY_SIZE;
        return 0;
    case RINTLS_EC_P521:
        *params_out = &secp521r1_str_params;
        *scalar_size_out = RINTLS_P521_PRIVATE_KEY_SIZE;
        *public_size_out = RINTLS_P521_PUBLIC_KEY_SIZE;
        return 0;
    default:
        return -1;
    }
}

static int rintls_hash_type(u32 hash_algorithm, hash_alg_type* type_out)
{
    if (!type_out)
        return -1;

    switch (hash_algorithm) {
    case RINTLS_HASH_SHA256:
        *type_out = SHA256;
        return 0;
    case RINTLS_HASH_SHA384:
        *type_out = SHA384;
        return 0;
    case RINTLS_HASH_SHA512:
        *type_out = SHA512;
        return 0;
    default:
        return -1;
    }
}

static int rintls_hash_type_for_digest_size(rin_size_t digest_len,
                                            hash_alg_type* type_out)
{
    if (!type_out)
        return -1;

    switch (digest_len) {
    case 32u:
        *type_out = SHA256;
        return 0;
    case 48u:
        *type_out = SHA384;
        return 0;
    case 64u:
        *type_out = SHA512;
        return 0;
    default:
        return -1;
    }
}

static void rintls_clear_nist_key_pair(ec_key_pair* key_pair)
{
    if (key_pair)
        rintls_secure_zero(key_pair, sizeof(*key_pair));
}

int rintls_nist_private_key_size(u32 curve, rin_size_t* size_out)
{
    const ec_str_params* params;
    rin_size_t public_size;

    rintls_clear_size_output(size_out);
    if (!size_out)
        return -1;
    if (rintls_nist_parameters(curve, &params, size_out, &public_size) != 0)
        return -1;
    (void)params;
    return 0;
}

int rintls_nist_public_key_size(u32 curve, rin_size_t* size_out)
{
    const ec_str_params* params;
    rin_size_t scalar_size;

    rintls_clear_size_output(size_out);
    if (!size_out)
        return -1;
    if (rintls_nist_parameters(curve, &params, &scalar_size, size_out) != 0)
        return -1;
    (void)params;
    return 0;
}

int rintls_nist_keygen(u32 curve, u8* private_key, u8* public_key)
{
    const ec_str_params* str_params;
    ec_params params;
    ec_key_pair key_pair;
    rin_size_t scalar_size;
    rin_size_t public_size;
    int ret = -1;

    if (rintls_nist_parameters(curve, &str_params, &scalar_size, &public_size) != 0)
        return -1;

    rintls_clear_output(private_key, scalar_size);
    rintls_clear_output(public_key, public_size);
    if (!private_key || !public_key)
        return -1;

    rintls_memset(&params, 0, sizeof(params));
    rintls_memset(&key_pair, 0, sizeof(key_pair));

    if (import_params(&params, str_params) != 0 ||
        ec_key_pair_gen(&key_pair, &params, ECDSA) != 0 ||
        ec_priv_key_export_to_buf(&key_pair.priv_key, private_key,
                                  (u8)scalar_size) != 0)
        goto done;

    public_key[0] = 0x04;
    if (ec_pub_key_export_to_aff_buf(&key_pair.pub_key, public_key + 1,
                                     (u8)(public_size - 1u)) != 0) {
        rintls_memset(public_key, 0, public_size);
        goto done;
    }
    ret = 0;

done:
    if (ret != 0) {
        rintls_memset(private_key, 0, scalar_size);
        rintls_memset(public_key, 0, public_size);
    }
    rintls_clear_nist_key_pair(&key_pair);
    rintls_secure_zero(&params, sizeof(params));
    return ret;
}

int rintls_nist_public_from_private(u32 curve, const u8* private_key,
                                    u8* public_key)
{
    const ec_str_params* str_params;
    ec_params params;
    ec_key_pair key_pair;
    rin_size_t scalar_size;
    rin_size_t public_size;
    int ret = -1;

    if (rintls_nist_parameters(curve, &str_params, &scalar_size, &public_size) != 0)
        return -1;

    rintls_clear_output(public_key, public_size);
    if (!private_key || !public_key)
        return -1;

    rintls_memset(&params, 0, sizeof(params));
    rintls_memset(&key_pair, 0, sizeof(key_pair));

    if (import_params(&params, str_params) != 0 ||
        ec_key_pair_import_from_priv_key_buf(&key_pair, &params, private_key,
                                             (u8)scalar_size, ECDSA) != 0)
        goto done;

    public_key[0] = 0x04;
    if (ec_pub_key_export_to_aff_buf(&key_pair.pub_key, public_key + 1,
                                     (u8)(public_size - 1u)) != 0) {
        rintls_memset(public_key, 0, public_size);
        goto done;
    }
    ret = 0;

done:
    if (ret != 0)
        rintls_memset(public_key, 0, public_size);
    rintls_clear_nist_key_pair(&key_pair);
    rintls_secure_zero(&params, sizeof(params));
    return ret;
}

int rintls_nist_validate_public(u32 curve, const u8* public_key,
                                rin_size_t public_key_len)
{
    const ec_str_params* str_params;
    ec_params params;
    ec_pub_key key;
    rin_size_t scalar_size;
    rin_size_t expected_public_size;
    int ret = -1;

    if (!public_key ||
        rintls_nist_parameters(curve, &str_params, &scalar_size,
                               &expected_public_size) != 0 ||
        public_key_len != expected_public_size || public_key[0] != 0x04)
        return -1;

    rintls_memset(&params, 0, sizeof(params));
    rintls_memset(&key, 0, sizeof(key));
    if (import_params(&params, str_params) == 0 &&
        ec_pub_key_import_from_aff_buf(&key, &params, public_key + 1,
                                       (u8)(expected_public_size - 1u),
                                       ECCCDH) == 0)
        ret = 0;

    rintls_secure_zero(&key, sizeof(key));
    rintls_secure_zero(&params, sizeof(params));
    return ret;
}

int rintls_nist_ecdh(u32 curve, u8* shared_secret, const u8* private_key,
                     const u8* peer_public_key, rin_size_t peer_public_key_len)
{
    const ec_str_params* str_params;
    ec_params params;
    ec_key_pair key_pair;
    rin_size_t scalar_size;
    rin_size_t public_size;
    int ret = -1;

    if (rintls_nist_parameters(curve, &str_params, &scalar_size, &public_size) != 0)
        return -1;

    rintls_clear_output(shared_secret, scalar_size);
    if (!shared_secret || !private_key || !peer_public_key ||
        peer_public_key_len != public_size || peer_public_key[0] != 0x04)
        return -1;

    rintls_memset(&params, 0, sizeof(params));
    rintls_memset(&key_pair, 0, sizeof(key_pair));
    if (import_params(&params, str_params) != 0 ||
        ecccdh_import_key_pair_from_priv_key_buf(&key_pair, &params, private_key,
                                                  (u8)scalar_size) != 0 ||
        ecccdh_derive_secret(&key_pair.priv_key, peer_public_key + 1,
                             (u8)(public_size - 1u), shared_secret,
                             (u8)scalar_size) != 0)
        goto done;

    ret = 0;

done:
    if (ret != 0)
        rintls_memset(shared_secret, 0, scalar_size);
    rintls_clear_nist_key_pair(&key_pair);
    rintls_secure_zero(&params, sizeof(params));
    return ret;
}

int rintls_nist_ecdsa_sign(u32 curve, u32 hash_algorithm,
                           const u8* message, rin_size_t message_len,
                           const u8* private_key, u8* signature)
{
    const ec_str_params* str_params;
    ec_params params;
    ec_key_pair key_pair;
    hash_alg_type hash_type;
    rin_size_t scalar_size;
    rin_size_t public_size;
    int ret = -1;

    if (rintls_nist_parameters(curve, &str_params, &scalar_size, &public_size) != 0)
        return -1;

    rintls_clear_output(signature, scalar_size * 2u);
    if (!private_key || !signature || !rintls_message_is_valid(message, message_len) ||
        rintls_hash_type(hash_algorithm, &hash_type) != 0)
        return -1;

    rintls_memset(&params, 0, sizeof(params));
    rintls_memset(&key_pair, 0, sizeof(key_pair));
    if (import_params(&params, str_params) != 0 ||
        ec_key_pair_import_from_priv_key_buf(&key_pair, &params, private_key,
                                             (u8)scalar_size, ECDSA) != 0 ||
        ec_sign(signature, (u8)(scalar_size * 2u), &key_pair, message,
                (u32)message_len, ECDSA, hash_type, NULL, 0) != 0)
        goto done;

    ret = 0;

done:
    if (ret != 0)
        rintls_memset(signature, 0, scalar_size * 2u);
    rintls_clear_nist_key_pair(&key_pair);
    rintls_secure_zero(&params, sizeof(params));
    return ret;
}

int rintls_nist_ecdsa_verify(u32 curve, u32 hash_algorithm,
                             const u8* message, rin_size_t message_len,
                             const u8* public_key, rin_size_t public_key_len,
                             const u8* signature, rin_size_t signature_len)
{
    const ec_str_params* str_params;
    ec_params params;
    ec_pub_key key;
    hash_alg_type hash_type;
    rin_size_t scalar_size;
    rin_size_t expected_public_size;
    int ret = -1;

    if (!public_key || !signature || !rintls_message_is_valid(message, message_len) ||
        rintls_nist_parameters(curve, &str_params, &scalar_size,
                               &expected_public_size) != 0 ||
        rintls_hash_type(hash_algorithm, &hash_type) != 0 ||
        public_key_len != expected_public_size || public_key[0] != 0x04 ||
        signature_len != scalar_size * 2u)
        return -1;

    rintls_memset(&params, 0, sizeof(params));
    rintls_memset(&key, 0, sizeof(key));
    if (import_params(&params, str_params) == 0 &&
        ec_pub_key_import_from_aff_buf(&key, &params, public_key + 1,
                                       (u8)(expected_public_size - 1u), ECDSA) == 0 &&
        ec_verify(signature, (u8)signature_len, &key, message, (u32)message_len,
                  ECDSA, hash_type, NULL, 0) == 0)
        ret = 0;

    rintls_secure_zero(&key, sizeof(key));
    rintls_secure_zero(&params, sizeof(params));
    return ret;
}

int rintls_nist_ecdsa_sign_digest(u32 curve, const u8* digest,
                                  rin_size_t digest_len,
                                  const u8* private_key, u8* signature)
{
    const ec_str_params* str_params;
    ec_params params;
    ec_key_pair key_pair;
    hash_alg_type hash_type;
    rin_size_t scalar_size;
    rin_size_t public_size;
    int ret = -1;

    if (rintls_nist_parameters(curve, &str_params, &scalar_size, &public_size) != 0)
        return -1;

    rintls_clear_output(signature, scalar_size * 2u);
    if (!digest || !private_key || !signature ||
        rintls_hash_type_for_digest_size(digest_len, &hash_type) != 0)
        return -1;

    rintls_memset(&params, 0, sizeof(params));
    rintls_memset(&key_pair, 0, sizeof(key_pair));
    if (import_params(&params, str_params) != 0 ||
        ec_key_pair_import_from_priv_key_buf(&key_pair, &params, private_key,
                                             (u8)scalar_size, ECDSA) != 0 ||
        ecdsa_sign_digest(signature, (u8)(scalar_size * 2u), &key_pair,
                          digest, (u8)digest_len, hash_type) != 0)
        goto done;

    ret = 0;

done:
    if (ret != 0)
        rintls_memset(signature, 0, scalar_size * 2u);
    rintls_clear_nist_key_pair(&key_pair);
    rintls_secure_zero(&params, sizeof(params));
    return ret;
}

int rintls_nist_ecdsa_verify_digest(u32 curve, const u8* digest,
                                    rin_size_t digest_len,
                                    const u8* public_key,
                                    rin_size_t public_key_len,
                                    const u8* signature,
                                    rin_size_t signature_len)
{
    const ec_str_params* str_params;
    ec_params params;
    ec_pub_key key;
    hash_alg_type hash_type;
    rin_size_t scalar_size;
    rin_size_t expected_public_size;
    int ret = -1;

    if (!digest || !public_key || !signature ||
        rintls_nist_parameters(curve, &str_params, &scalar_size,
                               &expected_public_size) != 0 ||
        rintls_hash_type_for_digest_size(digest_len, &hash_type) != 0 ||
        public_key_len != expected_public_size || public_key[0] != 0x04 ||
        signature_len != scalar_size * 2u)
        return -1;

    rintls_memset(&params, 0, sizeof(params));
    rintls_memset(&key, 0, sizeof(key));
    if (import_params(&params, str_params) == 0 &&
        ec_pub_key_import_from_aff_buf(&key, &params, public_key + 1,
                                       (u8)(expected_public_size - 1u), ECDSA) == 0 &&
        ecdsa_verify_digest(signature, (u8)signature_len, &key, digest,
                            (u8)digest_len, hash_type) == 0)
        ret = 0;

    rintls_secure_zero(&key, sizeof(key));
    rintls_secure_zero(&params, sizeof(params));
    return ret;
}

static int rintls_eddsa_public_from_private(const u8* private_key,
                                            rin_size_t private_size,
                                            const ec_str_params* str_params,
                                            ec_alg_type algorithm,
                                            u8* public_key,
                                            rin_size_t public_size)
{
    ec_params params;
    ec_key_pair key_pair;
    int ret = -1;

    rintls_clear_output(public_key, public_size);
    if (!private_key || !public_key)
        return -1;

    rintls_memset(&params, 0, sizeof(params));
    rintls_memset(&key_pair, 0, sizeof(key_pair));
    if (import_params(&params, str_params) == 0 &&
        eddsa_import_key_pair_from_priv_key_buf(&key_pair, private_key,
                                                (u16)private_size, &params,
                                                algorithm) == 0 &&
        eddsa_export_pub_key(&key_pair.pub_key, public_key,
                             (u16)public_size) == 0)
        ret = 0;

    if (ret != 0)
        rintls_memset(public_key, 0, public_size);
    rintls_clear_nist_key_pair(&key_pair);
    rintls_secure_zero(&params, sizeof(params));
    return ret;
}

int rintls_ed25519_keygen(u8 private_key[RINTLS_ED25519_PRIVATE_KEY_SIZE],
                          u8 public_key[RINTLS_ED25519_PUBLIC_KEY_SIZE])
{
    rintls_clear_output(private_key, RINTLS_ED25519_PRIVATE_KEY_SIZE);
    rintls_clear_output(public_key, RINTLS_ED25519_PUBLIC_KEY_SIZE);
    if (!private_key || !public_key)
        return -1;
    if (rintls_get_random(private_key, RINTLS_ED25519_PRIVATE_KEY_SIZE) != 0 ||
        rintls_ed25519_public_from_private(private_key, public_key) != 0) {
        rintls_memset(private_key, 0, RINTLS_ED25519_PRIVATE_KEY_SIZE);
        rintls_memset(public_key, 0, RINTLS_ED25519_PUBLIC_KEY_SIZE);
        return -1;
    }
    return 0;
}

int rintls_ed25519_public_from_private(
    const u8 private_key[RINTLS_ED25519_PRIVATE_KEY_SIZE],
    u8 public_key[RINTLS_ED25519_PUBLIC_KEY_SIZE])
{
    return rintls_eddsa_public_from_private(private_key,
                                             RINTLS_ED25519_PRIVATE_KEY_SIZE,
                                             &wei25519_str_params, EDDSA25519,
                                             public_key,
                                             RINTLS_ED25519_PUBLIC_KEY_SIZE);
}

int rintls_ed25519_sign(u8 signature[RINTLS_ED25519_SIGNATURE_SIZE],
                        const u8 private_key[RINTLS_ED25519_PRIVATE_KEY_SIZE],
                        const u8* message, rin_size_t message_len)
{
    ec_params params;
    ec_key_pair key_pair;
    int ret = -1;

    rintls_clear_output(signature, RINTLS_ED25519_SIGNATURE_SIZE);
    if (!signature || !private_key || !rintls_message_is_valid(message, message_len))
        return -1;
    rintls_memset(&params, 0, sizeof(params));
    rintls_memset(&key_pair, 0, sizeof(key_pair));
    if (import_params(&params, &wei25519_str_params) == 0 &&
        eddsa_import_key_pair_from_priv_key_buf(&key_pair, private_key,
                                                RINTLS_ED25519_PRIVATE_KEY_SIZE,
                                                &params, EDDSA25519) == 0 &&
        ec_sign(signature, RINTLS_ED25519_SIGNATURE_SIZE, &key_pair, message,
                (u32)message_len, EDDSA25519, SHA512, NULL, 0) == 0)
        ret = 0;

    if (ret != 0)
        rintls_memset(signature, 0, RINTLS_ED25519_SIGNATURE_SIZE);
    rintls_clear_nist_key_pair(&key_pair);
    rintls_secure_zero(&params, sizeof(params));
    return ret;
}

int rintls_ed25519_verify(
    const u8 signature[RINTLS_ED25519_SIGNATURE_SIZE],
    const u8 public_key[RINTLS_ED25519_PUBLIC_KEY_SIZE], const u8* message,
    rin_size_t message_len)
{
    ec_params params;
    ec_pub_key key;
    int ret = -1;

    if (!signature || !public_key || !rintls_message_is_valid(message, message_len))
        return -1;
    rintls_memset(&params, 0, sizeof(params));
    rintls_memset(&key, 0, sizeof(key));
    if (import_params(&params, &wei25519_str_params) == 0 &&
        eddsa_import_pub_key(&key, public_key, RINTLS_ED25519_PUBLIC_KEY_SIZE,
                             &params, EDDSA25519) == 0 &&
        ec_verify(signature, RINTLS_ED25519_SIGNATURE_SIZE, &key, message,
                  (u32)message_len, EDDSA25519, SHA512, NULL, 0) == 0)
        ret = 0;

    rintls_secure_zero(&key, sizeof(key));
    rintls_secure_zero(&params, sizeof(params));
    return ret;
}

int rintls_ed448_keygen(u8 private_key[RINTLS_ED448_PRIVATE_KEY_SIZE],
                        u8 public_key[RINTLS_ED448_PUBLIC_KEY_SIZE])
{
    rintls_clear_output(private_key, RINTLS_ED448_PRIVATE_KEY_SIZE);
    rintls_clear_output(public_key, RINTLS_ED448_PUBLIC_KEY_SIZE);
    if (!private_key || !public_key)
        return -1;
    if (rintls_get_random(private_key, RINTLS_ED448_PRIVATE_KEY_SIZE) != 0 ||
        rintls_ed448_public_from_private(private_key, public_key) != 0) {
        rintls_memset(private_key, 0, RINTLS_ED448_PRIVATE_KEY_SIZE);
        rintls_memset(public_key, 0, RINTLS_ED448_PUBLIC_KEY_SIZE);
        return -1;
    }
    return 0;
}

int rintls_ed448_public_from_private(
    const u8 private_key[RINTLS_ED448_PRIVATE_KEY_SIZE],
    u8 public_key[RINTLS_ED448_PUBLIC_KEY_SIZE])
{
    return rintls_eddsa_public_from_private(private_key,
                                             RINTLS_ED448_PRIVATE_KEY_SIZE,
                                             &wei448_str_params, EDDSA448,
                                             public_key,
                                             RINTLS_ED448_PUBLIC_KEY_SIZE);
}

int rintls_ed448_sign(u8 signature[RINTLS_ED448_SIGNATURE_SIZE],
                      const u8 private_key[RINTLS_ED448_PRIVATE_KEY_SIZE],
                      const u8* message, rin_size_t message_len,
                      const u8* context, rin_size_t context_len)
{
    ec_params params;
    ec_key_pair key_pair;
    int ret = -1;

    rintls_clear_output(signature, RINTLS_ED448_SIGNATURE_SIZE);
    if (!signature || !private_key || !rintls_message_is_valid(message, message_len) ||
        !rintls_context_is_valid(context, context_len))
        return -1;
    rintls_memset(&params, 0, sizeof(params));
    rintls_memset(&key_pair, 0, sizeof(key_pair));
    if (import_params(&params, &wei448_str_params) == 0 &&
        eddsa_import_key_pair_from_priv_key_buf(&key_pair, private_key,
                                                RINTLS_ED448_PRIVATE_KEY_SIZE,
                                                &params, EDDSA448) == 0 &&
        ec_sign(signature, RINTLS_ED448_SIGNATURE_SIZE, &key_pair, message,
                (u32)message_len, EDDSA448, SHAKE256, context,
                (u16)context_len) == 0)
        ret = 0;

    if (ret != 0)
        rintls_memset(signature, 0, RINTLS_ED448_SIGNATURE_SIZE);
    rintls_clear_nist_key_pair(&key_pair);
    rintls_secure_zero(&params, sizeof(params));
    return ret;
}

int rintls_ed448_verify(const u8 signature[RINTLS_ED448_SIGNATURE_SIZE],
                        const u8 public_key[RINTLS_ED448_PUBLIC_KEY_SIZE],
                        const u8* message, rin_size_t message_len,
                        const u8* context, rin_size_t context_len)
{
    ec_params params;
    ec_pub_key key;
    int ret = -1;

    if (!signature || !public_key || !rintls_message_is_valid(message, message_len) ||
        !rintls_context_is_valid(context, context_len))
        return -1;
    rintls_memset(&params, 0, sizeof(params));
    rintls_memset(&key, 0, sizeof(key));
    if (import_params(&params, &wei448_str_params) == 0 &&
        eddsa_import_pub_key(&key, public_key, RINTLS_ED448_PUBLIC_KEY_SIZE,
                             &params, EDDSA448) == 0 &&
        ec_verify(signature, RINTLS_ED448_SIGNATURE_SIZE, &key, message,
                  (u32)message_len, EDDSA448, SHAKE256, context,
                  (u16)context_len) == 0)
        ret = 0;

    rintls_secure_zero(&key, sizeof(key));
    rintls_secure_zero(&params, sizeof(params));
    return ret;
}

int rintls_x448_keygen(u8 private_key[RINTLS_X448_KEY_SIZE],
                       u8 public_key[RINTLS_X448_KEY_SIZE])
{
    rintls_clear_output(private_key, RINTLS_X448_KEY_SIZE);
    rintls_clear_output(public_key, RINTLS_X448_KEY_SIZE);
    if (!private_key || !public_key)
        return -1;
    if (rintls_get_random(private_key, RINTLS_X448_KEY_SIZE) != 0 ||
        x448_init_pub_key(private_key, public_key) != 0) {
        rintls_memset(private_key, 0, RINTLS_X448_KEY_SIZE);
        rintls_memset(public_key, 0, RINTLS_X448_KEY_SIZE);
        return -1;
    }
    return 0;
}

int rintls_x448_public_from_private(const u8 private_key[RINTLS_X448_KEY_SIZE],
                                    u8 public_key[RINTLS_X448_KEY_SIZE])
{
    rintls_clear_output(public_key, RINTLS_X448_KEY_SIZE);
    if (!private_key || !public_key)
        return -1;
    if (x448_init_pub_key(private_key, public_key) != 0) {
        rintls_memset(public_key, 0, RINTLS_X448_KEY_SIZE);
        return -1;
    }
    return 0;
}

int rintls_x448_ecdh(u8 shared_secret[RINTLS_X448_KEY_SIZE],
                     const u8 private_key[RINTLS_X448_KEY_SIZE],
                     const u8 peer_public_key[RINTLS_X448_KEY_SIZE])
{
    u8 zero[RINTLS_X448_KEY_SIZE] = { 0 };

    rintls_clear_output(shared_secret, RINTLS_X448_KEY_SIZE);
    if (!shared_secret || !private_key || !peer_public_key)
        return -1;
    if (x448_derive_secret(private_key, peer_public_key, shared_secret) != 0 ||
        rintls_secure_cmp(shared_secret, zero, RINTLS_X448_KEY_SIZE)) {
        rintls_secure_zero(shared_secret, RINTLS_X448_KEY_SIZE);
        return -1;
    }
    return 0;
}
