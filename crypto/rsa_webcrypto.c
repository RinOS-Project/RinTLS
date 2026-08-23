/* rinTLS bounded RSA provider for the RinOS WebCrypto consumer. */

#include "rsa_webcrypto.h"

#include <bearssl.h>

/* BearSSL exposes MGF1 to its RSA implementations but not its public API.
 * The pinned provider archive owns hash/mgf1.c, so keep this provider-local
 * declaration here instead of widening the application-visible API. */
void br_mgf1_xor(void* data, size_t len, const br_hash_class* digest,
                 const void* seed, size_t seed_len);

typedef struct {
    br_rsa_public_key key;
    u8 modulus[RINTLS_RSA_MAX_MODULUS_BYTES];
    u8 public_exponent[RINTLS_RSA_MAX_PUBLIC_EXPONENT_BYTES];
} rintls_bearssl_public_key;

typedef struct {
    br_rsa_private_key key;
    u8 prime1[RINTLS_RSA_MAX_FACTOR_BYTES];
    u8 prime2[RINTLS_RSA_MAX_FACTOR_BYTES];
    u8 exponent1[RINTLS_RSA_MAX_FACTOR_BYTES];
    u8 exponent2[RINTLS_RSA_MAX_FACTOR_BYTES];
    u8 coefficient[RINTLS_RSA_MAX_FACTOR_BYTES];
} rintls_bearssl_private_key;

static int rintls_rsa_bytes_are_valid(const u8* bytes, rin_size_t length,
                                      rin_size_t maximum)
{
    return bytes != NULL && length != 0 && length <= maximum && bytes[0] != 0;
}

static int rintls_rsa_message_is_valid(const u8* bytes, rin_size_t length)
{
    return bytes != NULL || length == 0;
}

static u32 rintls_rsa_parse_exponent(const u8* exponent, rin_size_t length)
{
    u32 value = 0;
    rin_size_t index;

    for (index = 0; index < length; ++index)
        value = (value << 8) | exponent[index];
    return value;
}

static u32 rintls_rsa_constant_time_diff(const u8* left, const u8* right,
                                          rin_size_t length)
{
    u32 diff = 0;
    rin_size_t index;

    for (index = 0; index < length; ++index)
        diff |= (u32)(left[index] ^ right[index]);
    return diff;
}

static int rintls_rsa_output_is_valid(const u8* output, rin_size_t capacity)
{
    return output != NULL && capacity <= RINTLS_RSA_MAX_MODULUS_BYTES;
}

static void rintls_rsa_clear_output(u8* output, rin_size_t capacity)
{
    if (rintls_rsa_output_is_valid(output, capacity))
        rintls_secure_zero(output, capacity);
}

static int rintls_rsa_public_key_is_valid(const rintls_rsa_public_key* key)
{
    u32 exponent;

    if (!key || key->modulus_bits < RINTLS_RSA_MIN_MODULUS_BITS ||
        key->modulus_bits > RINTLS_RSA_MAX_MODULUS_BITS ||
        (key->modulus_bits & 7u) != 0 ||
        key->modulus_len != key->modulus_bits / 8u ||
        !rintls_rsa_bytes_are_valid(key->modulus, key->modulus_len,
                                    RINTLS_RSA_MAX_MODULUS_BYTES) ||
        (key->modulus[0] & 0x80u) == 0 ||
        !rintls_rsa_bytes_are_valid(key->public_exponent,
                                    key->public_exponent_len,
                                    RINTLS_RSA_MAX_PUBLIC_EXPONENT_BYTES))
        return 0;

    exponent = rintls_rsa_parse_exponent(key->public_exponent,
                                         key->public_exponent_len);
    return exponent >= 3u && (exponent & 1u) != 0;
}

static int rintls_rsa_public_key_to_bearssl(const rintls_rsa_public_key* key,
                                             rintls_bearssl_public_key* out)
{
    if (!out)
        return -1;
    rintls_secure_zero(out, sizeof(*out));
    if (!rintls_rsa_public_key_is_valid(key))
        return -1;

    rintls_memcpy(out->modulus, key->modulus, key->modulus_len);
    rintls_memcpy(out->public_exponent, key->public_exponent,
                  key->public_exponent_len);
    out->key.n = out->modulus;
    out->key.nlen = key->modulus_len;
    out->key.e = out->public_exponent;
    out->key.elen = key->public_exponent_len;
    return 0;
}

static int rintls_rsa_private_key_to_bearssl(const rintls_rsa_private_key* key,
                                              rintls_bearssl_private_key* out)
{
    if (!out)
        return -1;
    rintls_secure_zero(out, sizeof(*out));
    if (!key || !rintls_rsa_public_key_is_valid(&key->public_key) ||
        !rintls_rsa_bytes_are_valid(key->private_exponent,
                                    key->private_exponent_len,
                                    key->public_key.modulus_len) ||
        !rintls_rsa_bytes_are_valid(key->prime1, key->prime1_len,
                                    RINTLS_RSA_MAX_FACTOR_BYTES) ||
        !rintls_rsa_bytes_are_valid(key->prime2, key->prime2_len,
                                    RINTLS_RSA_MAX_FACTOR_BYTES) ||
        !rintls_rsa_bytes_are_valid(key->exponent1, key->exponent1_len,
                                    RINTLS_RSA_MAX_FACTOR_BYTES) ||
        !rintls_rsa_bytes_are_valid(key->exponent2, key->exponent2_len,
                                    RINTLS_RSA_MAX_FACTOR_BYTES) ||
        !rintls_rsa_bytes_are_valid(key->coefficient, key->coefficient_len,
                                    RINTLS_RSA_MAX_FACTOR_BYTES))
        return -1;

    rintls_memcpy(out->prime1, key->prime1, key->prime1_len);
    rintls_memcpy(out->prime2, key->prime2, key->prime2_len);
    rintls_memcpy(out->exponent1, key->exponent1, key->exponent1_len);
    rintls_memcpy(out->exponent2, key->exponent2, key->exponent2_len);
    rintls_memcpy(out->coefficient, key->coefficient, key->coefficient_len);
    out->key.n_bitlen = key->public_key.modulus_bits;
    out->key.p = out->prime1;
    out->key.plen = key->prime1_len;
    out->key.q = out->prime2;
    out->key.qlen = key->prime2_len;
    out->key.dp = out->exponent1;
    out->key.dplen = key->exponent1_len;
    out->key.dq = out->exponent2;
    out->key.dqlen = key->exponent2_len;
    out->key.iq = out->coefficient;
    out->key.iqlen = key->coefficient_len;
    return 0;
}

static int rintls_rsa_private_key_is_consistent(
    const rintls_rsa_private_key* key, const rintls_bearssl_private_key* bearssl)
{
    u8 modulus[RINTLS_RSA_MAX_MODULUS_BYTES];
    u8 private_exponent[RINTLS_RSA_MAX_MODULUS_BYTES];
    rin_size_t modulus_len;
    rin_size_t private_exponent_len;
    u32 public_exponent;
    int result = -1;

    rintls_secure_zero(modulus, sizeof(modulus));
    rintls_secure_zero(private_exponent, sizeof(private_exponent));
    if (!key || !bearssl)
        goto done;

    modulus_len = br_rsa_i31_compute_modulus(modulus, &bearssl->key);
    if (modulus_len != key->public_key.modulus_len ||
        rintls_rsa_constant_time_diff(modulus, key->public_key.modulus,
                                      modulus_len) != 0)
        goto done;

    public_exponent = rintls_rsa_parse_exponent(key->public_key.public_exponent,
                                                 key->public_key.public_exponent_len);
    if (br_rsa_i31_compute_pubexp(&bearssl->key) != public_exponent)
        goto done;

    private_exponent_len = br_rsa_i31_compute_privexp(private_exponent,
                                                       &bearssl->key,
                                                       public_exponent);
    if (private_exponent_len != key->private_exponent_len ||
        rintls_rsa_constant_time_diff(private_exponent, key->private_exponent,
                                      private_exponent_len) != 0)
        goto done;
    result = 0;

done:
    rintls_secure_zero(private_exponent, sizeof(private_exponent));
    rintls_secure_zero(modulus, sizeof(modulus));
    return result;
}

static int rintls_rsa_hash_parameters(u32 hash_algorithm,
                                      const br_hash_class** digest_out,
                                      const unsigned char** oid_out,
                                      rin_size_t* digest_len_out)
{
    if (!digest_out || !oid_out || !digest_len_out)
        return -1;

    switch (hash_algorithm) {
    case RINTLS_RSA_HASH_SHA1:
        *digest_out = &br_sha1_vtable;
        *oid_out = BR_HASH_OID_SHA1;
        *digest_len_out = 20u;
        return 0;
    case RINTLS_RSA_HASH_SHA256:
        *digest_out = &br_sha256_vtable;
        *oid_out = BR_HASH_OID_SHA256;
        *digest_len_out = 32u;
        return 0;
    case RINTLS_RSA_HASH_SHA384:
        *digest_out = &br_sha384_vtable;
        *oid_out = BR_HASH_OID_SHA384;
        *digest_len_out = 48u;
        return 0;
    case RINTLS_RSA_HASH_SHA512:
        *digest_out = &br_sha512_vtable;
        *oid_out = BR_HASH_OID_SHA512;
        *digest_len_out = 64u;
        return 0;
    default:
        return -1;
    }
}

static int rintls_rsa_hash_message(u32 hash_algorithm, const u8* message,
                                   rin_size_t message_len, u8 digest[64],
                                   rin_size_t* digest_len_out)
{
    if (!digest || !digest_len_out ||
        !rintls_rsa_message_is_valid(message, message_len))
        return -1;
    rintls_secure_zero(digest, 64u);

    switch (hash_algorithm) {
    case RINTLS_RSA_HASH_SHA1: {
        br_sha1_context context;
        br_sha1_init(&context);
        br_sha1_update(&context, message, message_len);
        br_sha1_out(&context, digest);
        rintls_secure_zero(&context, sizeof(context));
        *digest_len_out = 20u;
        return 0;
    }
    case RINTLS_RSA_HASH_SHA256: {
        br_sha256_context context;
        br_sha256_init(&context);
        br_sha256_update(&context, message, message_len);
        br_sha256_out(&context, digest);
        rintls_secure_zero(&context, sizeof(context));
        *digest_len_out = 32u;
        return 0;
    }
    case RINTLS_RSA_HASH_SHA384: {
        br_sha384_context context;
        br_sha384_init(&context);
        br_sha384_update(&context, message, message_len);
        br_sha384_out(&context, digest);
        rintls_secure_zero(&context, sizeof(context));
        *digest_len_out = 48u;
        return 0;
    }
    case RINTLS_RSA_HASH_SHA512: {
        br_sha512_context context;
        br_sha512_init(&context);
        br_sha512_update(&context, message, message_len);
        br_sha512_out(&context, digest);
        rintls_secure_zero(&context, sizeof(context));
        *digest_len_out = 64u;
        return 0;
    }
    default:
        return -1;
    }
}

int rintls_rsa_generate_keypair(u32 modulus_bits, u32 public_exponent,
                                rintls_rsa_private_key* key_out)
{
    br_hmac_drbg_context rng;
    br_rsa_private_key private_key;
    br_rsa_public_key public_key;
    u8 seed[48];
    u8 private_buffer[BR_RSA_KBUF_PRIV_SIZE(RINTLS_RSA_MAX_MODULUS_BITS)];
    u8 public_buffer[BR_RSA_KBUF_PUB_SIZE(RINTLS_RSA_MAX_MODULUS_BITS)];
    rin_size_t private_exponent_len;
    int result = -1;

    rintls_secure_zero(&rng, sizeof(rng));
    rintls_secure_zero(&private_key, sizeof(private_key));
    rintls_secure_zero(&public_key, sizeof(public_key));
    rintls_secure_zero(seed, sizeof(seed));
    rintls_secure_zero(private_buffer, sizeof(private_buffer));
    rintls_secure_zero(public_buffer, sizeof(public_buffer));
    if (!key_out)
        goto done;
    rintls_secure_zero(key_out, sizeof(*key_out));
    if (modulus_bits < RINTLS_RSA_MIN_MODULUS_BITS ||
        modulus_bits > RINTLS_RSA_MAX_MODULUS_BITS ||
        (modulus_bits & 7u) != 0 || public_exponent < 3u ||
        (public_exponent & 1u) == 0 ||
        rintls_get_random(seed, sizeof(seed)) != 0)
        goto done;

    br_hmac_drbg_init(&rng, &br_sha256_vtable, seed, sizeof(seed));
    if (br_rsa_i31_keygen_bounded(&rng.vtable, &private_key, private_buffer,
                                  &public_key, public_buffer, modulus_bits,
                                  public_exponent,
                                  RINTLS_RSA_KEYGEN_CANDIDATE_LIMIT) == 0 ||
        public_key.nlen > RINTLS_RSA_MAX_MODULUS_BYTES ||
        public_key.elen > RINTLS_RSA_MAX_PUBLIC_EXPONENT_BYTES ||
        private_key.plen > RINTLS_RSA_MAX_FACTOR_BYTES ||
        private_key.qlen > RINTLS_RSA_MAX_FACTOR_BYTES ||
        private_key.dplen > RINTLS_RSA_MAX_FACTOR_BYTES ||
        private_key.dqlen > RINTLS_RSA_MAX_FACTOR_BYTES ||
        private_key.iqlen > RINTLS_RSA_MAX_FACTOR_BYTES)
        goto done;

    key_out->public_key.modulus_bits = (u16)modulus_bits;
    key_out->public_key.modulus_len = (u16)public_key.nlen;
    key_out->public_key.public_exponent_len = (u8)public_key.elen;
    rintls_memcpy(key_out->public_key.modulus, public_key.n, public_key.nlen);
    rintls_memcpy(key_out->public_key.public_exponent, public_key.e,
                  public_key.elen);
    key_out->prime1_len = (u16)private_key.plen;
    key_out->prime2_len = (u16)private_key.qlen;
    key_out->exponent1_len = (u16)private_key.dplen;
    key_out->exponent2_len = (u16)private_key.dqlen;
    key_out->coefficient_len = (u16)private_key.iqlen;
    rintls_memcpy(key_out->prime1, private_key.p, private_key.plen);
    rintls_memcpy(key_out->prime2, private_key.q, private_key.qlen);
    rintls_memcpy(key_out->exponent1, private_key.dp, private_key.dplen);
    rintls_memcpy(key_out->exponent2, private_key.dq, private_key.dqlen);
    rintls_memcpy(key_out->coefficient, private_key.iq, private_key.iqlen);
    private_exponent_len = br_rsa_i31_compute_privexp(
        key_out->private_exponent, &private_key, public_exponent);
    if (private_exponent_len == 0 ||
        private_exponent_len > RINTLS_RSA_MAX_MODULUS_BYTES)
        goto done;
    key_out->private_exponent_len = (u16)private_exponent_len;

    {
        rintls_bearssl_private_key validated_private_key;
        if (rintls_rsa_private_key_to_bearssl(key_out, &validated_private_key) != 0 ||
            rintls_rsa_private_key_is_consistent(key_out,
                                                  &validated_private_key) != 0) {
            rintls_secure_zero(&validated_private_key,
                               sizeof(validated_private_key));
            goto done;
        }
        rintls_secure_zero(&validated_private_key, sizeof(validated_private_key));
    }
    result = 0;

done:
    if (result != 0 && key_out)
        rintls_secure_zero(key_out, sizeof(*key_out));
    rintls_secure_zero(public_buffer, sizeof(public_buffer));
    rintls_secure_zero(private_buffer, sizeof(private_buffer));
    rintls_secure_zero(seed, sizeof(seed));
    rintls_secure_zero(&public_key, sizeof(public_key));
    rintls_secure_zero(&private_key, sizeof(private_key));
    rintls_secure_zero(&rng, sizeof(rng));
    return result;
}

int rintls_rsa_oaep_encrypt(u32 hash_algorithm,
                            const rintls_rsa_public_key* public_key,
                            const u8* label, rin_size_t label_len,
                            const u8* message, rin_size_t message_len,
                            u8* encrypted, rin_size_t encrypted_capacity,
                            rin_size_t* encrypted_len)
{
    rintls_bearssl_public_key bearssl_public_key;
    br_hmac_drbg_context rng;
    const br_hash_class* digest;
    const unsigned char* oid;
    u8 seed[48];
    rin_size_t digest_len;
    rin_size_t produced;
    int result = -1;

    rintls_secure_zero(&bearssl_public_key, sizeof(bearssl_public_key));
    rintls_secure_zero(&rng, sizeof(rng));
    rintls_secure_zero(seed, sizeof(seed));
    if (!encrypted_len)
        goto done;
    *encrypted_len = 0;
    if (!rintls_rsa_output_is_valid(encrypted, encrypted_capacity))
        goto done;
    rintls_rsa_clear_output(encrypted, encrypted_capacity);
    if (!rintls_rsa_message_is_valid(label, label_len) ||
        !rintls_rsa_message_is_valid(message, message_len) ||
        rintls_rsa_hash_parameters(hash_algorithm, &digest, &oid,
                                   &digest_len) != 0 ||
        rintls_rsa_public_key_to_bearssl(public_key, &bearssl_public_key) != 0 ||
        encrypted_capacity < public_key->modulus_len ||
        rintls_get_random(seed, sizeof(seed)) != 0)
        goto done;
    (void)oid;
    (void)digest_len;

    br_hmac_drbg_init(&rng, &br_sha256_vtable, seed, sizeof(seed));
    produced = br_rsa_i31_oaep_encrypt(&rng.vtable, digest, label, label_len,
                                       &bearssl_public_key.key, encrypted,
                                       public_key->modulus_len, message,
                                       message_len);
    if (produced != public_key->modulus_len)
        goto done;
    *encrypted_len = produced;
    result = 0;

done:
    if (result != 0) {
        rintls_rsa_clear_output(encrypted, encrypted_capacity);
        if (encrypted_len)
            *encrypted_len = 0;
    }
    rintls_secure_zero(seed, sizeof(seed));
    rintls_secure_zero(&rng, sizeof(rng));
    rintls_secure_zero(&bearssl_public_key, sizeof(bearssl_public_key));
    return result;
}

int rintls_rsa_oaep_decrypt(u32 hash_algorithm,
                            const rintls_rsa_private_key* private_key,
                            const u8* encrypted, rin_size_t encrypted_len,
                            const u8* label, rin_size_t label_len,
                            u8* message, rin_size_t message_capacity,
                            rin_size_t* message_len)
{
    rintls_bearssl_private_key bearssl_private_key;
    const br_hash_class* digest;
    const unsigned char* oid;
    u8 work[RINTLS_RSA_MAX_MODULUS_BYTES];
    rin_size_t digest_len;
    size_t work_len;
    int result = -1;

    rintls_secure_zero(&bearssl_private_key, sizeof(bearssl_private_key));
    rintls_secure_zero(work, sizeof(work));
    if (!message_len)
        goto done;
    *message_len = 0;
    if (!rintls_rsa_output_is_valid(message, message_capacity))
        goto done;
    rintls_rsa_clear_output(message, message_capacity);
    if (!rintls_rsa_message_is_valid(label, label_len) ||
        !rintls_rsa_message_is_valid(encrypted, encrypted_len) ||
        rintls_rsa_hash_parameters(hash_algorithm, &digest, &oid,
                                   &digest_len) != 0 ||
        rintls_rsa_private_key_to_bearssl(private_key,
                                           &bearssl_private_key) != 0 ||
        rintls_rsa_private_key_is_consistent(private_key,
                                              &bearssl_private_key) != 0 ||
        encrypted_len != private_key->public_key.modulus_len ||
        message_capacity < private_key->public_key.modulus_len)
        goto done;
    (void)oid;
    (void)digest_len;

    rintls_memcpy(work, encrypted, encrypted_len);
    work_len = encrypted_len;
    if (br_rsa_i31_oaep_decrypt(digest, label, label_len,
                                &bearssl_private_key.key, work,
                                &work_len) == 0 ||
        work_len > RINTLS_RSA_MAX_MODULUS_BYTES)
        goto done;
    rintls_memcpy(message, work, work_len);
    *message_len = (rin_size_t)work_len;
    result = 0;

done:
    if (result != 0) {
        rintls_rsa_clear_output(message, message_capacity);
        if (message_len)
            *message_len = 0;
    }
    rintls_secure_zero(work, sizeof(work));
    rintls_secure_zero(&bearssl_private_key, sizeof(bearssl_private_key));
    return result;
}

int rintls_rsa_pkcs1_sign(u32 hash_algorithm,
                          const rintls_rsa_private_key* private_key,
                          const u8* message, rin_size_t message_len,
                          u8* signature, rin_size_t signature_capacity,
                          rin_size_t* signature_len)
{
    rintls_bearssl_private_key bearssl_private_key;
    rintls_bearssl_public_key bearssl_public_key;
    const br_hash_class* digest_class;
    const unsigned char* oid;
    u8 digest[64];
    u8 verified_digest[64];
    rin_size_t digest_len;
    int result = -1;

    rintls_secure_zero(&bearssl_private_key, sizeof(bearssl_private_key));
    rintls_secure_zero(&bearssl_public_key, sizeof(bearssl_public_key));
    rintls_secure_zero(digest, sizeof(digest));
    rintls_secure_zero(verified_digest, sizeof(verified_digest));
    if (!signature_len)
        goto done;
    *signature_len = 0;
    if (!rintls_rsa_output_is_valid(signature, signature_capacity))
        goto done;
    rintls_rsa_clear_output(signature, signature_capacity);
    if (rintls_rsa_hash_parameters(hash_algorithm, &digest_class, &oid,
                                   &digest_len) != 0 ||
        rintls_rsa_hash_message(hash_algorithm, message, message_len, digest,
                                &digest_len) != 0 ||
        rintls_rsa_private_key_to_bearssl(private_key,
                                           &bearssl_private_key) != 0 ||
        rintls_rsa_private_key_is_consistent(private_key,
                                              &bearssl_private_key) != 0 ||
        signature_capacity < private_key->public_key.modulus_len ||
        rintls_rsa_public_key_to_bearssl(&private_key->public_key,
                                          &bearssl_public_key) != 0 ||
        br_rsa_i31_pkcs1_sign(oid, digest, digest_len,
                              &bearssl_private_key.key, signature) == 0 ||
        br_rsa_i31_pkcs1_vrfy(signature,
                              private_key->public_key.modulus_len, oid,
                              digest_len, &bearssl_public_key.key,
                              verified_digest) == 0 ||
        rintls_rsa_constant_time_diff(digest, verified_digest, digest_len) != 0)
        goto done;
    (void)digest_class;
    *signature_len = private_key->public_key.modulus_len;
    result = 0;

done:
    if (result != 0) {
        rintls_rsa_clear_output(signature, signature_capacity);
        if (signature_len)
            *signature_len = 0;
    }
    rintls_secure_zero(verified_digest, sizeof(verified_digest));
    rintls_secure_zero(digest, sizeof(digest));
    rintls_secure_zero(&bearssl_public_key, sizeof(bearssl_public_key));
    rintls_secure_zero(&bearssl_private_key, sizeof(bearssl_private_key));
    return result;
}

int rintls_rsa_pkcs1_verify(u32 hash_algorithm,
                            const rintls_rsa_public_key* public_key,
                            const u8* message, rin_size_t message_len,
                            const u8* signature, rin_size_t signature_len)
{
    rintls_bearssl_public_key bearssl_public_key;
    const br_hash_class* digest_class;
    const unsigned char* oid;
    u8 digest[64];
    u8 verified_digest[64];
    rin_size_t digest_len;
    int result = -1;

    rintls_secure_zero(&bearssl_public_key, sizeof(bearssl_public_key));
    rintls_secure_zero(digest, sizeof(digest));
    rintls_secure_zero(verified_digest, sizeof(verified_digest));
    if (rintls_rsa_hash_parameters(hash_algorithm, &digest_class, &oid,
                                   &digest_len) != 0 ||
        rintls_rsa_hash_message(hash_algorithm, message, message_len, digest,
                                &digest_len) != 0 ||
        !rintls_rsa_message_is_valid(signature, signature_len) ||
        rintls_rsa_public_key_to_bearssl(public_key, &bearssl_public_key) != 0)
        goto done;
    (void)digest_class;
    if (signature_len != public_key->modulus_len ||
        br_rsa_i31_pkcs1_vrfy(signature, signature_len, oid, digest_len,
                              &bearssl_public_key.key, verified_digest) == 0) {
        result = RINTLS_RSA_VERIFY_INVALID;
        goto done;
    }
    result = rintls_rsa_constant_time_diff(digest, verified_digest,
                                           digest_len) == 0
        ? RINTLS_RSA_VERIFY_VALID
        : RINTLS_RSA_VERIFY_INVALID;

done:
    rintls_secure_zero(verified_digest, sizeof(verified_digest));
    rintls_secure_zero(digest, sizeof(digest));
    rintls_secure_zero(&bearssl_public_key, sizeof(bearssl_public_key));
    return result;
}

static int rintls_rsa_pss_salt_length(const rintls_rsa_public_key* public_key,
                                      rin_size_t digest_len, u32 requested,
                                      rin_size_t* salt_len_out)
{
    rin_size_t maximum;

    if (!public_key || !salt_len_out ||
        public_key->modulus_len < digest_len + 2u)
        return -1;
    maximum = public_key->modulus_len - digest_len - 2u;
    if (requested == RINTLS_RSA_PSS_SALT_LENGTH_MAX) {
        *salt_len_out = maximum;
        return 0;
    }
    if ((rin_size_t)requested > maximum)
        return -1;
    *salt_len_out = (rin_size_t)requested;
    return 0;
}

static int rintls_rsa_pss_encode(u32 hash_algorithm,
                                 const br_hash_class* digest_class,
                                 const u8* message, rin_size_t message_len,
                                 const rintls_rsa_public_key* public_key,
                                 rin_size_t salt_len,
                                 u8 encoded[RINTLS_RSA_MAX_MODULUS_BYTES])
{
    u8 digest[64];
    u8 hash[64];
    u8 salt[RINTLS_RSA_MAX_MODULUS_BYTES];
    u8 hash_input[8u + 64u + RINTLS_RSA_MAX_MODULUS_BYTES];
    rin_size_t digest_len;
    rin_size_t encoded_len;
    rin_size_t database_len;
    rin_size_t delimiter;
    u32 unused_bits;
    int result = -1;

    rintls_secure_zero(digest, sizeof(digest));
    rintls_secure_zero(hash, sizeof(hash));
    rintls_secure_zero(salt, sizeof(salt));
    rintls_secure_zero(hash_input, sizeof(hash_input));
    if (!digest_class || !public_key || !encoded ||
        rintls_rsa_hash_message(hash_algorithm, message, message_len, digest,
                                &digest_len) != 0 ||
        rintls_rsa_pss_salt_length(public_key, digest_len, (u32)salt_len,
                                    &salt_len) != 0)
        goto done;

    encoded_len = public_key->modulus_len;
    database_len = encoded_len - digest_len - 1u;
    if (salt_len > database_len - 1u ||
        rintls_get_random(salt, salt_len) != 0)
        goto done;
    rintls_memcpy(hash_input + 8u, digest, digest_len);
    rintls_memcpy(hash_input + 8u + digest_len, salt, salt_len);
    if (rintls_rsa_hash_message(hash_algorithm, hash_input,
                                8u + digest_len + salt_len, hash,
                                &digest_len) != 0)
        goto done;

    rintls_secure_zero(encoded, encoded_len);
    delimiter = database_len - salt_len - 1u;
    encoded[delimiter] = 0x01u;
    rintls_memcpy(encoded + delimiter + 1u, salt, salt_len);
    br_mgf1_xor(encoded, database_len, digest_class, hash, digest_len);
    unused_bits = (u32)(8u * encoded_len - (public_key->modulus_bits - 1u));
    if (unused_bits == 0 || unused_bits > 8u)
        goto done;
    encoded[0] &= (u8)(0xffu >> unused_bits);
    rintls_memcpy(encoded + database_len, hash, digest_len);
    encoded[encoded_len - 1u] = 0xbcu;
    result = 0;

done:
    rintls_secure_zero(hash_input, sizeof(hash_input));
    rintls_secure_zero(salt, sizeof(salt));
    rintls_secure_zero(hash, sizeof(hash));
    rintls_secure_zero(digest, sizeof(digest));
    return result;
}

int rintls_rsa_pss_sign(u32 hash_algorithm,
                        const rintls_rsa_private_key* private_key,
                        const u8* message, rin_size_t message_len,
                        u32 salt_length, u8* signature,
                        rin_size_t signature_capacity,
                        rin_size_t* signature_len)
{
    rintls_bearssl_private_key bearssl_private_key;
    rintls_bearssl_public_key bearssl_public_key;
    const br_hash_class* digest_class;
    const unsigned char* oid;
    rin_size_t digest_len;
    rin_size_t effective_salt_len;
    int result = -1;

    rintls_secure_zero(&bearssl_private_key, sizeof(bearssl_private_key));
    rintls_secure_zero(&bearssl_public_key, sizeof(bearssl_public_key));
    if (!signature_len)
        goto done;
    *signature_len = 0;
    if (!rintls_rsa_output_is_valid(signature, signature_capacity))
        goto done;
    rintls_rsa_clear_output(signature, signature_capacity);
    if (rintls_rsa_hash_parameters(hash_algorithm, &digest_class, &oid,
                                   &digest_len) != 0 ||
        rintls_rsa_private_key_to_bearssl(private_key,
                                           &bearssl_private_key) != 0 ||
        rintls_rsa_private_key_is_consistent(private_key,
                                              &bearssl_private_key) != 0 ||
        rintls_rsa_public_key_to_bearssl(&private_key->public_key,
                                          &bearssl_public_key) != 0 ||
        signature_capacity < private_key->public_key.modulus_len ||
        rintls_rsa_pss_salt_length(&private_key->public_key, digest_len,
                                   salt_length, &effective_salt_len) != 0 ||
        rintls_rsa_pss_encode(hash_algorithm, digest_class, message,
                              message_len, &private_key->public_key,
                              effective_salt_len, signature) != 0 ||
        br_rsa_i31_private(signature, &bearssl_private_key.key) == 0 ||
        rintls_rsa_pss_verify(hash_algorithm, &private_key->public_key,
                              message, message_len, salt_length, signature,
                              private_key->public_key.modulus_len) !=
            RINTLS_RSA_VERIFY_VALID)
        goto done;
    (void)oid;
    *signature_len = private_key->public_key.modulus_len;
    result = 0;

done:
    if (result != 0) {
        rintls_rsa_clear_output(signature, signature_capacity);
        if (signature_len)
            *signature_len = 0;
    }
    rintls_secure_zero(&bearssl_public_key, sizeof(bearssl_public_key));
    rintls_secure_zero(&bearssl_private_key, sizeof(bearssl_private_key));
    return result;
}

int rintls_rsa_pss_verify(u32 hash_algorithm,
                          const rintls_rsa_public_key* public_key,
                          const u8* message, rin_size_t message_len,
                          u32 salt_length, const u8* signature,
                          rin_size_t signature_len)
{
    rintls_bearssl_public_key bearssl_public_key;
    const br_hash_class* digest_class;
    const unsigned char* oid;
    u8 encoded[RINTLS_RSA_MAX_MODULUS_BYTES];
    u8 digest[64];
    u8 computed_hash[64];
    u8 hash_input[8u + 64u + RINTLS_RSA_MAX_MODULUS_BYTES];
    rin_size_t digest_len;
    rin_size_t effective_salt_len;
    rin_size_t encoded_len;
    rin_size_t database_len;
    rin_size_t delimiter;
    u32 unused_bits;
    u8 top_mask;
    int result = -1;

    rintls_secure_zero(&bearssl_public_key, sizeof(bearssl_public_key));
    rintls_secure_zero(encoded, sizeof(encoded));
    rintls_secure_zero(digest, sizeof(digest));
    rintls_secure_zero(computed_hash, sizeof(computed_hash));
    rintls_secure_zero(hash_input, sizeof(hash_input));
    if (rintls_rsa_hash_parameters(hash_algorithm, &digest_class, &oid,
                                   &digest_len) != 0 ||
        rintls_rsa_hash_message(hash_algorithm, message, message_len, digest,
                                &digest_len) != 0 ||
        rintls_rsa_public_key_to_bearssl(public_key, &bearssl_public_key) != 0 ||
        rintls_rsa_pss_salt_length(public_key, digest_len, salt_length,
                                   &effective_salt_len) != 0 ||
        !rintls_rsa_message_is_valid(signature, signature_len))
        goto done;
    (void)oid;
    if (signature_len != public_key->modulus_len) {
        result = RINTLS_RSA_VERIFY_INVALID;
        goto done;
    }
    encoded_len = public_key->modulus_len;
    database_len = encoded_len - digest_len - 1u;
    if (effective_salt_len > database_len - 1u) {
        result = RINTLS_RSA_VERIFY_INVALID;
        goto done;
    }
    rintls_memcpy(encoded, signature, signature_len);
    if (br_rsa_i31_public(encoded, encoded_len, &bearssl_public_key.key) == 0 ||
        encoded[encoded_len - 1u] != 0xbcu) {
        result = RINTLS_RSA_VERIFY_INVALID;
        goto done;
    }
    unused_bits = (u32)(8u * encoded_len - (public_key->modulus_bits - 1u));
    if (unused_bits == 0 || unused_bits > 8u) {
        result = RINTLS_RSA_VERIFY_INVALID;
        goto done;
    }
    top_mask = (u8)(0xffu << (8u - unused_bits));
    if ((encoded[0] & top_mask) != 0) {
        result = RINTLS_RSA_VERIFY_INVALID;
        goto done;
    }
    br_mgf1_xor(encoded, database_len, digest_class,
                encoded + database_len, digest_len);
    encoded[0] &= (u8)(0xffu >> unused_bits);
    delimiter = database_len - effective_salt_len - 1u;
    {
        rin_size_t index;
        for (index = 0; index < delimiter; ++index) {
            if (encoded[index] != 0) {
                result = RINTLS_RSA_VERIFY_INVALID;
                goto done;
            }
        }
    }
    if (encoded[delimiter] != 0x01u) {
        result = RINTLS_RSA_VERIFY_INVALID;
        goto done;
    }
    rintls_memcpy(hash_input + 8u, digest, digest_len);
    rintls_memcpy(hash_input + 8u + digest_len,
                  encoded + delimiter + 1u, effective_salt_len);
    if (rintls_rsa_hash_message(hash_algorithm, hash_input,
                                8u + digest_len + effective_salt_len,
                                computed_hash, &digest_len) != 0)
        goto done;
    result = rintls_rsa_constant_time_diff(encoded + database_len,
                                           computed_hash, digest_len) == 0
        ? RINTLS_RSA_VERIFY_VALID
        : RINTLS_RSA_VERIFY_INVALID;

done:
    rintls_secure_zero(hash_input, sizeof(hash_input));
    rintls_secure_zero(computed_hash, sizeof(computed_hash));
    rintls_secure_zero(digest, sizeof(digest));
    rintls_secure_zero(encoded, sizeof(encoded));
    rintls_secure_zero(&bearssl_public_key, sizeof(bearssl_public_key));
    return result;
}
