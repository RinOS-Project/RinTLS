/* Fixed-width rintls facade for the three FIPS 203/204 parameter sets. */
#include "pqc.h"

typedef int (*rintls_mldsa_keypair_fn)(u8*, u8*, const u8*);
typedef int (*rintls_mldsa_public_fn)(u8*, const u8*);
typedef int (*rintls_mldsa_sign_fn)(u8*, const u8*, size_t, const u8*, size_t,
                                    const u8*);
typedef int (*rintls_mldsa_verify_fn)(const u8*, const u8*, size_t, const u8*,
                                      size_t, const u8*);

typedef struct rintls_mldsa_provider {
    rin_size_t public_key_size;
    rin_size_t private_key_size;
    rin_size_t signature_size;
    rintls_mldsa_keypair_fn keypair;
    rintls_mldsa_public_fn public_from_private;
    rintls_mldsa_sign_fn sign;
    rintls_mldsa_verify_fn verify;
} rintls_mldsa_provider;

typedef int (*rintls_mlkem_keypair_fn)(u8*, u8*, const u8*);
typedef int (*rintls_mlkem_enc_fn)(u8*, u8*, const u8*);
typedef int (*rintls_mlkem_dec_fn)(u8*, const u8*, const u8*);
typedef int (*rintls_mlkem_check_sk_fn)(const u8*);

typedef struct rintls_mlkem_provider {
    rin_size_t public_key_size;
    rin_size_t private_key_size;
    rin_size_t ciphertext_size;
    rintls_mlkem_keypair_fn keypair;
    rintls_mlkem_enc_fn encapsulate;
    rintls_mlkem_dec_fn decapsulate;
    rintls_mlkem_check_sk_fn check_private_key;
} rintls_mlkem_provider;

/* These declarations are the deliberately namespaced public APIs emitted by
 * the six single-compilation-unit provider builds. */
extern int rintls_mldsa44_keypair_internal(u8*, u8*, const u8*);
extern int rintls_mldsa44_pk_from_sk(u8*, const u8*);
extern int rintls_mldsa44_signature(u8*, const u8*, size_t, const u8*, size_t,
                                    const u8*);
extern int rintls_mldsa44_verify(const u8*, const u8*, size_t, const u8*, size_t,
                                 const u8*);
extern int rintls_mldsa65_keypair_internal(u8*, u8*, const u8*);
extern int rintls_mldsa65_pk_from_sk(u8*, const u8*);
extern int rintls_mldsa65_signature(u8*, const u8*, size_t, const u8*, size_t,
                                    const u8*);
extern int rintls_mldsa65_verify(const u8*, const u8*, size_t, const u8*, size_t,
                                 const u8*);
extern int rintls_mldsa87_keypair_internal(u8*, u8*, const u8*);
extern int rintls_mldsa87_pk_from_sk(u8*, const u8*);
extern int rintls_mldsa87_signature(u8*, const u8*, size_t, const u8*, size_t,
                                    const u8*);
extern int rintls_mldsa87_verify(const u8*, const u8*, size_t, const u8*, size_t,
                                 const u8*);

extern int rintls_mlkem512_keypair_derand(u8*, u8*, const u8*);
extern int rintls_mlkem512_enc(u8*, u8*, const u8*);
extern int rintls_mlkem512_dec(u8*, const u8*, const u8*);
extern int rintls_mlkem512_check_sk(const u8*);
extern int rintls_mlkem768_keypair_derand(u8*, u8*, const u8*);
extern int rintls_mlkem768_enc(u8*, u8*, const u8*);
extern int rintls_mlkem768_dec(u8*, const u8*, const u8*);
extern int rintls_mlkem768_check_sk(const u8*);
extern int rintls_mlkem1024_keypair_derand(u8*, u8*, const u8*);
extern int rintls_mlkem1024_enc(u8*, u8*, const u8*);
extern int rintls_mlkem1024_dec(u8*, const u8*, const u8*);
extern int rintls_mlkem1024_check_sk(const u8*);

static int rintls_message_and_context_are_valid(const u8* message,
                                                rin_size_t message_len,
                                                const u8* context,
                                                rin_size_t context_len)
{
    return (message != NULL || message_len == 0) &&
           (context != NULL || context_len == 0) && context_len <= 255u;
}

/* Keep stale material from being mistaken for a successful result when a
 * recognized parameter set rejects a later input. */
static void rintls_clear_pqc_output(void* output, rin_size_t output_size)
{
    if (output)
        rintls_memset(output, 0, output_size);
}

static void rintls_clear_size_output(rin_size_t* output)
{
    if (output)
        *output = 0;
}

static int rintls_mldsa_provider_for_level(u32 level,
                                           rintls_mldsa_provider* provider)
{
    if (!provider)
        return -1;

    switch (level) {
    case RINTLS_MLDSA_44:
        provider->public_key_size = 1312u;
        provider->private_key_size = 2560u;
        provider->signature_size = 2420u;
        provider->keypair = rintls_mldsa44_keypair_internal;
        provider->public_from_private = rintls_mldsa44_pk_from_sk;
        provider->sign = rintls_mldsa44_signature;
        provider->verify = rintls_mldsa44_verify;
        return 0;
    case RINTLS_MLDSA_65:
        provider->public_key_size = 1952u;
        provider->private_key_size = 4032u;
        provider->signature_size = 3309u;
        provider->keypair = rintls_mldsa65_keypair_internal;
        provider->public_from_private = rintls_mldsa65_pk_from_sk;
        provider->sign = rintls_mldsa65_signature;
        provider->verify = rintls_mldsa65_verify;
        return 0;
    case RINTLS_MLDSA_87:
        provider->public_key_size = 2592u;
        provider->private_key_size = 4896u;
        provider->signature_size = 4627u;
        provider->keypair = rintls_mldsa87_keypair_internal;
        provider->public_from_private = rintls_mldsa87_pk_from_sk;
        provider->sign = rintls_mldsa87_signature;
        provider->verify = rintls_mldsa87_verify;
        return 0;
    default:
        return -1;
    }
}

static int rintls_mlkem_provider_for_level(u32 level,
                                           rintls_mlkem_provider* provider)
{
    if (!provider)
        return -1;

    switch (level) {
    case RINTLS_MLKEM_512:
        provider->public_key_size = 800u;
        provider->private_key_size = 1632u;
        provider->ciphertext_size = 768u;
        provider->keypair = rintls_mlkem512_keypair_derand;
        provider->encapsulate = rintls_mlkem512_enc;
        provider->decapsulate = rintls_mlkem512_dec;
        provider->check_private_key = rintls_mlkem512_check_sk;
        return 0;
    case RINTLS_MLKEM_768:
        provider->public_key_size = 1184u;
        provider->private_key_size = 2400u;
        provider->ciphertext_size = 1088u;
        provider->keypair = rintls_mlkem768_keypair_derand;
        provider->encapsulate = rintls_mlkem768_enc;
        provider->decapsulate = rintls_mlkem768_dec;
        provider->check_private_key = rintls_mlkem768_check_sk;
        return 0;
    case RINTLS_MLKEM_1024:
        provider->public_key_size = 1568u;
        provider->private_key_size = 3168u;
        provider->ciphertext_size = 1568u;
        provider->keypair = rintls_mlkem1024_keypair_derand;
        provider->encapsulate = rintls_mlkem1024_enc;
        provider->decapsulate = rintls_mlkem1024_dec;
        provider->check_private_key = rintls_mlkem1024_check_sk;
        return 0;
    default:
        return -1;
    }
}

int rintls_mldsa_sizes(u32 level, rin_size_t* public_key_size,
                       rin_size_t* private_key_size, rin_size_t* signature_size)
{
    rintls_mldsa_provider provider;

    rintls_clear_size_output(public_key_size);
    rintls_clear_size_output(private_key_size);
    rintls_clear_size_output(signature_size);
    if (!public_key_size || !private_key_size || !signature_size ||
        rintls_mldsa_provider_for_level(level, &provider) != 0)
        return -1;
    *public_key_size = provider.public_key_size;
    *private_key_size = provider.private_key_size;
    *signature_size = provider.signature_size;
    return 0;
}

int rintls_mldsa_keygen_from_seed(u32 level,
                                  const u8 seed[RINTLS_MLDSA_SEED_SIZE],
                                  u8* public_key, u8* private_key)
{
    rintls_mldsa_provider provider;
    int ret = -1;

    if (rintls_mldsa_provider_for_level(level, &provider) != 0)
        return -1;

    rintls_clear_pqc_output(public_key, provider.public_key_size);
    rintls_clear_pqc_output(private_key, provider.private_key_size);
    if (!seed || !public_key || !private_key)
        return -1;
    if (provider.keypair(public_key, private_key, seed) == 0)
        ret = 0;
    if (ret != 0) {
        rintls_memset(public_key, 0, provider.public_key_size);
        rintls_memset(private_key, 0, provider.private_key_size);
    }
    return ret;
}

int rintls_mldsa_keygen(u32 level, u8 seed[RINTLS_MLDSA_SEED_SIZE],
                        u8* public_key, u8* private_key)
{
    rintls_mldsa_provider provider;

    rintls_clear_pqc_output(seed, RINTLS_MLDSA_SEED_SIZE);
    if (rintls_mldsa_provider_for_level(level, &provider) != 0)
        return -1;

    rintls_clear_pqc_output(public_key, provider.public_key_size);
    rintls_clear_pqc_output(private_key, provider.private_key_size);
    if (!seed || !public_key || !private_key)
        return -1;
    if (rintls_get_random(seed, RINTLS_MLDSA_SEED_SIZE) != 0 ||
        rintls_mldsa_keygen_from_seed(level, seed, public_key, private_key) != 0) {
        rintls_memset(seed, 0, RINTLS_MLDSA_SEED_SIZE);
        rintls_memset(public_key, 0, provider.public_key_size);
        rintls_memset(private_key, 0, provider.private_key_size);
        return -1;
    }
    return 0;
}

int rintls_mldsa_public_from_private(u32 level, u8* public_key,
                                     const u8* private_key)
{
    rintls_mldsa_provider provider;
    int ret = -1;

    if (rintls_mldsa_provider_for_level(level, &provider) != 0)
        return -1;

    rintls_clear_pqc_output(public_key, provider.public_key_size);
    if (!public_key || !private_key)
        return -1;
    if (provider.public_from_private(public_key, private_key) == 0)
        ret = 0;
    if (ret != 0)
        rintls_memset(public_key, 0, provider.public_key_size);
    return ret;
}

int rintls_mldsa_sign(u32 level, u8* signature, const u8* message,
                      rin_size_t message_len, const u8* context,
                      rin_size_t context_len, const u8* private_key)
{
    rintls_mldsa_provider provider;
    u8 derived_public_key[2592];
    int ret = -1;

    if (rintls_mldsa_provider_for_level(level, &provider) != 0)
        return -1;

    rintls_clear_pqc_output(signature, provider.signature_size);
    if (!signature || !private_key ||
        !rintls_message_and_context_are_valid(message, message_len, context,
                                              context_len))
        return -1;
    rintls_memset(derived_public_key, 0, sizeof(derived_public_key));
    /* Validate imported private keys before using them for signing. */
    if (provider.public_from_private(derived_public_key, private_key) != 0 ||
        provider.sign(signature, message, (size_t)message_len, context,
                      (size_t)context_len, private_key) != 0)
        goto done;
    ret = 0;

done:
    if (ret != 0)
        rintls_memset(signature, 0, provider.signature_size);
    rintls_secure_zero(derived_public_key, sizeof(derived_public_key));
    return ret;
}

int rintls_mldsa_verify(u32 level, const u8* signature, const u8* message,
                        rin_size_t message_len, const u8* context,
                        rin_size_t context_len, const u8* public_key)
{
    rintls_mldsa_provider provider;
    int provider_ret;

    if (!signature || !public_key ||
        !rintls_message_and_context_are_valid(message, message_len, context,
                                              context_len) ||
        rintls_mldsa_provider_for_level(level, &provider) != 0)
        return -1;
    provider_ret = provider.verify(signature, message, (size_t)message_len,
                                   context, (size_t)context_len, public_key);
    if (provider_ret == 0)
        return RINTLS_PQC_VERIFY_VALID;
    /* FIPS 204 distinguishes an ordinary invalid signature from a provider
     * failure; preserve that distinction for the WebCrypto caller. */
    if (provider_ret == -6)
        return RINTLS_PQC_VERIFY_INVALID;
    return -1;
}

int rintls_mlkem_sizes(u32 level, rin_size_t* public_key_size,
                       rin_size_t* private_key_size, rin_size_t* ciphertext_size)
{
    rintls_mlkem_provider provider;

    rintls_clear_size_output(public_key_size);
    rintls_clear_size_output(private_key_size);
    rintls_clear_size_output(ciphertext_size);
    if (!public_key_size || !private_key_size || !ciphertext_size ||
        rintls_mlkem_provider_for_level(level, &provider) != 0)
        return -1;
    *public_key_size = provider.public_key_size;
    *private_key_size = provider.private_key_size;
    *ciphertext_size = provider.ciphertext_size;
    return 0;
}

int rintls_mlkem_keygen_from_seed(u32 level,
                                  const u8 seed[RINTLS_MLKEM_SEED_SIZE],
                                  u8* public_key, u8* private_key)
{
    rintls_mlkem_provider provider;
    int ret = -1;

    if (rintls_mlkem_provider_for_level(level, &provider) != 0)
        return -1;

    rintls_clear_pqc_output(public_key, provider.public_key_size);
    rintls_clear_pqc_output(private_key, provider.private_key_size);
    if (!seed || !public_key || !private_key)
        return -1;
    /* Provider PCT is enabled in every configuration and uses the same
     * rintls CSPRNG through mlk_randombytes. */
    if (provider.keypair(public_key, private_key, seed) == 0)
        ret = 0;
    if (ret != 0) {
        rintls_memset(public_key, 0, provider.public_key_size);
        rintls_memset(private_key, 0, provider.private_key_size);
    }
    return ret;
}

int rintls_mlkem_keygen(u32 level, u8 seed[RINTLS_MLKEM_SEED_SIZE],
                        u8* public_key, u8* private_key)
{
    rintls_mlkem_provider provider;

    rintls_clear_pqc_output(seed, RINTLS_MLKEM_SEED_SIZE);
    if (rintls_mlkem_provider_for_level(level, &provider) != 0)
        return -1;

    rintls_clear_pqc_output(public_key, provider.public_key_size);
    rintls_clear_pqc_output(private_key, provider.private_key_size);
    if (!seed || !public_key || !private_key)
        return -1;
    if (rintls_get_random(seed, RINTLS_MLKEM_SEED_SIZE) != 0 ||
        rintls_mlkem_keygen_from_seed(level, seed, public_key, private_key) != 0) {
        rintls_memset(seed, 0, RINTLS_MLKEM_SEED_SIZE);
        rintls_memset(public_key, 0, provider.public_key_size);
        rintls_memset(private_key, 0, provider.private_key_size);
        return -1;
    }
    return 0;
}

int rintls_mlkem_public_from_private(u32 level, u8* public_key,
                                     const u8* private_key)
{
    rintls_mlkem_provider provider;
    rin_size_t public_key_offset;

    if (rintls_mlkem_provider_for_level(level, &provider) != 0)
        return -1;

    rintls_clear_pqc_output(public_key, provider.public_key_size);
    if (!public_key || !private_key)
        return -1;
    if (provider.check_private_key(private_key) != 0)
        return -1;
    /* FIPS 203 encodes sk = s || pk || H(pk) || z.  check_sk above verifies
     * the embedded public-key hash before this bounded extraction. */
    public_key_offset = provider.private_key_size - provider.public_key_size -
                        (2u * RINTLS_MLKEM_SHARED_SECRET_SIZE);
    rintls_memcpy(public_key, private_key + public_key_offset,
                  provider.public_key_size);
    return 0;
}

int rintls_mlkem_encapsulate(u32 level, u8* ciphertext,
                             u8 shared_secret[RINTLS_MLKEM_SHARED_SECRET_SIZE],
                             const u8* public_key)
{
    rintls_mlkem_provider provider;
    int ret = -1;

    rintls_clear_pqc_output(shared_secret, RINTLS_MLKEM_SHARED_SECRET_SIZE);
    if (rintls_mlkem_provider_for_level(level, &provider) != 0)
        return -1;

    rintls_clear_pqc_output(ciphertext, provider.ciphertext_size);
    if (!ciphertext || !shared_secret || !public_key)
        return -1;
    if (provider.encapsulate(ciphertext, shared_secret, public_key) == 0)
        ret = 0;
    if (ret != 0) {
        rintls_memset(ciphertext, 0, provider.ciphertext_size);
        rintls_memset(shared_secret, 0, RINTLS_MLKEM_SHARED_SECRET_SIZE);
    }
    return ret;
}

int rintls_mlkem_decapsulate(u32 level,
                             u8 shared_secret[RINTLS_MLKEM_SHARED_SECRET_SIZE],
                             const u8* ciphertext, const u8* private_key)
{
    rintls_mlkem_provider provider;
    int ret = -1;

    rintls_clear_pqc_output(shared_secret, RINTLS_MLKEM_SHARED_SECRET_SIZE);
    if (rintls_mlkem_provider_for_level(level, &provider) != 0)
        return -1;
    if (!shared_secret || !ciphertext || !private_key)
        return -1;
    /* Decapsulation intentionally produces the implicit-rejection secret for
     * a malformed ciphertext. A malformed private key, however, must never
     * reach the provider: validate its embedded public-key hash first. */
    if (provider.check_private_key(private_key) == 0 &&
        provider.decapsulate(shared_secret, ciphertext, private_key) == 0)
        ret = 0;
    if (ret != 0)
        rintls_memset(shared_secret, 0, RINTLS_MLKEM_SHARED_SECRET_SIZE);
    return ret;
}
