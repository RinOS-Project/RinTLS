/* rinTLS bounded RSA provider for the RinOS WebCrypto consumer. */
#ifndef RINTLS_RSA_WEBCRYPTO_H
#define RINTLS_RSA_WEBCRYPTO_H

#include "../platform/rin_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RINTLS_RSA_MIN_MODULUS_BITS 2048u
#define RINTLS_RSA_MAX_MODULUS_BITS 4096u
#define RINTLS_RSA_MAX_MODULUS_BYTES (RINTLS_RSA_MAX_MODULUS_BITS / 8u)
#define RINTLS_RSA_MAX_FACTOR_BYTES (RINTLS_RSA_MAX_MODULUS_BYTES / 2u)
#define RINTLS_RSA_MAX_PUBLIC_EXPONENT_BYTES 4u
#define RINTLS_RSA_KEYGEN_CANDIDATE_LIMIT 65536u
#define RINTLS_RSA_PSS_SALT_LENGTH_MAX 0xffffffffu

#define RINTLS_RSA_HASH_SHA1 1u
#define RINTLS_RSA_HASH_SHA256 2u
#define RINTLS_RSA_HASH_SHA384 3u
#define RINTLS_RSA_HASH_SHA512 4u

#define RINTLS_RSA_VERIFY_VALID 0
#define RINTLS_RSA_VERIFY_INVALID 1

typedef struct {
    u16 modulus_bits;
    u16 modulus_len;
    u8 modulus[RINTLS_RSA_MAX_MODULUS_BYTES];
    u8 public_exponent[RINTLS_RSA_MAX_PUBLIC_EXPONENT_BYTES];
    u8 public_exponent_len;
} rintls_rsa_public_key;

typedef struct {
    rintls_rsa_public_key public_key;
    u16 private_exponent_len;
    u16 prime1_len;
    u16 prime2_len;
    u16 exponent1_len;
    u16 exponent2_len;
    u16 coefficient_len;
    u8 private_exponent[RINTLS_RSA_MAX_MODULUS_BYTES];
    u8 prime1[RINTLS_RSA_MAX_FACTOR_BYTES];
    u8 prime2[RINTLS_RSA_MAX_FACTOR_BYTES];
    u8 exponent1[RINTLS_RSA_MAX_FACTOR_BYTES];
    u8 exponent2[RINTLS_RSA_MAX_FACTOR_BYTES];
    u8 coefficient[RINTLS_RSA_MAX_FACTOR_BYTES];
} rintls_rsa_private_key;

/* Output capacities must describe the supplied buffers and cannot exceed
 * RINTLS_RSA_MAX_MODULUS_BYTES. On failure, the declared output range is
 * cleared. Every result buffer and its length record must be disjoint from
 * every other non-empty buffer argument; an overlap is rejected before every
 * write and leaves caller storage unchanged. RSA-PSS uses the selected message
 * hash for MGF1. A salt length of RINTLS_RSA_PSS_SALT_LENGTH_MAX requests the
 * largest RFC 8017 value for the key and hash. */
int rintls_rsa_generate_keypair(u32 modulus_bits, u32 public_exponent,
                                rintls_rsa_private_key* key_out);

/* Raw RSA representatives and generic EMSA-PKCS1-v1_5 encoding.  These
 * primitives are intentionally separate from the WebCrypto algorithm
 * wrappers: callers must supply an exactly modulus-sized representative and
 * receive an exactly modulus-sized result.  The provider validates the
 * representative is below n, rejects all overlapping input/output ranges,
 * and clears the declared output range on ordinary failure. */
int rintls_rsa_raw_public(const rintls_rsa_public_key* public_key,
                          const u8* input, rin_size_t input_len,
                          u8* output, rin_size_t output_capacity,
                          rin_size_t* output_len);
int rintls_rsa_raw_private(const rintls_rsa_private_key* private_key,
                           const u8* input, rin_size_t input_len,
                           u8* output, rin_size_t output_capacity,
                           rin_size_t* output_len);
int rintls_rsa_emsa_pkcs1_encode(const u8* message, rin_size_t message_len,
                                 rin_size_t modulus_len, u8* encoded,
                                 rin_size_t encoded_capacity,
                                 rin_size_t* encoded_len);
int rintls_rsa_emsa_pkcs1_verify(const u8* message, rin_size_t message_len,
                                 rin_size_t modulus_len,
                                 const u8* encoded,
                                 rin_size_t encoded_len);

int rintls_rsa_oaep_encrypt(u32 hash_algorithm,
                            const rintls_rsa_public_key* public_key,
                            const u8* label, rin_size_t label_len,
                            const u8* message, rin_size_t message_len,
                            u8* encrypted, rin_size_t encrypted_capacity,
                            rin_size_t* encrypted_len);
int rintls_rsa_oaep_decrypt(u32 hash_algorithm,
                            const rintls_rsa_private_key* private_key,
                            const u8* encrypted, rin_size_t encrypted_len,
                            const u8* label, rin_size_t label_len,
                            u8* message, rin_size_t message_capacity,
                            rin_size_t* message_len);
int rintls_rsa_pkcs1_sign(u32 hash_algorithm,
                          const rintls_rsa_private_key* private_key,
                          const u8* message, rin_size_t message_len,
                          u8* signature, rin_size_t signature_capacity,
                          rin_size_t* signature_len);
int rintls_rsa_pkcs1_verify(u32 hash_algorithm,
                            const rintls_rsa_public_key* public_key,
                            const u8* message, rin_size_t message_len,
                            const u8* signature, rin_size_t signature_len);
/* Hash-oriented counterparts for callers such as System.Security.Cryptography
 * whose SignHash/VerifyHash APIs receive the digest rather than the original
 * message. The digest is never hashed a second time. */
int rintls_rsa_pkcs1_sign_digest(u32 hash_algorithm,
                                 const rintls_rsa_private_key* private_key,
                                 const u8* digest, rin_size_t digest_len,
                                 u8* signature, rin_size_t signature_capacity,
                                 rin_size_t* signature_len);
int rintls_rsa_pkcs1_verify_digest(u32 hash_algorithm,
                                   const rintls_rsa_public_key* public_key,
                                   const u8* digest, rin_size_t digest_len,
                                   const u8* signature, rin_size_t signature_len);
int rintls_rsa_pss_sign(u32 hash_algorithm,
                        const rintls_rsa_private_key* private_key,
                        const u8* message, rin_size_t message_len,
                        u32 salt_length, u8* signature,
                        rin_size_t signature_capacity,
                        rin_size_t* signature_len);
int rintls_rsa_pss_verify(u32 hash_algorithm,
                          const rintls_rsa_public_key* public_key,
                          const u8* message, rin_size_t message_len,
                          u32 salt_length, const u8* signature,
                          rin_size_t signature_len);
int rintls_rsa_pss_sign_digest(u32 hash_algorithm,
                               const rintls_rsa_private_key* private_key,
                               const u8* digest, rin_size_t digest_len,
                               u32 salt_length, u8* signature,
                               rin_size_t signature_capacity,
                               rin_size_t* signature_len);
int rintls_rsa_pss_verify_digest(u32 hash_algorithm,
                                 const rintls_rsa_public_key* public_key,
                                 const u8* digest, rin_size_t digest_len,
                                 u32 salt_length, const u8* signature,
                                 rin_size_t signature_len);

#ifdef __cplusplus
}
#endif

#endif /* RINTLS_RSA_WEBCRYPTO_H */
