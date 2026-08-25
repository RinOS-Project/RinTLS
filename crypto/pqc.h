/* rinTLS post-quantum provider boundary (FIPS 203 / FIPS 204). */
#ifndef RINTLS_PQC_H
#define RINTLS_PQC_H

#include "../platform/rin_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RINTLS_MLDSA_44 44u
#define RINTLS_MLDSA_65 65u
#define RINTLS_MLDSA_87 87u
#define RINTLS_MLKEM_512 512u
#define RINTLS_MLKEM_768 768u
#define RINTLS_MLKEM_1024 1024u

#define RINTLS_MLDSA_SEED_SIZE 32u
#define RINTLS_MLKEM_SEED_SIZE 64u
#define RINTLS_MLKEM_SHARED_SECRET_SIZE 32u

/* For recognized parameter sets, non-NULL output buffers and size outputs are
 * cleared before an ordinary later admission failure. An unknown set has no
 * safe output extent to clear. An output overlapping another non-empty buffer
 * argument is rejected before every write, preserving caller storage. ML-KEM
 * decapsulation preserves the FIPS 203 implicit-rejection secret for malformed
 * ciphertexts, but rejects a private key whose embedded public-key hash is
 * inconsistent. Verification distinguishes an invalid signature from an
 * operational fault. */
#define RINTLS_PQC_VERIFY_VALID 0
#define RINTLS_PQC_VERIFY_INVALID 1

int rintls_mldsa_sizes(u32 level, rin_size_t* public_key_size,
                       rin_size_t* private_key_size, rin_size_t* signature_size);
int rintls_mldsa_keygen(u32 level, u8 seed[RINTLS_MLDSA_SEED_SIZE],
                        u8* public_key, u8* private_key);
int rintls_mldsa_keygen_from_seed(u32 level,
                                  const u8 seed[RINTLS_MLDSA_SEED_SIZE],
                                  u8* public_key, u8* private_key);
int rintls_mldsa_public_from_private(u32 level, u8* public_key,
                                     const u8* private_key);
int rintls_mldsa_sign(u32 level, u8* signature, const u8* message,
                      rin_size_t message_len, const u8* context,
                      rin_size_t context_len, const u8* private_key);
int rintls_mldsa_verify(u32 level, const u8* signature, const u8* message,
                        rin_size_t message_len, const u8* context,
                        rin_size_t context_len, const u8* public_key);

int rintls_mlkem_sizes(u32 level, rin_size_t* public_key_size,
                       rin_size_t* private_key_size, rin_size_t* ciphertext_size);
int rintls_mlkem_keygen(u32 level, u8 seed[RINTLS_MLKEM_SEED_SIZE],
                        u8* public_key, u8* private_key);
int rintls_mlkem_keygen_from_seed(u32 level,
                                  const u8 seed[RINTLS_MLKEM_SEED_SIZE],
                                  u8* public_key, u8* private_key);
int rintls_mlkem_public_from_private(u32 level, u8* public_key,
                                     const u8* private_key);
int rintls_mlkem_encapsulate(u32 level, u8* ciphertext,
                             u8 shared_secret[RINTLS_MLKEM_SHARED_SECRET_SIZE],
                             const u8* public_key);
int rintls_mlkem_decapsulate(u32 level,
                             u8 shared_secret[RINTLS_MLKEM_SHARED_SECRET_SIZE],
                             const u8* ciphertext, const u8* private_key);

#ifdef __cplusplus
}
#endif

#endif /* RINTLS_PQC_H */
