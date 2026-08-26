/*
 * rinTLS - modern public-key backend
 *
 * The API deliberately exposes only fixed-width standard encodings.  It is a
 * boundary between rintls consumers and the audited curve/PQC providers; no
 * provider object, allocator, or random-byte callback crosses this boundary.
 */

#ifndef RINTLS_MODERN_H
#define RINTLS_MODERN_H

#include "../platform/rin_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RINTLS_EC_P256 23u
#define RINTLS_EC_P384 24u
#define RINTLS_EC_P521 25u

#define RINTLS_P256_PRIVATE_KEY_SIZE 32u
#define RINTLS_P256_PUBLIC_KEY_SIZE 65u
#define RINTLS_P384_PRIVATE_KEY_SIZE 48u
#define RINTLS_P384_PUBLIC_KEY_SIZE 97u
#define RINTLS_P521_PRIVATE_KEY_SIZE 66u
#define RINTLS_P521_PUBLIC_KEY_SIZE 133u

#define RINTLS_ED25519_PRIVATE_KEY_SIZE 32u
#define RINTLS_ED25519_PUBLIC_KEY_SIZE 32u
#define RINTLS_ED25519_SIGNATURE_SIZE 64u
#define RINTLS_ED448_PRIVATE_KEY_SIZE 57u
#define RINTLS_ED448_PUBLIC_KEY_SIZE 57u
#define RINTLS_ED448_SIGNATURE_SIZE 114u
#define RINTLS_X448_KEY_SIZE 56u

#define RINTLS_HASH_SHA256 1u
#define RINTLS_HASH_SHA384 2u
#define RINTLS_HASH_SHA512 3u

/* Every function returns zero only on success. For recognized parameter sets,
 * non-NULL output buffers (and size outputs) are cleared before an ordinary
 * later admission failure; an unknown set has no safe output extent to clear.
 * An output overlapping any other non-empty buffer argument is instead
 * rejected before every write, preserving caller storage. Every pointer/length
 * pair is validated before provider calls. */
int rintls_nist_private_key_size(u32 curve, rin_size_t* size_out);
int rintls_nist_public_key_size(u32 curve, rin_size_t* size_out);
int rintls_nist_keygen(u32 curve, u8* private_key, u8* public_key);
int rintls_nist_public_from_private(u32 curve, const u8* private_key,
                                    u8* public_key);
int rintls_nist_validate_public(u32 curve, const u8* public_key,
                                rin_size_t public_key_len);
int rintls_nist_ecdh(u32 curve, u8* shared_secret, const u8* private_key,
                     const u8* peer_public_key, rin_size_t peer_public_key_len);
int rintls_nist_ecdsa_sign(u32 curve, u32 hash_algorithm,
                           const u8* message, rin_size_t message_len,
                           const u8* private_key, u8* signature);
int rintls_nist_ecdsa_verify(u32 curve, u32 hash_algorithm,
                             const u8* message, rin_size_t message_len,
                             const u8* public_key, rin_size_t public_key_len,
                             const u8* signature, rin_size_t signature_len);
/* Sign/verify an ECDSA digest that was computed by the caller. Only the
 * SHA-256, SHA-384, and SHA-512 digest widths are admitted; rintls selects
 * the matching libecc hash mapping and never hashes this input again. */
int rintls_nist_ecdsa_sign_digest(u32 curve, const u8* digest,
                                  rin_size_t digest_len,
                                  const u8* private_key, u8* signature);
int rintls_nist_ecdsa_verify_digest(u32 curve, const u8* digest,
                                    rin_size_t digest_len,
                                    const u8* public_key,
                                    rin_size_t public_key_len,
                                    const u8* signature,
                                    rin_size_t signature_len);

int rintls_ed25519_keygen(u8 private_key[RINTLS_ED25519_PRIVATE_KEY_SIZE],
                          u8 public_key[RINTLS_ED25519_PUBLIC_KEY_SIZE]);
int rintls_ed25519_public_from_private(
    const u8 private_key[RINTLS_ED25519_PRIVATE_KEY_SIZE],
    u8 public_key[RINTLS_ED25519_PUBLIC_KEY_SIZE]);
int rintls_ed25519_sign(u8 signature[RINTLS_ED25519_SIGNATURE_SIZE],
                        const u8 private_key[RINTLS_ED25519_PRIVATE_KEY_SIZE],
                        const u8* message, rin_size_t message_len);
int rintls_ed25519_verify(
    const u8 signature[RINTLS_ED25519_SIGNATURE_SIZE],
    const u8 public_key[RINTLS_ED25519_PUBLIC_KEY_SIZE], const u8* message,
    rin_size_t message_len);

int rintls_ed448_keygen(u8 private_key[RINTLS_ED448_PRIVATE_KEY_SIZE],
                        u8 public_key[RINTLS_ED448_PUBLIC_KEY_SIZE]);
int rintls_ed448_public_from_private(
    const u8 private_key[RINTLS_ED448_PRIVATE_KEY_SIZE],
    u8 public_key[RINTLS_ED448_PUBLIC_KEY_SIZE]);
int rintls_ed448_sign(u8 signature[RINTLS_ED448_SIGNATURE_SIZE],
                      const u8 private_key[RINTLS_ED448_PRIVATE_KEY_SIZE],
                      const u8* message, rin_size_t message_len,
                      const u8* context, rin_size_t context_len);
int rintls_ed448_verify(const u8 signature[RINTLS_ED448_SIGNATURE_SIZE],
                        const u8 public_key[RINTLS_ED448_PUBLIC_KEY_SIZE],
                        const u8* message, rin_size_t message_len,
                        const u8* context, rin_size_t context_len);

int rintls_x448_keygen(u8 private_key[RINTLS_X448_KEY_SIZE],
                       u8 public_key[RINTLS_X448_KEY_SIZE]);
int rintls_x448_public_from_private(const u8 private_key[RINTLS_X448_KEY_SIZE],
                                    u8 public_key[RINTLS_X448_KEY_SIZE]);
/* Rejects the all-zero shared secret produced by a low-order peer input and
 * clears shared_secret before returning an error. */
int rintls_x448_ecdh(u8 shared_secret[RINTLS_X448_KEY_SIZE],
                     const u8 private_key[RINTLS_X448_KEY_SIZE],
                     const u8 peer_public_key[RINTLS_X448_KEY_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* RINTLS_MODERN_H */
