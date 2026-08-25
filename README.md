# RinTLS
RinOS用TLSライブラリ

## Modern WebCrypto provider boundary

RinOS builds the modern public-key boundary from `crypto/modern.c` and
`crypto/pqc.c`. The fixed-width API is backed by the reduced libecc profile
(P-256/P-384/P-521, Ed25519/Ed448, X25519/X448) and namespaced ML-DSA/ML-KEM
reference providers. Their only random-byte route is `rintls_get_random()`;
there is no provider-local PRNG fallback.

The native Ladybird CTest targets `rintls-modern-backend` and
`rintls-modern-random-failclose` respectively cover the real provider
operations and forced CSPRNG failure. The latter compiles a test-only
freestanding boundary and verifies that randomized operations clear every
caller-visible seed/output buffer before returning an error. It does not ship
in a RinOS image. Every modern/PQC output buffer must be disjoint from the
operation's other non-empty buffer arguments. An overlap is rejected before
the first write and leaves all caller storage unchanged; this prevents the
ordinary output-zeroization policy from erasing a private key, message, or
second result buffer. `rintls_nist_ecdsa_sign_digest()` and
`rintls_nist_ecdsa_verify_digest()` are the separate path for callers that
already have an ECDSA digest: only 32-, 48-, and 64-byte SHA-256/SHA-384/
SHA-512 digests are admitted, so these callers do not accidentally hash a
digest a second time. The linked test covers their P-384/P-521 round trip,
tamper rejection, invalid digest-width rejection, and entropy-failure output
clearing. ML-KEM keeps the FIPS 203 implicit-rejection secret for a
malformed ciphertext, while a private key with an inconsistent embedded
public-key hash is rejected before it reaches the provider and its caller
shared-secret output is cleared. Both X25519 and X448 reject the all-zero
shared secret produced by a low-order peer input and clear their caller output
before returning an error. RSA-OAEP, RSASSA-PKCS1-v1_5, and RSA-PSS apply the
same boundary to their result bytes and result-length record: neither may
overlap a key, label, message, ciphertext, signature, or each other. An
overlap is rejected without modifying caller storage. RSA key generation and
browser-process/QEMU WebCrypto coverage remain unfinished; see the root
`TODO.md`.
