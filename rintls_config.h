/*
 * rinTLS - RinOS TLS Library Configuration
 * 設定ヘッダー
 */

#ifndef RINTLS_CONFIG_H
#define RINTLS_CONFIG_H

/* Platform Detection
 * RIN_USERSPACE builds use libc/socket APIs even with freestanding toolchain flags. */
#if defined(RIN_USERSPACE)
#ifdef RIN_FREESTANDING
#undef RIN_FREESTANDING
#endif
#define RIN_FREESTANDING  0
#else
#ifndef RIN_FREESTANDING
#define RIN_FREESTANDING  1  /* Enable for kernel builds */
#endif
#endif

/* Common Definitions */
#ifndef RIN_NULL
#define RIN_NULL  ((void*)0)
#endif

/* TLS Version Support */
#define RINTLS_TLS12_ENABLED    1
#define RINTLS_TLS13_ENABLED    1

/* Cipher Suites - TLS 1.2 */
#define RINTLS_CIPHER_ECDHE_RSA_AES128_GCM_SHA256   1
#define RINTLS_CIPHER_ECDHE_RSA_AES256_GCM_SHA384   1

/* Cipher Suites - TLS 1.3 */
#define RINTLS_CIPHER_AES128_GCM_SHA256             1
#define RINTLS_CIPHER_AES256_GCM_SHA384             1
#define RINTLS_CIPHER_CHACHA20_POLY1305_SHA256      0  /* Optional, disabled by default */

/* Key Exchange */
#define RINTLS_ECDH_P256_ENABLED    1
#define RINTLS_ECDH_X25519_ENABLED  1

/* Hash Algorithms */
#define RINTLS_SHA256_ENABLED   1
#define RINTLS_SHA384_ENABLED   1
#define RINTLS_SHA1_ENABLED     1  /* For compatibility only */

/* Certificate Verification */
#define RINTLS_CERT_VERIFY_ENABLED  1
#define RINTLS_CA_BUNDLE_EMBEDDED   1

/* Buffer Sizes */
#define RINTLS_MAX_RECORD_SIZE      16384   /* 16KB - TLS max */
#define RINTLS_MAX_HANDSHAKE_SIZE   65536   /* 64KB */
#define RINTLS_MAX_CERT_SIZE        8192    /* 8KB per cert */
#define RINTLS_MAX_CERT_CHAIN       5       /* Max certs in chain */

/* Bignum Configuration */
#define RINTLS_BIGNUM_MAX_BITS      4096    /* Max RSA key size */
#define RINTLS_BIGNUM_WORD_SIZE     32      /* 32-bit words */

/* Session Cache */
#define RINTLS_SESSION_CACHE_SIZE   8

/* Debug */
#ifdef RINTLS_DEBUG
#define RINTLS_DEBUG_HANDSHAKE  1
#define RINTLS_DEBUG_RECORD     1
#define RINTLS_DEBUG_CRYPTO     1
#endif

#endif /* RINTLS_CONFIG_H */
