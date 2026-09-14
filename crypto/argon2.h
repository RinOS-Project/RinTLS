/*
 * rinTLS - Argon2id password KDF contract
 *
 * The implementation is supplied by the versioned Argon2 provider selected by
 * the product.  Consumers must use this contract instead of including the
 * provider header directly.
 */

#ifndef RINTLS_ARGON2_H
#define RINTLS_ARGON2_H

#include "../platform/rin_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RINTLS_ARGON2_REQUEST_VERSION 1u
#define RINTLS_ARGON2_FLAG_CLEAR_PASSWORD 1u

#define RINTLS_ARGON2_OK 0
#define RINTLS_ARGON2_ERR_INVALID (-1)
#define RINTLS_ARGON2_ERR_PROVIDER (-2)

typedef int (*rintls_argon2_allocate_func)(u8** memory, size_t bytes);
typedef void (*rintls_argon2_free_func)(u8* memory, size_t bytes);

/*
 * All storage remains owned by the caller.  The callbacks are deliberately
 * part of the request so a caller can keep Argon2's memory in a bounded,
 * zeroized workspace without exposing an allocator to the public library.
 */
typedef struct rintls_argon2id_request_v1 {
    u32 struct_size;
    u32 version;
    u8* output;
    u32 output_size;
    u8* password;
    u32 password_size;
    const u8* salt;
    u32 salt_size;
    u32 memory_kib;
    u32 time_cost;
    u32 lanes;
    u32 threads;
    rintls_argon2_allocate_func allocate;
    rintls_argon2_free_func release;
    u32 flags;
    u32 reserved0;
    u64 reserved[2];
} rintls_argon2id_request_v1;

/* Derive an Argon2id v1.3 digest, returning an error on every failure. */
int rintls_argon2id_derive(const rintls_argon2id_request_v1* request);

#ifdef __cplusplus
}
#endif

#endif /* RINTLS_ARGON2_H */
