/* SPDX-License-Identifier: Apache-2.0 OR CC0-1.0 */

#include "argon2.h"

/* The provider is an external, version-pinned source dependency.  Keeping
 * this include in RinTLS confines provider-specific types and constants to
 * this adapter; consumers only see the contract in argon2.h. */
#include <argon2.h>

static int rintls_argon2_request_valid(
    const rintls_argon2id_request_v1* request)
{
    return request && request->struct_size == sizeof(*request) &&
           request->version == RINTLS_ARGON2_REQUEST_VERSION &&
           request->output && request->output_size != 0u &&
           request->password && request->password_size != 0u &&
           request->salt && request->salt_size >= ARGON2_MIN_SALT_LENGTH &&
           request->memory_kib != 0u && request->time_cost != 0u &&
           request->lanes != 0u && request->threads != 0u &&
           request->allocate && request->release &&
           (request->flags & ~RINTLS_ARGON2_FLAG_CLEAR_PASSWORD) == 0u &&
           request->reserved0 == 0u && request->reserved[0] == 0u &&
           request->reserved[1] == 0u;
}

int rintls_argon2id_derive(const rintls_argon2id_request_v1* request)
{
    argon2_context context;
    int result;

    if (request && request->output && request->output_size != 0u)
        rintls_memzero(request->output, request->output_size);
    if (!rintls_argon2_request_valid(request)) return RINTLS_ARGON2_ERR_INVALID;

    rintls_memzero(&context, sizeof(context));
    context.out = request->output;
    context.outlen = request->output_size;
    context.pwd = request->password;
    context.pwdlen = request->password_size;
    context.salt = (u8*)request->salt;
    context.saltlen = request->salt_size;
    context.t_cost = request->time_cost;
    context.m_cost = request->memory_kib;
    context.lanes = request->lanes;
    context.threads = request->threads;
    context.version = ARGON2_VERSION_13;
    context.allocate_cbk = request->allocate;
    context.free_cbk = request->release;
    context.flags = (request->flags & RINTLS_ARGON2_FLAG_CLEAR_PASSWORD) ?
                    ARGON2_FLAG_CLEAR_PASSWORD : ARGON2_DEFAULT_FLAGS;

    result = argon2_ctx(&context, Argon2_id);
    rintls_memzero(&context, sizeof(context));
    if (result != ARGON2_OK) {
        rintls_memzero(request->output, request->output_size);
        return RINTLS_ARGON2_ERR_PROVIDER;
    }
    return RINTLS_ARGON2_OK;
}
