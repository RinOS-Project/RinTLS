#ifndef RINTLS_MLDSA44_CONFIG_H
#define RINTLS_MLDSA44_CONFIG_H

#include <stddef.h>
#include <stdint.h>
#include "../platform/rin_platform.h"

#define MLD_CONFIG_PARAMETER_SET 44
#define MLD_CONFIG_NAMESPACE_PREFIX rintls_mldsa44
#define MLD_CONFIG_CUSTOM_RANDOMBYTES
#define MLD_CONFIG_CUSTOM_ZEROIZE
#define MLD_CONFIG_NO_ASM
#define MLD_CONFIG_KEYGEN_PCT

static int mld_randombytes(uint8_t* out, size_t len)
{
    return rintls_get_random((u8*)out, (rin_size_t)len);
}

static void mld_zeroize(void* ptr, size_t len)
{
    rintls_secure_zero(ptr, (rin_size_t)len);
}

#endif
