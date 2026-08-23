#ifndef RINTLS_MLKEM768_CONFIG_H
#define RINTLS_MLKEM768_CONFIG_H

#include <stddef.h>
#include <stdint.h>
#include "../platform/rin_platform.h"

#define MLK_CONFIG_PARAMETER_SET 768
#define MLK_CONFIG_NAMESPACE_PREFIX rintls_mlkem768
#define MLK_CONFIG_CUSTOM_RANDOMBYTES
#define MLK_CONFIG_CUSTOM_ZEROIZE
#define MLK_CONFIG_NO_ASM
#define MLK_CONFIG_KEYGEN_PCT

static int mlk_randombytes(uint8_t* out, size_t len)
{
    return rintls_get_random((u8*)out, (rin_size_t)len);
}

static void mlk_zeroize(void* ptr, size_t len)
{
    rintls_secure_zero(ptr, (rin_size_t)len);
}

#endif
