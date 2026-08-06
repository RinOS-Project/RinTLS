/*
 * rinTLS - Platform Abstraction Layer
 * RinOSプラットフォーム依存コード
 */

#ifndef RINTLS_PLATFORM_H
#define RINTLS_PLATFORM_H

#include "../rintls_config.h"

/* Basic Types */
#ifndef RINTLS_SKIP_BASIC_TYPEDEFS
#ifdef __cplusplus
/* C++ embedders in RinOS (Ladybird/AK) already provide u8/u16/u32/u64 and signed variants. */
#else
typedef unsigned char       u8;
typedef unsigned short      u16;
typedef unsigned int        u32;
typedef unsigned long long  u64;
typedef signed char         i8;
typedef signed short        i16;
typedef signed int          i32;
typedef signed long long    i64;
#endif
#endif

#ifndef NULL
#define NULL ((void*)0)
#endif

/* Size type */
#if RIN_FREESTANDING
typedef u32 rin_size_t;
#else
#include <stddef.h>
typedef size_t rin_size_t;
#endif

/* Memory Functions */
#if RIN_FREESTANDING
/* Kernel environment - use platform functions */
extern void* platform_memset(void* dst, int val, u32 n);
extern void* platform_memcpy(void* dst, const void* src, u32 n);
extern int   platform_memcmp(const void* s1, const void* s2, u32 n);
extern void* platform_kmalloc(u32 size);
extern void  platform_kfree(void* ptr);

#define rintls_memset   platform_memset
#define rintls_memcpy   platform_memcpy
#define rintls_memcmp   platform_memcmp
#define rintls_malloc   platform_kmalloc
#define rintls_mem_free platform_kfree  /* Internal use only - not public API */

/* Secure memory clear */
static inline void rintls_memzero(void* ptr, rin_size_t len) {
    volatile u8* p = (volatile u8*)ptr;
    while (len--) *p++ = 0;
}

#define rintls_secure_zero  rintls_memzero

#else
/* Userspace - use standard library */
#if defined(RINTLS_HOST_LIBC)
#include <string.h>
#include <stdlib.h>
#else
#include "../../libc/string.h"
#include "../../libc/stdlib.h"
#endif

#define rintls_memset   memset
#define rintls_memcpy   memcpy
#define rintls_memcmp   memcmp
#define rintls_malloc   malloc
#define rintls_mem_free free

static inline void rintls_memzero(void* ptr, rin_size_t len) {
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    while (len--) *p++ = 0;
}

#define rintls_secure_zero  rintls_memzero
#endif

/* Network Functions */
#if RIN_FREESTANDING
/* tcp.c の RinTCPSocket* API を使用 */
struct RinTCPSocket;  /* Forward declaration */
typedef struct RinTCPSocket RinTCPSocket;

extern int tcp_send(RinTCPSocket* sock, const void* buf, u32 size);
extern int tcp_recv(RinTCPSocket* sock, void* buf, u32 size);
extern int tcp_close(RinTCPSocket* sock);

#define rintls_tcp_send(sock, data, len)   tcp_send((RinTCPSocket*)(sock), (data), (u32)(len))
#define rintls_tcp_recv(sock, buf, len)    tcp_recv((RinTCPSocket*)(sock), (buf), (u32)(len))
#define rintls_tcp_close(sock)             tcp_close((RinTCPSocket*)(sock))
#else
/* Userspace - socket FD API */
#if defined(RINTLS_HOST_LIBC)
#include <sys/socket.h>
#include <unistd.h>
#else
#include "../../libc/sys/socket.h"
#include "../../libc/unistd.h"
#endif

#define rintls_tcp_send(sock, data, len)   send((int)(sock), (data), (size_t)(len), 0)
#define rintls_tcp_recv(sock, buf, len)    recv((int)(sock), (buf), (size_t)(len), 0)
#define rintls_tcp_close(sock)             close((int)(sock))
#endif

/* Random Number Generation */
#if RIN_FREESTANDING
extern int rin_get_random_bytes(void* buf, u32 len);

static inline int rintls_get_random(u8* buf, rin_size_t len) {
    if (!buf && len) return -1;
    return rin_get_random_bytes(buf, (u32)len);
}
#else
#if defined(RINTLS_HOST_LIBC)
#ifdef _WIN32
/* No insecure PRNG fallback: host embedders must provide OS randomness. */
#else
#include <fcntl.h>
#include <unistd.h>
#endif
#else
#include "../../libc/sys/random.h"
#endif

static inline int rintls_get_random(u8* buf, rin_size_t len) {
    if (!buf && len) return -1;
#if defined(RINTLS_HOST_LIBC)
#ifdef _WIN32
    (void)buf;
    (void)len;
    return -1;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    rin_size_t off = 0;
    while (off < len) {
        int n = (int)read(fd, buf + off, (size_t)(len - off));
        if (n <= 0) {
            close(fd);
            return -1;
        }
        off += (rin_size_t)n;
    }
    close(fd);
    return 0;
#endif
#else
    return getrandom(buf, len, 0) == (ssize_t)len ? 0 : -1;
#endif
}
#endif

/* Alias for random bytes */
#define rintls_random_bytes(buf, len)  rintls_get_random((u8*)(buf), (rin_size_t)(len))

/* Time */
#if RIN_FREESTANDING
extern unsigned long rin_time(void);
#define rintls_time() ((u32)rin_time())
#else
#include <time.h>
#define rintls_time() ((u32)time(NULL))
#endif

/* Debug Output - Disable by default to reduce log noise */
#ifndef RINTLS_VERBOSE_DEBUG
#define RINTLS_VERBOSE_DEBUG 0
#endif

#if RINTLS_VERBOSE_DEBUG
#if RIN_FREESTANDING
extern void platform_serial_print(const char* str);
extern void platform_serial_hex(u32 val);
#define rintls_debug(msg) platform_serial_print(msg)
#define rintls_debug_hex(val) platform_serial_hex((u32)(val))
#else
#include <stdio.h>
#define rintls_debug(msg) printf("%s", msg)
#define rintls_debug_hex(val) printf("0x%08X", (unsigned int)(val))
#endif
#else
#define rintls_debug(msg) ((void)0)
#define rintls_debug_hex(val) ((void)0)
#endif

/* Endianness Conversion */
static inline u16 rintls_be16(u16 val) {
    return ((val & 0xFF) << 8) | ((val >> 8) & 0xFF);
}

static inline u32 rintls_be32(u32 val) {
    return ((val & 0xFF) << 24) |
           ((val & 0xFF00) << 8) |
           ((val >> 8) & 0xFF00) |
           ((val >> 24) & 0xFF);
}

static inline u64 rintls_be64(u64 val) {
    return ((u64)rintls_be32((u32)val) << 32) | rintls_be32((u32)(val >> 32));
}

/* Read big-endian from byte array */
static inline u16 rintls_read_be16(const u8* p) {
    return ((u16)p[0] << 8) | p[1];
}

static inline u32 rintls_read_be32(const u8* p) {
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3];
}

static inline u64 rintls_read_be64(const u8* p) {
    return ((u64)rintls_read_be32(p) << 32) | rintls_read_be32(p + 4);
}

/* Write big-endian to byte array */
static inline void rintls_write_be16(u8* p, u16 val) {
    p[0] = (u8)(val >> 8);
    p[1] = (u8)val;
}

static inline void rintls_write_be32(u8* p, u32 val) {
    p[0] = (u8)(val >> 24);
    p[1] = (u8)(val >> 16);
    p[2] = (u8)(val >> 8);
    p[3] = (u8)val;
}

static inline void rintls_write_be64(u8* p, u64 val) {
    rintls_write_be32(p, (u32)(val >> 32));
    rintls_write_be32(p + 4, (u32)val);
}

/* Constant-time comparison (timing attack resistant) */
static inline int rintls_secure_compare(const u8* a, const u8* b, rin_size_t len) {
    u8 diff = 0;
    for (rin_size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0 ? 0 : -1;
}

/* Returns 1 if equal, 0 if different (for secure comparison) */
static inline int rintls_secure_cmp(const u8* a, const u8* b, rin_size_t len) {
    return rintls_secure_compare(a, b, len) == 0 ? 1 : 0;
}

/* Rotate operations for crypto */
#define RINTLS_ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define RINTLS_ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define RINTLS_ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define RINTLS_ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

#endif /* RINTLS_PLATFORM_H */
