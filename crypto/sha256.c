/*
 * rinTLS - SHA-256/384/512 Implementation
 * SHA-256/384/512ハッシュ関数実装
 */

#include "sha256.h"

/* SHA-256 round constants */
static const u32 K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* SHA-256 macros */
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)       (RINTLS_ROTR32(x, 2) ^ RINTLS_ROTR32(x, 13) ^ RINTLS_ROTR32(x, 22))
#define EP1(x)       (RINTLS_ROTR32(x, 6) ^ RINTLS_ROTR32(x, 11) ^ RINTLS_ROTR32(x, 25))
#define SIG0(x)      (RINTLS_ROTR32(x, 7) ^ RINTLS_ROTR32(x, 18) ^ ((x) >> 3))
#define SIG1(x)      (RINTLS_ROTR32(x, 17) ^ RINTLS_ROTR32(x, 19) ^ ((x) >> 10))

static void sha256_transform(sha256_ctx* ctx, const u8* data) {
    /* volatile を使用してコンパイラ最適化による破壊を防止 */
    volatile u32 a, b, c, d, e, f, g, h, t1, t2;
    volatile u32 m[64];
    int i;

    /* Prepare message schedule - byte-by-byte to prevent optimization */
    for (i = 0; i < 16; i++) {
        m[i] = ((u32)data[i*4] << 24) |
               ((u32)data[i*4+1] << 16) |
               ((u32)data[i*4+2] << 8) |
               ((u32)data[i*4+3]);
    }
    for (i = 16; i < 64; i++) {
        u32 mi2 = m[i-2];
        u32 mi7 = m[i-7];
        u32 mi15 = m[i-15];
        u32 mi16 = m[i-16];
        u32 s1 = (RINTLS_ROTR32(mi2, 17) ^ RINTLS_ROTR32(mi2, 19) ^ (mi2 >> 10));
        u32 s0 = (RINTLS_ROTR32(mi15, 7) ^ RINTLS_ROTR32(mi15, 18) ^ (mi15 >> 3));
        m[i] = s1 + mi7 + s0 + mi16;
    }

    /* Initialize working variables */
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    /* Main loop - explicit expansion to prevent optimization issues */
    for (i = 0; i < 64; i++) {
        u32 va = a, vb = b, vc = c, vd = d, ve = e, vf = f, vg = g, vh = h;
        u32 ep1 = RINTLS_ROTR32(ve, 6) ^ RINTLS_ROTR32(ve, 11) ^ RINTLS_ROTR32(ve, 25);
        u32 ch = (ve & vf) ^ (~ve & vg);
        u32 ep0 = RINTLS_ROTR32(va, 2) ^ RINTLS_ROTR32(va, 13) ^ RINTLS_ROTR32(va, 22);
        u32 maj = (va & vb) ^ (va & vc) ^ (vb & vc);
        t1 = vh + ep1 + ch + K256[i] + m[i];
        t2 = ep0 + maj;
        h = vg;
        g = vf;
        f = ve;
        e = vd + t1;
        d = vc;
        c = vb;
        b = va;
        a = t1 + t2;
    }

    /* Add to state - use local copies to ensure correct values */
    {
        u32 fa = a, fb = b, fc = c, fd = d, fe = e, ff = f, fg = g, fh = h;
        ctx->state[0] += fa;
        ctx->state[1] += fb;
        ctx->state[2] += fc;
        ctx->state[3] += fd;
        ctx->state[4] += fe;
        ctx->state[5] += ff;
        ctx->state[6] += fg;
        ctx->state[7] += fh;
    }
}

void sha256_init(sha256_ctx* ctx) {
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

void sha256_update(sha256_ctx* ctx, const u8* data, rin_size_t len) {
    rin_size_t i;
    u32 index = (u32)((ctx->count >> 3) & 0x3F);

    ctx->count += (u64)len << 3;

    /* Fill buffer first */
    if (index) {
        rin_size_t space = 64 - index;
        if (len < space) {
            rintls_memcpy(ctx->buffer + index, data, len);
            return;
        }
        rintls_memcpy(ctx->buffer + index, data, space);
        sha256_transform(ctx, ctx->buffer);
        data += space;
        len -= space;
    }

    /* Process full blocks */
    while (len >= 64) {
        sha256_transform(ctx, data);
        data += 64;
        len -= 64;
    }

    /* Save remainder */
    if (len) {
        rintls_memcpy(ctx->buffer, data, len);
    }
}

void sha256_final(sha256_ctx* ctx, u8* digest) {
    u8 pad[64];
    u32 index = (u32)((ctx->count >> 3) & 0x3F);
    u32 padlen = (index < 56) ? (56 - index) : (120 - index);

    /* Save original bit count BEFORE padding */
    u64 bits = ctx->count;

    /* Padding */
    rintls_memset(pad, 0, 64);
    pad[0] = 0x80;
    sha256_update(ctx, pad, padlen);

    /* Append original length (saved before padding) */
    rintls_write_be64(pad, bits);
    sha256_update(ctx, pad, 8);

    /* Output hash */
    for (int i = 0; i < 8; i++) {
        rintls_write_be32(digest + i * 4, ctx->state[i]);
    }

    /* Clear sensitive data */
    rintls_memzero(ctx, sizeof(sha256_ctx));
}

void sha256(const u8* data, rin_size_t len, u8* digest) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SHA-384/512 Implementation
 * ═══════════════════════════════════════════════════════════════════════════ */

static const u64 K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

#define CH64(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ64(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0_64(x)      (RINTLS_ROTR64(x, 28) ^ RINTLS_ROTR64(x, 34) ^ RINTLS_ROTR64(x, 39))
#define EP1_64(x)      (RINTLS_ROTR64(x, 14) ^ RINTLS_ROTR64(x, 18) ^ RINTLS_ROTR64(x, 41))
#define SIG0_64(x)     (RINTLS_ROTR64(x, 1) ^ RINTLS_ROTR64(x, 8) ^ ((x) >> 7))
#define SIG1_64(x)     (RINTLS_ROTR64(x, 19) ^ RINTLS_ROTR64(x, 61) ^ ((x) >> 6))

static void sha512_transform(sha512_ctx* ctx, const u8* data) {
    u64 a, b, c, d, e, f, g, h, t1, t2, m[80];
    int i;

    for (i = 0; i < 16; i++) {
        m[i] = rintls_read_be64(data + i * 8);
    }
    for (i = 16; i < 80; i++) {
        m[i] = SIG1_64(m[i-2]) + m[i-7] + SIG0_64(m[i-15]) + m[i-16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 80; i++) {
        t1 = h + EP1_64(e) + CH64(e, f, g) + K512[i] + m[i];
        t2 = EP0_64(a) + MAJ64(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha512_init(sha512_ctx* ctx) {
    ctx->state[0] = 0x6a09e667f3bcc908ULL;
    ctx->state[1] = 0xbb67ae8584caa73bULL;
    ctx->state[2] = 0x3c6ef372fe94f82bULL;
    ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->state[4] = 0x510e527fade682d1ULL;
    ctx->state[5] = 0x9b05688c2b3e6c1fULL;
    ctx->state[6] = 0x1f83d9abfb41bd6bULL;
    ctx->state[7] = 0x5be0cd19137e2179ULL;
    ctx->count[0] = 0;
    ctx->count[1] = 0;
}

void sha384_init(sha384_ctx* ctx) {
    ctx->state[0] = 0xcbbb9d5dc1059ed8ULL;
    ctx->state[1] = 0x629a292a367cd507ULL;
    ctx->state[2] = 0x9159015a3070dd17ULL;
    ctx->state[3] = 0x152fecd8f70e5939ULL;
    ctx->state[4] = 0x67332667ffc00b31ULL;
    ctx->state[5] = 0x8eb44a8768581511ULL;
    ctx->state[6] = 0xdb0c2e0d64f98fa7ULL;
    ctx->state[7] = 0x47b5481dbefa4fa4ULL;
    ctx->count[0] = 0;
    ctx->count[1] = 0;
}

void sha512_update(sha512_ctx* ctx, const u8* data, rin_size_t len) {
    u32 index = (u32)(ctx->count[0] & 0x7F);

    /* Update bit count */
    ctx->count[0] += len;
    if (ctx->count[0] < len) ctx->count[1]++;

    if (index) {
        rin_size_t space = 128 - index;
        if (len < space) {
            rintls_memcpy(ctx->buffer + index, data, len);
            return;
        }
        rintls_memcpy(ctx->buffer + index, data, space);
        sha512_transform(ctx, ctx->buffer);
        data += space;
        len -= space;
    }

    while (len >= 128) {
        sha512_transform(ctx, data);
        data += 128;
        len -= 128;
    }

    if (len) {
        rintls_memcpy(ctx->buffer, data, len);
    }
}

void sha384_update(sha384_ctx* ctx, const u8* data, rin_size_t len) {
    sha512_update(ctx, data, len);
}

void sha512_final(sha512_ctx* ctx, u8* digest) {
    u8 pad[128];
    u32 index = (u32)(ctx->count[0] & 0x7F);
    u32 padlen = (index < 112) ? (112 - index) : (240 - index);

    /* Save original bit count BEFORE padding */
    u64 bits_lo = ctx->count[0] << 3;
    u64 bits_hi = (ctx->count[1] << 3) | (ctx->count[0] >> 61);

    rintls_memset(pad, 0, 128);
    pad[0] = 0x80;
    sha512_update(ctx, pad, padlen);

    /* Append original length (saved before padding) */
    rintls_write_be64(pad, bits_hi);
    rintls_write_be64(pad + 8, bits_lo);
    sha512_update(ctx, pad, 16);

    for (int i = 0; i < 8; i++) {
        rintls_write_be64(digest + i * 8, ctx->state[i]);
    }

    rintls_memzero(ctx, sizeof(sha512_ctx));
}

void sha384_final(sha384_ctx* ctx, u8* digest) {
    u8 full_digest[64];
    sha512_final(ctx, full_digest);
    rintls_memcpy(digest, full_digest, 48);
    rintls_memzero(full_digest, 64);
}

void sha512(const u8* data, rin_size_t len, u8* digest) {
    sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, data, len);
    sha512_final(&ctx, digest);
}

void sha384(const u8* data, rin_size_t len, u8* digest) {
    sha384_ctx ctx;
    sha384_init(&ctx);
    sha384_update(&ctx, data, len);
    sha384_final(&ctx, digest);
}
