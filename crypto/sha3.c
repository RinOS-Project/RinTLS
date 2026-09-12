/*
 * rinTLS - SHA-3 hash functions
 * FIPS 202 Keccak-f[1600] implementation.
 */

#include "sha3.h"

static const u64 KECCAK_ROUND_CONSTANTS[24] = {
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
    UINT64_C(0x800000000000808A), UINT64_C(0x8000000080008000),
    UINT64_C(0x000000000000808B), UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
    UINT64_C(0x000000000000008A), UINT64_C(0x0000000000000088),
    UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000A),
    UINT64_C(0x000000008000808B), UINT64_C(0x800000000000008B),
    UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
    UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800A), UINT64_C(0x800000008000000A),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
    UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008),
};

/* r[x][y] from FIPS 202, indexed by the x/y coordinates of a lane. */
static const u32 KECCAK_ROTATION[5][5] = {
    { 0u, 36u,  3u, 41u, 18u },
    { 1u, 44u, 10u, 45u,  2u },
    {62u,  6u, 43u, 15u, 61u },
    {28u, 55u, 25u, 21u, 56u },
    {27u, 20u, 39u,  8u, 14u },
};

static u64 sha3_rotate_left(u64 value, u32 amount)
{
    if (amount == 0u) return value;
    return (value << amount) | (value >> (64u - amount));
}

static u64 sha3_load_le64(const u8* bytes)
{
    return ((u64)bytes[0]) |
           ((u64)bytes[1] << 8) |
           ((u64)bytes[2] << 16) |
           ((u64)bytes[3] << 24) |
           ((u64)bytes[4] << 32) |
           ((u64)bytes[5] << 40) |
           ((u64)bytes[6] << 48) |
           ((u64)bytes[7] << 56);
}

static void sha3_store_le64(u8* bytes, u64 value)
{
    bytes[0] = (u8)value;
    bytes[1] = (u8)(value >> 8);
    bytes[2] = (u8)(value >> 16);
    bytes[3] = (u8)(value >> 24);
    bytes[4] = (u8)(value >> 32);
    bytes[5] = (u8)(value >> 40);
    bytes[6] = (u8)(value >> 48);
    bytes[7] = (u8)(value >> 56);
}

static void sha3_permute(u64 state[25])
{
    u64 c[5];
    u64 d[5];
    u64 b[25];
    u32 round;
    u32 x;
    u32 y;

    for (round = 0; round < 24u; round++) {
        for (x = 0; x < 5u; x++) {
            c[x] = state[x] ^ state[x + 5u] ^ state[x + 10u] ^
                   state[x + 15u] ^ state[x + 20u];
        }
        for (x = 0; x < 5u; x++) {
            d[x] = c[(x + 4u) % 5u] ^ sha3_rotate_left(c[(x + 1u) % 5u], 1u);
        }
        for (x = 0; x < 5u; x++) {
            for (y = 0; y < 5u; y++) {
                state[x + 5u * y] ^= d[x];
            }
        }

        for (x = 0; x < 5u; x++) {
            for (y = 0; y < 5u; y++) {
                u32 destination_x = y;
                u32 destination_y = (2u * x + 3u * y) % 5u;
                b[destination_x + 5u * destination_y] =
                    sha3_rotate_left(state[x + 5u * y], KECCAK_ROTATION[x][y]);
            }
        }

        for (x = 0; x < 5u; x++) {
            for (y = 0; y < 5u; y++) {
                u64 current = b[x + 5u * y];
                u64 next = b[((x + 1u) % 5u) + 5u * y];
                u64 next_next = b[((x + 2u) % 5u) + 5u * y];
                state[x + 5u * y] = current ^ ((~next) & next_next);
            }
        }
        state[0] ^= KECCAK_ROUND_CONSTANTS[round];
    }
}

static void sha3_absorb_block(sha3_ctx* ctx)
{
    u32 offset;

    for (offset = 0; offset < ctx->rate; offset += 8u) {
        ctx->state[offset / 8u] ^= sha3_load_le64(ctx->buffer + offset);
    }
    sha3_permute(ctx->state);
    rintls_memset(ctx->buffer, 0, ctx->rate);
}

static void sha3_init(sha3_ctx* ctx, u32 rate, u32 digest_size)
{
    rintls_memset(ctx, 0, sizeof(*ctx));
    ctx->rate = rate;
    ctx->digest_size = digest_size;
}

void sha3_256_init(sha3_ctx* ctx)
{
    sha3_init(ctx, 136u, SHA3_256_DIGEST_SIZE);
}

void sha3_384_init(sha3_ctx* ctx)
{
    sha3_init(ctx, 104u, SHA3_384_DIGEST_SIZE);
}

void sha3_512_init(sha3_ctx* ctx)
{
    sha3_init(ctx, 72u, SHA3_512_DIGEST_SIZE);
}

void sha3_update(sha3_ctx* ctx, const u8* data, rin_size_t len)
{
    if (ctx == NULL || (data == NULL && len != 0)) return;

    while (len != 0) {
        rin_size_t available = (rin_size_t)(ctx->rate - ctx->position);
        rin_size_t take = len < available ? len : available;
        rintls_memcpy(ctx->buffer + ctx->position, data, take);
        ctx->position += (u32)take;
        data += take;
        len -= take;
        if (ctx->position == ctx->rate) {
            sha3_absorb_block(ctx);
            ctx->position = 0;
        }
    }
}

void sha3_final(sha3_ctx* ctx, u8* digest)
{
    u32 offset;
    u32 written = 0;

    if (ctx == NULL || digest == NULL || ctx->rate == 0u ||
        ctx->digest_size == 0u || ctx->position >= ctx->rate) return;

    ctx->buffer[ctx->position] = 0x06u;
    for (offset = ctx->position + 1u; offset < ctx->rate; offset++) {
        ctx->buffer[offset] = 0;
    }
    ctx->buffer[ctx->rate - 1u] |= 0x80u;
    sha3_absorb_block(ctx);

    while (written < ctx->digest_size) {
        u32 lane = written / 8u;
        u32 lane_offset = written % 8u;
        u32 take = ctx->digest_size - written;
        if (take > 8u - lane_offset) take = 8u - lane_offset;
        {
            u8 lane_bytes[8];
            sha3_store_le64(lane_bytes, ctx->state[lane]);
            rintls_memcpy(digest + written, lane_bytes + lane_offset, take);
            rintls_secure_zero(lane_bytes, sizeof(lane_bytes));
        }
        written += take;
    }
}

void sha3_256(const u8* data, rin_size_t len, u8* digest)
{
    sha3_ctx ctx;
    sha3_256_init(&ctx);
    sha3_update(&ctx, data, len);
    sha3_final(&ctx, digest);
    rintls_secure_zero(&ctx, sizeof(ctx));
}

void sha3_384(const u8* data, rin_size_t len, u8* digest)
{
    sha3_ctx ctx;
    sha3_384_init(&ctx);
    sha3_update(&ctx, data, len);
    sha3_final(&ctx, digest);
    rintls_secure_zero(&ctx, sizeof(ctx));
}

void sha3_512(const u8* data, rin_size_t len, u8* digest)
{
    sha3_ctx ctx;
    sha3_512_init(&ctx);
    sha3_update(&ctx, data, len);
    sha3_final(&ctx, digest);
    rintls_secure_zero(&ctx, sizeof(ctx));
}
