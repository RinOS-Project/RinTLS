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
    ctx->domain = 0x06u;
}

void sha3_xof_init(sha3_ctx* ctx, u32 rate, u8 domain)
{
    rintls_memset(ctx, 0, sizeof(*ctx));
    ctx->rate = rate;
    ctx->domain = domain;
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

static int sha3_left_encode(u8 output[9], u64 value)
{
    int bytes = 1;
    u64 remaining = value;
    int index;

    while (remaining > UINT64_C(0xff)) {
        remaining >>= 8;
        bytes++;
    }

    output[0] = (u8)bytes;
    for (index = 0; index < bytes; index++) {
        output[1 + index] = (u8)(value >> (8 * (bytes - index - 1)));
    }
    return bytes + 1;
}

static int sha3_append_encoded_string(sha3_ctx* ctx, const u8* data,
                                      rin_size_t len, u64* total)
{
    u8 encoded_length[9];
    int encoded_length_size;
    u64 bit_length;

    if (len > (rin_size_t)(UINT64_MAX / UINT64_C(8))) return 0;
    bit_length = (u64)len * UINT64_C(8);
    encoded_length_size = sha3_left_encode(encoded_length, bit_length);
    sha3_update(ctx, encoded_length, (rin_size_t)encoded_length_size);
    sha3_update(ctx, data, len);
    *total += (u64)encoded_length_size + (u64)len;
    return 1;
}

static int sha3_append_bytepad(sha3_ctx* ctx, u32 rate, const u8* data,
                               rin_size_t len)
{
    u8 encoded_rate[9];
    u8 zeros[200];
    int encoded_rate_size;
    u64 total;
    u64 padding;

    if (len > (rin_size_t)(UINT64_MAX / UINT64_C(8))) return 0;
    encoded_rate_size = sha3_left_encode(encoded_rate, rate);
    total = (u64)encoded_rate_size;
    sha3_update(ctx, encoded_rate, (rin_size_t)encoded_rate_size);
    if (!sha3_append_encoded_string(ctx, data, len, &total)) return 0;

    padding = ((u64)rate - (total % (u64)rate)) % (u64)rate;
    rintls_memset(zeros, 0, sizeof(zeros));
    while (padding != 0) {
        rin_size_t chunk = (rin_size_t)padding;
        if (chunk > sizeof(zeros)) chunk = sizeof(zeros);
        sha3_update(ctx, zeros, chunk);
        padding -= (u64)chunk;
    }
    rintls_secure_zero(zeros, sizeof(zeros));
    return 1;
}

static int sha3_cshake_prefix(sha3_ctx* ctx, u32 rate,
                              const u8* customization,
                              rin_size_t customization_len)
{
    static const u8 function_name[] = { 'K', 'M', 'A', 'C' };
    u8 encoded_rate[9];
    u8 zeros[200];
    int encoded_rate_size;
    u64 total;
    u64 padding;

    if (customization_len > (rin_size_t)(UINT64_MAX / UINT64_C(8))) return 0;
    encoded_rate_size = sha3_left_encode(encoded_rate, rate);
    total = (u64)encoded_rate_size;
    sha3_update(ctx, encoded_rate, (rin_size_t)encoded_rate_size);
    if (!sha3_append_encoded_string(ctx, function_name,
                                    sizeof(function_name), &total) ||
        !sha3_append_encoded_string(ctx, customization,
                                    customization_len, &total)) return 0;

    padding = ((u64)rate - (total % (u64)rate)) % (u64)rate;
    rintls_memset(zeros, 0, sizeof(zeros));
    while (padding != 0) {
        rin_size_t chunk = (rin_size_t)padding;
        if (chunk > sizeof(zeros)) chunk = sizeof(zeros);
        sha3_update(ctx, zeros, chunk);
        padding -= (u64)chunk;
    }
    rintls_secure_zero(zeros, sizeof(zeros));
    return 1;
}

static int sha3_right_encode(u8 output[9], u64 value)
{
    int bytes = 1;
    int index;
    u64 remaining = value;

    while (remaining > UINT64_C(0xff)) {
        remaining >>= 8;
        bytes++;
    }

    for (index = 0; index < bytes; index++) {
        output[index] = (u8)(value >> (8 * (bytes - index - 1)));
    }
    output[bytes] = (u8)bytes;
    return bytes + 1;
}

static void sha3_xof_finalize_state(sha3_ctx* ctx)
{
    u32 offset;

    if (ctx->squeezing != 0u) return;
    if (ctx->position >= ctx->rate) return;

    ctx->buffer[ctx->position] = ctx->domain;
    for (offset = ctx->position + 1u; offset < ctx->rate; offset++) {
        ctx->buffer[offset] = 0;
    }
    ctx->buffer[ctx->rate - 1u] |= 0x80u;
    sha3_absorb_block(ctx);
    ctx->position = 0;
    ctx->squeezing = 1u;
}

int sha3_xof_squeeze(sha3_ctx* ctx, u8* output, rin_size_t output_len)
{
    if (ctx == NULL || ctx->rate == 0u ||
        (output == NULL && output_len != 0)) return 0;

    sha3_xof_finalize_state(ctx);
    while (output_len != 0) {
        rin_size_t available = (rin_size_t)(ctx->rate - ctx->position);
        rin_size_t take = output_len < available ? output_len : available;
        rin_size_t offset = ctx->position;
        while (take != 0) {
            u32 lane = (u32)(offset / 8u);
            u32 lane_offset = (u32)(offset % 8u);
            u32 lane_take = 8u - lane_offset;
            u8 lane_bytes[8];
            if ((rin_size_t)lane_take > take) lane_take = (u32)take;
            sha3_store_le64(lane_bytes, ctx->state[lane]);
            rintls_memcpy(output, lane_bytes + lane_offset, lane_take);
            rintls_secure_zero(lane_bytes, sizeof(lane_bytes));
            output += lane_take;
            offset += lane_take;
            take -= lane_take;
            output_len -= lane_take;
        }
        ctx->position += (u32)(offset - ctx->position);
        if (ctx->position == ctx->rate && output_len != 0) {
            sha3_permute(ctx->state);
            ctx->position = 0;
        }
    }
    return 1;
}

int sha3_kmac_init(sha3_ctx* ctx, u32 rate, const u8* key,
                   rin_size_t key_len, const u8* customization,
                   rin_size_t customization_len, int xof)
{
    if (ctx == NULL || (key == NULL && key_len != 0) ||
        (customization == NULL && customization_len != 0) ||
        (rate != 168u && rate != 136u)) return 0;

    sha3_xof_init(ctx, rate, 0x04u);
    if (!sha3_cshake_prefix(ctx, rate, customization, customization_len) ||
        !sha3_append_bytepad(ctx, rate, key, key_len)) return 0;
    (void)xof;
    ctx->squeezing = 0u;
    return 1;
}

int sha3_kmac_finalize(const sha3_ctx* ctx, u8* output, rin_size_t output_len,
                       int xof)
{
    sha3_ctx copy;
    u8 encoded_length[9];
    int encoded_length_size;
    u64 bit_length;
    int result;

    if (ctx == NULL || (output == NULL && output_len != 0) ||
        output_len > (rin_size_t)(UINT64_MAX / UINT64_C(8))) return 0;

    rintls_memcpy(&copy, ctx, sizeof(copy));
    bit_length = xof != 0 ? 0 : (u64)output_len * UINT64_C(8);
    encoded_length_size = sha3_right_encode(encoded_length, bit_length);
    sha3_update(&copy, encoded_length, (rin_size_t)encoded_length_size);
    result = sha3_xof_squeeze(&copy, output, output_len);
    rintls_secure_zero(&copy, sizeof(copy));
    rintls_secure_zero(encoded_length, sizeof(encoded_length));
    return result;
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
