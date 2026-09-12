/* SPDX-License-Identifier: MIT */

#include "crypto/sha3.h"

#include <stdio.h>
#include <string.h>

typedef void (*sha3_init_func)(sha3_ctx*);

static int from_hex(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return value - 'A' + 10;
}

static int check_vector(sha3_init_func init, const char* message,
                        const char* expected, size_t digest_size)
{
    sha3_ctx context;
    sha3_ctx current;
    unsigned char digest[64];
    unsigned char current_digest[64];
    size_t message_size = strlen(message);
    size_t split = message_size / 2u;
    size_t i;

    init(&context);
    sha3_update(&context, (const u8*)message, split);
    sha3_update(&context, (const u8*)message + split, message_size - split);
    current = context;
    sha3_final(&current, current_digest);
    for (i = 0; i < digest_size; i++) {
        if (current_digest[i] != (unsigned char)((from_hex(expected[i * 2]) << 4) |
                                                 from_hex(expected[i * 2 + 1]))) {
            fprintf(stderr, "SHA-3 vector mismatch at byte %zu\n", i);
            return 0;
        }
    }

    /* Finalizing a copy must leave the original stream available. */
    memset(digest, 0, sizeof(digest));
    sha3_final(&context, digest);
    if (memcmp(digest, current_digest, digest_size) != 0) {
        return 0;
    }
    return 1;
}

int main(void)
{
    static const char* SHA3_256_EMPTY =
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    static const char* SHA3_384_EMPTY =
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004";
    static const char* SHA3_512_EMPTY =
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
    static const char* SHA3_256_ABC =
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
    static const char* SHA3_384_ABC =
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25";
    static const char* SHA3_512_ABC =
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0";

    if (!check_vector(sha3_256_init, "", SHA3_256_EMPTY, SHA3_256_DIGEST_SIZE) ||
        !check_vector(sha3_384_init, "", SHA3_384_EMPTY, SHA3_384_DIGEST_SIZE) ||
        !check_vector(sha3_512_init, "", SHA3_512_EMPTY, SHA3_512_DIGEST_SIZE) ||
        !check_vector(sha3_256_init, "abc", SHA3_256_ABC, SHA3_256_DIGEST_SIZE) ||
        !check_vector(sha3_384_init, "abc", SHA3_384_ABC, SHA3_384_DIGEST_SIZE) ||
        !check_vector(sha3_512_init, "abc", SHA3_512_ABC, SHA3_512_DIGEST_SIZE)) {
        return 1;
    }
    return 0;
}
