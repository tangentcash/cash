/*
 * Copyright (c) 2016-2018 . All Rights Reserved.
 */

#include "base32.h"
#include <string.h>

const char *XBASE32_ALPHABET_RFC4648 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ23456789";

size_t xbase32_decoded_length(size_t inlen) {
    uint8_t remainder = inlen % 8;

    return (inlen / 8) * 5 + (remainder * 5) / 8;
}

void xbase32_8to5_raw(const uint8_t *in, uint8_t length, uint8_t *out) {
    if (length >= 2) {
        out[0]  = (in[0] << 3);
        out[0] |= (in[1] >> 2);
    }

    if (length >= 4) {
        out[1]  = (in[1] &  3) << 6;
        out[1] |= (in[2] << 1);
        out[1] |= (in[3] >> 4);
    }

    if (length >= 5) {
        out[2]  = (in[3] & 15) << 4;
        out[2] |= (in[4] >> 1);
    }

    if (length >= 7) {
        out[3]  = (in[4] &  1) << 7;
        out[3] |= (in[5] << 2);
        out[3] |= (in[6] >> 3);
    }

    if (length >= 8) {
        out[4]  = (in[6] &  7) << 5;
        out[4] |= (in[7] & 31);
    }
}

int xbase32_decode_character(char encoded, const char *alphabet) {
    if (alphabet == XBASE32_ALPHABET_RFC4648) {
        if (encoded >= 'A' && encoded <= 'Z') {
            return encoded - 'A';
        } else if (encoded >= 'a' && encoded <= 'z') {
            return encoded - 'a';
        } else if (encoded >= '2' && encoded <= '7') {
            return encoded - '2' + 26;
        } else {
            return -1;
        }
    }

    const char *occurrence = strchr(alphabet, encoded);

    if (occurrence) {
        return (int)(occurrence - alphabet);
    } else {
        return -1;
    }
}

bool xbase32_8to5(const uint8_t *in, uint8_t length, uint8_t *out, const char *alphabet) {
    if (length == 1 || length == 3 || length == 6 || length > 8) {
        return false;
    }

    if (alphabet) {
        uint8_t decoded[16];

        for (size_t i = 0; i < length; i++) {
            int ret = xbase32_decode_character(in[i], alphabet);

            if (ret == -1) {
                return false;
            } else {
                decoded[i] = ret;
            }
        }

        xbase32_8to5_raw(decoded, length, out);
    } else {
        xbase32_8to5_raw(in, length, out);
    }

    return true;
}


bool xbase32_decode_unsafe(const uint8_t *in, size_t inlen, uint8_t *out, const char *alphabet) {
    uint8_t remainder = inlen % 8;
    size_t limit = inlen - remainder;

    size_t i, j;
    for (i = 0, j = 0; i < limit; i += 8, j += 5) {
        if (!xbase32_8to5(&in[i], 8, &out[j], alphabet)) {
            return false;
        }
    }

    if (remainder && !xbase32_8to5(&in[i], remainder, &out[j], alphabet)) {
        return false;
    }

    return true;
}

uint8_t *xbase32_decode(const char *in, size_t inlen, uint8_t *out, size_t outlen, const char *alphabet) {
    size_t length = xbase32_decoded_length(inlen);
    if (outlen < length) {
        return NULL;
    }

    if (!xbase32_decode_unsafe((uint8_t *) in, inlen, (uint8_t *) out, alphabet)) {
        return NULL;
    }

    return &out[length];
}
