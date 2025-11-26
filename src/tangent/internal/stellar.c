/*
 * Copyright (c) 2016-2018 . All Rights Reserved.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "stellar.h"
#include "base32.h"

bool stellar_getAddressBytes(char* str_address, uint8_t *out_bytes){
    uint8_t decoded[STELLAR_ADDRESS_SIZE_RAW];

    xbase32_decode(str_address, STELLAR_ADDRESS_SIZE, decoded, sizeof(decoded), XBASE32_ALPHABET_RFC4648);

    // The 32 bytes with offset 1-33 represent the public key
    memcpy(out_bytes, &decoded[1], 32);
    memset(decoded, 0, sizeof(decoded));

    return true;
}
