/*

 The MIT License (MIT)

 Copyright (c) 2021 libbtc

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

 */

#include "base58.h"
#include "chainparams.h"

#include "../trezor-crypto/base58.h"
#include "../trezor-crypto/segwit_addr.h"

static const HasherType BTC_HASHER = HASHER_SHA2D;

int btc_base58_decode(void* bin, size_t* binszp, const char* b58)
{
    return b58tobin(bin, binszp, b58);
}

int btc_b58check(const void* bin, size_t binsz, const char* base58str)
{
    return b58check(bin, binsz, BTC_HASHER, base58str);
}

int btc_base58_encode(char* b58, size_t* b58sz, const void* data, size_t binsz)
{
    return b58enc(b58, b58sz, data, binsz);
}

int btc_base58_encode_check(const uint8_t* data, int datalen, char* str, int strsize)
{
    return base58_encode_check(data, datalen, BTC_HASHER, str, strsize);
}

int btc_base58_decode_check(const char* str, uint8_t* data, size_t datalen)
{
    int res = base58_decode_check(str, BTC_HASHER, data, (int)datalen);
    if (res > 0) {
        res += 4;
    }
    return res;
}

btc_bool btc_p2pkh_addr_from_hash160(const uint160 hashin, const btc_chainparams* chain, char *addrout, int len) {
    uint8_t hash160[sizeof(uint160) + B58_PREFIX_MAX_SIZE];
    size_t offset = base58_prefix_dump(chain->b58prefix_pubkey_address, hash160);
    memcpy(hash160 + offset, hashin, sizeof(uint160));

    return (btc_base58_encode_check(hash160, sizeof(hash160) + (int)offset, addrout, len) > 0);
}

btc_bool btc_p2sh_addr_from_hash160(const uint160 hashin, const btc_chainparams* chain, char* addrout, int len) {
    uint8_t hash160[sizeof(uint160) + B58_PREFIX_MAX_SIZE];
    size_t offset = base58_prefix_dump(chain->b58prefix_script_address, hash160);
    memcpy(hash160 + offset, hashin, sizeof(uint160));

    return (btc_base58_encode_check(hash160, sizeof(uint160) + (int)offset, addrout, len) > 0);
}

btc_bool btc_p2wpkh_addr_from_hash160(const uint160 hashin, const btc_chainparams* chain, char *addrout) {
    return segwit_addr_encode(addrout, chain->bech32_hrp, 0, hashin, sizeof(uint160));
}


btc_bool base58_prefix_partition(uint16_t prefix16bits, uint8_t* prefix0bits, uint8_t* prefix8bits) {
    if (prefix0bits)
        *prefix0bits = (prefix16bits >> 8) & 0x00FF;
    if (prefix8bits)
        *prefix8bits = prefix16bits & 0x00FF;
    return true;
}

btc_bool base58_prefix_check(uint16_t prefix16bits, const uint8_t* hash160) {
    uint8_t prefix0bits, prefix8bits;
    base58_prefix_partition(prefix16bits, &prefix0bits, &prefix8bits);

    size_t prefix_size = base58_prefix_size(prefix16bits);
    if (prefix_size == 1)
        return hash160[0] == prefix0bits;

    if (prefix_size == 2)
        return hash160[0] == prefix0bits && hash160[1] == prefix8bits;

    return false;
}

size_t base58_prefix_dump(uint16_t prefix16bits, uint8_t* hash160) {
    uint8_t prefix0bits, prefix8bits;
    base58_prefix_partition(prefix16bits, &prefix0bits, &prefix8bits);

    hash160[0] = prefix0bits;
    if (!prefix8bits)
        return 1;

    hash160[1] = prefix8bits;
    return 2;
}

size_t base58_prefix_size(uint16_t prefix16bits) {
    uint8_t prefix8bits;
    base58_prefix_partition(prefix16bits, NULL, &prefix8bits);
    return prefix8bits > 0 ? 2 : 1;
}