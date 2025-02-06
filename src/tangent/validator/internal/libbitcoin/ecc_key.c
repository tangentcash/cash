/*

 The MIT License (MIT)

 Copyright (c) 2015 Jonas Schnelli

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

#include "ecc_key.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base58.h"
#include "chainparams.h"
#include "ecc.h"
#include "hash.h"
#include "random.h"
#include "ripemd160.h"
#include "script.h"
#include "../../../internal/segwit_addr.h"
#include "utils.h"
#include "taproot.h"
#include "serialize.h"

void btc_privkey_init(btc_key* privkey)
{
    memset(&privkey->privkey, 0, BTC_ECKEY_PKEY_LENGTH);
}

btc_bool btc_privkey_is_valid(const btc_key* privkey)
{
    if (!privkey) {
        return false;
    }
    return btc_ecc_verify_privatekey(privkey->privkey);
}

void btc_privkey_cleanse(btc_key* privkey)
{
    btc_mem_zero(&privkey->privkey, BTC_ECKEY_PKEY_LENGTH);
}

btc_bool btc_privkey_gen(btc_key* privkey)
{
    if (privkey == NULL)
        return false;

    do {
        const btc_bool res = btc_random_bytes(privkey->privkey, BTC_ECKEY_PKEY_LENGTH, 0);
        if (!res)
            return false;
    } while (btc_ecc_verify_privatekey(privkey->privkey) == 0);
    return true;
}

btc_bool btc_privkey_verify_pubkey(btc_key* privkey, btc_pubkey* pubkey)
{
    uint256 rnddata, hash;
    const btc_bool res = btc_random_bytes(rnddata, BTC_HASH_LENGTH, 0);
    if (!res)
        return false;
    btc_hash(rnddata, BTC_HASH_LENGTH, hash);

    unsigned char sig[74];
    size_t siglen = 74;

    if (!btc_key_sign_hash(privkey, hash, sig, &siglen))
        return false;

    return btc_pubkey_verify_sig(pubkey, hash, sig, (int)siglen);
}

void btc_privkey_encode_wif(const btc_key* privkey, const btc_chainparams* chain, char *privkey_wif, size_t *strsize_inout) {
    uint8_t pkeybase58c[34];
    pkeybase58c[0] = chain->b58prefix_secret_address;
    pkeybase58c[33] = 1; /* always use compressed keys */

    memcpy(&pkeybase58c[1], privkey->privkey, BTC_ECKEY_PKEY_LENGTH);
    int status = btc_base58_encode_check(pkeybase58c, 34, privkey_wif, (int)*strsize_inout);
    assert(status != 0);
    btc_mem_zero(&pkeybase58c, 34);
}

btc_bool btc_privkey_decode_wif(const char *privkey_wif, const btc_chainparams* chain, btc_key* privkey) {

    if (!privkey_wif || strlen(privkey_wif) < 50) {
        return false;
    }

    const size_t privkey_len = strlen(privkey_wif);
    uint8_t *privkey_data = (uint8_t *)btc_malloc(privkey_len);
    memset(privkey_data, 0, privkey_len);
    size_t outlen = 0;

    outlen = btc_base58_decode_check(privkey_wif, privkey_data, privkey_len);
    if (!outlen) {
        btc_free(privkey_data);
        return false;
    }
    if (privkey_data[0] != chain->b58prefix_secret_address) {
        btc_free(privkey_data);
        return false;
    }
    memcpy(privkey->privkey, &privkey_data[1], BTC_ECKEY_PKEY_LENGTH);
    btc_mem_zero(privkey_data, sizeof(privkey_data));
    btc_free(privkey_data);
    return true;
}

void btc_privkey_get_taproot_privkey(const btc_key* privkey, const uint256 leaf_hash, uint256 hash256)
{
    btc_pubkey pubkey;
    btc_pubkey_init(&pubkey);
    btc_pubkey_from_key(privkey, &pubkey);

    cstring* control_block = cstr_new_sz(64);
    btc_controlblock_append_internalpubkey(control_block, &pubkey);
    if (leaf_hash)
        btc_controlblock_append_leafscripthash(control_block, leaf_hash);

    uint256 tweak_privkey;
    memcpy(tweak_privkey, privkey->privkey, sizeof(privkey->privkey));

    uint256 tweak_hash;
    btc_tagged_hash(BTC_TAG_TAP_TWEAK, control_block->str, control_block->len, tweak_hash);
    btc_ecc_private_key_tweak_add(tweak_privkey, tweak_hash);
    memcpy(hash256, tweak_privkey, sizeof(tweak_privkey));
    cstr_free(control_block, true);
}

void btc_pubkey_init(btc_pubkey* pubkey)
{
    if (pubkey == NULL)
        return;

    memset(pubkey->pubkey, 0, BTC_ECKEY_UNCOMPRESSED_LENGTH);
    pubkey->compressed = false;
}

unsigned int btc_pubkey_get_length(unsigned char ch_header)
{
    if (ch_header == 2 || ch_header == 3)
        return BTC_ECKEY_COMPRESSED_LENGTH;
    if (ch_header == 4 || ch_header == 6 || ch_header == 7)
        return BTC_ECKEY_UNCOMPRESSED_LENGTH;
    return 0;
}

btc_bool btc_pubkey_is_valid(const btc_pubkey* pubkey)
{
    return btc_ecc_verify_pubkey(pubkey->pubkey, pubkey->compressed);
}

void btc_pubkey_cleanse(btc_pubkey* pubkey)
{
    if (pubkey == NULL)
        return;

    btc_mem_zero(pubkey->pubkey, BTC_ECKEY_UNCOMPRESSED_LENGTH);
}

void btc_pubkey_get_hash160(const btc_pubkey* pubkey, uint160 hash160)
{
    uint256 hashout;
    btc_hash_sngl_sha256(pubkey->pubkey, pubkey->compressed ? BTC_ECKEY_COMPRESSED_LENGTH : BTC_ECKEY_UNCOMPRESSED_LENGTH, hashout);

    btc_ripemd160(hashout, sizeof(hashout), hash160);
}

void btc_pubkey_get_taproot_pubkey(const btc_pubkey* pubkey, const uint256 leaf_hash, uint256 hash256)
{
    cstring* control_block = cstr_new_sz(64);
    btc_controlblock_append_internalpubkey(control_block, pubkey);
    if (leaf_hash)
        btc_controlblock_append_leafscripthash(control_block, leaf_hash);

    uint256 tweak_hash;
    btc_tagged_hash(BTC_TAG_TAP_TWEAK, control_block->str, control_block->len, tweak_hash);
    btc_xonly_public_key_tweak_add(control_block->str, tweak_hash);
    memcpy(hash256, control_block->str, sizeof(tweak_hash));
    cstr_free(control_block, true);
}

btc_bool btc_pubkey_get_hex(const btc_pubkey* pubkey, char* str, size_t* strsize)
{
    if (*strsize < BTC_ECKEY_COMPRESSED_LENGTH * 2)
        return false;
    utils_bin_to_hex((unsigned char*)pubkey->pubkey, BTC_ECKEY_COMPRESSED_LENGTH, str);
    *strsize = BTC_ECKEY_COMPRESSED_LENGTH * 2;
    return true;
}

void btc_pubkey_from_key(const btc_key* privkey, btc_pubkey* pubkey_inout)
{
    if (pubkey_inout == NULL || privkey == NULL)
        return;

    size_t in_out_len = BTC_ECKEY_COMPRESSED_LENGTH;

    btc_ecc_get_pubkey(privkey->privkey, pubkey_inout->pubkey, &in_out_len, true);
    pubkey_inout->compressed = true;
}

btc_bool btc_key_sign_hash(const btc_key* privkey, const uint256 hash, unsigned char* sigout, size_t* outlen)
{
    return btc_ecc_sign(privkey->privkey, hash, sigout, outlen);
}

btc_bool btc_key_sign_hash_compact(const btc_key* privkey, const uint256 hash, unsigned char* sigout, size_t* outlen)
{
    return btc_ecc_sign_compact(privkey->privkey, hash, sigout, outlen);
}

btc_bool btc_key_sign_hash_compact_recoverable(const btc_key* privkey, const uint256 hash, unsigned char* sigout, size_t* outlen, int* recid)
{
    return btc_ecc_sign_compact_recoverable(privkey->privkey, hash, sigout, outlen, recid);
}

btc_bool btc_key_sign_recover_pubkey(const unsigned char* sig, const uint256 hash, int recid, btc_pubkey* pubkey)
{
    uint8_t pubkeybuf[128];
    size_t outlen = 128;
    if (!btc_ecc_recover_pubkey(sig, hash, recid, pubkeybuf, &outlen) || outlen > BTC_ECKEY_UNCOMPRESSED_LENGTH)
        return 0;

    memset(pubkey->pubkey, 0, sizeof(pubkey->pubkey));
    memcpy(pubkey->pubkey, pubkeybuf, outlen);
    if (outlen == BTC_ECKEY_COMPRESSED_LENGTH)
        pubkey->compressed = true;

    return 1;
}

btc_bool btc_pubkey_verify_sig(const btc_pubkey* pubkey, const uint256 hash, unsigned char* sigder, int len)
{
    return btc_ecc_verify_sig(pubkey->pubkey, pubkey->compressed, hash, sigder, len);
}

btc_bool btc_pubkey_getaddr_p2pk(const btc_pubkey* pubkey, const btc_chainparams* chain, char* addrout)
{
    utils_bin_to_hex((unsigned char*)pubkey->pubkey, pubkey->compressed ? BTC_ECKEY_COMPRESSED_LENGTH : BTC_ECKEY_UNCOMPRESSED_LENGTH, addrout);
    return true;
}

btc_bool btc_pubkey_getaddr_p2pkh(const btc_pubkey* pubkey, const btc_chainparams* chain, char *addrout)
{
    uint8_t hash[sizeof(uint160) + B58_PREFIX_MAX_SIZE]; size_t hash_offset;
    btc_pubkey_getaddr_p2pkh_hash(pubkey, chain, hash, &hash_offset);
    btc_base58_encode_check(hash, sizeof(uint160) + (int)hash_offset, addrout, 100);
    return true;
}

btc_bool btc_pubkey_getaddr_p2pkh_hash(const btc_pubkey* pubkey, const btc_chainparams* chain, uint8_t* hash, size_t* hash_offset)
{
    size_t offset = base58_prefix_dump(chain->b58prefix_pubkey_address, hash);
    btc_pubkey_get_hash160(pubkey, hash + offset);
    if (hash_offset)
        *hash_offset = offset;
    return true;
}

btc_bool btc_pubkey_getaddr_p2sh_p2wpkh(const btc_pubkey* pubkey, const btc_chainparams* chain, char* addrout)
{
    uint8_t hash[sizeof(uint160) + B58_PREFIX_MAX_SIZE]; size_t hash_offset;
    btc_pubkey_getaddr_p2sh_p2wpkh_hash(pubkey, chain, hash, &hash_offset);
    btc_base58_encode_check(hash, sizeof(uint160) + (int)hash_offset, addrout, 100);
    return true;
}

btc_bool btc_pubkey_getaddr_p2sh_p2wpkh_hash(const btc_pubkey* pubkey, const btc_chainparams* chain, uint8_t* hash, size_t* hash_offset)
{
    cstring* wscript = cstr_new_sz(22);
    uint160 keyhash;
    btc_pubkey_get_hash160(pubkey, keyhash);
    btc_script_build_p2wpkh(wscript, keyhash);

    size_t offset = base58_prefix_dump(chain->b58prefix_script_address, hash);
    btc_script_get_scripthash(wscript, hash + offset);
    cstr_free(wscript, true);
    if (hash_offset)
        *hash_offset = offset;

    return true;
}

btc_bool btc_pubkey_getaddr_p2wsh_p2pkh(const btc_pubkey* pubkey, const btc_chainparams* chain, char* addrout)
{
    uint8_t hash160[sizeof(uint8_t) * 32];
    btc_pubkey_getaddr_p2wsh_p2pkh_hash(pubkey, chain, hash160);
    segwit_addr_encode(addrout, chain->bech32_hrp, 0, hash160, sizeof(hash160));
    return true;
}

btc_bool btc_pubkey_getaddr_p2wsh_p2pkh_hash(const btc_pubkey* pubkey, const btc_chainparams* chain, uint8_t* hash)
{
    cstring* wscript = cstr_new_sz(22);
    uint160 keyhash;
    btc_pubkey_get_hash160(pubkey, keyhash);
    btc_script_build_p2pkh(wscript, keyhash); 
    btc_hash_sngl_sha256((const unsigned char*)wscript->str, wscript->len, hash);
    cstr_free(wscript, true);
    return true;
}

btc_bool btc_pubkey_getaddr_p2wpkh(const btc_pubkey* pubkey, const btc_chainparams* chain, char *addrout)
{
    uint8_t hash[sizeof(uint160)];
    btc_pubkey_getaddr_p2wpkh_hash(pubkey, chain, hash);
    segwit_addr_encode(addrout, chain->bech32_hrp, 0, hash, sizeof(hash));
    return true;
}

btc_bool btc_pubkey_getaddr_p2wpkh_hash(const btc_pubkey* pubkey, const btc_chainparams* chain, uint8_t* hash)
{
    btc_pubkey_get_hash160(pubkey, hash);
    return true;
}

btc_bool btc_pubkey_getaddr_p2tr(const btc_pubkey* pubkey, const btc_chainparams* chain, char* addrout)
{
    uint8_t hash[sizeof(uint8_t) * 32];
    btc_pubkey_getaddr_p2tr_hash(pubkey, chain, hash);
    segwit_addr_encode(addrout, chain->bech32_hrp, 1, hash, sizeof(hash));
    return true;
}

btc_bool btc_pubkey_getaddr_p2tr_hash(const btc_pubkey* pubkey, const btc_chainparams* chain, uint8_t* hash)
{
    btc_pubkey_get_taproot_pubkey(pubkey, NULL, hash);
    return true;
}

btc_bool btc_pubkey_getaddr_p2tr_p2pk(const btc_pubkey* pubkey, const btc_chainparams* chain, char* addrout)
{
    uint8_t hash[sizeof(uint8_t) * 32];
    btc_pubkey_getaddr_p2tr_p2pk_hash(pubkey, chain, hash);
    segwit_addr_encode(addrout, chain->bech32_hrp, 1, hash, sizeof(hash));
    return true;
}

btc_bool btc_pubkey_getaddr_p2tr_p2pk_hash(const btc_pubkey* pubkey, const btc_chainparams* chain, uint8_t* hash)
{
    if (!btc_pubkey_getaddr_p2tr_hash(pubkey, chain, hash))
        return false;

    uint256 leaf_hash;
    cstring* leaf_script = cstr_new_sz(64);
    btc_script_build_p2pk(leaf_script, hash, 32);
    btc_script_get_leafscripthash(leaf_script, leaf_hash);
    btc_pubkey_get_taproot_pubkey(pubkey, leaf_hash, hash);
    cstr_free(leaf_script, true);
    return true;
}