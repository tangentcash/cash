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

#ifndef __LIBBTC_TX_H__
#define __LIBBTC_TX_H__

#include "btc.h"
#include "chainparams.h"
#include "cstr.h"
#include "hash.h"
#include "script.h"
#include "vector.h"

LIBBTC_BEGIN_DECL

typedef struct btc_script_ {
    int* data;
    size_t limit;   // Total size of the dvector
    size_t current; //Number of vectors in it at present
} btc_script;

typedef struct btc_tx_outpoint_ {
    uint256 hash;
    uint32_t n;
} btc_tx_outpoint;

typedef struct btc_tx_in_ {
    btc_tx_outpoint prevout;
    cstring* script_sig;
    uint32_t sequence;
    dvector* witness_stack;
} btc_tx_in;

typedef struct btc_tx_out_ {
    int64_t value;
    cstring* script_pubkey;
} btc_tx_out;

typedef struct btc_tx_ {
    int32_t version;
    dvector* vin;
    dvector* vout;
    uint32_t locktime;
} btc_tx;

typedef struct btc_tx_witness_stack_ {
    cstring* const* scripts;
    cstring* const* stacks;
    cstring* const* redeems;
    uint64_t* amounts;
} btc_tx_witness_stack;


//!create a new tx input
LIBBTC_API btc_tx_in* btc_tx_in_new();
LIBBTC_API void btc_tx_in_free(btc_tx_in* tx_in);
LIBBTC_API void btc_tx_in_copy(btc_tx_in* dest, const btc_tx_in* src);

//!create a new tx output
LIBBTC_API btc_tx_out* btc_tx_out_new();
LIBBTC_API void btc_tx_out_free(btc_tx_out* tx_out);
LIBBTC_API void btc_tx_out_copy(btc_tx_out* dest, const btc_tx_out* src);

//!create a new tx input
LIBBTC_API btc_tx* btc_tx_new();
LIBBTC_API void btc_tx_free(btc_tx* tx);
LIBBTC_API void btc_tx_copy(btc_tx* dest, const btc_tx* src);

//!deserialize/parse a p2p serialized bitcoin transaction
LIBBTC_API int btc_tx_deserialize(const unsigned char* tx_serialized, size_t inlen, btc_tx* tx, size_t* consumed_length, btc_bool allow_witness);

//!serialize a lbc bitcoin data structure into a p2p serialized buffer
LIBBTC_API void btc_tx_serialize(cstring* s, const btc_tx* tx, btc_bool allow_witness);

LIBBTC_API void btc_tx_hash(const btc_tx* tx, uint8_t* hashout);

LIBBTC_API btc_bool btc_tx_sighash(const btc_tx* tx_to, const enum btc_sig_version sigversion, uint32_t hashtype, const btc_tx_witness_stack* vin_stack, uint32_t input_index, const uint256 leaf_hash, uint256 hash);

LIBBTC_API btc_bool btc_tx_add_address_out(btc_tx* tx, const btc_chainparams* chain, int64_t amount, const char* address);
LIBBTC_API btc_bool btc_tx_add_p2sh_hash160_out(btc_tx* tx, int64_t amount, uint160 hash160);
LIBBTC_API btc_bool btc_tx_add_p2pk_out(btc_tx* tx, int64_t amount, const uint8_t* pubkey, size_t pubkey_size);
LIBBTC_API btc_bool btc_tx_add_p2pkh_hash160_out(btc_tx* tx, int64_t amount, uint160 hash160);
LIBBTC_API btc_bool btc_tx_add_p2wpkh_hash160_out(btc_tx* tx, int64_t amount, const uint8_t* hash160);
LIBBTC_API btc_bool btc_tx_add_p2wsh_hash256_out(btc_tx* tx, int64_t amount, const uint8_t* hash256);
LIBBTC_API btc_bool btc_tx_add_p2tr_hash256_out(btc_tx* tx, int64_t amount, const uint8_t* hash256);

LIBBTC_API btc_bool btc_tx_add_data_out(btc_tx* tx, const int64_t amount, const uint8_t *data, const size_t datalen);
LIBBTC_API btc_bool btc_tx_add_puzzle_out(btc_tx* tx, const int64_t amount, const uint8_t *puzzle, const size_t puzzlelen);

LIBBTC_API btc_bool btc_tx_outpoint_is_null(btc_tx_outpoint* tx);
LIBBTC_API btc_bool btc_tx_is_coinbase(btc_tx* tx);

LIBBTC_API btc_bool btc_tx_has_witness(const btc_tx *tx);

enum btc_tx_sign_result {
    BTC_SIGN_UNKNOWN = 0,
    BTC_SIGN_INVALID_KEY = -2,
    BTC_SIGN_SIGHASH_FAILED = -4,
    BTC_SIGN_UNKNOWN_SCRIPT_TYPE = -5,
    BTC_SIGN_INVALID_TX_OR_SCRIPT = -6,
    BTC_SIGN_INPUTINDEX_OUT_OF_RANGE = -7,
    BTC_SIGN_OK = 1,
    BTC_SIGN_HASH_OK = 2,
    BTC_SIGN_FINALIZE_OK = 3
};
const char* btc_tx_sign_result_to_str(const enum btc_tx_sign_result result);
enum btc_tx_sign_result btc_tx_hash_input(btc_tx* tx_in_out, uint32_t sighashtype, enum btc_tx_out_type type, const btc_tx_witness_stack* vin_stack, uint32_t inputindex, uint256 sighash_out);
enum btc_tx_sign_result btc_tx_sign_input(uint256 sighash, const btc_key* privkey, uint32_t sighashtype, enum btc_tx_out_type type, uint8_t* sigdata_out, size_t* sigdata_size_out);
enum btc_tx_sign_result btc_tx_finalize_input(btc_tx* tx_in_out, const uint8_t* sigdata, size_t sigdata_size, const btc_pubkey* pubkey, uint32_t sighashtype, enum btc_tx_out_type type, const btc_tx_witness_stack* vin_stack, uint32_t inputindex);

LIBBTC_END_DECL

#endif // __LIBBTC_TX_H__
