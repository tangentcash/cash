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

#ifndef __LIBBTC_BTC_H__
#define __LIBBTC_BTC_H__
#include "chainparams.h"
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <secp256k1.h>
#include "sha2.h"
#if defined(_MSC_VER)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif
#define BTC_ECKEY_UNCOMPRESSED_LENGTH 65
#define BTC_ECKEY_COMPRESSED_LENGTH 33
#define BTC_ECKEY_PKEY_LENGTH 32
#define BTC_HASH_LENGTH 32
#define B58_PREFIX_MAX_SIZE 2
#define MAX_SCRIPT_SIZE 10000
#define BTC_MIN(a,b) (((a)<(b))?(a):(b))
#define BTC_MAX(a,b) (((a)>(b))?(a):(b))
#define TO_UINT8_HEX_BUF_LEN 2048
#define VARINT_LEN 20
#define strlens(s) (s == NULL ? 0 : strlen(s))
#define vector_idx(vec, idx) ((vec)->data[(idx)])

enum btc_tagged_prefixes
{
    BTC_TAG_BIP0340_CHALLENGE = 0,
    BTC_TAG_BIP0340_AUX = 1,
    BTC_TAG_BIP0340_NONCE = 2,
    BTC_TAG_TAP_LEAF = 3,
    BTC_TAG_TAP_BRANCH = 4,
    BTC_TAG_TAP_SIGHASH = 5,
    BTC_TAG_TAP_TWEAK = 6,
    BTC_TAG_KEYAGG_LIST = 7,
    BTC_TAG_KEYAGG_COEFFICIENT = 8
};

/** Sighash version types */
enum btc_sig_version
{
    SIGVERSION_BASE = 0,
    SIGVERSION_WITNESS_V0 = 1,
    SIGVERSION_WITNESS_V1_TAPROOT = 2,
    SIGVERSION_WITNESS_V1_TAPSCRIPT = 3,
};

/** Tapscript version types */
enum btc_tapscript_versions
{
    BTC_TAPSCRIPT_V0 = 0xc0
};

/** Signature hash types/flags */
enum
{
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_FORKID = 0x40,
    SIGHASH_ANYONECANPAY = 0x80,

    SIGHASH_DEFAULT = 0, //!< Taproot only; implied when sighash byte is missing, and equivalent to SIGHASH_ALL
    SIGHASH_OUTPUT_MASK = 3,
    SIGHASH_INPUT_MASK = 0x80,
};

/** Script opcodes */
enum opcodetype
{
    // push value
    OP_0 = 0x00,
    OP_FALSE = OP_0,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_RESERVED = 0x50,
    OP_1 = 0x51,
    OP_TRUE = OP_1,
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,

    // control
    OP_NOP = 0x61,
    OP_VER = 0x62,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,

    // stack ops
    OP_TOALTSTACK = 0x6b,
    OP_FROMALTSTACK = 0x6c,
    OP_2DROP = 0x6d,
    OP_2DUP = 0x6e,
    OP_3DUP = 0x6f,
    OP_2OVER = 0x70,
    OP_2ROT = 0x71,
    OP_2SWAP = 0x72,
    OP_IFDUP = 0x73,
    OP_DEPTH = 0x74,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_NIP = 0x77,
    OP_OVER = 0x78,
    OP_PICK = 0x79,
    OP_ROLL = 0x7a,
    OP_ROT = 0x7b,
    OP_SWAP = 0x7c,
    OP_TUCK = 0x7d,

    // splice ops
    OP_CAT = 0x7e,
    OP_SUBSTR = 0x7f,
    OP_LEFT = 0x80,
    OP_RIGHT = 0x81,
    OP_SIZE = 0x82,

    // bit logic
    OP_INVERT = 0x83,
    OP_AND = 0x84,
    OP_OR = 0x85,
    OP_XOR = 0x86,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8a,

    // numeric
    OP_1ADD = 0x8b,
    OP_1SUB = 0x8c,
    OP_2MUL = 0x8d,
    OP_2DIV = 0x8e,
    OP_NEGATE = 0x8f,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,

    OP_ADD = 0x93,
    OP_SUB = 0x94,
    OP_MUL = 0x95,
    OP_DIV = 0x96,
    OP_MOD = 0x97,
    OP_LSHIFT = 0x98,
    OP_RSHIFT = 0x99,

    OP_BOOLAND = 0x9a,
    OP_BOOLOR = 0x9b,
    OP_NUMEQUAL = 0x9c,
    OP_NUMEQUALVERIFY = 0x9d,
    OP_NUMNOTEQUAL = 0x9e,
    OP_LESSTHAN = 0x9f,
    OP_GREATERTHAN = 0xa0,
    OP_LESSTHANOREQUAL = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN = 0xa3,
    OP_MAX = 0xa4,

    OP_WITHIN = 0xa5,

    // crypto
    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_CODESEPARATOR = 0xab,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,

    // expansion
    OP_NOP1 = 0xb0,
    OP_NOP2 = 0xb1,
    OP_CHECKLOCKTIMEVERIFY = OP_NOP2,
    OP_NOP3 = 0xb2,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,


    // template matching params
    OP_SMALLINTEGER = 0xfa,
    OP_PUBKEYS = 0xfb,
    OP_PUBKEYHASH = 0xfd,
    OP_PUBKEY = 0xfe,

    OP_INVALIDOPCODE = 0xff,
};

enum btc_tx_out_type
{
    BTC_TX_INVALID = -1,
    BTC_TX_NONSTANDARD,
    // 'standard' transaction types:
    BTC_TX_PUBKEY,
    BTC_TX_PUBKEYHASH,
    BTC_TX_SCRIPTHASH,
    BTC_TX_MULTISIG,
    BTC_TX_WITNESS_V0_PUBKEYHASH,
    BTC_TX_WITNESS_V0_SCRIPTHASH,
    BTC_TX_WITNESS_V1_TAPROOT_KEYPATH,
    BTC_TX_WITNESS_V1_TAPROOT_SCRIPTPATH,
};

enum btc_tx_sign_result
{
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

typedef struct btc_script_op_
{
    enum opcodetype op;  /* opcode found */
    unsigned char* data; /* associated data, if any */
    size_t datalen;
} btc_script_op;

typedef uint8_t btc_bool; //!serialize, c/c++ save bool
typedef uint8_t uint256[32];
typedef uint8_t uint160[20];

typedef struct cstring
{
    char* str;    /* string data, incl. NUL */
    size_t len;   /* length of string, not including NUL */
    size_t alloc; /* total allocated buffer length */
} cstring;

typedef struct dvector
{
    void** data;  /* array of pointers */
    size_t len;   /* array element count */
    size_t alloc; /* allocated array elements */

    void (*elem_free_f)(void*);
} dvector;

struct buffer
{
    void* p;
    size_t len;
};

struct const_buffer
{
    const void* p;
    size_t len;
};

typedef struct btc_key_
{
    uint8_t privkey[BTC_ECKEY_PKEY_LENGTH];
} btc_key;

typedef struct btc_pubkey_
{
    btc_bool compressed;
    uint8_t pubkey[BTC_ECKEY_UNCOMPRESSED_LENGTH];
} btc_pubkey;

typedef struct btc_mem_mapper_
{
    void* (*btc_malloc)(size_t size);
    void* (*btc_calloc)(size_t count, size_t size);
    void* (*btc_realloc)(void* ptr, size_t size);
    void (*btc_free)(void* ptr);
} btc_mem_mapper;

struct btc_btree_node
{
    void* key;
    struct btc_btree_node* left;
    struct btc_btree_node* right;
};

typedef struct btc_script_
{
    int* data;
    size_t limit;   // Total size of the dvector
    size_t current; //Number of vectors in it at present
} btc_script;

typedef struct btc_tx_outpoint_
{
    uint256 hash;
    uint32_t n;
} btc_tx_outpoint;

typedef struct btc_tx_in_
{
    btc_tx_outpoint prevout;
    cstring* script_sig;
    uint32_t sequence;
    dvector* witness_stack;
} btc_tx_in;

typedef struct btc_tx_out_
{
    int64_t value;
    cstring* script_pubkey;
} btc_tx_out;

typedef struct btc_tx_
{
    int32_t version;
    dvector* vin;
    dvector* vout;
    uint32_t locktime;
} btc_tx;

typedef struct btc_tx_witness_stack_
{
    cstring* const* scripts;
    cstring* const* stacks;
    cstring* const* redeems;
    uint64_t* amounts;
} btc_tx_witness_stack;

extern const char b58digits_ordered[];
extern const int8_t b58digits_map[];

void btc_mem_set_mapper(const btc_mem_mapper mapper);
void btc_mem_set_mapper_default();
void* btc_malloc(size_t size);
void* btc_calloc(size_t count, size_t size);
void* btc_realloc(void* ptr, size_t size);
void btc_free(void* ptr);
void* btc_mem_zero(void* dst, size_t len);

cstring* cstr_new(const char* init_str);
cstring* cstr_new_sz(size_t sz);
cstring* cstr_new_buf(const void* buf, size_t sz);
cstring* cstr_new_cstr(const cstring* copy_str);
void cstr_free(cstring* s, int free_buf);
int cstr_equal(const cstring* a, const cstring* b);
int cstr_compare(const cstring* a, const cstring* b);
int cstr_resize(cstring* s, size_t sz);
int cstr_erase(cstring* s, size_t pos, ssize_t len);
int cstr_append_buf(cstring* s, const void* buf, size_t sz);
int cstr_append_cstr(cstring* s, cstring* append);
int cstr_append_c(cstring* s, char ch);
int cstr_alloc_minsize(cstring* s, size_t sz);

dvector* vector_new(size_t res, void (*free_f)(void*));
void vector_free(dvector* vec, btc_bool free_array);
btc_bool vector_add(dvector* vec, void* data);
btc_bool vector_remove(dvector* vec, void* data);
void vector_remove_idx(dvector* vec, size_t idx);
void vector_remove_range(dvector* vec, size_t idx, size_t len);
btc_bool vector_resize(dvector* vec, size_t newsz);
ssize_t vector_find(dvector* vec, void* data);

int buffer_equal(const void* a, const void* b);
void buffer_free(void* struct_buffer);
struct buffer* buffer_copy(const void* data, size_t data_len);

int btc_base58_encode_check(const uint8_t* data, int len, char* str, int strsize);
int btc_base58_decode_check(const char* str, uint8_t* data, size_t datalen);
int btc_base58_encode(char* b58, size_t* b58sz, const void* data, size_t binsz);
int btc_base58_decode(void* bin, size_t* binszp, const char* b58);

bool b58enc(char* b58, size_t* b58sz, const void* data, size_t binsz);
bool b58dec(void* bin, size_t* binszp, const char* b58, size_t b58size);

btc_bool btc_p2pkh_addr_from_hash160(const uint160 hashin, const sc_chainparams* chain, char* addrout, int len);
btc_bool btc_p2sh_addr_from_hash160(const uint160 hashin, const sc_chainparams* chain, char* addrout, int len);
btc_bool btc_p2wpkh_addr_from_hash160(const uint160 hashin, const sc_chainparams* chain, char* addrout);

btc_bool base58_prefix_partition(uint16_t prefix16bits, uint8_t* prefix0bits, uint8_t* prefix8bits);
btc_bool base58_prefix_check(uint16_t prefix16bits, const uint8_t* hash160);
size_t base58_prefix_dump(uint16_t prefix16bits, uint8_t* hash160);
size_t base58_prefix_size(uint16_t prefix16bits);

void utils_clear_buffers(void);
void utils_hex_to_bin(const char* str, unsigned char* out, int inLen, int* outLen);
void utils_bin_to_hex(unsigned char* bin_in, size_t inlen, char* hex_out);
uint8_t* utils_hex_to_uint8(const char* str);
char* utils_uint8_to_hex(const uint8_t* bin, size_t l);
void utils_reverse_hex(char* h, int len);
void utils_uint256_sethex(char* psz, uint8_t* out);
void* safe_malloc(size_t size);
void btc_cheap_random_bytes(uint8_t* buf, uint32_t len);
void btc_get_default_datadir(cstring* path_out);
void btc_file_commit(FILE* file);

static inline void btc_btree_tdestroy(void* root, void (*freekey)(void*))
{
    struct btc_btree_node* r = (struct btc_btree_node*)root;

    if (r == 0)
        return;
    btc_btree_tdestroy(r->left, freekey);
    btc_btree_tdestroy(r->right, freekey);

    if (freekey) freekey(r->key);
    btc_free(r);
}
static inline btc_bool btc_hash_is_empty(uint256 hash)
{
    return hash[0] == 0 && !memcmp(hash, hash + 1, 19);
}
static inline void btc_hash_clear(uint256 hash)
{
    memset(hash, 0, BTC_HASH_LENGTH);
}
static inline btc_bool btc_hash_equal(uint256 hash_a, uint256 hash_b)
{
    return (memcmp(hash_a, hash_b, BTC_HASH_LENGTH) == 0);
}
static inline void btc_hash_set(uint256 hash_dest, const uint256 hash_src)
{
    memcpy(hash_dest, hash_src, BTC_HASH_LENGTH);
}
//bitcoin double sha256 hash
static inline void btc_hash(const unsigned char* datain, size_t length, uint256 hashout)
{
    sha256_Raw(datain, length, hashout);
    sha256_Raw(hashout, 32, hashout);
}
void btc_tagged_hash(enum btc_tagged_prefixes prefix, const uint8_t* message, size_t message_size, uint256 hash);
//single sha256 hash
static inline void btc_hash_sngl_sha256(const unsigned char* datain, size_t length, uint256 hashout)
{
    sha256_Raw(datain, length, hashout);
}

void btc_ecc_set_context(secp256k1_context* new_secp256k1_ctx);
//!get public key from given private key
void btc_ecc_get_pubkey(const uint8_t* private_key, uint8_t* public_key, size_t* public_key_len, btc_bool compressed);
//!ec mul tweak on given private key
btc_bool btc_ecc_private_key_tweak_add(uint8_t* private_key, const uint8_t* tweak);
//!ec mul tweak on given public key
btc_bool btc_ecc_public_key_tweak_add(uint8_t* public_key_inout, const uint8_t* tweak);
//!ec mul tweak on given x public key
btc_bool btc_xonly_public_key_tweak_add(uint8_t* public_key_inout, const uint8_t* tweak);
//!verifies a given 32byte key
btc_bool btc_ecc_verify_privatekey(const uint8_t* private_key);
//!verifies a given public key (compressed[33] or uncompressed[65] bytes)
btc_bool btc_ecc_verify_pubkey(const uint8_t* public_key, btc_bool compressed);
//!create a DER signature (72-74 bytes) with private key
btc_bool btc_ecc_sign(const uint8_t* private_key, const uint256 hash, unsigned char* sigder, size_t* outlen);
//!create a compact (64bytes) signature with private key
btc_bool btc_ecc_sign_compact(const uint8_t* private_key, const uint256 hash, unsigned char* sigcomp, size_t* outlen);
//!create a compact recoverable (65bytes) signature with private key
btc_bool btc_ecc_sign_compact_recoverable(const uint8_t* private_key, const uint256 hash, unsigned char* sigcomprec, size_t* outlen, int* recid);
//!recover a pubkey from a signature and recid
btc_bool btc_ecc_recover_pubkey(const unsigned char* sigrec, const uint256 hash, const int recid, uint8_t* public_key, size_t* outlen);
//!converts (and normalized) a compact signature to DER
btc_bool btc_ecc_compact_to_der_normalized(const unsigned char* sigcomp_in, unsigned char* sigder_out, size_t* sigder_len_out);
//!convert DER signature to compact
btc_bool btc_ecc_der_to_compact(unsigned char* sigder_in, size_t sigder_len, unsigned char* sigcomp_out);
//!verify DER signature with public key
btc_bool btc_ecc_verify_sig(const uint8_t* public_key, btc_bool compressed, const uint256 hash, unsigned char* sigder, size_t siglen);
//!create a compact (64bytes) signature with private key
btc_bool btc_ecc_sign_schnorr(const uint8_t* private_key, const uint256 hash, const uint256 auxiliary, unsigned char* sigcomp, size_t* outlen);
//!create a tagged sha256 hash of message
btc_bool btc_ecc_tagged_sha256(const uint8_t* message, size_t message_size, const uint8_t* tag, size_t tag_size, uint256 hash_out);

void btc_privkey_init(btc_key* privkey);
btc_bool btc_privkey_is_valid(const btc_key* privkey);
void btc_privkey_cleanse(btc_key* privkey);
btc_bool btc_privkey_gen(btc_key* privkey);
btc_bool btc_privkey_verify_pubkey(btc_key* privkey, btc_pubkey* pubkey);
//get the tweaked taproot privkey
void btc_privkey_get_taproot_privkey(const btc_key* privkey, const uint256 leaf_hash, uint256 hash256);
// form a WIF encoded string from the given pubkey, make sure privkey_wif is large enough and strsize_inout contains the size of the buffer
void btc_privkey_encode_wif(const btc_key* privkey, const sc_chainparams* chain, char* privkey_wif, size_t* strsize_inout);
btc_bool btc_privkey_decode_wif(const char* privkey_wif, const sc_chainparams* chain, btc_key* privkey);
void btc_pubkey_init(btc_pubkey* pubkey);
// Compute the length of a pubkey with a given first byte.
unsigned int btc_pubkey_get_length(unsigned char ch_header);
btc_bool btc_pubkey_is_valid(const btc_pubkey* pubkey);
void btc_pubkey_cleanse(btc_pubkey* pubkey);
void btc_pubkey_from_key(const btc_key* privkey, btc_pubkey* pubkey_inout);
//get the hash160 (single SHA256 + RIPEMD160)
void btc_pubkey_get_hash160(const btc_pubkey* pubkey, uint160 hash160);
//get the tweaked taproot pubkey
void btc_pubkey_get_taproot_pubkey(const btc_pubkey* pubkey, const uint256 leaf_hash, uint256 hash256);
//get the hex representation of a pubkey, strsize must be at leat 66 bytes
btc_bool btc_pubkey_get_hex(const btc_pubkey* pubkey, char* str, size_t* strsize);
//sign a 32byte message/hash and returns a DER encoded signature (through *sigout)
btc_bool btc_key_sign_hash(const btc_key* privkey, const uint256 hash, unsigned char* sigout, size_t* outlen);
void btc_key_get_taproot_tweak(const btc_pubkey* pubkey, const uint256 leaf_hash, uint256 hash256);
//sign a 32byte message/hash and returns a 64 byte compact signature (through *sigout)
btc_bool btc_key_sign_hash_compact(const btc_key* privkey, const uint256 hash, unsigned char* sigout, size_t* outlen);
//sign a 32byte message/hash and returns a 64 byte compact signature (through *sigout) plus a 1byte recovery id
btc_bool btc_key_sign_hash_compact_recoverable(const btc_key* privkey, const uint256 hash, unsigned char* sigout, size_t* outlen, int* recid);
btc_bool btc_key_sign_recover_pubkey(const unsigned char* sig, const uint256 hash, int recid, btc_pubkey* pubkey);

//verifies a DER encoded signature with given pubkey and return true if valid
btc_bool btc_pubkey_verify_sig(const btc_pubkey* pubkey, const uint256 hash, unsigned char* sigder, int len);
btc_bool btc_pubkey_getaddr_p2pk(const btc_pubkey* pubkey, const sc_chainparams* chain, char* addrout);
btc_bool btc_pubkey_getaddr_p2pkh(const btc_pubkey* pubkey, const sc_chainparams* chain, char* addrout);
btc_bool btc_pubkey_getaddr_p2pkh_hash(const btc_pubkey* pubkey, const sc_chainparams* chain, uint8_t* hash, size_t* hash_offset);
btc_bool btc_pubkey_getaddr_p2sh_p2wpkh(const btc_pubkey* pubkey, const sc_chainparams* chain, char* addrout);
btc_bool btc_pubkey_getaddr_p2sh_p2wpkh_hash(const btc_pubkey* pubkey, const sc_chainparams* chain, uint8_t* hash, size_t* hash_offset);
btc_bool btc_pubkey_getaddr_p2wsh_p2pkh(const btc_pubkey* pubkey, const sc_chainparams* chain, char* addrout);
btc_bool btc_pubkey_getaddr_p2wsh_p2pkh_hash(const btc_pubkey* pubkey, const sc_chainparams* chain, uint8_t* hash);
btc_bool btc_pubkey_getaddr_p2wpkh(const btc_pubkey* pubkey, const sc_chainparams* chain, char* addrout);
btc_bool btc_pubkey_getaddr_p2wpkh_hash(const btc_pubkey* pubkey, const sc_chainparams* chain, uint8_t* hash);
btc_bool btc_pubkey_getaddr_p2tr(const btc_pubkey* pubkey, const sc_chainparams* chain, char* addrout);
btc_bool btc_pubkey_getaddr_p2tr_hash(const btc_pubkey* pubkey, const sc_chainparams* chain, uint8_t* hash);
btc_bool btc_pubkey_getaddr_p2tr_p2pk(const btc_pubkey* pubkey, const sc_chainparams* chain, char* addrout);
btc_bool btc_pubkey_getaddr_p2tr_p2pk_hash(const btc_pubkey* pubkey, const sc_chainparams* chain, uint8_t* hash);

//copy a script without the codeseperator ops
btc_bool btc_script_copy_without_op_codeseperator(const cstring* scriptin, cstring* scriptout);
btc_script_op* btc_script_op_new();
void btc_script_op_free(btc_script_op* script_op);
void btc_script_op_free_cb(void* data);
btc_bool btc_script_get_ops(const cstring* script_in, dvector* ops_out);
enum btc_tx_out_type btc_script_classify_ops(const dvector* ops);
enum btc_tx_out_type btc_script_classify(const cstring* script, dvector* data_out);
enum opcodetype btc_encode_op_n(const int n);
void btc_script_append_op(cstring* script_in, enum opcodetype op);
void btc_script_append_pushdata(cstring* script_in, const unsigned char* data, const size_t datalen);
btc_bool btc_script_build_multisig(cstring* script_in, const unsigned int required_signatures, const dvector* pubkeys_chars);
btc_bool btc_script_build_p2pk(cstring* script, const uint8_t* pubkey, size_t pubkey_size);
btc_bool btc_script_build_p2pkh(cstring* script, const uint160 hash160);
btc_bool btc_script_build_p2wpkh(cstring* script, const uint160 hash160);
btc_bool btc_script_build_p2sh(cstring* script_in, const uint160 hash160);
btc_bool btc_script_build_p2wsh(cstring* script_in, const uint256 hash256);
btc_bool btc_script_build_p2tr(cstring* script_in, const uint256 hash256);
btc_bool btc_script_get_scripthash(const cstring* script_in, uint160 scripthash);
btc_bool btc_script_get_leafscripthash(const cstring* script_in, uint256 leafhash);
btc_bool btc_script_is_witnessprogram(const cstring* script, uint8_t* version_out, uint8_t* program_out, int* programm_len_out);

btc_bool btc_controlblock_append_version(cstring* controlblock_in, enum btc_tapscript_versions version);
btc_bool btc_controlblock_append_internalpubkey(cstring* controlblock_in, const btc_pubkey* pubkey);
btc_bool btc_controlblock_append_leafscripthash(cstring* controlblock_in, const uint256 hash);
btc_bool btc_controlblock_append_leafscript(cstring* controlblock_in, const cstring* script);

//!create a new tx input
const char* btc_tx_out_type_to_str(const enum btc_tx_out_type type);
btc_tx_in* btc_tx_in_new();
void btc_tx_in_free(btc_tx_in* tx_in);
void btc_tx_in_copy(btc_tx_in* dest, const btc_tx_in* src);
//!create a new tx output
btc_tx_out* btc_tx_out_new();
void btc_tx_out_free(btc_tx_out* tx_out);
void btc_tx_out_copy(btc_tx_out* dest, const btc_tx_out* src);
//!create a new tx input
btc_tx* btc_tx_new();
void btc_tx_free(btc_tx* tx);
void btc_tx_copy(btc_tx* dest, const btc_tx* src);
//!deserialize/parse a p2p serialized bitcoin transaction
int btc_tx_deserialize(const unsigned char* tx_serialized, size_t inlen, btc_tx* tx, size_t* consumed_length, btc_bool allow_witness);
//!serialize a lbc bitcoin data structure into a p2p serialized buffer
void btc_tx_serialize(cstring* s, const btc_tx* tx, btc_bool allow_witness);
void btc_tx_hash(const btc_tx* tx, uint256 hashout);
btc_bool btc_tx_sighash(const btc_tx* tx_to, const enum btc_sig_version sigversion, uint32_t hashtype, const btc_tx_witness_stack* vin_stack, uint32_t input_index, const uint256 leaf_hash, uint256 hash);
btc_bool btc_tx_add_address_out(btc_tx* tx, const sc_chainparams* chain, int64_t amount, const char* address);
btc_bool btc_tx_add_p2sh_hash160_out(btc_tx* tx, int64_t amount, uint160 hash160);
btc_bool btc_tx_add_p2pk_out(btc_tx* tx, int64_t amount, const uint8_t* pubkey, size_t pubkey_size);
btc_bool btc_tx_add_p2pkh_hash160_out(btc_tx* tx, int64_t amount, uint160 hash160);
btc_bool btc_tx_add_p2wpkh_hash160_out(btc_tx* tx, int64_t amount, const uint8_t* hash160);
btc_bool btc_tx_add_p2wsh_hash256_out(btc_tx* tx, int64_t amount, const uint8_t* hash256);
btc_bool btc_tx_add_p2tr_hash256_out(btc_tx* tx, int64_t amount, const uint8_t* hash256);
btc_bool btc_tx_add_data_out(btc_tx* tx, const int64_t amount, const uint8_t* data, const size_t datalen);
btc_bool btc_tx_add_puzzle_out(btc_tx* tx, const int64_t amount, const uint8_t* puzzle, const size_t puzzlelen);
btc_bool btc_tx_outpoint_is_null(btc_tx_outpoint* tx);
btc_bool btc_tx_is_coinbase(btc_tx* tx);
btc_bool btc_tx_has_witness(const btc_tx* tx);
const char* btc_tx_sign_result_to_str(const enum btc_tx_sign_result result);
enum btc_tx_sign_result btc_tx_hash_input(btc_tx* tx_in_out, uint32_t sighashtype, enum btc_tx_out_type type, const btc_tx_witness_stack* vin_stack, uint32_t inputindex, uint256 sighash_out);
enum btc_tx_sign_result btc_tx_sign_input(uint256 sighash, const btc_key* privkey, uint32_t sighashtype, enum btc_tx_out_type type, uint8_t* sigdata_out, size_t* sigdata_size_out);
enum btc_tx_sign_result btc_tx_finalize_input(btc_tx* tx_in_out, const uint8_t* sigdata, size_t sigdata_size, const btc_pubkey* pubkey, uint32_t sighashtype, enum btc_tx_out_type type, const btc_tx_witness_stack* vin_stack, uint32_t inputindex);

void ser_bytes(cstring* s, const void* p, size_t len);
void ser_u16(cstring* s, uint16_t v_);
void ser_u32(cstring* s, uint32_t v_);
void ser_u64(cstring* s, uint64_t v_);
void ser_u256(cstring* s, const unsigned char* v_);
void ser_varlen(cstring* s, uint32_t vlen);
void ser_str(cstring* s, const char* s_in, size_t maxlen);
void ser_varstr(cstring* s, cstring* s_in);
void ser_s32(cstring* s, int32_t v_);
void ser_s64(cstring* s, int64_t v_);
int deser_skip(struct const_buffer* buf, size_t len);
int deser_bytes(void* po, struct const_buffer* buf, size_t len);
int deser_u16(uint16_t* vo, struct const_buffer* buf);
int deser_u32(uint32_t* vo, struct const_buffer* buf);
int deser_s32(int32_t* vo, struct const_buffer* buf);
int deser_u64(uint64_t* vo, struct const_buffer* buf);
int deser_u256(uint256 vo, struct const_buffer* buf);
int deser_varlen(uint32_t* lo, struct const_buffer* buf);
int deser_varlen_from_file(uint32_t* lo, FILE* file);
int deser_varlen_file(uint32_t* lo, FILE* file, uint8_t* rawdata, size_t* buflen_inout);
int deser_str(char* so, struct const_buffer* buf, size_t maxlen);
int deser_varstr(cstring** so, struct const_buffer* buf);
int deser_s64(int64_t* vo, struct const_buffer* buf);
#endif