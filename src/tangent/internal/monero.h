// Copyright (c) 2014-2018, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#ifndef __MONERO_H__
#define __MONERO_H__
#include <stdbool.h>
#include "ed25519/ed25519-donna.h"
#define XMR_ATOMS 64

typedef uint64_t xmr_amount;
typedef unsigned char xmr_key_t[32];
typedef xmr_key_t xmr_key64_t[64];

typedef struct xmr_boro_sig
{
    xmr_key64_t s0;
    xmr_key64_t s1;
    xmr_key_t ee;
} xmr_boro_sig_t;

typedef struct range_sig
{
    xmr_boro_sig_t asig;
    xmr_key64_t Ci;
} xmr_range_sig_t;

/* From fe2.h */

typedef int32_t fe2[10];

/* From ge.h */

typedef struct
{
    fe2 X;
    fe2 Y;
    fe2 Z;
} ge_p2;

typedef struct
{
    fe2 X;
    fe2 Y;
    fe2 Z;
    fe2 T;
} ge_p3;

typedef struct
{
    fe2 X;
    fe2 Y;
    fe2 Z;
    fe2 T;
} ge_p1p1;

typedef struct
{
    fe2 yplusx;
    fe2 yminusx;
    fe2 xy2d;
} ge_precomp;

typedef struct
{
    fe2 YplusX;
    fe2 YminusX;
    fe2 Z;
    fe2 T2d;
} ge_cached;

extern const ge25519 ALIGN(16) xmr_h;

typedef struct xmr_ctkey
{
    xmr_key_t dest;
    xmr_key_t mask;
} xmr_ctkey_t;

int xmr_base58_addr_encode_check(uint64_t tag, const uint8_t* data, size_t binsz, char* b58, size_t b58sz);
int xmr_base58_addr_decode_check(const char* addr, size_t sz, uint64_t* tag, void* data, size_t datalen);
bool xmr_base58_encode(char* b58, size_t* b58sz, const void* data, size_t binsz);
bool xmr_base58_decode(const char* b58, size_t b58sz, void* data, size_t* binsz);
int xmr_size_varint(uint64_t num);
int xmr_write_varint(uint8_t* buff, size_t buff_size, uint64_t num);
int xmr_read_varint(uint8_t* buff, size_t buff_size, uint64_t* val);

void xmr_gen_range_sig(xmr_range_sig_t* sig, ge25519* C, bignum256modm mask,
                       xmr_amount amount, bignum256modm* last_mask);
void xmr_gen_range_sig_ex(xmr_range_sig_t* sig, ge25519* C, bignum256modm mask,
                          xmr_amount amount, bignum256modm* last_mask,
                          bignum256modm ai[64], bignum256modm alpha[64]);

/* sets H point to r */
void ge25519_set_xmr_h(ge25519* r);

/* random scalar value */
void xmr_random_scalar(bignum256modm m);

/* cn_fast_hash */
void xmr_fast_hash(uint8_t* hash, const void* data, size_t length);

/* H_s(buffer) */
void xmr_hash_to_scalar(bignum256modm r, const void* data, size_t length);

/* H_p(buffer) */
void xmr_hash_to_ec(ge25519* P, const void* data, size_t length);

/* derivation to scalar value */
void xmr_derivation_to_scalar(bignum256modm s, const ge25519* p,
                              uint32_t output_index);

/* derivation */
void xmr_generate_key_derivation(ge25519* r, const ge25519* A,
                                 const bignum256modm b);

/* H_s(derivation || varint(output_index)) + base */
void xmr_derive_private_key(bignum256modm s, const ge25519* deriv, uint32_t idx,
                            const bignum256modm base);

/* H_s(derivation || varint(output_index))G + base */
void xmr_derive_public_key(ge25519* r, const ge25519* deriv, uint32_t idx,
                           const ge25519* base);

/* aG + bB, G is basepoint */
void xmr_add_keys2(ge25519* r, const bignum256modm a, const bignum256modm b,
                   const ge25519* B);
void xmr_add_keys2_vartime(ge25519* r, const bignum256modm a,
                           const bignum256modm b, const ge25519* B);

/* aA + bB */
void xmr_add_keys3(ge25519* r, const bignum256modm a, const ge25519* A,
                   const bignum256modm b, const ge25519* B);
void xmr_add_keys3_vartime(ge25519* r, const bignum256modm a, const ge25519* A,
                           const bignum256modm b, const ge25519* B);

/* subaddress secret */
void xmr_get_subaddress_secret_key(bignum256modm r, uint32_t major,
                                   uint32_t minor, const bignum256modm m);

/* Generates Pedersen commitment C = aG + bH */
void xmr_gen_c(ge25519* r, const bignum256modm a, uint64_t amount);

/* From ge_add.c */

void ge_add(ge_p1p1*, const ge_p3*, const ge_cached*);

/* From ge_double_scalarmult.c, modified */

typedef ge_cached ge_dsmp[8];
extern const ge_precomp ge_Bi[8];
void ge_dsm_precomp(ge_dsmp r, const ge_p3* s);
void ge_double_scalarmult_base_vartime(ge_p2*, const unsigned char*, const ge_p3*, const unsigned char*);

/* From ge_frombytes.c, modified */

extern const fe2 fe2_sqrtm1;
extern const fe2 fe2_d;
int ge_frombytes_vartime(ge_p3*, const unsigned char*);

/* From ge_p1p1_to_p2.c */

void ge_p1p1_to_p2(ge_p2*, const ge_p1p1*);

/* From ge_p1p1_to_p3.c */

void ge_p1p1_to_p3(ge_p3*, const ge_p1p1*);

/* From ge_p2_dbl.c */

void ge_p2_dbl(ge_p1p1*, const ge_p2*);

/* From ge_p3_to_cached.c */

extern const fe2 fe2_d2;
void ge_p3_to_cached(ge_cached*, const ge_p3*);

/* From ge_p3_to_p2.c */

void ge_p3_to_p2(ge_p2*, const ge_p3*);

/* From ge_p3_tobytes.c */

void ge_p3_tobytes(unsigned char*, const ge_p3*);

/* From ge_scalarmult_base.c */

extern const ge_precomp ge_base[32][8];
void ge_scalarmult_base(ge_p3*, const unsigned char*);

/* From ge_tobytes.c */

void ge_tobytes(unsigned char*, const ge_p2*);

/* From sc_reduce.c */

void sc_reduce(unsigned char*);

/* New code */

void ge_scalarmult(ge_p2*, const unsigned char*, const ge_p3*);
void ge_double_scalarmult_precomp_vartime(ge_p2*, const unsigned char*, const ge_p3*, const unsigned char*, const ge_dsmp);
void ge_mul8(ge_p1p1*, const ge_p2*);
extern const fe2 fe2_ma2;
extern const fe2 fe2_ma;
extern const fe2 fe2_fffb1;
extern const fe2 fe2_fffb2;
extern const fe2 fe2_fffb3;
extern const fe2 fe2_fffb4;
void ge_fromfe2_frombytes_vartime(ge_p2*, const unsigned char*);
int sc_0(unsigned char*);
void sc_reduce32(unsigned char*);
void sc_add(unsigned char*, const unsigned char*, const unsigned char*);
void sc_sub(unsigned char*, const unsigned char*, const unsigned char*);
void sc_mulsub(unsigned char*, const unsigned char*, const unsigned char*, const unsigned char*);
int sc_check(const unsigned char*);
int sc_isnonzero(const unsigned char*); /* Doesn't normalize */

// internal
uint64_t load2_3(const unsigned char* in);
uint64_t load2_4(const unsigned char* in);
void ge_sub(ge_p1p1* r, const ge_p3* p, const ge_cached* q);
void fe2_add(fe2 h, const fe2 f, const fe2 g);
void fe2_tobytes(unsigned char*, const fe2);
void fe2_invert(fe2 out, const fe2 z);

void extern_discard(int);
#endif
