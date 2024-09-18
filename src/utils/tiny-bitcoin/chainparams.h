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

#ifndef __LIBBTC_CHAINPARAMS_H__
#define __LIBBTC_CHAINPARAMS_H__

#include "btc.h"
#define B58_PREFIX_MAX_SIZE 2

LIBBTC_BEGIN_DECL

typedef struct btc_chainparams_ {
    const char bech32_hrp[16];
    const char bech32_cashaddr[16];
    uint16_t b58prefix_pubkey_address;
    uint16_t b58prefix_script_address;
    uint8_t b58prefix_secret_address; //!private key
    uint32_t b58prefix_bip32_pubkey;
    uint32_t b58prefix_bip32_privkey;
} btc_chainparams;

/* bitcoin */
extern const btc_chainparams btc_chainparams_main;
extern const btc_chainparams btc_chainparams_test;
extern const btc_chainparams btc_chainparams_regtest;

/* litecoin */
extern const btc_chainparams ltc_chainparams_main;
extern const btc_chainparams ltc_chainparams_test;
extern const btc_chainparams ltc_chainparams_regtest;

/* dogecoin */
extern const btc_chainparams doge_chainparams_main;
extern const btc_chainparams doge_chainparams_test;
extern const btc_chainparams doge_chainparams_regtest;

/* bitcoin-cash */
extern const btc_chainparams bch_chainparams_main;
extern const btc_chainparams bch_chainparams_test;
extern const btc_chainparams bch_chainparams_regtest;

/* ecash */
extern const btc_chainparams xec_chainparams_main;
extern const btc_chainparams xec_chainparams_test;
extern const btc_chainparams xec_chainparams_regtest;

/* bitcoin-gold */
extern const btc_chainparams btg_chainparams_main;
extern const btc_chainparams btg_chainparams_test;
extern const btc_chainparams btg_chainparams_regtest;

/* bitcoin-sv */
extern const btc_chainparams bsv_chainparams_main;
extern const btc_chainparams bsv_chainparams_test;
extern const btc_chainparams bsv_chainparams_regtest;

/* zcash */
extern const btc_chainparams zec_chainparams_main;
extern const btc_chainparams zec_chainparams_test;
extern const btc_chainparams zec_chainparams_regtest;

/* dash */
extern const btc_chainparams dash_chainparams_main;
extern const btc_chainparams dash_chainparams_test;
extern const btc_chainparams dash_chainparams_regtest;

/* digibyte */
extern const btc_chainparams dgb_chainparams_main;
extern const btc_chainparams dgb_chainparams_test;
extern const btc_chainparams dgb_chainparams_regtest;

/* ethereum */
extern const btc_chainparams eth_chainparams_main;
extern const btc_chainparams eth_chainparams_test;
extern const btc_chainparams eth_chainparams_regtest;

/* ethereum classic */
extern const btc_chainparams etc_chainparams_main;
extern const btc_chainparams etc_chainparams_test;
extern const btc_chainparams etc_chainparams_regtest;

/* fantom */
extern const btc_chainparams ftm_chainparams_main;
extern const btc_chainparams ftm_chainparams_test;
extern const btc_chainparams ftm_chainparams_regtest;

/* fuseio */
extern const btc_chainparams fuse_chainparams_main;
extern const btc_chainparams fuse_chainparams_test;
extern const btc_chainparams fuse_chainparams_regtest;

/* moonbeam */
extern const btc_chainparams glmr_chainparams_main;
extern const btc_chainparams glmr_chainparams_test;
extern const btc_chainparams glmr_chainparams_regtest;

/* optimism */
extern const btc_chainparams op_chainparams_main;
extern const btc_chainparams op_chainparams_test;
extern const btc_chainparams op_chainparams_regtest;

/* rootstock */
extern const btc_chainparams rsk_chainparams_main;
extern const btc_chainparams rsk_chainparams_test;
extern const btc_chainparams rsk_chainparams_regtest;

/* heco */
extern const btc_chainparams heco_chainparams_main;
extern const btc_chainparams heco_chainparams_test;
extern const btc_chainparams heco_chainparams_regtest;

/* kcc */
extern const btc_chainparams kcc_chainparams_main;
extern const btc_chainparams kcc_chainparams_test;
extern const btc_chainparams kcc_chainparams_regtest;

/* avalanche */
extern const btc_chainparams avax_chainparams_main;
extern const btc_chainparams avax_chainparams_test;
extern const btc_chainparams avax_chainparams_regtest;

/* arbitrum */
extern const btc_chainparams arb_chainparams_main;
extern const btc_chainparams arb_chainparams_test;
extern const btc_chainparams arb_chainparams_regtest;

/* tron */
extern const btc_chainparams trx_chainparams_main;
extern const btc_chainparams trx_chainparams_test;
extern const btc_chainparams trx_chainparams_regtest;

/* harmony one */
extern const btc_chainparams one_chainparams_main;
extern const btc_chainparams one_chainparams_test;
extern const btc_chainparams one_chainparams_regtest;

/* celo */
extern const btc_chainparams celo_chainparams_main;
extern const btc_chainparams celo_chainparams_test;
extern const btc_chainparams celo_chainparams_regtest;

/* polygon matic */
extern const btc_chainparams matic_chainparams_main;
extern const btc_chainparams matic_chainparams_test;
extern const btc_chainparams matic_chainparams_regtest;

/* binance smart chain */
extern const btc_chainparams bsc_chainparams_main;
extern const btc_chainparams bsc_chainparams_test;
extern const btc_chainparams bsc_chainparams_regtest;

/* build-and-build beacon chain */
extern const btc_chainparams bnb_chainparams_main;
extern const btc_chainparams bnb_chainparams_test;
extern const btc_chainparams bnb_chainparams_regtest;

/* ripple xrp */
extern const btc_chainparams xrp_chainparams_main;
extern const btc_chainparams xrp_chainparams_test;
extern const btc_chainparams xrp_chainparams_regtest;

/* stellar xlm */
extern const btc_chainparams xlm_chainparams_main;
extern const btc_chainparams xlm_chainparams_test;
extern const btc_chainparams xlm_chainparams_regtest;

/* solana */
extern const btc_chainparams sol_chainparams_main;
extern const btc_chainparams sol_chainparams_test;
extern const btc_chainparams sol_chainparams_regtest;

LIBBTC_END_DECL

#endif // __LIBBTC_CHAINPARAMS_H__
