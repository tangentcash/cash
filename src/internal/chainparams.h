#ifndef __CHAINPARAMS_H__
#define __CHAINPARAMS_H__
#include <stdint.h>

typedef struct sc_chainparams_
{
    const char bech32_hrp[16];
    const char bech32_cashaddr[16];
    uint16_t b58prefix_pubkey_address;
    uint16_t b58prefix_script_address;
    uint8_t b58prefix_secret_address; //!private key
    uint32_t b58prefix_bip32_pubkey;
    uint32_t b58prefix_bip32_privkey;
} sc_chainparams;

/* bitcoin */
extern const sc_chainparams btc_chainparams_main;
extern const sc_chainparams btc_chainparams_test;
extern const sc_chainparams btc_chainparams_regtest;

/* litecoin */
extern const sc_chainparams ltc_chainparams_main;
extern const sc_chainparams ltc_chainparams_test;
extern const sc_chainparams ltc_chainparams_regtest;

/* dogecoin */
extern const sc_chainparams doge_chainparams_main;
extern const sc_chainparams doge_chainparams_test;
extern const sc_chainparams doge_chainparams_regtest;

/* bitcoin-cash */
extern const sc_chainparams bch_chainparams_main;
extern const sc_chainparams bch_chainparams_test;
extern const sc_chainparams bch_chainparams_regtest;

/* ecash */
extern const sc_chainparams xec_chainparams_main;
extern const sc_chainparams xec_chainparams_test;
extern const sc_chainparams xec_chainparams_regtest;

/* bitcoin-gold */
extern const sc_chainparams btg_chainparams_main;
extern const sc_chainparams btg_chainparams_test;
extern const sc_chainparams btg_chainparams_regtest;

/* bitcoin-sv */
extern const sc_chainparams bsv_chainparams_main;
extern const sc_chainparams bsv_chainparams_test;
extern const sc_chainparams bsv_chainparams_regtest;

/* zcash */
extern const sc_chainparams zec_chainparams_main;
extern const sc_chainparams zec_chainparams_test;
extern const sc_chainparams zec_chainparams_regtest;

/* dash */
extern const sc_chainparams dash_chainparams_main;
extern const sc_chainparams dash_chainparams_test;
extern const sc_chainparams dash_chainparams_regtest;

/* digibyte */
extern const sc_chainparams dgb_chainparams_main;
extern const sc_chainparams dgb_chainparams_test;
extern const sc_chainparams dgb_chainparams_regtest;

/* ethereum */
extern const sc_chainparams eth_chainparams_main;
extern const sc_chainparams eth_chainparams_test;
extern const sc_chainparams eth_chainparams_regtest;

/* tron */
extern const sc_chainparams trx_chainparams_main;
extern const sc_chainparams trx_chainparams_test;
extern const sc_chainparams trx_chainparams_regtest;

/* ripple xrp */
extern const sc_chainparams xrp_chainparams_main;
extern const sc_chainparams xrp_chainparams_test;
extern const sc_chainparams xrp_chainparams_regtest;

/* stellar xlm */
extern const sc_chainparams xlm_chainparams_main;
extern const sc_chainparams xlm_chainparams_test;
extern const sc_chainparams xlm_chainparams_regtest;

/* solana */
extern const sc_chainparams sol_chainparams_main;
extern const sc_chainparams sol_chainparams_test;
extern const sc_chainparams sol_chainparams_regtest;
#endif