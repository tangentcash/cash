/*

 The MIT License (MIT)

 Copyright (c) 2017 Jonas Schnelli

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

#include "chainparams.h"

/* bitcoin */
const btc_chainparams btc_chainparams_main = {
	"bc",
	"",
	0x0000,
	0x0500,
	0x80,
	0x0488B21E,
	0x0488ADE4
};
const btc_chainparams btc_chainparams_test = {
	"tb",
	"",
	0x6f00,
	0xc400,
	0xEF,
	0x043587CF,
	0x04358394
};
const btc_chainparams btc_chainparams_regtest = {
	"bcrt",
	"",
	0x6f00,
	0xc400,
	0xEF,
	0x043587CF,
	0x04358394
};

/* litecoin */
const btc_chainparams ltc_chainparams_main = {
	"ltc",
	"",
	0x3000,
	0x3200,
	0xb0,
	0x019da462,
	0x019d9cfe
};
const btc_chainparams ltc_chainparams_test = {
	"tltc",
	"",
	0x6f00,
	0x3a00,
	0xef,
	0x0436f6e1,
	0x0436ef7d
};
const btc_chainparams ltc_chainparams_regtest = {
	"rltc",
	"",
	0x6f00,
	0x3a00,
	0xef,
	0x043587cf,
	0x04358394
};

/* dogecoin */
const btc_chainparams doge_chainparams_main = {
	"",
	"",
	0x1e00,
	0x1600,
	0x9e,
	0x02facafd,
	0x02fac398
};
const btc_chainparams doge_chainparams_test = {
	"",
	"",
	0x7100,
	0xc400,
	0xf1,
	0x043587cf,
	0x04358394
};
const btc_chainparams doge_chainparams_regtest = {
	"",
	"",
	0x6f00,
	0xc400,
	0xEF,
	0x043587CF,
	0x04358394,
};

/* bitcoin-cash */
const btc_chainparams bch_chainparams_main = {
	"",
	"bitcoincash",
	0x0000,
	0x0500,
	0x80,
	0x0488b21e,
	0x0488ade4,
};
const btc_chainparams bch_chainparams_test = {
	"",
	"bchtest",
	0x6f00,
	0xc400,
	0xef,
	0x043587cf,
	0x04358394,
};
const btc_chainparams bch_chainparams_regtest = {
	"",
	"bchreg",
	0x6f00,
	0xc400,
	0xef,
	0x043587cf,
	0x04358394,
};

/* ecash */
const btc_chainparams xec_chainparams_main = {
	"",
	"ecash",
	0x0000,
	0x0500,
	0x80,
	0x0488b21e,
	0x0488ade4,
};
const btc_chainparams xec_chainparams_test = {
	"",
	"ectest",
	0x6f00,
	0xc400,
	0xef,
	0x043587cf,
	0x04358394,
};
const btc_chainparams xec_chainparams_regtest = {
	"",
	"ecregtest",
	0x6f00,
	0xc400,
	0xef,
	0x043587cf,
	0x04358394,
};

/* bitcoin gold */
const btc_chainparams btg_chainparams_main = {
	"btg",
	"",
	0x2600,
	0x1700,
	0x80,
	0x0488B21E,
	0x0488ADE4
};
const btc_chainparams btg_chainparams_test = {
	"tbtg",
	"",
	0x6f00,
	0xc400,
	0xEF,
	0x043587CF,
	0x04358394
};
const btc_chainparams btg_chainparams_regtest = {
	"btgrt",
	"",
	0x6f00,
	0xc400,
	0xEF,
	0x043587CF,
	0x04358394
};

/* bitcoin sv */
const btc_chainparams bsv_chainparams_main = {
	"",
	"",
	0x0000,
	0x0500,
	0x80,
	0x0488B21E,
	0x0488ADE4
};
const btc_chainparams bsv_chainparams_test = {
	"",
	"",
	0x6f00,
	0xc400,
	0xEF,
	0x043587CF,
	0x04358394
};
const btc_chainparams bsv_chainparams_regtest = {
	"",
	"",
	0x6f00,
	0xc400,
	0xEF,
	0x043587CF,
	0x04358394
};

/* zcash */
const btc_chainparams zec_chainparams_main = {
	"u",
	"",
	0x1CB8,
	0x1CBD,
	0x80,
	0x0488B21E,
	0x0488ADE4,
};
const btc_chainparams zec_chainparams_test = {
	"utest",
	"",
	0x1D25,
	0x1CBA,
	0xEF,
	0x043587CF,
	0x04358394,
};
const btc_chainparams zec_chainparams_regtest = {
	"uregtest",
	"",
	0x1D25,
	0x1CBA,
	0xEF,
	0x043587CF,
	0x04358394,
};

/* dash */
const btc_chainparams dash_chainparams_main = {
	"",
	"",
	0x4C00,
	0x1000,
	0xCC,
	0x0488B21E,
	0x0488ADE4
};
const btc_chainparams dash_chainparams_test = {
	"",
	"",
	0x8C00,
	0x1300,
	0xEF,
	0x043587CF,
	0x04358394
};
const btc_chainparams dash_chainparams_regtest = {
	"",
	"",
	0x8C00,
	0x1300,
	0xEF,
	0x043587CF,
	0x04358394
};

/* digibyte */
const btc_chainparams dgb_chainparams_main = {
	"dgb",
	"",
	0x1e00,
	0x3f00,
	0x80,
	0x0488B21E,
	0x0488ADE4
};
const btc_chainparams dgb_chainparams_test = {
	"dgbt",
	"",
	0x7e00,
	0x8c00,
	0xfe,
	0x043587CF,
	0x04358394
};
const btc_chainparams dgb_chainparams_regtest = {
	"dgbrt",
	"",
	0x7e00,
	0x8c00,
	0xfe,
	0x043587CF,
	0x04358394
};

/* ethereum */
const btc_chainparams eth_chainparams_main = {
	"0x",
	"",
	0x0000,
	0x0500,
	0x80,
	0x0488B21E,
	0x0488ADE4
};
const btc_chainparams eth_chainparams_test = {
	"0x",
	"",
	0x6f00,
	0xc400,
	0xEF,
	0x0488B21E,
	0x0488ADE4
};
const btc_chainparams eth_chainparams_regtest = {
	"0x",
	"",
	0x6f00,
	0xc400,
	0xEF,
	0x0488B21E,
	0x0488ADE4
};

/* tron */
const btc_chainparams trx_chainparams_main = {
	"0x",
	"",
	0x4100,
	0x0500,
	0x80,
	0x0488B21E,
	0x0488ADE4
};
const btc_chainparams trx_chainparams_test = {
	"0x",
	"",
	0x4100,
	0x0500,
	0xEF,
	0x0488B21E,
	0x0488ADE4
};
const btc_chainparams trx_chainparams_regtest = {
	"0x",
	"",
	0x4100,
	0x0500,
	0xEF,
	0x0488B21E,
	0x0488ADE4
};

/* ripple xrp */
const btc_chainparams xrp_chainparams_main = {
	"",
	"",
	0x0000,
	0x0500,
	0x80,
	0x0488B21E,
	0x0488ADE4
};
const btc_chainparams xrp_chainparams_test = {
	"",
	"",
	0x6f00,
	0xc400,
	0xEF,
	0x043587CF,
	0x04358394
};
const btc_chainparams xrp_chainparams_regtest = {
	"",
	"",
	0x6f00,
	0xc400,
	0xEF,
	0x043587CF,
	0x04358394
};

/* stellar xlm */
const btc_chainparams xlm_chainparams_main = {
	"",
	"",
	0x0000,
	0x0500,
	0x80,
	0x0488B21E,
	0x0488ADE4
};
const btc_chainparams xlm_chainparams_test = {
	"",
	"",
	0x6f00,
	0xc400,
	0xEF,
	0x043587CF,
	0x04358394
};
const btc_chainparams xlm_chainparams_regtest = {
	"",
	"",
	0x6f00,
	0xc400,
	0xEF,
	0x043587CF,
	0x04358394
};

/* solana */
const btc_chainparams sol_chainparams_main = {
	"",
	"",
	0x0000,
	0x0500,
	0x80,
	0x0488B21E,
	0x0488ADE4
};
const btc_chainparams sol_chainparams_test = {
	"",
	"",
	0x6f00,
	0xc400,
	0xEF,
	0x043587CF,
	0x04358394
};
const btc_chainparams sol_chainparams_regtest = {
	"",
	"",
	0x6f00,
	0xc400,
	0xEF,
	0x043587CF,
	0x04358394
};