/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */


#ifndef __LIBBTC_TAPROOT_H__
#define __LIBBTC_TAPROOT_H__

#include "btc.h"

LIBBTC_BEGIN_DECL

/** Taproot tag types */
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

LIBBTC_API void btc_tagged_hash(enum btc_tagged_prefixes prefix, const uint8_t* message, size_t message_size, uint256 hash);

LIBBTC_END_DECL

#endif // END __LIBBTC_RIPEMD160_H__
