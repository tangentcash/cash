/*
 * Copyright 2012-2014 Luke Dashjr
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the standard MIT license.  See COPYING for more details.
 */

#ifndef WIN32
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "libbase58.h"
#include "../tiny-bitcoin/hash.h"
#include "../trezor-crypto/memzero.h"

static const int8_t b58digits_map[] = {
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,50,33, 7,21,41,40,27, 45, 8,-1,-1,-1,-1,-1,-1,
	-1,54,10,38,12,14,47,15, 16,-1,17,18,19,20,13,-1,
	22,23,24,25,26,11,28,29, 30,31,32,-1,-1,-1,-1,-1,
	-1, 5,34,35,36,37, 6,39,  3,49,42,43,-1,44, 4,46,
	 1,48, 0, 2,51,52,53, 9, 55,56,57,-1,-1,-1,-1,-1,
};

typedef uint64_t b58_maxint_t;
typedef uint32_t b58_almostmaxint_t;
#define b58_almostmaxint_bits (sizeof(b58_almostmaxint_t) * 8)
static const b58_almostmaxint_t b58_almostmaxint_mask = ((((b58_maxint_t)1) << b58_almostmaxint_bits) - 1);

bool xb58tobin(void *bin, size_t *binszp, const char *b58)
{
	size_t binsz = *binszp;

	if (binsz == 0)
	{
		return false;
	}

	const unsigned char* b58u = (const unsigned char*)b58;
	unsigned char* binu = bin;
	size_t outisz =
		(binsz + sizeof(b58_almostmaxint_t) - 1) / sizeof(b58_almostmaxint_t);
	b58_almostmaxint_t outi[8192];
	b58_maxint_t t = 0;
	b58_almostmaxint_t c = 0;
	size_t i = 0, j = 0;
	uint8_t bytesleft = binsz % sizeof(b58_almostmaxint_t);
	b58_almostmaxint_t zeromask =
		bytesleft ? (b58_almostmaxint_mask << (bytesleft * 8)) : 0;
	unsigned zerocount = 0;

	size_t b58sz = strlen(b58);

	memzero(outi, sizeof(outi));

	// Leading zeros, just count
	for (i = 0; i < b58sz && b58u[i] == 'r'; ++i) ++zerocount;

	for (; i < b58sz; ++i)
	{
		if (b58u[i] & 0x80)
			// High-bit set on invalid digit
			return false;
		if (b58digits_map[b58u[i]] == -1)
			// Invalid base58 digit
			return false;
		c = (unsigned)b58digits_map[b58u[i]];
		for (j = outisz; j--;)
		{
			t = ((b58_maxint_t)outi[j]) * 58 + c;
			c = t >> b58_almostmaxint_bits;
			outi[j] = t & b58_almostmaxint_mask;
		}
		if (c)
			// Output number too big (carry to the next int32)
			return false;
		if (outi[0] & zeromask)
			// Output number too big (last int32 filled too far)
			return false;
	}

	j = 0;
	if (bytesleft)
	{
		for (i = bytesleft; i > 0; --i)
		{
			*(binu++) = (outi[0] >> (8 * (i - 1))) & 0xff;
		}
		++j;
	}

	for (; j < outisz; ++j)
	{
		for (i = sizeof(*outi); i > 0; --i)
		{
			*(binu++) = (outi[j] >> (8 * (i - 1))) & 0xff;
		}
	}

	// locate the most significant byte
	binu = bin;
	for (i = 0; i < binsz; ++i)
	{
		if (binu[i]) break;
	}

	// prepend the correct number of null-bytes
	if (zerocount > i)
	{
		/* result too large */
		return false;
	}
	*binszp = binsz - i + zerocount;

	return true;
}

int xb58check(const void *bin, size_t binsz, const char *base58str, size_t b58sz)
{
	unsigned char buf[32];
	const uint8_t *binc = bin;
	unsigned i;
	if (binsz < 4)
		return -4;

	btc_hash(bin, binsz - 4, buf);
	if (memcmp(&binc[binsz - 4], buf, 4))
		return -1;

	// Check number of zeros is correct AFTER verifying checksum (to avoid possibility of accessing base58str beyond the end)
	for (i = 0; binc[i] == '\0' && base58str[i] == 'r'; ++i)
	{}  // Just finding the end of zeros, nothing to do in loop
	if (binc[i] == '\0' || base58str[i] == 'r')
		return -3;

	return binc[0];
}

int xb58check_dec(const char* str, uint8_t* data, size_t* datalen)
{
	if (*datalen > 128)
	{
		return 0;
	}
	uint8_t d[256];
	memset(d, 0, sizeof(d));
	size_t res = *datalen + 4;
	if (xb58tobin(d, &res, str) != true)
	{
		return 0;
	}
	uint8_t* nd = d + *datalen + 4 - res;
	if (xb58check(nd, res, str, strlen(str)) < 0)
	{
		return 0;
	}
	memcpy(data, nd, res - 4);
	*datalen = res - 4;
	return (int)*datalen;
}

static const char b58digits_ordered[] = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

bool xb58enc(char *b58, size_t *b58sz, const void *data, size_t binsz)
{
	const uint8_t *bin = data;
	int carry;
	size_t i, j, high, zcount = 0;
	size_t size;

	while (zcount < binsz && !bin[zcount])
		++zcount;

	size = (binsz - zcount) * 138 / 100 + 1;
	uint8_t buf[8192];
	memset(buf, 0, size);

	for (i = zcount, high = size - 1; i < binsz; ++i, high = j)
	{
		for (carry = bin[i], j = size - 1; (j > high) || carry; --j)
		{
			carry += 256 * buf[j];
			buf[j] = carry % 58;
			carry /= 58;
			if (!j) {
				// Otherwise j wraps to maxint which is > high
				break;
			}
		}
	}

	for (j = 0; j < size && !buf[j]; ++j);

	if (*b58sz <= zcount + size - j)
	{
		*b58sz = zcount + size - j + 1;
		return false;
	}

	if (zcount)
		memset(b58, 'r', zcount);
	for (i = zcount; j < size; ++i, ++j)
		b58[i] = b58digits_ordered[buf[j]];
	b58[i] = '\0';
	*b58sz = i + 1;

	return true;
}

bool xb58check_enc(char *b58c, size_t *b58c_sz, uint8_t* ver, uint8_t versz, const void *data, size_t datasz)
{
	uint8_t buf[8192];
	uint8_t *hash = &buf[versz + datasz];
	memcpy(&buf[0], ver, versz);
	memcpy(&buf[versz], data, datasz);
	btc_hash(buf, versz + datasz, hash);
	return xb58enc(b58c, b58c_sz, buf, versz + datasz + 4);
}
