#include "bitcoin.h"
#include "chainparams.h"
#include "memzero.h"
#include "ripemd160.h"
#include "bech32.h"
#include "rand.h"
#include "ripemd160.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include <time.h>
#include <secp256k1_recovery.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#if (defined(_WIN16) || defined(_WIN32) || defined(_WIN64)) && !defined(__WINDOWS__)
#define __WINDOWS__
#endif
#if defined(__linux__) || defined(__CYGWIN__)
#include <endian.h>
#elif defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)
#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)
#define __BYTE_ORDER BYTE_ORDER
#define __BIG_ENDIAN BIG_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#define __PDP_ENDIAN PDP_ENDIAN
#elif defined(__OpenBSD__)
#include <sys/endian.h>
#elif defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
#include <sys/endian.h>
#define be16toh(x) betoh16(x)
#define le16toh(x) letoh16(x)
#define be32toh(x) betoh32(x)
#define le32toh(x) letoh32(x)
#define be64toh(x) betoh64(x)
#define le64toh(x) letoh64(x)
#elif defined(__WINDOWS__)
#ifndef _MSC_VER
#include <sys/param.h>
#endif
#include <winsock2.h>
#if BYTE_ORDER == LITTLE_ENDIAN
#define htobe16(x) htons(x)
#define htole16(x) (x)
#define be16toh(x) ntohs(x)
#define le16toh(x) (x)
#define htobe32(x) htonl(x)
#define htole32(x) (x)
#define be32toh(x) ntohl(x)
#define le32toh(x) (x)
#define htobe64(x) htonll(x)
#define htole64(x) (x)
#define be64toh(x) ntohll(x)
#define le64toh(x) (x)
#elif BYTE_ORDER == BIG_ENDIAN
#define htobe16(x) (x)
#define htole16(x) __builtin_bswap16(x)
#define be16toh(x) (x)
#define le16toh(x) __builtin_bswap16(x)
#define htobe32(x) (x)
#define htole32(x) __builtin_bswap32(x)
#define be32toh(x) (x)
#define le32toh(x) __builtin_bswap32(x)
#define htobe64(x) (x)
#define htole64(x) __builtin_bswap64(x)
#define be64toh(x) (x)
#define le64toh(x) __builtin_bswap64(x)
#else
#error byte order not supported
#endif
#define __BYTE_ORDER BYTE_ORDER
#define __BIG_ENDIAN BIG_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#define __PDP_ENDIAN PDP_ENDIAN
#else
#error platform not supported
#endif
#ifdef WIN32
#ifdef _MSC_VER
#pragma warning(disable:4786)
#pragma warning(disable:4804)
#pragma warning(disable:4805)
#pragma warning(disable:4717)
#endif
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0501
#ifdef _WIN32_IE
#undef _WIN32_IE
#endif
#define _WIN32_IE 0x0501
#define WIN32_LEAN_AND_MEAN 1
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <io.h>
#include <shlobj.h>
#else
#include <unistd.h>
#endif
#define b58_almostmaxint_bits (sizeof(b58_almostmaxint_t) * 8)

typedef uint64_t b58_maxint_t;
typedef uint32_t b58_almostmaxint_t;

void* btc_malloc_internal(size_t size);
void* btc_calloc_internal(size_t count, size_t size);
void* btc_realloc_internal(void* ptr, size_t size);
void btc_free_internal(void* ptr);

static secp256k1_context* secp256k1_ctx = NULL;
static const btc_mem_mapper default_mem_mapper = { btc_malloc_internal, btc_calloc_internal, btc_realloc_internal, btc_free_internal };
static btc_mem_mapper current_mem_mapper = { btc_malloc_internal, btc_calloc_internal, btc_realloc_internal, btc_free_internal };
const b58_almostmaxint_t b58_almostmaxint_mask = ((((b58_maxint_t)1) << b58_almostmaxint_bits) - 1);
static uint8_t buffer_hex_to_uint8[TO_UINT8_HEX_BUF_LEN];
static char buffer_uint8_to_hex[TO_UINT8_HEX_BUF_LEN];
const char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const int8_t b58digits_map[] =
{
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,
    8,  -1, -1, -1, -1, -1, -1, -1, 9,  10, 11, 12, 13, 14, 15, 16, -1, 17, 18,
    19, 20, 21, -1, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1,
    -1, -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46, 47, 48,
    49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1,
};
const signed char p_util_hexdigit[256] =
{
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1,
    -1, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};
const uint8_t tagged_hash_prefixes[][64] =
{
    { 123, 181, 45, 122, 159, 239, 88, 50, 62, 177, 191, 122, 64, 125, 179, 130,
    210, 243, 242, 216, 27, 177, 34, 79, 73, 254, 81, 143, 109, 72, 211, 124,
    123, 181, 45, 122, 159, 239, 88, 50, 62, 177, 191, 122, 64, 125, 179, 130,
    210, 243, 242, 216, 27, 177, 34, 79, 73, 254, 81, 143, 109, 72, 211, 124 },
    { 241, 239, 78, 94, 192, 99, 202, 218, 109, 148, 202, 250, 157, 152, 126, 160,
    105, 38, 88, 57, 236, 193, 31, 151, 45, 119, 165, 46, 216, 193, 204, 144,
    241, 239, 78, 94, 192, 99, 202, 218, 109, 148, 202, 250, 157, 152, 126, 160,
    105, 38, 88, 57, 236, 193, 31, 151, 45, 119, 165, 46, 216, 193, 204, 144 },
    { 7, 73, 119, 52, 167, 155, 203, 53, 91, 155, 140, 125, 3, 79, 18, 28, 244,
    52, 215, 62, 247, 45, 218, 25, 135, 0, 97, 251, 82, 191, 235, 47, 7, 73,
    119, 52, 167, 155, 203, 53, 91, 155, 140, 125, 3, 79, 18, 28, 244, 52, 215,
    62, 247, 45, 218, 25, 135, 0, 97, 251, 82, 191, 235, 47 },
    { 174, 234, 143, 220, 66, 8, 152, 49, 5, 115, 75, 88, 8, 29, 30, 38, 56, 211,
    95, 28, 181, 64, 8, 212, 211, 87, 202, 3, 190, 120, 233, 238, 174, 234, 143,
    220, 66, 8, 152, 49, 5, 115, 75, 88, 8, 29, 30, 38, 56, 211, 95, 28, 181,
    64, 8, 212, 211, 87, 202, 3, 190, 120, 233, 238 },
    { 25, 65, 161, 242, 229, 110, 185, 95, 162, 169, 241, 148, 190, 92, 1, 247,
    33, 111, 51, 237, 130, 176, 145, 70, 52, 144, 208, 91, 245, 22, 160, 21, 25,
    65, 161, 242, 229, 110, 185, 95, 162, 169, 241, 148, 190, 92, 1, 247, 33,
    111, 51, 237, 130, 176, 145, 70, 52, 144, 208, 91, 245, 22, 160, 21 },
    { 244, 10, 72, 223, 75, 42, 112, 200, 180, 146, 75, 242, 101, 70, 97, 237, 61,
    149, 253, 102, 163, 19, 235, 135, 35, 117, 151, 198, 40, 228, 160, 49, 244,
    10, 72, 223, 75, 42, 112, 200, 180, 146, 75, 242, 101, 70, 97, 237, 61, 149,
    253, 102, 163, 19, 235, 135, 35, 117, 151, 198, 40, 228, 160, 49 },
    { 232, 15, 225, 99, 156, 156, 160, 80, 227, 175, 27, 57, 193, 67, 198, 62, 66,
    156, 188, 235, 21, 217, 64, 251, 181, 197, 161, 244, 175, 87, 197, 233, 232,
    15, 225, 99, 156, 156, 160, 80, 227, 175, 27, 57, 193, 67, 198, 62, 66, 156,
    188, 235, 21, 217, 64, 251, 181, 197, 161, 244, 175, 87, 197, 233 },
    { 72, 28, 151, 28, 60, 11, 70, 215, 240, 178, 117, 174, 89, 141, 78, 44, 126,
    215, 49, 156, 89, 74, 92, 110, 199, 158, 160, 212, 153, 2, 148, 240, 72, 28,
    151, 28, 60, 11, 70, 215, 240, 178, 117, 174, 89, 141, 78, 44, 126, 215, 49,
    156, 89, 74, 92, 110, 199, 158, 160, 212, 153, 2, 148, 240 },
    { 191, 201, 4, 3, 77, 28, 136, 232, 200, 14, 34, 229, 61, 36, 86, 109, 100,
    130, 78, 214, 66, 114, 129, 192, 145, 0, 249, 77, 205, 82, 201, 129, 191,
    201, 4, 3, 77, 28, 136, 232, 200, 14, 34, 229, 61, 36, 86, 109, 100, 130,
    78, 214, 66, 114, 129, 192, 145, 0, 249, 77, 205, 82, 201, 129 }
};

bool b58tobin(void* bin, size_t* binszp, const char* b58, size_t b58size)
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
    b58_almostmaxint_t outi[1024];
    b58_maxint_t t = 0;
    b58_almostmaxint_t c = 0;
    size_t i = 0, j = 0;
    uint8_t bytesleft = binsz % sizeof(b58_almostmaxint_t);
    b58_almostmaxint_t zeromask =
        bytesleft ? (b58_almostmaxint_mask << (bytesleft * 8)) : 0;
    unsigned zerocount = 0;

    size_t b58sz = (size_t)b58size;

    memzero(outi, sizeof(outi));

    // Leading zeros, just count
    for (i = 0; i < b58sz && b58u[i] == '1'; ++i) ++zerocount;

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

int b58check(const void* bin, size_t binsz, const char* base58str)
{
    unsigned char buf[32] = { 0 };
    const uint8_t* binc = bin;
    unsigned i = 0;
    if (binsz < 4) return -4;
    btc_hash(bin, binsz - 4, buf);
    if (memcmp(&binc[binsz - 4], buf, 4)) return -1;

    // Check number of zeros is correct AFTER verifying checksum (to avoid
    // possibility of accessing base58str beyond the end)
    for (i = 0; binc[i] == '\0' && base58str[i] == '1'; ++i)
    {
    }  // Just finding the end of zeros, nothing to do in loop
    if (binc[i] == '\0' || base58str[i] == '1') return -3;

    return binc[0];
}

bool b58enc(char* b58, size_t* b58sz, const void* data, size_t binsz)
{
    const uint8_t* bin = data;
    int carry = 0;
    size_t i = 0, j = 0, high = 0, zcount = 0;
    size_t size = 0;

    while (zcount < binsz && !bin[zcount]) ++zcount;

    size = (binsz - zcount) * 138 / 100 + 1;
    uint8_t buf[1024];
    memzero(buf, size);

    for (i = zcount, high = size - 1; i < binsz; ++i, high = j)
    {
        for (carry = bin[i], j = size - 1; (j > high) || carry; --j)
        {
            carry += 256 * buf[j];
            buf[j] = carry % 58;
            carry /= 58;
            if (!j)
            {
                // Otherwise j wraps to maxint which is > high
                break;
            }
        }
    }

    for (j = 0; j < size && !buf[j]; ++j)
        ;

    if (*b58sz <= zcount + size - j)
    {
        *b58sz = zcount + size - j + 1;
        return false;
    }

    if (zcount) memset(b58, '1', zcount);
    for (i = zcount; j < size; ++i, ++j) b58[i] = b58digits_ordered[buf[j]];
    b58[i] = '\0';
    *b58sz = i + 1;

    return true;
}

bool b58dec(void* bin, size_t* binszp, const char* b58, size_t b58size)
{
    uint8_t d[1024];
    memset(d, 0, sizeof(d));
    size_t res = *binszp;
    if (b58tobin(d, &res, b58, b58size) != true)
    {
        return false;
    }
    uint8_t* nd = d + *binszp - res;
    memcpy(bin, nd, res);
    *binszp = res;
    return true;
}

int base58_encode_check(const uint8_t* data, int datalen, char* str, int strsize)
{
    if (datalen > 256)
    {
        return 0;
    }
    uint8_t buf[1024 + 32];
    memset(buf, 0, sizeof(buf));
    uint8_t* hash = buf + datalen;
    memcpy(buf, data, datalen);
    btc_hash(data, datalen, hash);
    size_t res = strsize;
    bool success = b58enc(str, &res, buf, datalen + 4);
    memzero(buf, sizeof(buf));
    return success ? (int)res : 0;
}

int base58_decode_check(const char* str, uint8_t* data, int datalen)
{
    if (datalen > 512)
    {
        return 0;
    }
    uint8_t d[1024 + 4];
    memset(d, 0, sizeof(d));
    size_t res = datalen + 4;
    if (b58tobin(d, &res, str, strlen(str)) != true)
    {
        return 0;
    }
    uint8_t* nd = d + datalen + 4 - res;
    if (b58check(nd, res, str) < 0)
    {
        return 0;
    }
    memcpy(data, nd, res - 4);
    return (int)res - 4;
}

void btc_mem_set_mapper_default()
{
    current_mem_mapper = default_mem_mapper;
}

void btc_mem_set_mapper(const btc_mem_mapper mapper)
{
    current_mem_mapper = mapper;
}

void* btc_malloc(size_t size)
{
    return current_mem_mapper.btc_malloc(size);
}

void* btc_calloc(size_t count, size_t size)
{
    return current_mem_mapper.btc_calloc(count, size);
}

void* btc_realloc(void* ptr, size_t size)
{
    return current_mem_mapper.btc_realloc(ptr, size);
}

void btc_free(void* ptr)
{
    current_mem_mapper.btc_free(ptr);
}

void* btc_malloc_internal(size_t size)
{
    void* result;

    if ((result = malloc(size)))
    { /* assignment intentional */
        return (result);
    }
    else
    {
        printf("memory overflow: malloc failed in btc_malloc.");
        printf("  Exiting Program.\n");
        exit(-1);
        return (0);
    }
}

void* btc_calloc_internal(size_t count, size_t size)
{
    void* result;

    if ((result = calloc(count, size)))
    { /* assignment intentional */
        return (result);
    }
    else
    {
        printf("memory overflow: calloc failed in btc_calloc.");
        printf("  Exiting Program.\n");
        exit(-1);
        return (0);
    }
}

void* btc_realloc_internal(void* ptr, size_t size)
{
    void* result;

    if ((result = realloc(ptr, size)))
    { /* assignment intentional */
        return (result);
    }
    else
    {
        printf("memory overflow: realloc failed in btc_realloc.");
        printf("  Exiting Program.\n");
        exit(-1);
        return (0);
    }
}

void btc_free_internal(void* ptr)
{
    free(ptr);
}

void* btc_mem_zero(void* dst, size_t len)
{
    memzero(dst, len);
    return dst;
}

static int cstr_alloc_min_sz(cstring* s, size_t sz)
{
    unsigned int shift;
    unsigned int al_sz;
    char* new_s;

    sz++; /* NULL overhead */

    if (s->alloc && (s->alloc >= sz))
        return 1;

    shift = 3;
    while ((al_sz = (1 << shift)) < sz)
        shift++;

    new_s = btc_realloc(s->str, al_sz);
    if (!new_s)
        return 0;

    s->str = new_s;
    s->alloc = al_sz;
    s->str[s->len] = 0;

    return 1;
}

int cstr_alloc_minsize(cstring* s, size_t new_sz)
{
    /* no change */
    if (new_sz == s->len)
        return 1;

    /* truncate string */
    if (new_sz <= s->len)
    {
        return 0;
    }

    /* increase string size */
    if (!cstr_alloc_min_sz(s, new_sz))
        return 0;

    /* contents of string tail undefined */
    //s->len = new_sz;
    s->str[s->len] = 0;

    return 1;
}

cstring* cstr_new_sz(size_t sz)
{
    cstring* s = btc_calloc(1, sizeof(cstring));
    if (!s)
        return NULL;

    if (!cstr_alloc_min_sz(s, sz))
    {
        btc_free(s);
        return NULL;
    }

    return s;
}

cstring* cstr_new_buf(const void* buf, size_t sz)
{
    cstring* s = cstr_new_sz(sz);
    if (!s)
        return NULL;

    memcpy(s->str, buf, sz);
    s->len = sz;
    s->str[s->len] = 0;

    return s;
}

cstring* cstr_new_cstr(const cstring* copy_str)
{
    return cstr_new_buf(copy_str->str, copy_str->len);
}

cstring* cstr_new(const char* init_str)
{
    size_t slen;

    if (!init_str || !*init_str)
        return cstr_new_sz(0);

    slen = strlen(init_str);
    return cstr_new_buf(init_str, slen);
}

void cstr_free(cstring* s, int free_buf)
{
    if (!s)
        return;

    if (free_buf)
        btc_free(s->str);

    memset(s, 0, sizeof(*s));
    btc_free(s);
}

int cstr_resize(cstring* s, size_t new_sz)
{
    /* no change */
    if (new_sz == s->len)
        return 1;

    /* truncate string */
    if (new_sz <= s->len)
    {
        s->len = new_sz;
        s->str[s->len] = 0;
        return 1;
    }

    /* increase string size */
    if (!cstr_alloc_min_sz(s, new_sz))
        return 0;

    /* contents of string tail undefined */

    s->len = new_sz;
    s->str[s->len] = 0;

    return 1;
}

int cstr_append_buf(cstring* s, const void* buf, size_t sz)
{
    if (!cstr_alloc_min_sz(s, s->len + sz))
        return 0;

    memcpy(s->str + s->len, buf, sz);
    s->len += sz;
    s->str[s->len] = 0;

    return 1;
}

int cstr_append_cstr(cstring* s, cstring* append)
{
    return cstr_append_buf(s, append->str, append->len);
}

int cstr_append_c(cstring* s, char ch)
{
    return cstr_append_buf(s, &ch, 1);
}

int cstr_equal(const cstring* a, const cstring* b)
{
    if (a == b)
        return 1;
    if (!a || !b)
        return 0;
    if (a->len != b->len)
        return 0;
    return (memcmp(a->str, b->str, a->len) == 0);
}

int cstr_compare(const cstring* a, const cstring* b)
{
    unsigned int i;
    if (a->len > b->len)
        return (1);
    if (a->len < b->len)
        return (-1);

    /* length equal, byte per byte compare */
    for (i = 0; i < a->len; i++)
    {
        char a1 = a->str[i];
        char b1 = b->str[i];

        if (a1 > b1)
            return (1);
        if (a1 < b1)
            return (-1);
    }
    return (0);
}

int cstr_erase(cstring* s, size_t pos, ssize_t len)
{
    ssize_t old_tail;

    if (pos == s->len && len == 0)
        return 1;
    if (pos >= s->len)
        return 0;

    old_tail = s->len - pos;
    if ((len >= 0) && (len > old_tail))
        return 0;

    memmove(&s->str[pos], &s->str[pos + len], old_tail - len);
    s->len -= len;
    s->str[s->len] = 0;

    return 1;
}

dvector* vector_new(size_t res, void (*free_f)(void*))
{
    dvector* vec = btc_calloc(1, sizeof(dvector));
    if (!vec)
        return NULL;

    vec->alloc = 8;
    while (vec->alloc < res)
        vec->alloc *= 2;

    vec->elem_free_f = free_f;
    vec->data = btc_malloc(vec->alloc * sizeof(void*));
    if (!vec->data)
    {
        btc_free(vec);
        return NULL;
    }

    return vec;
}

static void vector_free_data(dvector* vec)
{
    if (!vec->data)
        return;

    if (vec->elem_free_f)
    {
        unsigned int i;
        for (i = 0; i < vec->len; i++)
            if (vec->data[i])
            {
                vec->elem_free_f(vec->data[i]);
                vec->data[i] = NULL;
            }
    }

    btc_free(vec->data);
    vec->data = NULL;
    vec->alloc = 0;
    vec->len = 0;
}

void vector_free(dvector* vec, btc_bool free_array)
{
    if (!vec)
        return;

    if (free_array)
        vector_free_data(vec);

    memset(vec, 0, sizeof(*vec));
    btc_free(vec);
}

static btc_bool vector_grow(dvector* vec, size_t min_sz)
{
    size_t new_alloc = vec->alloc;
    while (new_alloc < min_sz)
        new_alloc *= 2;

    if (vec->alloc == new_alloc)
        return true;

    void* new_data = btc_realloc(vec->data, new_alloc * sizeof(void*));
    if (!new_data)
        return false;

    vec->data = new_data;
    vec->alloc = new_alloc;
    return true;
}

ssize_t vector_find(dvector* vec, void* data)
{
    if (vec && vec->len)
    {
        size_t i;
        for (i = 0; i < vec->len; i++)
            if (vec->data[i] == data)
                return (ssize_t)i;
    }

    return -1;
}

btc_bool vector_add(dvector* vec, void* data)
{
    if (vec->len == vec->alloc)
        if (!vector_grow(vec, vec->len + 1))
            return false;

    vec->data[vec->len] = data;
    vec->len++;
    return true;
}

void vector_remove_range(dvector* vec, size_t pos, size_t len)
{
    if (!vec || ((pos + len) > vec->len))
        return;

    if (vec->elem_free_f)
    {
        unsigned int i, count;
        for (i = (unsigned int)pos, count = 0; count < len; i++, count++)
            vec->elem_free_f(vec->data[i]);
    }

    memmove(&vec->data[pos], &vec->data[pos + len], (vec->len - pos - len) * sizeof(void*));
    vec->len -= len;
}

void vector_remove_idx(dvector* vec, size_t pos)
{
    vector_remove_range(vec, pos, 1);
}

btc_bool vector_remove(dvector* vec, void* data)
{
    ssize_t idx = vector_find(vec, data);
    if (idx < 0)
        return false;

    vector_remove_idx(vec, idx);
    return true;
}

btc_bool vector_resize(dvector* vec, size_t newsz)
{
    unsigned int i;

    /* same size */
    if (newsz == vec->len)
        return true;

    /* truncate */
    else if (newsz < vec->len)
    {
        size_t del_count = vec->len - newsz;

        for (i = (unsigned int)(vec->len - del_count); i < vec->len; i++)
        {
            if (vec->elem_free_f)
                vec->elem_free_f(vec->data[i]);
            vec->data[i] = NULL;
        }

        vec->len = newsz;
        return true;
    }

    /* last possibility: grow */
    if (!vector_grow(vec, newsz))
        return false;

    /* set new elements to NULL */
    for (i = (unsigned int)vec->len; i < newsz; i++)
        vec->data[i] = NULL;

    return true;
}

int buffer_equal(const void* a_, const void* b_)
{
    const struct buffer* a = a_;
    const struct buffer* b = b_;

    if (a->len != b->len)
        return 0;
    return memcmp(a->p, b->p, a->len) == 0;
}

void buffer_free(void* struct_buffer)
{
    struct buffer* buf = struct_buffer;
    if (!buf)
        return;

    btc_free(buf->p);
    btc_free(buf);
}

struct buffer* buffer_copy(const void* data, size_t data_len)
{
    struct buffer* buf;
    buf = btc_malloc(sizeof(*buf));
    if (!buf)
        goto err_out;

    buf->p = btc_malloc(data_len);
    if (!buf->p)
        goto err_out_free;

    memcpy(buf->p, data, data_len);
    buf->len = data_len;

    return buf;

err_out_free:
    btc_free(buf);
err_out:
    return NULL;
}

int btc_base58_decode(void* bin, size_t* binszp, const char* b58)
{
    return b58tobin(bin, binszp, b58, (int)strlen(b58));
}

int btc_b58check(const void* bin, size_t binsz, const char* base58str)
{
    return b58check(bin, binsz, base58str);
}

int btc_base58_encode(char* b58, size_t* b58sz, const void* data, size_t binsz)
{
    return b58enc(b58, b58sz, data, binsz);
}

int btc_base58_encode_check(const uint8_t* data, int datalen, char* str, int strsize)
{
    return base58_encode_check(data, datalen, str, strsize);
}

int btc_base58_decode_check(const char* str, uint8_t* data, size_t datalen)
{
    int res = base58_decode_check(str, data, (int)datalen);
    if (res > 0)
    {
        res += 4;
    }
    return res;
}

btc_bool btc_p2pkh_addr_from_hash160(const uint160 hashin, const sc_chainparams* chain, char* addrout, int len)
{
    uint8_t hash160[sizeof(uint160) + B58_PREFIX_MAX_SIZE];
    size_t offset = base58_prefix_dump(chain->b58prefix_pubkey_address, hash160);
    memcpy(hash160 + offset, hashin, sizeof(uint160));

    return (btc_base58_encode_check(hash160, sizeof(hash160) + (int)offset, addrout, len) > 0);
}

btc_bool btc_p2sh_addr_from_hash160(const uint160 hashin, const sc_chainparams* chain, char* addrout, int len)
{
    uint8_t hash160[sizeof(uint160) + B58_PREFIX_MAX_SIZE];
    size_t offset = base58_prefix_dump(chain->b58prefix_script_address, hash160);
    memcpy(hash160 + offset, hashin, sizeof(uint160));

    return (btc_base58_encode_check(hash160, sizeof(uint160) + (int)offset, addrout, len) > 0);
}

btc_bool btc_p2wpkh_addr_from_hash160(const uint160 hashin, const sc_chainparams* chain, char* addrout)
{
    return bech32_address_encode(addrout, chain->bech32_hrp, 0, hashin, sizeof(uint160));
}

btc_bool base58_prefix_partition(uint16_t prefix16bits, uint8_t* prefix0bits, uint8_t* prefix8bits)
{
    if (prefix0bits)
        *prefix0bits = (prefix16bits >> 8) & 0x00FF;
    if (prefix8bits)
        *prefix8bits = prefix16bits & 0x00FF;
    return true;
}

btc_bool base58_prefix_check(uint16_t prefix16bits, const uint8_t* hash160)
{
    uint8_t prefix0bits, prefix8bits;
    base58_prefix_partition(prefix16bits, &prefix0bits, &prefix8bits);

    size_t prefix_size = base58_prefix_size(prefix16bits);
    if (prefix_size == 1)
        return hash160[0] == prefix0bits;

    if (prefix_size == 2)
        return hash160[0] == prefix0bits && hash160[1] == prefix8bits;

    return false;
}

size_t base58_prefix_dump(uint16_t prefix16bits, uint8_t* hash160)
{
    uint8_t prefix0bits, prefix8bits;
    base58_prefix_partition(prefix16bits, &prefix0bits, &prefix8bits);

    hash160[0] = prefix0bits;
    if (!prefix8bits)
        return 1;

    hash160[1] = prefix8bits;
    return 2;
}

size_t base58_prefix_size(uint16_t prefix16bits)
{
    uint8_t prefix8bits;
    base58_prefix_partition(prefix16bits, NULL, &prefix8bits);
    return prefix8bits > 0 ? 2 : 1;
}

void utils_clear_buffers(void)
{
    memset(buffer_hex_to_uint8, 0, TO_UINT8_HEX_BUF_LEN);
    memset(buffer_uint8_to_hex, 0, TO_UINT8_HEX_BUF_LEN);
}

void utils_hex_to_bin(const char* str, unsigned char* out, int inLen, int* outLen)
{
    int bLen = inLen / 2;
    if (bLen > *outLen)
    {
        *outLen = 0;
        return;
    }

    int i;
    memset(out, 0, bLen);
    for (i = 0; i < bLen; i++)
    {
        if (str[i * 2] >= '0' && str[i * 2] <= '9')
        {
            *out = (str[i * 2] - '0') << 4;
        }
        if (str[i * 2] >= 'a' && str[i * 2] <= 'f')
        {
            *out = (10 + str[i * 2] - 'a') << 4;
        }
        if (str[i * 2] >= 'A' && str[i * 2] <= 'F')
        {
            *out = (10 + str[i * 2] - 'A') << 4;
        }
        if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9')
        {
            *out |= (str[i * 2 + 1] - '0');
        }
        if (str[i * 2 + 1] >= 'a' && str[i * 2 + 1] <= 'f')
        {
            *out |= (10 + str[i * 2 + 1] - 'a');
        }
        if (str[i * 2 + 1] >= 'A' && str[i * 2 + 1] <= 'F')
        {
            *out |= (10 + str[i * 2 + 1] - 'A');
        }
        out++;
    }
    *outLen = i;
}

uint8_t* utils_hex_to_uint8(const char* str)
{
    uint8_t c;
    size_t i;
    if (strlens(str) > TO_UINT8_HEX_BUF_LEN)
    {
        return NULL;
    }
    memset(buffer_hex_to_uint8, 0, TO_UINT8_HEX_BUF_LEN);
    for (i = 0; i < strlens(str) / 2; i++)
    {
        c = 0;
        if (str[i * 2] >= '0' && str[i * 2] <= '9')
        {
            c += (str[i * 2] - '0') << 4;
        }
        if (str[i * 2] >= 'a' && str[i * 2] <= 'f')
        {
            c += (10 + str[i * 2] - 'a') << 4;
        }
        if (str[i * 2] >= 'A' && str[i * 2] <= 'F')
        {
            c += (10 + str[i * 2] - 'A') << 4;
        }
        if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9')
        {
            c += (str[i * 2 + 1] - '0');
        }
        if (str[i * 2 + 1] >= 'a' && str[i * 2 + 1] <= 'f')
        {
            c += (10 + str[i * 2 + 1] - 'a');
        }
        if (str[i * 2 + 1] >= 'A' && str[i * 2 + 1] <= 'F')
        {
            c += (10 + str[i * 2 + 1] - 'A');
        }
        buffer_hex_to_uint8[i] = c;
    }
    return buffer_hex_to_uint8;
}

void utils_bin_to_hex(unsigned char* bin_in, size_t inlen, char* hex_out)
{
    static char digits[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < inlen; i++)
    {
        hex_out[i * 2] = digits[(bin_in[i] >> 4) & 0xF];
        hex_out[i * 2 + 1] = digits[bin_in[i] & 0xF];
    }
    hex_out[inlen * 2] = '\0';
}

char* utils_uint8_to_hex(const uint8_t* bin, size_t l)
{
    static char digits[] = "0123456789abcdef";
    size_t i;
    if (l > (TO_UINT8_HEX_BUF_LEN / 2 - 1))
    {
        return NULL;
    }
    memset(buffer_uint8_to_hex, 0, TO_UINT8_HEX_BUF_LEN);
    for (i = 0; i < l; i++)
    {
        buffer_uint8_to_hex[i * 2] = digits[(bin[i] >> 4) & 0xF];
        buffer_uint8_to_hex[i * 2 + 1] = digits[bin[i] & 0xF];
    }
    buffer_uint8_to_hex[l * 2] = '\0';
    return buffer_uint8_to_hex;
}

void utils_reverse_hex(char* h, int len)
{
    char* copy = btc_malloc(len);
    int i;
    strncpy(copy, h, len);
    for (i = 0; i < len; i += 2)
    {
        h[i] = copy[len - i - 2];
        h[i + 1] = copy[len - i - 1];
    }
    btc_free(copy);
}

signed char utils_hex_digit(char c)
{
    return p_util_hexdigit[(unsigned char)c];
}

void utils_uint256_sethex(char* psz, uint8_t* out)
{
    memset(out, 0, sizeof(uint256));

    // skip leading spaces
    while (isspace(*psz))
        psz++;

    // skip 0x
    if (psz[0] == '0' && tolower(psz[1]) == 'x')
        psz += 2;

    // hex string to uint
    const char* pbegin = psz;
    while (utils_hex_digit(*psz) != -1)
        psz++;
    psz--;
    unsigned char* p1 = (unsigned char*)out;
    unsigned char* pend = p1 + sizeof(uint256);
    while (psz >= pbegin && p1 < pend)
    {
        *p1 = utils_hex_digit(*psz--);
        if (psz >= pbegin)
        {
            *p1 |= ((unsigned char)utils_hex_digit(*psz--) << 4);
            p1++;
        }
    }
}

void* safe_malloc(size_t size)
{
    void* result;

    if ((result = malloc(size)))
    { /* assignment intentional */
        return (result);
    }
    else
    {
        printf("memory overflow: malloc failed in safe_malloc.");
        printf("  Exiting Program.\n");
        exit(-1);
        return (0);
    }
}

void btc_cheap_random_bytes(uint8_t* buf, uint32_t len)
{
    srand((unsigned int)time(NULL));
    for (uint32_t i = 0; i < len; i++)
    {
        buf[i] = rand();
    }
}

void btc_get_default_datadir(cstring* path_out)
{
    // Windows < Vista: C:\Documents and Settings\Username\Application Data\Bitcoin
    // Windows >= Vista: C:\Users\Username\AppData\Roaming\Bitcoin
    // Mac: ~/Library/Application Support/Bitcoin
    // Unix: ~/.bitcoin
#ifdef WIN32
    // Windows
    char* homedrive = getenv("HOMEDRIVE");
    char* homepath = getenv("HOMEDRIVE");
    cstr_append_buf(path_out, homedrive, strlen(homedrive));
    cstr_append_buf(path_out, homepath, strlen(homepath));
#else
    char* home = getenv("HOME");
    if (home == NULL || strlen(home) == 0)
        cstr_append_c(path_out, '/');
    else
        cstr_append_buf(path_out, home, strlen(home));
#ifdef __APPLE__
    // Mac
    char* osx_home = "/Library/Application Support/Bitcoin";
    cstr_append_buf(path_out, osx_home, strlen(osx_home));
#else
    // Unix
    char* posix_home = "/.bitcoin";
    cstr_append_buf(path_out, posix_home, strlen(posix_home));
#endif
#endif
}

void btc_file_commit(FILE* file)
{
    fflush(file); // harmless if redundantly called
#ifdef WIN32
    HANDLE hFile = (HANDLE)_get_osfhandle(_fileno(file));
    FlushFileBuffers(hFile);
#else
#if defined(__linux__) || defined(__NetBSD__)
    fdatasync(fileno(file));
#elif defined(__APPLE__) && defined(F_FULLFSYNC)
    fcntl(fileno(file), F_FULLFSYNC, 0);
#else
    fsync(fileno(file));
#endif
#endif
}

void btc_tagged_hash(enum btc_tagged_prefixes prefix, const uint8_t* message, size_t message_size, uint256 hash)
{
    SHA256_CTX context;
    sha256_Init(&context);
    sha256_Update(&context, tagged_hash_prefixes[prefix], sizeof(tagged_hash_prefixes[prefix]));
    sha256_Update(&context, message, message_size);
    sha256_Final(&context, hash);
}

void btc_ecc_set_context(secp256k1_context* new_secp256k1_ctx)
{
    secp256k1_ctx = new_secp256k1_ctx;
}

void btc_ecc_get_pubkey(const uint8_t* private_key, uint8_t* public_key, size_t* in_outlen, btc_bool compressed)
{
    secp256k1_pubkey pubkey;
    assert(secp256k1_ctx);
    assert((int)*in_outlen == (compressed ? 33 : 65));
    memset(public_key, 0, *in_outlen);

    if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &pubkey, (const unsigned char*)private_key))
    {
        return;
    }

    if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, public_key, in_outlen, &pubkey, compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED))
    {
        return;
    }

    return;
}

btc_bool btc_ecc_private_key_tweak_add(uint8_t* private_key, const uint8_t* tweak)
{
    assert(secp256k1_ctx);
    return secp256k1_ec_seckey_tweak_add(secp256k1_ctx, (unsigned char*)private_key, (const unsigned char*)tweak);
}

btc_bool btc_ecc_public_key_tweak_add(uint8_t* public_key_inout, const uint8_t* tweak)
{
    size_t out = BTC_ECKEY_COMPRESSED_LENGTH;
    secp256k1_pubkey pubkey;

    assert(secp256k1_ctx);
    if (!secp256k1_ec_pubkey_parse(secp256k1_ctx, &pubkey, public_key_inout, 33))
        return false;

    if (!secp256k1_ec_pubkey_tweak_add(secp256k1_ctx, &pubkey, (const unsigned char*)tweak))
        return false;

    if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, public_key_inout, &out, &pubkey, SECP256K1_EC_COMPRESSED))
        return false;

    return true;
}

btc_bool btc_xonly_public_key_tweak_add(uint8_t* public_key_inout, const uint8_t* tweak)
{
    secp256k1_xonly_pubkey pubkey;

    assert(secp256k1_ctx);
    if (!secp256k1_xonly_pubkey_parse(secp256k1_ctx, &pubkey, public_key_inout))
        return false;

    secp256k1_pubkey tweak_pubkey;
    if (!secp256k1_xonly_pubkey_tweak_add(secp256k1_ctx, &tweak_pubkey, &pubkey, (const unsigned char*)tweak))
        return false;

    size_t out = BTC_ECKEY_UNCOMPRESSED_LENGTH;
    uint8_t serialized_pubkey[BTC_ECKEY_UNCOMPRESSED_LENGTH];
    if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, serialized_pubkey, &out, &tweak_pubkey, SECP256K1_EC_UNCOMPRESSED))
        return false;

    memcpy(public_key_inout, serialized_pubkey + 1, 32);
    return true;
}

btc_bool btc_ecc_verify_privatekey(const uint8_t* private_key)
{
    assert(secp256k1_ctx);
    return secp256k1_ec_seckey_verify(secp256k1_ctx, (const unsigned char*)private_key);
}

btc_bool btc_ecc_verify_pubkey(const uint8_t* public_key, btc_bool compressed)
{
    secp256k1_pubkey pubkey;

    assert(secp256k1_ctx);
    if (!secp256k1_ec_pubkey_parse(secp256k1_ctx, &pubkey, public_key, compressed ? 33 : 65))
    {
        memset(&pubkey, 0, sizeof(pubkey));
        return false;
    }

    memset(&pubkey, 0, sizeof(pubkey));
    return true;
}

btc_bool btc_ecc_sign(const uint8_t* private_key, const uint256 hash, unsigned char* sigder, size_t* outlen)
{
    assert(secp256k1_ctx);

    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(secp256k1_ctx, &sig, hash, private_key, secp256k1_nonce_function_rfc6979, NULL))
        return 0;

    if (!secp256k1_ecdsa_signature_serialize_der(secp256k1_ctx, sigder, outlen, &sig))
        return 0;

    return 1;
}

btc_bool btc_ecc_sign_compact(const uint8_t* private_key, const uint256 hash, unsigned char* sigcomp, size_t* outlen)
{
    assert(secp256k1_ctx);

    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(secp256k1_ctx, &sig, hash, private_key, secp256k1_nonce_function_rfc6979, NULL))
        return 0;

    *outlen = 64;
    if (!secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx, sigcomp, &sig))
        return 0;

    return 1;
}

btc_bool btc_ecc_sign_compact_recoverable(const uint8_t* private_key, const uint256 hash, unsigned char* sigrec, size_t* outlen, int* recid)
{
    assert(secp256k1_ctx);

    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_sign_recoverable(secp256k1_ctx, &sig, hash, private_key, secp256k1_nonce_function_rfc6979, NULL))
        return 0;

    *outlen = 65;
    if (!secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_ctx, sigrec, recid, &sig))
        return 0;

    return 1;
}

btc_bool btc_ecc_recover_pubkey(const unsigned char* sigrec, const uint256 hash, const int recid, uint8_t* public_key, size_t* outlen)
{
    assert(secp256k1_ctx);

    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_recoverable_signature sig;

    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_ctx, &sig, sigrec, recid))
        return false;

    if (!secp256k1_ecdsa_recover(secp256k1_ctx, &pubkey, &sig, hash))
        return 0;

    if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, public_key, outlen, &pubkey, SECP256K1_EC_COMPRESSED))
        return 0;

    return 1;
}

btc_bool btc_ecc_verify_sig(const uint8_t* public_key, btc_bool compressed, const uint256 hash, unsigned char* sigder, size_t siglen)
{
    assert(secp256k1_ctx);

    secp256k1_ecdsa_signature sig;
    secp256k1_pubkey pubkey;

    if (!secp256k1_ec_pubkey_parse(secp256k1_ctx, &pubkey, public_key, compressed ? 33 : 65))
        return false;

    if (!secp256k1_ecdsa_signature_parse_der(secp256k1_ctx, &sig, sigder, siglen))
        return false;

    return secp256k1_ecdsa_verify(secp256k1_ctx, &sig, hash, &pubkey);
}

btc_bool btc_ecc_compact_to_der_normalized(const unsigned char* sigcomp_in, unsigned char* sigder_out, size_t* sigder_len_out)
{
    assert(secp256k1_ctx);

    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_signature_parse_compact(secp256k1_ctx, &sig, sigcomp_in))
        return false;

    secp256k1_ecdsa_signature sigNorm;
    secp256k1_ecdsa_signature_normalize(secp256k1_ctx, &sigNorm, &sig);

    return secp256k1_ecdsa_signature_serialize_der(secp256k1_ctx, sigder_out, sigder_len_out, &sigNorm);
}

btc_bool btc_ecc_der_to_compact(unsigned char* sigder_in, size_t sigder_len, unsigned char* sigcomp_out)
{
    assert(secp256k1_ctx);

    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_signature_parse_der(secp256k1_ctx, &sig, sigder_in, sigder_len))
        return false;

    return secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx, sigcomp_out, &sig);
}

btc_bool btc_ecc_sign_schnorr(const uint8_t* private_key, const uint256 hash, const uint256 auxiliary, unsigned char* sigcomp, size_t* outlen)
{
    assert(secp256k1_ctx);

    secp256k1_keypair keypair;
    if (secp256k1_keypair_create(secp256k1_ctx, &keypair, private_key) != 1)
        return 0;

    *outlen = 64;
    if (secp256k1_schnorrsig_sign32(secp256k1_ctx, sigcomp, hash, &keypair, auxiliary) != 1)
        return 0;

    return 1;
}

btc_bool btc_ecc_tagged_sha256(const uint8_t* message, size_t message_size, const uint8_t* tag, size_t tag_size, uint256 hash_out)
{
    assert(secp256k1_ctx);
    return secp256k1_tagged_sha256(secp256k1_ctx, hash_out, tag, tag_size, message, message_size) == 1;
}

void btc_privkey_init(btc_key* privkey)
{
    memset(&privkey->privkey, 0, BTC_ECKEY_PKEY_LENGTH);
}

btc_bool btc_privkey_is_valid(const btc_key* privkey)
{
    if (!privkey)
    {
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

    do
    {
        random_buffer(privkey->privkey, BTC_ECKEY_PKEY_LENGTH);
    } while (btc_ecc_verify_privatekey(privkey->privkey) == 0);
    return true;
}

btc_bool btc_privkey_verify_pubkey(btc_key* privkey, btc_pubkey* pubkey)
{
    uint256 rnddata, hash;
    random_buffer(rnddata, BTC_HASH_LENGTH);
    btc_hash(rnddata, BTC_HASH_LENGTH, hash);

    unsigned char sig[74];
    size_t siglen = 74;

    if (!btc_key_sign_hash(privkey, hash, sig, &siglen))
        return false;

    return btc_pubkey_verify_sig(pubkey, hash, sig, (int)siglen);
}

void btc_privkey_encode_wif(const btc_key* privkey, const sc_chainparams* chain, char* privkey_wif, size_t* strsize_inout)
{
    uint8_t pkeybase58c[34];
    pkeybase58c[0] = chain->b58prefix_secret_address;
    pkeybase58c[33] = 1; /* always use compressed keys */

    memcpy(&pkeybase58c[1], privkey->privkey, BTC_ECKEY_PKEY_LENGTH);
    int status = btc_base58_encode_check(pkeybase58c, 34, privkey_wif, (int)*strsize_inout);
    assert(status != 0);
    btc_mem_zero(&pkeybase58c, 34);
}

btc_bool btc_privkey_decode_wif(const char* privkey_wif, const sc_chainparams* chain, btc_key* privkey)
{

    if (!privkey_wif || strlen(privkey_wif) < 50)
    {
        return false;
    }

    const size_t privkey_len = strlen(privkey_wif);
    uint8_t* privkey_data = (uint8_t*)btc_malloc(privkey_len);
    memset(privkey_data, 0, privkey_len);
    size_t outlen = 0;

    outlen = btc_base58_decode_check(privkey_wif, privkey_data, privkey_len);
    if (!outlen)
    {
        btc_free(privkey_data);
        return false;
    }
    if (privkey_data[0] != chain->b58prefix_secret_address)
    {
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

    uint256 tweak_hash;
    btc_key_get_taproot_tweak(&pubkey, leaf_hash, tweak_hash);

    uint256 tweak_privkey;
    memcpy(tweak_privkey, privkey->privkey, sizeof(privkey->privkey));
    btc_ecc_private_key_tweak_add(tweak_privkey, tweak_hash);
    memcpy(hash256, tweak_privkey, sizeof(tweak_privkey));
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

    ripemd160(hashout, sizeof(hashout), hash160);
}

void btc_pubkey_get_taproot_pubkey(const btc_pubkey* pubkey, const uint256 leaf_hash, uint256 hash256)
{
    uint256 tweak_hash;
    btc_key_get_taproot_tweak(pubkey, leaf_hash, tweak_hash);

    uint8_t tweaked_pubkey[33];
    memcpy(tweaked_pubkey, pubkey->pubkey, sizeof(tweaked_pubkey));
    btc_ecc_public_key_tweak_add(tweaked_pubkey, tweak_hash);
    memcpy(hash256, tweaked_pubkey + 1, sizeof(tweaked_pubkey) - 1);
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

void btc_key_get_taproot_tweak(const btc_pubkey* pubkey, const uint256 leaf_hash, uint256 hash256)
{
    cstring* control_block = cstr_new_sz(64);
    btc_controlblock_append_internalpubkey(control_block, pubkey);
    if (leaf_hash)
        btc_controlblock_append_leafscripthash(control_block, leaf_hash);

    btc_tagged_hash(BTC_TAG_TAP_TWEAK, (const uint8_t*)control_block->str, control_block->len, hash256);
    cstr_free(control_block, true);
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

btc_bool btc_pubkey_getaddr_p2pk(const btc_pubkey* pubkey, const sc_chainparams* chain, char* addrout)
{
    utils_bin_to_hex((unsigned char*)pubkey->pubkey, pubkey->compressed ? BTC_ECKEY_COMPRESSED_LENGTH : BTC_ECKEY_UNCOMPRESSED_LENGTH, addrout);
    return true;
}

btc_bool btc_pubkey_getaddr_p2pkh(const btc_pubkey* pubkey, const sc_chainparams* chain, char* addrout)
{
    uint8_t hash[sizeof(uint160) + B58_PREFIX_MAX_SIZE]; size_t hash_offset;
    btc_pubkey_getaddr_p2pkh_hash(pubkey, chain, hash, &hash_offset);
    btc_base58_encode_check(hash, sizeof(uint160) + (int)hash_offset, addrout, 100);
    return true;
}

btc_bool btc_pubkey_getaddr_p2pkh_hash(const btc_pubkey* pubkey, const sc_chainparams* chain, uint8_t* hash, size_t* hash_offset)
{
    size_t offset = base58_prefix_dump(chain->b58prefix_pubkey_address, hash);
    btc_pubkey_get_hash160(pubkey, hash + offset);
    if (hash_offset)
        *hash_offset = offset;
    return true;
}

btc_bool btc_pubkey_getaddr_p2sh_p2wpkh(const btc_pubkey* pubkey, const sc_chainparams* chain, char* addrout)
{
    uint8_t hash[sizeof(uint160) + B58_PREFIX_MAX_SIZE]; size_t hash_offset;
    btc_pubkey_getaddr_p2sh_p2wpkh_hash(pubkey, chain, hash, &hash_offset);
    btc_base58_encode_check(hash, sizeof(uint160) + (int)hash_offset, addrout, 100);
    return true;
}

btc_bool btc_pubkey_getaddr_p2sh_p2wpkh_hash(const btc_pubkey* pubkey, const sc_chainparams* chain, uint8_t* hash, size_t* hash_offset)
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

btc_bool btc_pubkey_getaddr_p2wsh_p2pkh(const btc_pubkey* pubkey, const sc_chainparams* chain, char* addrout)
{
    uint8_t hash160[sizeof(uint8_t) * 32];
    btc_pubkey_getaddr_p2wsh_p2pkh_hash(pubkey, chain, hash160);
    bech32_address_encode(addrout, chain->bech32_hrp, 0, hash160, sizeof(hash160));
    return true;
}

btc_bool btc_pubkey_getaddr_p2wsh_p2pkh_hash(const btc_pubkey* pubkey, const sc_chainparams* chain, uint8_t* hash)
{
    cstring* wscript = cstr_new_sz(22);
    uint160 keyhash;
    btc_pubkey_get_hash160(pubkey, keyhash);
    btc_script_build_p2pkh(wscript, keyhash);
    btc_hash_sngl_sha256((const unsigned char*)wscript->str, wscript->len, hash);
    cstr_free(wscript, true);
    return true;
}

btc_bool btc_pubkey_getaddr_p2wpkh(const btc_pubkey* pubkey, const sc_chainparams* chain, char* addrout)
{
    uint8_t hash[sizeof(uint160)];
    btc_pubkey_getaddr_p2wpkh_hash(pubkey, chain, hash);
    bech32_address_encode(addrout, chain->bech32_hrp, 0, hash, sizeof(hash));
    return true;
}

btc_bool btc_pubkey_getaddr_p2wpkh_hash(const btc_pubkey* pubkey, const sc_chainparams* chain, uint8_t* hash)
{
    btc_pubkey_get_hash160(pubkey, hash);
    return true;
}

btc_bool btc_pubkey_getaddr_p2tr(const btc_pubkey* pubkey, const sc_chainparams* chain, char* addrout)
{
    uint8_t hash[sizeof(uint8_t) * 32];
    btc_pubkey_getaddr_p2tr_hash(pubkey, chain, hash);
    bech32_address_encode(addrout, chain->bech32_hrp, 1, hash, sizeof(hash));
    return true;
}

btc_bool btc_pubkey_getaddr_p2tr_hash(const btc_pubkey* pubkey, const sc_chainparams* chain, uint8_t* hash)
{
    btc_pubkey_get_taproot_pubkey(pubkey, NULL, hash);
    return true;
}

btc_bool btc_pubkey_getaddr_p2tr_p2pk(const btc_pubkey* pubkey, const sc_chainparams* chain, char* addrout)
{
    uint8_t hash[sizeof(uint8_t) * 32];
    btc_pubkey_getaddr_p2tr_p2pk_hash(pubkey, chain, hash);
    bech32_address_encode(addrout, chain->bech32_hrp, 1, hash, sizeof(hash));
    return true;
}

btc_bool btc_pubkey_getaddr_p2tr_p2pk_hash(const btc_pubkey* pubkey, const sc_chainparams* chain, uint8_t* hash)
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

btc_bool btc_script_copy_without_op_codeseperator(const cstring* script_in, cstring* script_out)
{
    if (script_in->len == 0)
        return false; /* EOF */

    struct const_buffer buf = { script_in->str, script_in->len };
    unsigned char opcode;
    while (buf.len > 0)
    {
        if (!deser_bytes(&opcode, &buf, 1))
            goto err_out;

        uint32_t data_len = 0;

        if (opcode < OP_PUSHDATA1 && opcode > OP_0)
        {
            data_len = opcode;
            cstr_append_buf(script_out, &opcode, 1);
        }
        else if (opcode == OP_PUSHDATA1)
        {
            uint8_t v8;
            if (!deser_bytes(&v8, &buf, 1))
                goto err_out;
            cstr_append_buf(script_out, &opcode, 1);
            cstr_append_buf(script_out, &v8, 1);
            data_len = v8;
        }
        else if (opcode == OP_PUSHDATA2)
        {
            uint16_t v16;
            if (!deser_u16(&v16, &buf))
                goto err_out;
            cstr_append_buf(script_out, &opcode, 1);
            cstr_append_buf(script_out, &v16, 2);
            data_len = v16;
        }
        else if (opcode == OP_PUSHDATA4)
        {
            uint32_t v32;
            if (!deser_u32(&v32, &buf))
                goto err_out;
            cstr_append_buf(script_out, &opcode, 1);
            cstr_append_buf(script_out, &v32, 5);
            data_len = v32;
        }
        else if (opcode == OP_CODESEPARATOR)
            continue;

        if (data_len > 0)
        {
            assert(data_len < 16777215); //limit max push to 0xFFFFFF
            unsigned char* bufpush = (unsigned char*)btc_malloc(data_len);
            deser_bytes(bufpush, &buf, data_len);
            cstr_append_buf(script_out, bufpush, data_len);
            btc_free(bufpush);
        }
        else
            cstr_append_buf(script_out, &opcode, 1);
    }

    return true;

err_out:
    return false;
}

btc_script_op* btc_script_op_new()
{
    btc_script_op* script_op;
    script_op = btc_calloc(1, sizeof(btc_script_op));

    return script_op;
}

void btc_script_op_free(btc_script_op* script_op)
{
    if (script_op->data)
    {
        btc_free(script_op->data);
        script_op->data = NULL;
    }
    script_op->datalen = 0;
    script_op->op = OP_0;
}

void btc_script_op_free_cb(void* data)
{
    btc_script_op* script_op = data;
    btc_script_op_free(script_op);

    btc_free(script_op);
}

btc_bool btc_script_get_ops(const cstring* script_in, dvector* ops_out)
{
    if (script_in->len == 0)
        return false; /* EOF */

    struct const_buffer buf = { script_in->str, script_in->len };
    unsigned char opcode;

    btc_script_op* op = NULL;
    while (buf.len > 0)
    {
        op = btc_script_op_new();

        if (!deser_bytes(&opcode, &buf, 1))
            goto err_out;

        op->op = opcode;

        uint32_t data_len;

        if (opcode < OP_PUSHDATA1)
        {
            data_len = opcode;
        }
        else if (opcode == OP_PUSHDATA1)
        {
            uint8_t v8;
            if (!deser_bytes(&v8, &buf, 1))
                goto err_out;
            data_len = v8;
        }
        else if (opcode == OP_PUSHDATA2)
        {
            uint16_t v16;
            if (!deser_u16(&v16, &buf))
                goto err_out;
            data_len = v16;
        }
        else if (opcode == OP_PUSHDATA4)
        {
            uint32_t v32;
            if (!deser_u32(&v32, &buf))
                goto err_out;
            data_len = v32;
        }
        else
        {
            vector_add(ops_out, op);
            continue;
        }

        // don't alloc a push buffer if there is no more data available
        if (buf.len == 0 || data_len > buf.len)
        {
            goto err_out;
        }

        op->data = btc_calloc(1, data_len);
        memcpy(op->data, buf.p, data_len);
        op->datalen = data_len;

        vector_add(ops_out, op);

        if (!deser_skip(&buf, data_len))
            goto err_out;
    }

    return true;
err_out:
    btc_script_op_free_cb(op);
    return false;
}

static inline btc_bool btc_script_is_pushdata(const enum opcodetype op)
{
    return (op <= OP_PUSHDATA4);
}

static btc_bool btc_script_is_op(const btc_script_op* op, enum opcodetype opcode)
{
    return (op->op == opcode);
}

static btc_bool btc_script_is_op_pubkey(const btc_script_op* op)
{
    if (!btc_script_is_pushdata(op->op))
        return false;
    if (op->datalen != BTC_ECKEY_COMPRESSED_LENGTH && op->datalen != BTC_ECKEY_UNCOMPRESSED_LENGTH)
        return false;
    if (btc_pubkey_get_length(op->data[0]) != op->datalen)
    {
        return false;
    }
    return true;
}

static btc_bool btc_script_is_op_pubkeyhash(const btc_script_op* op)
{
    if (!btc_script_is_pushdata(op->op))
        return false;
    if (op->datalen != 20)
        return false;
    return true;
}

// OP_PUBKEY, OP_CHECKSIG
btc_bool btc_script_is_pubkey(const dvector* ops, dvector* data_out)
{
    if ((ops->len == 2) &&
            btc_script_is_op(vector_idx(ops, 1), OP_CHECKSIG) &&
            btc_script_is_op_pubkey(vector_idx(ops, 0)))
    {
        if (data_out)
        {
            //copy the full pubkey (33 or 65) in case of a non empty dvector
            const btc_script_op* op = vector_idx(ops, 0);
            uint8_t* buffer = btc_calloc(1, op->datalen);
            memcpy(buffer, op->data, op->datalen);
            vector_add(data_out, buffer);
        }
        return true;
    }
    return false;
}

// OP_DUP, OP_HASH160, OP_PUBKEYHASH, OP_EQUALVERIFY, OP_CHECKSIG,
btc_bool btc_script_is_pubkeyhash(const dvector* ops, dvector* data_out)
{
    if ((ops->len == 5) &&
        btc_script_is_op(vector_idx(ops, 0), OP_DUP) &&
        btc_script_is_op(vector_idx(ops, 1), OP_HASH160) &&
        btc_script_is_op_pubkeyhash(vector_idx(ops, 2)) &&
        btc_script_is_op(vector_idx(ops, 3), OP_EQUALVERIFY) &&
        btc_script_is_op(vector_idx(ops, 4), OP_CHECKSIG))
    {
        if (data_out)
        {
            //copy the data (hash160) in case of a non empty dvector
            const btc_script_op* op = vector_idx(ops, 2);
            uint8_t* buffer = btc_calloc(1, sizeof(uint160));
            memcpy(buffer, op->data, sizeof(uint160));
            vector_add(data_out, buffer);
        }
        return true;
    }
    return false;
}

// OP_HASH160, OP_PUBKEYHASH, OP_EQUAL
btc_bool btc_script_is_scripthash(const dvector* ops, dvector* data_out)
{
    if ((ops->len == 3) &&
            btc_script_is_op(vector_idx(ops, 0), OP_HASH160) &&
            btc_script_is_op_pubkeyhash(vector_idx(ops, 1)) &&
            btc_script_is_op(vector_idx(ops, 2), OP_EQUAL))
    {

        if (data_out)
        {
            //copy the data (hash160) in case of a non empty dvector
            const btc_script_op* op = vector_idx(ops, 1);
            uint8_t* buffer = btc_calloc(1, sizeof(uint160));
            memcpy(buffer, op->data, sizeof(uint160));
            vector_add(data_out, buffer);
        }

        return true;
    }
    return false;
}

static btc_bool btc_script_is_op_smallint(const btc_script_op* op)
{
    return ((op->op == OP_0) ||
            (op->op >= OP_1 && op->op <= OP_16));
}

btc_bool btc_script_is_multisig(const dvector* ops)
{
    if ((ops->len < 3) || (ops->len > (16 + 3)) ||
        !btc_script_is_op_smallint(vector_idx(ops, 0)) ||
        !btc_script_is_op_smallint(vector_idx(ops, ops->len - 2)) ||
        !btc_script_is_op(vector_idx(ops, ops->len - 1), OP_CHECKMULTISIG))
        return false;

    unsigned int i;
    for (i = 1; i < (ops->len - 2); i++)
        if (!btc_script_is_op_pubkey(vector_idx(ops, i)))
            return false;

    return true;
}

enum btc_tx_out_type btc_script_classify_ops(const dvector* ops)
{
    if (btc_script_is_pubkeyhash(ops, NULL))
        return BTC_TX_PUBKEYHASH;
    if (btc_script_is_scripthash(ops, NULL))
        return BTC_TX_SCRIPTHASH;
    if (btc_script_is_pubkey(ops, NULL))
        return BTC_TX_PUBKEY;
    if (btc_script_is_multisig(ops))
        return BTC_TX_MULTISIG;

    return BTC_TX_NONSTANDARD;
}

enum btc_tx_out_type btc_script_classify(const cstring* script, dvector* data_out)
{
    //INFO: could be speed up by not forming a dvector
    //      and directly parse the script cstring

    enum btc_tx_out_type tx_out_type = BTC_TX_NONSTANDARD;
    dvector* ops = vector_new(10, btc_script_op_free_cb);
    btc_script_get_ops(script, ops);

    if (btc_script_is_pubkeyhash(ops, data_out))
        tx_out_type = BTC_TX_PUBKEYHASH;
    if (btc_script_is_scripthash(ops, data_out))
        tx_out_type = BTC_TX_SCRIPTHASH;
    if (btc_script_is_pubkey(ops, data_out))
        tx_out_type = BTC_TX_PUBKEY;
    if (btc_script_is_multisig(ops))
        tx_out_type = BTC_TX_MULTISIG;
    uint8_t version = 0;
    uint8_t witness_program[40] = { 0 };
    int witness_program_len = 0;
    if (btc_script_is_witnessprogram(script, &version, witness_program, &witness_program_len))
    {
        if (version == 0 && witness_program_len == 20)
        {
            tx_out_type = BTC_TX_WITNESS_V0_PUBKEYHASH;
            if (data_out)
            {
                uint8_t* witness_program_cpy = btc_calloc(1, witness_program_len);
                memcpy(witness_program_cpy, witness_program, witness_program_len);
                vector_add(data_out, witness_program_cpy);
            }
        }
        if (version == 0 && witness_program_len == 32)
        {
            tx_out_type = BTC_TX_WITNESS_V0_SCRIPTHASH;
            if (data_out)
            {
                uint8_t* witness_program_cpy = btc_calloc(1, witness_program_len);
                memcpy(witness_program_cpy, witness_program, witness_program_len);
                vector_add(data_out, witness_program_cpy);
            }
        }
    }
    vector_free(ops, true);
    return tx_out_type;
}

enum opcodetype btc_encode_op_n(const int n)
{
    assert(n >= 0 && n <= 16);
    if (n == 0)
        return OP_0;
    return (enum opcodetype)(OP_1 + n - 1);
}

void btc_script_append_op(cstring* script_in, enum opcodetype op)
{
    cstr_append_buf(script_in, &op, 1);
}

void btc_script_append_pushdata(cstring* script_in, const unsigned char* data, const size_t datalen)
{
    if (datalen < OP_PUSHDATA1)
    {
        cstr_append_buf(script_in, (unsigned char*)&datalen, 1);
    }
    else if (datalen <= 0xff)
    {
        btc_script_append_op(script_in, OP_PUSHDATA1);
        cstr_append_buf(script_in, (unsigned char*)&datalen, 1);
    }
    else if (datalen <= 0xffff)
    {
        btc_script_append_op(script_in, OP_PUSHDATA2);
        uint16_t v = (uint16_t)htole16(datalen);
        cstr_append_buf(script_in, &v, sizeof(v));
    }
    else
    {
        btc_script_append_op(script_in, OP_PUSHDATA4);
        uint32_t v = (uint32_t)htole32(datalen);
        cstr_append_buf(script_in, &v, sizeof(v));
    }
    cstr_append_buf(script_in, data, datalen);
}

btc_bool btc_script_build_multisig(cstring* script_in, const unsigned int required_signatures, const dvector* pubkeys_chars)
{
    cstr_resize(script_in, 0); //clear script

    if (required_signatures > 16 || pubkeys_chars->len > 16)
        return false;
    enum opcodetype op_req_sig = btc_encode_op_n(required_signatures);
    cstr_append_buf(script_in, &op_req_sig, 1);

    int i;
    for (i = 0; i < (int)pubkeys_chars->len; i++)
    {
        btc_pubkey* pkey = pubkeys_chars->data[i];
        btc_script_append_pushdata(script_in, pkey->pubkey, (pkey->compressed ? BTC_ECKEY_COMPRESSED_LENGTH : BTC_ECKEY_UNCOMPRESSED_LENGTH));
    }

    enum opcodetype op_pub_len = btc_encode_op_n((int)pubkeys_chars->len);
    cstr_append_buf(script_in, &op_pub_len, 1);

    enum opcodetype op_checkmultisig = OP_CHECKMULTISIG;
    cstr_append_buf(script_in, &op_checkmultisig, 1);

    return true;
}

btc_bool btc_controlblock_append_version(cstring* controlblock_in, enum btc_tapscript_versions version)
{
    uint8_t version_byte = version;
    cstr_append_buf(controlblock_in, &version_byte, 1);
    return true;
}

btc_bool btc_controlblock_append_internalpubkey(cstring* controlblock_in, const btc_pubkey* pubkey)
{
    cstr_append_buf(controlblock_in, pubkey->pubkey + 1, BTC_ECKEY_COMPRESSED_LENGTH - 1);
    return true;
}

btc_bool btc_controlblock_append_leafscripthash(cstring* controlblock_in, const uint256 hash)
{
    cstr_append_buf(controlblock_in, hash, sizeof(uint256));
    return true;
}

btc_bool btc_controlblock_append_leafscript(cstring* controlblock_in, const cstring* script)
{
    uint256 leaf_hash;
    if (!btc_script_get_leafscripthash(script, leaf_hash))
        return false;

    return btc_controlblock_append_leafscripthash(controlblock_in, leaf_hash);
}

btc_bool btc_script_build_p2pk(cstring* script_in, const uint8_t* pubkey, size_t pubkey_size)
{
    cstr_resize(script_in, 0); //clear script
    btc_script_append_pushdata(script_in, (unsigned char*)pubkey, pubkey_size);
    btc_script_append_op(script_in, OP_CHECKSIG);
    return pubkey_size == BTC_ECKEY_COMPRESSED_LENGTH - 1 || pubkey_size == BTC_ECKEY_COMPRESSED_LENGTH || pubkey_size == BTC_ECKEY_UNCOMPRESSED_LENGTH;
}

btc_bool btc_script_build_p2pkh(cstring* script_in, const uint160 hash160)
{
    cstr_resize(script_in, 0); //clear script

    btc_script_append_op(script_in, OP_DUP);
    btc_script_append_op(script_in, OP_HASH160);


    btc_script_append_pushdata(script_in, (unsigned char*)hash160, sizeof(uint160));
    btc_script_append_op(script_in, OP_EQUALVERIFY);
    btc_script_append_op(script_in, OP_CHECKSIG);

    return true;
}

btc_bool btc_script_build_p2wpkh(cstring* script_in, const uint160 hash160)
{
    cstr_resize(script_in, 0); //clear script

    btc_script_append_op(script_in, OP_0);
    btc_script_append_pushdata(script_in, (unsigned char*)hash160, sizeof(uint160));

    return true;
}

btc_bool btc_script_build_p2sh(cstring* script_in, const uint160 hash160)
{
    cstr_resize(script_in, 0); //clear script
    btc_script_append_op(script_in, OP_HASH160);
    btc_script_append_pushdata(script_in, (unsigned char*)hash160, sizeof(uint160));
    btc_script_append_op(script_in, OP_EQUAL);

    return true;
}

btc_bool btc_script_build_p2wsh(cstring* script_in, const uint256 hash256)
{
    cstr_resize(script_in, 0); //clear script

    btc_script_append_op(script_in, OP_0);
    btc_script_append_pushdata(script_in, (unsigned char*)hash256, sizeof(uint256));

    return true;
}

btc_bool btc_script_build_p2tr(cstring* script_in, const uint256 hash256)
{
    cstr_resize(script_in, 0); //clear script

    btc_script_append_op(script_in, OP_1);
    btc_script_append_pushdata(script_in, (unsigned char*)hash256, sizeof(uint256));

    return true;
}

btc_bool btc_script_get_scripthash(const cstring* script_in, uint160 scripthash)
{
    if (!script_in)
        return false;

    uint256 hash;
    btc_hash_sngl_sha256((const unsigned char*)script_in->str, script_in->len, hash);
    ripemd160(hash, sizeof(hash), scripthash);
    return true;
}

btc_bool btc_script_get_leafscripthash(const cstring* script_in, uint256 leafhash)
{
    if (!script_in)
        return false;

    uint8_t leaf_version = BTC_TAPSCRIPT_V0;
    cstring* leaf_script = cstr_new_sz(script_in->len + 32);
    ser_bytes(leaf_script, &leaf_version, 1);
    ser_varlen(leaf_script, (uint32_t)script_in->len);
    ser_bytes(leaf_script, script_in->str, script_in->len);
    btc_tagged_hash(BTC_TAG_TAP_LEAF, (const uint8_t*)leaf_script->str, leaf_script->len, leafhash);
    cstr_free(leaf_script, true);
    return true;
}

const char* btc_tx_out_type_to_str(const enum btc_tx_out_type type)
{
    if (type == BTC_TX_PUBKEY)
    {
        return "TX_PUBKEY";
    }
    else if (type == BTC_TX_PUBKEYHASH)
    {
        return "TX_PUBKEYHASH";
    }
    else if (type == BTC_TX_SCRIPTHASH)
    {
        return "TX_SCRIPTHASH";
    }
    else if (type == BTC_TX_MULTISIG)
    {
        return "TX_MULTISIG";
    }
    else
    {
        return "TX_NONSTANDARD";
    }
}

static uint8_t btc_decode_op_n(enum opcodetype op)
{
    if (op == OP_0)
    {
        return 0;
    }
    assert(op >= OP_1 && op <= OP_16);
    return (uint8_t)op - (uint8_t)(OP_1 - 1);
}

btc_bool btc_script_is_witnessprogram(const cstring* script, uint8_t* version_out, uint8_t* program_out, int* programm_len_out)
{
    if (!version_out || !program_out)
    {
        return false;
    }
    if (script->len < 4 || script->len > 42)
    {
        return false;
    }
    if (script->str[0] != OP_0 && (script->str[0] < OP_1 || script->str[0] > OP_16))
    {
        return false;
    }
    if ((size_t)(script->str[1] + 2) == script->len)
    {
        *version_out = btc_decode_op_n((enum opcodetype)script->str[0]);
        if (program_out)
        {
            assert(script->len - 2 <= 40);
            memcpy(program_out, script->str + 2, script->len - 2);
            *programm_len_out = (int)script->len - 2;
        }
        return true;
    }
    return false;
}

void btc_tx_in_free(btc_tx_in* tx_in)
{
    if (!tx_in)
        return;

    memset(&tx_in->prevout.hash, 0, sizeof(tx_in->prevout.hash));
    tx_in->prevout.n = 0;

    if (tx_in->script_sig)
    {
        cstr_free(tx_in->script_sig, true);
        tx_in->script_sig = NULL;
    }

    if (tx_in->witness_stack)
    {
        vector_free(tx_in->witness_stack, true);
        tx_in->witness_stack = NULL;
    }

    memset(tx_in, 0, sizeof(*tx_in));
    btc_free(tx_in);
}

//callback for dvector free function
void btc_tx_in_free_cb(void* data)
{
    if (!data)
        return;

    btc_tx_in* tx_in = data;
    btc_tx_in_free(tx_in);
}

void btc_tx_in_witness_stack_free_cb(void* data)
{
    if (!data)
        return;

    cstring* stack_item = data;
    cstr_free(stack_item, true);
}

btc_tx_in* btc_tx_in_new()
{
    btc_tx_in* tx_in;
    tx_in = btc_calloc(1, sizeof(*tx_in));
    memset(&tx_in->prevout, 0, sizeof(tx_in->prevout));
    tx_in->sequence = UINT32_MAX;

    tx_in->witness_stack = vector_new(8, btc_tx_in_witness_stack_free_cb);
    return tx_in;
}

void btc_tx_out_free(btc_tx_out* tx_out)
{
    if (!tx_out)
        return;
    tx_out->value = 0;

    if (tx_out->script_pubkey)
    {
        cstr_free(tx_out->script_pubkey, true);
        tx_out->script_pubkey = NULL;
    }

    memset(tx_out, 0, sizeof(*tx_out));
    btc_free(tx_out);
}

void btc_tx_out_free_cb(void* data)
{
    if (!data)
        return;

    btc_tx_out* tx_out = data;
    btc_tx_out_free(tx_out);
}

btc_tx_out* btc_tx_out_new()
{
    btc_tx_out* tx_out;
    tx_out = btc_calloc(1, sizeof(*tx_out));

    return tx_out;
}

void btc_tx_free(btc_tx* tx)
{
    if (tx->vin)
        vector_free(tx->vin, true);

    if (tx->vout)
        vector_free(tx->vout, true);

    btc_free(tx);
}

btc_tx* btc_tx_new()
{
    btc_tx* tx;
    tx = btc_calloc(1, sizeof(*tx));
    tx->vin = vector_new(8, btc_tx_in_free_cb);
    tx->vout = vector_new(8, btc_tx_out_free_cb);
    tx->version = 1;
    tx->locktime = 0;
    return tx;
}

btc_bool btc_tx_in_deserialize(btc_tx_in* tx_in, struct const_buffer* buf)
{
    deser_u256(tx_in->prevout.hash, buf);
    if (!deser_u32(&tx_in->prevout.n, buf))
        return false;
    if (!deser_varstr(&tx_in->script_sig, buf))
        return false;
    if (!deser_u32(&tx_in->sequence, buf))
        return false;
    return true;
}

btc_bool btc_tx_out_deserialize(btc_tx_out* tx_out, struct const_buffer* buf)
{
    if (!deser_s64(&tx_out->value, buf))
        return false;
    if (!deser_varstr(&tx_out->script_pubkey, buf))
        return false;
    return true;
}

int btc_tx_deserialize(const unsigned char* tx_serialized, size_t inlen, btc_tx* tx, size_t* consumed_length, btc_bool allow_witness)
{
    struct const_buffer buf = { tx_serialized, inlen };
    if (consumed_length)
        *consumed_length = 0;

    //tx needs to be initialized
    deser_s32(&tx->version, &buf);

    uint32_t vlen;
    if (!deser_varlen(&vlen, &buf))
        return false;

    uint8_t flags = 0;
    if (vlen == 0 && allow_witness)
    {
        /* We read a dummy or an empty vin. */
        deser_bytes(&flags, &buf, 1);
        if (flags != 0)
        {
            // contains witness, deser the vin len
            if (!deser_varlen(&vlen, &buf))
                return false;
        }
    }

    unsigned int i;
    for (i = 0; i < vlen; i++)
    {
        btc_tx_in* tx_in = btc_tx_in_new();

        if (!btc_tx_in_deserialize(tx_in, &buf))
        {
            btc_tx_in_free(tx_in);
            return false;
        }
        else
        {
            vector_add(tx->vin, tx_in);
        }
    }

    if (!deser_varlen(&vlen, &buf))
        return false;
    for (i = 0; i < vlen; i++)
    {
        btc_tx_out* tx_out = btc_tx_out_new();

        if (!btc_tx_out_deserialize(tx_out, &buf))
        {
            btc_free(tx_out);
            return false;
        }
        else
        {
            vector_add(tx->vout, tx_out);
        }
    }

    if ((flags & 1) && allow_witness)
    {
        /* The witness flag is present, and we support witnesses. */
        flags ^= 1;
        for (size_t j = 0; j < tx->vin->len; j++)
        {
            btc_tx_in* tx_in = vector_idx(tx->vin, j);
            if (!deser_varlen(&vlen, &buf)) return false;
            for (size_t j = 0; j < vlen; j++)
            {
                cstring* witness_item = cstr_new_sz(1024);
                if (!deser_varstr(&witness_item, &buf))
                {
                    cstr_free(witness_item, true);
                    return false;
                }
                vector_add(tx_in->witness_stack, witness_item); //dvector is responsible for freeing the items memory
            }
        }
    }
    if (flags)
    {
        /* Unknown flag in the serialization */
        return false;
    }

    if (!deser_u32(&tx->locktime, &buf))
        return false;

    if (consumed_length)
        *consumed_length = inlen - buf.len;
    return true;
}

void btc_tx_in_serialize(cstring* s, const btc_tx_in* tx_in)
{
    ser_u256(s, tx_in->prevout.hash);
    ser_u32(s, tx_in->prevout.n);
    ser_varstr(s, tx_in->script_sig);
    ser_u32(s, tx_in->sequence);
}

void btc_tx_out_serialize(cstring* s, const btc_tx_out* tx_out)
{
    ser_s64(s, tx_out->value);
    ser_varstr(s, tx_out->script_pubkey);
}

btc_bool btc_tx_has_witness(const btc_tx* tx)
{
    for (size_t i = 0; i < tx->vin->len; i++)
    {
        btc_tx_in* tx_in = vector_idx(tx->vin, i);
        if (tx_in->witness_stack != NULL && tx_in->witness_stack->len > 0)
        {
            return true;
        }
    }
    return false;
}

void btc_tx_serialize(cstring* s, const btc_tx* tx, btc_bool allow_witness)
{
    ser_s32(s, tx->version);
    uint8_t flags = 0;
    // Consistency check
    if (allow_witness)
    {
        /* Check whether witnesses need to be serialized. */
        if (btc_tx_has_witness(tx))
        {
            flags |= 1;
        }
    }
    if (flags)
    {
        /* Use extended format in case witnesses are to be serialized. */
        uint8_t dummy = 0;
        ser_bytes(s, &dummy, 1);
        ser_bytes(s, &flags, 1);
    }

    ser_varlen(s, tx->vin ? (uint32_t)tx->vin->len : 0);

    unsigned int i;
    if (tx->vin)
    {
        for (i = 0; i < tx->vin->len; i++)
        {
            btc_tx_in* tx_in;

            tx_in = vector_idx(tx->vin, i);
            btc_tx_in_serialize(s, tx_in);
        }
    }

    ser_varlen(s, tx->vout ? (uint32_t)tx->vout->len : 0);

    if (tx->vout)
    {
        for (i = 0; i < tx->vout->len; i++)
        {
            btc_tx_out* tx_out;

            tx_out = vector_idx(tx->vout, i);
            btc_tx_out_serialize(s, tx_out);
        }
    }

    if (flags & 1)
    {
        // serialize the witness stack
        if (tx->vin)
        {
            for (i = 0; i < tx->vin->len; i++)
            {
                btc_tx_in* tx_in;
                tx_in = vector_idx(tx->vin, i);
                if (tx_in->witness_stack)
                {
                    ser_varlen(s, (uint32_t)tx_in->witness_stack->len);
                    for (unsigned int j = 0; j < tx_in->witness_stack->len; j++)
                    {
                        cstring* item = vector_idx(tx_in->witness_stack, j);
                        ser_varstr(s, item);
                    }
                }
            }
        }
    }

    ser_u32(s, tx->locktime);
}

void btc_tx_hash(const btc_tx* tx, uint256 hashout)
{
    cstring* txser = cstr_new_sz(1024);
    btc_tx_serialize(txser, tx, false);


    sha256_Raw((const uint8_t*)txser->str, txser->len, hashout);
    sha256_Raw(hashout, BTC_HASH_LENGTH, hashout);
    cstr_free(txser, true);
}

void btc_tx_in_copy(btc_tx_in* dest, const btc_tx_in* src)
{
    memcpy(&dest->prevout, &src->prevout, sizeof(dest->prevout));
    dest->sequence = src->sequence;

    if (!src->script_sig)
        dest->script_sig = NULL;
    else
    {
        dest->script_sig = cstr_new_sz(src->script_sig->len);
        cstr_append_buf(dest->script_sig,
            src->script_sig->str,
            src->script_sig->len);
    }

    if (!src->witness_stack)
        dest->witness_stack = NULL;
    else
    {
        dest->witness_stack = vector_new(src->witness_stack->len, btc_tx_in_witness_stack_free_cb);
        for (unsigned int i = 0; i < src->witness_stack->len; i++)
        {
            cstring* witness_item = vector_idx(src->witness_stack, i);
            cstring* item_cpy = cstr_new_cstr(witness_item);
            vector_add(dest->witness_stack, item_cpy);
        }
    }
}

void btc_tx_out_copy(btc_tx_out* dest, const btc_tx_out* src)
{
    dest->value = src->value;

    if (!src->script_pubkey)
        dest->script_pubkey = NULL;
    else
    {
        dest->script_pubkey = cstr_new_sz(src->script_pubkey->len);
        cstr_append_buf(dest->script_pubkey,
            src->script_pubkey->str,
            src->script_pubkey->len);
    }
}

void btc_tx_copy(btc_tx* dest, const btc_tx* src)
{
    dest->version = src->version;
    dest->locktime = src->locktime;

    if (!src->vin)
        dest->vin = NULL;
    else
    {
        unsigned int i;

        if (dest->vin)
            vector_free(dest->vin, true);

        dest->vin = vector_new(src->vin->len, btc_tx_in_free_cb);

        for (i = 0; i < src->vin->len; i++)
        {
            btc_tx_in* tx_in_old, * tx_in_new;

            tx_in_old = vector_idx(src->vin, i);
            tx_in_new = btc_malloc(sizeof(*tx_in_new));
            btc_tx_in_copy(tx_in_new, tx_in_old);
            vector_add(dest->vin, tx_in_new);
        }
    }

    if (!src->vout)
        dest->vout = NULL;
    else
    {
        unsigned int i;

        if (dest->vout)
            vector_free(dest->vout, true);

        dest->vout = vector_new(src->vout->len,
            btc_tx_out_free_cb);

        for (i = 0; i < src->vout->len; i++)
        {
            btc_tx_out* tx_out_old, * tx_out_new;

            tx_out_old = vector_idx(src->vout, i);
            tx_out_new = btc_malloc(sizeof(*tx_out_new));
            btc_tx_out_copy(tx_out_new, tx_out_old);
            vector_add(dest->vout, tx_out_new);
        }
    }
}

void btc_tx_prevout_hash(const btc_tx* tx, uint256 hash, btc_bool use_btc_hash)
{
    cstring* s = cstr_new_sz(512);
    unsigned int i;
    btc_tx_in* tx_in;
    for (i = 0; i < tx->vin->len; i++)
    {
        tx_in = vector_idx(tx->vin, i);
        ser_u256(s, tx_in->prevout.hash);
        ser_u32(s, tx_in->prevout.n);
    }

    if (use_btc_hash)
        btc_hash((const uint8_t*)s->str, s->len, hash);
    else
        sha256_Raw((const uint8_t*)s->str, s->len, hash);
    cstr_free(s, true);
}

void btc_tx_sequence_hash(const btc_tx* tx, uint256 hash, btc_bool use_btc_hash)
{
    cstring* s = cstr_new_sz(512);
    unsigned int i;
    btc_tx_in* tx_in;
    for (i = 0; i < tx->vin->len; i++)
    {
        tx_in = vector_idx(tx->vin, i);
        ser_u32(s, tx_in->sequence);
    }

    if (use_btc_hash)
        btc_hash((const uint8_t*)s->str, s->len, hash);
    else
        sha256_Raw((const uint8_t*)s->str, s->len, hash);
    cstr_free(s, true);
}

void btc_tx_outputs_hash(const btc_tx* tx, uint256 hash, btc_bool use_btc_hash)
{
    cstring* s = cstr_new_sz(512);
    unsigned int i;
    btc_tx_out* tx_out;
    for (i = 0; i < tx->vout->len; i++)
    {
        tx_out = vector_idx(tx->vout, i);
        btc_tx_out_serialize(s, tx_out);
    }

    if (use_btc_hash)
        btc_hash((const uint8_t*)s->str, s->len, hash);
    else
        sha256_Raw((const uint8_t*)s->str, s->len, hash);
    cstr_free(s, true);
}

void btc_tx_vin_amount_hash(const btc_tx* tx, const uint64_t* vin_amounts, uint256 hash, btc_bool use_btc_hash)
{
    cstring* s = cstr_new_sz(512);
    unsigned int i;
    for (i = 0; i < tx->vin->len; i++)
        ser_s64(s, vin_amounts[i]);

    if (use_btc_hash)
        btc_hash((const uint8_t*)s->str, s->len, hash);
    else
        sha256_Raw((const uint8_t*)s->str, s->len, hash);
    cstr_free(s, true);
}

void btc_tx_vin_script_hash(const btc_tx* tx, const cstring* const* vin_scripts, uint256 hash, btc_bool use_btc_hash)
{
    cstring* s = cstr_new_sz(512);
    unsigned int i;
    for (i = 0; i < tx->vin->len; i++)
        ser_varstr(s, (cstring*)vin_scripts[i]);

    if (use_btc_hash)
        btc_hash((const uint8_t*)s->str, s->len, hash);
    else
        sha256_Raw((const uint8_t*)s->str, s->len, hash);
    cstr_free(s, true);
}

btc_bool btc_tx_sighash(const btc_tx* tx_to, const enum btc_sig_version sigversion, uint32_t hashtype, const btc_tx_witness_stack* vin_stack, uint32_t input_index, const uint256 leaf_hash, uint256 hash)
{
    if (input_index >= tx_to->vin->len)
        return false;

    cstring* s = NULL;
    btc_bool ret = true;
    btc_bool use_btc_hash = true;
    btc_tx* tx_tmp = btc_tx_new();
    btc_tx_copy(tx_tmp, tx_to);

    if (sigversion == SIGVERSION_WITNESS_V1_TAPROOT || sigversion == SIGVERSION_WITNESS_V1_TAPSCRIPT)
    {
        uint8_t epoch = 0;
        s = cstr_new_sz(512);
        ser_bytes(s, &epoch, 1);
        ser_bytes(s, &hashtype, 1);
        ser_u32(s, tx_tmp->version);
        ser_u32(s, tx_tmp->locktime);

        const uint8_t output_type = (hashtype == SIGHASH_DEFAULT) ? SIGHASH_ALL : (hashtype & SIGHASH_OUTPUT_MASK); // Default (no sighash byte) is equivalent to SIGHASH_ALL
        const uint8_t input_type = hashtype & SIGHASH_INPUT_MASK;
        if (!(hashtype <= 0x03 || (hashtype >= 0x81 && hashtype <= 0x83)))
        {
            ret = false;
            goto out;
        }

        if (input_type != SIGHASH_ANYONECANPAY)
        {
            uint256 hash_prevouts;
            btc_hash_clear(hash_prevouts);
            uint256 hash_amounts;
            btc_hash_clear(hash_amounts);
            uint256 hash_scripts;
            btc_hash_clear(hash_scripts);
            uint256 hash_sequence;
            btc_hash_clear(hash_sequence);

            btc_tx_prevout_hash(tx_tmp, hash_prevouts, false);
            btc_tx_vin_amount_hash(tx_tmp, vin_stack->amounts, hash_amounts, false);
            btc_tx_vin_script_hash(tx_tmp, (const cstring* const*)vin_stack->scripts, hash_scripts, false);
            btc_tx_sequence_hash(tx_tmp, hash_sequence, false);
            ser_u256(s, hash_prevouts);
            ser_u256(s, hash_amounts);
            ser_u256(s, hash_scripts);
            ser_u256(s, hash_sequence);
        }

        if (output_type == SIGHASH_ALL)
        {
            uint256 hash_outputs;
            btc_hash_clear(hash_outputs);
            btc_tx_outputs_hash(tx_tmp, hash_outputs, false);
            ser_u256(s, hash_outputs);
        }

        const uint8_t have_annex = false;
        const uint8_t spend_type = (sigversion == SIGVERSION_WITNESS_V1_TAPROOT ? 0 : 2) + (have_annex ? 1 : 0);
        ser_bytes(s, &spend_type, 1);

        if (input_type == SIGHASH_ANYONECANPAY)
        {
            cstring* script = vin_stack->scripts[input_index];
            if (!script)
            {
                ret = false;
                goto out;
            }

            btc_tx_in* tx_in = vector_idx(tx_tmp->vin, input_index);
            ser_u256(s, tx_in->prevout.hash);
            ser_u32(s, tx_in->prevout.n);
            ser_varstr(s, script); // script code
            ser_u64(s, vin_stack->amounts[input_index]);
            ser_u32(s, tx_in->sequence);
        }
        else
            ser_u32(s, input_index);

        if (output_type == SIGHASH_SINGLE)
        {
            if (input_index >= tx_tmp->vout->len)
            {
                ret = false;
                goto out;
            }

            uint256 hash_output;
            cstring* s_out = cstr_new_sz(512);
            btc_tx_out* tx_out = vector_idx(tx_tmp->vout, input_index);
            btc_tx_out_serialize(s_out, tx_out);
            sha256_Raw((const uint8_t*)s_out->str, s_out->len, hash_output);
            cstr_free(s, true);
            ser_u256(s, hash_output);
        }

        if (sigversion == SIGVERSION_WITNESS_V1_TAPSCRIPT)
        {
            uint256 tapleaf_hash = { 0 };
            if (!leaf_hash)
            {
                cstring* script = vin_stack->scripts[input_index];
                if (!script)
                {
                    ret = false;
                    goto out;
                }

                btc_script_get_leafscripthash(script, tapleaf_hash);
            }
            else
                memcpy(tapleaf_hash, leaf_hash, sizeof(tapleaf_hash));
            ser_u256(s, tapleaf_hash);

            const uint8_t key_version = 0;
            ser_bytes(s, &key_version, 1);

            const uint32_t codeseparator_pos = 0xFFFFFFFF;
            ser_u32(s, codeseparator_pos);
        }

        use_btc_hash = false;
    }
    else if (sigversion == SIGVERSION_WITNESS_V0 || hashtype & SIGHASH_FORKID)
    {
        cstring* stack = vin_stack->stacks[input_index];
        if (!stack)
        {
            ret = false;
            goto out;
        }

        uint256 hash_prevouts;
        btc_hash_clear(hash_prevouts);
        uint256 hash_sequence;
        btc_hash_clear(hash_sequence);
        uint256 hash_outputs;
        btc_hash_clear(hash_outputs);

        if (!(hashtype & SIGHASH_ANYONECANPAY))
            btc_tx_prevout_hash(tx_tmp, hash_prevouts, true);
        if (!(hashtype & SIGHASH_ANYONECANPAY))
            btc_tx_outputs_hash(tx_tmp, hash_outputs, true);
        if (!(hashtype & SIGHASH_ANYONECANPAY) && (hashtype & 0x1f) != SIGHASH_SINGLE && (hashtype & 0x1f) != SIGHASH_NONE)
            btc_tx_sequence_hash(tx_tmp, hash_sequence, true);

        if ((hashtype & 0x1f) != SIGHASH_SINGLE && (hashtype & 0x1f) != SIGHASH_NONE)
        {
            btc_tx_outputs_hash(tx_tmp, hash_outputs, true);
        }
        else if ((hashtype & 0x1f) == SIGHASH_SINGLE && input_index < tx_tmp->vout->len)
        {
            cstring* s1 = cstr_new_sz(512);
            btc_tx_out* tx_out = vector_idx(tx_tmp->vout, input_index);
            btc_tx_out_serialize(s1, tx_out);
            btc_hash((const uint8_t*)s1->str, s1->len, hash);
            cstr_free(s1, true);
        }

        s = cstr_new_sz(512);
        ser_u32(s, tx_tmp->version); // Version

        // Input prevouts/nSequence (none/all, depending on flags)
        ser_u256(s, hash_prevouts);
        ser_u256(s, hash_sequence);

        // The input being signed (replacing the scriptSig with scriptCode + amount)
        // The prevout may already be contained in hashPrevout, and the nSequence
        // may already be contain in hashSequence.
        btc_tx_in* tx_in = vector_idx(tx_tmp->vin, input_index);
        ser_u256(s, tx_in->prevout.hash);
        ser_u32(s, tx_in->prevout.n);

        ser_varstr(s, stack); // script sig
        ser_u64(s, vin_stack->amounts[input_index]);
        ser_u32(s, tx_in->sequence);
        ser_u256(s, hash_outputs); // Outputs (none/one/all, depending on flags)
        ser_u32(s, tx_tmp->locktime); // Locktime
        ser_s32(s, hashtype); // Sighash type
    }
    else
    {
        // standard (non witness) sighash (SIGVERSION_BASE)
        cstring* stack = vin_stack->stacks[input_index];
        if (!stack)
        {
            ret = false;
            goto out;
        }

        cstring* scriptsig = cstr_new_sz(stack->len);
        btc_script_copy_without_op_codeseperator(stack, scriptsig);

        unsigned int i;
        btc_tx_in* tx_in;
        for (i = 0; i < tx_tmp->vin->len; i++)
        {
            tx_in = vector_idx(tx_tmp->vin, i);
            cstr_resize(tx_in->script_sig, 0);
            if (i == input_index)
                cstr_append_buf(tx_in->script_sig, scriptsig->str, scriptsig->len);
        }
        cstr_free(scriptsig, true);

        /* Blank out some of the outputs */
        if ((hashtype & 0x1f) == SIGHASH_NONE)
        {
            /* Wildcard payee */
            if (tx_tmp->vout)
                vector_free(tx_tmp->vout, true);

            tx_tmp->vout = vector_new(1, btc_tx_out_free_cb);

            /* Let the others update at will */
            for (i = 0; i < tx_tmp->vin->len; i++)
            {
                tx_in = vector_idx(tx_tmp->vin, i);
                if (i != input_index)
                    tx_in->sequence = 0;
            }
        }
        else if ((hashtype & 0x1f) == SIGHASH_SINGLE)
        {
            /* Only lock-in the txout payee at same index as txin */
            unsigned int n_out = input_index;
            if (n_out >= tx_tmp->vout->len)
            {
                //TODO: set error code
                ret = false;
                goto out;
            }

            vector_resize(tx_tmp->vout, n_out + 1);
            for (i = 0; i < n_out; i++)
            {
                btc_tx_out* tx_out;

                tx_out = vector_idx(tx_tmp->vout, i);
                tx_out->value = -1;
                if (tx_out->script_pubkey)
                {
                    cstr_free(tx_out->script_pubkey, true);
                    tx_out->script_pubkey = NULL;
                }
            }

            /* Let the others update at will */
            for (i = 0; i < tx_tmp->vin->len; i++)
            {
                tx_in = vector_idx(tx_tmp->vin, i);
                if (i != input_index)
                    tx_in->sequence = 0;
            }
        }

        /* Blank out other inputs completely;
         not recommended for open transactions */
        if (hashtype & SIGHASH_ANYONECANPAY)
        {
            if (input_index > 0)
                vector_remove_range(tx_tmp->vin, 0, input_index);
            vector_resize(tx_tmp->vin, 1);
        }

        s = cstr_new_sz(512);
        btc_tx_serialize(s, tx_tmp, false);
        ser_s32(s, hashtype);
    }

    if (use_btc_hash)
    {
        sha256_Raw((const uint8_t*)s->str, s->len, hash);
        sha256_Raw(hash, BTC_HASH_LENGTH, hash);
    }
    else
    {
        char tag[] = "TapSighash";
        btc_ecc_tagged_sha256((const uint8_t*)s->str, s->len, (const uint8_t*)tag, sizeof(tag) - 1, hash);
    }
    cstr_free(s, true);
out:
    btc_tx_free(tx_tmp);
    return ret;
}

btc_bool btc_tx_add_data_out(btc_tx* tx, const int64_t amount, const uint8_t* data, const size_t datalen)
{
    if (datalen > 80)
        return false;

    btc_tx_out* tx_out = btc_tx_out_new();

    tx_out->script_pubkey = cstr_new_sz(1024);
    btc_script_append_op(tx_out->script_pubkey, OP_RETURN);
    btc_script_append_pushdata(tx_out->script_pubkey, (unsigned char*)data, datalen);

    tx_out->value = amount;

    vector_add(tx->vout, tx_out);

    return true;
}

btc_bool btc_tx_add_puzzle_out(btc_tx* tx, const int64_t amount, const uint8_t* puzzle, const size_t puzzlelen)
{
    if (puzzlelen > BTC_HASH_LENGTH)
        return false;

    btc_tx_out* tx_out = btc_tx_out_new();

    tx_out->script_pubkey = cstr_new_sz(1024);
    btc_script_append_op(tx_out->script_pubkey, OP_HASH256);
    btc_script_append_pushdata(tx_out->script_pubkey, (unsigned char*)puzzle, puzzlelen);
    btc_script_append_op(tx_out->script_pubkey, OP_EQUAL);
    tx_out->value = amount;

    vector_add(tx->vout, tx_out);

    return true;
}

btc_bool btc_tx_add_address_out(btc_tx* tx, const sc_chainparams* chain, int64_t amount, const char* address)
{
    const size_t buflen = sizeof(uint8_t) * strlen(address) * 2;
    uint8_t* buf = (uint8_t*)btc_malloc(buflen);
    int r = btc_base58_decode_check(address, buf, buflen);
    btc_bool success = false;
    if (r > 0 && base58_prefix_check(chain->b58prefix_pubkey_address, buf))
    {
        success = btc_tx_add_p2pkh_hash160_out(tx, amount, buf + base58_prefix_size(chain->b58prefix_pubkey_address));
    }
    else if (r > 0 && base58_prefix_check(chain->b58prefix_script_address, buf))
    {
        success = btc_tx_add_p2sh_hash160_out(tx, amount, buf + base58_prefix_size(chain->b58prefix_script_address));
    }
    else
    {
        // check for bech32
        int version = 0;
        unsigned char programm[40] = { 0 };
        size_t programmlen = 0;
        if (bech32_address_decode(&version, programm, &programmlen, chain->bech32_hrp, address) != 1)
        {
            btc_free(buf);
            return false;
        }

        if (programmlen == 20)
        {
            success = btc_tx_add_p2wpkh_hash160_out(tx, amount, programm);
        }
        else if (programmlen == 32)
        {
            if (version == 1)
                success = btc_tx_add_p2tr_hash256_out(tx, amount, programm);
            else
                success = btc_tx_add_p2wsh_hash256_out(tx, amount, programm);
        }
    }

    btc_free(buf);
    return success;
}

btc_bool btc_tx_add_p2pk_out(btc_tx* tx, int64_t amount, const uint8_t* pubkey, size_t pubkey_size)
{
    btc_tx_out* tx_out = btc_tx_out_new();

    tx_out->script_pubkey = cstr_new_sz(1024);
    btc_script_build_p2pk(tx_out->script_pubkey, pubkey, pubkey_size);

    tx_out->value = amount;

    vector_add(tx->vout, tx_out);

    return true;
}

btc_bool btc_tx_add_p2pkh_hash160_out(btc_tx* tx, int64_t amount, uint160 hash160)
{
    btc_tx_out* tx_out = btc_tx_out_new();

    tx_out->script_pubkey = cstr_new_sz(1024);
    btc_script_build_p2pkh(tx_out->script_pubkey, hash160);

    tx_out->value = amount;

    vector_add(tx->vout, tx_out);

    return true;
}

btc_bool btc_tx_add_p2sh_hash160_out(btc_tx* tx, int64_t amount, uint160 hash160)
{
    btc_tx_out* tx_out = btc_tx_out_new();

    tx_out->script_pubkey = cstr_new_sz(1024);
    btc_script_build_p2sh(tx_out->script_pubkey, hash160);

    tx_out->value = amount;

    vector_add(tx->vout, tx_out);

    return true;
}

btc_bool btc_tx_add_p2wpkh_hash160_out(btc_tx* tx, int64_t amount, const uint8_t* hash160)
{
    btc_tx_out* tx_out = btc_tx_out_new();

    tx_out->script_pubkey = cstr_new_sz(1024);
    btc_script_build_p2wpkh(tx_out->script_pubkey, hash160);

    tx_out->value = amount;

    vector_add(tx->vout, tx_out);

    return true;
}

btc_bool btc_tx_add_p2wsh_hash256_out(btc_tx* tx, int64_t amount, const uint8_t* hash256)
{
    btc_tx_out* tx_out = btc_tx_out_new();

    tx_out->script_pubkey = cstr_new_sz(1024);
    btc_script_build_p2wsh(tx_out->script_pubkey, hash256);

    tx_out->value = amount;

    vector_add(tx->vout, tx_out);

    return true;
}

btc_bool btc_tx_add_p2tr_hash256_out(btc_tx* tx, int64_t amount, const uint8_t* hash256)
{
    btc_tx_out* tx_out = btc_tx_out_new();

    tx_out->script_pubkey = cstr_new_sz(1024);
    btc_script_build_p2tr(tx_out->script_pubkey, hash256);

    tx_out->value = amount;

    vector_add(tx->vout, tx_out);

    return true;
}

btc_bool btc_tx_outpoint_is_null(btc_tx_outpoint* tx)
{
    (void)(tx);
    return true;
}

btc_bool btc_tx_is_coinbase(btc_tx* tx)
{
    if (tx->vin->len == 1)
    {
        btc_tx_in* vin = vector_idx(tx->vin, 0);

        if (btc_hash_is_empty(vin->prevout.hash) && vin->prevout.n == UINT32_MAX)
            return true;
    }
    return false;
}

btc_bool btc_tx_sign_hash_ecdsa(const uint256 sighash, const btc_key* privkey, uint32_t sighashtype, uint8_t* sigdata_out, size_t* sigdata_size_out)
{
    uint8_t sig[64]; size_t siglen = 0;
    if (!btc_key_sign_hash_compact(privkey, sighash, sig, &siglen))
        return false;

    unsigned char sigder_plus_hashtype[74 + 1]; size_t sigderlen = sizeof(sigder_plus_hashtype);
    if (!btc_ecc_compact_to_der_normalized(sig, sigder_plus_hashtype, &sigderlen))
        return false;

    assert(siglen == sizeof(sig));
    assert(sigderlen <= 74 && sigderlen >= 70);
    sigder_plus_hashtype[sigderlen++] = sighashtype;
    memcpy(sigdata_out, sigder_plus_hashtype, sigderlen);
    *sigdata_size_out = sigderlen;
    return true;
}

btc_bool btc_tx_sign_hash_schnorr(const uint256 sighash, const btc_key* privkey, uint32_t sighashtype, uint8_t* sigdata_out, size_t* sigdata_size_out)
{
    uint256 auxiliary = { 0 };
    uint8_t sig[65]; size_t siglen = 0;
    if (!btc_ecc_sign_schnorr(privkey->privkey, sighash, auxiliary, sig, &siglen))
        return false;

    if (sighashtype)
        sig[siglen++] = sighashtype;

    memcpy(sigdata_out, sig, siglen);
    *sigdata_size_out = siglen;
    return true;
}

const char* btc_tx_sign_result_to_str(const enum btc_tx_sign_result result)
{
    if (result == BTC_SIGN_FINALIZE_OK)
    {
        return "FINALIZE_OK";
    }
    else if (result == BTC_SIGN_HASH_OK)
    {
        return "HASH_OK";
    }
    else if (result == BTC_SIGN_OK)
    {
        return "SIGN_OK";
    }
    else if (result == BTC_SIGN_INVALID_TX_OR_SCRIPT)
    {
        return "INVALID_TX_OR_SCRIPT";
    }
    else if (result == BTC_SIGN_INPUTINDEX_OUT_OF_RANGE)
    {
        return "INPUTINDEX_OUT_OF_RANGE";
    }
    else if (result == BTC_SIGN_INVALID_KEY)
    {
        return "INVALID_KEY";
    }
    else if (result == BTC_SIGN_UNKNOWN_SCRIPT_TYPE)
    {
        return "SIGN_UNKNOWN_SCRIPT_TYPE";
    }
    else if (result == BTC_SIGN_SIGHASH_FAILED)
    {
        return "SIGHASH_FAILED";
    }
    return "UNKOWN";
}

enum btc_tx_sign_result btc_tx_hash_input(btc_tx* tx_in_out, uint32_t sighashtype, enum btc_tx_out_type type, const btc_tx_witness_stack* vin_stack, uint32_t inputindex, uint256 sighash_out)
{
    if (!sighash_out || !tx_in_out || !vin_stack || type == BTC_TX_INVALID)
        return BTC_SIGN_INVALID_TX_OR_SCRIPT;

    if ((size_t)inputindex >= tx_in_out->vin->len)
        return BTC_SIGN_INPUTINDEX_OUT_OF_RANGE;

    switch (type)
    {
        case BTC_TX_PUBKEY:
        case BTC_TX_PUBKEYHASH:
        case BTC_TX_SCRIPTHASH:
        {
            // calculate message hash
            if (!btc_tx_sighash(tx_in_out, SIGVERSION_BASE, sighashtype, vin_stack, inputindex, NULL, sighash_out))
                return BTC_SIGN_SIGHASH_FAILED;

            return BTC_SIGN_HASH_OK;
        }
        case BTC_TX_WITNESS_V0_PUBKEYHASH:
        case BTC_TX_WITNESS_V0_SCRIPTHASH:
        {
            // calculate message hash
            if (!btc_tx_sighash(tx_in_out, SIGVERSION_WITNESS_V0, sighashtype, vin_stack, inputindex, NULL, sighash_out))
                return BTC_SIGN_SIGHASH_FAILED;

            return BTC_SIGN_HASH_OK;
        }
        case BTC_TX_WITNESS_V1_TAPROOT_KEYPATH:
        {
            // calculate message hash
            if (!btc_tx_sighash(tx_in_out, SIGVERSION_WITNESS_V1_TAPROOT, SIGHASH_DEFAULT, vin_stack, inputindex, NULL, sighash_out))
                return BTC_SIGN_SIGHASH_FAILED;

            return BTC_SIGN_HASH_OK;
        }
        case BTC_TX_WITNESS_V1_TAPROOT_SCRIPTPATH:
        {
            cstring* script = vin_stack->scripts[inputindex];
            if (!script)
                return BTC_SIGN_INVALID_TX_OR_SCRIPT;

            // calculate locking leaf script hash
            uint256 locking_leaf_hash;
            btc_script_get_leafscripthash(script, locking_leaf_hash);

            // calculate message hash
            if (!btc_tx_sighash(tx_in_out, SIGVERSION_WITNESS_V1_TAPSCRIPT, SIGHASH_DEFAULT, vin_stack, inputindex, locking_leaf_hash, sighash_out))
                return BTC_SIGN_SIGHASH_FAILED;

            return BTC_SIGN_HASH_OK;
        }
        default:
            return BTC_SIGN_UNKNOWN_SCRIPT_TYPE;
    }
}

enum btc_tx_sign_result btc_tx_sign_input(uint256 sighash, const btc_key* privkey, uint32_t sighashtype, enum btc_tx_out_type type, uint8_t* sigdata_out, size_t* sigdata_size_out)
{
    if (!sighash || !sigdata_out || !sigdata_size_out || type == BTC_TX_INVALID)
        return BTC_SIGN_INVALID_TX_OR_SCRIPT;

    if (!btc_privkey_is_valid(privkey))
        return BTC_SIGN_INVALID_KEY;

    switch (type)
    {
        case BTC_TX_PUBKEY:
        case BTC_TX_PUBKEYHASH:
        case BTC_TX_SCRIPTHASH:
        case BTC_TX_WITNESS_V0_PUBKEYHASH:
        case BTC_TX_WITNESS_V0_SCRIPTHASH:
        {
            // calculate ecdsa signature
            if (!btc_tx_sign_hash_ecdsa(sighash, privkey, sighashtype, sigdata_out, sigdata_size_out))
                return BTC_SIGN_SIGHASH_FAILED;

            return BTC_SIGN_OK;
        }
        case BTC_TX_WITNESS_V1_TAPROOT_KEYPATH:
        case BTC_TX_WITNESS_V1_TAPROOT_SCRIPTPATH:
        {
            // calculate schnorr privkey
            btc_key schnorr_privkey;
            btc_privkey_get_taproot_privkey(privkey, NULL, schnorr_privkey.privkey);

            // calculate schnorr signature
            if (!btc_tx_sign_hash_schnorr(sighash, &schnorr_privkey, SIGHASH_DEFAULT, sigdata_out, sigdata_size_out))
                return BTC_SIGN_SIGHASH_FAILED;

            return BTC_SIGN_OK;
        }
        default:
            return BTC_SIGN_UNKNOWN_SCRIPT_TYPE;
    }
}

enum btc_tx_sign_result btc_tx_finalize_input(btc_tx* tx_in_out, const uint8_t* sigdata, size_t sigdata_size, const btc_pubkey* pubkey, uint32_t sighashtype, enum btc_tx_out_type type, const btc_tx_witness_stack* vin_stack, uint32_t inputindex)
{
    if (!sigdata || !tx_in_out || !vin_stack || type == BTC_TX_INVALID)
        return BTC_SIGN_INVALID_TX_OR_SCRIPT;

    if ((size_t)inputindex >= tx_in_out->vin->len)
        return BTC_SIGN_INPUTINDEX_OUT_OF_RANGE;

    if (!pubkey || !btc_pubkey_is_valid(pubkey))
        return BTC_SIGN_INVALID_KEY;

    unsigned char signature[75];
    size_t signature_size = sizeof(signature) - 1;
    if (sigdata_size == 64)
    {
        memcpy(signature, sigdata, sigdata_size);
        signature_size = sigdata_size;
    }
    else
    {
        btc_ecc_compact_to_der_normalized(sigdata, signature, &signature_size);
        signature[signature_size++] = sighashtype;
    }

    btc_tx_in* tx_in = vector_idx(tx_in_out->vin, inputindex);
    switch (type)
    {
        case BTC_TX_PUBKEY:
        {
            // script_stack: [signature], witness_stack: []
            ser_varlen(tx_in->script_sig, (uint32_t)signature_size);
            ser_bytes(tx_in->script_sig, signature, signature_size);
            return BTC_SIGN_FINALIZE_OK;
        }
        case BTC_TX_PUBKEYHASH:
        case BTC_TX_SCRIPTHASH:
        {
            // script_stack: [signature, pubkey], witness_stack: []
            ser_varlen(tx_in->script_sig, (uint32_t)signature_size);
            ser_bytes(tx_in->script_sig, signature, signature_size);
            ser_varlen(tx_in->script_sig, pubkey->compressed ? BTC_ECKEY_COMPRESSED_LENGTH : BTC_ECKEY_UNCOMPRESSED_LENGTH);
            ser_bytes(tx_in->script_sig, pubkey->pubkey, pubkey->compressed ? BTC_ECKEY_COMPRESSED_LENGTH : BTC_ECKEY_UNCOMPRESSED_LENGTH);
            return BTC_SIGN_FINALIZE_OK;
        }
        case BTC_TX_WITNESS_V0_PUBKEYHASH:
        {
            cstring* redeem = vin_stack->redeems[inputindex];
            if (redeem)
            {
                // script_stack: [redeem], witness_stack: [signature, pubkey]
                cstr_resize(tx_in->script_sig, 0);
                cstr_append_cstr(tx_in->script_sig, redeem);
                vector_add(tx_in->witness_stack, cstr_new_buf(signature, signature_size));
                vector_add(tx_in->witness_stack, cstr_new_buf(pubkey->pubkey, pubkey->compressed ? BTC_ECKEY_COMPRESSED_LENGTH : BTC_ECKEY_UNCOMPRESSED_LENGTH));
            }
            else
            {
                // script_stack: [], witness_stack: [signature, pubkey]
                cstr_resize(tx_in->script_sig, 0);
                vector_add(tx_in->witness_stack, cstr_new_buf(signature, signature_size));
                vector_add(tx_in->witness_stack, cstr_new_buf(pubkey->pubkey, pubkey->compressed ? BTC_ECKEY_COMPRESSED_LENGTH : BTC_ECKEY_UNCOMPRESSED_LENGTH));
            }
            return BTC_SIGN_FINALIZE_OK;
        }
        case BTC_TX_WITNESS_V0_SCRIPTHASH:
        {
            cstring* stack = vin_stack->stacks[inputindex];
            if (!stack)
                return BTC_SIGN_INVALID_TX_OR_SCRIPT;

            // script_stack: [], witness_stack: [signature, pubkey, script]
            cstr_resize(tx_in->script_sig, 0);
            vector_add(tx_in->witness_stack, cstr_new_buf(signature, signature_size));
            vector_add(tx_in->witness_stack, cstr_new_buf(pubkey->pubkey, pubkey->compressed ? BTC_ECKEY_COMPRESSED_LENGTH : BTC_ECKEY_UNCOMPRESSED_LENGTH));
            vector_add(tx_in->witness_stack, cstr_new_cstr(stack));
            return BTC_SIGN_FINALIZE_OK;
        }
        case BTC_TX_WITNESS_V1_TAPROOT_KEYPATH:
        {
            // script_stack: [], witness_stack: [signature]
            cstr_resize(tx_in->script_sig, 0);
            vector_add(tx_in->witness_stack, cstr_new_buf(signature, signature_size));
            return BTC_SIGN_FINALIZE_OK;
        }
        case BTC_TX_WITNESS_V1_TAPROOT_SCRIPTPATH:
        {
            cstring* script = vin_stack->scripts[inputindex];
            if (!script)
                return BTC_SIGN_INVALID_TX_OR_SCRIPT;

            // calculate control block
            cstring* control_block = cstr_new_sz(512);
            btc_controlblock_append_version(control_block, BTC_TAPSCRIPT_V0);
            btc_controlblock_append_internalpubkey(control_block, pubkey);
            //btc_controlblock_append_leafscripthash(control_block, leaf_hash);

            // script_stack: [], witness_stack: [signature, script, control_block]
            cstr_resize(tx_in->script_sig, 0);
            vector_add(tx_in->witness_stack, cstr_new_buf(signature, signature_size));
            vector_add(tx_in->witness_stack, cstr_new_cstr(script));
            vector_add(tx_in->witness_stack, control_block);
            return BTC_SIGN_FINALIZE_OK;
        }
        default:
            return BTC_SIGN_UNKNOWN_SCRIPT_TYPE;
    }
}

void ser_bytes(cstring* s, const void* p, size_t len)
{
    cstr_append_buf(s, p, len);
}

void ser_u16(cstring* s, uint16_t v_)
{
    uint16_t v = htole16(v_);
    cstr_append_buf(s, &v, sizeof(v));
}

void ser_u32(cstring* s, uint32_t v_)
{
    uint32_t v = htole32(v_);
    cstr_append_buf(s, &v, sizeof(v));
}

void ser_s32(cstring* s, int32_t v_)
{
    ser_u32(s, (uint32_t)v_);
}

void ser_u64(cstring* s, uint64_t v_)
{
    uint64_t v = htole64(v_);
    cstr_append_buf(s, &v, sizeof(v));
}

void ser_s64(cstring* s, int64_t v_)
{
    ser_u64(s, (uint64_t)v_);
}

void ser_u256(cstring* s, const unsigned char* v_)
{
    ser_bytes(s, v_, 32);
}

void ser_varlen(cstring* s, uint32_t vlen)
{
    unsigned char c;

    if (vlen < 253)
    {
        c = vlen;
        ser_bytes(s, &c, 1);
    }

    else if (vlen < 0x10000)
    {
        c = 253;
        ser_bytes(s, &c, 1);
        ser_u16(s, (uint16_t)vlen);
    }

    else
    {
        c = 254;
        ser_bytes(s, &c, 1);
        ser_u32(s, vlen);
    }

    /* u64 case intentionally not implemented */
}

void ser_str(cstring* s, const char* s_in, size_t maxlen)
{
    size_t slen = strnlen(s_in, maxlen);

    ser_varlen(s, (uint32_t)slen);
    ser_bytes(s, s_in, slen);
}

void ser_varstr(cstring* s, cstring* s_in)
{
    if (!s_in || !s_in->len)
    {
        ser_varlen(s, 0);
        return;
    }

    ser_varlen(s, (uint32_t)s_in->len);
    ser_bytes(s, s_in->str, s_in->len);
}

int deser_skip(struct const_buffer* buf, size_t len)
{
    char* p;
    if (buf->len < len)
        return false;

    p = (char*)buf->p;
    p += len;
    buf->p = p;
    buf->len -= len;

    return true;
}

int deser_bytes(void* po, struct const_buffer* buf, size_t len)
{
    char* p;
    if (buf->len < len)
        return false;

    memcpy(po, buf->p, len);
    p = (char*)buf->p;
    p += len;
    buf->p = p;
    buf->len -= len;

    return true;
}

int deser_u16(uint16_t* vo, struct const_buffer* buf)
{
    uint16_t v;

    if (!deser_bytes(&v, buf, sizeof(v)))
        return false;

    *vo = le16toh(v);
    return true;
}

int deser_s32(int32_t* vo, struct const_buffer* buf)
{
    int32_t v;

    if (!deser_bytes(&v, buf, sizeof(v)))
        return false;

    *vo = le32toh(v);
    return true;
}

int deser_u32(uint32_t* vo, struct const_buffer* buf)
{
    uint32_t v;

    if (!deser_bytes(&v, buf, sizeof(v)))
        return false;

    *vo = le32toh(v);
    return true;
}

int deser_u64(uint64_t* vo, struct const_buffer* buf)
{
    uint64_t v;

    if (!deser_bytes(&v, buf, sizeof(v)))
        return false;

    *vo = le64toh(v);
    return true;
}

int deser_u256(uint256 vo, struct const_buffer* buf)
{
    return deser_bytes(vo, buf, 32);
}

int deser_varlen(uint32_t* lo, struct const_buffer* buf)
{
    uint32_t len;

    unsigned char c;
    if (!deser_bytes(&c, buf, 1))
        return false;

    if (c == 253)
    {
        uint16_t v16;
        if (!deser_u16(&v16, buf))
            return false;
        len = v16;
    }
    else if (c == 254)
    {
        uint32_t v32;
        if (!deser_u32(&v32, buf))
            return false;
        len = v32;
    }
    else if (c == 255)
    {
        uint64_t v64;
        if (!deser_u64(&v64, buf))
            return false;
        len = (uint32_t)v64; /* WARNING: truncate */
    }
    else
        len = c;

    *lo = len;
    return true;
}

int deser_varlen_from_file(uint32_t* lo, FILE* file)
{
    uint32_t len;
    struct const_buffer buf;
    unsigned char c;
    unsigned char bufp[sizeof(uint64_t)];

    if (fread(&c, 1, 1, file) != 1)
        return false;

    buf.p = (void*)bufp;
    buf.len = sizeof(uint64_t);

    if (c == 253)
    {
        uint16_t v16;
        if (fread((void*)buf.p, 1, sizeof(v16), file) != sizeof(v16))
            return false;
        if (!deser_u16(&v16, &buf))
            return false;
        len = v16;
    }
    else if (c == 254)
    {
        uint32_t v32;
        if (fread((void*)buf.p, 1, sizeof(v32), file) != sizeof(v32))
            return false;
        if (!deser_u32(&v32, &buf))
            return false;
        len = v32;
    }
    else if (c == 255)
    {
        uint64_t v64;
        if (fread((void*)buf.p, 1, sizeof(v64), file) != sizeof(v64))
            return false;
        if (!deser_u64(&v64, &buf))
            return false;
        len = (uint32_t)v64; /* WARNING: truncate */
    }
    else
        len = c;

    *lo = len;
    return true;
}

int deser_varlen_file(uint32_t* lo, FILE* file, uint8_t* rawdata, size_t* buflen_inout)
{
    uint32_t len;
    struct const_buffer buf;
    unsigned char c;
    unsigned char bufp[sizeof(uint64_t)];

    /* check min size of the buffer */
    if (*buflen_inout < sizeof(len))
        return false;

    if (fread(&c, 1, 1, file) != 1)
        return false;

    rawdata[0] = c;
    *buflen_inout = 1;

    buf.p = (void*)bufp;
    buf.len = sizeof(uint64_t);

    if (c == 253)
    {
        uint16_t v16;
        if (fread((void*)buf.p, 1, sizeof(v16), file) != sizeof(v16))
            return false;
        memcpy(rawdata + 1, buf.p, sizeof(v16));
        *buflen_inout += sizeof(v16);
        if (!deser_u16(&v16, &buf))
            return false;
        len = v16;
    }
    else if (c == 254)
    {
        uint32_t v32;
        if (fread((void*)buf.p, 1, sizeof(v32), file) != sizeof(v32))
            return false;
        memcpy(rawdata + 1, buf.p, sizeof(v32));
        *buflen_inout += sizeof(v32);
        if (!deser_u32(&v32, &buf))
            return false;
        len = v32;
    }
    else if (c == 255)
    {
        uint64_t v64;
        if (fread((void*)buf.p, 1, sizeof(v64), file) != sizeof(v64))
            return false;
        memcpy(rawdata + 1, buf.p, sizeof(uint32_t)); /* warning, truncate! */
        *buflen_inout += sizeof(uint32_t);
        if (!deser_u64(&v64, &buf))
            return false;
        len = (uint32_t)v64; /* WARNING: truncate */
    }
    else
        len = c;

    *lo = len;
    return true;
}


int deser_str(char* so, struct const_buffer* buf, size_t maxlen)
{
    uint32_t len;
    uint32_t skip_len = 0;
    if (!deser_varlen(&len, buf))
        return false;

    /* if input larger than buffer, truncate copy, skip remainder */
    if (len > maxlen)
    {
        skip_len = len - (uint32_t)maxlen;
        len = (uint32_t)maxlen;
    }

    if (!deser_bytes(so, buf, len))
        return false;
    if (!deser_skip(buf, skip_len))
        return false;

    /* add C string null */
    if (len < maxlen)
        so[len] = 0;
    else
        so[maxlen - 1] = 0;

    return true;
}

int deser_varstr(cstring** so, struct const_buffer* buf)
{
    uint32_t len;
    cstring* s;
    char* p;

    if (*so)
    {
        cstr_free(*so, 1);
        *so = NULL;
    }

    if (!deser_varlen(&len, buf))
        return false;

    if (buf->len < len)
        return false;

    s = cstr_new_sz(len);
    cstr_append_buf(s, buf->p, len);

    p = (char*)buf->p;
    p += len;
    buf->p = p;
    buf->len -= len;

    *so = s;

    return true;
}

int deser_s64(int64_t* vo, struct const_buffer* buf)
{
    return deser_u64((uint64_t*)vo, buf);
}