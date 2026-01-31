#include "ethereum.h"
#include "sha3.h"
#include <secp256k1_recovery.h>
#include <string.h>
#include <ctype.h>
#include <gmp.h>
#include "rand.h"
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <strings.h>
#elif defined(_MSC_VER)
#define strncasecmp _strnicmp
#endif
#define ethc_abi_buf_pr64(dest, framebuf, offset) \
  dest = (uint64_t)framebuf->buf[offset + 24] << 0x38; \
  dest |= (uint64_t)framebuf->buf[offset + 25] << 0x30; \
  dest |= (uint64_t)framebuf->buf[offset + 26] << 0x28; \
  dest |= (uint64_t)framebuf->buf[offset + 27] << 0x20; \
  dest |= (uint64_t)framebuf->buf[offset + 28] << 0x18; \
  dest |= framebuf->buf[offset + 29] << 0x10; \
  dest |= framebuf->buf[offset + 30] << 0x08; \
  dest |= framebuf->buf[offset + 31];

#define ethc_abi_buf_pr32(dest, framebuf, offset) \
  dest = (uint64_t)framebuf->buf[offset + 28] << 0x18; \
  dest |= framebuf->buf[offset + 29] << 0x10; \
  dest |= framebuf->buf[offset + 30] << 0x08; \
  dest |= framebuf->buf[offset + 31];

#define ethc_abi_buf_pr16(dest, framebuf, offset) \
  dest = framebuf->buf[offset + 30] << 0x08; \
  dest |= framebuf->buf[offset + 31];

#define ethc_abi_buf_pr8(dest, framebuf, offset) \
  dest = framebuf->buf[offset + 31];

#define ethc_abi_buf_pw64(framebuf, src, offset) \
  framebuf->buf[offset + 24] = (src >> 0x38) & 0xFF; \
  framebuf->buf[offset + 25] = (src >> 0x30) & 0xFF; \
  framebuf->buf[offset + 26] = (src >> 0x28) & 0xFF; \
  framebuf->buf[offset + 27] = (src >> 0x20) & 0xFF; \
  framebuf->buf[offset + 28] = (src >> 0x18) & 0xFF; \
  framebuf->buf[offset + 29] = (src >> 0x10) & 0xFF; \
  framebuf->buf[offset + 30] = (src >> 0x08) & 0xFF; \
  framebuf->buf[offset + 31] = (src & 0xFF);

#define ethc_abi_buf_pw32(framebuf, src, offset) \
  framebuf->buf[offset + 28] = (src >> 0x18) & 0xFF; \
  framebuf->buf[offset + 29] = (src >> 0x10) & 0xFF; \
  framebuf->buf[offset + 30] = (src >> 0x08) & 0xFF; \
  framebuf->buf[offset + 31] = (src & 0xFF);

#define ethc_abi_buf_pw16(framebuf, src, offset) \
  framebuf->buf[offset + 30] = (src >> 0x08) & 0xFF; \
  framebuf->buf[offset + 31] = (src & 0xFF);

#define ethc_abi_buf_pw8(framebuf, src, offset) \
  framebuf->buf[offset + 31] = (src & 0xFF);

int eth_keccak256(uint8_t* dest, const uint8_t* bytes, size_t len)
{
    keccak_256(bytes, len, dest);
    return 1;
}

int eth_keccak256p(uint8_t* dest, const uint8_t* bytes, size_t len)
{
    int size, r;
    char* sig, * tmp;

    if (dest == NULL || bytes == NULL)
        return -1;

    size = gmp_asprintf(&sig, "\x19" "Ethereum Signed Message:\n%llu", len);
    tmp = realloc(sig, size + len);
    if (tmp == NULL)
    {
        free(sig);
        return -1;
    }
    sig = tmp;

    strncpy(sig + size, (char*)bytes, len);
    r = eth_keccak256(dest, (uint8_t*)sig, size + len);
    free(sig);
    return r;
}

int eth_is_hex(const char* str, int len)
{
    int i;
    char ch;

    if (str == NULL || len == 0)
        return -1;

    if (len < 0)
        len = (int)strlen(str);

    if (ethc_strncasecmp(str, "0x", 2) == 0)
    {
        if (len == 2)
            return 0;

        str += 2;
        len -= 2;
    }

    for (i = 0; i < len; i++)
    {
        ch = str[i];
        if (((ch < 'A' || ch > 'F') && (ch < 'a' || ch > 'f')) &&
            (ch < '0' || ch > '9'))
            return 0;
    }

    return 1;
}

int eth_hex_pad_left(char* dest, const char* str, int len, size_t width)
{
    size_t zeros = 0;

    if (len < 0)
        len = (int)strlen(str);

    if (dest == NULL || str == NULL || len == 0 || len > (int)width)
        return -1;

    if (eth_is_hex(str, len) != 1)
        return -1;

    zeros = width - len;
    memset(dest, '0', zeros);
    memcpy(dest + zeros, str, len);
    dest[width] = '\0';

    return 1;
}

int eth_hex_pad_right(char* dest, const char* str, int len, size_t width)
{
    size_t zeros = 0;

    if (len < 0)
        len = (int)strlen(str);

    if (dest == NULL || str == NULL || len == 0 || len > (int)width)
        return -1;

    if (eth_is_hex(str, len) == 0)
        return -1;

    strncpy(dest, str, len);
    zeros = width - len;
    memset(dest + len, '0', zeros);
    dest[width] = '\0';

    return 1;
}

int eth_hex_from_bytes(char** dest, const uint8_t* bytes, size_t len)
{
    char* buf;
    size_t i = 0, j = 0;

    if (dest == NULL || bytes == NULL)
        return -1;

    buf = (char*)malloc((len * 2) + 1);
    if (buf == NULL)
        return -1;

    while (i < len)
    {
        buf[j++] = ethc_hexchar((bytes[i] >> 4) & 0xf);
        buf[j++] = ethc_hexchar(bytes[i] & 0xf);
        i++;
    }

    buf[j] = '\0';
    *dest = buf;
    return (int)j;
}

int eth_hex_to_bytes(uint8_t** dest, const char* hex, int len)
{
    uint8_t* buf;
    size_t i, bsize, k = 0;

    if (dest == NULL || hex == NULL)
        return -1;

    if (len < 0)
        len = (int)strlen(hex);

    if (eth_is_hex(hex, len) <= 0)
        return -1;

    if (ethc_strncasecmp(hex, "0x", 2) == 0)
    {
        if (len == 2)
            return -1;

        hex += 2;
        len -= 2;
    }

    bsize = (len % 2 == 0 ? len : len + 1) / 2;
    buf = (uint8_t*)malloc(bsize);
    if (buf == NULL)
        return -1;

    if (len % 2 != 0)
    {
        buf[k++] = ethc_hexcharb(hex[0]);
        hex += 1;
        len -= 1;
    }

    for (i = 0; i < (size_t)len; i += 2)
        buf[k++] = (ethc_hexcharb((hex[i])) << 4)
        | ethc_hexcharb((hex[i + 1]));

    *dest = buf;
    return (int)k;
}

int ethc_rand(uint8_t* bytes, size_t len)
{
    random_buffer(bytes, len);
    return 1;
}

int ethc_strncasecmp(const char* s1, const char* s2, size_t len)
{
    return strncasecmp(s1, s2, len);
}

int ethc_hexcharb(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    else if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    else if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    else
        return 0;
}

char ethc_hexchar(uint8_t d)
{
    const char* hexchars = "0123456789abcdef";
    return hexchars[d];
}

int eth_is_address(const char* addr)
{
    if (addr == NULL)
        return -1;

    if (ethc_strncasecmp(addr, "0x", 2) == 0)
        return eth_is_hex(addr, 42);

    return eth_is_hex(addr, 40);
}

int eth_is_checksum_address(const char* addr)
{
    uint8_t lcaddr[40], keccak[32], i;

    if (addr == NULL)
        return -1;

    if (ethc_strncasecmp(addr, "0x", 2) == 0)
        addr += 2;

    if (eth_is_hex(addr, 40) <= 0)
        return -1;

    for (i = 0; i < 40; i++)
        lcaddr[i] = tolower(addr[i]);

    if (eth_keccak256(keccak, lcaddr, 40) <= 0)
        return -1;

    for (i = 0; i < 20; i++)
    {
        const char* addrptr = addr + (i * 2);
        uint8_t hnib = (keccak[i] >> 0x04) & 0xf;
        uint8_t lnib = keccak[i] & 0x0f;

        if ((hnib >= 8 && islower(*addrptr)) || (hnib < 8 && isupper(*addrptr)))
            return 0;

        if ((lnib >= 8 && islower(*(addrptr + 1))) || (lnib < 8 && isupper(*(addrptr + 1))))
            return 0;
    }

    return 1;
}

int eth_to_checksum_address(char* addr)
{
    uint8_t keccak[32];
    int i;

    if (addr == NULL)
        return -1;

    if (ethc_strncasecmp(addr, "0x", 2) == 0)
        addr += 2;

    if (eth_is_hex(addr, 40) <= 0)
        return -1;

    if (eth_keccak256(keccak, (uint8_t*)addr, 40) != 1)
        return -1;

    for (i = 0; i < 20; i++)
    {
        char* addrptr = addr + (i * 2);
        uint8_t hnib = keccak[i] >> 4 & 0xf;
        uint8_t lnib = keccak[i] & 0x0f;

        if (hnib >= 8)
            *addrptr = toupper(*addrptr);
        else
            *addrptr = tolower(*addrptr);

        if (lnib >= 8)
            *(addrptr + 1) = toupper(*(addrptr + 1));
        else
            *(addrptr + 1) = tolower(*(addrptr + 1));
    }

    return 1;
}

int eth_ecdsa_pubkey_get(uint8_t* dest, const uint8_t* privkey)
{
    secp256k1_context* secp_ctx;
    secp256k1_pubkey secp_pub;
    size_t outlen = 65;
    uint8_t tmp[65];
    int r = 0;

    if (dest == NULL || privkey == NULL)
        return -1;

    secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (secp_ctx == NULL)
        return -1;

    r = secp256k1_ec_pubkey_create(secp_ctx, &secp_pub, privkey);
    if (r == 0)
        return -1;

    secp256k1_ec_pubkey_serialize(secp_ctx, tmp, &outlen, &secp_pub,
                                  SECP256K1_EC_UNCOMPRESSED);
    memcpy(dest, tmp + 1, 64);
    secp256k1_context_destroy(secp_ctx);
    return 1;
}

int eth_ecdsa_sign(struct eth_ecdsa_signature* dest, const uint8_t* privkey, const uint8_t* bytes32)
{
    secp256k1_context* secp_ctx;
    secp256k1_ecdsa_recoverable_signature secp_sig;
    uint8_t signature[64];
    int r = 0;

    if (dest == NULL || privkey == NULL || bytes32 == NULL)
        return -1;

    secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (secp_ctx == NULL)
        return -1;

    r = secp256k1_ecdsa_sign_recoverable(secp_ctx, &secp_sig, bytes32, privkey,
                                         NULL, NULL);
    if (r == 0)
        return -1;

    r = secp256k1_ecdsa_recoverable_signature_serialize_compact(
        secp_ctx, signature, &dest->recid, &secp_sig);
    if (r == 0)
        return -1;

    memcpy(dest->r, signature, 32);
    memcpy(dest->s, signature + 32, 32);

    secp256k1_context_destroy(secp_ctx);
    return 1;
}

int eth_rlp_frame_init(struct ethc_rlp_frame** dest, uint8_t* bytes, size_t len)
{
    struct ethc_rlp_frame* nframe;
    uint8_t* buf;
    size_t bufsize;

    nframe = (struct ethc_rlp_frame*)malloc(sizeof(struct ethc_rlp_frame));
    if (nframe == NULL)
        return -1;

    bufsize = bytes != NULL ? len : ETHC_RLP_FRAME_INITIAL_SIZE;
    buf = (uint8_t*)malloc(bufsize);
    if (buf == NULL)
    {
        free(nframe);
        return -1;
    }

    nframe->buf = buf;
    nframe->pframe = NULL;
    nframe->offset = 0;
    nframe->len = len;

    if (bytes != NULL)
        memcpy(nframe->buf, bytes, len);

    *dest = nframe;
    return 1;
}

int eth_rlp_init(struct eth_rlp* dest, int m)
{
    struct ethc_rlp_frame* nframe;

    if (dest == NULL)
        return -1;

    if (eth_rlp_frame_init(&nframe, NULL, 0) <= 0)
        return -1;

    dest->cframe = nframe;
    dest->m = m;
    return 1;
}

int eth_rlp_array(struct eth_rlp* rlp)
{
    struct ethc_rlp_frame* cframe, * nframe;
    uint8_t base;

    if (rlp == NULL)
        return -1;

    cframe = rlp->cframe;

    if (rlp->m == ETH_RLP_ENCODE)
    {
        if (eth_rlp_frame_init(&nframe, NULL, 0) <= 0)
            return -1;

        nframe->pframe = cframe;
        rlp->cframe = nframe;
        return 1;
    }

    if (rlp->m == ETH_RLP_DECODE)
    {
        if (eth_rlp_len(rlp, NULL, &base) <= 0)
            return -1;

        if (base != 0xc0 && base != 0xf7)
            return -1;

        return 1;
    }

    return -1;
}

int eth_rlp_array_end(struct eth_rlp* rlp)
{
    struct ethc_rlp_frame* cframe, * pframe;
    uint8_t base;

    if (rlp == NULL)
        return -1;

    cframe = rlp->cframe;
    pframe = cframe->pframe;

    if (rlp->m == ETH_RLP_ENCODE)
    {
        base = cframe->len <= 0x37 ? 0xc0 : 0xf7;

        rlp->cframe = pframe;

        if (eth_rlp_len(rlp, &(cframe->len), &base) <= 0)
            return -1;

        memcpy(&(pframe->buf[pframe->offset]), cframe->buf, cframe->len);
        pframe->offset += cframe->len;
        pframe->len += cframe->len;
        free(cframe->buf);
        free(cframe);
        return 1;
    }

    if (rlp->m == ETH_RLP_DECODE)
        return 1;

    return -1;
}

int eth_rlp_len(struct eth_rlp* rlp, size_t* len, uint8_t* base)
{
    struct ethc_rlp_frame* cframe;
    uint8_t head, bbase, llen;

    if (rlp == NULL)
        return -1;

    cframe = rlp->cframe;

    if (rlp->m == ETH_RLP_ENCODE)
    {
        if (len == NULL || base == NULL)
            return -1;

        if (*len <= 0x37)
        {
            cframe->buf[cframe->offset++] = *base + (uint8_t)*len;
            cframe->len++;
        }
        else if (*len <= 0xFF)
        {
            cframe->buf[cframe->offset++] = *base + 0x01;
            cframe->buf[cframe->offset++] = (uint8_t)*len;
            cframe->len += 2;
        }
        else if (*len <= 0xFFFF)
        {
            cframe->buf[cframe->offset++] = *base + 0x02;
            cframe->buf[cframe->offset++] = (*len >> 0x08) & 0xFF;
            cframe->buf[cframe->offset++] = *len & 0xFF;
            cframe->len += 3;
        }
        else if (*len <= 0xFFFFFFFF)
        {
            cframe->buf[cframe->offset++] = *base + 0x04;
            cframe->buf[cframe->offset++] = (*len >> 0x18) & 0xFF;
            cframe->buf[cframe->offset++] = (*len >> 0x10) & 0xFF;
            cframe->buf[cframe->offset++] = (*len >> 0x08) & 0xFF;
            cframe->buf[cframe->offset++] = *len & 0xFF;
            cframe->len += 5;
        }
        else if (*len <= 0xFFFFFFFFFFFFFFFF)
        {
            cframe->buf[cframe->offset++] = *base + 0x08;
            cframe->buf[cframe->offset++] = (*len >> 0x38) & 0xFF;
            cframe->buf[cframe->offset++] = (*len >> 0x30) & 0xFF;
            cframe->buf[cframe->offset++] = (*len >> 0x28) & 0xFF;
            cframe->buf[cframe->offset++] = (*len >> 0x20) & 0xFF;
            cframe->buf[cframe->offset++] = (*len >> 0x18) & 0xFF;
            cframe->buf[cframe->offset++] = (*len >> 0x10) & 0xFF;
            cframe->buf[cframe->offset++] = (*len >> 0x08) & 0xFF;
            cframe->buf[cframe->offset++] = *len & 0xFF;
            cframe->len += 9;
        }
        else
        {
            return -1;
        }

        return 1;
    }

    if (rlp->m == ETH_RLP_DECODE)
    {
        head = cframe->buf[cframe->offset];

        if (head <= 0x7F)
        {
            llen = 1;
            bbase = 0;
        }
        else if (head <= 0xB7 || head <= 0xF7)
        {
            bbase = head <= 0xB7 ? 0x80 : 0xC0;
            llen = head - bbase;
            cframe->offset++;
        }
        else
        {
            bbase = head <= 0xBF ? 0xB8 : 0xF8;
            llen = head - bbase;

            if (llen <= 1)
            {
                llen = cframe->buf[cframe->offset++];
                cframe->offset += llen + 1;
            }
            else if (llen <= 2)
            {
                llen = cframe->buf[cframe->offset++] << 0x04;
                llen |= llen | cframe->buf[cframe->offset++];
                cframe->offset += llen + 2;
            }
            else if (*len <= 4)
            {
                llen = cframe->buf[cframe->offset++] << 0x18;
                llen |= cframe->buf[cframe->offset++] << 0x10;
                llen |= cframe->buf[cframe->offset++] << 0x08;
                llen |= cframe->buf[cframe->offset++];
                cframe->offset = llen + 4;
            }
            else if (*len <= 8)
            {
                llen = (size_t)cframe->buf[cframe->offset++] << 0x38;
                llen |= (size_t)cframe->buf[cframe->offset++] << 0x30;
                llen |= (size_t)cframe->buf[cframe->offset++] << 0x28;
                llen |= (size_t)cframe->buf[cframe->offset++] << 0x20;
                llen |= cframe->buf[cframe->offset++] << 0x18;
                llen |= cframe->buf[cframe->offset++] << 0x10;
                llen |= cframe->buf[cframe->offset++] << 0x08;
                llen |= cframe->buf[cframe->offset++];
                cframe->offset += 8;
            }
            else
            {
                return -1;
            }
        }

        if (len != NULL)
            *len = llen;

        if (base != NULL)
            *base = bbase;

        return 1;
    }

    return -1;
}

int eth_rlp_bytes(struct eth_rlp* rlp, uint8_t** bytes, size_t* len)
{
    struct ethc_rlp_frame* cframe;
    uint8_t base, * buf;

    if (rlp == NULL || bytes == NULL)
        return -1;

    cframe = rlp->cframe;

    if (rlp->m == ETH_RLP_ENCODE)
    {
        if (*len == 1 && **bytes <= 0x7F)
        {
            /* single 0 value is empty bytes (0x) */
            if (**bytes == 0x00)
                cframe->buf[cframe->offset++] = 0x80;
            else
                cframe->buf[cframe->offset++] = **bytes;

            cframe->len++;
            return 1;
        }

        base = *len <= 0x37 ? 0x80 : 0xB7;
        if (eth_rlp_len(rlp, len, &base) <= 0)
            return -1;

        memcpy(&(cframe->buf[cframe->offset]), *bytes, *len);
        cframe->offset += *len;
        cframe->len += *len;
        return 1;
    }

    if (rlp->m == ETH_RLP_DECODE)
    {
        if (eth_rlp_len(rlp, len, &base) <= 0)
            return -1;

        if (base != 0x00 && base != 0x80)
            return -1;

        buf = (uint8_t*)malloc(sizeof(uint8_t) * (*len));
        if (buf == NULL)
            return -1;

        memcpy(buf, &(cframe->buf[cframe->offset]), *len);
        cframe->offset += *len;
        cframe->len += *len;
        *bytes = buf;
        return 1;
    }

    return -1;
}

int eth_rlp_hex(struct eth_rlp* rlp, char** hex, int* len)
{
    uint8_t* buf;
    size_t hsize;
    int hlen;

    if (rlp == NULL || hex == NULL)
        return -1;

    if (rlp->m == ETH_RLP_ENCODE)
    {
        /* TODO: not safe */
        hlen = len == NULL ? (int)strlen(*hex) : *len;

        if (eth_is_hex(*hex, hlen) <= 0)
            return -1;

        if ((hsize = eth_hex_to_bytes(&buf, *hex, hlen)) <= 0)
            return -1;

        if (eth_rlp_bytes(rlp, &buf, &hsize) <= 0)
        {
            free(buf);
            return -1;
        }

        free(buf);
        return 1;
    }

    if (rlp->m == ETH_RLP_DECODE)
    {
        if (eth_rlp_bytes(rlp, &buf, &hsize) <= 0)
            return -1;

        if ((hsize = (size_t)eth_hex_from_bytes(hex, buf, hsize)) <= 0)
            return -1;

        if (len != NULL)
            *len = (int)hsize;

        free(buf);
        return 1;
    }

    return -1;
}

int eth_rlp_uint8(struct eth_rlp* rlp, uint8_t* d)
{
    uint8_t data[1], * bytes = data;
    size_t blen = 0;

    if (rlp == NULL || d == NULL)
        return -1;

    if (rlp->m == ETH_RLP_ENCODE)
    {
        bytes[blen++] = *d;

        return eth_rlp_bytes(rlp, &bytes, &blen);
    }

    if (rlp->m == ETH_RLP_DECODE)
    {
        if (eth_rlp_bytes(rlp, &bytes, &blen) <= 0)
            return -1;

        *d = *bytes;
        free(bytes);
        return 1;
    }

    return -1;
}

int eth_rlp_uint16(struct eth_rlp* rlp, uint16_t* d)
{
    uint8_t data[2], * bytes = data;
    size_t blen = 0;

    if (rlp == NULL || d == NULL)
        return -1;

    if (rlp->m == ETH_RLP_ENCODE)
    {
        bytes[blen++] = (*d >> 0x08) & 0xFF;
        bytes[blen++] = *d & 0xFF;

        return eth_rlp_bytes(rlp, &bytes, &blen);
    }

    if (rlp->m == ETH_RLP_DECODE)
    {
        if (eth_rlp_bytes(rlp, &bytes, &blen) <= 0)
            return -1;

        *d = bytes[0] << 0x08;
        *d += bytes[1];

        free(bytes);
        return 1;
    }

    return -1;
}

int eth_rlp_uint32(struct eth_rlp* rlp, uint32_t* d)
{
    uint8_t data[4], * bytes = data;
    size_t blen = 0;

    if (rlp == NULL || d == NULL)
        return -1;

    if (rlp->m == ETH_RLP_ENCODE)
    {
        bytes[blen++] = (*d >> 0x18) & 0xFF;
        bytes[blen++] = (*d >> 0x10) & 0xFF;
        bytes[blen++] = (*d >> 0x08) & 0xFF;
        bytes[blen++] = *d & 0xFF;

        return eth_rlp_bytes(rlp, &bytes, &blen);
    }

    if (rlp->m == ETH_RLP_DECODE)
    {
        if (eth_rlp_bytes(rlp, &bytes, &blen) <= 0)
            return -1;

        *d = bytes[0] << 0x18;
        *d |= bytes[1] << 0x10;
        *d |= bytes[2] << 0x08;
        *d |= bytes[3];
        free(bytes);
        return 1;
    }

    return -1;
}

int eth_rlp_uint64(struct eth_rlp* rlp, uint64_t* d)
{
    uint8_t data[8], * bytes = data;
    size_t blen = 0;

    if (rlp == NULL || d == NULL)
        return -1;

    if (rlp->m == ETH_RLP_ENCODE)
    {
        bytes[blen++] = (*d >> 0x38) & 0xFF;
        bytes[blen++] = (*d >> 0x30) & 0xFF;
        bytes[blen++] = (*d >> 0x28) & 0xFF;
        bytes[blen++] = (*d >> 0x20) & 0xFF;
        bytes[blen++] = (*d >> 0x18) & 0xFF;
        bytes[blen++] = (*d >> 0x10) & 0xFF;
        bytes[blen++] = (*d >> 0x08) & 0xFF;
        bytes[blen++] = *d & 0xFF;

        return eth_rlp_bytes(rlp, &bytes, &blen);
    }

    if (rlp->m == ETH_RLP_DECODE)
    {
        if (eth_rlp_bytes(rlp, &bytes, &blen) <= 0)
            return -1;

        *d = (uint64_t)bytes[0] << 0x38;
        *d |= (uint64_t)bytes[1] << 0x30;
        *d |= (uint64_t)bytes[2] << 0x28;
        *d |= (uint64_t)bytes[3] << 0x20;
        *d |= bytes[4] << 0x18;
        *d |= bytes[5] << 0x10;
        *d |= bytes[6] << 0x8;
        *d |= bytes[7];
        free(bytes);
        return 1;
    }

    return -1;
}

int eth_rlp_uint(struct eth_rlp* rlp, uint64_t* d)
{
    size_t offset, len;
    uint8_t base;

    if (rlp->m == ETH_RLP_ENCODE)
    {
        if (*d <= 0xff)
        {
            return eth_rlp_uint8(rlp, (uint8_t*)d);
        }
        else if (*d <= 0xffff)
        {
            return eth_rlp_uint16(rlp, (uint16_t*)d);
        }
        else if (*d <= 0xffffffff)
        {
            return eth_rlp_uint32(rlp, (uint32_t*)d);
        }
        else if (*d <= 0xffffffffffffffff)
        {
            return eth_rlp_uint64(rlp, d);
        }

        return -1;
    }

    if (rlp->m == ETH_RLP_DECODE)
    {
        offset = rlp->cframe->offset;

        if (eth_rlp_len(rlp, &len, &base) <= 0)
            return -1;

        rlp->cframe->offset = offset;

        if (len <= 1)
            return eth_rlp_uint8(rlp, (uint8_t*)d);
        else if (len <= 2)
            return eth_rlp_uint16(rlp, (uint16_t*)d);
        else if (len <= 4)
            return eth_rlp_uint32(rlp, (uint32_t*)d);
        else if (len <= 8)
            return eth_rlp_uint64(rlp, (uint64_t*)d);

        return -1;
    }

    return -1;
}

int eth_rlp_address(struct eth_rlp* rlp, char** addr)
{
    int hexlen;

    if (rlp == NULL || addr == NULL)
        return -1;

    if (rlp->m == ETH_RLP_ENCODE)
    {
        if (eth_is_address(*addr) <= 0)
            return -1;

        if (strncmp(*addr, "0x", 2) == 0)
            *addr += 2;

        hexlen = 40;
        if (eth_rlp_hex(rlp, addr, &hexlen) <= 0)
            return -1;

        return 1;
    }

    if (rlp->m == ETH_RLP_DECODE)
        return eth_rlp_hex(rlp, addr, &hexlen);

    return -1;
}

int eth_rlp_to_hex(char** dest, struct eth_rlp* src)
{
    struct ethc_rlp_frame* cframe;
    char* buf;
    int hsize;

    if (dest == NULL || src == NULL)
        return -1;

    cframe = src->cframe;

    hsize = eth_hex_from_bytes(&buf, cframe->buf, cframe->len);
    if (hsize <= 0)
        return -1;

    *dest = buf;
    return hsize;
}

int eth_rlp_to_bytes(uint8_t** bytes, size_t* len, struct eth_rlp* src)
{
    struct ethc_rlp_frame* cframe;
    uint8_t* buf;

    if (bytes == NULL || len == NULL || src == NULL)
        return -1;

    cframe = src->cframe;

    buf = (uint8_t*)malloc(cframe->len);
    if (buf == NULL)
        return -1;

    memcpy(buf, cframe->buf, cframe->len);

    *bytes = buf;
    *len = cframe->len;
    return 1;
}

int eth_rlp_from_hex(struct eth_rlp* dest, char* hex, int len)
{
    struct ethc_rlp_frame* nframe;
    uint8_t* buf, sbuf;

    if (dest == NULL || hex == NULL)
        return -1;

    if (len < 0)
        len = (int)strlen(hex); /* TODO: NOT SAFE */

    if ((sbuf = eth_hex_to_bytes(&buf, hex, len)) <= 0)
        return -1;

    if (eth_rlp_frame_init(&nframe, buf, sbuf) <= 0)
        return -1;

    dest->cframe = nframe;
    dest->m = ETH_RLP_DECODE;
    return 1;
}

int eth_rlp_free(struct eth_rlp* dest)
{
    struct ethc_rlp_frame* cframe;
    if (dest == NULL)
        return -1;

    cframe = dest->cframe;

    free(cframe->buf);
    return 1;
}

int ethc_abi_buf_init(struct ethc_abi_buf** dest, size_t size)
{
    struct ethc_abi_buf* bbuf;
    uint8_t* buf;

    bbuf = (struct ethc_abi_buf*)malloc(sizeof(struct ethc_abi_buf));
    if (bbuf == NULL)
        return -1;

    buf = calloc(size, sizeof(uint8_t));
    if (buf == NULL)
    {
        free(bbuf);
        return -1;
    }

    bbuf->buf = buf;
    bbuf->len = 0;
    bbuf->offset = 0;
    *dest = bbuf;
    return 1;
}

int ethc_abi_frame_init(struct ethc_abi_frame** frame)
{
    struct ethc_abi_frame* nframe;
    struct ethc_abi_buf* fbuf;

    nframe = (struct ethc_abi_frame*)malloc(sizeof(struct ethc_abi_frame));
    if (nframe == NULL)
        return -1;

    if (ethc_abi_buf_init(&fbuf, ETHC_ABI_BUFFER_INITIAL_SIZE) < 0)
        return -1;

    nframe->buf = fbuf;
    nframe->pframe = NULL;
    nframe->dybuflen = 0;
    nframe->len = 0;
    *frame = nframe;
    return 1;
}

int ethc_abi_frame_backpatch(struct ethc_abi_frame* frame)
{
    struct ethc_abi_buf* framebuf, * dybuf;
    uint64_t dyoffset, i;

    framebuf = frame->buf;

    for (i = 0; i < frame->dybuflen; i++)
    {
        dybuf = frame->dybufs[i];

        dyoffset = frame->pframe == NULL
            ? framebuf->offset
            : framebuf->offset - ETH_ABI_WORD_SIZE;

        /* backpatch the offset for the dynamic buffer (can up to 2**64) */
        ethc_abi_buf_pw64(framebuf, dyoffset, dybuf->doffset);

        memcpy(&(framebuf->buf[framebuf->offset]), dybuf->buf, dybuf->len);
        framebuf->len += dybuf->len;
        framebuf->offset += dybuf->len;

        free(dybuf);
    }

    frame->dybuflen = 0;
    return 1;
}

int eth_abi_init(struct eth_abi* abi, int m)
{
    struct ethc_abi_frame* nframe;

    if (abi == NULL)
        return -1;

    if (ethc_abi_frame_init(&nframe) < 0)
        return -1;

    abi->m = m;
    abi->cframe = nframe;
    return 1;
}

int eth_abi_free(struct eth_abi* abi)
{
    if (abi == NULL)
        return -1;

    if (abi->cframe)
    {
        if (abi->cframe->buf)
            free(abi->cframe->buf->buf);
        free(abi->cframe->buf);
    }

    free(abi->cframe);
    abi->cframe = NULL;
    return 1;
}

int eth_abi_array(struct eth_abi* abi, uint64_t* len)
{
    struct ethc_abi_frame* cframe, * nframe;
    struct ethc_abi_buf* cframebuf, * nframebuf;
    uint64_t dyoffset, framelen;

    if (abi == NULL)
        return -1;

    cframe = abi->cframe;
    cframebuf = cframe->buf;

    if (abi->m == ETH_ABI_ENCODE)
    {
        if (ethc_abi_frame_init(&nframe) < 0)
            return -1;

        nframebuf = nframe->buf;
        nframebuf->doffset = cframebuf->offset;

        /* write offset */
        memset(cframebuf->buf + cframebuf->offset, 0, ETH_ABI_WORD_SIZE);
        cframebuf->len += ETH_ABI_WORD_SIZE;
        cframebuf->offset += ETH_ABI_WORD_SIZE;

        /* write length */
        memset(nframebuf->buf + nframebuf->offset, 0, ETH_ABI_WORD_SIZE);
        nframebuf->len += ETH_ABI_WORD_SIZE;
        nframebuf->offset += ETH_ABI_WORD_SIZE;

        cframe->dybufs[cframe->dybuflen++] = nframe->buf;
        nframe->pframe = cframe;
        abi->cframe = nframe;
        return 1;
    }

    if (abi->m == ETH_ABI_DECODE)
    {
        ethc_abi_buf_pr64(dyoffset, cframebuf, cframebuf->offset);
        dyoffset = cframebuf->offset % 32 != 0 ? dyoffset + 4 : dyoffset;
        ethc_abi_buf_pr64(framelen, cframebuf, dyoffset);

        nframebuf = (struct ethc_abi_buf*)malloc(sizeof(struct ethc_abi_buf));
        if (nframebuf == NULL)
            return -1;

        nframe = (struct ethc_abi_frame*)malloc(sizeof(struct ethc_abi_frame));
        if (nframe == NULL)
        {
            free(nframebuf);
            return -1;
        }

        if (len != NULL)
            *len = framelen;

        nframebuf->buf = &(cframebuf->buf[dyoffset + 32]);
        nframebuf->len = framelen * 32;
        nframebuf->offset = 0;
        nframebuf->doffset = cframebuf->offset;

        nframe->pframe = cframe;
        nframe->buf = nframebuf;
        nframe->len = framelen;

        abi->cframe = nframe;
        cframebuf->offset += 32;
        return 1;
    }

    return -1;
}

int eth_abi_array_end(struct eth_abi* abi)
{
    struct ethc_abi_buf* cframebuf;
    struct ethc_abi_frame* cframe;
    uint64_t asize;

    cframe = abi->cframe;
    cframebuf = cframe->buf;

    if (abi->m == ETH_ABI_ENCODE)
    {
        asize = cframebuf->len / ETH_ABI_WORD_SIZE - 1;

        /* backpatch the length */
        ethc_abi_buf_pw64(cframebuf, asize, 0);

        ethc_abi_frame_backpatch(abi->cframe);
        abi->cframe = abi->cframe->pframe;
        return 1;
    }

    if (abi->m == ETH_ABI_DECODE)
    {
        abi->cframe = abi->cframe->pframe;
        return 1;
    }

    return -1;
}

int eth_abi_bool(struct eth_abi* abi, uint8_t* b)
{
    uint8_t u8bool;

    if (abi == NULL || b == NULL)
        return -1;

    if (abi->m == ETH_ABI_ENCODE)
    {
        u8bool = *b == 0 ? 0 : 1;
        return eth_abi_uint8(abi, &u8bool);
    }

    if (abi->m == ETH_ABI_DECODE)
        return eth_abi_uint8(abi, b);

    return -1;
}

int eth_abi_address(struct eth_abi* abi, char** addr)
{
    struct ethc_abi_frame* cframe;
    struct ethc_abi_buf* cframebuf;
    uint8_t* tmp;

    cframe = abi->cframe;
    cframebuf = cframe->buf;

    if (abi->m == ETH_ABI_ENCODE)
    {
        if (eth_is_hex(*addr, 42) <= 0)
            return -1;

        if (eth_hex_to_bytes(&tmp, *addr, 42) < 0)
            return -1;

        memcpy(&(cframebuf->buf[cframebuf->offset + 12]), tmp, 20);
        cframebuf->offset += ETH_ABI_WORD_SIZE;
        cframebuf->len += ETH_ABI_WORD_SIZE;
        free(tmp);
        return 1;
    }

    if (abi->m == ETH_ABI_DECODE)
    {
        tmp = &(cframebuf->buf[cframebuf->offset + 12]);

        if (eth_hex_from_bytes(addr, tmp, 20) < 0)
            return -1;

        cframebuf->offset += 32;

        return 1;
    }
    return -1;
}

int eth_abi_call(struct eth_abi* abi, char** fn, int* len)
{
    struct ethc_abi_buf* cframebuf;
    uint8_t keccak[32];
    int fnlen;

    cframebuf = abi->cframe->buf;

    if (abi->m == ETH_ABI_ENCODE)
    {
        if (len == NULL)
            fnlen = (int)strlen(*fn);

        if (eth_keccak256(keccak, (uint8_t*)*fn, fnlen) < 0)
            return -1;

        memcpy(&(cframebuf->buf[cframebuf->offset]), keccak, 4);
        cframebuf->buf += 4;
        return 1;
    }

    if (abi->m == ETH_ABI_DECODE)
    {
        fnlen = eth_hex_from_bytes(fn, &(cframebuf->buf[cframebuf->offset]), 4);
        if (fnlen < 0)
            return -1;

        if (len != NULL)
            *len = fnlen;
        cframebuf->offset += 4;
        return 1;
    }

    return -1;
}

int eth_abi_call_end(struct eth_abi* abi)
{
    struct ethc_abi_frame* cframe;
    struct ethc_abi_buf* cframebuf;

    cframe = abi->cframe;
    cframebuf = cframe->buf;

    if (abi->m == ETH_ABI_ENCODE)
    {
        ethc_abi_frame_backpatch(cframe);
        cframebuf->buf -= 4;
        cframebuf->len += 4;
        cframebuf->offset += 4;
        return 1;
    }

    if (abi->m == ETH_ABI_DECODE)
        return 1;

    return -1;
}

int eth_abi_uint8(struct eth_abi* abi, uint8_t* d)
{
    struct ethc_abi_buf* cframebuf;

    if (abi == NULL || d == NULL)
        return -1;

    cframebuf = abi->cframe->buf;

    if (abi->m == ETH_ABI_ENCODE)
    {
        ethc_abi_buf_pw8(cframebuf, *d, cframebuf->offset);
        cframebuf->offset += ETH_ABI_WORD_SIZE;
        cframebuf->len += ETH_ABI_WORD_SIZE;
        return 1;
    }

    if (abi->m == ETH_ABI_DECODE)
    {
        ethc_abi_buf_pr8(*d, cframebuf, cframebuf->offset);
        cframebuf->offset += ETH_ABI_WORD_SIZE;
        return 1;
    }

    return -1;
}

int eth_abi_uint16(struct eth_abi* abi, uint16_t* d)
{
    struct ethc_abi_buf* cframebuf;

    if (abi == NULL || d == NULL)
        return -1;

    cframebuf = abi->cframe->buf;

    if (abi->m == ETH_ABI_ENCODE)
    {
        ethc_abi_buf_pw16(cframebuf, *d, cframebuf->offset);
        cframebuf->offset += ETH_ABI_WORD_SIZE;
        cframebuf->len += ETH_ABI_WORD_SIZE;
        return 1;
    }

    if (abi->m == ETH_ABI_DECODE)
    {
        ethc_abi_buf_pr16(*d, cframebuf, cframebuf->offset);
        cframebuf->offset += ETH_ABI_WORD_SIZE;
        return 1;
    }

    return -1;
}

int eth_abi_uint32(struct eth_abi* abi, uint32_t* d)
{
    struct ethc_abi_buf* cframebuf;

    if (abi == NULL || d == NULL)
        return -1;

    cframebuf = abi->cframe->buf;

    if (abi->m == ETH_ABI_ENCODE)
    {
        ethc_abi_buf_pw32(cframebuf, *d, cframebuf->offset);
        cframebuf->offset += ETH_ABI_WORD_SIZE;
        cframebuf->len += ETH_ABI_WORD_SIZE;
        return 1;
    }

    if (abi->m == ETH_ABI_DECODE)
    {
        uint64_t tmp_d = (uint64_t)*d;
        ethc_abi_buf_pr32(tmp_d, cframebuf, cframebuf->offset);
        cframebuf->offset += ETH_ABI_WORD_SIZE;
        *d = (uint32_t)tmp_d;
        return 1;
    }

    return -1;
}

int eth_abi_uint64(struct eth_abi* abi, uint64_t* d)
{
    struct ethc_abi_buf* cframebuf;

    if (abi == NULL || d == NULL)
        return -1;

    cframebuf = abi->cframe->buf;

    if (abi->m == ETH_ABI_ENCODE)
    {
        ethc_abi_buf_pw64(cframebuf, *d, cframebuf->offset);
        cframebuf->offset += ETH_ABI_WORD_SIZE;
        cframebuf->len += ETH_ABI_WORD_SIZE;
        return 1;
    }

    if (abi->m == ETH_ABI_DECODE)
    {
        ethc_abi_buf_pr64(*d, cframebuf, cframebuf->offset);
        cframebuf->offset += ETH_ABI_WORD_SIZE;
        cframebuf->len += ETH_ABI_WORD_SIZE;
        return 1;
    }

    return -1;
}

int eth_abi_int8(struct eth_abi* abi, int8_t* d)
{
    struct ethc_abi_buf* cframebuf;
    int f;

    if (abi == NULL || d == NULL)
        return -1;

    cframebuf = abi->cframe->buf;

    if (abi->m == ETH_ABI_ENCODE)
    {
        f = *d & 0x8000 ? 0xFF : 0x00;
        memset(&(cframebuf->buf[cframebuf->offset]), f, ETH_ABI_WORD_SIZE - 1);
        cframebuf->offset += ETH_ABI_WORD_SIZE - 1;
        cframebuf->buf[cframebuf->offset++] = *d;
        cframebuf->len += ETH_ABI_WORD_SIZE;
        return 1;
    }

    if (abi->m == ETH_ABI_DECODE)
    {
        cframebuf->offset += ETH_ABI_WORD_SIZE - 1;
        *d = cframebuf->buf[cframebuf->offset++];
        return 1;
    }

    return -1;
}

int eth_abi_int16(struct eth_abi* abi, int16_t* d)
{
    struct ethc_abi_buf* cframebuf;
    int f;

    if (abi == NULL || d == NULL)
        return -1;

    cframebuf = abi->cframe->buf;

    if (abi->m == ETH_ABI_ENCODE)
    {
        f = *d & 0x8000 ? 0xFF : 0x00;
        memset(&(cframebuf->buf[cframebuf->offset]), f, ETH_ABI_WORD_SIZE - 2);
        ethc_abi_buf_pw16(cframebuf, *d, cframebuf->offset);
        cframebuf->offset += ETH_ABI_WORD_SIZE;
        cframebuf->len += ETH_ABI_WORD_SIZE;
        return 1;
    }

    if (abi->m == ETH_ABI_DECODE)
    {
        ethc_abi_buf_pr16(*d, cframebuf, cframebuf->offset);
        cframebuf->offset += ETH_ABI_WORD_SIZE;
        return 1;
    }

    return -1;
}

int eth_abi_int32(struct eth_abi* abi, int32_t* d)
{
    struct ethc_abi_buf* cframebuf;
    int f;

    if (abi == NULL || d == NULL)
        return -1;

    cframebuf = abi->cframe->buf;

    if (abi->m == ETH_ABI_ENCODE)
    {
        f = *d & 0x80000000 ? 0xFF : 0x00;
        memset(&(cframebuf->buf[cframebuf->offset]), f, ETH_ABI_WORD_SIZE - 4);
        ethc_abi_buf_pw32(cframebuf, *d, cframebuf->offset);
        cframebuf->offset += ETH_ABI_WORD_SIZE;
        cframebuf->len += ETH_ABI_WORD_SIZE;
        return 1;
    }

    if (abi->m == ETH_ABI_DECODE)
    {
        int64_t tmp_d = (int64_t)*d;
        ethc_abi_buf_pr32(tmp_d, cframebuf, cframebuf->offset);
        cframebuf->offset += ETH_ABI_WORD_SIZE;
        *d = (int32_t)tmp_d;
        return 1;
    }

    return -1;
}

int eth_abi_int64(struct eth_abi* abi, int64_t* d)
{
    struct ethc_abi_buf* cframebuf;
    int f;

    if (abi == NULL || d == NULL)
        return -1;

    cframebuf = abi->cframe->buf;

    if (abi->m == ETH_ABI_ENCODE)
    {
        f = *d & 0x8000000000000000 ? 0xFF : 0x00;
        memset(&(cframebuf->buf[cframebuf->offset]), f, ETH_ABI_WORD_SIZE - 8);
        ethc_abi_buf_pw64(cframebuf, *d, cframebuf->offset);
        cframebuf->offset += ETH_ABI_WORD_SIZE;
        cframebuf->len += ETH_ABI_WORD_SIZE;
        return 1;
    }

    if (abi->m == ETH_ABI_DECODE)
    {
        ethc_abi_buf_pr64(*d, cframebuf, cframebuf->offset);
        cframebuf->offset += ETH_ABI_WORD_SIZE;
        return 1;
    }

    return -1;
}

int eth_abi_bytes8(struct eth_abi* abi, uint8_t* bytes)
{
    struct ethc_abi_buf* cframebuf;

    if (abi == NULL || bytes == NULL)
        return -1;

    cframebuf = abi->cframe->buf;

    if (abi->m == ETH_ABI_ENCODE)
    {
        memcpy(&(cframebuf->buf[cframebuf->offset]), bytes, 8);
        cframebuf->offset += ETH_ABI_WORD_SIZE;
        cframebuf->len += ETH_ABI_WORD_SIZE;
        return 1;
    }

    if (abi->m == ETH_ABI_DECODE)
    {
        memcpy(bytes, &(cframebuf->buf[cframebuf->offset]), 8);
        cframebuf->offset += ETH_ABI_WORD_SIZE;
        return 1;
    }

    return -1;
}

int eth_abi_bytes16(struct eth_abi* abi, uint8_t* bytes)
{
    struct ethc_abi_buf* cframebuf;

    if (abi == NULL || bytes == NULL)
        return -1;

    cframebuf = abi->cframe->buf;

    if (abi->m == ETH_ABI_ENCODE)
    {
        memcpy(&(cframebuf->buf[cframebuf->offset]), bytes, 16);
        cframebuf->offset += ETH_ABI_WORD_SIZE;
        cframebuf->len += ETH_ABI_WORD_SIZE;
        return 1;
    }

    if (abi->m == ETH_ABI_DECODE)
    {
        memcpy(bytes, &(cframebuf->buf[cframebuf->offset]), 16);
        cframebuf->offset += ETH_ABI_WORD_SIZE;
        return 1;
    }

    return -1;
}

int eth_abi_bytes32(struct eth_abi* abi, uint8_t* bytes)
{
    struct ethc_abi_buf* cframebuf;

    if (abi == NULL || bytes == NULL)
        return -1;

    cframebuf = abi->cframe->buf;

    if (abi->m == ETH_ABI_ENCODE)
    {
        memcpy(&(cframebuf->buf[cframebuf->offset]), bytes, 32);
        cframebuf->offset += ETH_ABI_WORD_SIZE;
        cframebuf->len += ETH_ABI_WORD_SIZE;
        return 1;
    }

    if (abi->m == ETH_ABI_DECODE)
    {
        memcpy(bytes, &(cframebuf->buf[cframebuf->offset]), 32);
        cframebuf->offset += ETH_ABI_WORD_SIZE;
        return 1;
    }

    return -1;
}

int eth_abi_bytes64(struct eth_abi* abi, uint8_t* bytes)
{
    struct ethc_abi_buf* cframebuf;

    if (abi == NULL || bytes == NULL)
        return -1;

    cframebuf = abi->cframe->buf;

    if (abi->m == ETH_ABI_ENCODE)
    {
        memcpy(&(cframebuf->buf[cframebuf->offset]), bytes, 64);
        cframebuf->offset += ETH_ABI_WORD_SIZE;
        cframebuf->len += ETH_ABI_WORD_SIZE;
        return 1;
    }

    if (abi->m == ETH_ABI_DECODE)
    {
        memcpy(bytes, &(cframebuf->buf[cframebuf->offset]), 64);
        cframebuf->offset += ETH_ABI_WORD_SIZE;
        return 1;
    }

    return -1;
}

int eth_abi_bytes(struct eth_abi* abi, uint8_t** bytes, size_t* len)
{
    struct ethc_abi_frame* cframe;
    struct ethc_abi_buf* cframebuf, * dybuf;
    uint64_t dyoffset, blen;
    uint8_t* buf;
    size_t bsize;

    cframe = abi->cframe;
    cframebuf = cframe->buf;

    if (abi->m == ETH_ABI_ENCODE)
    {
        /* make the arbitrary length 32-byte aligned (16->32, 33->64) */
        bsize = *len % ETH_ABI_WORD_SIZE
            ? *len + (ETH_ABI_WORD_SIZE - (*len % ETH_ABI_WORD_SIZE))
            : *len;

        if (ethc_abi_buf_init(&dybuf, ETH_ABI_WORD_SIZE + bsize) < 0)
            return -1;

        /* store the declaration offset for the dynamic buffer */
        dybuf->doffset = cframebuf->offset;

        memset(&(cframebuf->buf[cframebuf->offset]), 0, ETH_ABI_WORD_SIZE);
        cframebuf->offset += ETH_ABI_WORD_SIZE;
        cframebuf->len += ETH_ABI_WORD_SIZE;

        /* write the length */
        ethc_abi_buf_pw64(dybuf, *len, 0);
        dybuf->offset += ETH_ABI_WORD_SIZE;
        dybuf->len += ETH_ABI_WORD_SIZE;

        memcpy(&(dybuf->buf[dybuf->offset]), *bytes, *len);
        dybuf->offset += bsize;
        dybuf->len += bsize;

        cframe->dybufs[cframe->dybuflen++] = dybuf;
        return 1;
    }

    if (abi->m == ETH_ABI_DECODE)
    {
        /* read the offset */
        ethc_abi_buf_pr64(dyoffset, cframebuf, cframebuf->offset);
        cframebuf->offset += ETH_ABI_WORD_SIZE;

        /* read the length */
        ethc_abi_buf_pr64(blen, cframebuf, dyoffset);

        buf = (uint8_t*)malloc(blen);
        if (buf == NULL)
            return -1;

        memcpy(buf, &(cframebuf->buf[cframebuf->offset + dyoffset]), blen);
        *bytes = buf;

        if (len != NULL)
            *len = blen;
        return 1;
    }

    return -1;
}

int eth_abi_from_hex(struct eth_abi* abi, char* hex, int len)
{
    struct ethc_abi_frame* nframe;

    if (abi == NULL || abi == NULL)
        return -1;

    if (ethc_abi_frame_init(&nframe) < 0)
        return -1;

    if ((len = eth_hex_to_bytes(&(nframe->buf->buf), hex, len)) < 0)
        return -1;

    nframe->pframe = NULL;
    nframe->buf->len = len;
    abi->m = ETH_ABI_DECODE;
    abi->cframe = nframe;
    return 1;
}

int eth_abi_to_hex(struct eth_abi* abi, char** hex, size_t* len)
{
    struct ethc_abi_buf* cframebuf;
    int hexlen;

    cframebuf = abi->cframe->buf;

    if (abi == NULL || hex == NULL || len == NULL)
        return -1;

    ethc_abi_frame_backpatch(abi->cframe);

    if ((hexlen = eth_hex_from_bytes(hex, cframebuf->buf, cframebuf->len)) < 0)
        return -1;

    *len = hexlen;
    return 1;
}