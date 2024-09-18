#ifndef LIBBASE58_H
#define LIBBASE58_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

extern bool xb58tobin(void *bin, size_t *binsz, const char *b58);
extern int xb58check(const void *bin, size_t binsz, const char *b58, size_t b58sz);
extern int xb58check_dec(const char* str, uint8_t* data, size_t* datalen);

extern bool xb58enc(char *b58, size_t *b58sz, const void *bin, size_t binsz);
extern bool xb58check_enc(char *b58c, size_t *b58c_sz, uint8_t* ver, uint8_t versz, const void *data, size_t datasz);

#ifdef __cplusplus
}
#endif

#endif
