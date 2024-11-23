#ifndef ETHC_INTERNALS_H
#define ETHC_INTERNALS_H

#ifdef __cplusplus
extern "C" {
#endif
#include "ethc-common.h"
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
#define ETHC_EXPORT_CPP extern "C"
#else
#define ETHC_EXPORT_CPP
#endif

ETHC_EXPORT_CPP int ethc_rand(uint8_t *bytes, size_t len);
ETHC_EXPORT_CPP int ethc_strncasecmp(const char *s1, const char *s2, size_t len);
ETHC_EXPORT_CPP int ethc_hexcharb(char h);
ETHC_EXPORT_CPP char ethc_hexchar(uint8_t d);

#undef ETHC_EXPORT_CPP
#endif