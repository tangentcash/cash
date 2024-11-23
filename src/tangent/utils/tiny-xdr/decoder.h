#ifndef XDRPROJECT_DECODER_H
#define XDRPROJECT_DECODER_H

#include <stdint.h>

uint8_t strtohex(char c);
int hex2byte_arr(char *buf, int len, uint8_t *out, int outbuf_size);

#endif