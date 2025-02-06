/*
 * Copyright (c) 2016-2018 . All Rights Reserved.
 */

#ifndef BASE64_H_
#define BASE64_H_

char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length);

unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length);

#endif /* #define BASE64_H_ */
