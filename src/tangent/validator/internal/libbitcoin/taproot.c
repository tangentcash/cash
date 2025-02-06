/*

 The MIT License (MIT)

 Copyright (c) 2021 libbtc

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

#include "taproot.h"
#include "../../../internal/sha2.h"

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

void btc_tagged_hash(enum btc_tagged_prefixes prefix, const uint8_t* message, size_t message_size, uint256 hash)
{
    SHA256_CTX context;
    sha256_Init(&context);
    sha256_Update(&context, tagged_hash_prefixes[prefix], sizeof(tagged_hash_prefixes[prefix]));
    sha256_Update(&context, message, message_size);
    sha256_Final(&context, hash);
}
