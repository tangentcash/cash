#include "rand.h"
#include <vitex/compute.h>

int random_u32(uint32_t* output)
{
    uint32_t result;
    if (!vitex::compute::crypto::fill_random_bytes((unsigned char*)&result, sizeof(result)))
        return -1;

    if (output)
        *output = result;
    return 0;
}
int random_u8a(uint8_t* buffer, size_t size)
{
    if (!vitex::compute::crypto::fill_random_bytes(buffer, size))
        return -1;

    return 0;
}