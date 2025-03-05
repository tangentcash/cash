#include "rand.h"
#include <vitex/compute.h>

uint32_t random32(void)
{
    uint32_t value;
    if (!vitex::compute::crypto::fill_random_bytes((unsigned char*)&value, sizeof(value)))
        value = vitex::compute::crypto::random() % std::numeric_limits<uint32_t>::max();
    return value;
}
void random_buffer(uint8_t* buffer, size_t size)
{
    vitex::compute::crypto::fill_random_bytes(buffer, size);
}