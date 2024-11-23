#include "rand.h"
#include <vitex/compute.h>

uint32_t random32(void)
{
    uint32_t value;
    if (!Vitex::Compute::Crypto::FillRandomBytes((unsigned char*)&value, sizeof(value)))
        value = Vitex::Compute::Crypto::Random() % std::numeric_limits<uint32_t>::max();
    return value;
}
void random_buffer(uint8_t* buffer, size_t size)
{
    Vitex::Compute::Crypto::FillRandomBytes(buffer, size);
}