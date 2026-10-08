#ifndef XMR_BPP_H
#define XMR_BPP_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <tuple>
#include <vector>

namespace xmr_bpp
{
    template <typename Tag>
    struct ed25519uint256_t
    {
        uint8_t b32[32];

        ed25519uint256_t()
        {
            std::memset(b32, 0, sizeof(b32));
        }

        explicit ed25519uint256_t(const uint8_t src[32])
        {
            std::memcpy(b32, src, sizeof(b32));
        }

        bool empty() const
        {
            uint8_t zero[32] = { 0 };
            return std::memcmp(b32, zero, sizeof(zero)) == 0;
        }
    };

    using scalar_t = ed25519uint256_t<uint8_t>;
    using point_t = ed25519uint256_t<uint16_t>;
    using scalar_vec_t = std::vector<scalar_t>;
    using point_vec_t = std::vector<point_t>;

    struct seed_t
    {
        uint8_t seed[32];
        uint64_t nonce = 0;
    };

    struct proof_t
    {
        point_t A, A1, B;
        scalar_t r1, s1, d1;
        std::vector<point_t> L, R;
    };

    std::tuple<proof_t, std::vector<point_t>> prove(
        seed_t& seeder,
        const std::vector<uint64_t>& amounts,
        const std::vector<scalar_t>& blinding_factors,
        size_t N = 64);
}

#endif
