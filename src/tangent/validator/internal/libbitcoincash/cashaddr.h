// Copyright (c) 2017 Pieter Wuille
// Copyright (c) 2017-2018 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CASHADDR_H
#define BITCOIN_CASHADDR_H

// Cashaddr is an address format inspired by bech32.

#include <cstdint>
#include <string>
#include <vector>

namespace cashaddr {

    /**
     * Encode a cashaddr string. Returns the empty string in case of failure.
     */
    std::string Encode(const std::string& prefix,
        const std::vector<uint8_t>& values);

    /**
     * Decode a cashaddr string. Returns (prefix, data). Empty prefix means failure.
     */
    std::pair<std::string, std::vector<uint8_t>>
        Decode(const std::string& str, const std::string& default_prefix);

    /**
     * Convert from one power-of-2 number base to another.
     *
     * If padding is enabled, this always return true. If not, then it returns true
     * of all the bits of the input are encoded in the output.
     */
    template <int frombits, int tobits, bool pad, typename O, typename I>
    bool ConvertBits(const O& outfn, I it, I end)
    {
        size_t acc = 0;
        size_t bits = 0;
        constexpr size_t maxv = (1 << tobits) - 1;
        constexpr size_t max_acc = (1 << (frombits + tobits - 1)) - 1;
        while (it != end)
        {
            acc = ((acc << frombits) | *it) & max_acc;
            bits += frombits;
            while (bits >= tobits)
            {
                bits -= tobits;
                outfn((acc >> bits) & maxv);
            }
            ++it;
        }

        if (pad)
        {
            if (bits)
            {
                outfn((acc << (tobits - bits)) & maxv);
            }
        }
        else if (bits >= frombits || ((acc << (tobits - bits)) & maxv))
        {
            return false;
        }

        return true;
    }

    // Convert the data part to a 5 bit representation.
    template <class T>
    std::vector<uint8_t> PackAddrData(const T& id, uint8_t type)
    {
        std::vector<uint8_t> converted;
        uint8_t version_byte(type << 3);
        size_t size = id.size();
        uint8_t encoded_size = 0;
        switch (size * 8)
        {
            case 160:
                encoded_size = 0;
                break;
            case 192:
                encoded_size = 1;
                break;
            case 224:
                encoded_size = 2;
                break;
            case 256:
                encoded_size = 3;
                break;
            case 320:
                encoded_size = 4;
                break;
            case 384:
                encoded_size = 5;
                break;
            case 448:
                encoded_size = 6;
                break;
            case 512:
                encoded_size = 7;
                break;
            default:
                return converted;
        }
        version_byte |= encoded_size;
        std::vector<uint8_t> data = { version_byte };
        data.insert(data.end(), std::begin(id), std::end(id));

        // Reserve the number of bytes required for a 5-bit packed version of a
        // hash, with version byte.  Add half a byte(4) so integer math provides
        // the next multiple-of-5 that would fit all the data.
        converted.reserve(((size + 1) * 8 + 4) / 5);
        ConvertBits<8, 5, true>([&](uint8_t c) { converted.push_back(c); },
            std::begin(data), std::end(data));

        return converted;
    }

} // namespace cashaddr

#endif // BITCOIN_CASHADDR_H