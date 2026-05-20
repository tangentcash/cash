#ifndef BULLETPROOFS_PLUS_H
#define BULLETPROOFS_PLUS_H

#include <cstdint>
#include <vector>
#include <tuple>

/**
 * Bulletproofs+ Range Proof Implementation
 *
 * This module provides a minimal, self-contained implementation of the Bulletproofs+
 * prove function for range proofs. It is designed to be decoupled from the original
 * crypto-master project and uses external primitives for all low-level operations.
 *
 */

 // ============================================================================
 // BULLETPROOFS+ MODULE
 // ============================================================================

namespace xmr_bpp
{
    template <typename t>
    struct ed25519uint256_t
    {
        uint8_t b32[32];

        ed25519uint256_t()
        {
            memset(b32, 0, sizeof(b32));
        }
        explicit ed25519uint256_t(const uint8_t arr[32])
        {
            memcpy(b32, arr, sizeof(b32));
        }
        ed25519uint256_t(const ed25519uint256_t& other) : ed25519uint256_t(other.b32)
        {
            memcpy(b32, other.b32, sizeof(b32));
        }
        t type() const
        {
            return t(0);
        }
        bool empty() const
        {
            uint8_t zero[32] = { 0 };
            return !memcmp(b32, zero, sizeof(zero));
        }
    };

    using scalar_t = ed25519uint256_t<uint8_t>;
    using point_t = ed25519uint256_t<uint16_t>;
    using hash_t = ed25519uint256_t<uint32_t>;
    using scalar_vec_t = std::vector<scalar_t>;
    using point_vec_t = std::vector<point_t>;

    /**
     * Transcript for Fiat-Shamir challenges
     *
     * Implements a domain-separated hash chain for generating deterministic
     * challenges in the Bulletproofs+ protocol.
     */
    struct transcript_t
    {
        scalar_t state;

        /**
         * Initialize transcript with seed
         */
        void init(const scalar_t& seed)
        {
            state = seed;
        }
        /**
         * Update transcript with a point
         */
        void update(const point_t& p);
        /**
         * Update transcript with a scalar
         */
        void update(const scalar_t& s);
        /**
         * Update transcript with multiple points
         */
        void update(const point_vec_t& points)
        {
            for (const auto& p : points)
                update(p);
        }
        /**
         * Generate a challenge from the transcript state
         * @throws std::runtime_error if challenge is zero
         */
        scalar_t challenge();
    };

    /**
     * Bulletproof+ Range Proof Structure
     *
     * Contains all components of a Bulletproof+ proof:
     * - A, A1, B: Point commitments from the inner product protocol
     * - r1, s1, d1: Scalar challenges from the inner product protocol
     * - L, R: Vector of points from each round of the inner product protocol
     *
     * @note This structure does NOT include serialization methods.
     * The module is designed to be minimal and self-contained.
     */
    struct proof_t
    {
        point_t A, A1, B;
        scalar_t r1, s1, d1;
        std::vector<point_t> L, R;
    };

    /**
     * Generate a Bulletproof+ range proof for the given amounts and blinding factors.
     *
     * This function implements the Bulletproof+ proving protocol as described in:
     * "Bulletproofs+: Faster and Shorter Zero-Knowledge Arguments for Ranges and More"
     *
     * @param amounts Vector of amounts to prove (each amount must be in range [0, 2^N))
     * @param blinding_factors Vector of blinding factors (one per amount, must be non-zero)
     * @param N Number of bits for the range proof (default 64, must be in [1, 64])
     * @return Tuple containing:
     *   - proof_t: The Bulletproof+ proof
     *   - std::vector<point_t>: Pedersen commitments for each amount
     *
     * @throws std::range_error if N is out of valid range
     * @throws std::runtime_error if amounts and blinding_factors have different sizes
     * @throws std::runtime_error if amounts is empty
     * @throws std::invalid_argument if any blinding factor is zero
     */
    std::tuple<proof_t, std::vector<point_t>> prove(const std::vector<uint64_t>& amounts, const std::vector<scalar_t>& blinding_factors, size_t N = 64);
    /**
     * Generate exponent vectors for the inner product protocol.
     *
     * This function generates the L and R generator points used in the inner product
     * proof. The exponents are cached for efficiency - if more are requested, they are
     * generated on demand; if less, a slice is returned.
     *
     * @param count Number of exponent pairs needed (maximum 64)
     * @return Pair of exponent vectors: (L, R)
     */
    std::pair<std::vector<point_t>, std::vector<point_t>> generate_exponents(size_t count);
}

#endif // BULLETPROOFS_PLUS_H