/**
 * Bulletproofs+ Range Proof Implementation
 *
 * This file contains the minimal implementation of the Bulletproofs+ prove function.
 * It relies on external primitives defined in the ExternalCrypto namespace.
 *
 */

#include "bpp.h"
#include "sha3.h"
#include "rand.h"
#include <sodium.h>

namespace xmr_bpp
{
    /**
     * Compute domain scalar from index using SHA3
     * Formula: scalar(sha3(domain_salt || index))
     * Uses BULLETPROOFS_PLUS_DOMAIN_0 scalar from crypto_constants.h
     */
    static scalar_t compute_domain_scalar(uint32_t index)
    {
        uint8_t hash_input[40];
        uint8_t* ptr = hash_input;

        // SALT_DOMAIN = 202053504f4e534f52454420425920444f4e5554532041524520474f4f442020
        const uint8_t SALT_DOMAIN[32] = {
            0x20, 0x20, 0x53, 0x50, 0x4f, 0x4e, 0x53, 0x4f,
            0x52, 0x45, 0x44, 0x20, 0x42, 0x59, 0x20, 0x44,
            0x4f, 0x4e, 0x55, 0x54, 0x53, 0x20, 0x41, 0x52,
            0x45, 0x20, 0x47, 0x4f, 0x4f, 0x44, 0x20, 0x20
        };
        memcpy(ptr, SALT_DOMAIN, 32);
        ptr += 32;

        // Write index as uint64 (little endian)
        for (int i = 0; i < 8; ++i)
            *ptr++ = (index >> (i * 8)) & 0xFF;

        hash_t h;
        sha3_256(hash_input, sizeof(hash_input), h.b32);

        scalar_t s;
        crypto_core_ed25519_scalar_reduce(s.b32, h.b32);
        return s;
    }
    static point_t compute_domain_point(uint32_t index)
    {
        uint8_t hash_input[40];
        uint8_t* ptr = hash_input;

        // SALT_DOMAIN = 202053504f4e534f52454420425920444f4e5554532041524520474f4f442020
        const uint8_t SALT_DOMAIN[32] = {
            0x20, 0x20, 0x53, 0x50, 0x4f, 0x4e, 0x53, 0x4f,
            0x52, 0x45, 0x44, 0x20, 0x42, 0x59, 0x20, 0x44,
            0x4f, 0x4e, 0x55, 0x54, 0x53, 0x20, 0x41, 0x52,
            0x45, 0x20, 0x47, 0x4f, 0x4f, 0x44, 0x20, 0x20
        };
        memcpy(ptr, SALT_DOMAIN, 32);
        ptr += 32;

        // Write index as uint64 (little endian)
        for (int i = 0; i < 8; ++i)
            *ptr++ = (index >> (i * 8)) & 0xFF;

        hash_t h;
        sha3_256(hash_input, sizeof(hash_input), h.b32);

        point_t point;
        memcpy(point.b32, h.b32, 32);
        return point;
    }

    // ========================================================================
    // SCALAR OPERATIONS (using libsodium crypto_core_ed25519_scalar_*)
    // ========================================================================
    scalar_t scalar_one()
    {
        scalar_t out;
        out.b32[0] = 1;
        return out;
    }
    scalar_t scalar_uint64(uint64_t value)
    {
        scalar_t out;
        for (size_t i = 0; i < 8; ++i)
            out.b32[i] = (value >> (i * 8)) & 0xFF;
        return out;
    }
    scalar_t scalar_random()
    {
        scalar_t out;
        random_buffer(out.b32, 32);

        hash_t h;
        sha3_256(out.b32, 32, h.b32);
        crypto_core_ed25519_scalar_reduce(out.b32, h.b32);
        return out;
    }
    scalar_t scalar_pow(const scalar_t& base, size_t exp)
    {
        if (exp == 0)
            return scalar_one();

        scalar_t result = base;
        for (size_t i = 1; i < exp; ++i)
        {
            scalar_t temp;
            crypto_core_ed25519_scalar_mul(temp.b32, result.b32, base.b32);
            result = temp;
        }
        return result;
    }
    scalar_vec_t scalar_vec_pow(const scalar_t& s, size_t n)
    {
        scalar_vec_t result;
        result.reserve(n);
        if (n == 0)
            return result;

        // FIX: Return ascending powers: [s^1, s^2, ..., s^n]
        // Original returned descending powers [s^n, s^(n-1), ..., s^1]
        scalar_t current = s;
        for (size_t i = 0; i < n; ++i)
        {
            result.push_back(current);
            crypto_core_ed25519_scalar_mul(current.b32, current.b32, s.b32);
        }
        return result;
    }

    // ========================================================================
    // POINT OPERATIONS (using libsodium public API)
    // ========================================================================
    point_t point_generator_G()
    {
        // Ed25519 generator point G (compressed)
        static const uint8_t ED25519_G_BYTES[32] =
        {
            0x21, 0x69, 0x36, 0xd3, 0xcd, 0x6e, 0x53, 0xfe,
            0xc0, 0xa4, 0xe2, 0x31, 0xfb, 0xd6, 0x1e, 0x84,
            0x59, 0x4a, 0x59, 0x5e, 0x77, 0xb5, 0xc3, 0xb9,
            0x94, 0xdb, 0x8a, 0x23, 0xf3, 0x19, 0x97, 0x26
        };
        point_t g;
        memcpy(g.b32, ED25519_G_BYTES, 32);
        return g;
    }
    point_t point_generator_H()
    {
        // Ed25519 generator H (sha512("H") reduced)
        static const uint8_t ED25519_H_BYTES[32] =
        {
            0x58, 0x50, 0x8a, 0x3c, 0x7f, 0x47, 0x3a, 0x28,
            0x9d, 0x6f, 0xb6, 0xe7, 0x40, 0x4d, 0xa1, 0x06,
            0x80, 0x41, 0x18, 0x99, 0xba, 0x52, 0x45, 0x32,
            0x69, 0x03, 0x89, 0x7f, 0x4e, 0x9e, 0x55, 0x9b
        };
        point_t h;
        memcpy(h.b32, ED25519_H_BYTES, 32);
        return h;
    }
    void point_vec_inner_product(point_t& out, const point_vec_t& P, const scalar_vec_t& s)
    {
        if (P.size() != s.size())
            throw std::runtime_error("Point and scalar vectors must have same size");

        memset(out.b32, 0, 32);
        for (size_t i = 0; i < P.size(); ++i)
        {
            point_t term;
            crypto_scalarmult_ed25519(term.b32, s[i].b32, P[i].b32);
            crypto_core_ed25519_add(out.b32, out.b32, term.b32);
        }
    }

    // ========================================================================
    // TRANSCRIPT IMPLEMENTATION
    // ========================================================================
    void transcript_t::update(const point_t& p)
    {
        hash_t h, combined;
        sha3_256(p.b32, sizeof(p.b32), h.b32);

        scalar_t input;
        crypto_core_ed25519_scalar_reduce(input.b32, h.b32);

        SHA3_CTX ctx;
        sha3_256_Init(&ctx);
        sha3_Update(&ctx, state.b32, sizeof(state.b32));
        sha3_Update(&ctx, input.b32, sizeof(input.b32));
        sha3_Final(&ctx, combined.b32);
        crypto_core_ed25519_scalar_reduce(state.b32, combined.b32);
    }
    void transcript_t::update(const scalar_t& s)
    {
        hash_t combined;
        SHA3_CTX ctx;
        sha3_256_Init(&ctx);
        sha3_Update(&ctx, state.b32, sizeof(state.b32));
        sha3_Update(&ctx, s.b32, sizeof(s.b32));
        sha3_Final(&ctx, combined.b32);
        crypto_core_ed25519_scalar_reduce(state.b32, combined.b32);
    }
    scalar_t transcript_t::challenge()
    {
        hash_t h;
        sha3_256(state.b32, sizeof(state.b32), h.b32);

        scalar_t challenge;
        crypto_core_ed25519_scalar_reduce(challenge.b32, h.b32);
        if (challenge.empty())
            throw std::runtime_error("Transcript challenge cannot be zero");

        return challenge;
    }

    // ============================================================================
    // GENERATE EXPONENTS
    // ============================================================================
    // Generates L and R generator points for the inner product protocol
    // using SHA3 hashing with domain separation.
    // 
    // Original: writer.uint64(i); writer.pod(DOMAIN1); hash = sha3(writer)
    // This matches the original crypto-master implementation.
    std::pair<std::vector<point_t>, std::vector<point_t>> generate_exponents(size_t count)
    {
        const point_t BPP_DOMAIN_1 = compute_domain_point(16);
        const point_t BPP_DOMAIN_2 = compute_domain_point(17);
        std::vector<point_t> L, R;
        L.reserve(count);
        R.reserve(count);
        for (size_t i = 0; i < count; ++i)
        {
            // L_i = H(uint64(i) || DOMAIN1) - matches original implementation
            uint8_t hash_input[40];
            uint8_t* ptr = hash_input;

            // Write index as uint64 (little endian)
            for (int j = 0; j < 8; ++j)
                *ptr++ = (i >> (j * 8)) & 0xFF;

            // Copy DOMAIN1 bytes
            for (int j = 0; j < 32; ++j)
                *ptr++ = BPP_DOMAIN_1.b32[j];

            hash_t hash_output;
            sha3_256(hash_input, sizeof(hash_input), hash_output.b32);

            point_t L_i = point_t(hash_output.b32);
            L.push_back(L_i);

            // R_i = H(uint64(i) || DOMAIN2) - recompute hash_input from scratch
            hash_input[0] = 0;
            ptr = hash_input;

            // Write index as uint64 (little endian)
            for (int j = 0; j < 8; ++j)
                *ptr++ = (i >> (j * 8)) & 0xFF;

            // Copy DOMAIN2 bytes
            for (int j = 0; j < 32; ++j)
                *ptr++ = BPP_DOMAIN_2.b32[j];

            sha3_256(hash_input, sizeof(hash_input), hash_output.b32);
            point_t R_i = point_t(hash_output.b32);
            R.push_back(R_i);
        }
        return std::make_pair(std::move(L), std::move(R));
    }

    // ============================================================================
    // GLOBAL PRECOMPUTED VALUES
    // ============================================================================
    static const std::vector<scalar_t> powers_of_two = []()
    {
        std::vector<scalar_t> result;
        result.reserve(64);
        scalar_t current = scalar_one();
        result.push_back(current);

        scalar_t two;
        two.b32[0] = 2;

        for (int i = 1; i < 64; ++i)
        {
            scalar_t next;
            crypto_core_ed25519_scalar_mul(next.b32, current.b32, two.b32);
            result.push_back(next);
            current = next;
        }
        return result;
    }();

    // ============================================================================
    // PROVE FUNCTION
    // ============================================================================
    // Main entry point for Bulletproofs+ range proof generation.
    std::tuple<proof_t, std::vector<point_t>> prove(const std::vector<uint64_t>& amounts, const std::vector<scalar_t>& blinding_factors, size_t N)
    {
        // Validate N
        if (N == 0)
            throw std::range_error("N must be at least 1-bit");

        if (N > 64)
            throw std::range_error("N must not exceed 64-bits");

        // Validate inputs match
        if (amounts.size() != blinding_factors.size())
            throw std::runtime_error("amounts and blinding factors must be the same size");

        if (amounts.empty())
            throw std::runtime_error("amounts is empty");

        // Validate blinding factors are non-zero
        for (const auto& bf : blinding_factors)
        {
            if (bf.empty())
                throw std::invalid_argument("blinding factor cannot be zero");
        }

        const size_t M = amounts.size();

        // Round N to next power of 2 - matches Crypto::pow2_round behavior
        // N must be in range [1, 64]
        size_t N_rounded = 1;
        while (N_rounded < N && N_rounded < 64)
            N_rounded *= 2;
        N = N_rounded;
        if (N > 64) N = 64;

        // Generate exponent vectors
        const size_t MN = M * N;
        const auto [_Gi, _Hi] = generate_exponents(MN);
        // one_MN = vector of ones of size MN
        // FIX: Initialize all elements to 1, not just first element
        scalar_vec_t one_MN(MN, scalar_one());

        // Build aL (bit decomposition of amounts) and aR
        std::vector<point_t> V;
        std::vector<scalar_t> aL, aR;
        for (size_t i = 0; i < M; ++i)
        {
            // Generate Pedersen commitment for this amount
            // C = (gamma * G) + (amount * H)
            point_t commitment_G, commitment_H;
            crypto_scalarmult_ed25519(commitment_G.b32, blinding_factors[i].b32, point_generator_G().b32);
            scalar_t amount_scalar = scalar_uint64(amounts[i]);
            crypto_scalarmult_ed25519(commitment_H.b32, amount_scalar.b32, point_generator_H().b32);
            crypto_core_ed25519_add(commitment_G.b32, commitment_G.b32, commitment_H.b32);
            V.push_back(commitment_G);

            // Convert amount to bits
            // FIX: Push 0s for unset bits, not just 1s
            for (size_t bit = 0; bit < N; ++bit)
            {
                if (amounts[i] & (1ULL << bit))
                    aL.push_back(scalar_one());
                else
                    aL.push_back(scalar_t {});  // Push zero for unset bit
            }
        }

        // aR = aL - one_MN (subtract ONE from each element)
        aR = aL;
        for (size_t i = 0; i < MN; ++i)
            crypto_core_ed25519_scalar_sub(aR[i].b32, aR[i].b32, scalar_one().b32);

        const scalar_t BPP_DOMAIN_0 = compute_domain_scalar(15);
    try_setup:
        // Initialize transcript with domain separator
        transcript_t tr;
        tr.init(BPP_DOMAIN_0);

        // Generate random alpha
        scalar_t alpha = scalar_random();
        if (alpha.empty())
            goto try_setup;

        // Update transcript with commitments
        tr.update(V);

        // Compute A = INV_EIGHT * (aL . Gi + aR . Hi + alpha * G)
        point_t A_inner_L, A_inner_R, A_alpha_G, A_combined;
        point_vec_inner_product(A_inner_L, _Gi, aL);
        point_vec_inner_product(A_inner_R, _Hi, aR);
        crypto_scalarmult_ed25519(A_alpha_G.b32, alpha.b32, point_generator_G().b32);
        crypto_core_ed25519_add(A_combined.b32, A_inner_L.b32, A_inner_R.b32);
        crypto_core_ed25519_add(A_combined.b32, A_combined.b32, A_alpha_G.b32);

        // Scale A by 1/8
        scalar_t inv_eight = scalar_uint64(8);
        crypto_core_ed25519_scalar_invert(inv_eight.b32, inv_eight.b32);
        point_t _A;
        crypto_scalarmult_ed25519(_A.b32, inv_eight.b32, A_combined.b32);
        tr.update(_A);

        // Get challenge y
        scalar_t _y = tr.challenge();
        if (_y.empty())
            goto try_setup;

        tr.update(_y);
        // Get challenge z
        scalar_t z = tr.challenge();
        // FIX: Retry when z is empty (invalid), not when it's valid
        if (z.empty())
            goto try_setup;

        // Build d vector: d[j*N + i] = z^(2*(j+1)) * 2^i
        // This matches: d.append(z.pow(2 * (j + 1)) * powers_of_two[i])
        std::vector<scalar_t> d;
        d.reserve(MN);
        for (size_t j = 0; j < M; ++j)
        {
            scalar_t z_pow = scalar_pow(z, 2 * (j + 1));
            for (size_t i = 0; i < N; ++i)
            {
                scalar_t d_i;
                crypto_core_ed25519_scalar_mul(d_i.b32, z_pow.b32, powers_of_two[i].b32);
                d.push_back(d_i);
            }
        }

        // aL1 = aL - (one_MN * z) = aL - z (since one_MN is all ones)
        std::vector<scalar_t> aL1 = aL;
        for (size_t i = 0; i < MN; ++i)
            crypto_core_ed25519_scalar_sub(aL1[i].b32, aL1[i].b32, z.b32);

        // yexp = y.pow_expand(MN, true, false) - ascending powers: [y^1, y^2, ..., y^MN]
        scalar_vec_t y_powers = scalar_vec_pow(_y, MN);
        // aR1 = aR + (d * yexp) + (one_MN * z)
        std::vector<scalar_t> aR1 = aR;
        for (size_t i = 0; i < MN; ++i)
        {
            scalar_t term;
            crypto_core_ed25519_scalar_mul(term.b32, d[i].b32, y_powers[i].b32);
            crypto_core_ed25519_scalar_add(term.b32, term.b32, z.b32);
            crypto_core_ed25519_scalar_add(aR1[i].b32, aR1[i].b32, term.b32);
        }

        // Compute alpha1
        scalar_t alpha1 = alpha;
        // ypow = y.pow(MN + 1)
        scalar_t y_pow = scalar_pow(_y, MN + 1);
        for (size_t j = 0; j < M; ++j)
        {
            scalar_t z_pow = scalar_pow(z, 2 * (j + 1)), term;
            crypto_core_ed25519_scalar_mul(term.b32, z_pow.b32, blinding_factors[j].b32);
            crypto_core_ed25519_scalar_mul(term.b32, term.b32, y_pow.b32);
            crypto_core_ed25519_scalar_add(alpha1.b32, alpha1.b32, term.b32);
        }

        // Compute inner product round
        auto weighted_inner_product = [](const std::vector<scalar_t>& a, const std::vector<scalar_t>& b, const scalar_t& y) -> scalar_t
        {
            if (a.size() != b.size())
                throw std::invalid_argument("weighted inner product vectors must be of the same size");

            scalar_t result;
            for (size_t i = 0; i < a.size(); ++i)
            {
                scalar_t term, y_pow = scalar_pow(y, i + 1);
                crypto_core_ed25519_scalar_mul(term.b32, a[i].b32, b[i].b32);
                crypto_core_ed25519_scalar_mul(term.b32, term.b32, y_pow.b32);
                crypto_core_ed25519_scalar_add(result.b32, result.b32, term.b32);
            }
            return result;
        };

        try
        {
            // Recursive inner product rounds
            std::vector<point_t> Gi = _Gi;
            std::vector<point_t> Hi = _Hi;
            std::vector<scalar_t> a = aL1;
            std::vector<scalar_t> b = aR1;
            scalar_t alpha = alpha1;
            scalar_t y = _y;
            auto n = static_cast<size_t>(Gi.size());
            proof_t p;
            while (n > 1)
            {
                n /= 2;

                // Split vectors in half
                std::vector<scalar_t> a1(a.begin(), a.begin() + n);
                std::vector<scalar_t> a2(a.begin() + n, a.end());
                std::vector<scalar_t> b1(b.begin(), b.begin() + n);
                std::vector<scalar_t> b2(b.begin() + n, b.end());
                std::vector<point_t> G1(Gi.begin(), Gi.begin() + n);
                std::vector<point_t> G2(Gi.begin() + n, Gi.end());
                std::vector<point_t> H1(Hi.begin(), Hi.begin() + n);
                std::vector<point_t> H2(Hi.begin() + n, Hi.end());

                // Generate random d values
                scalar_t dL = scalar_random();
                scalar_t dR = scalar_random();
                if (dL.empty() || dR.empty())
                    throw std::runtime_error("d values cannot be zero");

                // Compute cL = weighted_inner_product(a1, b2, y)
                // Compute cR = weighted_inner_product(a2 * y^n, b1, y)
                scalar_t cL = weighted_inner_product(a1, b2, y);
                scalar_t y_pow_n = scalar_pow(y, n);
                std::vector<scalar_t> a2_scaled;
                for (auto& s : a2)
                {
                    scalar_t scaled;
                    crypto_core_ed25519_scalar_mul(scaled.b32, s.b32, y_pow_n.b32);
                    a2_scaled.push_back(scaled);
                }

                scalar_t cR = weighted_inner_product(a2_scaled, b1, y);
                // Compute y^n and y^(-n)
                scalar_t y_pow_n_full = scalar_pow(y, n), y_inv;
                crypto_core_ed25519_scalar_invert(y_inv.b32, y.b32);
                scalar_t y_inv_pow_n = scalar_pow(y_inv, n);

                // Compute L point:
                // L = INV_EIGHT * ((a1 * y^(-n)) . G2 + b2 . H1 + cL*H + dL*G)
                point_t L_term1, L_term2, L_term3, L_combined;
                // (a1 * y^(-n)) . G2
                std::vector<scalar_t> a1_scaled;
                for (auto& s : a1)
                {
                    scalar_t scaled;
                    crypto_core_ed25519_scalar_mul(scaled.b32, s.b32, y_inv_pow_n.b32);
                    a1_scaled.push_back(scaled);
                }

                point_vec_inner_product(L_term1, G2, a1_scaled);
                // b2 . H1
                point_vec_inner_product(L_term2, H1, b2);

                // cL * H + dL * G
                point_t cL_H, dL_G;
                crypto_scalarmult_ed25519(cL_H.b32, cL.b32, point_generator_H().b32);
                crypto_scalarmult_ed25519(dL_G.b32, dL.b32, point_generator_G().b32);
                crypto_core_ed25519_add(L_term3.b32, cL_H.b32, dL_G.b32);

                // Combine L terms
                crypto_core_ed25519_add(L_combined.b32, L_term1.b32, L_term2.b32);
                crypto_core_ed25519_add(L_combined.b32, L_combined.b32, L_term3.b32);

                // Scale by 1/8
                scalar_t inv_eight = scalar_uint64(8);
                crypto_core_ed25519_scalar_invert(inv_eight.b32, inv_eight.b32);

                point_t L_point;
                crypto_scalarmult_ed25519(L_point.b32, inv_eight.b32, L_combined.b32);

                // Compute R point:
                // R = INV_EIGHT * ((a2 * y^n) . G1 + b1 . H2 + cR*H + dR*G)
                point_t R_term1, R_term2, R_term3, R_combined;
                // (a2 * y^n) . G1
                point_vec_inner_product(R_term1, G1, a2_scaled);
                // b1 . H2
                point_vec_inner_product(R_term2, H2, b1);

                // cR * H + dR * G
                point_t cR_H, dR_G;
                crypto_scalarmult_ed25519(cR_H.b32, cR.b32, point_generator_H().b32);
                crypto_scalarmult_ed25519(dR_G.b32, dR.b32, point_generator_G().b32);
                crypto_core_ed25519_add(R_term3.b32, cR_H.b32, dR_G.b32);

                // Combine R terms
                crypto_core_ed25519_add(R_combined.b32, R_term1.b32, R_term2.b32);
                crypto_core_ed25519_add(R_combined.b32, R_combined.b32, R_term3.b32);

                // Scale by 1/8
                point_t R_point;
                crypto_scalarmult_ed25519(R_point.b32, inv_eight.b32, R_combined.b32);
                p.L.push_back(L_point);
                p.R.push_back(R_point);
                tr.update(L_point);
                tr.update(R_point);

                const scalar_t x = tr.challenge();
                if (x.empty())
                    throw std::runtime_error("x cannot be zero");

                // Update Gi = G1.dbl_mult(x^(-1), G2, x * y^(-n))
                // This is: Gi_new = x^(-1)*G1 + x*y^(-n)*G2
                scalar_t x_inv;
                crypto_core_ed25519_scalar_invert(x_inv.b32, x.b32);

                std::vector<point_t> new_Gi;
                for (size_t i = 0; i < n; ++i)
                {
                    // Gi = G1*x^(-1) + G2*x*y^(-n)
                    scalar_t g1_coeff = x_inv;
                    scalar_t g2_coeff;
                    crypto_core_ed25519_scalar_mul(g2_coeff.b32, x.b32, y_inv_pow_n.b32);

                    point_t g1_scaled;
                    crypto_scalarmult_ed25519(g1_scaled.b32, g1_coeff.b32, G1[i].b32);
                    point_t g2_scaled;
                    crypto_scalarmult_ed25519(g2_scaled.b32, g2_coeff.b32, G2[i].b32);

                    point_t new_G;
                    crypto_core_ed25519_add(new_G.b32, g1_scaled.b32, g2_scaled.b32);
                    new_Gi.push_back(new_G);
                }
                Gi = std::move(new_Gi);

                // Update Hi = H1.dbl_mult(x, H2, x^(-1))
                // This is: Hi_new = x*H1 + x^(-1)*H2
                std::vector<point_t> new_Hi;
                for (size_t i = 0; i < n; ++i)
                {
                    // Hi = H1*x + H2*x^(-1)
                    scalar_t h1_coeff = x;
                    scalar_t h2_coeff;
                    crypto_core_ed25519_scalar_invert(h2_coeff.b32, x.b32);

                    point_t h1_scaled;
                    crypto_scalarmult_ed25519(h1_scaled.b32, h1_coeff.b32, H1[i].b32);
                    point_t h2_scaled;
                    crypto_scalarmult_ed25519(h2_scaled.b32, h2_coeff.b32, H2[i].b32);

                    point_t new_H;
                    crypto_core_ed25519_add(new_H.b32, h1_scaled.b32, h2_scaled.b32);
                    new_Hi.push_back(new_H);
                }
                Hi = std::move(new_Hi);

                // Update a = (a1 * x) + (a2 * y^n * x^(-1))
                // Update b = (b1 * x^(-1)) + (b2 * x)
                // Update alpha = dL * x^2 + alpha + dR * x^(-2)

                scalar_t x_sq, x_inv_sq;
                crypto_core_ed25519_scalar_mul(x_sq.b32, x.b32, x.b32);
                crypto_core_ed25519_scalar_invert(x_inv_sq.b32, x_sq.b32);

                for (size_t i = 0; i < n; ++i)
                {
                    // a[i] = a1[i] * x + a2[i] * y^n * x^(-1)
                    scalar_t a1_term;
                    crypto_core_ed25519_scalar_mul(a1_term.b32, a1[i].b32, x.b32);
                    scalar_t a2_term;
                    crypto_core_ed25519_scalar_mul(a2_term.b32, a2[i].b32, y_pow_n_full.b32);
                    crypto_core_ed25519_scalar_mul(a2_term.b32, a2_term.b32, x_inv.b32);
                    crypto_core_ed25519_scalar_add(a[i].b32, a1_term.b32, a2_term.b32);

                    // b[i] = b1[i] * x^(-1) + b2[i] * x
                    scalar_t b1_term;
                    crypto_core_ed25519_scalar_mul(b1_term.b32, b1[i].b32, x_inv.b32);
                    scalar_t b2_term;
                    crypto_core_ed25519_scalar_mul(b2_term.b32, b2[i].b32, x.b32);
                    crypto_core_ed25519_scalar_add(b[i].b32, b1_term.b32, b2_term.b32);
                }

                // alpha = dL * x^2 + alpha + dR * x^(-2)
                scalar_t dL_x_sq, dR_x_inv_sq;
                crypto_core_ed25519_scalar_mul(dL_x_sq.b32, dL.b32, x_sq.b32);
                crypto_core_ed25519_scalar_mul(dR_x_inv_sq.b32, dR.b32, x_inv_sq.b32);
                crypto_core_ed25519_scalar_add(dL_x_sq.b32, dL_x_sq.b32, alpha.b32);
                crypto_core_ed25519_scalar_add(dL_x_sq.b32, dL_x_sq.b32, dR_x_inv_sq.b32);
                alpha = dL_x_sq;
            }

            // Final round
        try_prove:
            scalar_t r = scalar_random();
            scalar_t s = scalar_random();
            scalar_t d = scalar_random();
            scalar_t eta = scalar_random();
            if (r.empty() || s.empty() || d.empty() || eta.empty())
                goto try_prove;

            // Compute rybsya = r * y * b[0] + s * y * a[0]
            scalar_t ry, sy, rybsya;
            crypto_core_ed25519_scalar_mul(ry.b32, r.b32, y.b32);
            crypto_core_ed25519_scalar_mul(ry.b32, ry.b32, b[0].b32);
            crypto_core_ed25519_scalar_mul(sy.b32, s.b32, y.b32);
            crypto_core_ed25519_scalar_mul(sy.b32, sy.b32, a[0].b32);
            crypto_core_ed25519_scalar_add(rybsya.b32, ry.b32, sy.b32);

            // A = INV_EIGHT * (r*G1[0] + s*H1[0] + rybsya*H + d*G)
            point_t A_rG, A_sH, A_rybsyaH, A_dG, A_combined;
            crypto_scalarmult_ed25519(A_rG.b32, r.b32, Gi[0].b32);
            crypto_scalarmult_ed25519(A_sH.b32, s.b32, Hi[0].b32);
            crypto_scalarmult_ed25519(A_rybsyaH.b32, rybsya.b32, point_generator_H().b32);
            crypto_scalarmult_ed25519(A_dG.b32, d.b32, point_generator_G().b32);
            crypto_core_ed25519_add(A_combined.b32, A_rG.b32, A_sH.b32);
            crypto_core_ed25519_add(A_combined.b32, A_combined.b32, A_rybsyaH.b32);
            crypto_core_ed25519_add(A_combined.b32, A_combined.b32, A_dG.b32);

            scalar_t inv_eight = scalar_uint64(8);
            crypto_core_ed25519_scalar_invert(inv_eight.b32, inv_eight.b32);
            crypto_scalarmult_ed25519(p.A.b32, inv_eight.b32, A_combined.b32);

            // B = INV_EIGHT * ((r * y * s) * H + eta * G)
            scalar_t ry_s;
            crypto_core_ed25519_scalar_mul(ry_s.b32, r.b32, y.b32);
            crypto_core_ed25519_scalar_mul(ry_s.b32, ry_s.b32, s.b32);

            point_t B_rybsH, B_etaG, B_combined;
            crypto_scalarmult_ed25519(B_rybsH.b32, ry_s.b32, point_generator_H().b32);
            crypto_scalarmult_ed25519(B_etaG.b32, eta.b32, point_generator_G().b32);
            crypto_core_ed25519_add(B_combined.b32, B_rybsH.b32, B_etaG.b32);
            crypto_scalarmult_ed25519(p.B.b32, inv_eight.b32, B_combined.b32);

            tr.update(p.A);
            tr.update(p.B);

            const scalar_t x = tr.challenge();
            if (x.empty())
                goto try_prove;

            // r1 = r + a[0] * x
            scalar_t r1_term;
            crypto_core_ed25519_scalar_mul(r1_term.b32, a[0].b32, x.b32);
            crypto_core_ed25519_scalar_add(p.r1.b32, r.b32, r1_term.b32);

            // s1 = s + b[0] * x
            scalar_t s1_term;
            crypto_core_ed25519_scalar_mul(s1_term.b32, b[0].b32, x.b32);
            crypto_core_ed25519_scalar_add(p.s1.b32, s.b32, s1_term.b32);

            // d1 = eta + d * x + alpha * x^2
            scalar_t x_sq;
            crypto_core_ed25519_scalar_mul(x_sq.b32, x.b32, x.b32);

            scalar_t d_x, alpha_x_sq;
            crypto_core_ed25519_scalar_mul(d_x.b32, d.b32, x.b32);
            crypto_core_ed25519_scalar_mul(alpha_x_sq.b32, alpha.b32, x_sq.b32);
            crypto_core_ed25519_scalar_add(p.d1.b32, eta.b32, d_x.b32);
            crypto_core_ed25519_scalar_add(p.d1.b32, p.d1.b32, alpha_x_sq.b32);
            return std::make_pair(std::move(p), std::move(V));
        }
        catch (const std::exception&)
        {
            goto try_setup;
        }
    }
}