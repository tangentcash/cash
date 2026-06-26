#include "bpp.h"

#include <stdexcept>
#include <string>
#include <utility>
#include "rand.h"

extern "C"
{
#include "monero.h"
}

namespace xmr_bpp
{
    namespace
    {
        constexpr size_t maxN = 64;
        constexpr size_t maxM = 16;

        constexpr uint8_t H_BYTES[32] = {
            0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf,
            0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
            0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9,
            0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94
        };

        constexpr char HASH_KEY_BULLETPROOF_PLUS_EXPONENT[] = "bulletproof_plus";
        constexpr char HASH_KEY_BULLETPROOF_PLUS_TRANSCRIPT[] = "bulletproof_plus_transcript";

        struct constants_t
        {
            scalar_t zero, one, two, minus_one, inv_eight, minus_inv_eight;
            point_t G, H, initial_transcript;
        };

        point_t point_identity()
        {
            point_t out;
            out.b32[0] = 1;
            return out;
        }

        bool equal(const scalar_t& lhs, const scalar_t& rhs)
        {
            return std::memcmp(lhs.b32, rhs.b32, 32) == 0;
        }

        bool equal(const point_t& lhs, const point_t& rhs)
        {
            return std::memcmp(lhs.b32, rhs.b32, 32) == 0;
        }

        scalar_t scalar_uint64(uint64_t value)
        {
            scalar_t out;
            for (size_t i = 0; i < 8; ++i)
                out.b32[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xff);
            return out;
        }

        scalar_t scalar_random()
        {
            scalar_t out;
            do
            {
                random_buffer(out.b32, sizeof(out.b32));
                sc_reduce32(out.b32);
            } while (out.empty());
            return out;
        }

        void scalar_add(scalar_t& out, const scalar_t& lhs, const scalar_t& rhs)
        {
            scalar_t tmp;
            sc_add(tmp.b32, lhs.b32, rhs.b32);
            out = tmp;
        }

        void scalar_sub(scalar_t& out, const scalar_t& lhs, const scalar_t& rhs)
        {
            scalar_t tmp;
            sc_sub(tmp.b32, lhs.b32, rhs.b32);
            out = tmp;
        }

        void scalar_mul(scalar_t& out, const scalar_t& lhs, const scalar_t& rhs)
        {
            scalar_t tmp;
            sc_mul(tmp.b32, lhs.b32, rhs.b32);
            out = tmp;
        }

        void scalar_muladd(scalar_t& out, const scalar_t& a, const scalar_t& b, const scalar_t& c)
        {
            scalar_t tmp;
            sc_muladd(tmp.b32, a.b32, b.b32, c.b32);
            out = tmp;
        }

        void scalar_invert(scalar_t& out, const scalar_t& value)
        {
            if (value.empty())
                throw std::runtime_error("cannot invert zero scalar");
            scalar_t tmp;
            sc_invert(tmp.b32, value.b32);
            out = tmp;
        }

        void write_varint(uint64_t value, std::string& out)
        {
            while (value >= 0x80)
            {
                out.push_back(static_cast<char>((value & 0x7f) | 0x80));
                value >>= 7;
            }
            out.push_back(static_cast<char>(value));
        }

        scalar_t hash_to_scalar_bytes(const uint8_t* data, size_t size)
        {
            scalar_t out;
            xmr_fast_hash(out.b32, data, size);
            sc_reduce32(out.b32);
            return out;
        }

        scalar_t hash_to_scalar_keys(const std::vector<point_t>& keys)
        {
            std::vector<uint8_t> data;
            data.reserve(keys.size() * 32);
            for (const auto& key : keys)
                data.insert(data.end(), key.b32, key.b32 + 32);
            return hash_to_scalar_bytes(data.data(), data.size());
        }

        scalar_t hash_to_scalar_pair(const scalar_t& state, const point_t& update)
        {
            uint8_t data[64];
            std::memcpy(data, state.b32, 32);
            std::memcpy(data + 32, update.b32, 32);
            return hash_to_scalar_bytes(data, sizeof(data));
        }

        scalar_t hash_to_scalar_triple(const scalar_t& state, const point_t& update0, const point_t& update1)
        {
            uint8_t data[96];
            std::memcpy(data, state.b32, 32);
            std::memcpy(data + 32, update0.b32, 32);
            std::memcpy(data + 64, update1.b32, 32);
            return hash_to_scalar_bytes(data, sizeof(data));
        }

        point_t point_from_p3(const ge_p3& p3)
        {
            point_t out;
            ge_p3_tobytes(out.b32, &p3);
            return out;
        }

        ge_p3 point_to_p3(const point_t& point)
        {
            ge_p3 p3;
            if (ge_frombytes_vartime(&p3, point.b32) != 0)
                throw std::runtime_error("failed to decode point");
            return p3;
        }

        point_t point_hash_key(const scalar_t& key)
        {
            scalar_t hash_key;
            xmr_fast_hash(hash_key.b32, key.b32, sizeof(key.b32));

            ge_p2 hash_p2;
            ge_fromfe_frombytes_vartime(&hash_p2, hash_key.b32);

            ge_p1p1 hash8_p1p1;
            ge_mul8(&hash8_p1p1, &hash_p2);

            ge_p3 hash8_p3;
            ge_p1p1_to_p3(&hash8_p3, &hash8_p1p1);
            return point_from_p3(hash8_p3);
        }

        point_t point_hash_bytes(const uint8_t* data, size_t size)
        {
            scalar_t first_hash;
            xmr_fast_hash(first_hash.b32, data, size);
            return point_hash_key(first_hash);
        }

        point_t point_add(const point_t& lhs, const point_t& rhs)
        {
            const point_t identity = point_identity();
            if (equal(lhs, identity))
                return rhs;
            if (equal(rhs, identity))
                return lhs;

            ge_p3 lhs_p3 = point_to_p3(lhs);
            ge_p3 rhs_p3 = point_to_p3(rhs);
            ge_cached rhs_cached;
            ge_p3_to_cached(&rhs_cached, &rhs_p3);

            ge_p1p1 sum_p1p1;
            ge_add(&sum_p1p1, &lhs_p3, &rhs_cached);

            ge_p3 sum_p3;
            ge_p1p1_to_p3(&sum_p3, &sum_p1p1);
            return point_from_p3(sum_p3);
        }

        point_t point_scalar_mul(const point_t& point, const scalar_t& scalar)
        {
            if (scalar.empty() || equal(point, point_identity()))
                return point_identity();

            ge_p3 p3 = point_to_p3(point);
            ge_p2 result;
            ge_scalarmult(&result, scalar.b32, &p3);

            point_t out;
            ge_tobytes(out.b32, &result);
            return out;
        }

        point_t point_base_mul(const scalar_t& scalar)
        {
            point_t out;
            sc_mul_g(out.b32, scalar.b32);
            return out;
        }

        point_t add_keys2(const scalar_t& a, const scalar_t& b, const point_t& B)
        {
            ge_p3 B_p3 = point_to_p3(B);
            ge_p2 result;
            ge_double_scalarmult_base_vartime(&result, b.b32, &B_p3, a.b32);

            point_t out;
            ge_tobytes(out.b32, &result);
            return out;
        }

        point_t point_multiexp(const std::vector<std::pair<scalar_t, point_t>>& terms)
        {
            point_t acc = point_identity();
            for (const auto& term : terms)
            {
                if (term.first.empty())
                    continue;
                acc = point_add(acc, point_scalar_mul(term.second, term.first));
            }
            return acc;
        }

        void hadamard_fold(std::vector<point_t>& points, const scalar_t& a, const scalar_t& b)
        {
            if ((points.size() & 1) != 0)
                throw std::runtime_error("cannot fold odd point vector");

            const size_t half = points.size() / 2;
            for (size_t i = 0; i < half; ++i)
            {
                ge_p3 left = point_to_p3(points[i]);
                ge_p3 right = point_to_p3(points[half + i]);
                ge_dsmp precomp[2];
                ge_dsm_precomp(precomp[0], &left);
                ge_dsm_precomp(precomp[1], &right);
                ge_double_scalarmult_precomp_vartime2_p3(&left, a.b32, precomp[0], b.b32, precomp[1]);
                points[i] = point_from_p3(left);
            }
            points.resize(half);
        }

        std::vector<scalar_t> scalar_powers(const scalar_t& base, size_t count)
        {
            if (count == 0)
                throw std::runtime_error("scalar power count must be nonzero");

            std::vector<scalar_t> out(count);
            out[0].b32[0] = 1;
            for (size_t i = 1; i < count; ++i)
                scalar_mul(out[i], out[i - 1], base);
            return out;
        }

        std::vector<scalar_t> vector_add(const std::vector<scalar_t>& lhs, const std::vector<scalar_t>& rhs)
        {
            if (lhs.size() != rhs.size())
                throw std::runtime_error("scalar vector size mismatch");

            std::vector<scalar_t> out(lhs.size());
            for (size_t i = 0; i < lhs.size(); ++i)
                scalar_add(out[i], lhs[i], rhs[i]);
            return out;
        }

        std::vector<scalar_t> vector_add(const std::vector<scalar_t>& lhs, const scalar_t& rhs)
        {
            std::vector<scalar_t> out(lhs.size());
            for (size_t i = 0; i < lhs.size(); ++i)
                scalar_add(out[i], lhs[i], rhs);
            return out;
        }

        std::vector<scalar_t> vector_sub(const std::vector<scalar_t>& lhs, const scalar_t& rhs)
        {
            std::vector<scalar_t> out(lhs.size());
            for (size_t i = 0; i < lhs.size(); ++i)
                scalar_sub(out[i], lhs[i], rhs);
            return out;
        }

        std::vector<scalar_t> vector_scalar(
            const std::vector<scalar_t>& values,
            size_t start,
            size_t stop,
            const scalar_t& multiplier)
        {
            if (start >= stop || stop > values.size())
                throw std::runtime_error("invalid vector slice");

            std::vector<scalar_t> out(stop - start);
            for (size_t i = start; i < stop; ++i)
                scalar_mul(out[i - start], values[i], multiplier);
            return out;
        }

        scalar_t weighted_inner_product(
            const std::vector<scalar_t>& lhs,
            size_t lhs_start,
            const std::vector<scalar_t>& rhs,
            size_t rhs_start,
            size_t count,
            const scalar_t& y)
        {
            scalar_t result;
            scalar_t y_power;
            y_power.b32[0] = 1;

            for (size_t i = 0; i < count; ++i)
            {
                scalar_t term;
                scalar_mul(term, lhs[lhs_start + i], rhs[rhs_start + i]);
                scalar_mul(y_power, y_power, y);
                scalar_muladd(result, term, y_power, result);
            }
            return result;
        }

        scalar_t weighted_inner_product(
            const std::vector<scalar_t>& lhs,
            const std::vector<scalar_t>& rhs,
            size_t rhs_start,
            const scalar_t& y)
        {
            scalar_t result;
            scalar_t y_power;
            y_power.b32[0] = 1;

            for (size_t i = 0; i < lhs.size(); ++i)
            {
                scalar_t term;
                scalar_mul(term, lhs[i], rhs[rhs_start + i]);
                scalar_mul(y_power, y_power, y);
                scalar_muladd(result, term, y_power, result);
            }
            return result;
        }

        constants_t make_constants()
        {
            constants_t c;
            c.one.b32[0] = 1;
            c.two.b32[0] = 2;
            scalar_sub(c.minus_one, c.zero, c.one);

            scalar_t eight = scalar_uint64(8);
            scalar_invert(c.inv_eight, eight);
            scalar_sub(c.minus_inv_eight, c.zero, c.inv_eight);

            c.G = point_base_mul(c.one);
            std::memcpy(c.H.b32, H_BYTES, 32);
            c.initial_transcript = point_hash_bytes(
                reinterpret_cast<const uint8_t*>(HASH_KEY_BULLETPROOF_PLUS_TRANSCRIPT),
                std::strlen(HASH_KEY_BULLETPROOF_PLUS_TRANSCRIPT));
            return c;
        }

        const constants_t& constants()
        {
            static const constants_t c = make_constants();
            return c;
        }

        void init_exponents(std::vector<point_t>& Gi, std::vector<point_t>& Hi, size_t count)
        {
            const constants_t& c = constants();
            Gi.resize(count);
            Hi.resize(count);
            for (size_t i = 0; i < count; ++i)
            {
                std::string h_hash(reinterpret_cast<const char*>(c.H.b32), 32);
                h_hash += HASH_KEY_BULLETPROOF_PLUS_EXPONENT;
                write_varint(i * 2, h_hash);
                Hi[i] = point_hash_bytes(reinterpret_cast<const uint8_t*>(h_hash.data()), h_hash.size());

                std::string g_hash(reinterpret_cast<const char*>(c.H.b32), 32);
                g_hash += HASH_KEY_BULLETPROOF_PLUS_EXPONENT;
                write_varint(i * 2 + 1, g_hash);
                Gi[i] = point_hash_bytes(reinterpret_cast<const uint8_t*>(g_hash.data()), g_hash.size());
            }
        }

        point_t vector_exponent(
            const std::vector<scalar_t>& a,
            const std::vector<scalar_t>& b,
            const std::vector<point_t>& Gi,
            const std::vector<point_t>& Hi)
        {
            std::vector<std::pair<scalar_t, point_t>> terms;
            terms.reserve(a.size() * 2);
            for (size_t i = 0; i < a.size(); ++i)
            {
                terms.push_back({ a[i], Gi[i] });
                terms.push_back({ b[i], Hi[i] });
            }
            return point_multiexp(terms);
        }

        point_t compute_LR(
            size_t size,
            const scalar_t& y,
            const std::vector<point_t>& G,
            size_t G0,
            const std::vector<point_t>& H,
            size_t H0,
            const std::vector<scalar_t>& a,
            size_t a0,
            const std::vector<scalar_t>& b,
            size_t b0,
            const scalar_t& c,
            const scalar_t& d)
        {
            const constants_t& k = constants();
            std::vector<std::pair<scalar_t, point_t>> terms;
            terms.reserve(size * 2 + 2);

            for (size_t i = 0; i < size; ++i)
            {
                scalar_t g_scalar, h_scalar, temp;
                scalar_mul(temp, a[a0 + i], y);
                scalar_mul(g_scalar, temp, k.inv_eight);
                scalar_mul(h_scalar, b[b0 + i], k.inv_eight);
                terms.push_back({ g_scalar, G[G0 + i] });
                terms.push_back({ h_scalar, H[H0 + i] });
            }

            scalar_t c_scaled, d_scaled;
            scalar_mul(c_scaled, c, k.inv_eight);
            scalar_mul(d_scaled, d, k.inv_eight);
            terms.push_back({ c_scaled, k.H });
            terms.push_back({ d_scaled, k.G });
            return point_multiexp(terms);
        }
    }

    std::tuple<proof_t, std::vector<point_t>> prove(
        const std::vector<uint64_t>& amounts,
        const std::vector<scalar_t>& blinding_factors,
        size_t N)
    {
        const constants_t& k = constants();
        if (N != 64)
            throw std::runtime_error("Monero Bulletproofs+ proofs must use 64-bit ranges");
        if (amounts.empty() || amounts.size() != blinding_factors.size() || amounts.size() > maxM)
            throw std::runtime_error("invalid Bulletproofs+ input sizes");
        for (const scalar_t& gamma : blinding_factors)
        {
            if (sc_check(gamma.b32) != 0)
                throw std::runtime_error("invalid Bulletproofs+ mask scalar");
        }

        size_t M = 1, logM = 0;
        while (M < amounts.size())
        {
            M <<= 1;
            ++logM;
        }
        const size_t logN = 6;
        const size_t logMN = logM + logN;
        const size_t MN = M * N;

        std::vector<point_t> Gi, Hi;
        init_exponents(Gi, Hi, MN);

        std::vector<point_t> V(amounts.size());
        std::vector<point_t> output_commitments(amounts.size());
        std::vector<scalar_t> sv(amounts.size());
        for (size_t i = 0; i < amounts.size(); ++i)
        {
            sv[i] = scalar_uint64(amounts[i]);

            output_commitments[i] = add_keys2(blinding_factors[i], sv[i], k.H);

            scalar_t gamma8, sv8;
            scalar_mul(gamma8, blinding_factors[i], k.inv_eight);
            scalar_mul(sv8, sv[i], k.inv_eight);
            V[i] = add_keys2(gamma8, sv8, k.H);
        }

        std::vector<scalar_t> aL(MN), aR(MN), aL8(MN), aR8(MN);
        for (size_t j = 0; j < M; ++j)
        {
            for (size_t i = N; i-- > 0;)
            {
                const bool bit = j < amounts.size() && ((amounts[j] >> i) & 1);
                if (bit)
                {
                    aL[j * N + i] = k.one;
                    aL8[j * N + i] = k.inv_eight;
                    aR[j * N + i] = k.zero;
                    aR8[j * N + i] = k.zero;
                }
                else
                {
                    aL[j * N + i] = k.zero;
                    aL8[j * N + i] = k.zero;
                    aR[j * N + i] = k.minus_one;
                    aR8[j * N + i] = k.minus_inv_eight;
                }
            }
        }

        for (;;)
        {
            scalar_t transcript(k.initial_transcript.b32);
            const scalar_t V_hash = hash_to_scalar_keys(V);
            transcript = hash_to_scalar_pair(transcript, point_t(V_hash.b32));

            scalar_t alpha = scalar_random();
            point_t pre_A = vector_exponent(aL8, aR8, Gi, Hi);
            scalar_t alpha8;
            scalar_mul(alpha8, alpha, k.inv_eight);
            point_t A = point_add(pre_A, point_base_mul(alpha8));

            scalar_t y = hash_to_scalar_pair(transcript, A);
            if (y.empty())
                continue;

            scalar_t z = hash_to_scalar_bytes(y.b32, 32);
            transcript = z;
            if (z.empty())
                continue;

            scalar_t z_squared;
            scalar_mul(z_squared, z, z);

            std::vector<scalar_t> d(MN);
            d[0] = z_squared;
            for (size_t i = 1; i < N; ++i)
                scalar_mul(d[i], d[i - 1], k.two);
            for (size_t j = 1; j < M; ++j)
            {
                for (size_t i = 0; i < N; ++i)
                    scalar_mul(d[j * N + i], d[(j - 1) * N + i], z_squared);
            }

            std::vector<scalar_t> y_powers = scalar_powers(y, MN + 2);
            std::vector<scalar_t> aL1 = vector_sub(aL, z);
            std::vector<scalar_t> aR1 = vector_add(aR, z);
            std::vector<scalar_t> d_y(MN);
            for (size_t i = 0; i < MN; ++i)
                scalar_mul(d_y[i], d[i], y_powers[MN - i]);
            aR1 = vector_add(aR1, d_y);

            scalar_t alpha1 = alpha;
            scalar_t z_pow = k.one;
            for (size_t j = 0; j < amounts.size(); ++j)
            {
                scalar_t temp;
                scalar_mul(z_pow, z_pow, z_squared);
                scalar_mul(temp, y_powers[MN + 1], z_pow);
                scalar_muladd(alpha1, temp, blinding_factors[j], alpha1);
            }

            std::vector<point_t> Gprime = Gi;
            std::vector<point_t> Hprime = Hi;
            std::vector<scalar_t> aprime = aL1;
            std::vector<scalar_t> bprime = aR1;

            scalar_t yinv;
            scalar_invert(yinv, y);
            std::vector<scalar_t> yinvpow(MN);
            yinvpow[0] = k.one;
            for (size_t i = 1; i < MN; ++i)
                scalar_mul(yinvpow[i], yinvpow[i - 1], yinv);

            proof_t proof;
            proof.A = A;
            proof.L.resize(logMN);
            proof.R.resize(logMN);

            size_t nprime = MN;
            size_t round = 0;
            bool retry_proof = false;
            while (nprime > 1)
            {
                nprime /= 2;

                scalar_t cL = weighted_inner_product(aprime, 0, bprime, nprime, nprime, y);
                std::vector<scalar_t> a2_scaled = vector_scalar(aprime, nprime, aprime.size(), y_powers[nprime]);
                scalar_t cR = weighted_inner_product(a2_scaled, bprime, 0, y);

                scalar_t dL = scalar_random();
                scalar_t dR = scalar_random();

                proof.L[round] = compute_LR(nprime, yinvpow[nprime], Gprime, nprime, Hprime, 0, aprime, 0, bprime, nprime, cL, dL);
                proof.R[round] = compute_LR(nprime, y_powers[nprime], Gprime, 0, Hprime, nprime, aprime, nprime, bprime, 0, cR, dR);

                scalar_t challenge = hash_to_scalar_triple(transcript, proof.L[round], proof.R[round]);
                if (challenge.empty())
                {
                    retry_proof = true;
                    break;
                }
                transcript = challenge;

                scalar_t challenge_inv;
                scalar_invert(challenge_inv, challenge);

                scalar_t temp;
                scalar_mul(temp, yinvpow[nprime], challenge);
                hadamard_fold(Gprime, challenge_inv, temp);
                hadamard_fold(Hprime, challenge, challenge_inv);

                scalar_mul(temp, challenge_inv, y_powers[nprime]);
                aprime = vector_add(vector_scalar(aprime, 0, nprime, challenge), vector_scalar(aprime, nprime, aprime.size(), temp));
                bprime = vector_add(vector_scalar(bprime, 0, nprime, challenge_inv), vector_scalar(bprime, nprime, bprime.size(), challenge));

                scalar_t challenge_squared, challenge_squared_inv;
                scalar_mul(challenge_squared, challenge, challenge);
                scalar_mul(challenge_squared_inv, challenge_inv, challenge_inv);
                scalar_muladd(alpha1, dL, challenge_squared, alpha1);
                scalar_muladd(alpha1, dR, challenge_squared_inv, alpha1);

                ++round;
            }
            if (retry_proof)
                continue;

            scalar_t r = scalar_random();
            scalar_t s = scalar_random();
            scalar_t d_final = scalar_random();
            scalar_t eta = scalar_random();

            std::vector<std::pair<scalar_t, point_t>> A1_terms;
            A1_terms.reserve(4);

            scalar_t r8, s8, d8, h_scalar;
            scalar_mul(r8, r, k.inv_eight);
            scalar_mul(s8, s, k.inv_eight);
            scalar_mul(d8, d_final, k.inv_eight);

            scalar_t temp, temp2;
            scalar_mul(temp, r, y);
            scalar_mul(temp, temp, bprime[0]);
            scalar_mul(temp2, s, y);
            scalar_mul(temp2, temp2, aprime[0]);
            scalar_add(temp, temp, temp2);
            scalar_mul(h_scalar, temp, k.inv_eight);

            A1_terms.push_back({ r8, Gprime[0] });
            A1_terms.push_back({ s8, Hprime[0] });
            A1_terms.push_back({ d8, k.G });
            A1_terms.push_back({ h_scalar, k.H });
            proof.A1 = point_multiexp(A1_terms);

            scalar_t B_h_scalar, eta8;
            scalar_mul(B_h_scalar, r, y);
            scalar_mul(B_h_scalar, B_h_scalar, s);
            scalar_mul(B_h_scalar, B_h_scalar, k.inv_eight);
            scalar_mul(eta8, eta, k.inv_eight);
            proof.B = add_keys2(eta8, B_h_scalar, k.H);

            scalar_t e = hash_to_scalar_triple(transcript, proof.A1, proof.B);
            if (e.empty())
                continue;

            scalar_t e_squared;
            scalar_mul(e_squared, e, e);
            scalar_muladd(proof.r1, aprime[0], e, r);
            scalar_muladd(proof.s1, bprime[0], e, s);
            scalar_muladd(proof.d1, d_final, e, eta);
            scalar_muladd(proof.d1, alpha1, e_squared, proof.d1);

            return std::make_tuple(std::move(proof), std::move(output_commitments));
        }
    }
}
