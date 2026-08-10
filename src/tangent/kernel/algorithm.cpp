#include "algorithm.h"
#include "superchain.h"
#include "../policy/compositions.h"
#include <array>
#include <gmp.h>
extern "C"
{
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_recovery.h>
#include <sodium.h>
#include "../internal/ripemd160.h"
#include "../internal/sha2.h"
#include "../internal/sha3.h"
#include "../internal/blake2b.h"
#include "../internal/bech32.h"
#include "../internal/bip39.h"
#include "../internal/pbkdf2.h"
#include "../internal/memzero.h"
#include "../internal/shamir.h"
}
#define COMPOSITION_CACHE_KEYS 256

namespace tangent
{
	namespace algorithm
	{
		static void mpz_free(void* data, size_t size)
		{
			typedef void (*gmp_free_t)(void*, size_t);
			static gmp_free_t gmp_free = nullptr;
			if (!gmp_free)
				mp_get_memory_functions(nullptr, nullptr, &gmp_free);
			gmp_free(data, size);
		}
		static void mpz_import0(const uint8_t* data, size_t size, mpz_t value)
		{
			mpz_import(value, size, 1, 1, 1, 0, data);
		}
		static string mpz_export0(const mpz_t value)
		{
			size_t size = 0;
			char* data = (char*)mpz_export(nullptr, &size, 1, 1, 1, 0, value);
			string buffer = string(data, size);
			mpz_free(data, size);
			return buffer;
		}
		static bool wvdf_import(mpz_t p, mpz_t l, const std::string_view& input, const size_t size_limit = 0)
		{
			string input_p, input_y;
			format::ro_stream stream = format::ro_stream(input);
			if (!stream.read_string(stream.read_type(), &input_p) || (size_limit > 0 && input_p.size() > size_limit))
				return false;

			if (!stream.read_string(stream.read_type(), &input_y) || (size_limit > 0 && input_p.size() > size_limit))
				return false;

			mpz_init(p);
			mpz_init(l);
			mpz_import0((uint8_t*)input_p.data(), input_p.size(), p);
			mpz_import0((uint8_t*)input_y.data(), input_y.size(), l);
			return true;
		}
		static void wvdf_order(mpz_t order, size_t* size_limit, uint64_t block_number)
		{
			auto& params = kernel::mparams();
			if (!params.on(fork_id::base_to_root_modulo, block_number))
			{
				uint8_t base[256] = { 0x9f, 0xdf, 0x38, 0xe0, 0xee, 0x4b, 0x0, 0x59, 0xdd, 0xa2, 0x23, 0x28, 0x89, 0x3c, 0x5c, 0x15, 0x2b, 0xb6, 0xba, 0xe4, 0x66, 0xa7, 0xe7, 0x70, 0xb5, 0x12, 0x52, 0x26, 0x5c, 0xf3, 0x20, 0xd, 0x90, 0x38, 0xc8, 0xdc, 0x1a, 0x23, 0xa8, 0x8a, 0xa9, 0x8c, 0x3a, 0xc9, 0x36, 0x81, 0x73, 0x5f, 0x7, 0xa, 0x59, 0xad, 0x46, 0xaa, 0xcd, 0xd3, 0xea, 0xf, 0xf9, 0xae, 0x38, 0xdf, 0x2, 0x1, 0x7e, 0x59, 0x4b, 0xf5, 0x42, 0x55, 0x1d, 0x1, 0xc7, 0x35, 0x48, 0x3e, 0x33, 0x5f, 0x51, 0xfd, 0x14, 0xca, 0xad, 0x17, 0x60, 0x33, 0x47, 0x27, 0xc5, 0xe7, 0x26, 0xe7, 0xcb, 0x25, 0x76, 0x56, 0x5c, 0x46, 0x8b, 0x26, 0x73, 0xb5, 0x1f, 0x44, 0x4f, 0x88, 0x37, 0xa2, 0xa0, 0xfc, 0xf8, 0xba, 0x78, 0xd, 0x56, 0xe, 0x9b, 0xf7, 0x26, 0xd1, 0x85, 0x63, 0x35, 0x47, 0xbc, 0xa5, 0xbb, 0x78, 0x6a, 0x69, 0x6b, 0xf1, 0x41, 0x30, 0x70, 0x9, 0x99, 0xae, 0x2b, 0x59, 0x93, 0x6c, 0x51, 0xb8, 0xf3, 0xa4, 0x5e, 0x25, 0x94, 0x38, 0x40, 0x0, 0xc8, 0x64, 0xd0, 0x68, 0x1a, 0x5, 0x5a, 0xba, 0xa5, 0x92, 0x75, 0xab, 0xb, 0xe4, 0xc9, 0xa5, 0xe1, 0x61, 0x69, 0x52, 0x90, 0xda, 0x9f, 0x20, 0x14, 0x75, 0x60, 0x60, 0x1b, 0xe8, 0x12, 0x54, 0x88, 0x95, 0x40, 0x95, 0x7, 0x6e, 0x7e, 0x79, 0x85, 0x6a, 0xf1, 0x16, 0xf, 0xaf, 0x2a, 0x66, 0xba, 0x16, 0xcd, 0x82, 0x86, 0xc9, 0x2e, 0x8e, 0xaa, 0x5c, 0xed, 0x3c, 0x18, 0xf6, 0xd0, 0xa5, 0x3c, 0xdc, 0xcf, 0x71, 0x49, 0x6, 0x2d, 0x89, 0x77, 0x32, 0xcf, 0x2f, 0x9a, 0x9c, 0x65, 0x20, 0x75, 0x59, 0x83, 0xe7, 0x4e, 0xe, 0xe9, 0x30, 0xee, 0x66, 0xbe, 0x14, 0x95, 0xb6, 0xdb, 0xf, 0x25, 0x16, 0xe0, 0x30, 0xa7, 0x21, 0x75, 0xf };
				if (size_limit)
					*size_limit = sizeof(base) * 2;
				return mpz_import0(base, sizeof(base), order);
			}
			else if (size_limit)
				*size_limit = sizeof(params.policy.pow.root) * 2;
			return mpz_import0(params.policy.pow.root, sizeof(params.policy.pow.root), order);
		}

		uint64_t pow256::solve(const uint256_t& block_hash, const pubkeyhash_t& account, uint64_t account_nonce)
		{
			auto& tx = kernel::mparams().policy.pow.tx;
			size_t offset = sizeof(block_hash) + sizeof(account_nonce) + sizeof(account.blob);
			uint64_t encoded_account_nonce = os::hw::to_endianness(os::hw::endian::big, account_nonce);
			uint8_t challenge[sizeof(block_hash) + sizeof(account_nonce) + sizeof(account.blob) + 20 * sizeof(uint8_t)], hash[64];
			memcpy(challenge + sizeof(block_hash), &encoded_account_nonce, sizeof(encoded_account_nonce));
			memcpy(challenge + sizeof(block_hash) + sizeof(encoded_account_nonce), account.blob, sizeof(account.blob));
			block_hash.encode(challenge);

			uint64_t solution = 0; uint256_t hash_value, target_value = target();
			while (!solution || hash_value > target_value)
			{
				uint64_t encoded_solution = os::hw::to_endianness(os::hw::endian::big, ++solution);
				hashing::hash160((uint8_t*)&encoded_solution, sizeof(encoded_solution), challenge + offset);
				hashing::hash512(challenge, sizeof(challenge), hash);
				for (uint16_t i = 0; i < tx.steps; i++)
					hashing::hash256(hash, i > 0 ? sizeof(hash) / 2 : sizeof(hash), hash);
				hash_value.decode(hash);
			}
			return solution;
		}
		bool pow256::verify(const uint256_t& block_hash, const pubkeyhash_t& account, uint64_t account_nonce, uint64_t solution)
		{
			if (!solution)
				return false;

			auto& tx = kernel::params().policy.pow.tx;
			size_t offset = sizeof(block_hash) + sizeof(account_nonce) + sizeof(account.blob);
			uint64_t encoded_account_nonce = os::hw::to_endianness(os::hw::endian::big, account_nonce);
			uint64_t encoded_solution = os::hw::to_endianness(os::hw::endian::big, solution);
			uint8_t challenge[sizeof(block_hash) + sizeof(account_nonce) + sizeof(account.blob) + 20 * sizeof(uint8_t)], hash[64];
			memcpy(challenge + sizeof(block_hash), &encoded_account_nonce, sizeof(encoded_account_nonce));
			memcpy(challenge + sizeof(block_hash) + sizeof(account_nonce), account.blob, sizeof(account.blob));
			block_hash.encode(challenge);
			hashing::hash160((uint8_t*)&encoded_solution, sizeof(encoded_solution), challenge + offset);
			hashing::hash512(challenge, sizeof(challenge), hash);
			for (uint16_t i = 0; i < tx.steps; i++)
				hashing::hash256(hash, i > 0 ? sizeof(hash) / 2 : sizeof(hash), hash);

			uint256_t hash_value;
			hash_value.decode(hash);
			return hash_value <= target();
		}
		uint256_t pow256::target()
		{
			return uint256_t(2 << uint256_t(256 - kernel::params().policy.pow.tx.difficulty)) - uint256_t(1);
		}

		uint256_t wesolowski::distribution::derive()
		{
			return derive(nonce++);
		}
		uint256_t wesolowski::distribution::derive(const uint256_t& step) const
		{
			char data[sizeof(uint256_t) * 2] = { 0 };
			step.encode((uint8_t*)((char*)data + sizeof(uint256_t) * 0));
			value.encode((uint8_t*)((char*)data + sizeof(uint256_t) * 1));
			return hashing::hash256i(std::string_view(data, sizeof(data)));
		}

		uint64_t wesolowski::adjust(uint64_t prev_difficulty, uint64_t prev_time, uint64_t target_block_number)
		{
			uint64_t default_difficulty = kernel::params().policy.pow.difficulty;
			if (target_block_number <= 1)
				return default_difficulty;

			if (adjustment_block_number(target_block_number) != target_block_number)
			{
			leave_as_is:
				return std::max(prev_difficulty, default_difficulty);
			}

			auto next_difficulty = prev_difficulty;
			auto& policy = kernel::params().policy;
			prev_time = std::max(policy.pow.time / 4, std::min(policy.pow.time * 4, prev_time));
			if (policy.pow.time >= prev_time)
			{
				uint64_t time_delta = policy.pow.time - prev_time;
				if (1'000'000 * time_delta / policy.pow.time < 100'000)
					goto leave_as_is;

				decimal adjustment = std::min(policy.pow.max_increase, 1 + arithmetic::divide(time_delta, prev_time));
				next_difficulty = (decimal(next_difficulty) * adjustment).to_uint64();
				if (next_difficulty < prev_difficulty)
					next_difficulty = std::numeric_limits<uint64_t>::max();
			}
			else
			{
				uint64_t time_delta = prev_time - policy.pow.time;
				if (1'000'000 * time_delta / policy.pow.time < 100'000)
					goto leave_as_is;

				decimal adjustment = std::max(policy.pow.max_decrease, 1 - arithmetic::divide(time_delta, prev_time));
				next_difficulty = (decimal(next_difficulty) * adjustment).to_uint64();
			}
			return next_difficulty;
		}
		uint64_t wesolowski::scale(uint64_t difficulty, const decimal& multiplier)
		{
			uint64_t new_difficulty = difficulty;
			if (multiplier > 1)
				new_difficulty = std::max((decimal(new_difficulty) * multiplier).to_uint64(), std::max(new_difficulty, kernel::params().policy.pow.difficulty));
			else if (multiplier < 1)
				new_difficulty = std::max((decimal(new_difficulty) * multiplier).to_uint64(), kernel::params().policy.pow.difficulty);
			return new_difficulty;
		}
		string wesolowski::evaluate(uint64_t block_number, uint64_t difficulty, const std::string_view& message)
		{
			string result;
			evaluate_or_proof(block_number, difficulty, message, std::string_view(), &result);
			return result;
		}
		bool wesolowski::verify(uint64_t block_number, uint64_t difficulty, const std::string_view& message, const std::string_view& proof)
		{
			return evaluate_or_proof(block_number, difficulty, message, proof, nullptr);
		}
		bool wesolowski::evaluate_or_proof(uint64_t block_number, uint64_t difficulty, const std::string_view& message, const std::string_view& proof_in, string* proof_out)
		{
			size_t limit;
			mpz_t x, n, n1;
			mpz_init(x);
			mpz_init(n);
			wvdf_order(n, &limit, block_number);
			mpz_init_set(n1, n);
			mpz_sub_ui(n1, n1, 1);

			uint8_t hash[64];
			hashing::hash512((uint8_t*)message.data(), message.size(), hash);
			mpz_import0(hash, sizeof(hash), x);
			bool valid_challenge = mpz_cmp_ui(x, 1) > 0 && mpz_cmp(x, n1) < 0;
			mpz_clear(n1);
			if (!valid_challenge)
			{
				mpz_clear(x);
				mpz_clear(n);
				return false;
			}

			bool success = false;
			if (proof_in.empty())
			{
				mpz_t l, p;
				mpz_init(l);
				mpz_ui_pow_ui(l, 2, (unsigned long)difficulty);
				mpz_init_set(p, l);
				mpz_powm(l, x, l, n);
				mpz_add(l, x, l);

				string lm = mpz_export0(l);
				hashing::hash512((uint8_t*)lm.data(), lm.size(), hash);
				mpz_import0(hash, sizeof(hash), l);
				mpz_nextprime(l, l);
				mpz_fdiv_q(p, p, l);
				mpz_powm(p, x, p, n);

				if (proof_out != nullptr)
				{
					format::wo_stream stream;
					stream.write_string(mpz_export0(p));
					stream.write_string(mpz_export0(l));
					proof_out->assign(std::move(stream.data));
					success = true;
				}
				mpz_clear(l);
				mpz_clear(p);
			}
			else
			{
				mpz_t p, l;
				if (wvdf_import(p, l, proof_in, limit))
				{
					mpz_t r;
					mpz_init_set_ui(r, 2);
					mpz_powm_ui(r, r, (unsigned long)difficulty, l);

					mpz_t y, t, l_evaluated;
					mpz_init(y);
					mpz_init(t);
					mpz_init(l_evaluated);
					mpz_powm(y, p, l, n);
					mpz_powm(t, x, r, n);
					mpz_mul(y, y, t);
					mpz_mod(y, y, n);
					mpz_add(l_evaluated, x, y);
					mpz_clear(r);
					mpz_clear(y);
					mpz_clear(t);
					mpz_clear(p);

					string lm = mpz_export0(l_evaluated);
					hashing::hash512((uint8_t*)lm.data(), lm.size(), hash);
					mpz_import0(hash, sizeof(hash), l_evaluated);
					mpz_nextprime(l_evaluated, l_evaluated);

					success = (mpz_cmp(l_evaluated, l) == 0);
					mpz_clear(l_evaluated);
					mpz_clear(l);
				}
			}

			mpz_clear(x);
			mpz_clear(n);
			return success;
		}
		int8_t wesolowski::compare(const std::string_view& proof1, const std::string_view& proof2)
		{
			int result = 0;
			mpz_t p1_p, p1_l, p2_p, p2_l;
			bool p1_valid = wvdf_import(p1_p, p1_l, proof1);
			bool p2_valid = wvdf_import(p2_p, p2_l, proof2);
			if (p1_valid && p2_valid)
			{
				int compare_y = mpz_cmp(p1_l, p2_l);
				if (compare_y == 0)
				{
					int compare_p = mpz_cmp(p1_p, p2_p);
					if (compare_p != 0)
						result = compare_p;
				}
				else
					result = compare_y;
			}
			else
				result = p1_valid ? 1 : -1;

			if (p1_valid)
			{
				mpz_clear(p1_p);
				mpz_clear(p1_l);
			}

			if (p2_valid)
			{
				mpz_clear(p2_p);
				mpz_clear(p2_l);
			}

			return (int8_t)result;
		}
		uint64_t wesolowski::adjustment_interval()
		{
			auto& policy = kernel::params().policy;
			return policy.pow.adjustment_time / policy.pow.time;
		}
		uint64_t wesolowski::adjustment_block_number(uint64_t block_number)
		{
			return block_number - block_number % adjustment_interval();
		}
		decimal wesolowski::adjustment_scaling(uint64_t block_number)
		{
			if (block_number == 0)
				return 1;

			bool outside_priority = block_number >= kernel::params().policy.production.max_per_block;
			if (outside_priority)
				return kernel::params().policy.pow.bump_outside_priority;

			auto scale = decimal(kernel::params().policy.pow.bump_per_priority);
			auto result = scale;
			while (block_number--)
				result *= scale;
			return result;
		}
		format::tree wesolowski::serialize(uint64_t difficulty, const std::string_view& signature, const decimal& scaling)
		{
			mpz_t p, l;
			if (!wvdf_import(p, l, signature))
				return format::tree();

			auto data = format::tree::map();
			data.set("p", format::variable(format::util::encode_0xhex(mpz_export0(p))));
			data.set("l", format::variable(format::util::encode_0xhex(mpz_export0(l))));
			if (scaling.is_positive())
				data.set("scaling", format::variable(scaling));
			data.set("kdifficulty", algorithm::encoding::serialize_uint256(kdifficulty(difficulty)));
			data.set("difficulty", format::variable(difficulty));
			data.set("security", format::variable(kernel::params().policy.pow.security));
			data.set("size", format::variable(signature.size()));
			mpz_clear(p);
			mpz_clear(l);
			return data;
		}
		uint128_t wesolowski::kdifficulty(uint64_t difficulty)
		{
			auto& policy = kernel::params().policy;
			uint128_t x = uint128_t(policy.pow.security / 8);
			uint128_t y = uint128_t(difficulty);
			return x * x * y;
		}

		int segwit::tweak(uint8_t* output, size_t* output_size, int32_t output_bits, const uint8_t* input, size_t input_size, int32_t input_bits, int32_t padding)
		{
			int32_t bits = 0;
			uint32_t value = 0;
			uint32_t max = (((uint32_t)1) << output_bits) - 1;
			while (input_size--)
			{
				value = (value << input_bits) | *(input++);
				bits += input_bits;
				while (bits >= output_bits)
				{
					bits -= output_bits;
					output[(*output_size)++] = (value >> bits) & max;
				}
			}

			if (padding)
			{
				if (bits)
					output[(*output_size)++] = (value << (output_bits - bits)) & max;
			}
			else if (((value << (output_bits - bits)) & max) || bits >= input_bits)
				return 0;

			return 1;
		}
		int segwit::encode(char* output, const char* prefix, int32_t version, const uint8_t* program, size_t program_size)
		{
			uint8_t data[65] = { 0 };
			size_t data_size = 0;
			if (version == 0 && program_size != 20 && program_size != 32)
				return 0;
			else if (program_size < 2 || program_size > 40)
				return 0;

			data[0] = version;
			tweak(data + 1, &data_size, 5, program, program_size, 8, 1);
			++data_size;

			return bech32_encode(output, prefix, data, data_size, BECH32_ENCODING_BECH32M);
		}
		int segwit::decode(int* version, uint8_t* program, size_t* program_size, const char* prefix, const char* input)
		{
			char hrp[84] = { 0 };
			uint8_t data[84] = { 0 };
			size_t data_size = 0;
			if (bech32_decode(hrp, data, &data_size, input) != BECH32_ENCODING_BECH32M)
				return 0;

			if (data_size == 0 || data_size > 65)
				return 0;

			if (strncmp(prefix, hrp, 84) != 0)
				return 0;

			*program_size = 0;
			if (!tweak(program, program_size, 8, data + 1, data_size - 1, 5, 0))
				return 0;

			if (*program_size < 2 || *program_size > 40)
				return 0;

			if (data[0] == 0 && *program_size != 20 && *program_size != 32)
				return 0;

			*version = data[0];
			return 1;
		}

		void signing::initialize()
		{
			if (!shared_context)
				shared_context = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
		}
		void signing::deinitialize()
		{
			if (shared_context != nullptr)
			{
				secp256k1_context_destroy(shared_context);
				shared_context = nullptr;
			}
		}
		uint256_t signing::message_hash(const std::string_view& signable_message)
		{
			format::wo_stream message;
			message.write_typeless(kernel::params().account.message_magic);
			message.write_typeless(signable_message.data(), signable_message.size());
			return message.hash();
		}
		string signing::mnemonicgen(uint16_t strength)
		{
			VI_ASSERT(strength % 32 == 0 && strength >= 128 && strength <= 256, "invalid mnemonic strength");
			uint8_t data[32] = { 0 };
			crypto::fill_random_bytes(data, 32);

			size_t length = strength / 8;
			uint8_t bits[32 + 1] = { 0 };
			sha256_Raw(data, length, bits);
			bits[length] = bits[0];
			memcpy(bits, data, length);
			memzero(data, sizeof(data));

			char buffer[256] = { 0 };
			char* p = buffer;
			size_t mlen = length * 3 / 4;
			size_t i = 0, j = 0, idx = 0;
			for (i = 0; i < mlen; i++)
			{
				idx = 0;
				for (j = 0; j < 11; j++)
				{
					idx <<= 1;
					idx += (bits[(i * 11 + j) / 8] & (1 << (7 - ((i * 11 + j) % 8)))) > 0;
				}
				strcpy(p, mnemonic_words[idx]);
				p += strlen(mnemonic_words[idx]);
				*p = (i < mlen - 1) ? ' ' : 0;
				p++;
			}
			memzero(bits, sizeof(bits));
			return string(buffer, strnlen(buffer, sizeof(buffer)));
		}
		void signing::keygen(seckey_t& secret_key)
		{
			while (true)
			{
				if (!crypto::fill_random_bytes(secret_key.blob, sizeof(seckey_t)))
					break;
				else if (verify_secret_key(secret_key))
					break;
			}
		}
		bool signing::recover(const uint256_t& hash, pubkey_t& public_key, const hashsig_t& signature)
		{
			uint8_t recovery_id = 0;
			size_t signature_size = sizeof(hashsig_t);
			size_t recovery_offset = signature_size - sizeof(recovery_id);
			memcpy(&recovery_id, signature.blob + recovery_offset, sizeof(recovery_id));
			if (recovery_id >= 4)
				return false;

			secp256k1_context* context = get_context();
			secp256k1_ecdsa_recoverable_signature recoverable_signature;
			if (!secp256k1_ecdsa_recoverable_signature_parse_compact(context, &recoverable_signature, signature.blob, recovery_id))
				return false;

			secp256k1_ecdsa_signature normalized_signature, compact_signature;
			memcpy(compact_signature.data, recoverable_signature.data, sizeof(compact_signature));
			if (secp256k1_ecdsa_signature_normalize(context, &normalized_signature, &compact_signature) != 0)
				return false;

			uint8_t data[32];
			hash.encode(data);

			secp256k1_pubkey recovered_public_key;
			if (secp256k1_ecdsa_recover(context, &recovered_public_key, &recoverable_signature, data) != 1)
				return false;

			size_t public_key_size = sizeof(pubkey_t);
			return secp256k1_ec_pubkey_serialize(context, public_key.blob, &public_key_size, &recovered_public_key, SECP256K1_EC_COMPRESSED) == 1;
		}
		bool signing::recover_hash(const uint256_t& hash, pubkeyhash_t& public_key_hash, const hashsig_t& signature)
		{
			pubkey_t public_key;
			if (!recover(hash, public_key, signature))
				return false;

			derive_public_key_hash(public_key, public_key_hash);
			return true;
		}
		bool signing::sign(const uint256_t& hash, const seckey_t& secret_key, hashsig_t& signature)
		{
			uint8_t data[32];
			hash.encode(data);
			memzero(signature.blob, sizeof(hashsig_t));

			secp256k1_context* context = get_context();
			secp256k1_ecdsa_recoverable_signature recoverable_signature;
			if (secp256k1_ecdsa_sign_recoverable(context, &recoverable_signature, data, secret_key.blob, secp256k1_nonce_function_rfc6979, nullptr) != 1)
				return false;

			int recovery_id = 0;
			if (secp256k1_ecdsa_recoverable_signature_serialize_compact(context, signature.blob, &recovery_id, &recoverable_signature) != 1)
				return false;

			signature.blob[sizeof(hashsig_t) - 1] = (uint8_t)recovery_id;
			return true;
		}
		bool signing::verify(const uint256_t& hash, const pubkey_t& public_key, const hashsig_t& signature)
		{
			secp256k1_context* context = get_context();
			secp256k1_ecdsa_signature compact_signature;
			if (secp256k1_ecdsa_signature_parse_compact(context, &compact_signature, signature.blob) != 1)
				return false;

			secp256k1_pubkey derived_public_key;
			if (secp256k1_ec_pubkey_parse(context, &derived_public_key, public_key.blob, sizeof(pubkey_t)) != 1)
				return false;

			secp256k1_ecdsa_signature normalized_signature;
			if (secp256k1_ecdsa_signature_normalize(context, &normalized_signature, &compact_signature) != 0)
				return false;

			uint8_t data[32];
			hash.encode(data);
			return secp256k1_ecdsa_verify(context, &normalized_signature, data, &derived_public_key) == 1;
		}
		bool signing::verify_mnemonic(const std::string_view& mnemonic)
		{
			uint32_t i = 0, n = 0;
			while (i < mnemonic.size())
			{
				if (mnemonic[i] == ' ')
					n++;
				i++;
			}

			n++;
			if (n != 12 && n != 18 && n != 24)
				return false;

			char current_word[10] = { 0 };
			uint32_t j = 0, k = 0, ki = 0, bi = 0;
			uint8_t result[32 + 1] = { 0 };
			memzero(result, sizeof(result));
			i = 0;

			while (i < mnemonic.size())
			{
				j = 0;
				while (i < mnemonic.size() && mnemonic[i] != ' ')
				{
					if (j >= sizeof(current_word) - 1)
					{
						memzero(result, sizeof(result));
						return false;
					}

					current_word[j] = mnemonic[i];
					i++;
					j++;
				}

				current_word[j] = 0;
				if (i < mnemonic.size())
					i++;

				k = 0;
				for (;;)
				{
					if (!mnemonic_words[k])
					{
						memzero(result, sizeof(result));
						return false;
					}

					if (strcmp(current_word, mnemonic_words[k]) == 0)
					{ 
						for (ki = 0; ki < 11; ki++)
						{
							if (k & (1 << (10 - ki)))
								result[bi / 8] |= 1 << (7 - (bi % 8));
							bi++;
						}
						break;
					}
					k++;
				}
			}

			if (bi != n * 11 || (n != 12 && n != 18 && n != 24))
			{
				memzero(result, sizeof(result));
				return false;
			}

			uint8_t checksum = result[n * 4 / 3];
			sha256_Raw(result, n * 4 / 3, result);
			if (n == 12)
				return (result[0] & 0xF0) == (checksum & 0xF0);
			else if (n == 18)
				return (result[0] & 0xFC) == (checksum & 0xFC);
			else if (n == 24)
				return result[0] == checksum;

			return true;
		}
		bool signing::verify_secret_key(const seckey_t& secret_key)
		{
			secp256k1_context* context = get_context();
			return secp256k1_ec_seckey_verify(context, secret_key.blob) == 1;
		}
		bool signing::verify_public_key(const pubkey_t& public_key)
		{
			secp256k1_pubkey derived_public_key;
			secp256k1_context* context = get_context();
			return secp256k1_ec_pubkey_parse(context, &derived_public_key, public_key.blob, sizeof(pubkey_t)) == 1;
		}
		bool signing::verify_address(const std::string_view& address)
		{
			pubkeyhash_t public_key_hash;
			return decode_address(address, public_key_hash);
		}
		void signing::derive_secret_key_from_mnemonic(const std::string_view& mnemonic, seckey_t& secret_key)
		{
			VI_ASSERT(stringify::is_cstring(mnemonic), "mnemonic should be set");
			uint8_t seed[64] = { 0 };
			const uint8_t salt[] = "mnemonic";
			PBKDF2_HMAC_SHA512_CTX pctx;
			pbkdf2_hmac_sha512_Init(&pctx, (const uint8_t*)mnemonic.data(), (int)mnemonic.size(), salt, sizeof(salt) - 1, 1);
			for (int i = 0; i < 16; i++)
				pbkdf2_hmac_sha512_Update(&pctx, 2048 / 16);
			pbkdf2_hmac_sha512_Final(&pctx, seed);
			derive_secret_key(algorithm::hashing::hash256i(seed, sizeof(seed)), secret_key);
		}
		void signing::derive_secret_key_from_parent(const seckey_t& secret_key, const uint256_t& entropy, seckey_t& child_secret_key)
		{
			format::wo_stream message;
			message.write_typeless(secret_key.blob, sizeof(seckey_t));
			message.write_typeless(entropy);
			derive_secret_key(message.hash(), child_secret_key);
		}
		void signing::derive_secret_key(const uint256_t& entropy, seckey_t& secret_key)
		{
			auto hash = entropy;
			hash.encode(secret_key.blob);
			while (!verify_secret_key(secret_key))
			{
				hash = hashing::hash256i(secret_key.blob, sizeof(secret_key.blob));
				hash.encode(secret_key.blob);
			}
		}
		bool signing::derive_public_key(const seckey_t& secret_key, pubkey_t& public_key)
		{
			secp256k1_pubkey derived_public_key;
			secp256k1_context* context = get_context();
			memzero(public_key.blob, sizeof(pubkey_t));
			if (secp256k1_ec_pubkey_create(context, &derived_public_key, secret_key.blob) != 1)
				return false;

			size_t public_key_size = sizeof(pubkey_t);
			return secp256k1_ec_pubkey_serialize(context, public_key.blob, &public_key_size, &derived_public_key, SECP256K1_EC_COMPRESSED) == 1;
		}
		void signing::derive_public_key_hash(const pubkey_t& public_key, pubkeyhash_t& public_key_hash)
		{
			hashing::hash160(public_key.blob, sizeof(pubkey_t), public_key_hash.blob);
		}
		bool signing::derive_seed_from_high_entropy_password(const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size)
		{
			const uint8_t salt[crypto_pwhash_SALTBYTES + 1] = "ecf64bb58acc059f";
			const uint32_t operations = 3, memory = 1 << 20;
			return crypto_pwhash(output, output_size, (const char*)input, input_size, salt, operations, memory, crypto_pwhash_ALG_ARGON2I13) == 0;
		}
		bool signing::split_secret_into_shares(const uint8_t* message_in, size_t message_in_size, uint8_t threshold, uint8_t count, btree_set<share_t>& shares)
		{
			VI_ASSERT(message_in != nullptr, "message must be set");
			VI_ASSERT(message_in_size <= sss_MLEN, "message size must be less than 64");
			VI_ASSERT(threshold <= count, "threshold must be less than or equal to count");
			VI_ASSERT(count <= 64, "count must be less than or equal to 64");
			uint8_t wrapped_message[sss_MLEN];
			memset(wrapped_message, 0, sizeof(wrapped_message));
			memcpy(wrapped_message, message_in, message_in_size);

			std::array<sss_Share, 64> sss_shares;
			if (sss_create_shares(sss_shares.data(), wrapped_message, count, threshold) != 0)
				return false;

			shares.clear();
			for (size_t i = 0; i < count; i++)
				shares.insert(share_t(sss_shares[i], sizeof(sss_Share)));

			return true;
		}
		bool signing::combine_shares_into_secret(const btree_set<share_t>& shares, uint8_t* message_out, size_t message_out_size)
		{
			VI_ASSERT(message_out != nullptr, "message must be set");
			VI_ASSERT(message_out_size <= sss_MLEN, "message size must be less than 64");
			VI_ASSERT(shares.size() <= 64, "shares count must be less than or equal to 64");
			std::array<sss_Share, 64> sss_shares; size_t index = 0;
			for (auto& share : shares)
				memcpy(sss_shares[index++], share.blob, sizeof(sss_Share));

			uint8_t wrapped_message[sss_MLEN];
			if (sss_combine_shares(wrapped_message, sss_shares.data(), (uint8_t)shares.size()) != 0)
				return false;

			memcpy(message_out, wrapped_message, message_out_size);
			return true;
		}
		uint8_t signing::recovery_threshold(size_t shares)
		{
			return (uint8_t)std::min<size_t>((2 + shares * 2) / 3, 64);
		}
		bool signing::scalar_add_secret_key(seckey_t& secret_key, const seckey_t& scalar)
		{
			secp256k1_context* context = algorithm::signing::get_context();
			return secp256k1_ec_seckey_tweak_add(context, secret_key.blob, scalar.blob) == 1;
		}
		bool signing::scalar_mul_secret_key(seckey_t& secret_key, const seckey_t& scalar)
		{
			secp256k1_context* context = algorithm::signing::get_context();
			return secp256k1_ec_seckey_tweak_mul(context, secret_key.blob, scalar.blob) == 1;
		}
		bool signing::scalar_add_public_key(pubkey_t& public_key, const seckey_t& scalar)
		{
			secp256k1_context* context = algorithm::signing::get_context();
			secp256k1_pubkey result_public_key;
			if (secp256k1_ec_pubkey_parse(context, &result_public_key, public_key.blob, sizeof(public_key.blob)) != 1)
				return false;

			if (secp256k1_ec_pubkey_tweak_add(context, &result_public_key, scalar.blob) != 1)
				return false;

			size_t key_size = sizeof(public_key.blob);
			return secp256k1_ec_pubkey_serialize(context, public_key.blob, &key_size, &result_public_key, SECP256K1_EC_COMPRESSED) == 1;
		}
		bool signing::scalar_mul_public_key(pubkey_t& public_key, const seckey_t& scalar)
		{
			secp256k1_context* context = algorithm::signing::get_context();
			secp256k1_pubkey result_public_key;
			if (secp256k1_ec_pubkey_parse(context, &result_public_key, public_key.blob, sizeof(public_key.blob)) != 1)
				return false;

			if (secp256k1_ec_pubkey_tweak_mul(context, &result_public_key, scalar.blob) != 1)
				return false;

			size_t key_size = sizeof(public_key.blob);
			return secp256k1_ec_pubkey_serialize(context, public_key.blob, &key_size, &result_public_key, SECP256K1_EC_COMPRESSED) == 1;
		}
		bool signing::point_add_public_key(pubkey_t& public_key, const pubkey_t& point)
		{
			secp256k1_context* context = algorithm::signing::get_context();
			secp256k1_pubkey result_public_key, other_public_key;
			if (secp256k1_ec_pubkey_parse(context, &result_public_key, public_key.blob, sizeof(public_key.blob)) != 1)
				return false;

			if (secp256k1_ec_pubkey_parse(context, &other_public_key, point.blob, sizeof(point.blob)) != 1)
				return false;

			secp256k1_pubkey* public_keys[2] = { &result_public_key, &other_public_key };
			if (secp256k1_ec_pubkey_combine(context, &result_public_key, public_keys, 2) != 1)
				return false;

			size_t key_size = sizeof(public_key.blob);
			return secp256k1_ec_pubkey_serialize(context, public_key.blob, &key_size, &result_public_key, SECP256K1_EC_COMPRESSED) == 1;
		}
		option<string> signing::public_encrypt(const pubkey_t& public_key, const std::string_view& plaintext, const uint256_t& entropy)
		{
			secp256k1_pubkey recipient_public_key;
			secp256k1_context* context = get_context();
			if (secp256k1_ec_pubkey_parse(context, &recipient_public_key, public_key.blob, sizeof(public_key.blob)) != 1)
				return optional::none;

			uint8_t nonce_secret_key_seed[40], salt_entropy_seed[40];
			memcpy(nonce_secret_key_seed, "PKDOMAIN", 8);
			memcpy(salt_entropy_seed, "SNDOMAIN", 8);
			entropy.encode(nonce_secret_key_seed + 8);
			entropy.encode(salt_entropy_seed + 8);

			seckey_t nonce_secret_key;
			derive_secret_key(hashing::hash256i(nonce_secret_key_seed, sizeof(nonce_secret_key_seed)), nonce_secret_key);

			pubkey_t nonce_public_key;
			if (!derive_public_key(nonce_secret_key, nonce_public_key))
				return optional::none;

			uint8_t shared_entropy[32];
			if (secp256k1_ecdh(context, shared_entropy, &recipient_public_key, nonce_secret_key.blob, secp256k1_ecdh_hash_function_default, nullptr) != 1)
				return optional::none;

			uint8_t salt[32], nonce[32], salt_message[32], salt_entropy[32];
			hashing::hash256((uint8_t*)plaintext.data(), plaintext.size(), salt_message);
			hashing::hash256(salt_entropy_seed, sizeof(salt_entropy_seed), salt_entropy);
			secp256k1_nonce_function_rfc6979(nonce, salt_message, nonce_secret_key.blob, nullptr, salt_entropy, 0);
			secp256k1_nonce_function_rfc6979(salt, nonce, nonce_secret_key.blob, nullptr, salt_entropy, 1);

			uint8_t shared_secret_key[32];
			if (crypto_kdf_hkdf_sha256_extract(shared_secret_key, shared_entropy, sizeof(shared_entropy), nonce, sizeof(nonce)) < 0)
				return optional::none;

			auto key_boxed = secret_box::insecure(std::string_view((char*)shared_secret_key, sizeof(shared_secret_key)));
			auto salt_boxed = secret_box::insecure(std::string_view((char*)salt, 12));
			auto result = crypto::encrypt(ciphers::aes_256_gcm(), plaintext, key_boxed, salt_boxed);
			if (!result)
				return optional::none;

			format::wo_stream message;
			message.write_string(*result);
			message.write_string(std::string_view((char*)nonce, sizeof(nonce)));
			message.write_string(salt_boxed.expose<sizeof(salt)>().view);

			hashsig_t signature;
			if (!sign(message.hash(), nonce_secret_key, signature))
				return optional::none;

			message.write_string(signature.optimized_view());
			return option<string>(std::move(message.data));
		}
		option<string> signing::private_decrypt(const seckey_t& secret_key, const std::string_view& packed_ciphertext)
		{
			string ciphertext;
			format::ro_stream message = format::ro_stream(packed_ciphertext);
			if (!message.read_string(message.read_type(), &ciphertext))
				return optional::none;
			
			string nonce;
			if (!message.read_string(message.read_type(), &nonce))
				return optional::none;

			string salt;
			if (!message.read_string(message.read_type(), &salt))
				return optional::none;

			hashsig_t signature;
			if (!message.read_optimized_view(message.read_type(), signature.blob, sizeof(signature.blob)))
				return optional::none;

			pubkey_t nonce_public_key;
			format::wo_stream unsigned_message;
			unsigned_message.write_string(ciphertext);
			unsigned_message.write_string(nonce);
			unsigned_message.write_string(salt);
			if (!recover(unsigned_message.hash(), nonce_public_key, signature))
				return optional::none;

			secp256k1_pubkey sender_public_key;
			secp256k1_context* context = get_context();
			if (secp256k1_ec_pubkey_parse(context, &sender_public_key, nonce_public_key.blob, sizeof(nonce_public_key.blob)) != 1)
				return optional::none;

			uint8_t shared_entropy[32];
			if (secp256k1_ecdh(context, shared_entropy, &sender_public_key, secret_key.blob, secp256k1_ecdh_hash_function_default, nullptr) != 1)
				return optional::none;

			uint8_t shared_secret_key[32];
			crypto_kdf_hkdf_sha256_extract(shared_secret_key, shared_entropy, sizeof(shared_entropy), (uint8_t*)nonce.data(), nonce.size());

			auto key_boxed = secret_box::insecure(std::string_view((char*)shared_secret_key, sizeof(shared_secret_key)));
			auto salt_boxed = secret_box::insecure(salt);
			auto result = crypto::decrypt(ciphers::aes_256_gcm(), ciphertext, key_boxed, salt_boxed);
			if (!result)
				return optional::none;

			return option<string>(std::move(*result));
		}
		bool signing::decode_secret_key(const std::string_view& value, seckey_t& secret_key)
		{
			auto& account = kernel::params().account;
			uint8_t decoded[40];
			size_t decoded_size = sizeof(decoded);
			int version = 0;

			if (segwit::decode(&version, decoded, &decoded_size, account.secret_key_prefix.c_str(), value.data()) != 1)
				return false;
			else if (version != (int)account.secret_key_version)
				return false;
			else if (decoded_size != sizeof(seckey_t))
				return false;

			memcpy(secret_key.blob, decoded, sizeof(seckey_t));
			return true;
		}
		bool signing::encode_secret_key(const seckey_t& secret_key, string& value)
		{
			auto& account = kernel::params().account;
			char encoded[128];
			if (segwit::encode(encoded, account.secret_key_prefix.c_str(), (int)account.secret_key_version, secret_key.blob, sizeof(seckey_t)) != 1)
				return false;

			size_t size = strnlen(encoded, sizeof(encoded));
			value.resize(size);
			memcpy(value.data(), encoded, size);
			return true;
		}
		bool signing::decode_public_key(const std::string_view& value, pubkey_t& public_key)
		{
			auto& account = kernel::params().account;
			uint8_t decoded[40];
			size_t decoded_size = sizeof(decoded);
			int version = 0;

			if (segwit::decode(&version, decoded, &decoded_size, account.public_key_prefix.c_str(), value.data()) != 1)
				return false;
			else if (version != (int)account.public_key_version)
				return false;
			else if (decoded_size != sizeof(pubkey_t))
				return false;

			memcpy(public_key.blob, decoded, sizeof(pubkey_t));
			return true;
		}
		bool signing::encode_public_key(const pubkey_t& public_key, string& value)
		{
			auto& account = kernel::params().account;
			char encoded[128];
			if (segwit::encode(encoded, account.public_key_prefix.c_str(), (int)account.public_key_version, public_key.blob, sizeof(pubkey_t)) != 1)
				return false;

			size_t size = strnlen(encoded, sizeof(encoded));
			value.resize(size);
			memcpy(value.data(), encoded, size);
			return true;
		}
		bool signing::decode_address(const std::string_view& address, pubkeyhash_t& public_key_hash)
		{
			VI_ASSERT(stringify::is_cstring(address), "public key hash, derivation hash and address should be set");
			auto& account = kernel::params().account;
			uint8_t decoded[60];
			size_t decoded_size = sizeof(decoded);
			int version = 0;

			if (segwit::decode(&version, decoded, &decoded_size, account.address_prefix.c_str(), address.data()) != 1)
				return false;
			else if (version != (int)account.address_version)
				return false;
			else if (decoded_size != sizeof(pubkeyhash_t))
				return false;

			memcpy(public_key_hash.blob, decoded, decoded_size);
			return true;
		}
		bool signing::encode_address(const pubkeyhash_t& public_key_hash, string& address)
		{
			char encoded[128];
			auto& account = kernel::params().account;
			if (segwit::encode(encoded, account.address_prefix.c_str(), (int)account.address_version, public_key_hash.blob, sizeof(pubkeyhash_t)) != 1)
				return false;

			size_t size = strnlen(encoded, sizeof(encoded));
			address.resize(size);
			memcpy(address.data(), encoded, size);
			return true;
		}
		string signing::encode_address(const pubkeyhash_t& public_key_hash)
		{
			string address;
			if (!encode_address(public_key_hash, address))
				address.clear();
			return address;
		}
		format::variable signing::serialize_secret_key(const seckey_t& secret_key)
		{
			if (secret_key.empty())
				return format::variable();

			string data;
			if (!encode_secret_key(secret_key, data))
				return format::variable();

			return format::variable(data);
		}
		format::variable signing::serialize_public_key(const pubkey_t& public_key)
		{
			if (public_key.empty())
				return format::variable();

			string data;
			if (!encode_public_key(public_key, data))
				return format::variable();

			return format::variable(data);
		}
		format::variable signing::serialize_address(const pubkeyhash_t& public_key_hash)
		{
			if (public_key_hash.empty())
				return format::variable();

			string data;
			if (!encode_address(public_key_hash, data))
				return format::variable();

			return format::variable(data);
		}
		secp256k1_context* signing::get_context()
		{
			VI_ASSERT(shared_context != nullptr, "secp256k1 context is not initialized");
			return shared_context;
		}
		secp256k1_context* signing::shared_context = nullptr;

		string encoding::encode_0xhex256(const uint256_t& value)
		{
			uint8_t data[32];
			value.encode(data);
			return "0x" + codec::hex_encode(std::string_view((char*)data, sizeof(data)));
		}
		uint256_t encoding::decode_0xhex256(const std::string_view& data)
		{
			if (data.size() < 2)
				return uint256_t(0);

			return uint256_t(data[0] == '0' && data[1] == 'x' ? data.substr(2) : data, 16);
		}
		string encoding::encode_0xhex128(const uint128_t& value)
		{
			uint8_t data[16];
			value.encode(data);
			return "0x" + codec::hex_encode(std::string_view((char*)data, sizeof(data)));
		}
		uint128_t encoding::decode_0xhex128(const std::string_view& data)
		{
			if (data.size() < 2)
				return uint128_t(0);

			return uint128_t(data[0] == '0' && data[1] == 'x' ? data.substr(2) : data, 16);
		}
		uint32_t encoding::type_of(const std::string_view& name)
		{
			return hashing::hash32d(name);
		}
		format::variable encoding::serialize_uint256(const uint256_t& value, bool always16)
		{
			if (!always16 && value <= std::numeric_limits<int64_t>::max())
				return format::variable((uint64_t)value);

			uint8_t data[32];
			value.encode(data);

			size_t size = value.bytes();
			return format::variable(format::util::encode_0xhex(std::string_view((char*)data + (sizeof(data) - size), size)));
		}
		expects_lr<string> encoding::pack_program(const std::string_view& unpacked_code)
		{
			auto packed_code = codec::compress(unpacked_code, compression::best_compression);
			if (!packed_code)
				return layer_exception(std::move(packed_code.error().message()));

			return *packed_code;
		}
		expects_lr<string> encoding::unpack_program(const std::string_view& packed_code)
		{
			auto unpacked_code = codec::decompress(packed_code, kernel::params().message.max_message_size);
			if (!unpacked_code)
				return layer_exception(std::move(unpacked_code.error().message()));

			return *unpacked_code;
		}

		uint256_t hashing::sha256ci(const uint256_t& a, const uint256_t& b)
		{
			uint8_t combine_buffer[sizeof(uint256_t) * 2];
			a.encode(combine_buffer + sizeof(uint256_t) * 0);
			b.encode(combine_buffer + sizeof(uint256_t) * 1);
			return hashing::hash256i(combine_buffer, sizeof(combine_buffer));
		}
		uint64_t hashing::sha64d(const uint8_t* buffer, size_t size)
		{
			uint64_t result = 0;
			if (!size)
				return uint64_t(0);

			string hash = hashing::hash256(buffer, size);
			if (hash.size() < sizeof(result))
				return uint64_t(0);

			memcpy(&result, hash.data(), sizeof(result));
			return os::hw::to_endianness(os::hw::endian::little, result);
		}
		uint64_t hashing::sha64d(const std::string_view& buffer)
		{
			return sha64d((uint8_t*)buffer.data(), buffer.size());
		}
		uint32_t hashing::hash32d(const uint8_t* buffer, size_t size)
		{
			uint8_t data[20];
			sha1_Raw(buffer, size, data);

			uint32_t result;
			memcpy(&result, data, sizeof(result));
			return os::hw::to_endianness(os::hw::endian::little, result);
		}
		uint32_t hashing::hash32d(const std::string_view& buffer)
		{
			return hash32d((uint8_t*)buffer.data(), buffer.size());
		}
		void hashing::hash160(const uint8_t* buffer, size_t size, uint8_t out_buffer[20])
		{
			ripemd160(buffer, (uint32_t)size, out_buffer);
		}
		string hashing::hash160(const uint8_t* buffer, size_t size)
		{
			uint8_t hash[RIPEMD160_DIGEST_LENGTH];
			hash160(buffer, size, hash);
			return string((char*)hash, sizeof(hash));
		}
		void hashing::hash256(const uint8_t* buffer, size_t size, uint8_t out_buffer[32])
		{
			blake2b(buffer, (uint32_t)size, out_buffer, sizeof(uint256_t));
		}
		string hashing::hash256(const uint8_t* buffer, size_t size)
		{
			uint8_t hash[32];
			hash256(buffer, size, hash);
			return string((char*)hash, sizeof(hash));
		}
		void hashing::hash512(const uint8_t* buffer, size_t size, uint8_t out_buffer[64])
		{
			sha3_512(buffer, size, out_buffer);
		}
		string hashing::hash512(const uint8_t* buffer, size_t size)
		{
			uint8_t hash[SHA3_512_DIGEST_LENGTH];
			hash512(buffer, size, hash);
			return string((char*)hash, sizeof(hash));
		}
		uint256_t hashing::hash256i(const uint8_t* buffer, size_t size)
		{
			uint8_t hash[32];
			uint256_t value;
			hash256(buffer, size, hash);
			value.decode(hash);
			return value;
		}
		uint256_t hashing::hash256i(const std::string_view& data)
		{
			return hash256i((uint8_t*)data.data(), data.size());
		}
		string hashing::ppc512(const std::string_view& unpacked_code)
		{
			static std::string_view lines = "\r\n";
			static std::string_view erasable = " \r\n\t\'\"()<>=%&^*/+-,.!?:;@~";
			static std::string_view quotes = "\"'`";
			string hashable = string(unpacked_code);
			stringify::replace_in_between(stringify::trim(hashable), "/*", "*/", "", false);
			stringify::replace_starts_with_ends_of(stringify::trim(hashable), "//", lines, "");
			stringify::compress(stringify::trim(hashable), erasable, quotes);
			return hash512((uint8_t*)hashable.data(), hashable.size());
		}
		string hashing::atca160ascii(const std::string_view& contract_address)
		{
			auto sha160 = format::util::is_hex_encoding(contract_address) ? crypto::hash(digests::sha1(), codec::hex_decode(contract_address)) : crypto::hash(digests::sha1(), contract_address);
			auto ascii_base64_url = codec::base64_url_encode(*sha160);
			stringify::replace_of(ascii_base64_url, "-_", "");
			return ascii_base64_url;
		}

		asset_id asset::native()
		{
			return asset_id((uint8_t)0);
		}
		asset_id asset::id_of_handle(const std::string_view& handle)
		{
			std::string_view base = stringify::starts_with(handle, kernel::params().policy.token) ? handle.substr(kernel::params().policy.token.size()) : handle;
			uint8_t data[32] = { 0 };
			size_t size = std::min<size_t>(sizeof(data), base.size());
			memcpy((char*)data + (sizeof(data) - size), base.data(), size);

			uint256_t value;
			value.decode(data);
			return value;
		}
		asset_id asset::id_of(const std::string_view& blockchain, const std::string_view& token, const std::string_view& contract_address)
		{
			uint8_t data[32] = { 0 };
			string handle = handle_of(blockchain == kernel::params().policy.token ? std::string_view() : blockchain, token, contract_address);
			size_t size = std::min<size_t>(sizeof(data), handle.size());
			memcpy((char*)data + (sizeof(data) - size), handle.data(), size);

			uint256_t value;
			value.decode(data);
			return value;
		}
		asset_id asset::base_id_of(const asset_id& value)
		{
			return value == native() ? value : id_of(blockchain_of(value));
		}
		string asset::handle_of(const std::string_view& blockchain, const std::string_view& token, const std::string_view& contract_address)
		{
			string handle = string(blockchain.substr(0, blockchain == kernel::params().policy.token ? 0 : 8));
			if (!token.empty() || !contract_address.empty())
			{
				auto symbol = string(token);
				symbol.erase(std::remove_if(symbol.begin(), symbol.end(), [](char v) { return static_cast<uint8_t>(v) < 0x20 || static_cast<uint8_t>(v) >= 0x7F; }), symbol.end());
				stringify::trim(symbol);
				if (symbol.empty())
					symbol = hashing::atca160ascii(token);
				
				auto hash = hashing::atca160ascii(contract_address.empty() ? token : contract_address);
				handle.append(1, ':').append(std::string_view(symbol).substr(0, 11));
				handle.append(1, ':').append(std::string_view(hash).substr(0, sizeof(asset_id) - handle.size()));
			}
			return handle;
		}
		string asset::handle_of(const asset_id& value)
		{
			if (value == native())
				return kernel::params().policy.token;

			uint8_t data[33];
			value.encode(data);

			size_t offset = 0;
			while (!data[offset] && offset + 1 < sizeof(data))
				++offset;

			char* ptr = (char*)data + offset;
			auto handle = string(ptr, strnlen(ptr, (sizeof(data) - 1) - offset));
			if (handle.empty())
				handle.assign(kernel::params().policy.token);
			else if (handle.front() == ':')
				handle.insert(0, kernel::params().policy.token);
			return handle;
		}
		string asset::blockchain_of(const asset_id& value)
		{
			if (value == native())
				return kernel::params().policy.token;

			string handle = handle_of(value);
			std::string_view view = std::string_view(handle);
			size_t indices = view.find(':');
			std::string_view blockchain = view.substr(0, indices);
			return string(blockchain);
		}
		string asset::token_of(const asset_id& value)
		{
			if (value == native())
				return string();

			string handle = handle_of(value);
			std::string_view view = std::string_view(handle);
			size_t indices[2] = { view.find(':'), view.rfind(':') };
			std::string_view token = indices[0] != std::string::npos && indices[0] + 1 < view.size() ? view.substr(indices[0] + 1, indices[1] != std::string::npos ? indices[1] - indices[0] - 1 : std::string::npos) : std::string_view();
			return string(token);
		}
		string asset::checksum_of(const asset_id& value)
		{
			if (value == native())
				return string();

			string handle = handle_of(value);
			std::string_view view = std::string_view(handle);
			size_t indices[2] = { view.find(':'), view.rfind(':') };
			std::string_view checksum = indices[1] != std::string::npos && indices[1] + 1 < view.size() && indices[0] < indices[1] ? view.substr(indices[1] + 1) : std::string_view();
			return string(checksum);
		}
		string asset::name_of(const asset_id& value)
		{
			auto name = blockchain_of(value);
			auto specification = token_of(value);
			if (!specification.empty())
			{
				auto checksum = checksum_of(value);
				if (!checksum.empty())
					name = specification + " (" + name + "/" + checksum + ")";
				else
					name = specification + " (" + name + ")";
			}
			return name;
		}
		bool asset::is_any(const asset_id& value, bool require_no_token, bool auxiliary_only)
		{
			auto blockchain = blockchain_of(value);
			if (stringify::is_empty_or_whitespace(blockchain))
				return false;

			bool onchain = auxiliary_only ? false : blockchain == kernel::params().policy.token;
			auto* chain = onchain ? nullptr : superchain::bridge::get()->get_network(value);
			if (!onchain && !chain)
				return false;

			auto token = token_of(value);
			auto checksum = checksum_of(value);
			bool is_token_empty = stringify::is_empty_or_whitespace(token);
			bool is_checksum_empty = stringify::is_empty_or_whitespace(checksum);
			if (is_token_empty != is_checksum_empty || (require_no_token && !is_token_empty))
				return false;

			return is_token_empty || (onchain ? true : chain->get_chainparams().tokenization != superchain::token_policy::none);
		}
		bool asset::is_aux(const asset_id& value, bool require_no_token)
		{
			return is_any(value, require_no_token, true);
		}
		format::tree asset::serialize(const asset_id& value)
		{
			format::tree data;
			data.set("id", encoding::serialize_uint256(value, true));
			string chain = blockchain_of(value);
			if (!chain.empty())
				data.set("chain", format::variable(chain));
			string token = token_of(value);
			if (!token.empty())
				data.set("token", format::variable(token));
			string checksum = checksum_of(value);
			if (!checksum.empty())
				data.set("checksum", format::variable(checksum));
			return data;
		}

		composition::keypair::~keypair()
		{
			std::fill(secret_key.begin(), secret_key.end(), 0);
			std::fill(public_key.begin(), public_key.end(), 0);
		}

		void composition::initialize_cache()
		{
			derivation_cache = memory::init<hash_map<string, string>>();
			derivation_mutex = memory::init<std::mutex>();
		}
		void composition::deinitialize_cache()
		{
			memory::deinit(derivation_cache);
			memory::deinit(derivation_mutex);
		}
		void composition::push_derivation_cache(string&& key, string&& value)
		{
			if (!derivation_cache || !derivation_mutex)
				return;

			umutex<std::mutex> unique(*derivation_mutex);
			if (derivation_cache->size() + 1 > COMPOSITION_CACHE_KEYS)
				derivation_cache->clear();
			derivation_cache->insert(std::make_pair(std::move(key), std::move(value)));
		}
		option<string> composition::pull_derivation_cache(const std::string_view& key)
		{
			if (!derivation_cache || !derivation_mutex)
				return optional::none;

			umutex<std::mutex> unique(*derivation_mutex);
			auto it = derivation_cache->find(key);
			if (it == derivation_cache->end())
				return optional::none;

			auto result = std::move(it->second);
			derivation_cache->erase(it);
			return option<string>(std::move(result));
		}
		expects_lr<composition::keypair> composition::derive_keypair(type alg, const uint8_t* seed, size_t seed_size)
		{
			VI_ASSERT(seed != nullptr, "seed should be set");
			auto keypair_state = make_compositor(alg);
			if (!keypair_state)
				return keypair_state.error();

			auto& keypair_state_ptr = *keypair_state;
			auto keypair_result = keypair();
			auto aggregation = keypair_state_ptr->derive_secret_key(seed, seed_size, &keypair_result.secret_key);
			if (!aggregation)
				return aggregation.error();

			uint8_t message[32] = { 0xFF };
			aggregation = keypair_state_ptr->setup_public_key(message, sizeof(message), 1);
			if (!aggregation)
				return aggregation.error();

			aggregation = keypair_state_ptr->aggregate(keypair_result.secret_key);
			if (!aggregation)
				return aggregation.error();

			aggregation = keypair_state_ptr->derive_public_key(&keypair_result.public_key);
			if (!aggregation)
				return aggregation.error();

			return expects_lr<composition::keypair>(std::move(keypair_result));
		}
		expects_lr<composition::cpubkey_t> composition::derive_public_key(type alg, const cseckey_t& secret_key)
		{
			auto keypair_state = make_compositor(alg);
			if (!keypair_state)
				return keypair_state.error();

			auto& keypair_state_ptr = *keypair_state;
			uint8_t message[32] = { 0xFF };
			auto aggregation = keypair_state_ptr->setup_public_key(message, sizeof(message), 1);
			if (!aggregation)
				return aggregation.error();

			aggregation = keypair_state_ptr->aggregate(secret_key);
			if (!aggregation)
				return aggregation.error();

			cpubkey_t result;
			aggregation = keypair_state_ptr->derive_public_key(&result);
			if (!aggregation)
				return aggregation.error();

			return expects_lr<composition::cpubkey_t>(std::move(result));
		}
		expects_lr<uptr<composition::compositor>> composition::make_compositor(type alg)
		{
			switch (alg)
			{
				case type::ed25519:
					return expects_lr<uptr<compositor>>(memory::init<compositions::ed25519_compositor>());
				case type::ed25519_clsag:
					return expects_lr<uptr<compositor>>(memory::init<compositions::ed25519_clsag_compositor>());
				case type::secp256k1:
					return expects_lr<uptr<compositor>>(memory::init<compositions::secp256k1_compositor>());
				case type::secp256k1_schnorr:
					return expects_lr<uptr<compositor>>(memory::init<compositions::secp256k1_schnorr_compositor>());
				default:
					return layer_exception("invalid type");
			}
		}
		expects_lr<uptr<composition::compositor>> composition::make_compositor_from_copy(const compositor* other)
		{
			VI_ASSERT(other != nullptr, "other should be set");
			format::wo_stream writer;
			if (!other->store(&writer))
				return layer_exception("failed to serialize the copying compositor");

			format::ro_stream reader = writer.ro();
			return make_compositor_from_stream(other->alg_type(), reader);
		}
		expects_lr<uptr<composition::compositor>> composition::make_compositor_from_stream(type alg, format::ro_stream& stream)
		{
			auto state = make_compositor(alg);
			if (!state)
				return state.error();

			auto& state_ptr = *state;
			if (!state_ptr->load(stream))
				return layer_exception("state load error");

			return expects_lr<uptr<composition::compositor>>(std::move(state_ptr));
		}
		expects_lr<uptr<composition::compositor>> composition::make_public_key_compositor(type alg, const uint8_t* message, size_t message_size, uint16_t participants)
		{
			auto state = make_compositor(alg);
			if (!state)
				return layer_exception("invalid type");

			auto& state_ptr = *state;
			auto configuration = state_ptr->setup_public_key(message, message_size, participants);
			if (!configuration)
				return configuration.error();

			return expects_lr<uptr<composition::compositor>>(std::move(state_ptr));
		}
		expects_lr<uptr<composition::compositor>> composition::make_signature_compositor(type alg, const cpubkey_t& public_key, const uint8_t* message, size_t message_size, const shared_message* shared, uint16_t participants)
		{
			auto state = make_compositor(alg);
			if (!state)
				return layer_exception("invalid type");

			auto& state_ptr = *state;
			auto configuration = state_ptr->setup_signature(public_key, message, message_size, shared, participants);
			if (!configuration)
				return configuration.error();

			return expects_lr<uptr<composition::compositor>>(std::move(state_ptr));
		}
		hash_map<string, string>* composition::derivation_cache;
		std::mutex* composition::derivation_mutex;

		void keypair_utils::convert_to_secret_key_ed25519(uint8_t secret_key[32])
		{
			secret_key[0] &= 248;
			secret_key[31] &= 127;
			secret_key[31] |= 64;
		}
		void keypair_utils::convert_to_scalar_ed25519(const uint8_t scalar[64], uint8_t reduced_scalar[32])
		{
			crypto_core_ed25519_scalar_reduce(reduced_scalar, scalar);
			convert_to_secret_key_ed25519(reduced_scalar);
		}
		void keypair_utils::convert_to_scalar_ed25519(uint8_t scalar[32])
		{
			uint8_t scalar64[64] = { 0 };
			memcpy(scalar64, scalar, 32);
			crypto_core_ed25519_scalar_reduce(scalar, scalar64);
			convert_to_secret_key_ed25519(scalar);
		}

		exponential_distribution::exponential_distribution() : state(nullptr)
		{
		}
		exponential_distribution::exponential_distribution(exponential_distribution&& other) noexcept : state(other.state)
		{
			other.state = nullptr;
		}
		exponential_distribution::~exponential_distribution()
		{
			if (state != nullptr)
			{
				mpf_clear(*(mpf_t*)state);
				memory::deallocate((mpf_t*)state);
			}
		}
		exponential_distribution& exponential_distribution::operator=(exponential_distribution&& other) noexcept
		{
			if (this == &other)
				return *this;

			state = other.state;
			other.state = nullptr;
			return *this;
		}
		uint32_t exponential_distribution::next(const uint256_t& entropy, uint32_t order)
		{
			if (order < 2)
				return 0;

			if (!state)
			{
				state = memory::allocate<mpf_t>(sizeof(mpf_t));
				mpf_init(*(mpf_t*)state);
			}

			uint32_t seed = arithmetic::fastmod256r32(entropy, 4294967295llu);
			mpf_t& weight = *(mpf_t*)state;
			mpf_set_ui(weight, std::max<uint32_t>((order - 1) / 2, 1));
			mpf_mul_ui(weight, weight, 8 * order);
			mpf_mul_ui(weight, weight, seed);
			mpf_div_ui(weight, weight, std::numeric_limits<uint32_t>::max());
			mpf_add_ui(weight, weight, 1);
			mpf_sqrt(weight, weight);
			mpf_sub_ui(weight, weight, 1);
			mpf_div_ui(weight, weight, 2 * order);
			mpf_neg(weight, weight);
			mpf_add_ui(weight, weight, 1);
			mpf_pow_ui(weight, weight, 2);
			mpf_mul_ui(weight, weight, order);
			mpf_floor(weight, weight);
			return mpf_get_ui(weight) % order;
		}

		uint256_t merkle_tree::branch_path::root(uint256_t hash, const hash_function hasher) const
		{
			VI_ASSERT(hasher != nullptr, "hash function should be set");
			if (index != std::numeric_limits<size_t>::max())
			{
				size_t offset = index;
				for (size_t i = 0; i < branch.size(); i++)
				{
					hash = (offset & 1 ? hasher(branch[i], hash) : hasher(hash, branch[i]));
					offset >>= 1;
				}
			}
			return hash;
		}
		bool merkle_tree::branch_path::empty() const
		{
			return branch.empty() && index != std::numeric_limits<size_t>::max();
		}

		merkle_tree::branch_path merkle_tree::path(const uint256_t& hash) const
		{
			branch_path result;
			auto begin = nodes.begin(), end = nodes.begin() + pivot;
			auto it = std::lower_bound(nodes.begin(), nodes.begin() + pivot, hash);
			if (it == end)
				return result;

			if (nodes.size() > 1)
			{
				size_t index = it - begin;
				result.index = index;
				for (size_t size = pivot, node = 0; size > 1; size = (size + 1) / 2)
				{
					result.branch.push_back(nodes[node + std::min(index ^ 1, size - 1)]);
					index >>= 1;
					node += size;
				}
			}
			else
				result.index = std::numeric_limits<size_t>::max();

			return result;
		}
		uint256_t merkle_tree::root() const
		{
			return nodes.empty() ? uint256_t(0) : nodes.back();
		}
		size_t merkle_tree::size() const
		{
			return pivot > nodes.size() ? 0 : pivot;
		}
		merkle_tree merkle_tree::from(vector<uint256_t>&& elements, const hash_function hasher)
		{
			VI_ASSERT(hasher != nullptr, "hash function should be set");
			merkle_tree result;
			result.nodes = std::move(elements);
			result.pivot = result.nodes.size();

			std::sort(result.nodes.begin(), result.nodes.end());
			if (result.nodes.size() > 1)
			{
				for (size_t size = result.pivot, node = 0; size > 1; size = (size + 1) / 2)
				{
					for (size_t offset = 0; offset < size; offset += 2)
						result.nodes.push_back(hasher(result.nodes[node + offset], result.nodes[node + std::min(offset + 1, size - 1)]));
					node += size;
				}
			}

			return result;
		}
	}
}
