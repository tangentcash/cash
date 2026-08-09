#include "compositions.h"
#include "../internal/paillier.h"
extern "C"
{
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_recovery.h>
#include <sodium.h>
#include "../internal/secp256k1.h"
#include "../internal/ed25519.h"
#include "../internal/sha2.h"
#include "../internal/sha3.h"
#include "../internal/monero.h"
}

namespace tangent
{
	namespace compositions
	{
		typedef void(*gmp_free_t)(void*, size_t);
		static gmp_free_t gmp_free = nullptr;
		inline bool mpz_import_buffer(const uint8_t* data, size_t size, mpz_t value, bool le = false)
		{
			if (!size || size > 4096)
				return false;

			mpz_import(value, size, le ? -1 : 1, 1, le ? -1 : 1, 0, data);
			return true;
		}
		inline string mpz_export_buffer(const mpz_t value, bool le = false)
		{
			if (!gmp_free)
				mp_get_memory_functions(nullptr, nullptr, &gmp_free);

			size_t size = 0;
			char* data = (char*)mpz_export(nullptr, &size, le ? -1 : 1, 1, le ? -1 : 1, 0, value);
			string buffer = string(data, size);
			gmp_free(data, size);
			return buffer;
		}
		inline curve_point from_compressed_point_secp256k1(const algorithm::storage_type<uint8_t, 33>& value)
		{
			curve_point result;
			bn_read_be(value.blob + 1, &result.x);
			uncompress_coords(&secp256k1, value.blob[0], &result.x, &result.y);
			return result;
		}
		inline algorithm::storage_type<uint8_t, 33> to_compressed_point_secp256k1(const curve_point& value)
		{
			algorithm::storage_type<uint8_t, 33> result;
			compress_coords(&value, result.blob);
			return result;
		}
		inline bignum256 from_scalar_secp256k1(const algorithm::storage_type<uint8_t, 32>& value)
		{
			bignum256 result;
			bn_read_be(value.blob, &result);
			return result;
		}
		inline algorithm::storage_type<uint8_t, 32> to_scalar_secp256k1(const bignum256& value)
		{
			algorithm::storage_type<uint8_t, 32> result;
			bn_write_be(&value, result.blob);
			return result;
		}
		static void paillier_store_public_key(const paillier_pubkey* paillier_public_key, algorithm::paillier_scalar_t* key)
		{
			VI_ASSERT(paillier_public_key != nullptr, "public key should be set");
			VI_ASSERT(key != nullptr, "key should be set");
			auto buffer = mpz_export_buffer(paillier_public_key->n);
			key->resize(buffer.size());
			memcpy(key->data(), buffer.data(), buffer.size());
		}
		static expects_lr<void> paillier_load_public_key(const algorithm::paillier_scalar_t& key, paillier_pubkey* paillier_public_key, size_t expected_bit_size)
		{
			if (!mpz_import_buffer((uint8_t*)key.data(), key.size(), paillier_public_key->n))
				return layer_exception("Invalid or dangerously large public key buffer");

			auto size = mpz_sizeinbase(paillier_public_key->n, 2);
			if (mpz_sizeinbase(paillier_public_key->n, 2) < expected_bit_size)
				return layer_exception("paillier modulus n is too small (weak security)");

			if (mpz_odd_p(paillier_public_key->n) == 0)
				return layer_exception("paillier modulus n is even");

			if (mpz_perfect_power_p(paillier_public_key->n) != 0)
				return layer_exception("paillier modulus n is a perfect power");

			if (mpz_cmp_ui(paillier_public_key->n, 1) <= 0)
				return layer_exception("paillier modulus n must be greater than 1");

			if (mpz_probab_prime_p(paillier_public_key->n, 15) > 0)
				return layer_exception("paillier modulus n cannot be a prime number");

			const uint16_t small_prime_numbers[] =
			{
				2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
				31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
				73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
				127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
				179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
				233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
				283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
				353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
				419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
				467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
				547, 557, 563, 569, 571, 577, 587, 593, 599, 601,
				607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
				661, 673, 677, 683, 691, 701, 709, 719, 727, 733,
				739, 743, 751, 757, 761, 769, 773, 787, 797, 809,
				811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
				877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
				947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013,
				1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069,
				1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151,
				1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223,
				1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291,
				1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373,
				1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451,
				1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511,
				1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583,
				1597, 1601, 1607, 1609, 1613, 1619
			};
			for (uint16_t prime : small_prime_numbers)
			{
				if (mpz_divisible_ui_p(paillier_public_key->n, prime))
					return layer_exception("paillier modulus n contains weak small prime factors");
			}

			return expectation::met;
		}
		static void paillier_to_public_key(const uint8_t* seed, size_t seed_size, size_t expected_bit_size, algorithm::paillier_scalar_t* public_key)
		{
			VI_ASSERT(public_key != nullptr, "public key should be set");
			paillier_pubkey paillier_public_key;
			paillier_seckey paillier_secret_key;
			paillier_seckey_init(&paillier_secret_key);
			paillier_pubkey_init(&paillier_public_key);
			paillier_keypair_derive(&paillier_public_key, &paillier_secret_key, (mp_bitcnt_t)expected_bit_size, seed, (mp_bitcnt_t)seed_size);
			paillier_store_public_key(&paillier_public_key, public_key);
			paillier_pubkey_clear(&paillier_public_key);
			paillier_seckey_clear(&paillier_secret_key);
		}
		static expects_lr<void> paillier_accumulate_tweak(const algorithm::paillier_scalar_t& public_key, const algorithm::composition::cseckey_t& tweak, algorithm::paillier_scalar_t* tweak_accumulator, size_t expected_bit_size, bool le = false)
		{
			VI_ASSERT(tweak_accumulator != nullptr, "tweak accumulator should be set");
			paillier_pubkey paillier_public_key;
			paillier_pubkey_init(&paillier_public_key);

			auto status = paillier_load_public_key(public_key, &paillier_public_key, expected_bit_size);
			if (!status)
			{
				paillier_pubkey_clear(&paillier_public_key);
				return status;
			}

			mpz_t plaintext_tweak;
			mpz_init(plaintext_tweak);
			if (!mpz_import_buffer(tweak.data(), tweak.size(), plaintext_tweak, le))
			{
				mpz_clear(plaintext_tweak);
				paillier_pubkey_clear(&paillier_public_key);
				return layer_exception("invalid tweak");
			}

			mpz_t ciphertext_tweak;
			mpz_init(ciphertext_tweak);
			if (paillier_encrypt(ciphertext_tweak, plaintext_tweak, &paillier_public_key) != 0)
			{
				mpz_clear(ciphertext_tweak);
				mpz_clear(plaintext_tweak);
				paillier_pubkey_clear(&paillier_public_key);
				return layer_exception("invalid paillier entropy");
			}

			mpz_clear(plaintext_tweak);
			if (!tweak_accumulator->empty())
			{
				mpz_t ciphertext_tweak_sum;
				mpz_init(ciphertext_tweak_sum);
				if (!mpz_import_buffer(tweak_accumulator->data(), tweak_accumulator->size(), ciphertext_tweak_sum))
				{
					mpz_clear(ciphertext_tweak);
					mpz_clear(ciphertext_tweak_sum);
					paillier_pubkey_clear(&paillier_public_key);
					return layer_exception("invalid tweak accumulator");
				}

				paillier_homomorphic_add(ciphertext_tweak, ciphertext_tweak_sum, ciphertext_tweak, &paillier_public_key);
				mpz_clear(ciphertext_tweak_sum);
			}

			auto result = mpz_export_buffer(ciphertext_tweak);
			tweak_accumulator->resize(result.size());
			memcpy(tweak_accumulator->data(), result.data(), result.size());
			paillier_pubkey_clear(&paillier_public_key);
			mpz_clear(ciphertext_tweak);
			return expectation::met;
		}
		static expects_lr<void> paillier_finalize_tweak(const uint8_t* seed, size_t seed_size, size_t key_size, const algorithm::paillier_scalar_t& tweak_accumulator, mpz_t plaintext_tweak)
		{
			mpz_t ciphertext_tweak;
			mpz_init(ciphertext_tweak);
			if (!mpz_import_buffer(tweak_accumulator.data(), tweak_accumulator.size(), ciphertext_tweak))
			{
				mpz_clear(ciphertext_tweak);
				return layer_exception("invalid tweak accumulator");
			}

			paillier_pubkey paillier_public_key;
			paillier_seckey paillier_secret_key;
			paillier_seckey_init(&paillier_secret_key);
			paillier_pubkey_init(&paillier_public_key);
			paillier_keypair_derive(&paillier_public_key, &paillier_secret_key, (mp_bitcnt_t)key_size, seed, (mp_bitcnt_t)seed_size);

			mpz_init(plaintext_tweak);
			paillier_decrypt(plaintext_tweak, ciphertext_tweak, &paillier_secret_key);
			paillier_pubkey_clear(&paillier_public_key);
			paillier_seckey_clear(&paillier_secret_key);
			mpz_clear(ciphertext_tweak);
			return expectation::met;
		}
		static void ed25519_to_private_key(const uint8_t* seed, size_t seed_size, uint8_t result[32])
		{
			uint8_t key_buffer[64];
			algorithm::hashing::hash512(seed, seed_size, key_buffer);
			algorithm::keypair_utils::convert_to_scalar_ed25519(key_buffer, key_buffer);
			memcpy(result, key_buffer, sizeof(ed25519_scalar_t));
		}
		static expects_lr<void> ed25519_combine_secret_key(const algorithm::composition::cseckey_t* input, algorithm::composition::cseckey_t* input_output)
		{
			VI_ASSERT(input != nullptr, "input should be set");
			VI_ASSERT(input_output != nullptr, "output should be set");
			if (input->size() != sizeof(ed25519_scalar_t))
				return layer_exception("invalid input size");

			if (input_output->size() != sizeof(ed25519_scalar_t))
				return layer_exception("invalid input size");

			uint8_t x64[64] = { 0 }, y64[64] = { 0 };
			memcpy(x64, input_output->data(), input_output->size());
			memcpy(y64, input->data(), input->size());

			uint8_t x[32], y[32], z[32], w[32] = { 0 };
			crypto_core_ed25519_scalar_reduce(x, x64);
			crypto_core_ed25519_scalar_reduce(y, y64);
			crypto_core_ed25519_scalar_add(z, x, y);
			if (!memcmp(z, w, sizeof(w)))
				return layer_exception("zero scalar output");

			memcpy(input_output->data(), z, sizeof(z));
			return expectation::met;
		}
		static expects_lr<void> ed25519_accumulator_tweak_secret_key(const uint8_t* seed, size_t seed_size, size_t key_size, const algorithm::paillier_scalar_t& accumulator, algorithm::composition::cseckey_t* secret_key_input_output)
		{
			uint8_t order_buffer[crypto_core_ed25519_SCALARBYTES];
			uint8_t value_buffer[crypto_core_ed25519_SCALARBYTES] = { 1 };
			crypto_core_ed25519_scalar_negate(order_buffer, value_buffer);

			mpz_t scalar;
			auto status = paillier_finalize_tweak(seed, seed_size, key_size, accumulator, scalar);
			if (!status)
				return status;
			
			mpz_t order;
			mpz_init(order);
			mpz_import(order, crypto_core_ed25519_SCALARBYTES, -1, 1, -1, 0, order_buffer);
			mpz_add_ui(order, order, 1);
			mpz_mod(scalar, scalar, order);
			mpz_sub(scalar, order, scalar);
			mpz_clear(order);

			auto result = mpz_export_buffer(scalar, true);
			auto tweak = algorithm::composition::cseckey_t();
			tweak.resize(sizeof(value_buffer));
			memcpy(tweak.data(), result.data(), sizeof(value_buffer));
			mpz_clear(scalar);

			return ed25519_combine_secret_key(&tweak, secret_key_input_output);
		}
		static expects_lr<void> ed25519_combine_public_key(const algorithm::composition::cpubkey_t* input, algorithm::composition::cpubkey_t* input_output)
		{
			VI_ASSERT(input != nullptr, "input should be set");
			VI_ASSERT(input_output != nullptr, "output should be set");
			if (input->size() != sizeof(ed25519_point_t))
				return layer_exception("invalid input size");

			if (!input_output->empty() && input_output->size() != sizeof(ed25519_point_t))
				return layer_exception("invalid input-output size");

			if (input_output->empty())
				input_output->assign(input->begin(), input->end());
			else if (crypto_core_ed25519_add(input_output->data(), input->data(), input_output->data()) != 0)
				return layer_exception("invalid input");

			return expectation::met;
		}
		static void secp256k1_to_private_key(const uint8_t* seed, size_t seed_size, uint8_t result[32])
		{
			uint8_t key_buffer[64];
			algorithm::hashing::hash512(seed, seed_size, key_buffer);

			secp256k1_scalar_t secret_key;
			memcpy(secret_key.blob, key_buffer, std::min(sizeof(secret_key), sizeof(key_buffer)));

			secp256k1_pubkey extended_public_key;
			secp256k1_context* context = algorithm::signing::get_context();
			while (secp256k1_ec_seckey_verify(context, secret_key.blob) != 1 || secp256k1_ec_pubkey_create(context, &extended_public_key, secret_key.blob) != 1)
			{
				algorithm::hashing::hash512(key_buffer, sizeof(key_buffer), key_buffer);
				memcpy(secret_key.blob, key_buffer, std::min(sizeof(secret_key), sizeof(key_buffer)));
			}

			memcpy(result, secret_key.blob, sizeof(secret_key));
		}
		static expects_lr<void> secp256k1_combine_secret_key(const algorithm::composition::cseckey_t* input, algorithm::composition::cseckey_t* input_output)
		{
			VI_ASSERT(input != nullptr, "input should be set");
			VI_ASSERT(input_output != nullptr, "output should be set");
			if (input->size() != sizeof(ed25519_scalar_t))
				return layer_exception("invalid input size");

			if (input_output->size() != sizeof(ed25519_scalar_t))
				return layer_exception("invalid input size");

			bignum256 a, b;
			bn_read_be(input->data(), &a);
			bn_read_be(input_output->data(), &b);
			bn_addmod(&a, &b, &secp256k1.order);
			if (bn_is_zero(&a))
				return layer_exception("zero scalar output");

			bn_write_be(&a, input_output->data());
			return expectation::met;
		}
		static expects_lr<void> secp256k1_accumulator_tweak_secret_key(const uint8_t* seed, size_t seed_size, size_t key_size, const algorithm::paillier_scalar_t& accumulator, algorithm::composition::cseckey_t* secret_key_input_output)
		{
			uint8_t value_buffer[32] = { 0 };
			bn_write_be(&secp256k1.order, value_buffer);

			mpz_t scalar;
			auto status = paillier_finalize_tweak(seed, seed_size, key_size, accumulator, scalar);
			if (!status)
				return status;

			mpz_t order;
			mpz_init(order);
			if (!mpz_import_buffer(value_buffer, sizeof(value_buffer), order))
				return layer_exception("invalid order");

			mpz_mod(scalar, scalar, order);
			mpz_sub(scalar, order, scalar);
			mpz_clear(order);

			auto result = mpz_export_buffer(scalar);
			auto tweak = algorithm::composition::cseckey_t();
			tweak.resize(sizeof(value_buffer));
			memcpy(tweak.data(), result.data(), sizeof(value_buffer));
			mpz_clear(scalar);

			return secp256k1_combine_secret_key(&tweak, secret_key_input_output);
		}
		static expects_lr<void> secp256k1_combine_public_key(const algorithm::composition::cpubkey_t* input, algorithm::composition::cpubkey_t* input_output)
		{
			VI_ASSERT(input != nullptr, "input should be set");
			VI_ASSERT(input_output != nullptr, "output should be set");
			if (input->size() != sizeof(secp256k1_point_t))
				return layer_exception("invalid input size");

			if (!input_output->empty() && input_output->size() != sizeof(secp256k1_point_t))
				return layer_exception("invalid input-output size");

			if (!input_output->empty())
			{
				secp256k1_pubkey next_public_key;
				secp256k1_context* context = algorithm::signing::get_context();
				if (secp256k1_ec_pubkey_parse(context, &next_public_key, input->data(), input->size()) != 1)
					return layer_exception("invalid input");

				secp256k1_pubkey prev_public_key, result_public_key;
				if (secp256k1_ec_pubkey_parse(context, &prev_public_key, input_output->data(), input_output->size()) != 1)
					return layer_exception("invalid input-output");

				secp256k1_pubkey* public_keys[2] = { &prev_public_key, &next_public_key };
				if (secp256k1_ec_pubkey_combine(context, &result_public_key, public_keys, 2) != 1)
					return layer_exception("invalid input");

				size_t key_size = input_output->size();
				if (secp256k1_ec_pubkey_serialize(context, input_output->data(), &key_size, &result_public_key, SECP256K1_EC_COMPRESSED) != 1)
					return layer_exception("invalid secret key");
			}
			else
				input_output->assign(input->begin(), input->end());

			return expectation::met;
		}
		static std::string_view to_optimized_uint256(const uint8_t blob[32])
		{
			size_t size = 32;
			auto* ptr = blob + size;
			while (size > 0 && !*(--ptr))
				--size;
			return std::string_view((char*)blob, size);
		}

		expects_lr<void> ed25519_compositor::setup_public_key(const uint8_t* new_message, size_t new_message_size, uint16_t new_participants)
		{
			algorithm::composition::cpubkey_t temp_public_key;
			temp_public_key.resize(sizeof(ed25519_point_t));
			auto status = setup_signature(temp_public_key, new_message, new_message_size, nullptr, new_participants);
			if (!status)
				return status.error();

			z_steps = new_participants;
			cumulative_key.clear();
			return expectation::met;
		}
		expects_lr<void> ed25519_compositor::setup_signature(const algorithm::composition::cpubkey_t& new_public_key, const uint8_t* new_message, size_t new_message_size, const algorithm::composition::shared_message* new_shared, uint16_t new_participants)
		{
			VI_ASSERT(new_message != nullptr, "message should be set");
			if (new_public_key.size() != sizeof(ed25519_point_t))
				return layer_exception("invalid public key size");

			indices.clear();
			indices.resize((size_t)new_participants, uint256_t((uint8_t)0));
			cumulative_r = ed25519_point_t();
			cumulative_s = ed25519_scalar_t();
			z_steps = 0;
			r_steps = s_steps = new_participants;
			cumulative_key = std::string_view((char*)new_public_key.data(), new_public_key.size());
			message.resize(new_message_size);
			memcpy(message.data(), new_message, new_message_size);
			return expectation::met;
		}
		expects_lr<void> ed25519_compositor::aggregate(const algorithm::composition::cseckey_t& secret_key)
		{
			if (secret_key.size() != sizeof(ed25519_scalar_t))
				return layer_exception("invalid secret key size");

			auto use_nonce = [](uint8_t nonce[64], const vector<uint8_t>& message, const algorithm::composition::cseckey_t& secret_key, const uint256_t& index)
			{
				crypto_hash_sha512_state hash;
				crypto_hash_sha512_init(&hash);
				crypto_hash_sha512_update(&hash, secret_key.data(), secret_key.size());
				crypto_hash_sha512_update(&hash, message.data(), message.size());
				if (index > 0)
				{
					uint8_t index_nonce[32];
					index.encode(index_nonce);
					crypto_hash_sha512_update(&hash, index_nonce, sizeof(index_nonce));
				}
				crypto_hash_sha512_final(&hash, nonce);
				crypto_core_ed25519_scalar_reduce(nonce, nonce);
			};
			if (z_steps > 0)
			{
				uint8_t secret_key_buffer[64] = { 0 }, public_key[32] = { 0 };
				memcpy(secret_key_buffer, secret_key.data(), secret_key.size());
				ed25519_publickey_ext(secret_key_buffer, public_key);
				if (cumulative_key.empty())
					memcpy(cumulative_key.blob, public_key, sizeof(public_key));
				else if (crypto_core_ed25519_add(cumulative_key.blob, public_key, cumulative_key.blob) != 0)
					return layer_exception("invalid secret key");

				--z_steps;
			}
			else if (r_steps > 0)
			{
				if (r_steps > indices.size())
					return layer_exception("invalid compositor state");

			retry_nonce:
				uint8_t nonce[64];
				uint256_t& index = indices[r_steps - 1];
				use_nonce(nonce, message, secret_key, ++index);

				ed25519_point_t r;
				if (crypto_scalarmult_ed25519_base_noclamp(r.blob, nonce) != 0 || r.empty())
					goto retry_nonce;

				if (!cumulative_r.empty() && (crypto_core_ed25519_add(r.blob, r.blob, cumulative_r.blob) != 0 || r.empty()))
					goto retry_nonce;

				cumulative_r = r;
				--r_steps;
			}
			else if (s_steps > 0)
			{
				if (cumulative_r.empty() || s_steps > indices.size())
					return layer_exception("invalid compositor state");

				uint8_t nonce[64];
				use_nonce(nonce, message, secret_key, indices[s_steps - 1]);

				uint8_t hram[64];
				crypto_hash_sha512_state hash;
				crypto_hash_sha512_init(&hash);
				crypto_hash_sha512_update(&hash, cumulative_r.blob, sizeof(cumulative_r.blob));
				crypto_hash_sha512_update(&hash, cumulative_key.blob, sizeof(cumulative_key.blob));
				crypto_hash_sha512_update(&hash, message.data(), message.size());
				crypto_hash_sha512_final(&hash, hram);
				crypto_core_ed25519_scalar_reduce(hram, hram);

				ed25519_scalar_t s;
				crypto_core_ed25519_scalar_mul(s.blob, hram, secret_key.data());
				crypto_core_ed25519_scalar_add(s.blob, s.blob, nonce);
				if (!cumulative_s.empty())
					crypto_core_ed25519_scalar_add(s.blob, s.blob, cumulative_s.blob);

				cumulative_s = s;
				--s_steps;
			}
			return expectation::met;
		}
		expects_lr<void> ed25519_compositor::derive_tweaking_key(const uint8_t* seed, size_t seed_size, size_t key_size, algorithm::paillier_scalar_t* public_key) const
		{
			paillier_to_public_key(seed, seed_size, key_size, public_key);
			return expectation::met;
		}
		expects_lr<void> ed25519_compositor::tweak_secret_key(const algorithm::paillier_scalar_t& public_key, size_t key_size, const algorithm::composition::cseckey_t& tweak, algorithm::composition::cseckey_t* secret_key_input_output, algorithm::paillier_scalar_t* accumulator_output) const
		{
			if (accumulator_output != nullptr)
			{
				auto status = paillier_accumulate_tweak(public_key, tweak, accumulator_output, key_size, true);
				if (!status)
					return status;
			}

			if (secret_key_input_output != nullptr)
				return ed25519_combine_secret_key(&tweak, secret_key_input_output);

			return expectation::met;
		}
		expects_lr<void> ed25519_compositor::tweak_secret_key(const uint8_t* seed, size_t seed_size, size_t key_size, const algorithm::paillier_scalar_t& accumulator, algorithm::composition::cseckey_t* secret_key_input_output) const
		{
			return ed25519_accumulator_tweak_secret_key(seed, seed_size, key_size, accumulator, secret_key_input_output);
		}
		expects_lr<void> ed25519_compositor::combine_public_keys(const algorithm::composition::cpubkey_t* input, algorithm::composition::cpubkey_t* input_output) const
		{
			return ed25519_combine_public_key(input, input_output);
		}
		expects_lr<void> ed25519_compositor::derive_secret_key(const uint8_t* seed, size_t seed_size, algorithm::composition::cseckey_t* output) const
		{
			VI_ASSERT(output != nullptr, "output should be set");
			output->resize(sizeof(ed25519_scalar_t));
			ed25519_to_private_key(seed, seed_size, output->data());
			return expectation::met;
		}
		expects_lr<void> ed25519_compositor::derive_public_key(algorithm::composition::cpubkey_t* output) const
		{
			VI_ASSERT(output != nullptr, "output should be set");
			output->resize(sizeof(cumulative_key));
			memcpy(output->data(), cumulative_key.blob, sizeof(cumulative_key));
			return expectation::met;
		}
		expects_lr<void> ed25519_compositor::derive_signature(algorithm::composition::chashsig_t* output) const
		{
			VI_ASSERT(output != nullptr, "output should be set");
			algorithm::composition::cpubkey_t public_key;
			auto status = derive_public_key(&public_key);
			if (!status)
				return status;

			output->resize(sizeof(cumulative_r) + sizeof(cumulative_s));
			memcpy(output->data(), cumulative_r.blob, sizeof(cumulative_r));
			memcpy(output->data() + sizeof(cumulative_r.blob), cumulative_s.blob, sizeof(cumulative_s));
			return verify_signature(message.data(), message.size(), *output, public_key);
		}
		expects_lr<void> ed25519_compositor::verify_signature(const uint8_t* new_message, size_t new_message_size, const algorithm::composition::chashsig_t& signature, const algorithm::composition::cpubkey_t& public_key, uint8_t flags) const
		{
			VI_ASSERT(new_message != nullptr, "message should be set");
			if (public_key.size() != sizeof(ed25519_point_t))
				return layer_exception("invalid public key");

			if (signature.size() != sizeof(cumulative_r) + sizeof(cumulative_s))
				return layer_exception("invalid signature");

			if (crypto_sign_verify_detached(signature.data(), new_message, new_message_size, public_key.data()) != 0)
				return layer_exception("signature verification failed");

			return expectation::met;
		}
		algorithm::composition::type ed25519_compositor::alg_type() const
		{
			return algorithm::composition::type::ed25519;
		}
		algorithm::composition::phase ed25519_compositor::next_phase() const
		{
			if (z_steps == indices.size())
				return algorithm::composition::phase::consume_after_reset;
			else if (z_steps > 0)
				return algorithm::composition::phase::consume;

			if (r_steps == indices.size())
				return algorithm::composition::phase::consume_after_reset;
			else if (r_steps > 0)
				return algorithm::composition::phase::consume;

			if (s_steps == indices.size())
				return algorithm::composition::phase::consume_after_reset;
			else if (s_steps > 0)
				return algorithm::composition::phase::consume;

			return algorithm::composition::phase::finalize;
		}
		uint32_t ed25519_compositor::steps_left() const
		{
			return z_steps + r_steps + s_steps;
		}
		bool ed25519_compositor::store(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(z_steps);
			stream->write_integer(r_steps);
			stream->write_integer(s_steps);
			stream->write_integer((uint16_t)indices.size());
			for (auto& index : indices)
				stream->write_integer(index);
			stream->write_string(cumulative_r.optimized_view());
			stream->write_string(cumulative_s.optimized_view());
			stream->write_string(cumulative_key.optimized_view());
			stream->write_string(std::string_view((char*)message.data(), message.size()));
			return true;
		}
		bool ed25519_compositor::load(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &z_steps))
				return false;

			if (!stream.read_integer(stream.read_type(), &r_steps))
				return false;

			if (!stream.read_integer(stream.read_type(), &s_steps))
				return false;

			uint32_t indices_size;
			if (!stream.read_integer(stream.read_type(), &indices_size))
				return false;

			indices.resize(indices_size);
			for (uint32_t i = 0; i < indices_size; i++)
			{
				if (!stream.read_integer(stream.read_type(), &indices[i]))
					return false;
			}

			if (!stream.read_optimized_view(stream.read_type(), cumulative_r.blob, sizeof(cumulative_r)))
				return false;

			if (!stream.read_optimized_view(stream.read_type(), cumulative_s.blob, sizeof(cumulative_s)))
				return false;

			if (!stream.read_optimized_view(stream.read_type(), cumulative_key.blob, sizeof(cumulative_key)))
				return false;

			string intermediate;
			if (!stream.read_string(stream.read_type(), &intermediate))
				return false;

			message.resize(intermediate.size());
			memcpy(message.data(), intermediate.data(), intermediate.size());
			return true;
		}
		bool ed25519_compositor::may_transition_to(const compositor& next_ptr) const
		{
			auto* next = (const ed25519_compositor*)&next_ptr;
			if (indices.size() != next->indices.size() || message != next->message)
				return false;

			if ((z_steps == next->z_steps) != cumulative_key.equals(next->cumulative_key))
				return false;

			if ((r_steps == next->r_steps) != cumulative_r.equals(next->cumulative_r))
				return false;

			if (r_steps == next->r_steps && s_steps == next->s_steps && indices != next->indices)
				return false;

			if (r_steps > indices.size() || next->r_steps > next->indices.size())
				return false;

			if (s_steps > indices.size() || next->s_steps > next->indices.size())
				return false;

			if ((s_steps == next->s_steps) != cumulative_s.equals(next->cumulative_s))
				return false;

			return steps_left() >= next->steps_left();
		}

		void ed25519_clsag_compositor::clsag_message::optimize_index(uint16_t* vin_index_inout)
		{
			uint8_t prev_key_image[32];
			if (vin_index_inout && *vin_index_inout < vin.size())
				memcpy(prev_key_image, vin[*vin_index_inout].key_image, 32);

			std::sort(vin.begin(), vin.end(), [](const txin_to_key& a, const txin_to_key& b) { return std::memcmp(a.key_image, b.key_image, 32) > 0; });
			if (!vin_index_inout || *vin_index_inout >= vin.size())
				return;

			for (uint16_t i = 0; i < vin.size(); i++)
			{
				if (!memcmp(prev_key_image, vin[i].key_image, 32))
				{
					*vin_index_inout = i;
					break;
				}
			}
		}
		bool ed25519_clsag_compositor::clsag_message::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer((uint16_t)vin.size());
			for (auto& utxo : vin)
			{
				stream->write_string(to_optimized_uint256(utxo.clsag.c1));
				stream->write_string(to_optimized_uint256(utxo.clsag.d));
				stream->write_integer((uint8_t)utxo.clsag.s.size());
				for (auto& s : utxo.clsag.s)
					stream->write_string(to_optimized_uint256(s.data()));
				stream->write_string(to_optimized_uint256(utxo.pseudo_out.mask));
				stream->write_string(to_optimized_uint256(utxo.pseudo_out.key));
				stream->write_string(to_optimized_uint256(utxo.prev_out.commitment_mask));
				stream->write_string(to_optimized_uint256(utxo.prev_out.derivation_scalar));
				stream->write_integer(utxo.prev_out.index);
				stream->write_integer((uint8_t)utxo.keys.size());
				for (auto& key_offset : utxo.keys)
				{
					stream->write_string(to_optimized_uint256(key_offset.key));
					stream->write_string(to_optimized_uint256(key_offset.mask));
					stream->write_integer(key_offset.index);
					stream->write_boolean(key_offset.decoy);
				}
				stream->write_string(to_optimized_uint256(utxo.key_image));
			}
			stream->write_integer((uint16_t)vout.size());
			for (auto& utxo : vout)
			{
				stream->write_integer(utxo.target.tag);
				stream->write_string(to_optimized_uint256(utxo.target.key));
				stream->write_string(to_optimized_uint256(utxo.ecdh_info.amount));
				stream->write_string(to_optimized_uint256(utxo.out_pk.blinding_factor));
				stream->write_string(to_optimized_uint256(utxo.out_pk.mask));
			}
			stream->write_string(std::string_view((char*)extra.data(), extra.size()));
			stream->write_string(to_optimized_uint256(bpp.a));
			stream->write_string(to_optimized_uint256(bpp.a1));
			stream->write_string(to_optimized_uint256(bpp.b));
			stream->write_string(to_optimized_uint256(bpp.r1));
			stream->write_string(to_optimized_uint256(bpp.s1));
			stream->write_string(to_optimized_uint256(bpp.d1));
			stream->write_integer((uint8_t)bpp.l.size());
			for (auto& l : bpp.l)
				stream->write_string(to_optimized_uint256(l.data()));
			stream->write_integer((uint8_t)bpp.r.size());
			for (auto& r : bpp.r)
				stream->write_string(to_optimized_uint256(r.data()));
			stream->write_string(to_optimized_uint256(tx_key));
			stream->write_integer(fee);
			return true;
		}
		bool ed25519_clsag_compositor::clsag_message::load_payload(format::ro_stream& stream)
		{
			string intermediate;
			auto read_string256 = [&](format::viewable type, uint8_t data[32]) -> bool
			{
				if (!stream.read_string(type, &intermediate) || intermediate.size() > 32)
					return false;

				memset(data, 0, 32);
				memcpy(data, intermediate.data(), intermediate.size());
				return true;
			};

			uint16_t vin_size;
			if (!stream.read_integer(stream.read_type(), &vin_size))
				return false;

			vin.clear();
			for (uint16_t i = 0; i < vin_size; i++)
			{
				clsag_message::txin_to_key utxo;
				if (!read_string256(stream.read_type(), utxo.clsag.c1))
					return false;

				if (!read_string256(stream.read_type(), utxo.clsag.d))
					return false;

				uint8_t s_size;
				if (!stream.read_integer(stream.read_type(), &s_size))
					return false;

				for (uint8_t j = 0; j < s_size; j++)
				{
					std::array<uint8_t, 32> s;
					if (!read_string256(stream.read_type(), s.data()))
						return false;

					utxo.clsag.s.push_back(s);
				}

				if (!read_string256(stream.read_type(), utxo.pseudo_out.mask))
					return false;

				if (!read_string256(stream.read_type(), utxo.pseudo_out.key))
					return false;

				if (!read_string256(stream.read_type(), utxo.prev_out.commitment_mask))
					return false;

				if (!read_string256(stream.read_type(), utxo.prev_out.derivation_scalar))
					return false;

				if (!stream.read_integer(stream.read_type(), &utxo.prev_out.index))
					return false;

				uint8_t key_offsets_size;
				if (!stream.read_integer(stream.read_type(), &key_offsets_size))
					return false;

				for (uint8_t j = 0; j < key_offsets_size; j++)
				{
					txin_to_key::ref ref;
					if (!read_string256(stream.read_type(), ref.key))
						return false;

					if (!read_string256(stream.read_type(), ref.mask))
						return false;

					if (!stream.read_integer(stream.read_type(), &ref.index))
						return false;

					if (!stream.read_boolean(stream.read_type(), &ref.decoy))
						return false;

					utxo.keys.push_back(std::move(ref));
				}

				if (!read_string256(stream.read_type(), utxo.key_image))
					return false;

				vin.push_back(std::move(utxo));
			}

			uint16_t vout_size;
			if (!stream.read_integer(stream.read_type(), &vout_size))
				return false;

			vout.clear();
			for (uint16_t i = 0; i < vout_size; i++)
			{
				clsag_message::tx_out utxo;
				if (!stream.read_integer(stream.read_type(), &utxo.target.tag))
					return false;

				if (!read_string256(stream.read_type(), utxo.target.key))
					return false;

				if (!read_string256(stream.read_type(), utxo.ecdh_info.amount))
					return false;

				if (!read_string256(stream.read_type(), utxo.out_pk.blinding_factor))
					return false;

				if (!read_string256(stream.read_type(), utxo.out_pk.mask))
					return false;

				vout.push_back(std::move(utxo));
			}

			if (!stream.read_string(stream.read_type(), &intermediate))
				return false;

			extra.clear();
			extra.insert(extra.end(), (uint8_t*)intermediate.data(), (uint8_t*)intermediate.data() + intermediate.size());
			if (!read_string256(stream.read_type(), bpp.a))
				return false;

			if (!read_string256(stream.read_type(), bpp.a1))
				return false;

			if (!read_string256(stream.read_type(), bpp.b))
				return false;

			if (!read_string256(stream.read_type(), bpp.r1))
				return false;

			if (!read_string256(stream.read_type(), bpp.s1))
				return false;

			if (!read_string256(stream.read_type(), bpp.d1))
				return false;

			uint8_t bpp_l_size;
			if (!stream.read_integer(stream.read_type(), &bpp_l_size))
				return false;

			bpp.l.clear();
			for (uint8_t i = 0; i < bpp_l_size; i++)
			{
				std::array<uint8_t, 32> l;
				if (!read_string256(stream.read_type(), l.data()))
					return false;

				bpp.l.push_back(l);
			}

			uint8_t bpp_r_size;
			if (!stream.read_integer(stream.read_type(), &bpp_r_size))
				return false;

			bpp.r.clear();
			for (uint8_t i = 0; i < bpp_r_size; i++)
			{
				std::array<uint8_t, 32> r;
				if (!read_string256(stream.read_type(), r.data()))
					return false;

				bpp.r.push_back(r);
			}

			if (!read_string256(stream.read_type(), tx_key))
				return false;

			if (!stream.read_integer(stream.read_type(), &fee))
				return false;

			return true;
		}
		void ed25519_clsag_compositor::clsag_message::write_prefix(vector<uint8_t>& buffer, bool no_key_image) const
		{
			write_varint(0x2, buffer); // version: v2
			write_varint(0x0, buffer); // unlock_time: instant (zero)		
			write_varint(vin.size(), buffer); // vin.size
			for (const auto& in : vin) // vin
			{
				buffer.push_back(0x2); // vin[i].tag: txin_to_key
				write_varint(0, buffer); // vin[i].amount: legacy (zero)
				write_varint(in.keys.size(), buffer); // vin[i].key_offsets.size
				for (auto& offset : in.keys)
					write_varint(offset.index, buffer); // vin[i].key_offsets[j]: index
				if (!no_key_image)
					buffer.insert(buffer.end(), in.key_image, in.key_image + 32); // vin[i].key_image: 32 bytes
			}
			write_varint(vout.size(), buffer); // vout.size
			for (const auto& out : vout) // vout
			{
				write_varint(0, buffer); // vout[i].amount: legacy (zero)
				buffer.push_back(0x3); // vout[i].target.tag: txout_to_tagged_key
				buffer.insert(buffer.end(), out.target.key, out.target.key + 32); // vout[i].target.key: 32 bytes
				buffer.push_back(out.target.tag); // vout[i].target.view_tag: 1 byte
			}
			write_varint(extra.size(), buffer); // extra field size
			buffer.insert(buffer.end(), extra.begin(), extra.end()); // extra field data
		}
		void ed25519_clsag_compositor::clsag_message::write_rctsig_base(vector<uint8_t>& buffer) const
		{
			buffer.push_back(0x6); // rct_signatures.type: RCTTypeBulletproofPlus 
			write_varint(fee, buffer); // rct_signatures.txn_fee: fee to be paid
			for (auto& proof : vout) // rct_signatures.ecdh_info (based on vout.size)
				buffer.insert(buffer.end(), proof.ecdh_info.amount, proof.ecdh_info.amount + 8); // rct_signatures.ecdh_info[i].amount: 8 bytes	
			for (auto& proof : vout) // rct_signatures.out_pk (based on vout.size)
				buffer.insert(buffer.end(), proof.out_pk.mask, proof.out_pk.mask + 32); // rct_signatures.out_pk[i].mask: 32 bytes
		}
		void ed25519_clsag_compositor::clsag_message::write_rctsig_prunable(vector<uint8_t>& buffer, bool no_clsag, bool no_pseudo_size) const
		{
			if (!no_pseudo_size)
				write_varint(1, buffer); // rct_signatures.p.bulletproofs_plus.size: one aggregated proof
			buffer.insert(buffer.end(), bpp.a, bpp.a + 32); // rct_signatures.p.bulletproofs_plus[0].a: 32 bytes
			buffer.insert(buffer.end(), bpp.a1, bpp.a1 + 32); // rct_signatures.p.bulletproofs_plus[0].a1: 32 bytes
			buffer.insert(buffer.end(), bpp.b, bpp.b + 32); // rct_signatures.p.bulletproofs_plus[0].b: 32 bytes
			buffer.insert(buffer.end(), bpp.r1, bpp.r1 + 32); // rct_signatures.p.bulletproofs_plus[0].r1: 32 bytes
			buffer.insert(buffer.end(), bpp.s1, bpp.s1 + 32); // rct_signatures.p.bulletproofs_plus[0].s1: 32 bytes
			buffer.insert(buffer.end(), bpp.d1, bpp.d1 + 32); // rct_signatures.p.bulletproofs_plus[0].d1: 32 bytes
			if (!no_pseudo_size)
				write_varint(bpp.l.size(), buffer); // rct_signatures.p.bulletproofs_plus[0].l.size
			for (const auto& l : bpp.l)
				buffer.insert(buffer.end(), l.data(), l.data() + 32); // rct_signatures.p.bulletproofs_plus[0].l[j]: 32 bytes
			if (!no_pseudo_size)
				write_varint(bpp.r.size(), buffer); // rct_signatures.p.bulletproofs_plus[0].r.size
			for (const auto& r : bpp.r)
				buffer.insert(buffer.end(), r.data(), r.data() + 32); // rct_signatures.p.bulletproofs_plus[0].r[j]: 32 bytes
			if (!no_clsag)
			{
				for (const auto& proof : vin) // rct_signatures.clsags (based on vin.size)
				{
					for (const auto& s : proof.clsag.s) // rct_signatures.clsags[i].s (based on vin[0].key_offsets.size)
						buffer.insert(buffer.end(), s.data(), s.data() + 32); // rct_signatures.clsags[i].s[j]: 32 bytes
					buffer.insert(buffer.end(), proof.clsag.c1, proof.clsag.c1 + 32); // rct_signatures.clsags[i].c1: 32 bytes
					buffer.insert(buffer.end(), proof.clsag.d, proof.clsag.d + 32); // rct_signatures.clsags[i].d: 32 bytes
				}
			}
			if (!no_pseudo_size)
			{
				for (const auto& proof : vin) // rct_signatures.pseudo_outs (based on vin.size)
					buffer.insert(buffer.end(), proof.pseudo_out.key, proof.pseudo_out.key + 32); // rct_signatures.pseudo_outs[i]: 32 bytes
			}
		}
		void ed25519_clsag_compositor::clsag_message::write_all(vector<uint8_t>& buffer, bool no_clsag, bool no_pseudo_size) const
		{
			write_prefix(buffer);
			write_rctsig_base(buffer);
			write_rctsig_prunable(buffer, no_clsag, no_pseudo_size);
		}
		void ed25519_clsag_compositor::clsag_message::as_prefix_hash(uint8_t prefix_hash[32]) const
		{
			vector<uint8_t> prefix;
			write_prefix(prefix);
			xmr_fast_hash(prefix_hash, prefix.data(), prefix.size());
		}
		void ed25519_clsag_compositor::clsag_message::as_rctsig_base_hash(uint8_t rctsig_base_hash[32]) const
		{
			vector<uint8_t> rctsig_base;
			write_rctsig_base(rctsig_base);
			xmr_fast_hash(rctsig_base_hash, rctsig_base.data(), rctsig_base.size());
		}
		void ed25519_clsag_compositor::clsag_message::as_rctsig_prunable_hash(uint8_t rctsig_prunable_hash[32]) const
		{
			vector<uint8_t> rctsig_prunable;
			write_rctsig_prunable(rctsig_prunable, true, true);
			xmr_fast_hash(rctsig_prunable_hash, rctsig_prunable.data(), rctsig_prunable.size());
		}
		void ed25519_clsag_compositor::clsag_message::as_id_hash(uint8_t id_hash[32], bool no_clsag, bool no_pseudo_size, bool no_key_image) const
		{
			vector<uint8_t> prefix, rctsig_base, rctsig_prunable;
			write_prefix(prefix, no_key_image);
			write_rctsig_base(rctsig_base);
			write_rctsig_prunable(rctsig_prunable, no_clsag, no_pseudo_size);

			uint8_t prefix_hash[32], rctsig_base_hash[32], rctsig_prunable_hash[32];
			xmr_fast_hash(prefix_hash, prefix.data(), prefix.size());
			xmr_fast_hash(rctsig_base_hash, rctsig_base.data(), rctsig_base.size());
			xmr_fast_hash(rctsig_prunable_hash, rctsig_prunable.data(), rctsig_prunable.size());

			uint8_t id[96];
			memcpy(id + 00, prefix_hash, 32);
			memcpy(id + 32, rctsig_base_hash, 32);
			memcpy(id + 64, rctsig_prunable_hash, 32);
			xmr_fast_hash(id_hash, id, sizeof(id));
		}
		format::tree ed25519_clsag_compositor::clsag_message::as_tree() const
		{
			format::tree data;
			auto* vin_data = data.set("vin", format::tree::list());
			for (auto& utxo : vin)
			{
				auto* utxo_data = vin_data->push(format::tree::map());
				auto* clsag_data = utxo_data->set("clsag", format::tree::map());
				clsag_data->set("c1", format::variable(format::util::encode_0xhex(std::string_view((char*)utxo.clsag.c1, sizeof(utxo.clsag.c1)))));
				clsag_data->set("d", format::variable(format::util::encode_0xhex(std::string_view((char*)utxo.clsag.d, sizeof(utxo.clsag.d)))));
				auto* clsag_s_data = clsag_data->set("s", format::tree::list());
				for (auto& s : utxo.clsag.s)
					clsag_s_data->push(format::variable(format::util::encode_0xhex(std::string_view((char*)s.data(), s.size()))));
				auto* pseudo_out_data = utxo_data->set("pseudo_out", format::tree::map());
				pseudo_out_data->set("mask", format::variable(format::util::encode_0xhex(std::string_view((char*)utxo.pseudo_out.mask, sizeof(utxo.pseudo_out.mask)))));
				pseudo_out_data->set("key", format::variable(format::util::encode_0xhex(std::string_view((char*)utxo.pseudo_out.key, sizeof(utxo.pseudo_out.key)))));
				auto* prev_out_data = utxo_data->set("prev_out", format::tree::map());
				prev_out_data->set("commitment_mask", format::variable(format::util::encode_0xhex(std::string_view((char*)utxo.prev_out.commitment_mask, sizeof(utxo.prev_out.commitment_mask)))));
				prev_out_data->set("derivation_scalar", format::variable(format::util::encode_0xhex(std::string_view((char*)utxo.prev_out.derivation_scalar, sizeof(utxo.prev_out.derivation_scalar)))));
				prev_out_data->set("index", format::variable(utxo.prev_out.index));
				auto* keys_data = utxo_data->set("keys", format::tree::list());
				for (auto& key : utxo.keys)
				{
					auto* key_data = keys_data->push(format::tree::map());
					key_data->set("key", format::variable(format::util::encode_0xhex(std::string_view((char*)key.key, sizeof(key.key)))));
					key_data->set("mask", format::variable(format::util::encode_0xhex(std::string_view((char*)key.mask, sizeof(key.mask)))));
					key_data->set("index", format::variable(key.index));
					key_data->set("decoy", format::variable(key.decoy));
				}
				utxo_data->set("key_image", format::variable(format::util::encode_0xhex(std::string_view((char*)utxo.key_image, sizeof(utxo.key_image)))));
			}
			auto* vout_data = data.set("vout", format::tree::list());
			for (auto& utxo : vout)
			{
				auto* utxo_data = vout_data->push(format::tree::map());
				auto* target_data = utxo_data->set("target", format::tree::map());
				target_data->set("key", format::variable(format::util::encode_0xhex(std::string_view((char*)utxo.target.key, sizeof(utxo.target.key)))));
				target_data->set("tag", format::variable(utxo.target.tag));
				utxo_data->set("ecdh_info", format::tree::map())->set("amount", format::variable(format::util::encode_0xhex(std::string_view((char*)utxo.ecdh_info.amount, sizeof(utxo.ecdh_info.amount)))));
				auto* out_pk_data = utxo_data->set("out_pk", format::tree::map());
				out_pk_data->set("blinding_factor", format::variable(format::util::encode_0xhex(std::string_view((char*)utxo.out_pk.blinding_factor, sizeof(utxo.out_pk.blinding_factor)))));
				out_pk_data->set("mask", format::variable(format::util::encode_0xhex(std::string_view((char*)utxo.out_pk.mask, sizeof(utxo.out_pk.mask)))));
			}
			data.set("extra", format::variable(format::util::encode_0xhex(std::string_view((char*)extra.data(), extra.size()))));
			auto* bpp_data = data.set("bpp", format::tree::map());
			bpp_data->set("a", format::variable(format::util::encode_0xhex(std::string_view((char*)bpp.a, sizeof(bpp.a)))));
			bpp_data->set("a1", format::variable(format::util::encode_0xhex(std::string_view((char*)bpp.a1, sizeof(bpp.a1)))));
			bpp_data->set("b", format::variable(format::util::encode_0xhex(std::string_view((char*)bpp.b, sizeof(bpp.b)))));
			bpp_data->set("r1", format::variable(format::util::encode_0xhex(std::string_view((char*)bpp.r1, sizeof(bpp.r1)))));
			bpp_data->set("s1", format::variable(format::util::encode_0xhex(std::string_view((char*)bpp.s1, sizeof(bpp.s1)))));
			bpp_data->set("d1", format::variable(format::util::encode_0xhex(std::string_view((char*)bpp.d1, sizeof(bpp.d1)))));
			auto* bpp_l_data = bpp_data->set("l", format::tree::list());
			for (auto& l : bpp.l)
				bpp_l_data->push(format::variable(format::util::encode_0xhex(std::string_view((char*)l.data(), l.size()))));
			auto* bpp_r_data = bpp_data->set("r", format::tree::list());
			for (auto& r : bpp.r)
				bpp_r_data->push(format::variable(format::util::encode_0xhex(std::string_view((char*)r.data(), r.size()))));
			auto* tx_data = data.set("tx", format::tree::map());
			tx_data->set("tx_key", format::variable(format::util::encode_0xhex(std::string_view((char*)tx_key, sizeof(tx_key)))));
			data.set("fee", format::variable(fee));
			return data;
		}
		uint32_t ed25519_clsag_compositor::clsag_message::as_type() const
		{
			return as_instance_type();
		}
		std::string_view ed25519_clsag_compositor::clsag_message::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t ed25519_clsag_compositor::clsag_message::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view ed25519_clsag_compositor::clsag_message::as_instance_typename()
		{
			return "clsag_message";
		}

		expects_lr<void> ed25519_clsag_compositor::setup_public_key(const uint8_t* new_message, size_t new_message_size, uint16_t new_participants)
		{
			return setup_signature(algorithm::composition::cpubkey_t(), new_message, new_message_size, nullptr, new_participants);
		}
		expects_lr<void> ed25519_clsag_compositor::setup_signature(const algorithm::composition::cpubkey_t& public_key, const uint8_t* new_message, size_t new_message_size, const algorithm::composition::shared_message* new_shared, uint16_t new_participants)
		{
			VI_ASSERT(new_message != nullptr, "message should be set");
			if (!public_key.empty() && public_key.size() != sizeof(ed25519_point_t) && public_key.size() != 2 * sizeof(ed25519_point_t) + 1)
				return layer_exception("invalid public key size");
			
			if (new_shared != nullptr)
			{
				if (new_message_size != sizeof(vin_index))
					return layer_exception("invalid input message");

				memcpy(&vin_index, new_message, sizeof(vin_index));
				format::ro_stream stream = format::ro_stream(std::string_view((char*)new_shared->message.data(), new_shared->message.size()));
				if (!message.load(stream))
					return layer_exception("invalid shared message");

				size_t key_inputs_size = std::min(new_shared->keys.size(), message.vin.size());
				for (size_t i = 0; i < key_inputs_size; i++)
				{
					auto& vin = message.vin[i];
					auto& key_image = new_shared->keys[i];
					if (key_image.size() != sizeof(vin.key_image))
						return layer_exception("invalid key input size");

					memcpy(vin.key_image, key_image.data(), key_image.size());
				}

				i_steps = new_shared->keys.empty() || new_shared->keys.size() < message.vin.size() ? new_participants : 0;
				a_steps = s_steps = i_steps > 0 ? 0 : new_participants;
				if (!i_steps)
				{
					message.optimize_index(&vin_index);
					cumulative_I.clear();
				}
			}
			else
			{
				if (new_message_size != sizeof(ed25519_point_t))
					return layer_exception("invalid input message");

				derive_pseudo_message(new_message, new_message_size, message, vin_index);
				i_steps = a_steps = s_steps = new_participants;
			}

			if (public_key.size() == 2 * sizeof(ed25519_point_t) + 1)
			{
				if (!kernel::params().is(network_type::regtest))
					return layer_exception("invalid public key size");

				z_steps = new_participants;
				cumulative_key.clear();
			}
			else
			{
				z_steps = public_key.empty() ? new_participants : 0;
				cumulative_key = public_key;
			}

			participants = new_participants;
			return expectation::met;
		}
		expects_lr<void> ed25519_clsag_compositor::aggregate(const algorithm::composition::cseckey_t& secret_key)
		{
			if (secret_key.size() != sizeof(ed25519_scalar_t))
				return layer_exception("invalid secret key size");

			if (vin_index >= message.vin.size())
				return layer_exception("invalid vin index");

			auto& vin = message.vin[vin_index];
			auto ring_member = std::find_if(vin.keys.begin(), vin.keys.end(), [](const clsag_message::txin_to_key::ref& r) { return !r.decoy; });
			auto key_index = ring_member == vin.keys.end() ? std::numeric_limits<size_t>::max() : std::distance(vin.keys.begin(), ring_member);
			if (key_index == std::numeric_limits<size_t>::max())
				return layer_exception("invalid vin key index");

			auto use_nonce = [&](const clsag_message::txin_to_key& vin, uint8_t a_i[32])
			{
				uint8_t seed_buffer[128], message_hash[32], ask[32];
				message.as_prefix_hash(seed_buffer);
				memcpy(seed_buffer + sizeof(vin.key_image) * 1, vin.key_image, sizeof(vin.key_image));
				memcpy(seed_buffer + sizeof(vin.key_image) * 2, secret_key.data(), sizeof(vin.key_image));
				memcpy(seed_buffer + sizeof(vin.key_image) * 3, vin.pseudo_out.mask, sizeof(vin.pseudo_out.mask));
				xmr_fast_hash(message_hash, seed_buffer, sizeof(seed_buffer));
				sha256_Raw(secret_key.data(), secret_key.size(), ask);

				uint256_t index = 0;
				while (true)
				{
					uint8_t index_nonce[32];
					index.encode(index_nonce);
					++index;

					uint8_t nonce[32];
					if (secp256k1_nonce_function_rfc6979(nonce, message_hash, ask, nullptr, index_nonce, 0) != 1)
						continue;

					hash_to_scalar(nonce, sizeof(nonce), a_i);
					if (sc_valid(a_i) != 0)
						break;
				}
			};
			if (z_steps > 0)
			{
				uint8_t secret_key_buffer[64] = { 0 }, public_key[32] = { 0 };
				memcpy(secret_key_buffer, secret_key.data(), secret_key.size());
				ed25519_publickey_ext(secret_key_buffer, public_key);
				if (cumulative_key.empty())
					memcpy(cumulative_key.blob, public_key, sizeof(public_key));
				else if (crypto_core_ed25519_add(cumulative_key.blob, public_key, cumulative_key.blob) != 0)
					return layer_exception("invalid key derivation");

				if (!--z_steps)
				{
					uint8_t dsG[32];
					sc_mul_g(dsG, vin.prev_out.derivation_scalar);
					if (ge_add_w(ring_member->key, dsG, cumulative_key.blob) != 0)
						return layer_exception("invalid pG derivation");
				}
			}
			else if (i_steps > 0)
			{
				uint8_t I_i[32], H[32];
				hash_to_point(ring_member->key, sizeof(ring_member->key), H);
				if (ge_scalarmult_s(I_i, H, secret_key.data()) != 0)
					return layer_exception("invalid I derivation");

				if (cumulative_I.empty())
					memcpy(cumulative_I.blob, I_i, sizeof(I_i));
				else if (crypto_core_ed25519_add(cumulative_I.blob, I_i, cumulative_I.blob) != 0)
					return layer_exception("invalid I derivation");

				if (!--i_steps)
				{
					uint8_t dsH[32];
					ge_scalarmult_s(dsH, H, vin.prev_out.derivation_scalar);
					if (ge_add_w(cumulative_I.blob, dsH, cumulative_I.blob) != 0)
						return layer_exception("invalid I derivation");
				}
			}
			else if (a_steps > 0)
			{
				if (cumulative_I.empty())
				{
					memcpy(cumulative_I.blob, vin.key_image, sizeof(vin.key_image));
					if (cumulative_I.empty())
						return layer_exception("invalid I derivation");
				}
				else if (sc_isnonzero(vin.key_image) == 0)
					memcpy(vin.key_image, cumulative_I.blob, sizeof(cumulative_I.blob));
				else if (memcmp(cumulative_I.blob, vin.key_image, sizeof(vin.key_image)) != 0)
					return layer_exception("invalid I derivation");

				uint8_t H[32], a_i[32], aH_i[32];
				hash_to_point(ring_member->key, sizeof(ring_member->key), H);
				use_nonce(vin, a_i);
				if (ge_scalarmult_s(aH_i, H, a_i) != 0)
					return layer_exception("invalid aH derivation");

				uint8_t aG_i[32];
				sc_mul_g(aG_i, a_i);
				if (cumulative_aG.empty() || cumulative_aH.empty())
				{
					memcpy(cumulative_aG.blob, aG_i, sizeof(aG_i));
					memcpy(cumulative_aH.blob, aH_i, sizeof(aH_i));
				}
				else if (crypto_core_ed25519_add(cumulative_aG.blob, aG_i, cumulative_aG.blob) != 0 || crypto_core_ed25519_add(cumulative_aH.blob, aH_i, cumulative_aH.blob) != 0)
					return layer_exception("invalid aG, aH or I derivation");

				if (!--a_steps)
				{
					uint8_t z[32], D[32];
					sc_sub(z, vin.prev_out.commitment_mask, vin.pseudo_out.mask);
					if (ge_scalarmult_s(D, H, z) != 0)
						return layer_exception("invalid D derivation");
					else if (sc_valid(z) == 0 && sc_isnonzero(z) != 0)
						return layer_exception("invalid z derivation");

					ge_p3 I_3, D_3;
					if (ge_frombytes_vartime(&I_3, cumulative_I.blob) != 0 || ge_frombytes_vartime(&D_3, D) != 0)
						return layer_exception("invalid I or D derivation");

					ge_dsmp I_precomp, D_precomp;
					ge_dsm_precomp(I_precomp, &I_3);
					ge_dsm_precomp(D_precomp, &D_3);
					if (ge_scalarmult_i8(vin.clsag.d, D) != 0)
						return layer_exception("invalid D derivation");

					auto n = vin.keys.size();
					const unsigned char HASH_KEY_CLSAG_AGG_0[] = "CLSAG_agg_0";
					const unsigned char HASH_KEY_CLSAG_AGG_1[] = "CLSAG_agg_1";
					vector<std::array<uint8_t, 32>> mu_P_to_hash(2 * n + 4);
					vector<std::array<uint8_t, 32>> mu_C_to_hash(2 * n + 4);
					sc_0(mu_P_to_hash[0].data());
					sc_0(mu_C_to_hash[0].data());
					memcpy(mu_P_to_hash[0].data(), HASH_KEY_CLSAG_AGG_0, sizeof(HASH_KEY_CLSAG_AGG_0) - 1);
					memcpy(mu_C_to_hash[0].data(), HASH_KEY_CLSAG_AGG_1, sizeof(HASH_KEY_CLSAG_AGG_1) - 1);
					for (size_t i = 1; i < n + 1; ++i)
					{
						auto& member = vin.keys[i - 1];
						memcpy(mu_P_to_hash[i].data(), member.key, sizeof(member.key));
						memcpy(mu_C_to_hash[i].data(), member.key, sizeof(member.key));
					}
					for (size_t i = n + 1; i < 2 * n + 1; ++i)
					{
						auto& member = vin.keys[i - n - 1];
						memcpy(mu_P_to_hash[i].data(), member.mask, sizeof(member.mask));
						memcpy(mu_C_to_hash[i].data(), member.mask, sizeof(member.mask));
					}
					memcpy(mu_P_to_hash[2 * n + 1].data(), cumulative_I.blob, sizeof(cumulative_I.blob));
					memcpy(mu_P_to_hash[2 * n + 2].data(), vin.clsag.d, sizeof(vin.clsag.d));
					memcpy(mu_P_to_hash[2 * n + 3].data(), vin.pseudo_out.key, sizeof(vin.pseudo_out.key));
					memcpy(mu_C_to_hash[2 * n + 1].data(), cumulative_I.blob, sizeof(cumulative_I.blob));
					memcpy(mu_C_to_hash[2 * n + 2].data(), vin.clsag.d, sizeof(vin.clsag.d));
					memcpy(mu_C_to_hash[2 * n + 3].data(), vin.pseudo_out.key, sizeof(vin.pseudo_out.key));

					uint8_t mu_P[32], mu_C[32];
					vector<uint8_t> mu_P_to_hash8, mu_C_to_hash8;
					vector32_to_vector8(mu_P_to_hash, mu_P_to_hash8);
					vector32_to_vector8(mu_C_to_hash, mu_C_to_hash8);
					hash_to_scalar(mu_P_to_hash8.data(), mu_P_to_hash8.size(), mu_P);
					hash_to_scalar(mu_C_to_hash8.data(), mu_C_to_hash8.size(), mu_C);
					if (sc_valid(mu_P) == 0 || sc_valid(mu_C) == 0)
						return layer_exception("invalid mu_P or mu_C derivation");

					uint8_t mlsag_prehash_to_hash[96], mlsag_prehash[32];
					message.as_prefix_hash(mlsag_prehash_to_hash);
					message.as_rctsig_base_hash(mlsag_prehash_to_hash + 32);
					message.as_rctsig_prunable_hash(mlsag_prehash_to_hash + 64);
					xmr_fast_hash(mlsag_prehash, mlsag_prehash_to_hash, sizeof(mlsag_prehash_to_hash));

					const unsigned char HASH_KEY_CLSAG_ROUND[] = "CLSAG_round";
					vector<std::array<uint8_t, 32>> c_to_hash(2 * n + 5);
					sc_0(c_to_hash[0].data());
					memcpy(c_to_hash[0].data(), HASH_KEY_CLSAG_ROUND, sizeof(HASH_KEY_CLSAG_ROUND) - 1);
					for (size_t i = 1; i < n + 1; ++i)
					{
						auto& member = vin.keys[i - 1];
						memcpy(c_to_hash[i].data(), member.key, sizeof(member.key));
						memcpy(c_to_hash[i + n].data(), member.mask, sizeof(member.mask));
					}
					memcpy(c_to_hash[2 * n + 1].data(), vin.pseudo_out.key, sizeof(vin.pseudo_out.key));
					memcpy(c_to_hash[2 * n + 2].data(), mlsag_prehash, sizeof(mlsag_prehash));
					memcpy(c_to_hash[2 * n + 3].data(), cumulative_aG.blob, sizeof(cumulative_aG.blob));
					memcpy(c_to_hash[2 * n + 4].data(), cumulative_aH.blob, sizeof(cumulative_aH.blob));

					vector<uint8_t> c_to_hash8; uint8_t c[32];
					vector32_to_vector8(c_to_hash, c_to_hash8);
					hash_to_scalar(c_to_hash8.data(), c_to_hash8.size(), c);
					if (sc_valid(c) == 0)
						return layer_exception("invalid c derivation");

					size_t i = (key_index + 1) % n;
					if (i == 0)
						memcpy(vin.clsag.c1, c, sizeof(c));

					uint8_t base_hash[32];
					message.as_hash(true).encode(base_hash);
					vin.clsag.s.resize(n);
					while (i != key_index)
					{
						uint8_t seed[138] = { 0 };
						memcpy(seed + 00, mlsag_prehash, sizeof(mlsag_prehash));
						memcpy(seed + 32, base_hash, sizeof(base_hash));
						memcpy(seed + 64, c, sizeof(c));
						memcpy(seed + 96, secret_key.data(), secret_key.size());
						write_varint_fixed(i, seed + 128);

						auto& s_i = vin.clsag.s[i];
						hash_to_scalar(seed, sizeof(seed), s_i.data());
						if (sc_valid(s_i.data()) == 0)
							return layer_exception("invalid s(i) derivation");

						uint8_t c_i[32], c_p[32], c_c[32];
						sc_mul(c_p, mu_P, c);
						sc_mul(c_c, mu_C, c);
						sc_0(c_i);

						uint8_t C_i[32]; auto& member = vin.keys[i];
						if (ge_sub_w(C_i, member.mask, vin.pseudo_out.key) != 0)
							return layer_exception("invalid C(i) derivation");

						ge_p3 P_3, C_3, H_3; uint8_t H_i[32];
						hash_to_point(member.key, sizeof(member.key), H_i);
						if (ge_frombytes_vartime(&P_3, member.key) != 0 || ge_frombytes_vartime(&C_3, C_i) != 0 || ge_frombytes_vartime(&H_3, H_i) != 0)
							return layer_exception("invalid P, C or H derivation");

						ge_dsmp P_precomp, C_precomp, H_precomp;
						ge_dsm_precomp(P_precomp, &P_3);
						ge_dsm_precomp(C_precomp, &C_3);
						ge_dsm_precomp(H_precomp, &H_3);

						uint8_t L[32], R[32];
						ge_addKeys_aGbBcC(L, s_i.data(), c_p, P_precomp, c_c, C_precomp);
						ge_addKeys_aAbBcC(R, s_i.data(), H_precomp, c_p, I_precomp, c_c, D_precomp);
						memcpy(c_to_hash[2 * n + 3].data(), L, sizeof(L));
						memcpy(c_to_hash[2 * n + 4].data(), R, sizeof(R));
						vector32_to_vector8(c_to_hash, c_to_hash8);
						hash_to_scalar(c_to_hash8.data(), c_to_hash8.size(), c_i);
						memcpy(c, c_i, sizeof(c_i));
						if (sc_valid(c) == 0)
							return layer_exception("invalid c(i) derivation");

						i = (i + 1) % n;
						if (i == 0)
							memcpy(vin.clsag.c1, c, sizeof(c));
					}

					auto& s_i = vin.clsag.s[key_index];
					uint8_t s[32], mu_P_ds[32], mu_C_z[32];
					sc_mul(mu_P_ds, mu_P, vin.prev_out.derivation_scalar);
					sc_mul(mu_C_z, mu_C, z);
					sc_add(s, mu_P_ds, mu_C_z);
					sc_mul(s, s, c);
					sc_negate(s_i.data(), s);
					sc_mul(cumulative_c_mu_P.blob, mu_P, c);
					if (sc_valid(s_i.data()) == 0 || sc_valid(cumulative_c_mu_P.blob) == 0)
						return layer_exception("invalid s(i) derivation");
				}
			}
			else if (s_steps > 0)
			{
				if (key_index >= vin.clsag.s.size() || vin.clsag.s.size() != vin.keys.size())
					return layer_exception("invalid s derivation");

				auto& s_i = vin.clsag.s[key_index];
				uint8_t a_i[32], a_c_mu_P_x[32];
				use_nonce(vin, a_i);
				sc_mulsub(a_c_mu_P_x, cumulative_c_mu_P.blob, secret_key.data(), a_i);
				sc_add(s_i.data(), s_i.data(), a_c_mu_P_x);
				--s_steps;
			}
			return expectation::met;
		}
		expects_lr<void> ed25519_clsag_compositor::derive_tweaking_key(const uint8_t* seed, size_t seed_size, size_t key_size, algorithm::paillier_scalar_t* public_key) const
		{
			paillier_to_public_key(seed, seed_size, key_size, public_key);
			return expectation::met;
		}
		expects_lr<void> ed25519_clsag_compositor::tweak_secret_key(const algorithm::paillier_scalar_t& public_key, size_t key_size, const algorithm::composition::cseckey_t& tweak, algorithm::composition::cseckey_t* secret_key_input_output, algorithm::paillier_scalar_t* accumulator_output) const
		{
			if (accumulator_output != nullptr)
			{
				auto status = paillier_accumulate_tweak(public_key, tweak, accumulator_output, key_size, true);
				if (!status)
					return status;
			}

			if (secret_key_input_output != nullptr)
				return ed25519_combine_secret_key(&tweak, secret_key_input_output);

			return expectation::met;
		}
		expects_lr<void> ed25519_clsag_compositor::tweak_secret_key(const uint8_t* seed, size_t seed_size, size_t key_size, const algorithm::paillier_scalar_t& accumulator, algorithm::composition::cseckey_t* secret_key_input_output) const
		{
			return ed25519_accumulator_tweak_secret_key(seed, seed_size, key_size, accumulator, secret_key_input_output);
		}
		expects_lr<void> ed25519_clsag_compositor::combine_public_keys(const algorithm::composition::cpubkey_t* input, algorithm::composition::cpubkey_t* input_output) const
		{
			return ed25519_combine_public_key(input, input_output);
		}
		expects_lr<void> ed25519_clsag_compositor::derive_secret_key(const uint8_t* seed, size_t seed_size, algorithm::composition::cseckey_t* output) const
		{
			VI_ASSERT(output != nullptr, "output should be set");
			output->resize(sizeof(ed25519_scalar_t));
			ed25519_to_private_key(seed, seed_size, output->data());
			return expectation::met;
		}
		expects_lr<void> ed25519_clsag_compositor::derive_public_key(algorithm::composition::cpubkey_t* output) const
		{
			VI_ASSERT(output != nullptr, "output should be set");
			output->resize(sizeof(cumulative_key));
			memcpy(output->data(), cumulative_key.blob, sizeof(cumulative_key));
			return expectation::met;
		}
		expects_lr<void> ed25519_clsag_compositor::derive_signature(algorithm::composition::chashsig_t* output) const
		{
			VI_ASSERT(output != nullptr, "output should be set");
			if (vin_index >= message.vin.size())
				return layer_exception("invalid vin index");

			auto& vin = message.vin[vin_index];
			if (sc_isnonzero(vin.key_image) == 0)
			{
				if (cumulative_I.empty())
					return layer_exception("invalid I derivation");

				output->resize(sizeof(cumulative_I.blob));
				memcpy(output->data(), cumulative_I.blob, sizeof(cumulative_I.blob));
				return expectation::met;
			}

			if (vin.keys.size() != vin.clsag.s.size())
				return layer_exception("invalid s size");

			auto ring_member = std::find_if(vin.keys.begin(), vin.keys.end(), [](const clsag_message::txin_to_key::ref& r) { return !r.decoy; });
			if (ring_member == vin.keys.end())
				return layer_exception("invalid key index");

			size_t offset = sizeof(ring_member->key) + sizeof(vin.key_image) + sizeof(vin.clsag.c1) + sizeof(vin.clsag.d);
			output->resize(offset + sizeof(std::array<uint8_t, 32>) * vin.keys.size());
			memcpy(output->data(), ring_member->key, sizeof(ring_member->key));
			memcpy(output->data() + sizeof(ring_member->key), vin.key_image, sizeof(vin.key_image));
			memcpy(output->data() + sizeof(ring_member->key) + sizeof(vin.key_image), vin.clsag.c1, sizeof(vin.clsag.c1));
			memcpy(output->data() + sizeof(ring_member->key) + sizeof(vin.key_image) + sizeof(vin.clsag.c1), vin.clsag.d, sizeof(vin.clsag.d));
			for (size_t i = 0; i < vin.clsag.s.size(); i++)
				memcpy(output->data() + offset + sizeof(std::array<uint8_t, 32>) * i, vin.clsag.s[i].data(), vin.clsag.s[i].size());

			format::wo_stream signable;
			if (!message.store(&signable))
				return layer_exception("failed to store the message");

			return verify_signature((uint8_t*)signable.data.data(), signable.data.size(), *output, algorithm::composition::cpubkey_t());
		}
		expects_lr<void> ed25519_clsag_compositor::verify_signature(const uint8_t* new_message, size_t new_message_size, const algorithm::composition::chashsig_t& signature, const algorithm::composition::cpubkey_t& public_key, uint8_t flags) const
		{
			VI_ASSERT(new_message != nullptr, "message should be set");
			if (flags & (uint8_t)algorithm::composition::verify::user_message)
			{
				if (public_key.size() != sizeof(ed25519_point_t))
					return layer_exception("invalid public key");

				if (signature.size() != 64)
					return layer_exception("invalid signature");

				if (crypto_sign_verify_detached(signature.data(), new_message, new_message_size, public_key.data()) != 0)
					return layer_exception("signature verification failed");

				return expectation::met;
			}

			bool mockup_message = public_key.size() == 2 * sizeof(ed25519_point_t) + 1 && kernel::params().is(network_type::regtest);
			if (!public_key.empty() && public_key.size() != sizeof(ed25519_point_t) && !mockup_message)
				return layer_exception("invalid public key");

			bool tx_message_flag = (flags & (uint8_t)algorithm::composition::verify::tx_message) > 0;
			bool auth_message_flag = (flags & (uint8_t)algorithm::composition::verify::auth_message) > 0;
			bool tx_message = (tx_message_flag || new_message_size != sizeof(ed25519_point_t)) && !mockup_message;
			bool auth_message = (auth_message_flag || new_message_size == sizeof(ed25519_point_t) || mockup_message) && !tx_message;
			if (!tx_message_flag && !auth_message_flag)
			{
				if (vin_index < message.vin.size() && sc_isnonzero(message.vin[vin_index].key_image) == 0)
				{
					if (signature.size() != sizeof(ed25519_point_t) || signature.empty())
						return layer_exception("invalid key image");

					return expectation::met;
				}
			}
			
			if (!tx_message && !auth_message)
				return layer_exception("invalid verification flags");

			uint16_t pseudo_index = vin_index;
			clsag_message pseudo_message;
			if (auth_message)
			{
				derive_pseudo_message(new_message, new_message_size, pseudo_message, pseudo_index);
				if (pseudo_index >= pseudo_message.vin.size())
					return layer_exception("failed to derive the message");

				auto& vin = pseudo_message.vin[pseudo_index];
				size_t n = vin.keys.size();
				size_t offset = sizeof(vin.key_image) * 2 + sizeof(vin.clsag.c1) + sizeof(vin.clsag.d);
				size_t size = offset + sizeof(std::array<uint8_t, 32>) * n;
				if (signature.size() != size)
					return layer_exception("invalid signature size");

				auto ring_member = std::find_if(vin.keys.begin(), vin.keys.end(), [](const clsag_message::txin_to_key::ref& r) { return !r.decoy; });
				if (ring_member == vin.keys.end())
					return layer_exception("invalid key index");

				vin.clsag.s.resize(n);
				memcpy(ring_member->key, signature.data(), sizeof(ed25519_point_t));
				memcpy(vin.key_image, signature.data() + 32, sizeof(ed25519_point_t));
				memcpy(vin.clsag.c1, signature.data() + 64, sizeof(ed25519_point_t));
				memcpy(vin.clsag.d, signature.data() + 96, sizeof(ed25519_point_t));
				for (size_t i = 0; i < n; i++)
					memcpy(vin.clsag.s[i].data(), signature.data() + offset + i * sizeof(std::array<uint8_t, 32>), sizeof(ed25519_point_t));
			}
			else if (tx_message)
			{
				format::ro_stream signable = format::ro_stream(std::string_view((char*)new_message, new_message_size));
				if (!pseudo_message.load(signable) || pseudo_index >= pseudo_message.vin.size())
					return layer_exception("failed to load the message");

				auto& vin = pseudo_message.vin[pseudo_index];
				size_t n = vin.keys.size();
				size_t offset = sizeof(vin.key_image) * 2 + sizeof(vin.clsag.c1) + sizeof(vin.clsag.d);
				size_t size = offset + sizeof(std::array<uint8_t, 32>) * n;
				if (signature.size() != size)
					return layer_exception("invalid signature size");

				auto ring_member = std::find_if(vin.keys.begin(), vin.keys.end(), [](const clsag_message::txin_to_key::ref& r) { return !r.decoy; });
				if (ring_member == vin.keys.end())
					return layer_exception("invalid key index");
				else if (memcmp(ring_member->key, signature.data(), sizeof(ring_member->key)) != 0)
					return layer_exception("invalid key constant");

				uint8_t zero[32] = { 0 };
				bool postfill_signature = false;
				const uint8_t* sig_key_image = signature.data() + 32;
				const uint8_t* sig_c1 = signature.data() + 64;
				const uint8_t* sig_d = signature.data() + 96;
				if (memcmp(vin.key_image, sig_key_image, sizeof(vin.key_image)) != 0)
				{
					postfill_signature = true;
					if (memcmp(vin.key_image, zero, sizeof(zero)) != 0)
						return layer_exception("invalid key image constant");
				}
				else if (vin.clsag.s.size() != n)
				{
					postfill_signature = true;
					if (!vin.clsag.s.empty())
						return layer_exception("invalid signature size");
				}
				else if (memcmp(vin.clsag.c1, sig_c1, sizeof(vin.clsag.c1)) != 0 || sc_valid(vin.clsag.c1) == 0)
				{
					postfill_signature = true;
					if (memcmp(vin.clsag.c1, zero, sizeof(zero)) != 0)
						return layer_exception("invalid c1 constant");
				}
				else if (memcmp(vin.clsag.d, sig_d, sizeof(vin.clsag.d)) != 0)
				{
					postfill_signature = true;
					if (memcmp(vin.clsag.d, zero, sizeof(zero)) != 0)
						return layer_exception("invalid d constant");
				}

				if (postfill_signature || vin.clsag.s.size() != n)
				{
					vin.clsag.s.resize(n);
					memcpy(vin.key_image, sig_key_image, sizeof(vin.key_image));
					memcpy(vin.clsag.c1, sig_c1, sizeof(vin.clsag.c1));
					memcpy(vin.clsag.d, sig_d, sizeof(vin.clsag.d));
					for (size_t i = 0; i < n; i++)
						memcpy(vin.clsag.s[i].data(), signature.data() + offset + i * sizeof(std::array<uint8_t, 32>), sizeof(std::array<uint8_t, 32>));
				}
				else
				{
					for (size_t i = 0; i < n; i++)
					{
						if (memcmp(vin.clsag.s[i].data(), signature.data() + offset + i * sizeof(std::array<uint8_t, 32>), sizeof(std::array<uint8_t, 32>)) != 0 || sc_valid(vin.clsag.s[i].data()) == 0)
							return layer_exception("invalid s constant");
					}
				}
			}

			const auto& vin = pseudo_message.vin[pseudo_index]; ge_p3 I_3;
			if (ge_frombytes_vartime(&I_3, vin.key_image) != 0)
				return layer_exception("invalid key image constant");

			ge_dsmp I_precomp; uint8_t D[32];
			ge_dsm_precomp(I_precomp, &I_3);
			ge_scalarmult_8(D, vin.clsag.d);

			ge_p3 D_3;
			if (ge_frombytes_vartime(&D_3, D) != 0)
				return layer_exception("invalid d constant");

			ge_dsmp D_precomp;
			ge_dsm_precomp(D_precomp, &D_3);

			size_t n = vin.keys.size();
			const unsigned char HASH_KEY_CLSAG_AGG_0[] = "CLSAG_agg_0";
			const unsigned char HASH_KEY_CLSAG_AGG_1[] = "CLSAG_agg_1";
			vector<std::array<uint8_t, 32>> mu_P_to_hash(2 * n + 4);
			vector<std::array<uint8_t, 32>> mu_C_to_hash(2 * n + 4);
			sc_0(mu_P_to_hash[0].data());
			sc_0(mu_C_to_hash[0].data());
			memcpy(mu_P_to_hash[0].data(), HASH_KEY_CLSAG_AGG_0, sizeof(HASH_KEY_CLSAG_AGG_0) - 1);
			memcpy(mu_C_to_hash[0].data(), HASH_KEY_CLSAG_AGG_1, sizeof(HASH_KEY_CLSAG_AGG_1) - 1);
			for (size_t i = 1; i < n + 1; ++i)
			{
				const auto& member = vin.keys[i - 1];
				memcpy(mu_P_to_hash[i].data(), member.key, 32);
				memcpy(mu_C_to_hash[i].data(), member.key, 32);
			}
			for (size_t i = n + 1; i < 2 * n + 1; ++i)
			{
				const auto& member = vin.keys[i - n - 1];
				memcpy(mu_P_to_hash[i].data(), member.mask, 32);
				memcpy(mu_C_to_hash[i].data(), member.mask, 32);
			}
			memcpy(mu_P_to_hash[2 * n + 1].data(), vin.key_image, 32);
			memcpy(mu_P_to_hash[2 * n + 2].data(), vin.clsag.d, 32);
			memcpy(mu_P_to_hash[2 * n + 3].data(), vin.pseudo_out.key, 32);
			memcpy(mu_C_to_hash[2 * n + 1].data(), vin.key_image, 32);
			memcpy(mu_C_to_hash[2 * n + 2].data(), vin.clsag.d, 32);
			memcpy(mu_C_to_hash[2 * n + 3].data(), vin.pseudo_out.key, 32);

			vector<uint8_t> mu_P_to_hash8, mu_C_to_hash8; uint8_t mu_P[32], mu_C[32];
			vector32_to_vector8(mu_P_to_hash, mu_P_to_hash8);
			vector32_to_vector8(mu_C_to_hash, mu_C_to_hash8);
			hash_to_scalar(mu_P_to_hash8.data(), mu_P_to_hash8.size(), mu_P);
			hash_to_scalar(mu_C_to_hash8.data(), mu_C_to_hash8.size(), mu_C);
			if (sc_valid(mu_P) == 0 || sc_valid(mu_C) == 0)
				return layer_exception("invalid mu_P or mu_C constant");

			uint8_t mlsag_prehash_to_hash[96], mlsag_prehash[32];
			pseudo_message.as_prefix_hash(mlsag_prehash_to_hash);
			pseudo_message.as_rctsig_base_hash(mlsag_prehash_to_hash + 32);
			pseudo_message.as_rctsig_prunable_hash(mlsag_prehash_to_hash + 64);
			xmr_fast_hash(mlsag_prehash, mlsag_prehash_to_hash, sizeof(mlsag_prehash_to_hash));

			const unsigned char HASH_KEY_CLSAG_ROUND[] = "CLSAG_round";
			vector<std::array<uint8_t, 32>> c_to_hash(2 * n + 5);
			sc_0(c_to_hash[0].data());
			memcpy(c_to_hash[0].data(), HASH_KEY_CLSAG_ROUND, sizeof(HASH_KEY_CLSAG_ROUND) - 1);
			for (size_t i = 1; i < n + 1; ++i)
			{
				const auto& member = vin.keys[i - 1];
				memcpy(c_to_hash[i].data(), member.key, 32);
				memcpy(c_to_hash[i + n].data(), member.mask, 32);
			}
			memcpy(c_to_hash[2 * n + 1].data(), vin.pseudo_out.key, 32);
			memcpy(c_to_hash[2 * n + 2].data(), mlsag_prehash, 32);

			uint8_t c[32];
			memcpy(c, vin.clsag.c1, 32);

			vector<uint8_t> c_to_hash8;
			for (size_t i = 0; i < n; ++i)
			{
				const auto& s_i = vin.clsag.s[i];
				const auto& member = vin.keys[i];
				uint8_t c_p[32], c_c[32];
				sc_mul(c_p, mu_P, c);
				sc_mul(c_c, mu_C, c);

				uint8_t C_i[32];
				if (ge_sub_w(C_i, member.mask, vin.pseudo_out.key) != 0)
					return layer_exception("invalid C(i) constant");

				uint8_t H_i[32];
				hash_to_point(member.key, 32, H_i);

				ge_p3 P_3, C_3, H_3;
				if (ge_frombytes_vartime(&P_3, member.key) != 0 || ge_frombytes_vartime(&C_3, C_i) != 0 || ge_frombytes_vartime(&H_3, H_i) != 0)
					return layer_exception("invalid P, C or H constant");

				ge_dsmp P_precomp, C_precomp, H_precomp;
				ge_dsm_precomp(P_precomp, &P_3);
				ge_dsm_precomp(C_precomp, &C_3);
				ge_dsm_precomp(H_precomp, &H_3);

				uint8_t L[32], R[32];
				ge_addKeys_aGbBcC(L, s_i.data(), c_p, P_precomp, c_c, C_precomp);
				ge_addKeys_aAbBcC(R, s_i.data(), H_precomp, c_p, I_precomp, c_c, D_precomp);
				memcpy(c_to_hash[2 * n + 3].data(), L, 32);
				memcpy(c_to_hash[2 * n + 4].data(), R, 32);
				vector32_to_vector8(c_to_hash, c_to_hash8);

				uint8_t c_i[32];
				hash_to_scalar(c_to_hash8.data(), c_to_hash8.size(), c_i);
				memcpy(c, c_i, sizeof(c_i));
				if (sc_valid(c) == 0)
					return layer_exception("invalid c constant");
			}

			if (memcmp(c, vin.clsag.c1, 32) != 0)
				return layer_exception("invalid signature (c1 check fail)");

			return expectation::met;
		}
		algorithm::composition::type ed25519_clsag_compositor::alg_type() const
		{
			return algorithm::composition::type::ed25519_clsag;
		}
		algorithm::composition::phase ed25519_clsag_compositor::next_phase() const
		{
			if (z_steps == participants)
				return algorithm::composition::phase::consume_after_reset;
			else if (z_steps > 0)
				return algorithm::composition::phase::consume;

			if (i_steps == participants)
				return algorithm::composition::phase::consume_after_reset;
			else if (i_steps > 0)
				return algorithm::composition::phase::consume;

			if (a_steps == participants)
				return algorithm::composition::phase::consume_after_reset;
			else if (a_steps > 0)
				return algorithm::composition::phase::consume;

			if (s_steps == participants)
				return algorithm::composition::phase::consume_after_reset;
			else if (s_steps > 0)
				return algorithm::composition::phase::consume;

			return algorithm::composition::phase::finalize;
		}
		uint32_t ed25519_clsag_compositor::steps_left() const
		{
			return z_steps + i_steps + a_steps + s_steps;
		}
		bool ed25519_clsag_compositor::store(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(cumulative_key.optimized_view());
			stream->write_string(cumulative_I.optimized_view());
			stream->write_string(cumulative_aH.optimized_view());
			stream->write_string(cumulative_aG.optimized_view());
			stream->write_string(cumulative_c_mu_P.optimized_view());
			stream->write_integer(participants);
			stream->write_integer(vin_index);
			stream->write_integer(z_steps);
			stream->write_integer(i_steps);
			stream->write_integer(a_steps);
			stream->write_integer(s_steps);
			return message.store_payload(stream);
		}
		bool ed25519_clsag_compositor::load(format::ro_stream& stream)
		{
			if (!stream.read_optimized_view(stream.read_type(), cumulative_key.blob, sizeof(cumulative_key)))
				return false;

			if (!stream.read_optimized_view(stream.read_type(), cumulative_I.blob, sizeof(cumulative_I)))
				return false;

			if (!stream.read_optimized_view(stream.read_type(), cumulative_aH.blob, sizeof(cumulative_aH)))
				return false;

			if (!stream.read_optimized_view(stream.read_type(), cumulative_aG.blob, sizeof(cumulative_aG)))
				return false;

			if (!stream.read_optimized_view(stream.read_type(), cumulative_c_mu_P.blob, sizeof(cumulative_c_mu_P)))
				return false;

			if (!stream.read_integer(stream.read_type(), &participants))
				return false;

			if (!stream.read_integer(stream.read_type(), &vin_index))
				return false;

			if (!stream.read_integer(stream.read_type(), &z_steps))
				return false;

			if (!stream.read_integer(stream.read_type(), &i_steps))
				return false;

			if (!stream.read_integer(stream.read_type(), &a_steps))
				return false;

			if (!stream.read_integer(stream.read_type(), &s_steps))
				return false;

			return message.load_payload(stream);
		}
		bool ed25519_clsag_compositor::may_transition_to(const compositor& next_ptr) const
		{
			auto* next = (const ed25519_clsag_compositor*)&next_ptr;
			if (participants != next->participants || vin_index != next->vin_index)
				return false;

			if ((z_steps == next->z_steps) != cumulative_key.equals(next->cumulative_key))
				return false;

			if ((i_steps == next->i_steps) != cumulative_I.equals(next->cumulative_I))
			{
				if (a_steps <= next->a_steps || cumulative_I.equals(next->cumulative_I))
					return false;
			}

			if ((a_steps == next->a_steps) != cumulative_aH.equals(next->cumulative_aH))
				return false;

			if ((a_steps == next->a_steps) != cumulative_aG.equals(next->cumulative_aG))
				return false;

			if (a_steps > 0 && !next->a_steps && cumulative_c_mu_P.equals(next->cumulative_c_mu_P))
				return false;

			if (vin_index < message.vin.size())
			{
				if (next->vin_index >= next->message.vin.size())
					return false;

				auto& vin = message.vin[vin_index];
				auto next_vin = next->message.vin[next->vin_index];
				auto ring_member = std::find_if(vin.keys.begin(), vin.keys.end(), [](const clsag_message::txin_to_key::ref& r) { return !r.decoy; });
				auto next_ring_member = std::find_if(next_vin.keys.begin(), next_vin.keys.end(), [](const clsag_message::txin_to_key::ref& r) { return !r.decoy; });
				auto key_index = ring_member == vin.keys.end() ? std::numeric_limits<size_t>::max() : std::distance(vin.keys.begin(), ring_member);
				auto next_key_index = next_ring_member == next_vin.keys.end() ? std::numeric_limits<size_t>::max() : std::distance(next_vin.keys.begin(), next_ring_member);
				if (key_index != next_key_index || vin.clsag.s.size() > next_vin.clsag.s.size())
					return false;

				if (key_index != std::numeric_limits<size_t>::max() && key_index < vin.clsag.s.size())
				{
					auto& s_i = vin.clsag.s[key_index];
					auto& next_s_i = next_vin.clsag.s[next_key_index];
					if ((s_steps == next->s_steps) != (s_i == next_s_i))
						return false;
				}

				vector<uint8_t> a, b;
				a.insert(a.end(), vin.clsag.c1, vin.clsag.c1 + 32);
				a.insert(a.end(), vin.clsag.d, vin.clsag.d + 32);
				b.insert(b.end(), next_vin.clsag.c1, next_vin.clsag.c1 + 32);
				b.insert(b.end(), next_vin.clsag.d, next_vin.clsag.d + 32);
				for (auto& s : vin.clsag.s)
					a.insert(a.end(), s.data(), s.data() + 32);
				for (auto& s : next_vin.clsag.s)
					b.insert(b.end(), s.data(), s.data() + 32);
				
				bool clsag_updated = algorithm::hashing::hash256i(std::string_view((char*)a.data(), a.size())) != algorithm::hashing::hash256i(std::string_view((char*)b.data(), b.size()));
				if (a_steps > 0 && next->a_steps > 0 && clsag_updated)
					return false;

				if (a_steps > 0 && !next->a_steps)
				{
					if (!clsag_updated)
						return false;
				}
				else if ((s_steps == next->s_steps) != !clsag_updated)
					return false;
			}

			uint8_t hash_prev[32], hash_next[32];
			message.as_id_hash(hash_prev, true, true, true);
			next->message.as_id_hash(hash_next, true, true, true);
			if (memcmp(hash_prev, hash_next, sizeof(hash_next)) != 0)
				return false;

			return steps_left() >= next->steps_left();
		}
		bool ed25519_clsag_compositor::generate_derivation_key(const uint8_t transaction_public_key[32], const uint8_t private_view_key[32], uint8_t derivation_key[32])
		{
			ge_p3 m3;
			if (ge_frombytes_vartime(&m3, transaction_public_key) != 0)
				return false;

			ge_p2 m2;
			ge_scalarmult(&m2, private_view_key, &m3);

			ge_p1p1 m11;
			ge_mul8(&m11, &m2);
			ge_p1p1_to_p2(&m2, &m11);
			ge_tobytes(derivation_key, &m2);
			return true;
		}
		void ed25519_clsag_compositor::derive_private_key(const uint8_t derivation_scalar[32], const uint8_t private_spend_key[32], uint8_t private_key[32])
		{
			sc_add(private_key, private_spend_key, derivation_scalar);
		}
		bool ed25519_clsag_compositor::derive_public_key(const uint8_t derivation_scalar[32], const uint8_t public_spend_key[32], uint8_t public_key[32])
		{
			ge_p3 m3_1;
			if (ge_frombytes_vartime(&m3_1, public_spend_key) != 0)
				return false;

			ge_p3 m3_2;
			ge_scalarmult_base(&m3_2, derivation_scalar);

			ge_cached m3_3;
			ge_p3_to_cached(&m3_3, &m3_2);

			ge_p1p1 m11;
			ge_add(&m11, &m3_1, &m3_3);

			ge_p2 m2;
			ge_p1p1_to_p2(&m2, &m11);
			ge_tobytes(public_key, &m2);
			return true;
		}
		void ed25519_clsag_compositor::derivation_to_scalar(const uint8_t derivation_key[32], uint64_t derivation_index, uint8_t derivation_scalar[32])
		{
			uint8_t derivation[42] = { 0 };
			memcpy(derivation, derivation_key, 32);
			size_t size = 32 + write_varint_fixed(derivation_index, derivation + 32);
			hash_to_scalar(derivation, size, derivation_scalar);
		}
		uint8_t ed25519_clsag_compositor::derivation_to_view_tag(const uint8_t derivation_key[32], uint64_t derivation_index)
		{
			uint8_t buf[8 + 32 + 10]; uint8_t* p = buf;
			memcpy(p, "view_tag", 8); p += 8;
			memcpy(p, derivation_key, 32); p += 32;

			uint64_t i = derivation_index;
			while (i >= 0x80)
			{
				*p++ = static_cast<uint8_t>((i & 0x7f) | 0x80);
				i >>= 7;
			}
			*p++ = static_cast<uint8_t>(i);

			uint8_t h[32];
			xmr_fast_hash(h, buf, p - buf);
			return h[0];
		}
		void ed25519_clsag_compositor::hash_to_scalar(const uint8_t* buffer, size_t buffer_size, uint8_t scalar[32])
		{
			xmr_fast_hash(scalar, buffer, buffer_size);
			sc_reduce32(scalar);
		}
		void ed25519_clsag_compositor::hash_to_point(const uint8_t* buffer, size_t buffer_size, uint8_t point[32])
		{
			ge_p2 m2;
			xmr_fast_hash(point, buffer, buffer_size);
			ge_fromfe_frombytes_vartime(&m2, point);

			ge_p1p1 m11;
			ge_mul8(&m11, &m2);

			ge_p3 m3;
			ge_p1p1_to_p3(&m3, &m11);
			ge_p3_tobytes(point, &m3);
		}
		bool ed25519_clsag_compositor::pedersen_commit(const uint8_t mask[32], const uint8_t amount[32], uint8_t commitment[32])
		{
			static uint8_t h[32] = { 139, 101, 89, 112, 21, 55, 153, 175, 42, 234, 220, 159, 241, 173, 208, 234, 108, 114, 81, 213, 65, 84, 207, 169, 44, 23, 58, 13, 211, 156, 31, 148 };

			ge_p3 m3;
			if (ge_frombytes_vartime(&m3, h) != 0)
				return false;

			if (sc_check(amount) != 0 || sc_valid(mask) == 0)
				return false;

			ge_p2 m2;
			ge_double_scalarmult_base_vartime(&m2, amount, &m3, mask);
			ge_tobytes(commitment, &m2);
			return true;
		}
		void ed25519_clsag_compositor::derive_known_private_view_key(const uint8_t public_spend_key[32], uint8_t private_view_key[32])
		{
			uint8_t hash[32];
			xmr_fast_hash(hash, public_spend_key, sizeof(hash));
			memcpy(private_view_key, hash, sizeof(hash));
			sc_reduce32(private_view_key);
		}
		void ed25519_clsag_compositor::derive_known_public_view_key(const uint8_t public_spend_key[32], uint8_t public_view_key[32])
		{
			uint8_t private_view_key[32];
			derive_known_private_view_key(public_spend_key, private_view_key);
			crypto_scalarmult_ed25519_base_noclamp(public_view_key, private_view_key);
		}
		void ed25519_clsag_compositor::encode_amount_256(uint64_t amount_in, uint8_t amount_out[32])
		{
			amount_in = os::hw::to_endianness(os::hw::endian::little, amount_in);
			memset(amount_out, 0, 32);
			memcpy(amount_out, &amount_in, sizeof(amount_in));
		}
		void ed25519_clsag_compositor::vector32_to_vector8(const vector<std::array<uint8_t, 32>>& in, vector<uint8_t>& out)
		{
			out.resize(in.size() * 32);
			for (size_t i = 0; i < in.size(); i++)
				memcpy(out.data() + i * 32, in[i].data(), 32);
		}
		void ed25519_clsag_compositor::derive_pseudo_message(const uint8_t* message, size_t message_size, clsag_message& out, uint16_t& index_out)
		{
			VI_ASSERT(message != nullptr, "message should be set");
			uint64_t sc_nonce = 0;
			auto sc_derive = [&](uint8_t x[32])
			{
				uint8_t buffer[40]; uint64_t nonce = os::hw::to_endianness(os::hw::endian::little, sc_nonce++);
				memcpy(buffer, message, message_size);
				memcpy(buffer + message_size, &nonce, sizeof(nonce));
				hash_to_scalar(buffer, sizeof(buffer), x);
			};

			index_out = 0;
			out = clsag_message();
			out.fee = 1234;
			out.vout.resize(1);
			out.vin.resize(1);
			out.extra.resize(32);
			out.bpp.l.resize(2);
			out.bpp.r.resize(2);
			sc_derive(out.extra.data());
			sc_derive(out.tx_key);
			sc_derive(out.bpp.a);
			sc_derive(out.bpp.a1);
			sc_derive(out.bpp.b);
			sc_derive(out.bpp.r1);
			sc_derive(out.bpp.s1);
			sc_derive(out.bpp.d1);
			for (auto& x : out.bpp.l)
				sc_derive(x.data());
			for (auto& x : out.bpp.r)
				sc_derive(x.data());

			auto& vout = out.vout[0];
			sc_derive(vout.target.key);
			sc_derive(vout.ecdh_info.amount);
			sc_derive(vout.out_pk.blinding_factor);
			sc_mul_g(vout.out_pk.mask, vout.out_pk.blinding_factor);

			auto& vin = out.vin[0];
			vin.keys.resize(3);
			sc_derive(vin.pseudo_out.mask);
			sc_derive(vin.prev_out.derivation_scalar);
			sc_derive(vin.prev_out.commitment_mask);

			uint8_t z[32];
			sc_sub(z, vin.prev_out.commitment_mask, vin.pseudo_out.mask);
			sc_mul_g(vin.pseudo_out.key, vin.pseudo_out.mask);

			uint64_t index = 123, ring_index = 1;
			auto& real = vin.keys[ring_index];
			real.decoy = false;
			real.index = 123 + ring_index;
			vin.prev_out.index = real.index;
			memset(real.key, 0, sizeof(real.key));
			sc_mul_g(real.mask, vin.prev_out.commitment_mask);
			for (size_t i = 0; i < vin.keys.size(); ++i)
			{
				if (i == ring_index)
					continue;

				uint8_t fake_p[32], fake_mask[32];
				auto& member = vin.keys[i];
				member.decoy = true;
				member.index = index + i;
				sc_derive(fake_p);
				sc_derive(fake_mask);
				sc_mul_g(member.key, fake_p);
				sc_mul_g(member.mask, fake_mask);
			}
		}
		void ed25519_clsag_compositor::write_varint(uint64_t i, vector<uint8_t>& buffer)
		{
			while (i >= 0x80)
			{
				buffer.push_back(static_cast<uint8_t>((i & 0x7f) | 0x80));
				i >>= 7;
			}
			buffer.push_back(static_cast<uint8_t>(i));
		}
		size_t ed25519_clsag_compositor::write_varint_fixed(uint64_t i, uint8_t buffer[10])
		{
			size_t offset = 0;
			while (i >= 0x80)
			{
				buffer[offset++] = static_cast<uint8_t>((i & 0x7f) | 0x80);
				i >>= 7;
			}
			buffer[offset++] = static_cast<uint8_t>(i);
			return offset;
		}

		expects_lr<void> secp256k1_compositor::setup_public_key(const uint8_t* new_message, size_t new_message_size, uint16_t new_participants)
		{
			algorithm::composition::cpubkey_t temp_public_key;
			temp_public_key.resize(sizeof(secp256k1_point_t));
			auto status = setup_signature(temp_public_key, new_message, new_message_size, nullptr, new_participants);
			if (!status)
				return status.error();

			factors.clear();
			factors.resize((size_t)new_participants);
			z_steps = new_participants;
			cumulative_key.clear();
			return expectation::met;
		}
		expects_lr<void> secp256k1_compositor::setup_signature(const algorithm::composition::cpubkey_t& new_public_key, const uint8_t* new_message, size_t new_message_size, const algorithm::composition::shared_message* new_shared, uint16_t new_participants)
		{
			VI_ASSERT(new_message != nullptr, "message should be set");
			if (new_message_size != sizeof(message_hash))
				sha256_Raw(new_message, new_message_size, message_hash);
			else
				memcpy(message_hash, new_message, sizeof(message_hash));

			if (new_public_key.size() != sizeof(secp256k1_point_t))
			{
				auto* context = algorithm::signing::get_context();
				secp256k1_pubkey uncompressed_public_key;
				if (secp256k1_ec_pubkey_parse(context, &uncompressed_public_key, new_public_key.data(), new_public_key.size()) != 1)
					return layer_exception("invalid public key");

				size_t key_size = sizeof(cumulative_key);
				if (secp256k1_ec_pubkey_serialize(context, cumulative_key.blob, &key_size, &uncompressed_public_key, SECP256K1_EC_COMPRESSED) != 1)
					return layer_exception("invalid public key");
			}
			else
				cumulative_key = std::string_view((char*)new_public_key.data(), new_public_key.size());

			factors.clear();
			factors.resize((size_t)new_participants);
			cumulative_r = secp256k1_point_t();
			cumulative_s = secp256k1_scalar_t();
			z_steps = 0; r_steps = p_steps = d_steps = s_steps = new_participants;
			p_bits = 2048;
			return expectation::met;
		}
		expects_lr<void> secp256k1_compositor::aggregate(const algorithm::composition::cseckey_t& secret_key)
		{
			if (secret_key.size() != sizeof(secp256k1_scalar_t))
				return layer_exception("invalid secret key size");

			auto use_paillier_keypair = [&](paillier_pubkey* public_key, paillier_seckey* private_key, const bignum256* k, const bignum256* g)
			{
				uint8_t seed[96];
				bn_write_be(k, seed + 00);
				bn_write_be(g, seed + 32);
				memcpy(seed + 64, secret_key.data(), 32);
				auto cache = algorithm::composition::pull_derivation_cache(std::string_view((char*)seed, sizeof(seed)));
				if (cache)
				{
					string intermediate; uint64_t len;
					format::ro_stream message = format::ro_stream(*cache);
					if (!message.read_integer(message.read_type(), &len))
						goto paillier_keygen;

					private_key->len = (mp_bitcnt_t)len;
					if (!message.read_string(message.read_type(), &intermediate) || !mpz_import_buffer((uint8_t*)intermediate.data(), intermediate.size(), private_key->lambda))
						goto paillier_keygen;

					if (!message.read_string(message.read_type(), &intermediate) || !mpz_import_buffer((uint8_t*)intermediate.data(), intermediate.size(), private_key->mu))
						goto paillier_keygen;

					if (!message.read_string(message.read_type(), &intermediate) || !mpz_import_buffer((uint8_t*)intermediate.data(), intermediate.size(), private_key->p2))
						goto paillier_keygen;

					if (!message.read_string(message.read_type(), &intermediate) || !mpz_import_buffer((uint8_t*)intermediate.data(), intermediate.size(), private_key->q2))
						goto paillier_keygen;

					if (!message.read_string(message.read_type(), &intermediate) || !mpz_import_buffer((uint8_t*)intermediate.data(), intermediate.size(), private_key->p2invq2))
						goto paillier_keygen;

					if (!message.read_string(message.read_type(), &intermediate) || !mpz_import_buffer((uint8_t*)intermediate.data(), intermediate.size(), private_key->ninv))
						goto paillier_keygen;

					if (!message.read_string(message.read_type(), &intermediate) || !mpz_import_buffer((uint8_t*)intermediate.data(), intermediate.size(), private_key->n))
						goto paillier_keygen;

					mpz_set(public_key->n, private_key->n);
				}
				else
				{
				paillier_keygen:
					format::wo_stream message;
					paillier_keypair_derive(public_key, private_key, p_bits, seed, sizeof(seed));
					message.write_integer((uint64_t)private_key->len);
					message.write_string(mpz_export_buffer(private_key->lambda));
					message.write_string(mpz_export_buffer(private_key->mu));
					message.write_string(mpz_export_buffer(private_key->p2));
					message.write_string(mpz_export_buffer(private_key->q2));
					message.write_string(mpz_export_buffer(private_key->p2invq2));
					message.write_string(mpz_export_buffer(private_key->ninv));
					message.write_string(mpz_export_buffer(private_key->n));
					algorithm::composition::push_derivation_cache(string((char*)seed, sizeof(seed)), std::move(message.data));
				}
			};
			auto use_local_n = [&](const std::string_view& domain, uint256_t& index, bignum256* output)
			{
				format::wo_stream seed;
				seed.write_string(domain);
				seed.write_string(std::string_view((char*)secret_key.data(), secret_key.size()));

				uint8_t ask[32] = { 0 }, nonce[32] = { 0 };
				seed.hash().encode(ask);
				while (true)
				{
					uint8_t index_nonce[32] = { 0 };
					index.encode(index_nonce);
					if (secp256k1_nonce_function_rfc6979(nonce, message_hash, ask, nullptr, index_nonce, 0) == 1)
					{
						bignum256 inverse, negate;
						bn_read_be(nonce, output);
						bn_mod(output, &secp256k1.order);
						bn_copy(output, &inverse);
						bn_copy(output, &negate);
						bn_inverse(&inverse, &secp256k1.order);
						bn_mod(&inverse, &secp256k1.order);
						bn_cnegate(1, &negate, &secp256k1.order);
						bn_mod(&negate, &secp256k1.order);
						if (!bn_is_zero(&inverse) && !bn_is_zero(&negate) && !bn_is_zero(&inverse))
							break;
					}
					++index;
				}
			};
			auto use_local_s = [&](bignum256* s) -> bool
			{
				bignum256 n = { 0 };
				bn_read_uint32((uint32_t)factors.size(), &n);
				bn_inverse(&n, &secp256k1.order);

				bignum256 z = { 0 };
				bn_read_be(message_hash, &z);
				bn_multiply(&n, &z, &secp256k1.order);
				if (bn_is_zero(&z))
					return false;

				curve_point r = from_compressed_point_secp256k1(cumulative_r);
				bn_read_be(secret_key.data(), s);
				bn_multiply(&r.x, s, &secp256k1.order);
				bn_addmod(s, &z, &secp256k1.order);
				return true;
			};
			if (z_steps > 0)
			{
				secp256k1_context* context = algorithm::signing::get_context();
				if (secp256k1_ec_seckey_verify(context, secret_key.data()) != 1)
					return layer_exception("invalid secret key scalar");

				secp256k1_pubkey next_public_key;
				if (secp256k1_ec_pubkey_create(context, &next_public_key, secret_key.data()) != 1)
					return layer_exception("invalid secret key");

				if (cumulative_key.empty())
				{
					size_t key_size = sizeof(cumulative_key);
					if (secp256k1_ec_pubkey_serialize(context, cumulative_key.blob, &key_size, &next_public_key, SECP256K1_EC_COMPRESSED) != 1)
						return layer_exception("invalid secret key");
				}
				else
				{
					secp256k1_pubkey prev_public_key, result_public_key;
					if (secp256k1_ec_pubkey_parse(context, &prev_public_key, cumulative_key.blob, sizeof(cumulative_key)) != 1)
						return layer_exception("invalid intermediate public key");

					secp256k1_pubkey* public_keys[2] = { &prev_public_key, &next_public_key };
					if (secp256k1_ec_pubkey_combine(context, &result_public_key, public_keys, 2) != 1)
						return layer_exception("invalid secret key");

					size_t key_size = sizeof(cumulative_key);
					if (secp256k1_ec_pubkey_serialize(context, cumulative_key.blob, &key_size, &result_public_key, SECP256K1_EC_COMPRESSED) != 1)
						return layer_exception("invalid secret key");
				}

				--z_steps;
			}
			else if (r_steps > 0)
			{
				if (r_steps > factors.size())
					return layer_exception("invalid compositor state");

				bignum256 k = { 0 };
				auto& factor = factors[r_steps - 1];
			retry_k_nonce:
				use_local_n("KNONCE", factor.k_index, &k);

				curve_point r;
				memset(&r, 0, sizeof(r));
				if (scalar_multiply(&secp256k1, &k, &r) != 0)
				{
					++factor.k_index;
					goto retry_k_nonce;
				}
				else if (!cumulative_r.empty())
				{
					curve_point prev_r = from_compressed_point_secp256k1(cumulative_r);
					point_add(&secp256k1, &prev_r, &r);
				}

				bn_mod(&r.x, &secp256k1.order);
				if (point_is_infinity(&r) || bn_is_zero(&r.x))
				{
					++factor.k_index;
					goto retry_k_nonce;
				}

				cumulative_r = to_compressed_point_secp256k1(r);
				--r_steps;
			}
			else if (p_steps > 0)
			{
				if (p_steps > factors.size())
					return layer_exception("invalid compositor state");

				uint256_t g_index = 0;
				bignum256 g = { 0 }, k = { 0 };
				auto& factor = factors[p_steps - 1];
				use_local_n("GMASK", g_index, &g);
				use_local_n("KNONCE", factor.k_index, &k);

				bignum256 s = { 0 };
				if (!use_local_s(&s))
					return layer_exception("invalid message scalar");

				paillier_seckey paillier_secret_key;
				paillier_pubkey paillier_public_key;
				paillier_seckey_init(&paillier_secret_key);
				paillier_pubkey_init(&paillier_public_key);
				use_paillier_keypair(&paillier_public_key, &paillier_secret_key, &k, &g);
				paillier_store_public_key(&paillier_public_key, &factor.public_key);

				uint8_t k_buffer[32] = { 0 }, s_buffer[32] = { 0 };
				bn_write_be(&k, k_buffer);
				bn_write_be(&s, s_buffer);

				mpz_t plaintext_k, ciphertext_k;
				mpz_t plaintext_s, ciphertext_s;
				mpz_init(plaintext_k);
				mpz_init(ciphertext_k);
				mpz_init(plaintext_s);
				mpz_init(ciphertext_s);
				bool k_import = mpz_import_buffer(k_buffer, sizeof(k_buffer), plaintext_k);
				bool s_import = mpz_import_buffer(s_buffer, sizeof(s_buffer), plaintext_s);
				bool k_encrypt = paillier_encrypt(ciphertext_k, plaintext_k, &paillier_public_key) == 0;
				bool s_encrypt = paillier_encrypt(ciphertext_s, plaintext_s, &paillier_public_key) == 0;
				auto k_export = mpz_export_buffer(ciphertext_k);
				auto s_export = mpz_export_buffer(ciphertext_s);
				paillier_pubkey_clear(&paillier_public_key);
				paillier_seckey_clear(&paillier_secret_key);
				mpz_clear(plaintext_k);
				mpz_clear(ciphertext_k);
				mpz_clear(plaintext_s);
				mpz_clear(ciphertext_s);
				if (!k_import || !s_import || !k_encrypt || !s_encrypt || k_export.empty() || s_export.empty())
					return layer_exception("x/y encrypted keygen failed");

				factor.cumulative_x.resize(k_export.size());
				factor.cumulative_y.resize(s_export.size());
				memcpy(factor.cumulative_x.data(), k_export.data(), k_export.size());
				memcpy(factor.cumulative_y.data(), s_export.data(), s_export.size());
				--p_steps;
			}
			else if (d_steps > 0)
			{
				if (d_steps > factors.size())
					return layer_exception("invalid compositor state");
				
				uint8_t g_buffer[32] = { 0 };
				bignum256 g = { 0 }; uint256_t g_index = 0;
				use_local_n("GMASK", g_index, &g);
				bn_write_be(&g, g_buffer);

				mpz_t g_i;
				mpz_init(g_i);
				if (!mpz_import_buffer(g_buffer, sizeof(g_buffer), g_i))
				{
					mpz_clear(g_i);
					return layer_exception("invalid gamma factor");
				}

				auto i = d_steps - 1;
				auto& factor = factors[i];
				auto betas = vector<beta_state>();
				betas.reserve(factors.size());
				for (size_t j = 0; j < factors.size(); j++)
				{
					if (i != j || factors.size() == 1)
						betas.emplace_back().index = j;
				}

				parallel::wail_all(parallel::for_each(betas.begin(), betas.end(), 1, [&](beta_state& state)
				{
					size_t j = state.index;
					auto& jfactor = factors[j];
					format::wo_stream x_b_domain, y_b_domain;
					x_b_domain.write_integer((uint16_t)j);
					x_b_domain.write_string("XBFACTOR");
					y_b_domain.write_integer((uint16_t)j);
					y_b_domain.write_string("YBFACTOR");

					uint256_t x_b_index = 0, y_b_index = 0;
					uint8_t x_b_buffer[32] = { 0 }, y_b_buffer[32] = { 0 };
					bignum256 x_b = { 0 }, y_b = { 0 };
					use_local_n(x_b_domain.data, x_b_index, &x_b);
					use_local_n(y_b_domain.data, y_b_index, &y_b);
					bn_cnegate(1, &x_b, &secp256k1.order);
					bn_cnegate(1, &y_b, &secp256k1.order);
					bn_mod(&x_b, &secp256k1.order);
					bn_mod(&y_b, &secp256k1.order);
					bn_write_be(&x_b, x_b_buffer);
					bn_write_be(&y_b, y_b_buffer);

					paillier_pubkey paillier_public_key;
					paillier_pubkey_init(&paillier_public_key);
					mpz_t x_d_j, x_b_j;
					mpz_t y_d_j, y_b_j;
					mpz_init(x_d_j);
					mpz_init(x_b_j);
					mpz_init(y_d_j);
					mpz_init(y_b_j);

					auto key_import = paillier_load_public_key(jfactor.public_key, &paillier_public_key, p_bits);
					bool x_d_j_import = mpz_import_buffer(jfactor.cumulative_x.data(), jfactor.cumulative_x.size(), x_d_j);
					bool x_b_j_import = mpz_import_buffer(x_b_buffer, sizeof(x_b_buffer), x_b_j);
					bool y_d_j_import = mpz_import_buffer(jfactor.cumulative_y.data(), jfactor.cumulative_y.size(), y_d_j);
					bool y_b_j_import = mpz_import_buffer(y_b_buffer, sizeof(y_b_buffer), y_b_j);
					if (key_import && x_d_j_import && x_b_j_import && y_d_j_import && y_b_j_import)
					{
						paillier_homomorphic_mulc(x_d_j, x_d_j, g_i, &paillier_public_key);
						paillier_homomorphic_mulc(y_d_j, y_d_j, g_i, &paillier_public_key);
						bool x_d_j_add = paillier_homomorphic_addc(x_d_j, x_d_j, x_b_j, &paillier_public_key) == 0;
						bool y_d_j_add = paillier_homomorphic_addc(y_d_j, y_d_j, y_b_j, &paillier_public_key) == 0;
						if (x_d_j_add && !jfactor.cumulative_x_d.empty())
						{
							x_d_j_add = x_d_j_add && mpz_import_buffer(jfactor.cumulative_x_d.data(), jfactor.cumulative_x_d.size(), x_b_j);
							paillier_homomorphic_add(x_d_j, x_d_j, x_b_j, &paillier_public_key);
						}
						if (y_d_j_add && !jfactor.cumulative_y_d.empty())
						{
							y_d_j_add = y_d_j_add && mpz_import_buffer(jfactor.cumulative_y_d.data(), jfactor.cumulative_y_d.size(), y_b_j);
							paillier_homomorphic_add(y_d_j, y_d_j, y_b_j, &paillier_public_key);
						}

						auto x_d_j_export = mpz_export_buffer(x_d_j), y_d_j_export = mpz_export_buffer(y_d_j);
						if (x_d_j_add && y_d_j_add && !x_d_j_export.empty() && !y_d_j_export.empty())
						{
							jfactor.cumulative_x_d.resize(x_d_j_export.size());
							jfactor.cumulative_y_d.resize(y_d_j_export.size());
							memcpy(jfactor.cumulative_x_d.data(), x_d_j_export.data(), x_d_j_export.size());
							memcpy(jfactor.cumulative_y_d.data(), y_d_j_export.data(), y_d_j_export.size());
							state.sanity_check = true;
						}
					}

					paillier_pubkey_clear(&paillier_public_key);
					mpz_clear(x_d_j);
					mpz_clear(x_b_j);
					mpz_clear(y_d_j);
					mpz_clear(y_b_j);
				}));

				mpz_clear(g_i);
				for (auto& state : betas)
				{
					if (!state.sanity_check)
						return layer_exception("invalid x/y scalars, beta factors and/or paillier modulus");
				}

				--d_steps;
			}
			else if (s_steps > 0)
			{
				if (s_steps > factors.size())
					return layer_exception("invalid compositor state");

				auto i = s_steps - 1;
				auto& factor = factors[i];
				uint256_t g_index = 0;
				bignum256 g = { 0 }, k = { 0 };
				use_local_n("GMASK", g_index, &g);
				use_local_n("KNONCE", factor.k_index, &k);

				uint8_t order_buffer[32] = { 0 }, x_d_buffer[32] = { 0 }, y_d_buffer[32] = { 0 };
				bn_write_be(&secp256k1.order, order_buffer);

				bignum256 s = { 0 };
				if (!use_local_s(&s))
					return layer_exception("invalid message scalar");

				mpz_t order;
				mpz_t x_d_ciphertext, x_d_plaintext;
				mpz_t y_d_ciphertext, y_d_plaintext;
				mpz_init(order);
				mpz_init(x_d_ciphertext);
				mpz_init(x_d_plaintext);
				mpz_init(y_d_ciphertext);
				mpz_init(y_d_plaintext);
				paillier_seckey paillier_secret_key;
				paillier_pubkey paillier_public_key;
				paillier_seckey_init(&paillier_secret_key);
				paillier_pubkey_init(&paillier_public_key);
				use_paillier_keypair(&paillier_public_key, &paillier_secret_key, &k, &g);
				bool order_import = mpz_import_buffer(order_buffer, sizeof(order_buffer), order);
				bool x_d_import = mpz_import_buffer(factor.cumulative_x_d.data(), factor.cumulative_x_d.size(), x_d_ciphertext);
				bool y_d_import = mpz_import_buffer(factor.cumulative_y_d.data(), factor.cumulative_y_d.size(), y_d_ciphertext);
				paillier_decrypt(x_d_plaintext, x_d_ciphertext, &paillier_secret_key);
				paillier_decrypt(y_d_plaintext, y_d_ciphertext, &paillier_secret_key);
				paillier_pubkey_clear(&paillier_public_key);
				paillier_seckey_clear(&paillier_secret_key);
				mpz_mod(x_d_plaintext, x_d_plaintext, order);
				mpz_mod(y_d_plaintext, y_d_plaintext, order);
				auto x_d_export = mpz_export_buffer(x_d_plaintext);
				auto y_d_export = mpz_export_buffer(y_d_plaintext);
				auto x_d_size = std::min(sizeof(x_d_buffer), x_d_export.size());
				auto y_d_size = std::min(sizeof(y_d_buffer), y_d_export.size());
				memcpy(x_d_buffer + (sizeof(x_d_buffer) - x_d_size), x_d_export.data(), x_d_size);
				memcpy(y_d_buffer + (sizeof(y_d_buffer) - y_d_size), y_d_export.data(), y_d_size);
				mpz_clear(x_d_ciphertext);
				mpz_clear(y_d_ciphertext);
				mpz_clear(x_d_plaintext);
				mpz_clear(y_d_plaintext);
				mpz_clear(order);
				if (!order_import || !x_d_import || !y_d_import || x_d_export.empty() || y_d_export.empty())
					return layer_exception("x/y derivation failed");

				bignum256 x_d = { 0 }, y_d = { 0 };
				bn_read_be(x_d_buffer, &x_d);
				bn_read_be(y_d_buffer, &y_d);

				bignum256 x_b_sum = { 0 }, y_b_sum = { 0 };
				for (size_t j = 0; j < factors.size(); j++)
				{
					if (i == j && factors.size() > 1)
						continue;

					format::wo_stream x_b_domain, y_b_domain;
					x_b_domain.write_integer((uint16_t)j);
					x_b_domain.write_string("XBFACTOR");
					y_b_domain.write_integer((uint16_t)j);
					y_b_domain.write_string("YBFACTOR");

					uint256_t x_b_index = 0, y_b_index = 0;
					bignum256 x_b = { 0 }, y_b = { 0 };
					use_local_n(x_b_domain.data, x_b_index, &x_b);
					use_local_n(y_b_domain.data, y_b_index, &y_b);
					bn_addmod(&x_b_sum, &x_b, &secp256k1.order);
					bn_addmod(&y_b_sum, &y_b, &secp256k1.order);
				}

				bignum256 kgxdxb = k, sgydyb = s;
				bn_multiply(&g, &kgxdxb, &secp256k1.order);
				bn_addmod(&kgxdxb, &x_b_sum, &secp256k1.order);
				bn_addmod(&kgxdxb, &x_d, &secp256k1.order);
				bn_multiply(&g, &sgydyb, &secp256k1.order);
				bn_addmod(&sgydyb, &y_b_sum, &secp256k1.order);
				bn_addmod(&sgydyb, &y_d, &secp256k1.order);
				if (bn_is_zero(&kgxdxb) || bn_is_zero(&sgydyb))
					return layer_exception("invalid x/y subcoefficients");

				factor.public_key.clear();
				factor.cumulative_x_d.clear();
				factor.cumulative_y_d.clear();
				factor.cumulative_x.resize(sizeof(x_d_buffer));
				factor.cumulative_y.resize(sizeof(y_d_buffer));
				bn_write_be(&kgxdxb, factor.cumulative_x.data());
				bn_write_be(&sgydyb, factor.cumulative_y.data());
				if (!--s_steps)
				{
					bignum256 x = { 0 }, y = { 0 };
					for (auto& jfactor : factors)
					{
						if (jfactor.cumulative_x.size() != sizeof(x_d_buffer) || jfactor.cumulative_y.size() != sizeof(y_d_buffer))
							return layer_exception("invalid x/y subcoefficients");

						bignum256 x_i = { 0 }, y_i = { 0 };
						bn_read_be(jfactor.cumulative_x.data(), &x_i);
						bn_read_be(jfactor.cumulative_y.data(), &y_i);
						bn_addmod(&x, &x_i, &secp256k1.order);
						bn_addmod(&y, &y_i, &secp256k1.order);
					}
					if (bn_is_zero(&x) || bn_is_zero(&y))
						return layer_exception("invalid x/y coefficients");

					bn_inverse(&x, &secp256k1.order);
					bn_mod(&x, &secp256k1.order);
					bn_mod(&y, &secp256k1.order);
					if (bn_is_zero(&x) || bn_is_zero(&y))
						return layer_exception("invalid x/y coefficients");

					bn_multiply(&y, &x, &secp256k1.order);
					bn_write_be(&x, cumulative_s.blob);
					if (bn_is_zero(&x))
						return layer_exception("invalid cumulative s");
				}
			}
			return expectation::met;
		}
		expects_lr<void> secp256k1_compositor::derive_tweaking_key(const uint8_t* seed, size_t seed_size, size_t key_size, algorithm::paillier_scalar_t* public_key) const
		{
			paillier_to_public_key(seed, seed_size, key_size, public_key);
			return expectation::met;
		}
		expects_lr<void> secp256k1_compositor::tweak_secret_key(const algorithm::paillier_scalar_t& public_key, size_t key_size, const algorithm::composition::cseckey_t& tweak, algorithm::composition::cseckey_t* secret_key_input_output, algorithm::paillier_scalar_t* accumulator_output) const
		{
			if (accumulator_output != nullptr)
			{
				auto status = paillier_accumulate_tweak(public_key, tweak, accumulator_output, key_size);
				if (!status)
					return status;
			}

			if (secret_key_input_output != nullptr)
				return secp256k1_combine_secret_key(&tweak, secret_key_input_output);

			return expectation::met;
		}
		expects_lr<void> secp256k1_compositor::tweak_secret_key(const uint8_t* seed, size_t seed_size, size_t key_size, const algorithm::paillier_scalar_t& accumulator, algorithm::composition::cseckey_t* secret_key_input_output) const
		{
			return secp256k1_accumulator_tweak_secret_key(seed, seed_size, key_size, accumulator, secret_key_input_output);
		}
		expects_lr<void> secp256k1_compositor::combine_public_keys(const algorithm::composition::cpubkey_t* input, algorithm::composition::cpubkey_t* input_output) const
		{
			return secp256k1_combine_public_key(input, input_output);
		}
		expects_lr<void> secp256k1_compositor::derive_secret_key(const uint8_t* seed, size_t seed_size, algorithm::composition::cseckey_t* output) const
		{
			VI_ASSERT(output != nullptr, "output should be set");
			output->resize(sizeof(secp256k1_scalar_t));
			secp256k1_to_private_key(seed, seed_size, output->data());
			return expectation::met;
		}
		expects_lr<void> secp256k1_compositor::derive_public_key(algorithm::composition::cpubkey_t* output) const
		{
			VI_ASSERT(output != nullptr, "output should be set");
			output->resize(sizeof(cumulative_key));
			memcpy(output->data(), cumulative_key.blob, sizeof(cumulative_key));
			return expectation::met;
		}
		expects_lr<void> secp256k1_compositor::derive_signature(algorithm::composition::chashsig_t* output) const
		{
			VI_ASSERT(output != nullptr, "output should be set");
			algorithm::composition::cpubkey_t public_key;
			auto status = derive_public_key(&public_key);
			if (!status)
				return status;

			auto r = from_compressed_point_secp256k1(cumulative_r);
			auto s = from_scalar_secp256k1(cumulative_s);
			uint8_t signature_buffer[64];
			bn_write_be(&r.x, signature_buffer);
			bn_write_be(&s, signature_buffer + 32);
			output->resize(65);

			secp256k1_ecdsa_signature internal_signature;
			secp256k1_context* context = algorithm::signing::get_context();
			if (secp256k1_ecdsa_signature_parse_compact(context, &internal_signature, signature_buffer) != 1)
				return layer_exception("invalid signature");

			secp256k1_ecdsa_signature normalized_signature;
			secp256k1_ecdsa_signature_normalize(context, &normalized_signature, &internal_signature);
			secp256k1_ecdsa_signature_serialize_compact(context, output->data(), &normalized_signature);
			return verify_signature_set_recovery_id(message_hash, sizeof(message_hash), *output, public_key, false);
		}
		expects_lr<void> secp256k1_compositor::verify_signature(const uint8_t* message, size_t message_size, const algorithm::composition::chashsig_t& signature, const algorithm::composition::cpubkey_t& public_key, uint8_t flags) const
		{
			algorithm::composition::chashsig_t copy = signature;
			auto status = verify_signature_set_recovery_id(message, message_size, copy, public_key, flags);
			if (status && copy.back() != signature.back())
				return layer_exception("signature recovers incorrect public key");

			return status;
		}
		expects_lr<void> secp256k1_compositor::verify_signature_set_recovery_id(const uint8_t* message, size_t message_size, algorithm::composition::chashsig_t& signature, const algorithm::composition::cpubkey_t& public_key, uint8_t flags) const
		{
			VI_ASSERT(message != nullptr, "message should be set");
			if (signature.size() != 65)
				return layer_exception("invalid signature");

			uint8_t target_public_key[33];
			secp256k1_context* context = algorithm::signing::get_context();
			if (public_key.size() != sizeof(secp256k1_point_t))
			{
				if (!(flags & (uint8_t)algorithm::composition::verify::user_message) || (public_key.size() != 64 && public_key.size() != 65))
					return layer_exception("invalid public key");

				uint8_t uncompressed_public_key[65];
				if (public_key.size() == 64)
				{
					uncompressed_public_key[0] = 0x04;
					memcpy(uncompressed_public_key + 1, public_key.data(), public_key.size());
				}
				else
					memcpy(uncompressed_public_key, public_key.data(), public_key.size());

				secp256k1_pubkey extended_public_key;
				if (secp256k1_ec_pubkey_parse(context, &extended_public_key, uncompressed_public_key, sizeof(uncompressed_public_key)) != 1)
					return layer_exception("invalid public key");

				size_t target_public_key_size = sizeof(target_public_key);
				if (secp256k1_ec_pubkey_serialize(context, target_public_key, &target_public_key_size, &extended_public_key, SECP256K1_EC_COMPRESSED) != 1)
					return layer_exception("invalid public key");
			}
			else
				memcpy(target_public_key, public_key.data(), public_key.size());

			uint8_t target_message_hash[32];
			if (message_size != sizeof(target_message_hash))
				sha256_Raw(message, message_size, target_message_hash);
			else
				memcpy(target_message_hash, message, sizeof(target_message_hash));

			for (uint8_t recovery_id = 0; recovery_id < 4; recovery_id++)
			{
				secp256k1_ecdsa_recoverable_signature recoverable_signature;
				if (secp256k1_ecdsa_recoverable_signature_parse_compact(context, &recoverable_signature, signature.data(), recovery_id) != 1)
					continue;

				secp256k1_pubkey recovered_public_key;
				if (secp256k1_ecdsa_recover(context, &recovered_public_key, &recoverable_signature, target_message_hash) != 1)
					continue;

				uint8_t possible_public_key[33]; size_t possible_public_key_size = sizeof(target_public_key);
				if (secp256k1_ec_pubkey_serialize(context, possible_public_key, &possible_public_key_size, &recovered_public_key, SECP256K1_EC_COMPRESSED) != 1 || memcmp(target_public_key, possible_public_key, possible_public_key_size) != 0)
					continue;

				secp256k1_ecdsa_signature compact_signature;
				if (secp256k1_ecdsa_signature_parse_compact(context, &compact_signature, signature.data()) != 1)
					break;

				secp256k1_pubkey extended_public_key;
				secp256k1_ecdsa_signature normalized_signature;
				if (secp256k1_ecdsa_signature_normalize(context, &normalized_signature, &compact_signature) != 0)
					return layer_exception("signature must be canonical (S-value not normalized)");

				if (secp256k1_ec_pubkey_parse(context, &extended_public_key, target_public_key, sizeof(target_public_key)) != 1)
					break;

				if (secp256k1_ecdsa_verify(context, &normalized_signature, target_message_hash, &extended_public_key) != 1)
					break;

				signature[signature.size() - 1] = recovery_id;
				return expectation::met;
			}

			return layer_exception("signature verification failed");
		}
		algorithm::composition::type secp256k1_compositor::alg_type() const
		{
			return algorithm::composition::type::secp256k1;
		}
		algorithm::composition::phase secp256k1_compositor::next_phase() const
		{
			if (z_steps == factors.size())
				return algorithm::composition::phase::consume_after_reset;
			else if (z_steps > 0)
				return algorithm::composition::phase::consume;

			if (r_steps == factors.size())
				return algorithm::composition::phase::consume_after_reset;
			else if (r_steps > 0)
				return algorithm::composition::phase::consume;

			if (p_steps == factors.size())
				return algorithm::composition::phase::consume_after_reset;
			else if (p_steps > 0)
				return algorithm::composition::phase::consume;

			if (d_steps == factors.size())
				return algorithm::composition::phase::consume_after_reset;
			else if (d_steps > 0)
				return algorithm::composition::phase::consume;

			if (s_steps == factors.size())
				return algorithm::composition::phase::consume_after_reset;
			else if (s_steps > 0)
				return algorithm::composition::phase::consume;

			return algorithm::composition::phase::finalize;
		}
		uint32_t secp256k1_compositor::steps_left() const
		{
			return z_steps + r_steps + p_steps + d_steps + s_steps;
		}
		bool secp256k1_compositor::store(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(z_steps);
			stream->write_integer(r_steps);
			stream->write_integer(p_steps);
			stream->write_integer(d_steps);
			stream->write_integer(s_steps);
			stream->write_integer(p_bits);
			stream->write_string(cumulative_key.optimized_view());
			stream->write_string(cumulative_r.optimized_view());
			stream->write_string(cumulative_s.optimized_view());
			stream->write_string(std::string_view((char*)message_hash, sizeof(message_hash)));
			stream->write_integer((uint16_t)factors.size());
			for (auto& factor : factors)
			{
				stream->write_integer(factor.k_index);
				stream->write_string(std::string_view((char*)factor.public_key.data(), factor.public_key.size()));
				stream->write_string(std::string_view((char*)factor.cumulative_x.data(), factor.cumulative_x.size()));
				stream->write_string(std::string_view((char*)factor.cumulative_x_d.data(), factor.cumulative_x_d.size()));
				stream->write_string(std::string_view((char*)factor.cumulative_y.data(), factor.cumulative_y.size()));
				stream->write_string(std::string_view((char*)factor.cumulative_y_d.data(), factor.cumulative_y_d.size()));
			}
			return true;
		}
		bool secp256k1_compositor::load(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &z_steps))
				return false;

			if (!stream.read_integer(stream.read_type(), &r_steps))
				return false;

			if (!stream.read_integer(stream.read_type(), &p_steps))
				return false;

			if (!stream.read_integer(stream.read_type(), &d_steps))
				return false;

			if (!stream.read_integer(stream.read_type(), &s_steps))
				return false;

			if (!stream.read_integer(stream.read_type(), &p_bits))
				return false;

			if (!stream.read_optimized_view(stream.read_type(), cumulative_key.blob, sizeof(cumulative_key)))
				return false;

			if (!stream.read_optimized_view(stream.read_type(), cumulative_r.blob, sizeof(cumulative_r)))
				return false;

			if (!stream.read_optimized_view(stream.read_type(), cumulative_s.blob, sizeof(cumulative_s)))
				return false;

			if (!stream.read_view(stream.read_type(), message_hash, sizeof(message_hash)))
				return false;

			uint16_t factors_size;
			if (!stream.read_integer(stream.read_type(), &factors_size))
				return false;

			factors.resize(factors_size);
			for (uint16_t i = 0; i < factors_size; i++)
			{
				auto& factor = factors[i];
				if (!stream.read_integer(stream.read_type(), &factor.k_index))
					return false;

				string intermediate;
				if (!stream.read_string(stream.read_type(), &intermediate))
					return false;

				factor.public_key.resize(intermediate.size());
				memcpy(factor.public_key.data(), intermediate.data(), intermediate.size());
				if (!stream.read_string(stream.read_type(), &intermediate))
					return false;

				factor.cumulative_x.resize(intermediate.size());
				memcpy(factor.cumulative_x.data(), intermediate.data(), intermediate.size());
				if (!stream.read_string(stream.read_type(), &intermediate))
					return false;

				factor.cumulative_x_d.resize(intermediate.size());
				memcpy(factor.cumulative_x_d.data(), intermediate.data(), intermediate.size());
				if (!stream.read_string(stream.read_type(), &intermediate))
					return false;

				factor.cumulative_y.resize(intermediate.size());
				memcpy(factor.cumulative_y.data(), intermediate.data(), intermediate.size());
				if (!stream.read_string(stream.read_type(), &intermediate))
					return false;

				factor.cumulative_y_d.resize(intermediate.size());
				memcpy(factor.cumulative_y_d.data(), intermediate.data(), intermediate.size());
			}

			return true;
		}
		bool secp256k1_compositor::may_transition_to(const compositor& next_ptr) const
		{
			auto* next = (const secp256k1_compositor*)&next_ptr;
			if (factors.size() != next->factors.size() || p_bits != next->p_bits || memcmp(message_hash, next->message_hash, sizeof(message_hash)) != 0)
				return false;

			if ((z_steps == next->z_steps) != cumulative_key.equals(next->cumulative_key))
				return false;

			if ((r_steps == next->r_steps) != cumulative_r.equals(next->cumulative_r))
				return false;

			for (size_t i = 0; i < factors.size(); i++)
			{
				auto& prev_factor = factors[i];
				auto& next_factor = factors[i];
				if (prev_factor.public_key != next_factor.public_key && !prev_factor.public_key.empty() && !next_factor.public_key.empty())
					return false;

				if (prev_factor.cumulative_x != next_factor.cumulative_x && !prev_factor.cumulative_x.empty() && !next_factor.cumulative_x.empty())
					return false;

				if (prev_factor.cumulative_x_d != next_factor.cumulative_x_d && !prev_factor.cumulative_x_d.empty() && !next_factor.cumulative_x_d.empty())
					return false;

				if (prev_factor.cumulative_y != next_factor.cumulative_y && !prev_factor.cumulative_y.empty() && !next_factor.cumulative_y.empty())
					return false;

				if (prev_factor.cumulative_y_d != next_factor.cumulative_y_d && !prev_factor.cumulative_y_d.empty() && !next_factor.cumulative_y_d.empty())
					return false;

				if (prev_factor.k_index != next_factor.k_index && prev_factor.k_index > 0)
					return false;
			}

			return steps_left() >= next->steps_left();
		}

		expects_lr<void> secp256k1_schnorr_compositor::setup_public_key(const uint8_t* new_message, size_t new_message_size, uint16_t new_participants)
		{
			algorithm::composition::cpubkey_t temp_public_key;
			temp_public_key.resize(sizeof(secp256k1_point_t));
			auto status = setup_signature(temp_public_key, new_message, new_message_size, nullptr, new_participants);
			if (!status)
				return status.error();

			z_steps = new_participants;
			cumulative_key.clear();
			return expectation::met;
		}
		expects_lr<void> secp256k1_schnorr_compositor::setup_signature(const algorithm::composition::cpubkey_t& new_public_key, const uint8_t* new_message, size_t new_message_size, const algorithm::composition::shared_message* new_shared, uint16_t new_participants)
		{
			VI_ASSERT(new_message != nullptr, "message should be set");
			if (new_public_key.size() != sizeof(cumulative_key) && new_public_key.size() != sizeof(cumulative_key) + sizeof(group_public_key_tweak))
				return layer_exception("invalid public key size");

			if (new_message_size != sizeof(message_hash))
				sha256_Raw(new_message, new_message_size, message_hash);
			else
				memcpy(message_hash, new_message, sizeof(message_hash));

			indices.clear();
			indices.resize((size_t)new_participants, uint256_t((uint8_t)0));
			cumulative_r = secp256k1_point_t();
			cumulative_s = secp256k1_scalar_t();
			z_steps = 0; r_steps = s_steps = new_participants;
			cumulative_key = std::string_view((char*)new_public_key.data(), sizeof(cumulative_key));
			group_public_key_tweak = std::string_view((char*)new_public_key.data() + sizeof(cumulative_key), new_public_key.size() - sizeof(cumulative_key));
			return expectation::met;
		}
		expects_lr<void> secp256k1_schnorr_compositor::aggregate(const algorithm::composition::cseckey_t& secret_key)
		{
			if (secret_key.size() != sizeof(secp256k1_scalar_t))
				return layer_exception("invalid secret key size");

			auto use_nonce = [](bignum256* k, const uint8_t message_hash[32], const secp256k1_point_t& public_key, const algorithm::composition::cseckey_t& secret_key, const uint256_t& index) -> bool
			{
				uint8_t index_nonce[32];
				index.encode(index_nonce);

				uint8_t ask[32];
				sha256_Raw(secret_key.data(), secret_key.size(), ask);

				uint8_t bip340_algo[] = "BIP0340/nonce", nonce[32];
				if (secp256k1_nonce_function_bip340(nonce, message_hash, 32, ask, public_key.blob + 1, bip340_algo, sizeof(bip340_algo) - 1, index_nonce) != 1)
					return false;

				bn_read_be(nonce, k);
				bn_mod(k, &secp256k1.order);
				return true;
			};
			auto use_challenge = [](bignum256* e, const curve_point& r, const uint8_t message_hash[32], const secp256k1_point_t& public_key) -> bool
			{
				uint8_t data[96];
				bn_write_be(&r.x, data);
				memcpy(data + 32, public_key.blob + 1, 32);
				memcpy(data + 64, message_hash, 32);

				uint8_t bip340_challenge[] = "BIP0340/challenge", challenge[32];
				secp256k1_context* context = algorithm::signing::get_context();
				if (secp256k1_tagged_sha256(context, challenge, bip340_challenge, sizeof(bip340_challenge) - 1, data, sizeof(data)) != 1)
					return false;

				bn_read_be(challenge, e);
				bn_mod(e, &secp256k1.order);
				return !bn_is_zero(e);
			};
			if (z_steps > 0)
			{
				secp256k1_context* context = algorithm::signing::get_context();
				if (secp256k1_ec_seckey_verify(context, secret_key.data()) != 1)
					return layer_exception("invalid secret key scalar");

				secp256k1_pubkey next_public_key;
				if (secp256k1_ec_pubkey_create(context, &next_public_key, secret_key.data()) != 1)
					return layer_exception("invalid secret key");

				if (cumulative_key.empty())
				{
					size_t key_size = sizeof(cumulative_key);
					if (secp256k1_ec_pubkey_serialize(context, cumulative_key.blob, &key_size, &next_public_key, SECP256K1_EC_COMPRESSED) != 1)
						return layer_exception("invalid secret key");
				}
				else
				{
					secp256k1_pubkey prev_public_key, result_public_key;
					if (secp256k1_ec_pubkey_parse(context, &prev_public_key, cumulative_key.blob, sizeof(cumulative_key)) != 1)
						return layer_exception("invalid intermediate public key");

					secp256k1_pubkey* public_keys[2] = { &prev_public_key, &next_public_key };
					if (secp256k1_ec_pubkey_combine(context, &result_public_key, public_keys, 2) != 1)
						return layer_exception("invalid secret key");

					size_t key_size = sizeof(cumulative_key);
					if (secp256k1_ec_pubkey_serialize(context, cumulative_key.blob, &key_size, &result_public_key, SECP256K1_EC_COMPRESSED) != 1)
						return layer_exception("invalid secret key");
				}

				--z_steps;
			}
			else if (r_steps > 0)
			{
				if (r_steps > indices.size())
					return layer_exception("invalid compositor state");

			retry_nonce:
				bignum256 k;
				uint256_t& index = indices[r_steps - 1];
				if (!use_nonce(&k, message_hash, cumulative_key, secret_key, ++index))
					goto retry_nonce;

				curve_point r;
				memset(&r, 0, sizeof(r));
				if (scalar_multiply(&secp256k1, &k, &r) != 0)
					goto retry_nonce;

				bn_mod(&r.x, &secp256k1.order);
				if (point_is_infinity(&r) || bn_is_zero(&r.x) || bn_is_odd(&r.y))
					goto retry_nonce;

				if (!cumulative_r.empty())
				{
					curve_point prev_r = from_compressed_point_secp256k1(cumulative_r);
					point_add(&secp256k1, &prev_r, &r);
					if (point_is_infinity(&r) || bn_is_zero(&r.x) || bn_is_odd(&r.y))
						goto retry_nonce;
				}

				bignum256 e;
				if (!use_challenge(&e, r, message_hash, cumulative_key))
					goto retry_nonce;

				cumulative_r = to_compressed_point_secp256k1(r);
				--r_steps;
			}
			else if (s_steps > 0)
			{
				if (cumulative_r.empty() || s_steps > indices.size())
					return layer_exception("invalid compositor state");

				uint8_t null[32] = { 0 };
				if (!memcmp(message_hash, null, sizeof(null)))
					return layer_exception("bad message");

				bignum256 e;
				curve_point r = from_compressed_point_secp256k1(cumulative_r);
				if (!use_challenge(&e, r, message_hash, cumulative_key))
					return layer_exception("invalid public r");

				bignum256 k;
				if (!use_nonce(&k, message_hash, cumulative_key, secret_key, indices[s_steps - 1]))
					return layer_exception("invalid private k");

				bignum256 s;
				bn_read_be(secret_key.data(), &s);
				if (s_steps == 1 && !group_public_key_tweak.empty())
				{
					bignum256 t;
					bn_read_be(group_public_key_tweak.blob, &t);
					bn_addmod(&s, &t, &secp256k1.order);
					if (bn_is_zero(&s))
						return layer_exception("invalid taproot tweak");
				}
				bn_cnegate(cumulative_key.blob[0] == SECP256K1_TAG_PUBKEY_ODD, &s, &secp256k1.order);
				bn_mod(&s, &secp256k1.order);
				bn_multiply(&e, &s, &secp256k1.order);
				bn_addmod(&s, &k, &secp256k1.order);
				if (bn_is_zero(&s))
					return layer_exception("invalid s");

				if (!cumulative_s.empty())
				{
					bignum256 prev_s = from_scalar_secp256k1(cumulative_s);
					bn_addmod(&s, &prev_s, &secp256k1.order);
					if (bn_is_zero(&s))
						return layer_exception("invalid cumulative s");
				}

				cumulative_s = to_scalar_secp256k1(s);
				--s_steps;
			}
			return expectation::met;
		}
		expects_lr<void> secp256k1_schnorr_compositor::derive_tweaking_key(const uint8_t* seed, size_t seed_size, size_t key_size, algorithm::paillier_scalar_t* public_key) const
		{
			paillier_to_public_key(seed, seed_size, key_size, public_key);
			return expectation::met;
		}
		expects_lr<void> secp256k1_schnorr_compositor::tweak_secret_key(const algorithm::paillier_scalar_t& public_key, size_t key_size, const algorithm::composition::cseckey_t& tweak, algorithm::composition::cseckey_t* secret_key_input_output, algorithm::paillier_scalar_t* accumulator_output) const
		{
			if (accumulator_output != nullptr)
			{
				auto status = paillier_accumulate_tweak(public_key, tweak, accumulator_output, key_size);
				if (!status)
					return status;
			}

			if (secret_key_input_output != nullptr)
				return secp256k1_combine_secret_key(&tweak, secret_key_input_output);

			return expectation::met;
		}
		expects_lr<void> secp256k1_schnorr_compositor::tweak_secret_key(const uint8_t* seed, size_t seed_size, size_t key_size, const algorithm::paillier_scalar_t& accumulator, algorithm::composition::cseckey_t* secret_key_input_output) const
		{
			return secp256k1_accumulator_tweak_secret_key(seed, seed_size, key_size, accumulator, secret_key_input_output);
		}
		expects_lr<void> secp256k1_schnorr_compositor::combine_public_keys(const algorithm::composition::cpubkey_t* input, algorithm::composition::cpubkey_t* input_output) const
		{
			return secp256k1_combine_public_key(input, input_output);
		}
		expects_lr<void> secp256k1_schnorr_compositor::derive_secret_key(const uint8_t* seed, size_t seed_size, algorithm::composition::cseckey_t* output) const
		{
			VI_ASSERT(output != nullptr, "output should be set");
			output->resize(sizeof(secp256k1_scalar_t));
			secp256k1_to_private_key(seed, seed_size, output->data());
			return expectation::met;
		}
		expects_lr<void> secp256k1_schnorr_compositor::derive_public_key(algorithm::composition::cpubkey_t* output) const
		{
			VI_ASSERT(output != nullptr, "output should be set");
			output->resize(sizeof(cumulative_key));
			memcpy(output->data(), cumulative_key.blob, sizeof(cumulative_key));
			return expectation::met;
		}
		expects_lr<void> secp256k1_schnorr_compositor::derive_signature(algorithm::composition::chashsig_t* output) const
		{
			VI_ASSERT(output != nullptr, "output should be set");
			algorithm::composition::cpubkey_t public_key;
			auto status = derive_public_key(&public_key);
			if (!status)
				return status;

			output->resize(64);
			auto r = from_compressed_point_secp256k1(cumulative_r);
			auto s = from_scalar_secp256k1(cumulative_s);
			bn_write_be(&r.x, output->data());
			bn_write_be(&s, output->data() + 32);
			return verify_signature(message_hash, sizeof(message_hash), *output, public_key);
		}
		expects_lr<void> secp256k1_schnorr_compositor::verify_signature(const uint8_t* message, size_t message_size, const algorithm::composition::chashsig_t& signature, const algorithm::composition::cpubkey_t& public_key, uint8_t flags) const
		{
			VI_ASSERT(message != nullptr, "message should be set");
			if (public_key.size() != sizeof(secp256k1_point_t) && public_key.size() != sizeof(cumulative_key) + sizeof(group_public_key_tweak))
				return layer_exception("invalid public key");

			if (signature.size() != 64)
				return layer_exception("invalid signature");

			uint8_t target_message_hash[32] = { 0 };
			if (message_size != sizeof(target_message_hash))
				sha256_Raw(message, message_size, target_message_hash);
			else
				memcpy(target_message_hash, message, sizeof(target_message_hash));

			secp256k1_context* context = algorithm::signing::get_context();
			secp256k1_xonly_pubkey xonly_public_key;
			if (secp256k1_xonly_pubkey_parse(context, &xonly_public_key, public_key.data() + 1) != 1)
				return layer_exception("invalid public key");

			if (secp256k1_schnorrsig_verify(context, signature.data(), target_message_hash, sizeof(target_message_hash), &xonly_public_key) != 1)
				return layer_exception("signature verification failed");

			return expectation::met;
		}
		algorithm::composition::type secp256k1_schnorr_compositor::alg_type() const
		{
			return algorithm::composition::type::secp256k1_schnorr;
		}
		algorithm::composition::phase secp256k1_schnorr_compositor::next_phase() const
		{
			if (z_steps == indices.size())
				return algorithm::composition::phase::consume_after_reset;
			else if (z_steps > 0)
				return algorithm::composition::phase::consume;

			if (r_steps == indices.size())
				return algorithm::composition::phase::consume_after_reset;
			else if (r_steps > 0)
				return algorithm::composition::phase::consume;

			if (s_steps == indices.size())
				return algorithm::composition::phase::consume_after_reset;
			else if (s_steps > 0)
				return algorithm::composition::phase::consume;

			return algorithm::composition::phase::finalize;
		}
		uint32_t secp256k1_schnorr_compositor::steps_left() const
		{
			return z_steps + r_steps + s_steps;
		}
		bool secp256k1_schnorr_compositor::store(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(z_steps);
			stream->write_integer(r_steps);
			stream->write_integer(s_steps);
			stream->write_integer((uint16_t)indices.size());
			for (auto& index : indices)
				stream->write_integer(index);
			stream->write_string(cumulative_r.optimized_view());
			stream->write_string(cumulative_s.optimized_view());
			stream->write_string(cumulative_key.optimized_view());
			stream->write_string(group_public_key_tweak.optimized_view());
			stream->write_string(std::string_view((char*)message_hash, sizeof(message_hash)));
			return true;
		}
		bool secp256k1_schnorr_compositor::load(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &z_steps))
				return false;

			if (!stream.read_integer(stream.read_type(), &r_steps))
				return false;

			if (!stream.read_integer(stream.read_type(), &s_steps))
				return false;

			uint32_t indices_size;
			if (!stream.read_integer(stream.read_type(), &indices_size))
				return false;

			indices.resize(indices_size);
			for (uint32_t i = 0; i < indices_size; i++)
			{
				if (!stream.read_integer(stream.read_type(), &indices[i]))
					return false;
			}

			if (!stream.read_optimized_view(stream.read_type(), cumulative_r.blob, sizeof(cumulative_r)))
				return false;

			if (!stream.read_optimized_view(stream.read_type(), cumulative_s.blob, sizeof(cumulative_s)))
				return false;

			if (!stream.read_optimized_view(stream.read_type(), cumulative_key.blob, sizeof(cumulative_key)))
				return false;

			if (!stream.read_optimized_view(stream.read_type(), group_public_key_tweak.blob, sizeof(group_public_key_tweak)))
				return false;

			string intermediate;
			if (!stream.read_string(stream.read_type(), &intermediate) || intermediate.size() != sizeof(message_hash))
				return false;

			memcpy(message_hash, intermediate.data(), intermediate.size());
			return true;
		}
		bool secp256k1_schnorr_compositor::may_transition_to(const compositor& next_ptr) const
		{
			auto* next = (const secp256k1_schnorr_compositor*)&next_ptr;
			if (indices.size() != next->indices.size() || memcmp(message_hash, next->message_hash, sizeof(message_hash)) != 0 || !group_public_key_tweak.equals(next->group_public_key_tweak))
				return false;

			if ((z_steps == next->z_steps) != cumulative_key.equals(next->cumulative_key))
				return false;

			if ((r_steps == next->r_steps) != cumulative_r.equals(next->cumulative_r))
				return false;

			if ((s_steps == next->s_steps) != cumulative_s.equals(next->cumulative_s))
				return false;

			if (r_steps == next->r_steps && s_steps == next->s_steps && indices != next->indices)
				return false;

			if (r_steps > indices.size() || next->r_steps > next->indices.size())
				return false;

			if (s_steps > indices.size() || next->s_steps > next->indices.size())
				return false;

			return steps_left() >= next->steps_left();
		}
		expects_lr<algorithm::composition::cpubkey_t> secp256k1_schnorr_compositor::to_tweaked_public_key(const secp256k1_point_t& public_key, const secp256k1_scalar_t& tweak)
		{
			secp256k1_context* context = algorithm::signing::get_context();
			secp256k1_pubkey extended_public_key;
			if (secp256k1_ec_pubkey_parse(context, &extended_public_key, public_key.blob, sizeof(public_key.blob)) != 1)
				return layer_exception("invalid public key");

			if (secp256k1_ec_pubkey_tweak_add(context, &extended_public_key, tweak.blob) != 1)
				return layer_exception("invalid public key tweak");

			size_t result_size = sizeof(public_key.blob);
			auto result = algorithm::composition::cpubkey_t(result_size + sizeof(tweak.blob), 0);
			if (!secp256k1_ec_pubkey_serialize(context, result.data(), &result_size, &extended_public_key, SECP256K1_EC_COMPRESSED))
				return layer_exception("invalid tweaked public key");

			memcpy(result.data() + sizeof(public_key.blob), tweak.blob, sizeof(tweak.blob));
			return expects_lr<algorithm::composition::cpubkey_t>(std::move(result));
		}
	}
}