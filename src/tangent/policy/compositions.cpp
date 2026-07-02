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

			const uint32_t small_prime_numbers[] = { 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97 };
			for (uint32_t prime : small_prime_numbers)
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
			paillier_encrypt(ciphertext_tweak, plaintext_tweak, &paillier_public_key);
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
			cumulative_r = ed25519_point_t();
			cumulative_s = ed25519_scalar_t();
			z_steps = 0;
			r_steps = s_steps = participants = new_participants;
			cumulative_key = std::string_view((char*)new_public_key.data(), new_public_key.size());
			message.resize(new_message_size);
			memcpy(message.data(), new_message, new_message_size);
			return expectation::met;
		}
		expects_lr<void> ed25519_compositor::aggregate(const algorithm::composition::cseckey_t& secret_key)
		{
			if (secret_key.size() != sizeof(ed25519_scalar_t))
				return layer_exception("invalid secret key size");

			auto calculate_nonce = [](uint8_t nonce[64], const vector<uint8_t>& message, const algorithm::composition::cseckey_t& secret_key, const uint256_t& index)
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
				indices.push_back(0);
			retry_nonce:
				uint8_t nonce[64];
				uint256_t& index = indices.back();
				calculate_nonce(nonce, message, secret_key, ++index);

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
				if (cumulative_r.empty() || indices.empty())
					return layer_exception("invalid compositor state");

				uint8_t nonce[64];
				calculate_nonce(nonce, message, secret_key, indices.front());
				indices.erase(indices.begin());

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
		expects_lr<void> ed25519_compositor::verify_signature(const uint8_t* new_message, size_t new_message_size, const algorithm::composition::chashsig_t& signature, const algorithm::composition::cpubkey_t& public_key) const
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
			if (z_steps == participants)
				return algorithm::composition::phase::any_input_after_reset;
			else if (z_steps > 0)
				return algorithm::composition::phase::any_input;

			if (r_steps == participants)
				return algorithm::composition::phase::any_input_after_reset;
			else if (r_steps > 0)
				return algorithm::composition::phase::any_input;

			if (s_steps == participants)
				return algorithm::composition::phase::any_input_after_reset;
			else if (s_steps > 0)
				return algorithm::composition::phase::any_input;

			return algorithm::composition::phase::finalized;
		}
		uint32_t ed25519_compositor::steps_left() const
		{
			return z_steps + r_steps + s_steps;
		}
		bool ed25519_compositor::store(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(participants);
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
			if (!stream.read_integer(stream.read_type(), &participants))
				return false;

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

			string intermediate;
			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, cumulative_r.blob, sizeof(cumulative_r)))
				return false;

			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, cumulative_s.blob, sizeof(cumulative_s)))
				return false;


			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, cumulative_key.blob, sizeof(cumulative_key)))
				return false;

			if (!stream.read_string(stream.read_type(), &intermediate))
				return false;

			message.resize(intermediate.size());
			memcpy(message.data(), intermediate.data(), intermediate.size());
			return true;
		}
		bool ed25519_compositor::may_transition_to(const compositor& next_ptr) const
		{
			auto* next = (const ed25519_compositor*)&next_ptr;
			if (participants != next->participants || message != next->message)
				return false;

			if ((z_steps == next->z_steps) != cumulative_key.equals(next->cumulative_key))
				return false;

			if ((r_steps == next->r_steps) != cumulative_r.equals(next->cumulative_r))
				return false;

			if (r_steps == next->r_steps && s_steps == next->s_steps && indices != next->indices)
				return false;

			if (r_steps != next->r_steps && indices.size() >= next->indices.size())
				return false;

			if (s_steps != next->s_steps && indices.size() <= next->indices.size())
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

			uint8_t vin_size;
			if (!stream.read_integer(stream.read_type(), &vin_size))
				return false;

			vin.clear();
			for (uint8_t i = 0; i < vin_size; i++)
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

			uint8_t vout_size;
			if (!stream.read_integer(stream.read_type(), &vout_size))
				return false;

			vout.clear();
			for (uint8_t i = 0; i < vout_size; i++)
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
			if (!public_key.empty() && public_key.size() != sizeof(ed25519_point_t))
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

			z_steps = public_key.empty() ? new_participants : 0;
			cumulative_key = public_key;
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

			auto calculate_nonce = [&](const clsag_message::txin_to_key& vin, uint8_t a_i[32])
			{
				uint8_t seed_buffer[128], message_hash[32];
				message.as_prefix_hash(seed_buffer);
				memcpy(seed_buffer + sizeof(vin.key_image) * 1, vin.key_image, sizeof(vin.key_image));
				memcpy(seed_buffer + sizeof(vin.key_image) * 2, secret_key.data(), sizeof(vin.key_image));
				memcpy(seed_buffer + sizeof(vin.key_image) * 3, vin.pseudo_out.mask, sizeof(vin.pseudo_out.mask));
				xmr_fast_hash(message_hash, seed_buffer, sizeof(seed_buffer));

				uint256_t index = 0;
				while (true)
				{
					uint8_t index_nonce[32];
					index.encode(index_nonce);
					++index;

					uint8_t ask[32], nonce[32];
					sha256_Raw(secret_key.data(), secret_key.size(), ask);
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
				calculate_nonce(vin, a_i);
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
				calculate_nonce(vin, a_i);
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
		expects_lr<void> ed25519_clsag_compositor::verify_signature(const uint8_t* new_message, size_t new_message_size, const algorithm::composition::chashsig_t& signature, const algorithm::composition::cpubkey_t& public_key) const
		{
			VI_ASSERT(new_message != nullptr, "message should be set");
			if (!public_key.empty() && public_key.size() != sizeof(ed25519_point_t))
				return layer_exception("invalid public key");

			if (vin_index < message.vin.size() && sc_isnonzero(message.vin[vin_index].key_image) == 0)
			{
				if (signature.size() != sizeof(ed25519_point_t) || signature.empty())
					return layer_exception("invalid key image");

				return expectation::met;
			}

			clsag_message pseudo_message; uint16_t pseudo_index = vin_index;
			if (new_message_size != sizeof(ed25519_point_t))
			{
				format::ro_stream signable = format::ro_stream(std::string_view((char*)new_message, new_message_size));
				if (!pseudo_message.load(signable) || pseudo_index >= pseudo_message.vin.size())
					return layer_exception("failed to load the message");

				const auto& vin = pseudo_message.vin[pseudo_index];
				size_t n = vin.keys.size();
				size_t offset = sizeof(vin.key_image) * 2 + sizeof(vin.clsag.c1) + sizeof(vin.clsag.d);
				size_t size = offset + sizeof(std::array<uint8_t, 32>) * n;
				if (signature.size() != size || vin.clsag.s.size() != n)
					return layer_exception("invalid signature size");

				auto ring_member = std::find_if(vin.keys.begin(), vin.keys.end(), [](const clsag_message::txin_to_key::ref& r) { return !r.decoy; });
				if (ring_member == vin.keys.end())
					return layer_exception("invalid key index");

				if (memcmp(ring_member->key, signature.data(), sizeof(ring_member->key)) != 0)
					return layer_exception("invalid key constant");
				else if (memcmp(vin.key_image, signature.data() + 32, sizeof(vin.key_image)) != 0)
					return layer_exception("invalid key image constant");
				else if (memcmp(vin.clsag.c1, signature.data() + 64, sizeof(vin.clsag.c1)) != 0 || sc_valid(vin.clsag.c1) == 0)
					return layer_exception("invalid c1 constant");
				else if (memcmp(vin.clsag.d, signature.data() + 96, sizeof(vin.clsag.d)) != 0)
					return layer_exception("invalid d constant");

				for (size_t i = 0; i < n; i++)
				{
					if (memcmp(vin.clsag.s[i].data(), signature.data() + offset + i * sizeof(std::array<uint8_t, 32>), sizeof(std::array<uint8_t, 32>)) != 0 || sc_valid(vin.clsag.s[i].data()) == 0)
						return layer_exception("invalid s constant");
				}
			}
			else
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
				return algorithm::composition::phase::any_input_after_reset;
			else if (z_steps > 0)
				return algorithm::composition::phase::any_input;

			if (i_steps == participants)
				return algorithm::composition::phase::any_input_after_reset;
			else if (i_steps > 0)
				return algorithm::composition::phase::any_input;

			if (a_steps == participants)
				return algorithm::composition::phase::any_input_after_reset;
			else if (a_steps > 0)
				return algorithm::composition::phase::any_input;

			if (s_steps == participants)
				return algorithm::composition::phase::any_input_after_reset;
			else if (s_steps > 0)
				return algorithm::composition::phase::any_input;

			return algorithm::composition::phase::finalized;
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
			string intermediate;
			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, cumulative_key.blob, sizeof(cumulative_key)))
				return false;

			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, cumulative_I.blob, sizeof(cumulative_I)))
				return false;

			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, cumulative_aH.blob, sizeof(cumulative_aH)))
				return false;

			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, cumulative_aG.blob, sizeof(cumulative_aG)))
				return false;

			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, cumulative_c_mu_P.blob, sizeof(cumulative_c_mu_P)))
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

			uint16_t min_bits = 2048;
			uint16_t max_bits = 8192;
			uint16_t step_bits = 256;
			additions = new_participants;
			multiplications = std::min<uint16_t>(additions, 1 + (uint16_t)std::floor((double)(max_bits - step_bits - additions - 1) / (double)step_bits));

			uint16_t key_bits = (uint16_t)(std::ceil((double)std::max<uint16_t>(min_bits, std::min<uint16_t>(max_bits, 1 + additions + step_bits + step_bits * (multiplications - 1))) / 8.0) * 8.0);
			VI_ASSERT(multiplications == additions, "nonce randomness reduction caused by too many participants (security risk)");
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

			indices.clear();
			cumulative_r = secp256k1_point_t();
			cumulative_s = secp256k1_scalar_t();
			cumulative_i.clear();
			encryption_key.clear();
			z_steps = 0;
			r_steps = multiplications;
			i_steps = additions;
			s_steps = multiplications;
			p_bits = key_bits;
			return expectation::met;
		}
		expects_lr<void> secp256k1_compositor::aggregate(const algorithm::composition::cseckey_t& secret_key)
		{
			if (secret_key.size() != sizeof(secp256k1_scalar_t))
				return layer_exception("invalid secret key size");

			auto calculate_nonce = [](bignum256* k, const uint8_t message_hash[32], const algorithm::composition::cseckey_t& secret_key, const uint256_t& index) -> bool
			{
				uint8_t index_nonce[32];
				index.encode(index_nonce);

				uint8_t ask[32], nonce[32];
				sha256_Raw(secret_key.data(), secret_key.size(), ask);
				if (secp256k1_nonce_function_rfc6979(nonce, message_hash, ask, nullptr, index_nonce, 0) != 1)
					return false;

				bn_read_be(nonce, k);
				bn_mod(k, &secp256k1.order);
				return true;
			};
			auto calculate_paillier_keypair = [](paillier_pubkey* public_key, paillier_seckey* private_key, uint16_t bits, const algorithm::composition::cseckey_t& secret_key, const bignum256* k)
			{
				uint8_t message[64];
				memcpy(message + 00, secret_key.data(), 32);
				bn_write_be(k, message + 32);
				paillier_keypair_derive(public_key, private_key, bits, message, sizeof(message));
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
				indices.push_back(0);
			retry_nonce:
				bignum256 k;
				uint256_t& index = indices.back();
				if (!calculate_nonce(&k, message_hash, secret_key, ++index))
					goto retry_nonce;

				curve_point r;
				memset(&r, 0, sizeof(r));
				if (cumulative_r.empty())
				{
					if (scalar_multiply(&secp256k1, &k, &r) != 0)
						goto retry_nonce;
				}
				else
				{
					curve_point prev_r = from_compressed_point_secp256k1(cumulative_r);
					point_multiply(&secp256k1, &k, &prev_r, &r);
				}

				bn_inverse(&k, &secp256k1.order);
				if (bn_is_zero(&k))
					goto retry_nonce;

				bn_mod(&r.x, &secp256k1.order);
				if (point_is_infinity(&r) || bn_is_zero(&r.x))
					goto retry_nonce;

				cumulative_r = to_compressed_point_secp256k1(r);
				if (!--r_steps)
				{
					paillier_seckey paillier_secret_key;
					paillier_pubkey paillier_public_key;
					paillier_seckey_init(&paillier_secret_key);
					paillier_pubkey_init(&paillier_public_key);
					calculate_paillier_keypair(&paillier_public_key, &paillier_secret_key, p_bits, secret_key, &k);
					paillier_store_public_key(&paillier_public_key, &encryption_key);
					paillier_pubkey_clear(&paillier_public_key);
					paillier_seckey_clear(&paillier_secret_key);
				}
			}
			else if (i_steps > 0)
			{
				if (cumulative_r.empty() || encryption_key.empty())
					return layer_exception("invalid compositor state");

				bignum256 n = { 0 };
				bn_read_uint32(additions, &n);
				bn_inverse(&n, &secp256k1.order);

				bignum256 z = { 0 };
				bn_read_be(message_hash, &z);
				bn_multiply(&n, &z, &secp256k1.order);
				if (bn_is_zero(&z))
					return layer_exception("bad message");

				paillier_pubkey paillier_public_key;
				paillier_pubkey_init(&paillier_public_key);

				auto key_status = paillier_load_public_key(encryption_key, &paillier_public_key, p_bits);
				if (!key_status)
					return layer_exception("invalid group paillier key: " + key_status.what());

				curve_point r = from_compressed_point_secp256k1(cumulative_r);
				bignum256 i;
				bn_read_be(secret_key.data(), &i);
				bn_multiply(&r.x, &i, &secp256k1.order);
				bn_addmod(&i, &z, &secp256k1.order);

				uint8_t i_buffer[32];
				bn_write_be(&i, i_buffer);

				mpz_t partial_plaintext_i;
				mpz_init(partial_plaintext_i);
				if (!mpz_import_buffer(i_buffer, sizeof(i_buffer), partial_plaintext_i))
				{
					mpz_clear(partial_plaintext_i);
					return layer_exception("invalid i");
				}

				mpz_t partial_i;
				mpz_init(partial_i);
				paillier_encrypt(partial_i, partial_plaintext_i, &paillier_public_key);
				mpz_clear(partial_plaintext_i);

				auto result = string();
				if (!cumulative_i.empty())
				{
					mpz_t prev_i;
					mpz_init(prev_i);
					if (!mpz_import_buffer(cumulative_i.data(), cumulative_i.size(), prev_i))
					{
						mpz_clear(prev_i);
						mpz_clear(partial_i);
						return layer_exception("invalid cumulative i");
					}

					mpz_t next_i;
					mpz_init(next_i);
					paillier_homomorphic_add(next_i, prev_i, partial_i, &paillier_public_key);
					result = mpz_export_buffer(next_i);
					mpz_clear(next_i);
					mpz_clear(prev_i);
				}
				else
					result = mpz_export_buffer(partial_i);

				cumulative_i.resize(result.size());
				memcpy(cumulative_i.data(), result.data(), result.size());
				paillier_pubkey_clear(&paillier_public_key);
				mpz_clear(partial_i);
				--i_steps;
			}
			else if (s_steps > 0)
			{
				if (cumulative_i.empty() || encryption_key.empty() || indices.empty())
					return layer_exception("invalid compositor state");

				bignum256 k;
				if (!calculate_nonce(&k, message_hash, secret_key, indices.front()))
					return layer_exception("invalid private k");

				bn_inverse(&k, &secp256k1.order);
				if (bn_is_zero(&k))
					return layer_exception("invalid private k inverse");

				paillier_pubkey paillier_public_key;
				paillier_pubkey_init(&paillier_public_key);
				indices.erase(indices.begin());
				if (--s_steps > 0)
				{
					auto key_status = paillier_load_public_key(encryption_key, &paillier_public_key, p_bits);
					if (!key_status)
						return layer_exception("invalid group key: " + key_status.what());

					uint8_t k_buffer[32] = { 0 };
					bn_write_be(&k, k_buffer);

					mpz_t prev_i, partial_k;
					mpz_init(prev_i);
					mpz_init(partial_k);
					if (!mpz_import_buffer(k_buffer, sizeof(k_buffer), partial_k) || !mpz_import_buffer(cumulative_i.data(), cumulative_i.size(), prev_i))
					{
						mpz_clear(prev_i);
						mpz_clear(partial_k);
						return layer_exception("invalid partial k or i");
					}

					mpz_t next_i;
					mpz_init(next_i);
					paillier_homomorphic_mulc(next_i, prev_i, partial_k, &paillier_public_key);

					auto result = mpz_export_buffer(next_i);
					cumulative_i.resize(result.size());
					memcpy(cumulative_i.data(), result.data(), result.size());
					paillier_pubkey_clear(&paillier_public_key);
					mpz_clear(next_i);
					mpz_clear(prev_i);
					mpz_clear(partial_k);
				}
				else
				{
					paillier_seckey paillier_secret_key;
					paillier_seckey_init(&paillier_secret_key);
					calculate_paillier_keypair(&paillier_public_key, &paillier_secret_key, p_bits, secret_key, &k);

					uint8_t order_buffer[32] = { 0 };
					bn_write_be(&secp256k1.order, order_buffer);

					mpz_t prev_i, order;
					mpz_init(prev_i);
					mpz_init(order);
					if (!mpz_import_buffer(cumulative_i.data(), cumulative_i.size(), prev_i) || !mpz_import_buffer(order_buffer, sizeof(order_buffer), order))
					{
						mpz_clear(order);
						mpz_clear(prev_i);
						return layer_exception("invalid order or i");
					}

					mpz_t next_s;
					mpz_init(next_s);
					paillier_decrypt(next_s, prev_i, &paillier_secret_key);
					paillier_seckey_clear(&paillier_secret_key);
					paillier_pubkey_clear(&paillier_public_key);
					mpz_mod(next_s, next_s, order);

					uint8_t s_buffer[32] = { 0 };
					auto result = mpz_export_buffer(next_s);
					memcpy(s_buffer, result.data(), std::min(sizeof(s_buffer), result.size()));
					mpz_clear(order);
					mpz_clear(next_s);
					mpz_clear(prev_i);

					bignum256 s;
					bn_read_be(s_buffer, &s);
					bn_multiply(&k, &s, &secp256k1.order);
					if (bn_is_zero(&s))
						return layer_exception("bad final signature");
					else if (bn_is_less(&secp256k1.order_half, &s))
						bn_subtract(&secp256k1.order, &s, &s);

					cumulative_s = to_scalar_secp256k1(s);
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

			output->resize(65);
			auto r = from_compressed_point_secp256k1(cumulative_r);
			auto s = from_scalar_secp256k1(cumulative_s);
			bn_write_be(&r.x, output->data());
			bn_write_be(&s, output->data() + 32);
			return verify_signature_set_recovery_id(message_hash, sizeof(message_hash), *output, public_key);
		}
		expects_lr<void> secp256k1_compositor::verify_signature(const uint8_t* message, size_t message_size, const algorithm::composition::chashsig_t& signature, const algorithm::composition::cpubkey_t& public_key) const
		{
			algorithm::composition::chashsig_t copy = signature;
			auto status = verify_signature_set_recovery_id(message, message_size, copy, public_key);
			if (status && copy.back() != signature.back())
				return layer_exception("signature recovers incorrect public key");

			return status;
		}
		expects_lr<void> secp256k1_compositor::verify_signature_set_recovery_id(const uint8_t* message, size_t message_size, algorithm::composition::chashsig_t& signature, const algorithm::composition::cpubkey_t& public_key) const
		{
			VI_ASSERT(message != nullptr, "message should be set");
			if (public_key.size() != sizeof(secp256k1_point_t))
				return layer_exception("invalid public key");

			if (signature.size() != 65)
				return layer_exception("invalid signature");

			auto copy = *this;
			auto status = copy.setup_signature(public_key, message, message_size, nullptr, additions);
			if (!status)
				return status;

			secp256k1_context* context = algorithm::signing::get_context();
			for (uint8_t recovery_id = 0; recovery_id < 4; recovery_id++)
			{
				secp256k1_ecdsa_recoverable_signature recoverable_signature;
				if (secp256k1_ecdsa_recoverable_signature_parse_compact(context, &recoverable_signature, signature.data(), recovery_id) != 1)
					continue;

				secp256k1_pubkey recovered_public_key;
				if (secp256k1_ecdsa_recover(context, &recovered_public_key, &recoverable_signature, copy.message_hash) != 1)
					continue;

				uint8_t possible_public_key[33]; size_t possible_public_key_size = public_key.size();
				if (secp256k1_ec_pubkey_serialize(context, possible_public_key, &possible_public_key_size, &recovered_public_key, SECP256K1_EC_COMPRESSED) != 1 || memcmp(public_key.data(), possible_public_key, possible_public_key_size) != 0)
					continue;

				secp256k1_ecdsa_signature compact_signature;
				if (secp256k1_ecdsa_signature_parse_compact(context, &compact_signature, signature.data()) != 1)
					break;

				secp256k1_pubkey extended_public_key;
				secp256k1_ecdsa_signature normalized_signature;
				secp256k1_ecdsa_signature_normalize(context, &normalized_signature, &compact_signature);
				if (secp256k1_ec_pubkey_parse(context, &extended_public_key, public_key.data(), public_key.size()) != 1)
					break;

				if (secp256k1_ecdsa_verify(context, &normalized_signature, copy.message_hash, &extended_public_key) != 1)
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
			if (z_steps == additions)
				return algorithm::composition::phase::any_input_after_reset;
			else if (z_steps > 0)
				return algorithm::composition::phase::any_input;

			if (r_steps == multiplications)
				return algorithm::composition::phase::any_input_after_reset;
			else if (r_steps == 1)
				return algorithm::composition::phase::chosen_input;
			else if (r_steps > 0)
				return algorithm::composition::phase::any_input;

			if (i_steps == additions)
				return algorithm::composition::phase::chosen_input_after_reset;
			else if (i_steps > 0)
				return algorithm::composition::phase::any_input;

			if (s_steps == multiplications)
				return algorithm::composition::phase::any_input_after_reset;
			else if (s_steps == 1)
				return algorithm::composition::phase::chosen_input;
			else if (s_steps > 0)
				return algorithm::composition::phase::any_input;

			return algorithm::composition::phase::finalized;
		}
		uint32_t secp256k1_compositor::steps_left() const
		{
			return z_steps + r_steps + i_steps + s_steps;
		}
		bool secp256k1_compositor::store(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(additions);
			stream->write_integer(multiplications);
			stream->write_integer(z_steps);
			stream->write_integer(r_steps);
			stream->write_integer(i_steps);
			stream->write_integer(s_steps);
			stream->write_integer(p_bits);
			stream->write_string(cumulative_key.optimized_view());
			stream->write_string(cumulative_r.optimized_view());
			stream->write_string(cumulative_s.optimized_view());
			stream->write_string(std::string_view((char*)cumulative_i.data(), cumulative_i.size()));
			stream->write_string(std::string_view((char*)encryption_key.data(), encryption_key.size()));
			stream->write_string(std::string_view((char*)message_hash, sizeof(message_hash)));
			stream->write_integer((uint16_t)indices.size());
			for (auto& index : indices)
				stream->write_integer(index);
			return true;
		}
		bool secp256k1_compositor::load(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &additions))
				return false;

			if (!stream.read_integer(stream.read_type(), &multiplications))
				return false;

			if (!stream.read_integer(stream.read_type(), &z_steps))
				return false;

			if (!stream.read_integer(stream.read_type(), &r_steps))
				return false;

			if (!stream.read_integer(stream.read_type(), &i_steps))
				return false;

			if (!stream.read_integer(stream.read_type(), &s_steps))
				return false;

			if (!stream.read_integer(stream.read_type(), &p_bits))
				return false;

			string intermediate;
			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, cumulative_key.blob, sizeof(cumulative_key)))
				return false;

			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, cumulative_r.blob, sizeof(cumulative_r)))
				return false;

			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, cumulative_s.blob, sizeof(cumulative_s)))
				return false;

			if (!stream.read_string(stream.read_type(), &intermediate))
				return false;

			cumulative_i.resize(intermediate.size());
			memcpy(cumulative_i.data(), intermediate.data(), intermediate.size());
			if (!stream.read_string(stream.read_type(), &intermediate))
				return false;

			encryption_key.resize(intermediate.size());
			memcpy(encryption_key.data(), intermediate.data(), intermediate.size());
			if (!stream.read_string(stream.read_type(), &intermediate) || intermediate.size() != sizeof(message_hash))
				return false;

			uint32_t indices_size;
			memcpy(message_hash, intermediate.data(), intermediate.size());
			if (!stream.read_integer(stream.read_type(), &indices_size))
				return false;

			indices.resize(indices_size);
			for (uint32_t i = 0; i < indices_size; i++)
			{
				if (!stream.read_integer(stream.read_type(), &indices[i]))
					return false;
			}

			return true;
		}
		bool secp256k1_compositor::may_transition_to(const compositor& next_ptr) const
		{
			auto* next = (const secp256k1_compositor*)&next_ptr;
			if (additions != next->additions || multiplications != next->multiplications || p_bits != next->p_bits || memcmp(message_hash, next->message_hash, sizeof(message_hash)) != 0)
				return false;

			if ((z_steps == next->z_steps) != cumulative_key.equals(next->cumulative_key))
				return false;

			if ((r_steps == next->r_steps) != cumulative_r.equals(next->cumulative_r))
				return false;

			if ((i_steps == next->i_steps && (s_steps == next->s_steps || (s_steps > 0 && !next->s_steps))) != (cumulative_i == next->cumulative_i))
				return false;

			if (s_steps > 0 && !next->s_steps)
			{
				if (cumulative_s.equals(next->cumulative_s))
					return false;
			}
			else if (!cumulative_s.equals(next->cumulative_s))
				return false;

			if (r_steps > 0 && !next->r_steps)
			{
				if (!encryption_key.empty() || next->encryption_key.empty())
					return false;
			}
			else if (encryption_key != next->encryption_key)
				return false;

			if (r_steps == next->r_steps && s_steps == next->s_steps && indices != next->indices)
				return false;

			if (r_steps != next->r_steps && indices.size() >= next->indices.size())
				return false;

			if (s_steps != next->s_steps && indices.size() <= next->indices.size())
				return false;

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
			cumulative_r = secp256k1_point_t();
			cumulative_s = secp256k1_scalar_t();
			z_steps = 0;
			r_steps = s_steps = participants = new_participants;
			cumulative_key = std::string_view((char*)new_public_key.data(), sizeof(cumulative_key));
			group_public_key_tweak = std::string_view((char*)new_public_key.data() + sizeof(cumulative_key), new_public_key.size() - sizeof(cumulative_key));
			return expectation::met;
		}
		expects_lr<void> secp256k1_schnorr_compositor::aggregate(const algorithm::composition::cseckey_t& secret_key)
		{
			if (secret_key.size() != sizeof(secp256k1_scalar_t))
				return layer_exception("invalid secret key size");

			auto calculate_nonce = [](bignum256* k, const uint8_t message_hash[32], const secp256k1_point_t& public_key, const algorithm::composition::cseckey_t& secret_key, const uint256_t& index) -> bool
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
			auto calculate_challenge = [](bignum256* e, const curve_point& r, const uint8_t message_hash[32], const secp256k1_point_t& public_key) -> bool
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
				indices.push_back(0);
			retry_nonce:
				bignum256 k;
				uint256_t& index = indices.back();
				if (!calculate_nonce(&k, message_hash, cumulative_key, secret_key, ++index))
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
				if (!calculate_challenge(&e, r, message_hash, cumulative_key))
					goto retry_nonce;

				cumulative_r = to_compressed_point_secp256k1(r);
				--r_steps;
			}
			else if (s_steps > 0)
			{
				if (cumulative_r.empty() || indices.empty())
					return layer_exception("invalid compositor state");

				uint8_t null[32] = { 0 };
				if (!memcmp(message_hash, null, sizeof(null)))
					return layer_exception("bad message");

				bignum256 e;
				curve_point r = from_compressed_point_secp256k1(cumulative_r);
				if (!calculate_challenge(&e, r, message_hash, cumulative_key))
					return layer_exception("invalid public r");

				bignum256 k;
				if (!calculate_nonce(&k, message_hash, cumulative_key, secret_key, indices.front()))
					return layer_exception("invalid private k");

				bignum256 s;
				bn_read_be(secret_key.data(), &s);
				if (indices.size() == 1 && !group_public_key_tweak.empty())
				{
					bignum256 t;
					bn_read_be(group_public_key_tweak.blob, &t);
					bn_addmod(&s, &t, &secp256k1.order);
					if (bn_is_zero(&s))
						return layer_exception("invalid taproot tweak");
				}
				bn_cnegate(cumulative_key.blob[0] == SECP256K1_TAG_PUBKEY_ODD, &s, &secp256k1.order);
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

				indices.erase(indices.begin());
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
		expects_lr<void> secp256k1_schnorr_compositor::verify_signature(const uint8_t* message, size_t message_size, const algorithm::composition::chashsig_t& signature, const algorithm::composition::cpubkey_t& public_key) const
		{
			if (public_key.size() != sizeof(secp256k1_point_t))
				return layer_exception("invalid public key");

			if (signature.size() != 64)
				return layer_exception("invalid signature");

			auto copy = *this;
			auto status = copy.setup_signature(public_key, message, message_size, nullptr, participants);
			if (!status)
				return status;

			secp256k1_context* context = algorithm::signing::get_context();
			secp256k1_xonly_pubkey xonly_public_key;
			if (secp256k1_xonly_pubkey_parse(context, &xonly_public_key, public_key.data() + 1) != 1)
				return layer_exception("invalid public key");

			if (secp256k1_schnorrsig_verify(context, signature.data(), copy.message_hash, sizeof(copy.message_hash), &xonly_public_key) != 1)
				return layer_exception("signature verification failed");

			return expectation::met;
		}
		algorithm::composition::type secp256k1_schnorr_compositor::alg_type() const
		{
			return algorithm::composition::type::secp256k1_schnorr;
		}
		algorithm::composition::phase secp256k1_schnorr_compositor::next_phase() const
		{
			if (z_steps == participants)
				return algorithm::composition::phase::any_input_after_reset;
			else if (z_steps > 0)
				return algorithm::composition::phase::any_input;

			if (r_steps == participants)
				return algorithm::composition::phase::any_input_after_reset;
			else if (r_steps > 0)
				return algorithm::composition::phase::any_input;

			if (s_steps == participants)
				return algorithm::composition::phase::any_input_after_reset;
			else if (s_steps > 0)
				return algorithm::composition::phase::any_input;

			return algorithm::composition::phase::finalized;
		}
		uint32_t secp256k1_schnorr_compositor::steps_left() const
		{
			return z_steps + r_steps + s_steps;
		}
		bool secp256k1_schnorr_compositor::store(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(participants);
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
			if (!stream.read_integer(stream.read_type(), &participants))
				return false;

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

			string intermediate;
			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, cumulative_r.blob, sizeof(cumulative_r)))
				return false;

			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, cumulative_s.blob, sizeof(cumulative_s)))
				return false;

			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, cumulative_key.blob, sizeof(cumulative_key)))
				return false;

			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, group_public_key_tweak.blob, sizeof(group_public_key_tweak)))
				return false;

			if (!stream.read_string(stream.read_type(), &intermediate) || intermediate.size() != sizeof(message_hash))
				return false;

			memcpy(message_hash, intermediate.data(), intermediate.size());
			return true;
		}
		bool secp256k1_schnorr_compositor::may_transition_to(const compositor& next_ptr) const
		{
			auto* next = (const secp256k1_schnorr_compositor*)&next_ptr;
			if (participants != next->participants || memcmp(message_hash, next->message_hash, sizeof(message_hash)) != 0 || !group_public_key_tweak.equals(next->group_public_key_tweak))
				return false;

			if ((z_steps == next->z_steps) != cumulative_key.equals(next->cumulative_key))
				return false;

			if ((r_steps == next->r_steps) != cumulative_r.equals(next->cumulative_r))
				return false;

			if ((s_steps == next->s_steps) != cumulative_s.equals(next->cumulative_s))
				return false;

			if (r_steps == next->r_steps && s_steps == next->s_steps && indices != next->indices)
				return false;

			if (r_steps != next->r_steps && indices.size() >= next->indices.size())
				return false;

			if (s_steps != next->s_steps && indices.size() <= next->indices.size())
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