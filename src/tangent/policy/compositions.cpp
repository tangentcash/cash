#include "compositions.h"
#include "../internal/paillier.h"
extern "C"
{
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_recovery.h>
#include <sodium.h>
#include "../internal/secp256k1.h"
}

namespace tangent
{
	namespace compositions
	{
		typedef void(*gmp_free_t)(void*, size_t);
		static gmp_free_t gmp_free = nullptr;
		inline void mpz_import_buffer(const uint8_t* data, size_t size, mpz_t value)
		{
			mpz_import(value, size, 1, 1, 1, 0, data);
		}
		inline string mpz_export_buffer(const mpz_t value)
		{
			if (!gmp_free)
				mp_get_memory_functions(nullptr, nullptr, &gmp_free);

			size_t size = 0;
			char* data = (char*)mpz_export(nullptr, &size, 1, 1, 1, 0, value);
			string buffer = string(data, size);
			gmp_free(data, size);
			return buffer;
		}
		inline curve_point from_compressed_point_secp256k1(const algorithm::storage_type<uint8_t, 33>& value)
		{
			curve_point result;
			bn_read_be(value.data + 1, &result.x);
			uncompress_coords(&secp256k1, value.data[0], &result.x, &result.y);
			return result;
		}
		inline algorithm::storage_type<uint8_t, 33> to_compressed_point_secp256k1(const curve_point& value)
		{
			algorithm::storage_type<uint8_t, 33> result;
			compress_coords(&value, result.data);
			return result;
		}
		inline bignum256 from_scalar_secp256k1(const algorithm::storage_type<uint8_t, 32>& value)
		{
			bignum256 result;
			bn_read_be(value.data, &result);
			return result;
		}
		inline algorithm::storage_type<uint8_t, 32> to_scalar_secp256k1(const bignum256& value)
		{
			algorithm::storage_type<uint8_t, 32> result;
			bn_write_be(&value, result.data);
			return result;
		}

		expects_lr<void> ed25519_secret_state::derive_from_seed(const uint256_t& seed)
		{
			uint8_t seed_buffer[32];
			seed.encode(seed_buffer);

			uint8_t key_buffer[64];
			algorithm::hashing::hash512(seed_buffer, sizeof(seed_buffer), key_buffer);
			algorithm::keypair_utils::convert_to_scalar_ed25519(key_buffer, key_buffer);
			memcpy(cumulative_key.data, key_buffer, sizeof(cumulative_key.data));
			return expectation::met;
		}
		expects_lr<void> ed25519_secret_state::derive_from_key(const algorithm::composition::cseckey_t& secret_key)
		{
			if (secret_key.size() != sizeof(cumulative_key.data))
				return layer_exception("invalid secret key size");

			if (cumulative_key.empty())
				memcpy(cumulative_key.data, secret_key.data(), secret_key.size());
			else
				crypto_core_ed25519_scalar_add(cumulative_key.data, cumulative_key.data, secret_key.data());

			return expectation::met;
		}
		expects_lr<void> ed25519_secret_state::finalize(algorithm::composition::cseckey_t* output) const
		{
			VI_ASSERT(output != nullptr, "output should be set");
			output->resize(sizeof(cumulative_key.data));
			memcpy(output->data(), cumulative_key.data, sizeof(cumulative_key.data));
			return expectation::met;
		}
		bool ed25519_secret_state::store(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(cumulative_key.optimized_view());
			return true;
		}
		bool ed25519_secret_state::load(format::ro_stream& stream)
		{
			string cumulative_key_assembly;
			if (!stream.read_string(stream.read_type(), &cumulative_key_assembly) || !algorithm::encoding::decode_bytes(cumulative_key_assembly, cumulative_key.data, sizeof(cumulative_key.data)))
				return false;

			return true;
		}

		expects_lr<void> ed25519_public_state::derive_from_key(const algorithm::composition::cseckey_t& secret_key)
		{
			if (secret_key.size() != sizeof(ed25519_secret_state::scalar_t))
				return layer_exception("invalid secret key size");

			uint8_t secret_key_buffer[64] = { 0 }, public_key[32] = { 0 };
			memcpy(secret_key_buffer, secret_key.data(), secret_key.size());
			ed25519_publickey_ext(secret_key_buffer, public_key);
			if (cumulative_key.empty())
				memcpy(cumulative_key.data, public_key, sizeof(public_key));
			else if (crypto_core_ed25519_add(cumulative_key.data, public_key, cumulative_key.data) != 0)
				return layer_exception("invalid secret key");

			return expectation::met;
		}
		expects_lr<void> ed25519_public_state::finalize(algorithm::composition::cpubkey_t* output) const
		{
			VI_ASSERT(output != nullptr, "output should be set");
			output->resize(sizeof(cumulative_key.data));
			memcpy(output->data(), cumulative_key.data, sizeof(cumulative_key.data));
			return expectation::met;
		}
		bool ed25519_public_state::store(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(cumulative_key.optimized_view());
			return true;
		}
		bool ed25519_public_state::load(format::ro_stream& stream)
		{
			string cumulative_key_assembly;
			if (!stream.read_string(stream.read_type(), &cumulative_key_assembly) || !algorithm::encoding::decode_bytes(cumulative_key_assembly, cumulative_key.data, sizeof(cumulative_key.data)))
				return false;

			return true;
		}

		expects_lr<void> ed25519_signature_state::setup(const algorithm::composition::cpubkey_t& new_public_key, const uint8_t* new_message, size_t new_message_size, uint16_t new_participants)
		{
			VI_ASSERT(new_message != nullptr, "message should be set");
			if (new_public_key.size() != sizeof(ed25519_public_state::point_t))
				return layer_exception("invalid public key size");

			indices.clear();
			cumulative_r = ed25519_public_state::point_t();
			cumulative_s = ed25519_secret_state::scalar_t();
			r_steps = s_steps = participants = new_participants;
			public_key = std::string_view((char*)new_public_key.data(), new_public_key.size());
			message.resize(new_message_size);
			memcpy(message.data(), new_message, new_message_size);
			return expectation::met;
		}
		expects_lr<void> ed25519_signature_state::aggregate(const algorithm::composition::cseckey_t& secret_key)
		{
			if (secret_key.size() != sizeof(ed25519_secret_state::scalar_t))
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
			if (r_steps > 0)
			{
				indices.push_back(0);
			retry_nonce:
				uint8_t nonce[64];
				uint256_t& index = indices.back();
				calculate_nonce(nonce, message, secret_key, ++index);

				ed25519_public_state::point_t r;
				if (crypto_scalarmult_ed25519_base_noclamp(r.data, nonce) != 0 || r.empty())
					goto retry_nonce;

				if (!cumulative_r.empty() && (crypto_core_ed25519_add(r.data, r.data, cumulative_r.data) != 0 || r.empty()))
					goto retry_nonce;

				cumulative_r = r;
				--r_steps;
			}
			else if (s_steps > 0)
			{
				if (cumulative_r.empty() || indices.empty())
					return layer_exception("invalid signature state");

				uint8_t nonce[64];
				calculate_nonce(nonce, message, secret_key, indices.front());
				indices.erase(indices.begin());

				uint8_t hram[64];
				crypto_hash_sha512_state hash;
				crypto_hash_sha512_init(&hash);
				crypto_hash_sha512_update(&hash, cumulative_r.data, sizeof(cumulative_r.data));
				crypto_hash_sha512_update(&hash, public_key.data, sizeof(public_key.data));
				crypto_hash_sha512_update(&hash, message.data(), message.size());
				crypto_hash_sha512_final(&hash, hram);
				crypto_core_ed25519_scalar_reduce(hram, hram);

				ed25519_secret_state::scalar_t s;
				crypto_core_ed25519_scalar_mul(s.data, hram, secret_key.data());
				crypto_core_ed25519_scalar_add(s.data, s.data, nonce);
				if (!cumulative_s.empty())
					crypto_core_ed25519_scalar_add(s.data, s.data, cumulative_s.data);

				cumulative_s = s;
				--s_steps;
			}
			return expectation::met;
		}
		expects_lr<void> ed25519_signature_state::finalize(algorithm::composition::chashsig_t* output) const
		{
			VI_ASSERT(output != nullptr, "output should be set");
			output->resize(sizeof(cumulative_r.data) + sizeof(cumulative_s.data));
			memcpy(output->data(), cumulative_r.data, sizeof(cumulative_r.data));
			memcpy(output->data() + sizeof(cumulative_r.data), cumulative_s.data, sizeof(cumulative_s.data));
			if (crypto_sign_verify_detached(output->data(), message.data(), message.size(), public_key.data) != 0)
				return layer_exception("final signature verification failed");

			return expectation::met;
		}
		algorithm::composition::phase ed25519_signature_state::next_phase() const
		{
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
		bool ed25519_signature_state::store(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(participants);
			stream->write_integer(r_steps);
			stream->write_integer(s_steps);
			stream->write_integer((uint16_t)indices.size());
			for (auto& index : indices)
				stream->write_integer(index);
			stream->write_string(cumulative_r.optimized_view());
			stream->write_string(cumulative_s.optimized_view());
			stream->write_string(public_key.optimized_view());
			stream->write_string(std::string_view((char*)message.data(), message.size()));
			return true;
		}
		bool ed25519_signature_state::load(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &participants))
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
			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, cumulative_r.data, sizeof(cumulative_r.data)))
				return false;

			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, cumulative_s.data, sizeof(cumulative_s.data)))
				return false;

			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, public_key.data, sizeof(public_key.data)))
				return false;

			if (!stream.read_string(stream.read_type(), &intermediate))
				return false;

			message.resize(intermediate.size());
			memcpy(message.data(), intermediate.data(), intermediate.size());
			return true;
		}
		bool ed25519_signature_state::prefer_over(const signature_state& other) const
		{
			auto* prev = (const ed25519_signature_state*)&other;
			if (participants != prev->participants || message != prev->message || !public_key.equals(prev->public_key))
				return false;

			return r_steps + s_steps < prev->r_steps + prev->s_steps;
		}

		expects_lr<void> ed25519_clsag_signature_state::setup(const algorithm::composition::cpubkey_t& public_key, const uint8_t* message, size_t message_size, uint16_t participants)
		{
			VI_ASSERT(message != nullptr, "message should be set");
			if (public_key.size() != sizeof(ed25519_public_state::point_t))
				return layer_exception("invalid public key size");

			return expectation::met;
		}
		expects_lr<void> ed25519_clsag_signature_state::aggregate(const algorithm::composition::cseckey_t& secret_key)
		{
			if (secret_key.size() != sizeof(ed25519_secret_state::scalar_t))
				return layer_exception("invalid secret key size");

			/* Not implemented yet */
			return expectation::met;
		}
		expects_lr<void> ed25519_clsag_signature_state::finalize(algorithm::composition::chashsig_t* output) const
		{
			VI_ASSERT(output != nullptr, "output should be set");
			/* Not implemented yet */
			output->resize(64, 0xCC);
			return expectation::met;
		}
		algorithm::composition::phase ed25519_clsag_signature_state::next_phase() const
		{
			return algorithm::composition::phase::finalized;
		}
		bool ed25519_clsag_signature_state::store(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			return true;
		}
		bool ed25519_clsag_signature_state::load(format::ro_stream& stream)
		{
			return true;
		}
		bool ed25519_clsag_signature_state::prefer_over(const signature_state& other) const
		{
			return true;
		}

		expects_lr<void> secp256k1_secret_state::derive_from_seed(const uint256_t& seed)
		{
			uint8_t seed_buffer[32];
			seed.encode(seed_buffer);

			uint8_t key_buffer[64];
			algorithm::hashing::hash512(seed_buffer, sizeof(seed_buffer), key_buffer);
			memcpy(cumulative_key.data, key_buffer, std::min(sizeof(cumulative_key.data), sizeof(key_buffer)));

			secp256k1_pubkey extended_public_key;
			secp256k1_context* context = algorithm::signing::get_context();
			while (secp256k1_ec_seckey_verify(context, cumulative_key.data) != 1 || secp256k1_ec_pubkey_create(context, &extended_public_key, cumulative_key.data) != 1)
			{
				algorithm::hashing::hash512(key_buffer, sizeof(key_buffer), key_buffer);
				memcpy(cumulative_key.data, key_buffer, std::min(sizeof(cumulative_key.data), sizeof(key_buffer)));
			}

			return expectation::met;
		}
		expects_lr<void> secp256k1_secret_state::derive_from_key(const algorithm::composition::cseckey_t& secret_key)
		{
			if (secret_key.size() != sizeof(cumulative_key.data))
				return layer_exception("invalid secret key size");

			secp256k1_context* context = algorithm::signing::get_context();
			if (cumulative_key.empty())
				memcpy(cumulative_key.data, secret_key.data(), secret_key.size());
			else if (secp256k1_ec_seckey_tweak_add(context, cumulative_key.data, secret_key.data()) != 1)
				return layer_exception("invalid secret key");

			return expectation::met;
		}
		expects_lr<void> secp256k1_secret_state::finalize(algorithm::composition::cseckey_t* output) const
		{
			VI_ASSERT(output != nullptr, "output should be set");
			output->resize(sizeof(cumulative_key.data));
			memcpy(output->data(), cumulative_key.data, sizeof(cumulative_key.data));
			return expectation::met;
		}
		bool secp256k1_secret_state::store(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(cumulative_key.optimized_view());
			return true;
		}
		bool secp256k1_secret_state::load(format::ro_stream& stream)
		{
			string cumulative_key_assembly;
			if (!stream.read_string(stream.read_type(), &cumulative_key_assembly) || !algorithm::encoding::decode_bytes(cumulative_key_assembly, cumulative_key.data, sizeof(cumulative_key.data)))
				return false;

			return true;
		}

		expects_lr<void> secp256k1_public_state::derive_from_key(const algorithm::composition::cseckey_t& secret_key)
		{
			if (secret_key.size() != sizeof(secp256k1_secret_state::scalar_t))
				return layer_exception("invalid secret key size");

			secp256k1_context* context = algorithm::signing::get_context();
			if (secp256k1_ec_seckey_verify(context, secret_key.data()) != 1)
				return layer_exception("invalid secret key scalar");

			secp256k1_pubkey next_public_key;
			if (secp256k1_ec_pubkey_create(context, &next_public_key, secret_key.data()) != 1)
				return layer_exception("invalid secret key");

			if (cumulative_key.empty())
			{
				size_t key_size = sizeof(cumulative_key.data);
				if (secp256k1_ec_pubkey_serialize(context, cumulative_key.data, &key_size, &next_public_key, SECP256K1_EC_COMPRESSED) != 1)
					return layer_exception("invalid secret key");
			}
			else
			{
				secp256k1_pubkey prev_public_key, result_public_key;
				if (secp256k1_ec_pubkey_parse(context, &prev_public_key, cumulative_key.data, sizeof(cumulative_key.data)) != 1)
					return layer_exception("invalid intermediate public key");

				secp256k1_pubkey* public_keys[2] = { &prev_public_key, &next_public_key };
				if (secp256k1_ec_pubkey_combine(context, &result_public_key, public_keys, 2) != 1)
					return layer_exception("invalid secret key");

				size_t key_size = sizeof(cumulative_key.data);
				if (secp256k1_ec_pubkey_serialize(context, cumulative_key.data, &key_size, &result_public_key, SECP256K1_EC_COMPRESSED) != 1)
					return layer_exception("invalid secret key");
			}

			return expectation::met;
		}
		expects_lr<void> secp256k1_public_state::finalize(algorithm::composition::cpubkey_t* output) const
		{
			VI_ASSERT(output != nullptr, "output should be set");
			output->resize(sizeof(cumulative_key.data));
			memcpy(output->data(), cumulative_key.data, sizeof(cumulative_key.data));
			return expectation::met;
		}
		bool secp256k1_public_state::store(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(cumulative_key.optimized_view());
			return true;
		}
		bool secp256k1_public_state::load(format::ro_stream& stream)
		{
			string cumulative_key_assembly;
			if (!stream.read_string(stream.read_type(), &cumulative_key_assembly) || !algorithm::encoding::decode_bytes(cumulative_key_assembly, cumulative_key.data, sizeof(cumulative_key.data)))
				return false;

			return true;
		}

		expects_lr<void> secp256k1_signature_state::setup(const algorithm::composition::cpubkey_t& new_public_key, const uint8_t* new_message, size_t new_message_size, uint16_t new_participants)
		{
			VI_ASSERT(new_message != nullptr, "message should be set");
			if (new_public_key.size() != sizeof(secp256k1_public_state::point_t))
				return layer_exception("invalid public key size");

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
			if (additions > 1 || multiplications > 1)
				key_bits = 1024;

			indices.clear();
			group_key.clear();
			public_key = std::string_view((char*)new_public_key.data(), new_public_key.size());
			r_steps = multiplications;
			i_steps = additions;
			s_steps = multiplications;
			p_bits = key_bits;
			return expectation::met;
		}
		expects_lr<void> secp256k1_signature_state::aggregate(const algorithm::composition::cseckey_t& secret_key)
		{
			if (secret_key.size() != sizeof(secp256k1_secret_state::scalar_t))
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
			auto calculate_paillier_public_key = [](const paillier_scalar_t& group_key, paillier_pubkey* paillier_public_key) -> bool
			{
				auto modulus = string(); auto modulus_bits = uint32_t(0);
				auto message = format::ro_stream(std::string_view((char*)group_key.data(), group_key.size()));
				if (!message.read_string(message.read_type(), &modulus) || modulus.empty() || !message.read_integer(message.read_type(), &modulus_bits))
					return false;

				paillier_public_key->len = (mp_bitcnt_t)modulus_bits;
				mpz_import_buffer((uint8_t*)modulus.data(), modulus.size(), paillier_public_key->n);
				return true;
			};
			if (r_steps > 0)
			{
				indices.push_back(0);
			retry_nonce:
				bignum256 k;
				uint256_t& index = indices.back();
				if (!calculate_nonce(&k, message_hash, secret_key, ++index))
					goto retry_nonce;

				curve_point r = { 0 };
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

					format::wo_stream message;
					message.write_string(mpz_export_buffer(paillier_public_key.n));
					message.write_integer((uint32_t)paillier_public_key.len);
					group_key.resize(message.data.size());
					memcpy(group_key.data(), message.data.data(), message.data.size());
					paillier_pubkey_clear(&paillier_public_key);
					paillier_seckey_clear(&paillier_secret_key);
				}
			}
			else if (i_steps > 0)
			{
				if (cumulative_r.empty() || group_key.empty())
					return layer_exception("invalid signature state");

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
				if (!calculate_paillier_public_key(group_key, &paillier_public_key))
					return layer_exception("invalid group key");

				curve_point r = from_compressed_point_secp256k1(cumulative_r);
				bignum256 i;
				bn_read_be(secret_key.data(), &i);
				bn_multiply(&r.x, &i, &secp256k1.order);
				bn_addmod(&i, &z, &secp256k1.order);

				uint8_t i_buffer[32];
				bn_write_be(&i, i_buffer);

				mpz_t partial_plaintext_i, partial_i;
				mpz_init(partial_plaintext_i);
				mpz_init(partial_i);
				mpz_import_buffer(i_buffer, sizeof(i_buffer), partial_plaintext_i);
				paillier_encrypt(partial_i, partial_plaintext_i, &paillier_public_key);
				mpz_clear(partial_plaintext_i);

				auto result = string();
				if (!cumulative_i.empty())
				{
					mpz_t prev_i, next_i;
					mpz_init(prev_i);
					mpz_init(next_i);
					mpz_import_buffer(cumulative_i.data(), cumulative_i.size(), prev_i);
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
				if (cumulative_i.empty() || group_key.empty() || indices.empty())
					return layer_exception("invalid signature state");

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
					if (!calculate_paillier_public_key(group_key, &paillier_public_key))
						return layer_exception("invalid group key");

					uint8_t k_buffer[32] = { 0 };
					bn_write_be(&k, k_buffer);

					mpz_t prev_i, next_i, partial_k;
					mpz_init(prev_i);
					mpz_init(next_i);
					mpz_init(partial_k);
					mpz_import_buffer(k_buffer, sizeof(k_buffer), partial_k);
					mpz_import_buffer(cumulative_i.data(), cumulative_i.size(), prev_i);
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

					mpz_t prev_i, next_s, order;
					mpz_init(prev_i);
					mpz_init(next_s);
					mpz_init(order);
					mpz_import_buffer(cumulative_i.data(), cumulative_i.size(), prev_i);
					mpz_import_buffer(order_buffer, sizeof(order_buffer), order);
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
		expects_lr<void> secp256k1_signature_state::finalize(algorithm::composition::chashsig_t* output) const
		{
			VI_ASSERT(output != nullptr, "output should be set");
			output->resize(65);
			auto r = from_compressed_point_secp256k1(cumulative_r);
			auto s = from_scalar_secp256k1(cumulative_s);
			bn_write_be(&r.x, output->data());
			bn_write_be(&s, output->data() + 32);

			secp256k1_context* context = algorithm::signing::get_context();
			for (uint8_t recovery_id = 0; recovery_id < 4; recovery_id++)
			{
				secp256k1_ecdsa_recoverable_signature recoverable_signature;
				if (secp256k1_ecdsa_recoverable_signature_parse_compact(context, &recoverable_signature, output->data(), recovery_id) != 1)
					continue;

				secp256k1_pubkey recovered_public_key;
				if (secp256k1_ecdsa_recover(context, &recovered_public_key, &recoverable_signature, message_hash) != 1)
					continue;

				uint8_t possible_public_key[33]; size_t possible_public_key_size = sizeof(public_key);
				if (secp256k1_ec_pubkey_serialize(context, possible_public_key, &possible_public_key_size, &recovered_public_key, SECP256K1_EC_COMPRESSED) != 1 || memcmp(public_key.data, possible_public_key, possible_public_key_size) != 0)
					continue;

				secp256k1_ecdsa_signature compact_signature;
				if (secp256k1_ecdsa_signature_parse_compact(context, &compact_signature, output->data()) != 1)
					break;

				secp256k1_pubkey extended_public_key;
				secp256k1_ecdsa_signature normalized_signature;
				secp256k1_ecdsa_signature_normalize(context, &normalized_signature, &compact_signature);
				if (secp256k1_ec_pubkey_parse(context, &extended_public_key, public_key.data, sizeof(public_key.data)) != 1)
					break;

				if (secp256k1_ecdsa_verify(context, &normalized_signature, message_hash, &extended_public_key) != 1)
					break;

				output->at(output->size() - 1) = recovery_id;
				return expectation::met;
			}
			return layer_exception("final signature verification failed");
		}
		algorithm::composition::phase secp256k1_signature_state::next_phase() const
		{
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
		bool secp256k1_signature_state::store(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(additions);
			stream->write_integer(multiplications);
			stream->write_integer(r_steps);
			stream->write_integer(i_steps);
			stream->write_integer(s_steps);
			stream->write_integer(p_bits);
			stream->write_string(public_key.optimized_view());
			stream->write_string(cumulative_r.optimized_view());
			stream->write_string(cumulative_s.optimized_view());
			stream->write_string(std::string_view((char*)cumulative_i.data(), cumulative_i.size()));
			stream->write_string(std::string_view((char*)group_key.data(), group_key.size()));
			stream->write_string(std::string_view((char*)message_hash, sizeof(message_hash)));
			stream->write_integer((uint16_t)indices.size());
			for (auto& index : indices)
				stream->write_integer(index);
			return true;
		}
		bool secp256k1_signature_state::load(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &additions))
				return false;

			if (!stream.read_integer(stream.read_type(), &multiplications))
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
			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, public_key.data, sizeof(public_key.data)))
				return false;

			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, cumulative_r.data, sizeof(cumulative_r.data)))
				return false;

			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, cumulative_s.data, sizeof(cumulative_s.data)))
				return false;

			if (!stream.read_string(stream.read_type(), &intermediate))
				return false;

			cumulative_i.resize(intermediate.size());
			memcpy(cumulative_i.data(), intermediate.data(), intermediate.size());
			if (!stream.read_string(stream.read_type(), &intermediate))
				return false;

			group_key.resize(intermediate.size());
			memcpy(group_key.data(), intermediate.data(), intermediate.size());
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
		bool secp256k1_signature_state::prefer_over(const signature_state& other) const
		{
			auto* prev = (const secp256k1_signature_state*)&other;
			if (additions != prev->additions || multiplications != prev->multiplications || p_bits != prev->p_bits || memcmp(message_hash, prev->message_hash, sizeof(message_hash)) != 0 || !public_key.equals(prev->public_key))
				return false;

			if (!group_key.empty() && !prev->group_key.empty() && group_key != prev->group_key)
				return false;

			return r_steps + i_steps + s_steps < prev->r_steps + prev->i_steps + prev->s_steps;
		}

		expects_lr<void> secp256k1_schnorr_signature_state::setup(const algorithm::composition::cpubkey_t& new_public_key, const uint8_t* new_message, size_t new_message_size, uint16_t new_participants)
		{
			VI_ASSERT(new_message != nullptr, "message should be set");
			if (new_public_key.size() != sizeof(public_key) && new_public_key.size() != sizeof(public_key) + sizeof(public_key_tweak))
				return layer_exception("invalid public key size");

			if (new_message_size != sizeof(message_hash))
				sha256_Raw(new_message, new_message_size, message_hash);
			else
				memcpy(message_hash, new_message, sizeof(message_hash));

			indices.clear();
			cumulative_r = secp256k1_public_state::point_t();
			cumulative_s = secp256k1_secret_state::scalar_t();
			r_steps = s_steps = participants = new_participants;
			public_key = std::string_view((char*)new_public_key.data(), sizeof(public_key));
			public_key_tweak = std::string_view((char*)new_public_key.data() + sizeof(public_key), new_public_key.size() - sizeof(public_key));
			return expectation::met;
		}
		expects_lr<void> secp256k1_schnorr_signature_state::aggregate(const algorithm::composition::cseckey_t& secret_key)
		{
			if (secret_key.size() != sizeof(secp256k1_secret_state::scalar_t))
				return layer_exception("invalid secret key size");

			auto calculate_nonce = [](bignum256* k, const uint8_t message_hash[32], const secp256k1_public_state::point_t& public_key, const algorithm::composition::cseckey_t& secret_key, const uint256_t& index) -> bool
			{
				uint8_t index_nonce[32];
				index.encode(index_nonce);

				uint8_t ask[32];
				sha256_Raw(secret_key.data(), secret_key.size(), ask);

				uint8_t bip340_algo[] = "BIP0340/nonce", nonce[32];
				if (secp256k1_nonce_function_bip340(nonce, message_hash, 32, ask, public_key.data + 1, bip340_algo, sizeof(bip340_algo) - 1, index_nonce) != 1)
					return false;

				bn_read_be(nonce, k);
				bn_mod(k, &secp256k1.order);
				return true;
			};
			auto calculate_challenge = [](bignum256* e, const curve_point& r, const uint8_t message_hash[32], const secp256k1_public_state::point_t& public_key) -> bool
			{
				uint8_t data[96];
				bn_write_be(&r.x, data);
				memcpy(data + 32, public_key.data + 1, 32);
				memcpy(data + 64, message_hash, 32);

				uint8_t bip340_challenge[] = "BIP0340/challenge", challenge[32];
				secp256k1_context* context = algorithm::signing::get_context();
				if (secp256k1_tagged_sha256(context, challenge, bip340_challenge, sizeof(bip340_challenge) - 1, data, sizeof(data)) != 1)
					return false;

				bn_read_be(challenge, e);
				bn_mod(e, &secp256k1.order);
				return !bn_is_zero(e);
			};
			if (r_steps > 0)
			{
				indices.push_back(0);
			retry_nonce:
				bignum256 k;
				uint256_t& index = indices.back();
				if (!calculate_nonce(&k, message_hash, public_key, secret_key, ++index))
					goto retry_nonce;

				curve_point r = { 0 };
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
				if (!calculate_challenge(&e, r, message_hash, public_key))
					goto retry_nonce;

				cumulative_r = to_compressed_point_secp256k1(r);
				--r_steps;
			}
			else if (s_steps > 0)
			{
				if (cumulative_r.empty() || indices.empty())
					return layer_exception("invalid signature state");

				uint8_t null[32] = { 0 };
				if (!memcmp(message_hash, null, sizeof(null)))
					return layer_exception("bad message");

				bignum256 e;
				curve_point r = from_compressed_point_secp256k1(cumulative_r);
				if (!calculate_challenge(&e, r, message_hash, public_key))
					return layer_exception("invalid public r");

				bignum256 k;
				if (!calculate_nonce(&k, message_hash, public_key, secret_key, indices.front()))
					return layer_exception("invalid private k");

				bignum256 s;
				bn_read_be(secret_key.data(), &s);
				if (indices.size() == 1 && !public_key_tweak.empty())
				{
					bignum256 t;
					bn_read_be(public_key_tweak.data, &t);
					bn_addmod(&s, &t, &secp256k1.order);
					if (bn_is_zero(&s))
						return layer_exception("invalid taproot tweak");
				}
				bn_cnegate(public_key.data[0] == SECP256K1_TAG_PUBKEY_ODD, &s, &secp256k1.order);
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
		expects_lr<void> secp256k1_schnorr_signature_state::finalize(algorithm::composition::chashsig_t* output) const
		{
			VI_ASSERT(output != nullptr, "output should be set");
			secp256k1_context* context = algorithm::signing::get_context();
			secp256k1_xonly_pubkey xonly_public_key;
			if (secp256k1_xonly_pubkey_parse(context, &xonly_public_key, public_key.data + 1) != 1)
				return layer_exception("invalid public key");

			output->resize(64);
			auto r = from_compressed_point_secp256k1(cumulative_r);
			auto s = from_scalar_secp256k1(cumulative_s);
			bn_write_be(&r.x, output->data());
			bn_write_be(&s, output->data() + 32);
			if (secp256k1_schnorrsig_verify(context, output->data(), message_hash, sizeof(message_hash), &xonly_public_key) != 1)
				return layer_exception("final signature verification failed");

			return expectation::met;
		}
		algorithm::composition::phase secp256k1_schnorr_signature_state::next_phase() const
		{
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
		bool secp256k1_schnorr_signature_state::store(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(participants);
			stream->write_integer(r_steps);
			stream->write_integer(s_steps);
			stream->write_integer((uint16_t)indices.size());
			for (auto& index : indices)
				stream->write_integer(index);
			stream->write_string(cumulative_r.optimized_view());
			stream->write_string(cumulative_s.optimized_view());
			stream->write_string(public_key.optimized_view());
			stream->write_string(public_key_tweak.optimized_view());
			stream->write_string(std::string_view((char*)message_hash, sizeof(message_hash)));
			return true;
		}
		bool secp256k1_schnorr_signature_state::load(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &participants))
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
			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, cumulative_r.data, sizeof(cumulative_r.data)))
				return false;

			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, cumulative_s.data, sizeof(cumulative_s.data)))
				return false;

			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, public_key.data, sizeof(public_key.data)))
				return false;

			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, public_key_tweak.data, sizeof(public_key_tweak.data)))
				return false;

			if (!stream.read_string(stream.read_type(), &intermediate) || intermediate.size() != sizeof(message_hash))
				return false;

			memcpy(message_hash, intermediate.data(), intermediate.size());
			return true;
		}
		bool secp256k1_schnorr_signature_state::prefer_over(const signature_state& other) const
		{
			auto* prev = (const secp256k1_schnorr_signature_state*)&other;
			if (participants != prev->participants || memcmp(message_hash, prev->message_hash, sizeof(message_hash)) != 0 || !public_key.equals(prev->public_key) || !public_key_tweak.equals(prev->public_key_tweak))
				return false;

			return r_steps + s_steps < prev->r_steps + prev->s_steps;
		}
		expects_lr<algorithm::composition::cpubkey_t> secp256k1_schnorr_signature_state::to_tweaked_public_key(const secp256k1_public_state::point_t& public_key, const secp256k1_secret_state::scalar_t& tweak)
		{
			secp256k1_context* context = algorithm::signing::get_context();
			secp256k1_pubkey extended_public_key;
			if (secp256k1_ec_pubkey_parse(context, &extended_public_key, public_key.data, sizeof(public_key.data)) != 1)
				return layer_exception("invalid public key");

			if (secp256k1_ec_pubkey_tweak_add(context, &extended_public_key, tweak.data) != 1)
				return layer_exception("invalid public key tweak");

			size_t result_size = sizeof(public_key.data);
			auto result = algorithm::composition::cpubkey_t(result_size + sizeof(tweak.data), 0);
			if (!secp256k1_ec_pubkey_serialize(context, result.data(), &result_size, &extended_public_key, SECP256K1_EC_COMPRESSED))
				return layer_exception("invalid tweaked public key");

			memcpy(result.data() + sizeof(public_key.data), tweak.data, sizeof(tweak.data));
			return expects_lr<algorithm::composition::cpubkey_t>(std::move(result));
		}
	}
}