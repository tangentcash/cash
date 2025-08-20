#include "algorithm.h"
#include "../validator/service/nss.h"
#include <gmp.h>
extern "C"
{
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <secp256k1_schnorrsig.h>
#include <sodium.h>
#include "../internal/segwit_addr.h"
#include "../internal/ecdsa.h"
#include "../internal/ed25519.h"
#include "../internal/ripemd160.h"
#include "../internal/bip39.h"
#include "../internal/sha2.h"
#include "../internal/secp256k1.h"
#include "../internal/monero/crypto.h"
}

namespace tangent
{
	namespace algorithm
	{
		struct mpz
		{
			static void free(void* data, size_t size)
			{
				typedef void (*gmp_free_t)(void*, size_t);
				static gmp_free_t gmp_free = nullptr;
				if (!gmp_free)
					mp_get_memory_functions(nullptr, nullptr, &gmp_free);
				gmp_free(data, size);
			}
			static void import0(const uint8_t* data, size_t size, mpz_t value)
			{
				mpz_import(value, size, 1, 1, 1, 0, data);
			}
			static void import256(const uint256_t& data, mpz_t value)
			{
				uint8_t buffer[32];
				data.encode(buffer);
				mpz_import(value, sizeof(buffer), 1, 1, 1, 0, buffer);
			}
			static string export0(const mpz_t value)
			{
				size_t size = 0;
				char* data = (char*)mpz_export(nullptr, &size, 1, 1, 1, 0, value);
				string buffer = string(data, size);
				free(data, size);
				return buffer;
			}
			static uint256_t export256(const mpz_t value)
			{
				size_t size = 0;
				char* data = (char*)mpz_export(nullptr, &size, 1, 1, 1, 0, value);
				uint8_t buffer[32] = { 0 };
				memcpy((char*)buffer + (sizeof(buffer) - size), data, size);
				free(data, size);

				uint256_t v;
				v.decode(buffer);
				return v;
			}
			static void export256(const mpz_t value, uint8_t buffer[32])
			{
				size_t size = 0;
				char* data = (char*)mpz_export(nullptr, &size, 1, 1, 1, 0, value);
				memset(buffer, 0, sizeof(uint256_t));
				memcpy((char*)buffer + (sizeof(uint256_t) - size), data, size);
				free(data, size);
			}
		};

		struct mpz_wesolowski
		{
			static void seed_init(mpz_t seed, gmp_randstate_t random, uint16_t bits, const std::string_view& message)
			{
				uint8_t mdata[64];
				hashing::hash512((uint8_t*)message.data(), message.size(), mdata);
				mpz::import0(mdata, sizeof(mdata), seed);

				mpz_t seed_p;
				mpz_init(seed_p);
				gmp_randseed(random, seed);
				mpz_urandomb(seed, random, bits / 2);
				mpz_nextprime(seed, seed_p);
				mpz_clear(seed_p);
			}
			static void order_init(mpz_t order, gmp_randstate_t random, uint16_t bits)
			{
				mpz_t order_p, order_q;
				mpz_init(order_p);
				mpz_init(order_q);
				mpz_urandomb(order_p, random, bits / 2);
				mpz_nextprime(order_p, order_p);
				mpz_urandomb(order_q, random, bits / 2);
				mpz_nextprime(order_q, order_q);
				mpz_mul(order, order_p, order_q);
				mpz_clear(order_p);
				mpz_clear(order_q);
			}
			static void lambda_init(mpz_t lambda, gmp_randstate_t random, uint16_t bits)
			{
				mpz_t lambda_c;
				mpz_init(lambda_c);
				mpz_urandomb(lambda_c, random, bits / 2);
				mpz_nextprime(lambda, lambda_c);
				mpz_clear(lambda_c);
			}
			static void serialize_proof(const mpz_t p, const mpz_t y, string* output)
			{
				format::wo_stream stream;
				stream.write_string(mpz::export0(p));
				stream.write_string(mpz::export0(y));
				output->assign(std::move(stream.data));
			}
			static bool deserialize_proof(mpz_t p, mpz_t y, const std::string_view& input)
			{
				string input_p, input_y;
				format::ro_stream stream = format::ro_stream(input);
				if (!stream.read_string(stream.read_type(), &input_p))
					return false;

				if (!stream.read_string(stream.read_type(), &input_y))
					return false;

				mpz_init(p);
				mpz_init(y);
				mpz::import0((uint8_t*)input_p.data(), input_p.size(), p);
				mpz::import0((uint8_t*)input_y.data(), input_y.size(), y);
				return true;
			}
		};

		uint128_t wesolowski::parameters::difficulty() const
		{
			uint128_t x = uint128_t(bits / 8);
			uint128_t y = uint128_t(ops);
			return x * x * x * y;
		}
		wesolowski::parameters wesolowski::parameters::from_policy()
		{
			parameters result;
			result.bits = protocol::now().policy.wesolowski_bits;
			result.ops = protocol::now().policy.wesolowski_ops;
			return result;
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

		wesolowski::distribution wesolowski::random(const parameters& alg, const std::string_view& seed)
		{
			distribution result;
			result.signature = evaluate(alg, seed);
			result.value = hashing::hash256i(*crypto::hash(digests::sha512(), result.signature));
			return result;
		}
		wesolowski::parameters wesolowski::calibrate(uint64_t confidence, uint64_t target_time)
		{
			uint64_t target_nonce = confidence;
			auto alg = wesolowski::parameters::from_policy();
			while (true)
			{
			retry:
				uint64_t start_time = protocol::now().time.now();
				auto signature = evaluate(alg, *crypto::random_bytes(math32u::random(256, 1024)));
				if (signature.empty())
					break;

				uint64_t end_time = protocol::now().time.now();
				uint64_t delta_time = end_time - start_time;
				double delta_target = (double)delta_time - (double)target_time;
				if (std::abs(delta_target) / target_time < 0.05)
				{
					if (!target_nonce--)
						break;
					goto retry;
				}

				alg = adjust(alg, delta_time, adjustment_interval());
				target_nonce = confidence;
			}
			return alg;
		}
		wesolowski::parameters wesolowski::adjust(const parameters& prev_alg, uint64_t prev_time, uint64_t target_index)
		{
			auto default_alg = wesolowski::parameters::from_policy();
			if (target_index <= 1)
				return default_alg;

			if (adjustment_index(target_index) != target_index)
			{
			leave_as_is:
				return (prev_alg.difficulty() < default_alg.difficulty() ? default_alg : prev_alg);
			}

			auto& policy = protocol::now().policy;
			prev_time = std::max(policy.consensus_proof_time / 4, std::min(policy.consensus_proof_time * 4, prev_time));

			int64_t time_delta = (int64_t)policy.consensus_proof_time - (int64_t)prev_time;
			if (std::abs((double)time_delta) / (double)policy.consensus_proof_time < 0.05)
				goto leave_as_is;

			parameters new_alg = prev_alg;
			decimal adjustment = decimal(time_delta).truncate(protocol::now().message.precision) / prev_time;
			if (adjustment > policy.consensus_difficulty_max_increase)
				adjustment = policy.consensus_difficulty_max_increase;
			else if (adjustment < policy.consensus_difficulty_max_decrease)
				adjustment = policy.consensus_difficulty_max_decrease;

			uint64_t ops_change = (decimal(new_alg.ops) * adjustment).to_uint64();
			new_alg.bits = default_alg.bits;
			new_alg.ops = std::max(new_alg.ops + ops_change >= new_alg.ops ? new_alg.ops + ops_change : std::numeric_limits<uint64_t>::max(), default_alg.ops);
			return new_alg;
		}
		wesolowski::parameters wesolowski::scale(const parameters& alg, double multiplier)
		{
			parameters new_alg = alg;
			if (multiplier > 1.0)
				new_alg.ops = std::max((decimal(new_alg.ops) * decimal(multiplier)).to_uint64(), std::max(new_alg.ops, protocol::now().policy.wesolowski_ops));
			return new_alg;
		}
		string wesolowski::evaluate(const parameters& alg, const std::string_view& message)
		{
			mpz_t seed, order, lambda;
			gmp_randstate_t random;
			gmp_randinit_mt(random);
			mpz_init(seed);
			mpz_init(order);
			mpz_init(lambda);
			mpz_wesolowski::seed_init(seed, random, alg.bits, message);
			mpz_wesolowski::order_init(order, random, alg.bits);
			mpz_wesolowski::lambda_init(lambda, random, alg.bits);
			gmp_randclear(random);

			mpz_t exponent_y, exponent_p;
			mpz_init(exponent_y);
			mpz_init(exponent_p);
			mpz_ui_pow_ui(exponent_y, 2, alg.ops);
			mpz_fdiv_q(exponent_p, exponent_y, lambda);
			mpz_clear(lambda);

			mpz_t p, y;
			mpz_init(p);
			mpz_init(y);
			mpz_powm(y, seed, exponent_y, order);
			mpz_powm(p, seed, exponent_p, order);
			mpz_clear(seed);
			mpz_clear(order);
			mpz_clear(exponent_y);
			mpz_clear(exponent_p);

			string result;
			mpz_wesolowski::serialize_proof(p, y, &result);
			mpz_clear(p);
			mpz_clear(y);
			return result;
		}
		bool wesolowski::verify(const parameters& alg, const std::string_view& message, const std::string_view& proof)
		{
			mpz_t p, y;
			if (!mpz_wesolowski::deserialize_proof(p, y, proof))
				return false;

			mpz_t seed, order, lambda;
			gmp_randstate_t random;
			gmp_randinit_mt(random);
			mpz_init(seed);
			mpz_init(order);
			mpz_init(lambda);
			mpz_wesolowski::seed_init(seed, random, alg.bits, message);
			mpz_wesolowski::order_init(order, random, alg.bits);
			mpz_wesolowski::lambda_init(lambda, random, alg.bits);
			gmp_randclear(random);

			mpz_t exponent_order, exponent_seed, exponent_two, exponent;
			mpz_init(exponent_order);
			mpz_init(exponent_seed);
			mpz_init(exponent_two);
			mpz_init(exponent);
			mpz_sub_ui(exponent_order, lambda, 1);
			mpz_set_ui(exponent_seed, alg.ops);
			mpz_set_ui(exponent_two, 2);
			mpz_mod(exponent_seed, exponent_seed, exponent_order);
			mpz_powm(exponent, exponent_two, exponent_seed, lambda);
			mpz_clear(exponent_order);
			mpz_clear(exponent_seed);
			mpz_clear(exponent_two);

			mpz_t y_target, y_multiplier;
			mpz_init(y_target);
			mpz_init(y_multiplier);
			mpz_powm(y_target, p, lambda, order);
			mpz_powm(y_multiplier, seed, exponent, order);
			mpz_mul(y_target, y_target, y_multiplier);
			mpz_mod(y_target, y_target, order);
			mpz_clear(y_multiplier);
			mpz_clear(exponent);
			mpz_clear(seed);
			mpz_clear(order);
			mpz_clear(lambda);

			int diff = mpz_cmp(y_target, y);
			mpz_clear(y_target);
			mpz_clear(p);
			mpz_clear(y);
			return diff == 0;
		}
		int8_t wesolowski::compare(const std::string_view& proof1, const std::string_view& proof2)
		{
			int result = 0;
			mpz_t p1_p, p1_y, p2_p, p2_y;
			bool p1_valid = mpz_wesolowski::deserialize_proof(p1_p, p1_y, proof1);
			bool p2_valid = mpz_wesolowski::deserialize_proof(p2_p, p2_y, proof2);
			if (p1_valid && p2_valid)
			{
				int compare_y = mpz_cmp(p1_y, p2_y);
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
				mpz_clear(p1_y);
			}

			if (p2_valid)
			{
				mpz_clear(p2_p);
				mpz_clear(p2_y);
			}

			return (int8_t)result;
		}
		uint64_t wesolowski::adjustment_interval()
		{
			auto& policy = protocol::now().policy;
			return policy.consensus_adjustment_time / policy.consensus_proof_time;
		}
		uint64_t wesolowski::adjustment_index(uint64_t index)
		{
			return index - index % adjustment_interval();
		}
		double wesolowski::adjustment_scaling(uint64_t index)
		{
			if (index == 0)
				return 1.0;

			bool outside_priority = index >= protocol::now().policy.production_max_per_block;
			if (outside_priority)
				return protocol::now().policy.consensus_difficulty_bump_outside_priority;

			return mathd::pow(protocol::now().policy.consensus_difficulty_bump_per_priority, index);
		}
		schema* wesolowski::serialize(const parameters& alg, const std::string_view& signature)
		{
			mpz_t p, y;
			if (!mpz_wesolowski::deserialize_proof(p, y, signature))
				return var::set::null();

			auto* data = var::set::object();
			data->set("p", var::string(format::util::encode_0xhex(mpz::export0(p))));
			data->set("y", var::string(format::util::encode_0xhex(mpz::export0(y))));
			data->set("difficulty", algorithm::encoding::serialize_uint256(alg.difficulty()));
			data->set("bits", var::integer(alg.bits));
			data->set("ops", var::integer(alg.ops));
			data->set("size", var::integer(signature.size()));
			mpz_clear(p);
			mpz_clear(y);
			return data;
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
			message.write_typeless(protocol::now().account.message_magic);
			message.write_typeless(signable_message.data(), signable_message.size());
			return message.hash();
		}
		string signing::mnemonicgen(uint16_t strength)
		{
			char buffer[256] = { 0 };
			mnemonic_generate((int)strength, buffer, (int)sizeof(buffer));
			return string(buffer, strnlen(buffer, sizeof(buffer)));
		}
		void signing::keygen(seckey_t& secret_key)
		{
			while (true)
			{
				if (!crypto::fill_random_bytes(secret_key.data, sizeof(seckey_t)))
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
			memcpy(&recovery_id, signature.data + recovery_offset, sizeof(recovery_id));
			if (recovery_id > 4)
				return false;

			secp256k1_context* context = get_context();
			secp256k1_ecdsa_recoverable_signature recoverable_signature;
			if (!secp256k1_ecdsa_recoverable_signature_parse_compact(context, &recoverable_signature, signature.data, recovery_id))
				return false;

			uint8_t data[32];
			hash.encode(data);

			secp256k1_pubkey recovered_public_key;
			if (secp256k1_ecdsa_recover(context, &recovered_public_key, &recoverable_signature, data) != 1)
				return false;

			size_t public_key_size = sizeof(pubkey_t);
			return secp256k1_ec_pubkey_serialize(context, public_key.data, &public_key_size, &recovered_public_key, SECP256K1_EC_COMPRESSED) == 1;
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
			memset(signature.data, 0, sizeof(hashsig_t));

			secp256k1_context* context = get_context();
			secp256k1_ecdsa_recoverable_signature recoverable_signature;
			if (secp256k1_ecdsa_sign_recoverable(context, &recoverable_signature, data, secret_key.data, secp256k1_nonce_function_rfc6979, nullptr) != 1)
				return false;

			int recovery_id = 0;
			if (secp256k1_ecdsa_recoverable_signature_serialize_compact(context, signature.data, &recovery_id, &recoverable_signature) != 1)
				return false;

			signature.data[sizeof(hashsig_t) - 1] = (uint8_t)recovery_id;
			return true;
		}
		bool signing::verify(const uint256_t& hash, const pubkey_t& public_key, const hashsig_t& signature)
		{
			secp256k1_context* context = get_context();
			secp256k1_ecdsa_signature compact_signature;
			if (secp256k1_ecdsa_signature_parse_compact(context, &compact_signature, signature.data) != 1)
				return false;

			secp256k1_pubkey derived_public_key;
			if (secp256k1_ec_pubkey_parse(context, &derived_public_key, public_key.data, sizeof(pubkey_t)) != 1)
				return false;

			uint8_t data[32];
			secp256k1_ecdsa_signature normalized_signature;
			secp256k1_ecdsa_signature_normalize(context, &normalized_signature, &compact_signature);
			hash.encode(data);
			return secp256k1_ecdsa_verify(context, &normalized_signature, data, &derived_public_key) == 1;
		}
		bool signing::verify_mnemonic(const std::string_view& mnemonic)
		{
			string data = string(mnemonic);
			return mnemonic_check(data.c_str()) == 1;
		}
		bool signing::verify_secret_key(const seckey_t& secret_key)
		{
			secp256k1_context* context = get_context();
			return secp256k1_ec_seckey_verify(context, secret_key.data) == 1;
		}
		bool signing::verify_public_key(const pubkey_t& public_key)
		{
			secp256k1_pubkey derived_public_key;
			secp256k1_context* context = get_context();
			return secp256k1_ec_pubkey_parse(context, &derived_public_key, public_key.data, sizeof(pubkey_t)) == 1;
		}
		bool signing::verify_address(const std::string_view& address)
		{
			pubkeyhash_t public_key_hash;
			return decode_address(address, public_key_hash);
		}
		bool signing::verify_sealed_message(const std::string_view& ciphertext)
		{
			return ciphertext.size() > crypto_box_SEALBYTES;
		}
		void signing::derive_secret_key_from_mnemonic(const std::string_view& mnemonic, seckey_t& secret_key)
		{
			VI_ASSERT(stringify::is_cstring(mnemonic), "mnemonic should be set");
			uint8_t seed[64] = { 0 };
			mnemonic_to_seed(mnemonic.data(), "", seed, nullptr);
			derive_secret_key(std::string_view((char*)seed, sizeof(seed)), secret_key);
		}
		void signing::derive_secret_key(const std::string_view& seed, seckey_t& secret_key)
		{
			string derivation = string(seed);
			while (true)
			{
				derivation = hashing::hash256((uint8_t*)derivation.data(), derivation.size());
				memcpy(secret_key.data, derivation.data(), sizeof(seckey_t));
				if (verify_secret_key(secret_key))
					break;
			}
		}
		bool signing::derive_public_key(const seckey_t& secret_key, pubkey_t& public_key)
		{
			secp256k1_pubkey derived_public_key;
			secp256k1_context* context = get_context();
			memset(public_key.data, 0, sizeof(pubkey_t));
			if (secp256k1_ec_pubkey_create(context, &derived_public_key, secret_key.data) != 1)
				return false;

			size_t public_key_size = sizeof(pubkey_t);
			return secp256k1_ec_pubkey_serialize(context, public_key.data, &public_key_size, &derived_public_key, SECP256K1_EC_COMPRESSED) == 1;
		}
		void signing::derive_public_key_hash(const pubkey_t& public_key, pubkeyhash_t& public_key_hash)
		{
			hashing::hash160(public_key.data, sizeof(pubkey_t), public_key_hash.data);
		}
		void signing::derive_cipher_keypair(const seckey_t& secret_key, const uint256_t& nonce, seckey_t& cipher_secret_key, pubkey_t& cipher_public_key)
		{
			format::wo_stream message;
			message.write_typeless(secret_key.data, sizeof(seckey_t));
			message.write_typeless(nonce);

			uint8_t seed[32];
			message.hash().encode(seed);
			memset(cipher_public_key.data, 0, sizeof(pubkey_t));
			crypto_box_seed_keypair(cipher_public_key.data, cipher_secret_key.data, seed);
		}
		option<string> signing::public_encrypt(const pubkey_t& cipher_public_key, const std::string_view& plaintext, const std::string_view& entropy)
		{
			if (plaintext.empty())
				return optional::none;

			string salt = hashing::hash512((uint8_t*)entropy.data(), entropy.size());
			string body = salt + string(plaintext);
			for (size_t i = salt.size(); i < body.size(); i++)
				body[i] ^= salt[i % salt.size()];
			body.append(hashing::hash256((uint8_t*)plaintext.data(), plaintext.size()));

			uint8_t seed[crypto_box_SEEDBYTES];
			uint8_t ephemeral_secret_key[crypto_box_SECRETKEYBYTES];
			uint8_t ephemeral_public_key[crypto_box_PUBLICKEYBYTES];
			algorithm::hashing::hash256((uint8_t*)entropy.data(), entropy.size(), seed);
			if (crypto_box_seed_keypair(ephemeral_public_key, ephemeral_secret_key, seed) != 0)
				return optional::none;

			uint8_t nonce[crypto_box_NONCEBYTES];
			crypto_generichash_state state;
			crypto_generichash_init(&state, nullptr, 0, crypto_box_NONCEBYTES);
			crypto_generichash_update(&state, ephemeral_public_key, crypto_box_PUBLICKEYBYTES);
			crypto_generichash_update(&state, cipher_public_key.data, crypto_box_PUBLICKEYBYTES);
			crypto_generichash_final(&state, nonce, crypto_box_NONCEBYTES);

			string ciphertext;
			ciphertext.resize(crypto_box_SEALBYTES + body.size());
			memcpy(ciphertext.data(), ephemeral_public_key, crypto_box_PUBLICKEYBYTES);
			if (crypto_box_easy((uint8_t*)ciphertext.data() + crypto_box_PUBLICKEYBYTES, (uint8_t*)body.data(), body.size(), nonce, cipher_public_key.data, ephemeral_secret_key) != 0)
				return optional::none;

			return ciphertext;
		}
		option<string> signing::private_decrypt(const seckey_t& cipher_secret_key, const pubkey_t& cipher_public_key, const std::string_view& ciphertext)
		{
			if (ciphertext.size() <= crypto_box_SEALBYTES)
				return optional::none;

			string body;
			body.resize(ciphertext.size() - crypto_box_SEALBYTES);
			if (crypto_box_seal_open((uint8_t*)body.data(), (uint8_t*)ciphertext.data(), ciphertext.size(), cipher_public_key.data, cipher_secret_key.data) != 0)
				return optional::none;

			if (body.size() < 96)
				return optional::none;

			size_t salt_body_size = body.size() - 32;
			std::string_view salt = std::string_view(body).substr(0, 64);
			for (size_t i = salt.size(); i < salt_body_size; i++)
				body[i] ^= salt[i % salt.size()];

			size_t plaintext_size = body.size() - 96;
			std::string_view checksum = std::string_view(body).substr(salt_body_size);
			std::string_view plaintext = std::string_view(body).substr(salt.size(), plaintext_size);
			if (hashing::hash256((uint8_t*)plaintext.data(), plaintext.size()) != checksum)
				return optional::none;

			return string(plaintext);
		}
		bool signing::decode_secret_key(const std::string_view& value, seckey_t& secret_key)
		{
			auto& account = protocol::now().account;
			uint8_t decoded[40];
			size_t decoded_size = sizeof(decoded);
			int version = 0;

			if (segwit::decode(&version, decoded, &decoded_size, account.secret_key_prefix.c_str(), value.data()) != 1)
				return false;
			else if (version != (int)account.secret_key_version)
				return false;
			else if (decoded_size != sizeof(seckey_t))
				return false;

			memcpy(secret_key.data, decoded, sizeof(seckey_t));
			return true;
		}
		bool signing::encode_secret_key(const seckey_t& secret_key, string& value)
		{
			auto& account = protocol::now().account;
			char encoded[128];
			if (segwit::encode(encoded, account.secret_key_prefix.c_str(), (int)account.secret_key_version, secret_key.data, sizeof(seckey_t)) != 1)
				return false;

			size_t size = strnlen(encoded, sizeof(encoded));
			value.resize(size);
			memcpy(value.data(), encoded, size);
			return true;
		}
		bool signing::decode_public_key(const std::string_view& value, pubkey_t& public_key)
		{
			auto& account = protocol::now().account;
			uint8_t decoded[40];
			size_t decoded_size = sizeof(decoded);
			int version = 0;

			if (segwit::decode(&version, decoded, &decoded_size, account.public_key_prefix.c_str(), value.data()) != 1)
				return false;
			else if (version != (int)account.public_key_version)
				return false;
			else if (decoded_size != sizeof(pubkey_t))
				return false;

			memcpy(public_key.data, decoded, sizeof(pubkey_t));
			return true;
		}
		bool signing::encode_public_key(const pubkey_t& public_key, string& value)
		{
			auto& account = protocol::now().account;
			char encoded[128];
			if (segwit::encode(encoded, account.public_key_prefix.c_str(), (int)account.public_key_version, public_key.data, sizeof(pubkey_t)) != 1)
				return false;

			size_t size = strnlen(encoded, sizeof(encoded));
			value.resize(size);
			memcpy(value.data(), encoded, size);
			return true;
		}
		bool signing::decode_address(const std::string_view& address, pubkeyhash_t& public_key_hash)
		{
			VI_ASSERT(stringify::is_cstring(address), "public key hash, derivation hash and address should be set");
			auto& account = protocol::now().account;
			uint8_t decoded[60];
			size_t decoded_size = sizeof(decoded);
			int version = 0;

			if (segwit::decode(&version, decoded, &decoded_size, account.address_prefix.c_str(), address.data()) != 1)
				return false;
			else if (version != (int)account.address_version)
				return false;
			else if (decoded_size != sizeof(pubkeyhash_t))
				return false;

			memcpy(public_key_hash.data, decoded, decoded_size);
			return true;
		}
		bool signing::encode_address(const pubkeyhash_t& public_key_hash, string& address)
		{
			char encoded[128];
			auto& account = protocol::now().account;
			if (segwit::encode(encoded, account.address_prefix.c_str(), (int)account.address_version, public_key_hash.data, sizeof(pubkeyhash_t)) != 1)
				return false;

			size_t size = strnlen(encoded, sizeof(encoded));
			address.resize(size);
			memcpy(address.data(), encoded, size);
			return true;
		}
		schema* signing::serialize_secret_key(const seckey_t& secret_key)
		{
			if (secret_key.empty())
				return var::set::null();

			string data;
			if (!encode_secret_key(secret_key, data))
				return var::set::null();

			return var::set::string(data);
		}
		schema* signing::serialize_public_key(const pubkey_t& public_key)
		{
			if (public_key.empty())
				return var::set::null();

			string data;
			if (!encode_public_key(public_key, data))
				return var::set::null();

			return var::set::string(data);
		}
		schema* signing::serialize_address(const pubkeyhash_t& public_key_hash)
		{
			if (public_key_hash.empty())
				return var::set::null();

			string data;
			if (!encode_address(public_key_hash, data))
				return var::set::null();

			return var::set::string(data);
		}
		secp256k1_context* signing::get_context()
		{
			VI_ASSERT(shared_context != nullptr, "secp256k1 context is not initialized");
			return shared_context;
		}
		secp256k1_context* signing::shared_context = nullptr;

		bool encoding::decode_bytes(const string& value, uint8_t* data, size_t data_size)
		{
			VI_ASSERT(data != nullptr, "data should be set");
			if (value.size() < data_size)
				memset(data, 0, data_size);
			else if (value.size() > data_size)
				return false;

			memcpy(data, value.data(), value.size());
			return true;
		}
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
		schema* encoding::serialize_uint256(const uint256_t& value, bool always16)
		{
			if (!always16 && value <= std::numeric_limits<int64_t>::max())
				return var::set::integer((uint64_t)value);

			uint8_t data[32];
			value.encode(data);

			size_t size = value.bytes();
			return var::set::string(format::util::encode_0xhex(std::string_view((char*)data + (sizeof(data) - size), size)));
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
			uint8_t hash[BLAKE256_DIGEST_LENGTH];
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
			uint256_t value;
			auto hash = hash256(buffer, size);
			value.decode((uint8_t*)hash.data());
			return value;
		}
		uint256_t hashing::hash256i(const std::string_view& data)
		{
			return hash256i((uint8_t*)data.data(), data.size());
		}
		uint64_t hashing::erd64(const uint256_t& entropy, uint64_t order)
		{
			const double lamda = 9.0;
			const double exponent = std::exp(-lamda);
			const double base = (double)(uint64_t)(entropy % std::numeric_limits<uint32_t>::max()) / (double)std::numeric_limits<uint32_t>::max();
			const double factor = std::min(1.0, std::max(0.0, -std::log(1.0 - (1.0 - exponent) * base) / lamda));
			const uint64_t index = (uint64_t)(factor * (double)order) % order;
			return index;
		}

		asset_id asset::id_of_handle(const std::string_view& handle)
		{
			uint8_t data[32] = { 0 };
			size_t size = std::min<size_t>(sizeof(data), handle.size());
			memcpy((char*)data + (sizeof(data) - size), handle.data(), size);

			uint256_t value;
			value.decode(data);
			return value;
		}
		asset_id asset::id_of(const std::string_view& blockchain, const std::string_view& token, const std::string_view& contract_address)
		{
			uint8_t data[32] = { 0 };
			string handle = handle_of(blockchain, token, contract_address);
			size_t size = std::min<size_t>(sizeof(data), handle.size());
			memcpy((char*)data + (sizeof(data) - size), handle.data(), size);

			uint256_t value;
			value.decode(data);
			return value;
		}
		asset_id asset::base_id_of(const asset_id& value)
		{
			return id_of(blockchain_of(value));
		}
		string asset::handle_of(const std::string_view& blockchain, const std::string_view& token, const std::string_view& contract_address)
		{
			string handle;
			handle.append(blockchain.substr(0, 8));
			if (!token.empty())
			{
				handle.append(1, ':').append(token.substr(0, 8));
				if (!contract_address.empty())
				{
					auto hash = codec::base64_url_encode(*crypto::hash(digests::sha1(), format::util::is_hex_encoding(contract_address) ? codec::hex_decode(contract_address) : string(contract_address)));
					stringify::replace_of(hash, "-_", "");
					handle.append(1, ':').append(hash.substr(0, 32 - handle.size()));
				}
			}
			return handle.substr(0, 32);
		}
		string asset::handle_of(const asset_id& value)
		{
			uint8_t data[33];
			value.encode(data);

			size_t offset = 0;
			while (!data[offset] && offset + 1 < sizeof(data))
				++offset;

			char* handle = (char*)data + offset;
			return string(handle, strnlen(handle, (sizeof(data) - 1) - offset));
		}
		string asset::base_handle_of(const asset_id& value)
		{
			return handle_of(base_id_of(value));
		}
		string asset::blockchain_of(const asset_id& value)
		{
			string handle = handle_of(value);
			std::string_view view = std::string_view(handle);
			size_t indices = view.find(':');
			std::string_view blockchain = view.substr(0, indices);
			return string(blockchain);
		}
		string asset::token_of(const asset_id& value)
		{
			string handle = handle_of(value);
			std::string_view view = std::string_view(handle);
			size_t indices[2] = { view.find(':'), view.rfind(':') };
			std::string_view token = indices[0] != std::string::npos && indices[0] + 1 < view.size() ? view.substr(indices[0] + 1, indices[1] != std::string::npos ? indices[1] - indices[0] - 1 : std::string::npos) : std::string_view();
			return string(token);
		}
		string asset::checksum_of(const asset_id& value)
		{
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
		bool asset::is_valid(const asset_id& value)
		{
			if (!value)
				return false;

			auto blockchain = blockchain_of(value);
			if (stringify::is_empty_or_whitespace(blockchain))
				return false;

			auto* chain = nss::server_node::get()->get_chain(value);
			if (!chain)
				return false;

			auto token = token_of(value);
			if (stringify::is_empty_or_whitespace(token))
				return true;

			auto checksum = checksum_of(value);
			if (stringify::is_empty_or_whitespace(checksum))
				return false;

			return chain->has_token(value);
		}
		uint64_t asset::expiry_of(const asset_id& value)
		{
			if (!value)
				return 0;

			auto blockchain = blockchain_of(value);
			if (stringify::is_empty_or_whitespace(blockchain))
				return 0;

			auto* chain = nss::server_node::get()->get_chain(value);
			if (!chain)
				return 0;

			auto token = token_of(value);
			if (stringify::is_empty_or_whitespace(token))
				return chain->get_retirement_block_number();

			auto checksum = checksum_of(value);
			if (stringify::is_empty_or_whitespace(checksum))
				return 0;

			return chain->get_retirement_block_number();
		}
		schema* asset::serialize(const asset_id& value)
		{
			schema* data = var::set::object();
			data->set("id", encoding::serialize_uint256(value, true));
			string chain = blockchain_of(value);
			if (!chain.empty())
				data->set("chain", var::string(chain));
			string token = token_of(value);
			if (!token.empty())
				data->set("token", var::string(token));
			string checksum = checksum_of(value);
			if (!checksum.empty())
				data->set("checksum", var::string(checksum));
			return data;
		}

		expects_lr<void> composition::derive_keypair(type alg, const uint256_t& seed, keypair* result)
		{
			VI_ASSERT(result != nullptr, "result should be set");
			uint8_t seed_buffer[32];
			seed.encode(seed_buffer);
			hashing::hash512(seed_buffer, sizeof(seed_buffer), result->secret_key.data);
			memset(result->public_key.data, 0, sizeof(cpubkey_t));
			switch (alg)
			{
				case type::ed25519:
				{
					keypair_utils::convert_to_scalar_ed25519(result->secret_key.data, result->secret_key.data);
					ed25519_publickey_ext(result->secret_key.data, result->public_key.data);
					memset(result->secret_key.data + 32, 0, 32);
					memset(result->public_key.data + 32, 0, 32);
					return expectation::met;
				}
				case type::ed25519_clsag:
				{
					keypair_utils::convert_to_scalar_ed25519(result->secret_key.data, result->secret_key.data);
					sc_reduce32(result->secret_key.data);
					ed25519_publickey_ext(result->secret_key.data, result->public_key.data);
					memset(result->secret_key.data + 32, 0, 32);
					memset(result->public_key.data + 32, 0, 32);
					return expectation::met;
				}
				case type::secp256k1:
				case type::schnorr:
				case type::schnorr_taproot:
				{
					secp256k1_context* context = signing::get_context();
					secp256k1_pubkey extended_public_key;
					while (secp256k1_ec_seckey_verify(context, result->secret_key.data) != 1 || secp256k1_ec_pubkey_create(context, &extended_public_key, result->secret_key.data) != 1)
						hashing::hash512(result->secret_key.data, sizeof(cseckey_t), result->secret_key.data);

					size_t key_size = sizeof(extended_public_key);
					if (secp256k1_ec_pubkey_serialize(context, result->public_key.data, &key_size, &extended_public_key, SECP256K1_EC_COMPRESSED) != 1)
						return layer_exception("bad seed");

					return expectation::met;
				}
				default:
					return layer_exception("invalid composition algorithm");
			}
		}
		expects_lr<void> composition::accumulate_secret_key(type alg, const cseckey_t& share_secret_key, cseckey_t& inout)
		{
			const auto condition = stage_of(share_secret_key, inout.data, sizeof(cseckey_t));
			switch (alg)
			{
				case type::ed25519:
				case type::ed25519_clsag:
				{
					switch (condition)
					{
						case stage::configure:
						{
							memcpy(inout.data, share_secret_key.data, sizeof(cseckey_t));
							return expectation::met;
						}
						case stage::accumulate:
						{
							crypto_core_ed25519_scalar_mul(inout.data, inout.data, share_secret_key.data);
							return expectation::met;
						}
						case stage::finalize:
							return expectation::met;
						default:
							return layer_exception("invalid stage");
					}
				}
				case type::secp256k1:
				case type::schnorr:
				case type::schnorr_taproot:
				{
					switch (condition)
					{
						case stage::configure:
						{
							memcpy(inout.data, share_secret_key.data, sizeof(cseckey_t));
							return expectation::met;
						}
						case stage::accumulate:
						{
							secp256k1_context* context = signing::get_context();
							if (secp256k1_ec_seckey_tweak_mul(context, inout.data, share_secret_key.data) != 1)
								return layer_exception("bad share secret key");

							return expectation::met;
						}
						case stage::finalize:
							return expectation::met;
						default:
							return layer_exception("invalid stage");
					}
				}
				default:
					return layer_exception("invalid composition algorithm");
			}
		}
		expects_lr<void> composition::accumulate_public_key(type alg, const cseckey_t& share_secret_key, cpubkey_t& inout)
		{
			const auto condition = stage_of(share_secret_key, inout.data, sizeof(cpubkey_t));
			switch (alg)
			{
				case type::ed25519:
				case type::ed25519_clsag:
				{
					switch (condition)
					{
						case stage::configure:
						{
							ed25519_publickey_ext(share_secret_key.data, inout.data);
							return expectation::met;
						}
						case stage::accumulate:
						{
							if (crypto_scalarmult_ed25519(inout.data, share_secret_key.data, inout.data) != 0)
								return layer_exception("bad share secret key");

							return expectation::met;
						}
						case stage::finalize:
							return expectation::met;
						default:
							return layer_exception("invalid stage");
					}
				}
				case type::secp256k1:
				{
					secp256k1_context* context = signing::get_context();
					secp256k1_pubkey result_public_key;
					switch (condition)
					{
						case stage::configure:
						{
							if (secp256k1_ec_pubkey_create(context, &result_public_key, share_secret_key.data) != 1)
								return layer_exception("bad share secret key");

							size_t key_size = sizeof(result_public_key);
							if (secp256k1_ec_pubkey_serialize(context, inout.data, &key_size, &result_public_key, SECP256K1_EC_COMPRESSED) != 1)
								return layer_exception("bad share secret key");

							return expectation::met;
						}
						case stage::accumulate:
						{
							if (secp256k1_ec_pubkey_parse(context, &result_public_key, inout.data, size_of_public_key(alg, stage::accumulate)) != 1)
								return layer_exception("bad intermediate public key");

							if (secp256k1_ec_pubkey_tweak_mul(context, &result_public_key, share_secret_key.data) != 1)
								return layer_exception("bad share secret key");

							size_t key_size = sizeof(result_public_key);
							if (secp256k1_ec_pubkey_serialize(context, inout.data, &key_size, &result_public_key, SECP256K1_EC_COMPRESSED) != 1)
								return layer_exception("bad share secret key");

							return expectation::met;
						}
						case stage::finalize:
							return expectation::met;
						default:
							return layer_exception("invalid stage");
					}
				}
				case type::schnorr:
				case type::schnorr_taproot:
				{
					secp256k1_context* context = signing::get_context();
					secp256k1_pubkey result_public_key;
					switch (condition)
					{
						case stage::configure:
						{
							if (secp256k1_ec_pubkey_create(context, &result_public_key, share_secret_key.data) != 1)
								return layer_exception("bad share secret key");

							size_t key_size = sizeof(result_public_key);
							if (secp256k1_ec_pubkey_serialize(context, inout.data, &key_size, &result_public_key, SECP256K1_EC_COMPRESSED) != 1)
								return layer_exception("bad share secret key");

							return expectation::met;
						}
						case stage::accumulate:
						{
							if (secp256k1_ec_pubkey_parse(context, &result_public_key, inout.data, size_of_public_key(type::secp256k1, stage::accumulate)) != 1)
								return layer_exception("bad intermediate public key");
							
							if (secp256k1_ec_pubkey_tweak_mul(context, &result_public_key, share_secret_key.data) != 1)
								return layer_exception("bad share secret key");

							size_t key_size = sizeof(result_public_key);
							if (secp256k1_ec_pubkey_serialize(context, inout.data, &key_size, &result_public_key, SECP256K1_EC_COMPRESSED) != 1)
								return layer_exception("bad share secret key");

							return expectation::met;
						}
						case stage::finalize:
						{
							if (secp256k1_ec_pubkey_parse(context, &result_public_key, inout.data, size_of_public_key(type::secp256k1, stage::accumulate)) != 1)
								return layer_exception("bad intermediate public key");

							secp256k1_xonly_pubkey result_xonly_public_key;
							if (secp256k1_xonly_pubkey_from_pubkey(context, &result_xonly_public_key, nullptr, &result_public_key) != 1)
								return layer_exception("bad share secret key");

							if (secp256k1_xonly_pubkey_serialize(context, inout.data, &result_xonly_public_key) != 1)
								return layer_exception("bad share secret key");

							inout.data[32] = 0;
							return expectation::met;
						}
						default:
							return layer_exception("invalid stage");
					}
				}
				default:
					return layer_exception("invalid composition algorithm");
			}
		}
		expects_lr<void> composition::accumulate_signature(type alg, const uint8_t* message, size_t message_size, const cpubkey_t& final_public_key, const cseckey_t& share_secret_key, chashsig_t& inout)
		{
			VI_ASSERT(message != nullptr, "message should be set");
			const auto condition = stage_of(share_secret_key, inout.data, sizeof(chashsig_t));
			switch (alg)
			{
				case type::ed25519:
				{
					switch (condition)
					{
						case stage::configure:
						case stage::finalize:
						{
							bignum256 a;
							bn_read_uint32(0, &a);
						retry_ed25519:
							uint8_t nonce[64];
							crypto_hash_sha512_state hash;
							crypto_hash_sha512_init(&hash);
							crypto_hash_sha512_update(&hash, final_public_key.data, size_of_public_key(alg, stage::finalize));
							crypto_hash_sha512_update(&hash, message, message_size);
							if (!bn_is_zero(&a))
							{
								uint8_t anonce[32];
								bn_write_be(&a, anonce);
								crypto_hash_sha512_update(&hash, anonce, sizeof(anonce));
							}
							crypto_hash_sha512_final(&hash, nonce);
							crypto_core_ed25519_scalar_reduce(nonce, nonce);

							uint8_t r[crypto_core_ed25519_SCALARBYTES], zero[crypto_core_ed25519_SCALARBYTES] = { 0 };
							if (crypto_scalarmult_ed25519_base_noclamp(r, nonce) != 0 || !memcmp(zero, r, sizeof(r)))
							{
								bn_addi(&a, 1);
								goto retry_ed25519;
							}

							if (condition == stage::configure)
							{
								uint8_t hram[64];
								crypto_hash_sha512_init(&hash);
								crypto_hash_sha512_update(&hash, r, sizeof(r));
								crypto_hash_sha512_update(&hash, final_public_key.data, size_of_public_key(alg, stage::finalize));
								crypto_hash_sha512_update(&hash, message, message_size);
								crypto_hash_sha512_final(&hash, hram);
								crypto_core_ed25519_scalar_reduce(hram, hram);
								crypto_core_ed25519_scalar_mul(inout.data, hram, share_secret_key.data);
								return expectation::met;
							}

							uint8_t s[crypto_core_ed25519_SCALARBYTES];
							crypto_core_ed25519_scalar_add(s, inout.data, nonce);
							if (!memcmp(zero, s, sizeof(s)))
								return layer_exception("bad final signature");

							memcpy(inout.data, r, sizeof(r));
							memcpy(inout.data + sizeof(r), s, sizeof(s));
							return verify_signature(alg, message, message_size, final_public_key, inout);
						}
						case stage::accumulate:
						{
							uint8_t zero[crypto_core_ed25519_SCALARBYTES] = { 0 };
							crypto_core_ed25519_scalar_mul(inout.data, inout.data, share_secret_key.data);
							if (!memcmp(inout.data, zero, sizeof(zero)))
								return layer_exception("bad share secret key");

							return expectation::met;
						}
						default:
							return layer_exception("invalid stage");
					}
				}
				case type::ed25519_clsag:
				{
					/* Not implemented yet */
					memset(inout.data, 0xcc, sizeof(cpubkey_t));
					return expectation::met;
				}
				case type::secp256k1:
				{
					auto* curve = &secp256k1;
					switch (condition)
					{
						case stage::configure:
						case stage::finalize:
						{
							uint8_t message_hash[32];
							if (message_size != sizeof(message_hash))
								sha256_Raw(message, message_size, message_hash);
							else
								memcpy(message_hash, message, sizeof(message_hash));

							uint8_t ask[32], nonce[32]; uint32_t attempt = 0;
							sha256_Raw(final_public_key.data, size_of_public_key(alg, stage::finalize), ask);
						retry_secp256k1:
							secp256k1_nonce_function_rfc6979(nonce, message_hash, ask, nullptr, nullptr, attempt);

							bignum256 k = { 0 };
							curve_point r = { 0 };
							bn_read_be(nonce, &k);
							bn_mod(&k, &curve->order);
							scalar_multiply(curve, &k, &r);

							bn_mod(&r.x, &curve->order);
							if (bn_is_zero(&r.x))
							{
								++attempt;
								goto retry_secp256k1;
							}

							if (condition == stage::configure)
							{
								bignum256 s;
								bn_read_be(share_secret_key.data, &s);
								bn_multiply(&r.x, &s, &curve->order);
								bn_write_be(&s, inout.data);
								return expectation::met;
							}

							bignum256 z = { 0 };
							bn_read_be(message_hash, &z);
							if (bn_is_zero(&z))
								return layer_exception("bad message");

							bignum256 s;
							bn_read_be(inout.data, &s);
							bn_inverse(&k, &curve->order);
							bn_addmod(&s, &z, &curve->order);
							bn_multiply(&k, &s, &curve->order);
							if (bn_is_zero(&s))
								return layer_exception("bad final signature");
							if (bn_is_less(&curve->order_half, &s))
								bn_subtract(&curve->order, &s, &s);

							auto* context = signing::get_context();
							bn_write_be(&r.x, inout.data);
							bn_write_be(&s, inout.data + 32);
							for (uint8_t recovery_id = 0; recovery_id < 4; recovery_id++)
							{
								secp256k1_ecdsa_recoverable_signature recoverable_signature;
								if (secp256k1_ecdsa_recoverable_signature_parse_compact(context, &recoverable_signature, inout.data, recovery_id))
								{
									secp256k1_pubkey recovered_public_key;
									if (secp256k1_ecdsa_recover(context, &recovered_public_key, &recoverable_signature, message_hash) == 1)
									{
										uint8_t public_key[33]; size_t public_key_size = sizeof(public_key);
										if (secp256k1_ec_pubkey_serialize(context, public_key, &public_key_size, &recovered_public_key, SECP256K1_EC_COMPRESSED) == 1)
										{
											if (!memcmp(final_public_key.data, public_key, public_key_size))
											{
												inout.data[sizeof(chashsig_t) - 1] = recovery_id;
												return verify_signature(alg, message, message_size, final_public_key, inout);
											}
										}
									}
								}
							}

							return layer_exception("final signature verification failed");
						}
						case stage::accumulate:
						{
							bignum256 s, p;
							bn_read_be(inout.data, &s);
							bn_read_be(share_secret_key.data, &p);
							bn_multiply(&p, &s, &curve->order);
							if (bn_is_zero(&s))
								return layer_exception("bad share secret key");

							bn_write_be(&s, inout.data);
							return expectation::met;
						}
						default:
							return layer_exception("invalid stage");
					}
				}
				case type::schnorr:
				case type::schnorr_taproot:
				{
					size_t public_key_size = size_of_public_key(type::schnorr, stage::finalize);
					auto* curve = &secp256k1;
					switch (condition)
					{
						case stage::configure:
						case stage::finalize:
						{
							uint8_t message_hash[32];
							if (message_size != sizeof(message_hash))
								sha256_Raw(message, message_size, message_hash);
							else
								memcpy(message_hash, message, sizeof(message_hash));

							uint8_t bip340_algo[] = "BIP0340/nonce";
							uint8_t ask[32], nonce[32], anonce[32];
							sha256_Raw(final_public_key.data, public_key_size, ask);

							bignum256 a;
							bn_read_uint32(0, &a);
						retry_schnorr:
							bn_write_be(&a, anonce);
							secp256k1_nonce_function_bip340(nonce, message_hash, sizeof(message_hash), ask, final_public_key.data, bip340_algo, sizeof(bip340_algo) - 1, anonce);

							bignum256 k = { 0 };
							curve_point r = { 0 };
							bn_read_be(nonce, &k);
							bn_mod(&k, &curve->order);
							scalar_multiply(curve, &k, &r);
							bn_mod(&r.x, &curve->order);
							if (bn_is_zero(&r.x))
							{
								bn_addi(&a, 1);
								goto retry_schnorr;
							}
							else if (bn_is_odd(&r.y))
								bn_subtractmod(&curve->order, &k, &k, &curve->order);

							uint8_t e_data[96], e_hash[32];
							bn_write_be(&r.x, e_data);
							memcpy(e_data + 32, final_public_key.data, public_key_size);
							memcpy(e_data + 64, message_hash, sizeof(message_hash));

							uint8_t bip340_challenge[] = "BIP0340/challenge";
							secp256k1_context* context = signing::get_context();
							if (secp256k1_tagged_sha256(context, e_hash, bip340_challenge, sizeof(bip340_challenge) - 1, e_data, sizeof(e_data)) != 1)
                                return layer_exception("bad message");
                            
							bignum256 e;
							bn_read_be(e_hash, &e);
							bn_mod(&e, &curve->order);
							if (bn_is_zero(&e))
								return layer_exception("bad message");

							if (condition == stage::configure)
							{
								bignum256 s;
								bn_read_be(share_secret_key.data, &s);
								bn_multiply(&e, &s, &curve->order);
								bn_write_be(&s, inout.data);
								return expectation::met;
							}
							
							bignum256 s;
							bn_read_be(inout.data, &s);
							if (alg == type::schnorr_taproot)
							{
								bignum256 t;
								bn_read_be(final_public_key.data + 32, &t);

								bool is_taproot = !bn_is_zero(&t);
								if (is_taproot)
								{
									bn_multiply(&e, &t, &curve->order);
									bn_addmod(&s, &t, &curve->order);
									if (bn_is_zero(&s))
										return layer_exception("bad final signature");
								}
							}

							bool is_odd = final_public_key.data[32];
							if (is_odd)
							{
								bn_multiply(&curve->order, &e, &curve->order);
								bn_subtractmod(&e, &s, &s, &curve->order);
							}

							bn_addmod(&s, &k, &curve->order);
							if (bn_is_zero(&s))
								return layer_exception("bad final signature");

							bn_write_be(&r.x, inout.data);
							bn_write_be(&s, inout.data + 32);
							return verify_signature(alg, message, message_size, final_public_key, inout);
						}
						case stage::accumulate:
						{
							bignum256 s, p;
							bn_read_be(inout.data, &s);
							bn_read_be(share_secret_key.data, &p);
							bn_multiply(&p, &s, &curve->order);
							if (bn_is_zero(&s))
								return layer_exception("bad share secret key");

							bn_write_be(&s, inout.data);
							return expectation::met;
						}
						default:
							return layer_exception("invalid stage");
					}

					return expectation::met;
				}
				default:
					return layer_exception("invalid composition algorithm");
			}
		}
		expects_lr<void> composition::verify_signature(type alg, const uint8_t* message, size_t message_size, const cpubkey_t& final_public_key, const chashsig_t& final_signature)
		{
			VI_ASSERT(message != nullptr, "message should be set");
			switch (alg)
			{
				case type::ed25519:
				{
					if (crypto_sign_verify_detached(final_signature.data, message, message_size, final_public_key.data) != 0)
						return layer_exception("final signature verification failed");

					return expectation::met;
				}
				case type::ed25519_clsag:
				{
					/* Not implemented yet */
					return expectation::met;
				}
				case type::secp256k1:
				{
					uint8_t message_hash[32];
					if (message_size != sizeof(message_hash))
						sha256_Raw(message, message_size, message_hash);
					else
						memcpy(message_hash, message, sizeof(message_hash));

					secp256k1_context* context = signing::get_context();
					secp256k1_pubkey final_public_key_ext;
					secp256k1_ecdsa_signature compact_signature;
					secp256k1_ecdsa_signature normalized_signature;
					secp256k1_ecdsa_signature_parse_compact(context, &compact_signature, final_signature.data);
					secp256k1_ecdsa_signature_normalize(context, &normalized_signature, &compact_signature);
					if (secp256k1_ec_pubkey_parse(context, &final_public_key_ext, final_public_key.data, sizeof(pubkey_t)) == 1)
					{
						if (secp256k1_ecdsa_verify(context, &normalized_signature, message_hash, &final_public_key_ext) == 1)
							return expectation::met;
					}

					return layer_exception("final signature verification failed");
				}
				case type::schnorr:
				case type::schnorr_taproot:
				{
					uint8_t message_hash[32];
					if (message_size != sizeof(message_hash))
						sha256_Raw(message, message_size, message_hash);
					else
						memcpy(message_hash, message, sizeof(message_hash));

					secp256k1_context* context = signing::get_context();
					secp256k1_xonly_pubkey final_public_key_ext;
					if (secp256k1_xonly_pubkey_parse(context, &final_public_key_ext, final_public_key.data) != 1)
                        return layer_exception("final public key parsing failed");
                        
					if (secp256k1_schnorrsig_verify(context, final_signature.data, message_hash, sizeof(message_hash), &final_public_key_ext) != 1)
						return layer_exception("final signature verification failed");

					return expectation::met;
				}
				default:
					return layer_exception("invalid composition algorithm");
			}
		}
		composition::stage composition::stage_of(const cseckey_t& share_secret_key, const uint8_t* inout, size_t inout_size)
		{
			if (share_secret_key.empty())
				return stage::finalize;

			uint8_t null[96] = { 0 };
			return !memcmp(inout, null, std::min(inout_size, sizeof(null))) ? stage::configure : stage::accumulate;
		}
		size_t composition::size_of_secret_key(type alg, stage condition)
		{
			switch (alg)
			{
				case type::ed25519:
				case type::ed25519_clsag:
					return crypto_core_ed25519_SCALARBYTES;
				case type::secp256k1:
					return 32;
				case type::schnorr:
				case type::schnorr_taproot:
					return 32;
				default:
					return 0;
			}
		}
		size_t composition::size_of_public_key(type alg, stage condition)
		{
			switch (alg)
			{
				case type::ed25519:
				case type::ed25519_clsag:
					return crypto_sign_PUBLICKEYBYTES;
				case type::secp256k1:
					return 33;
				case type::schnorr:
					return 32;
				case type::schnorr_taproot:
					return 64;
				default:
					return 0;
			}
		}
		size_t composition::size_of_signature(type alg, stage condition)
		{
			switch (alg)
			{
				case type::ed25519:
				case type::ed25519_clsag:
					return condition == stage::finalize ? 64 : 32;
				case type::secp256k1:
					return condition == stage::finalize ? 65 : 32;
				case type::schnorr:
				case type::schnorr_taproot:
					return condition == stage::finalize ? 64 : 32;
				default:
					return 0;
			}
		}

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
