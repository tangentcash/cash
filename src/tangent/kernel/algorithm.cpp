#include "algorithm.h"
#include "../validator/service/nss.h"
#include <gmp.h>
extern "C"
{
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <sodium.h>
#include "../internal/segwit_addr.h"
#include "../internal/ecdsa.h"
#include "../internal/ed25519.h"
#include "../internal/ripemd160.h"
#include "../internal/bip39.h"
#include "../internal/sha2.h"
}

namespace tangent
{
	namespace algorithm
	{
		struct gmp
		{
			static void free(void* data, size_t size)
			{
				typedef void (*gmp_free_t)(void*, size_t);
				static gmp_free_t gmp_free = nullptr;
				if (!gmp_free)
					mp_get_memory_functions(nullptr, nullptr, &gmp_free);
				gmp_free(data, size);
			}
			static void import0(const uint8_t * data, size_t size, mpz_t value)
			{
				mpz_import(value, size, 1, 1, 1, 0, data);
			}
			static void import256(const uint256_t& data, mpz_t value)
			{
				uint8_t buffer[32];
				encoding::decode_uint256(data, buffer);
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
				encoding::encode_uint256(buffer, v);
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

		struct gmp_signature
		{
			mpz_t p;
			mpz_t l;
			mpz_t y;
			mpz_t n;
			uint64_t t;

			gmp_signature()
			{
				mpz_init(p);
				mpz_init(l);
				mpz_init(y);
				mpz_init(n);
			}
			gmp_signature(const gmp_signature&) = delete;
			gmp_signature(gmp_signature&& other) noexcept
			{
				memcpy(this, &other, sizeof(other));
				memset(&other, 0, sizeof(other));
			}
			~gmp_signature()
			{
				if (p)
					mpz_clear(p);
				if (l)
					mpz_clear(l);
				if (y)
					mpz_clear(y);
				if (n)
					mpz_clear(n);
			}
			gmp_signature& operator= (const gmp_signature&) = delete;
			gmp_signature& operator= (gmp_signature&& other) noexcept
			{
				if (this == &other)
					return *this;

				this->~gmp_signature();
				memcpy(this, &other, sizeof(other));
				memset(&other, 0, sizeof(other));
				return *this;
			}
			string serialize() const
			{
				format::stream stream;
				stream.write_integer(t);
				stream.write_string(gmp::export0(p));
				stream.write_string(gmp::export0(l));
				stream.write_string(gmp::export0(y));
				stream.write_string(gmp::export0(n));
				stream.write_integer(hashing::sha64d(stream.data));
				return stream.data;
			}
			static option<gmp_signature> deserialize(const std::string_view& sig)
			{
				gmp_signature result;
				format::stream stream = format::stream(sig);
				if (!stream.read_integer(stream.read_type(), &result.t))
					return optional::none;

				string numeric;
				if (!stream.read_string(stream.read_type(), &numeric))
					return optional::none;

				gmp::import0((uint8_t*)numeric.data(), numeric.size(), result.p);
				if (!stream.read_string(stream.read_type(), &numeric))
					return optional::none;

				gmp::import0((uint8_t*)numeric.data(), numeric.size(), result.l);
				if (!stream.read_string(stream.read_type(), &numeric))
					return optional::none;

				gmp::import0((uint8_t*)numeric.data(), numeric.size(), result.y);
				if (!stream.read_string(stream.read_type(), &numeric))
					return optional::none;

				uint64_t checksum, seek = stream.seek;
				gmp::import0((uint8_t*)numeric.data(), numeric.size(), result.n);
				if (!stream.read_integer(stream.read_type(), &checksum))
					return optional::none;

				if (checksum != hashing::sha64d(std::string_view(stream.data.data(), seek)))
					return optional::none;

				return result;
			}
		};

		uint128_t wesolowski::parameters::difficulty() const
		{
			return uint128_t(length) * uint128_t(bits) + uint128_t(pow);
		}

		uint256_t wesolowski::distribution::derive()
		{
			return derive(nonce++);
		}
		uint256_t wesolowski::distribution::derive(const uint256_t& step) const
		{
			char data[sizeof(uint256_t) * 2] = { 0 };
			encoding::decode_uint256(step, (uint8_t*)((char*)data + sizeof(uint256_t) * 0));
			encoding::decode_uint256(value, (uint8_t*)((char*)data + sizeof(uint256_t) * 1));
			return hashing::hash256i(std::string_view(data, sizeof(data)));
		}

		wesolowski::distribution wesolowski::random(const parameters& alg, const format::stream& seed)
		{
			distribution result;
			result.signature = evaluate(alg, seed.data);
			result.value = hashing::hash256i(*crypto::hash_raw(digests::sha512(), result.signature));
			return result;
		}
		wesolowski::parameters wesolowski::calibrate(uint64_t confidence, uint64_t target_time)
		{
			uint64_t target_nonce = confidence;
			auto alg = default_alg;
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
			if (adjustment > 1.0 + policy.max_consensus_difficulty_increase)
				adjustment = 1.0 + policy.max_consensus_difficulty_increase;
			else if (adjustment < policy.max_consensus_difficulty_decrease)
				adjustment = policy.max_consensus_difficulty_decrease;

			uint64_t pow_offset = (decimal(new_alg.pow) * adjustment).to_uint64();
			if (new_alg.pow + pow_offset < new_alg.pow)
				new_alg.pow = std::numeric_limits<uint64_t>::max();
			else
				new_alg.pow += pow_offset;

			if (new_alg.pow < default_alg.pow)
				new_alg.pow = default_alg.pow;

			return (new_alg.difficulty() < default_alg.difficulty() ? default_alg : new_alg);
		}
		wesolowski::parameters wesolowski::bump(const parameters& alg, double bump)
		{
			parameters new_alg = alg;
			uint64_t new_pow = (decimal(new_alg.pow) * decimal(bump)).to_uint64();
			if (new_pow < new_alg.pow)
				new_alg.pow = std::numeric_limits<uint64_t>::max();
			else
				new_alg.pow = new_pow;

			if (new_alg.pow < default_alg.pow)
				new_alg.pow = default_alg.pow;

			return (new_alg.difficulty() < default_alg.difficulty() ? default_alg : new_alg);
		}
		string wesolowski::evaluate(const parameters& alg, const std::string_view& message)
		{
			uint8_t mdata[64];
			hashing::hash512((uint8_t*)message.data(), message.size(), mdata);

			mpz_t v;
			mpz_init(v);
			gmp::import0(mdata, sizeof(mdata), v);

			gmp_signature signature;
			gmp_randstate_t r;
			gmp_randinit_mt(r);
			gmp_randseed(r, v);

			mpz_t p;
			mpz_init(p);
			mpz_urandomb(p, r, alg.length / 2);
			mpz_nextprime(p, p);

			mpz_t q;
			mpz_init(q);
			mpz_urandomb(q, r, alg.length / 2);
			mpz_nextprime(q, q);
			mpz_init(signature.n);
			mpz_mul(signature.n, p, q);
			mpz_clear(p);
			mpz_clear(q);

			mpz_t e, c;
			mpz_init(e);
			mpz_ui_pow_ui(e, 2, alg.pow);
			mpz_init(signature.y);
			mpz_init(c);
			mpz_urandomb(c, r, 2 * alg.bits);
			mpz_nextprime(signature.l, c);
			mpz_init(q);
			mpz_powm(signature.y, v, e, signature.n);
			mpz_fdiv_q(q, e, signature.l);
			mpz_powm(signature.p, v, q, signature.n);
			mpz_clear(q);
			mpz_clear(e);
			mpz_clear(c);
			mpz_clear(v);
			gmp_randclear(r);

			signature.t = protocol::now().time.now();
			return signature.serialize();
		}
		bool wesolowski::verify(const parameters& alg, const std::string_view& message, const std::string_view& sig)
		{
			auto signature = gmp_signature::deserialize(sig);
			if (!signature)
				return false;

			uint8_t mdata[64];
			hashing::hash512((uint8_t*)message.data(), message.size(), mdata);

			mpz_t v;
			mpz_init(v);
			gmp::import0(mdata, sizeof(mdata), v);

			mpz_t p;
			mpz_init(p);
			mpz_sub_ui(p, signature->l, 1);

			mpz_t t;
			mpz_init(t);
			mpz_set_ui(t, alg.pow);
			mpz_mod(t, t, p);
			mpz_clear(p);

			mpz_t d;
			mpz_init(d);
			mpz_set_ui(d, 2);

			mpz_t r;
			mpz_init(r);
			mpz_powm(r, d, t, signature->l);
			mpz_clear(t);
			mpz_clear(d);

			mpz_t y, w;
			mpz_init(y);
			mpz_init(w);
			mpz_powm(y, signature->p, signature->l, signature->n);
			mpz_powm(w, v, r, signature->n);
			mpz_mul(y, y, w);
			mpz_mod(y, y, signature->n);
			mpz_clear(r);
			mpz_clear(w);
			mpz_clear(v);

			int diff = mpz_cmp(y, signature->y);
			mpz_clear(y);
			return diff == 0;
		}
		int8_t wesolowski::compare(const std::string_view& sig1, const std::string_view& sig2)
		{
			auto signature1 = gmp_signature::deserialize(sig1);
			auto signature2 = gmp_signature::deserialize(sig2);
			if (!signature1 || !signature2)
				return signature1 ? 1 : -1;

			int compare_y = mpz_cmp(signature1->y, signature2->y);
			if (compare_y != 0)
				return (int8_t)compare_y;

			int compare_p = mpz_cmp(signature1->p, signature2->p);
			if (compare_p != 0)
				return (int8_t)compare_p;

			int compare_n = mpz_cmp(signature1->n, signature2->n);
			if (compare_n != 0)
				return (int8_t)compare_n;

			int compare_l = mpz_cmp(signature1->l, signature2->l);
			if (compare_l != 0)
				return (int8_t)compare_l;

			if (signature1->t < signature2->t)
				return 1;
			else if (signature1->t > signature2->t)
				return -1;

			return 0;
		}
		uint64_t wesolowski::locktime(const std::string_view& sig)
		{
			auto signature = gmp_signature::deserialize(sig);
			if (!signature)
				return 0;

			return signature->t;
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
		void wesolowski::set_default(const parameters& alg)
		{
			default_alg = alg;
		}
		const wesolowski::parameters& wesolowski::get_default()
		{
			return default_alg;
		}
		wesolowski::parameters wesolowski::default_alg;

		uint256_t nakamoto::evaluate(const uint256_t& nonce, const std::string_view& message)
		{
			format::stream stream;
			serialize(stream, nonce, message);
			return stream.hash();
		}
		bool nakamoto::verify(const uint256_t& nonce, const std::string_view& message, const uint256_t& target, const uint256_t& solution)
		{
			if (solution > target)
				return false;
			else if (nonce == uint256_t::max())
				return false;

			return solution == evaluate(nonce, message);
		}
		void nakamoto::serialize(format::stream& stream, const uint256_t& nonce, const std::string_view& message)
		{
			stream.clear();
			stream.write_typeless(message);
			stream.write_typeless(nonce);
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
			format::stream message;
			message.write_typeless(protocol::now().account.message_magic);
			message.write_typeless(signable_message.data(), (uint32_t)signable_message.size());
			return message.hash();
		}
		string signing::mnemonicgen(uint16_t strength)
		{
			char buffer[256] = { 0 };
			mnemonic_generate((int)strength, buffer, (int)sizeof(buffer));
			return string(buffer, strnlen(buffer, sizeof(buffer)));
		}
		void signing::keygen(seckey secret_key)
		{
			VI_ASSERT(secret_key != nullptr, "secret key should be set");
			while (true)
			{
				if (!crypto::fill_random_bytes(secret_key, sizeof(seckey)))
					break;
				else if (verify_secret_key(secret_key))
					break;
			}
		}
		bool signing::recover(const uint256_t& hash, pubkey public_key, const recsighash signature)
		{
			VI_ASSERT(public_key != nullptr && signature != nullptr, "public key and signature should be set");
			uint8_t recovery_id = 0;
			size_t signature_size = sizeof(recsighash);
			size_t recovery_offset = signature_size - sizeof(recovery_id);
			memcpy(&recovery_id, signature + recovery_offset, sizeof(recovery_id));
			if (recovery_id > 4)
				return false;

			secp256k1_context* context = get_context();
			secp256k1_ecdsa_recoverable_signature recoverable_signature;
			if (!secp256k1_ecdsa_recoverable_signature_parse_compact(context, &recoverable_signature, signature, recovery_id))
				return false;

			uint8_t data[32];
			encoding::decode_uint256(hash, data);

			secp256k1_pubkey recovered_public_key;
			if (secp256k1_ecdsa_recover(context, &recovered_public_key, &recoverable_signature, data) != 1)
				return false;

			size_t public_key_size = sizeof(pubkey);
			return secp256k1_ec_pubkey_serialize(context, public_key, &public_key_size, &recovered_public_key, SECP256K1_EC_COMPRESSED) == 1;
		}
		bool signing::recover_hash(const uint256_t& hash, pubkeyhash public_key_hash, const recsighash signature)
		{
			VI_ASSERT(public_key_hash != nullptr && signature != nullptr, "public key hash and signature should be set");
			pubkey public_key;
			if (!recover(hash, public_key, signature))
				return false;

			derive_public_key_hash(public_key, public_key_hash);
			return true;
		}
		bool signing::sign(const uint256_t& hash, const seckey secret_key, recsighash signature)
		{
			VI_ASSERT(secret_key != nullptr && signature != nullptr, "secret key and signature should be set");
			uint8_t data[32];
			encoding::decode_uint256(hash, data);
			memset(signature, 0, sizeof(recsighash));

			secp256k1_context* context = get_context();
			secp256k1_ecdsa_recoverable_signature recoverable_signature;
			if (secp256k1_ecdsa_sign_recoverable(context, &recoverable_signature, data, secret_key, secp256k1_nonce_function_rfc6979, nullptr) != 1)
				return false;

			int recovery_id = 0;
			if (secp256k1_ecdsa_recoverable_signature_serialize_compact(context, signature, &recovery_id, &recoverable_signature) != 1)
				return false;

			signature[sizeof(sighash)] = (uint8_t)recovery_id;
			return true;
		}
		bool signing::verify(const uint256_t& hash, const pubkey public_key, const recsighash signature)
		{
			VI_ASSERT(public_key != nullptr && signature != nullptr, "public key and signature should be set");
			secp256k1_context* context = get_context();
			secp256k1_ecdsa_signature compact_signature;
			if (secp256k1_ecdsa_signature_parse_compact(context, &compact_signature, signature) != 1)
				return false;

			secp256k1_ecdsa_signature normalized_signature;
			secp256k1_ecdsa_signature_normalize(context, &normalized_signature, &compact_signature);

			secp256k1_pubkey derived_public_key;
			if (secp256k1_ec_pubkey_parse(context, &derived_public_key, public_key, sizeof(pubkey)) != 1)
				return false;

			uint8_t data[32];
			encoding::decode_uint256(hash, data);
			return secp256k1_ecdsa_verify(context, &normalized_signature, data, &derived_public_key) == 1;
		}
		bool signing::verify_mnemonic(const std::string_view& mnemonic)
		{
			string data = string(mnemonic);
			return mnemonic_check(data.c_str()) == 1;
		}
		bool signing::verify_secret_key(const seckey secret_key)
		{
			VI_ASSERT(secret_key != nullptr, "secret key should be set");
			secp256k1_context* context = get_context();
			return secp256k1_ec_seckey_verify(context, secret_key) == 1;
		}
		bool signing::verify_public_key(const pubkey public_key)
		{
			VI_ASSERT(public_key != nullptr, "public key should be set");
			secp256k1_pubkey derived_public_key;
			secp256k1_context* context = get_context();
			return secp256k1_ec_pubkey_parse(context, &derived_public_key, public_key, sizeof(pubkey)) == 1;
		}
		bool signing::verify_address(const std::string_view& address)
		{
			pubkeyhash public_key_hash;
			return decode_address(address, public_key_hash);
		}
		bool signing::verify_sealed_message(const std::string_view& ciphertext)
		{
			return ciphertext.size() > crypto_box_SEALBYTES;
		}
		void signing::derive_secret_key_from_mnemonic(const std::string_view& mnemonic, seckey secret_key)
		{
			VI_ASSERT(secret_key != nullptr, "secret key should be set");
			VI_ASSERT(stringify::is_cstring(mnemonic), "mnemonic should be set");
			uint8_t seed[64] = { 0 };
			mnemonic_to_seed(mnemonic.data(), "", seed, nullptr);
			derive_secret_key(std::string_view((char*)seed, sizeof(seed)), secret_key);
		}
		void signing::derive_secret_key(const std::string_view& seed, seckey secret_key)
		{
			VI_ASSERT(secret_key != nullptr, "secret key should be set");
			string derivation = string(seed);
			while (true)
			{
				derivation = hashing::hash256((uint8_t*)derivation.data(), derivation.size());
				memcpy(secret_key, derivation.data(), sizeof(seckey));
				if (verify_secret_key(secret_key))
					break;
			}
		}
		bool signing::derive_public_key(const seckey secret_key, pubkey public_key)
		{
			VI_ASSERT(secret_key != nullptr && public_key != nullptr, "secret key and public key should be set");
			secp256k1_pubkey derived_public_key;
			secp256k1_context* context = get_context();
			memset(public_key, 0, sizeof(pubkey));
			if (secp256k1_ec_pubkey_create(context, &derived_public_key, secret_key) != 1)
				return false;

			size_t public_key_size = sizeof(pubkey);
			return secp256k1_ec_pubkey_serialize(context, public_key, &public_key_size, &derived_public_key, SECP256K1_EC_COMPRESSED) == 1;
		}
		void signing::derive_public_key_hash(const pubkey public_key, pubkeyhash public_key_hash)
		{
			VI_ASSERT(public_key != nullptr, "public key should be set");
			VI_ASSERT(public_key_hash != nullptr, "public key hash should be set");
			hashing::hash160(public_key, sizeof(pubkey), public_key_hash);
		}
		void signing::derive_cipher_keypair(const seckey secret_key, const uint256_t& nonce, seckey cipher_secret_key, pubkey cipher_public_key)
		{
			VI_ASSERT(secret_key != nullptr, "secret key should be set");
			VI_ASSERT(cipher_secret_key != nullptr, "cipher secret key should be set");
			VI_ASSERT(cipher_public_key != nullptr, "cipher public key should be set");
			format::stream message;
			message.write_typeless((char*)secret_key, (uint32_t)sizeof(seckey));
			message.write_typeless(nonce);

			uint8_t seed[32];
			encoding::decode_uint256(message.hash(), seed);
			memset(cipher_public_key, 0, sizeof(pubkey));
			crypto_box_seed_keypair(cipher_public_key, cipher_secret_key, seed);
		}
		option<string> signing::public_encrypt(const pubkey cipher_public_key, const std::string_view& plaintext, const std::string_view& entropy)
		{
			VI_ASSERT(cipher_public_key != nullptr, "cipher public key should be set");
			if (plaintext.empty())
				return optional::none;

			string salt = hashing::hash512((uint8_t*)entropy.data(), entropy.size());
			string body = salt + string(plaintext);
			for (size_t i = salt.size(); i < body.size(); i++)
				body[i] ^= salt[i % salt.size()];
			body.append(hashing::hash256((uint8_t*)plaintext.data(), plaintext.size()));

			string ciphertext;
			ciphertext.resize(crypto_box_SEALBYTES + body.size());
			if (crypto_box_seal((uint8_t*)ciphertext.data(), (uint8_t*)body.data(), body.size(), cipher_public_key) != 0)
				return optional::none;

			return ciphertext;
		}
		option<string> signing::private_decrypt(const seckey cipher_secret_key, const pubkey cipher_public_key, const std::string_view& ciphertext)
		{
			VI_ASSERT(cipher_secret_key != nullptr, "cipher secret key should be set");
			VI_ASSERT(cipher_public_key != nullptr, "cipher public key should be set");
			if (ciphertext.size() <= crypto_box_SEALBYTES)
				return optional::none;

			string body;
			body.resize(ciphertext.size() - crypto_box_SEALBYTES);
			if (crypto_box_seal_open((uint8_t*)body.data(), (uint8_t*)ciphertext.data(), ciphertext.size(), cipher_public_key, cipher_secret_key) != 0)
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
		bool signing::decode_secret_key(const std::string_view& value, seckey secret_key)
		{
			VI_ASSERT(secret_key != nullptr && stringify::is_cstring(value), "secret key and value should be set");
			auto& account = protocol::now().account;
			uint8_t decoded[40];
			size_t decoded_size = sizeof(decoded);
			int version = 0;

			if (segwit::decode(&version, decoded, &decoded_size, account.secret_key_prefix.c_str(), value.data()) != 1)
				return false;
			else if (version != (int)account.secret_key_version)
				return false;
			else if (decoded_size != sizeof(seckey))
				return false;

			memcpy(secret_key, decoded, sizeof(seckey));
			return true;
		}
		bool signing::encode_secret_key(const seckey secret_key, string& value)
		{
			VI_ASSERT(secret_key != nullptr, "secret key should be set");
			auto& account = protocol::now().account;
			char encoded[128];
			if (segwit::encode(encoded, account.secret_key_prefix.c_str(), (int)account.secret_key_version, secret_key, sizeof(seckey)) != 1)
				return false;

			size_t size = strnlen(encoded, sizeof(encoded));
			value.resize(size);
			memcpy(value.data(), encoded, size);
			return true;
		}
		bool signing::decode_public_key(const std::string_view& value, pubkey public_key)
		{
			VI_ASSERT(public_key != nullptr && stringify::is_cstring(value), "public key and value should be set");
			auto& account = protocol::now().account;
			uint8_t decoded[40];
			size_t decoded_size = sizeof(decoded);
			int version = 0;

			if (segwit::decode(&version, decoded, &decoded_size, account.public_key_prefix.c_str(), value.data()) != 1)
				return false;
			else if (version != (int)account.public_key_version)
				return false;
			else if (decoded_size != sizeof(pubkey))
				return false;

			memcpy(public_key, decoded, sizeof(pubkey));
			return true;
		}
		bool signing::encode_public_key(const pubkey public_key, string& value)
		{
			VI_ASSERT(public_key != nullptr, "public key should be set");
			auto& account = protocol::now().account;
			char encoded[128];
			if (segwit::encode(encoded, account.public_key_prefix.c_str(), (int)account.public_key_version, public_key, sizeof(pubkey)) != 1)
				return false;

			size_t size = strnlen(encoded, sizeof(encoded));
			value.resize(size);
			memcpy(value.data(), encoded, size);
			return true;
		}
		bool signing::decode_address(const std::string_view& address, pubkeyhash public_key_hash)
		{
			VI_ASSERT(public_key_hash != nullptr && stringify::is_cstring(address), "public key hash and address should be set");
			auto& account = protocol::now().account;
			uint8_t decoded[40];
			size_t decoded_size = sizeof(decoded);
			int version = 0;

			if (segwit::decode(&version, decoded, &decoded_size, account.address_prefix.c_str(), address.data()) != 1)
				return false;
			else if (version != (int)account.address_version)
				return false;
			else if (decoded_size != sizeof(pubkeyhash))
				return false;

			memcpy(public_key_hash, decoded, sizeof(pubkeyhash));
			return true;
		}
		bool signing::encode_address(const pubkeyhash public_key_hash, string& address)
		{
			VI_ASSERT(public_key_hash != nullptr, "public key hash should be set");
			auto& account = protocol::now().account;
			char encoded[128];

			if (segwit::encode(encoded, account.address_prefix.c_str(), (int)account.address_version, public_key_hash, sizeof(pubkeyhash)) != 1)
				return false;

			size_t size = strnlen(encoded, sizeof(encoded));
			address.resize(size);
			memcpy(address.data(), encoded, size);
			return true;
		}
		schema* signing::serialize_secret_key(const seckey secret_key)
		{
			seckey null = { 0 };
			if (!memcmp(secret_key, null, sizeof(null)))
				return var::set::null();

			string data;
			if (!encode_secret_key(secret_key, data))
				return var::set::null();

			return var::set::string(data);
		}
		schema* signing::serialize_public_key(const pubkey public_key)
		{
			pubkey null = { 0 };
			if (!memcmp(public_key, null, sizeof(null)))
				return var::set::null();

			string data;
			if (!encode_public_key(public_key, data))
				return var::set::null();

			return var::set::string(data);
		}
		schema* signing::serialize_address(const pubkeyhash public_key_hash)
		{
			pubkeyhash null = { 0 };
			if (!memcmp(public_key_hash, null, sizeof(null)))
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

		bool encoding::decode_uint_blob(const string& value, uint8_t* data, size_t data_size)
		{
			VI_ASSERT(data != nullptr, "data should be set");
			if (value.size() != data_size)
			{
				memset(data, 0, data_size);
				return value.empty();
			}

			memcpy(data, value.data(), value.size());
			return true;
		}
		void encoding::encode_uint128(const uint8_t value[16], uint128_t& data)
		{
			VI_ASSERT(value != nullptr, "value should be set");
			uint64_t array[2] = { 0 };
			memcpy(array, value, sizeof(array));
			auto& bits0 = data.high();
			auto& bits1 = data.low();
			array[1] = os::hw::to_endianness(os::hw::endian::big, array[1]);
			array[0] = os::hw::to_endianness(os::hw::endian::big, array[0]);
			memcpy((uint64_t*)&bits0, &array[0], sizeof(uint64_t));
			memcpy((uint64_t*)&bits1, &array[1], sizeof(uint64_t));
		}
		void encoding::decode_uint128(const uint128_t& value, uint8_t data[16])
		{
			VI_ASSERT(data != nullptr, "data should be set");
			uint64_t array[2] =
			{
				os::hw::to_endianness(os::hw::endian::big, value.high()),
				os::hw::to_endianness(os::hw::endian::big, value.low())
			};
			memcpy((char*)data, array, sizeof(array));
		}
		void encoding::encode_uint256(const uint8_t value[32], uint256_t& data)
		{
			VI_ASSERT(value != nullptr, "value should be set");
			uint64_t array[4] = { 0 };
			memcpy(array, value, sizeof(array));
			auto& bits0 = data.high().high();
			auto& bits1 = data.high().low();
			auto& bits2 = data.low().high();
			auto& bits3 = data.low().low();
			array[0] = os::hw::to_endianness(os::hw::endian::big, array[0]);
			array[1] = os::hw::to_endianness(os::hw::endian::big, array[1]);
			array[2] = os::hw::to_endianness(os::hw::endian::big, array[2]);
			array[3] = os::hw::to_endianness(os::hw::endian::big, array[3]);
			memcpy((uint64_t*)&bits0, &array[0], sizeof(uint64_t));
			memcpy((uint64_t*)&bits1, &array[1], sizeof(uint64_t));
			memcpy((uint64_t*)&bits2, &array[2], sizeof(uint64_t));
			memcpy((uint64_t*)&bits3, &array[3], sizeof(uint64_t));
		}
		void encoding::decode_uint256(const uint256_t& value, uint8_t data[32])
		{
			VI_ASSERT(data != nullptr, "data should be set");
			uint64_t array[4] =
			{
				os::hw::to_endianness(os::hw::endian::big, value.high().high()),
				os::hw::to_endianness(os::hw::endian::big, value.high().low()),
				os::hw::to_endianness(os::hw::endian::big, value.low().high()),
				os::hw::to_endianness(os::hw::endian::big, value.low().low())
			};
			memcpy((char*)data, array, sizeof(array));
		}
		string encoding::encode_0xhex256(const uint256_t& value)
		{
			uint8_t data[32];
			decode_uint256(value, data);
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
			decode_uint128(value, data);
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
		schema* encoding::serialize_uint256(const uint256_t& value)
		{
			if (value <= std::numeric_limits<int64_t>::max())
				return var::set::integer((uint64_t)value);

			uint8_t data[32];
			decode_uint256(value, data);

			size_t size = value.bytes();
			return var::set::string(format::util::encode_0xhex(std::string_view((char*)data + (sizeof(data) - size), size)));
		}

		uint256_t hashing::sha256ci(const uint256_t& a, const uint256_t& b)
		{
			uint8_t combine_buffer[sizeof(uint256_t) * 2];
			encoding::decode_uint256(a, combine_buffer + sizeof(uint256_t) * 0);
			encoding::decode_uint256(b, combine_buffer + sizeof(uint256_t) * 1);
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
			encoding::encode_uint256((uint8_t*)hash.data(), value);
			return value;
		}
		uint256_t hashing::hash256i(const std::string_view& data)
		{
			return hash256i((uint8_t*)data.data(), data.size());
		}

		asset_id asset::id_of_handle(const std::string_view& handle)
		{
			uint8_t data[32] = { 0 };
			size_t size = std::min<size_t>(sizeof(data), handle.size());
			memcpy((char*)data + (sizeof(data) - size), handle.data(), size);

			uint256_t value;
			encoding::encode_uint256(data, value);
			return id_of(blockchain_of(value), token_of(value), checksum_of(value));
		}
		asset_id asset::id_of(const std::string_view& blockchain, const std::string_view& token, const std::string_view& contract_address)
		{
			uint8_t data[32] = { 0 };
			string handle = handle_of(blockchain, token, contract_address);
			size_t size = std::min<size_t>(sizeof(data), handle.size());
			memcpy((char*)data + (sizeof(data) - size), handle.data(), size);

			uint256_t value;
			encoding::encode_uint256(data, value);
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
				stringify::to_upper(handle);
				if (!contract_address.empty())
				{
					auto hash = codec::base64_url_encode(*crypto::hash_raw(digests::sha1(), format::util::is_hex_encoding(contract_address) ? codec::hex_decode(contract_address) : string(contract_address)));
					handle.append(1, ':').append(hash.substr(0, 32 - handle.size()));
				}
			}
			else
				stringify::to_upper(handle);
			return handle.substr(0, 32);
		}
		string asset::handle_of(const asset_id& value)
		{
			uint8_t data[33];
			encoding::decode_uint256(value, data);

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
			size_t index = handle.find(':');
			return handle.substr(0, index);
		}
		string asset::token_of(const asset_id& value)
		{
			string handle = handle_of(value);
			size_t index = handle.find(':');
			return index == std::string::npos ? string() : handle.substr(index + 1, handle.rfind(':', index) + 1);
		}
		string asset::checksum_of(const asset_id& value)
		{
			string handle = handle_of(value);
			size_t index1 = handle.find(':');
			size_t index2 = handle.rfind(':');
			return index1 == std::string::npos || index2 == std::string::npos || index1 == index2 ? string() : handle.substr(index2 + 1);
		}
		bool asset::is_valid(const asset_id& value)
		{
			if (!value)
				return false;

			auto blockchain = blockchain_of(value);
			if (stringify::is_empty_or_whitespace(blockchain))
				return false;

			if (!nss::server_node::get()->has_chain(value))
				return false;

			auto token = token_of(value);
			if (stringify::is_empty_or_whitespace(token))
				return true;

			auto checksum = checksum_of(value);
			return !stringify::is_empty_or_whitespace(checksum);
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
			data->set("id", encoding::serialize_uint256(value));
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

		expects_lr<void> composition::derive_keypair(type alg, const cseed seed, cseckey secret_key, cpubkey public_key)
		{
			VI_ASSERT(secret_key != nullptr, "secret key should be set");
			VI_ASSERT(public_key != nullptr, "public key should be set");
			hashing::hash512(seed, sizeof(cseed), secret_key);
			memset(public_key, 0, sizeof(cpubkey));
			switch (alg)
			{
				case type::ED25519:
				{
					convert_to_secret_key_ed25519(secret_key);
					ed25519_publickey_ext(secret_key, public_key);
					hashing::hash256(public_key, sizeof(cpubkey) / 2, public_key + sizeof(cpubkey) / 2);
					return expectation::met;
				}
				case type::SECP256K1:
				{
					secp256k1_context* context = signing::get_context();
					secp256k1_pubkey extended_public_key;
					while (secp256k1_ec_seckey_verify(context, secret_key) != 1 || secp256k1_ec_pubkey_create(context, &extended_public_key, secret_key) != 1)
						hashing::hash512(secret_key, sizeof(cseckey), secret_key);

					memcpy(public_key, extended_public_key.data, sizeof(extended_public_key.data));
					return expectation::met;
				}
				default:
					return layer_exception("invalid composition algorithm");
			}
		}
		expects_lr<void> composition::derive_public_key(type alg, const cpubkey public_key1, const cseckey secret_key2, cpubkey public_key, size_t* public_key_size)
		{
			VI_ASSERT(public_key1 != nullptr, "public key 1 should be set");
			VI_ASSERT(secret_key2 != nullptr, "secret key 2 should be set");
			VI_ASSERT(public_key != nullptr, "public key should be set");
			memset(public_key, 0, sizeof(cpubkey));
			switch (alg)
			{
				case type::ED25519:
				{
					uint8_t FX[crypto_sign_PUBLICKEYBYTES];
					memcpy(FX, public_key1, sizeof(FX));

					uint8_t y[crypto_core_ed25519_SCALARBYTES];
					memcpy(y, secret_key2, sizeof(y));

					if (crypto_scalarmult_ed25519(FX, y, FX) != 0)
						return layer_exception("bad parameters");

					memcpy(public_key, FX, sizeof(FX));
					if (public_key_size != nullptr)
						*public_key_size = sizeof(FX);
					return expectation::met;
				}
				case type::SECP256K1:
				{
					secp256k1_context* context = signing::get_context();
					secp256k1_pubkey FX;
					memcpy(FX.data, public_key1, sizeof(FX));

					uint8_t y[32];
					memcpy(y, secret_key2, sizeof(y));
					if (secp256k1_ec_pubkey_tweak_mul(context, &FX, y) != 1)
						return layer_exception("bad secret key 2");

					size_t key_size = sizeof(FX);
					secp256k1_ec_pubkey_serialize(context, public_key, &key_size, &FX, SECP256K1_EC_COMPRESSED);
					if (public_key_size != nullptr)
						*public_key_size = key_size;
					return expectation::met;
				}
				default:
					return layer_exception("invalid composition algorithm");
			}
		}
		expects_lr<void> composition::derive_secret_key(type alg, const cseckey secret_key1, const cseckey secret_key2, cseckey secret_key, size_t* secret_key_size)
		{
			VI_ASSERT(secret_key != nullptr, "secret key should be set");
			VI_ASSERT(secret_key1 != nullptr, "secret1 should be set");
			VI_ASSERT(secret_key2 != nullptr, "secret2 should be set");
			memset(secret_key, 0, sizeof(cseckey));
			switch (alg)
			{
				case type::ED25519:
				{
					uint8_t x[crypto_core_ed25519_SCALARBYTES], y[crypto_core_ed25519_SCALARBYTES];
					memcpy(x, secret_key1, sizeof(x));
					memcpy(y, secret_key2, sizeof(y));

					cseckey r;
					crypto_core_ed25519_scalar_mul(r, x, y);
					sha256_Raw(r, sizeof(r) / 2, r + sizeof(r) / 2);
					memcpy(secret_key, r, sizeof(r));
					if (secret_key_size != nullptr)
						*secret_key_size = sizeof(r);

					return expectation::met;
				}
				case type::SECP256K1:
				{
					secp256k1_context* context = signing::get_context();
					uint8_t x[32], y[32];
					memcpy(x, secret_key1, sizeof(x));
					memcpy(y, secret_key2, sizeof(y));
					if (secp256k1_ec_seckey_tweak_mul(context, x, y) != 1)
						return layer_exception("bad parameters");

					memcpy(secret_key, x, sizeof(x));
					if (secret_key_size)
						*secret_key_size = sizeof(x);
					return expectation::met;
				}
				default:
					return layer_exception("invalid composition algorithm");
			}
		}
		void composition::convert_to_composite_hash(const uint8_t* a, size_t asize, const uint8_t* b, size_t bsize, uint8_t c[32])
		{
			SHA256_CTX context;
			sha256_Init(&context);
			sha256_Update(&context, a, asize);
			sha256_Update(&context, b, bsize);
			sha256_Final(&context, c);
		}
		void composition::convert_to_secret_key_ed25519(uint8_t secret_key[32])
		{
			secret_key[0] &= 248;
			secret_key[31] &= 127;
			secret_key[31] |= 64;
		}
		void composition::convert_to_scalar_ed25519(uint8_t secret_key[32])
		{
			uint8_t point[64] = { 0 };
			memcpy(point, secret_key, 32);
			crypto_core_ed25519_scalar_reduce(secret_key, point);
		}
		void composition::convert_to_secret_seed(const seckey secret_key, const std::string_view& entropy, cseed seed)
		{
			auto input = hashing::hash512((uint8_t*)entropy.data(), entropy.size());
			input += hashing::hash256(secret_key, sizeof(seckey));
			hashing::hash512((uint8_t*)input.data(), input.size(), seed);
		}

		uint256_t merkle_tree::path::calculate_root(uint256_t hash) const
		{
			size_t offset = index;
			for (size_t i = 0; i < nodes.size(); i++)
			{
				hash = (offset & 1 ? hasher(nodes[i], hash) : hasher(hash, nodes[i]));
				offset >>= 1;
			}
			return hash;
		}
		vector<uint256_t>& merkle_tree::path::get_branch()
		{
			return nodes;
		}
		const vector<uint256_t>& merkle_tree::path::get_branch() const
		{
			return nodes;
		}
		size_t merkle_tree::path::get_index() const
		{
			return index;
		}
		bool merkle_tree::path::empty()
		{
			return nodes.empty();
		}

		merkle_tree::merkle_tree()
		{
		}
		merkle_tree::merkle_tree(const uint256_t& prev_merkle_root)
		{
			if (prev_merkle_root > 0)
				push(prev_merkle_root);
		}
		merkle_tree& merkle_tree::shift(const uint256_t& hash)
		{
			nodes.insert(nodes.begin(), hash);
			++hashes;
			return *this;
		}
		merkle_tree& merkle_tree::push(const uint256_t& hash)
		{
			nodes.push_back(hash);
			++hashes;
			return *this;
		}
		merkle_tree& merkle_tree::reset()
		{
			nodes.clear();
			hashes = 0;
			return *this;
		}
		merkle_tree& merkle_tree::calculate()
		{
			VI_ASSERT(hasher != nullptr, "hash function should be set");
			if (is_calculated())
				return *this;

			std::sort(nodes.begin(), nodes.end());
			for (size_t size = hashes, node = 0; size > 1; size = (size + 1) / 2)
			{
				for (size_t offset = 0; offset < size; offset += 2)
					nodes.push_back(hasher(nodes[node + offset], nodes[node + std::min(offset + 1, size - 1)]));
				node += size;
			}
			return *this;
		}
		merkle_tree::path merkle_tree::calculate_path(const uint256_t& hash)
		{
			path branch;
			branch.hasher = hasher;
			calculate();

			auto begin = nodes.begin(), end = nodes.begin() + hashes;
			auto it = std::lower_bound(nodes.begin(), nodes.begin() + hashes, hash);
			if (it == end)
				return branch;

			size_t index = it - begin;
			branch.index = index;

			for (size_t size = hashes, node = 0; size > 1; size = (size + 1) / 2)
			{
				branch.nodes.push_back(nodes[node + std::min(index ^ 1, size - 1)]);
				index >>= 1;
				node += size;
			}

			return branch;
		}
		uint256_t merkle_tree::calculate_root()
		{
			calculate();
			return nodes.empty() ? uint256_t(0) : nodes.back();
		}
		const vector<uint256_t>& merkle_tree::get_tree()
		{
			if (!is_calculated())
				calculate();

			return nodes;
		}
		const vector<uint256_t>& merkle_tree::get_tree() const
		{
			return nodes;
		}
		size_t merkle_tree::get_complexity() const
		{
			return hashes;
		}
		bool merkle_tree::is_calculated() const
		{
			return !hashes || hashes < nodes.size();
		}
	}
}
