#ifndef TAN_KERNEL_ALGORITHM_H
#define TAN_KERNEL_ALGORITHM_H
#include "../layer/format.h"
#include <array>

typedef struct secp256k1_context_struct secp256k1_context;

namespace tangent
{
	namespace algorithm
	{
		template <typename t, size_t s>
		struct storage_type
		{
			t data[s] = { 0 };

			storage_type() = default;
			storage_type(std::nullptr_t) = delete;
			storage_type(const t new_data[s])
			{
				if (new_data != nullptr)
					memcpy(data, new_data, sizeof(data));
			}
			storage_type(const t* new_data, size_t new_size)
			{
				if (new_data != nullptr)
					memcpy(data, new_data, std::min(new_size, sizeof(data)));
			}
			storage_type(const std::string_view& new_data)
			{
				memcpy(data, new_data.data(), std::min(new_data.size(), sizeof(data)));
			}
			storage_type(const vector<uint8_t>& new_data)
			{
				memcpy(data, new_data.data(), std::min(new_data.size(), sizeof(data)));
			}
			storage_type(const storage_type&) = default;
			storage_type(storage_type&&) noexcept = default;
			storage_type& operator=(const storage_type&) = default;
			storage_type& operator=(storage_type&&) noexcept = default;
			void clear()
			{
				memset(data, 0, sizeof(data));
			}
			bool equals(const storage_type& other) const
			{
				return !memcmp(other.data, data, sizeof(data));
			}
			bool empty() const
			{
				t null[s] = { 0 };
				return !memcmp(data, null, sizeof(null));
			}
			vector<uint8_t> container() const
			{
				vector<uint8_t> result;
				result.resize(s);
				memcpy(result.data(), data, sizeof(data));
				return result;
			}
			std::string_view view() const
			{
				return std::string_view((char*)data, sizeof(data));
			}
			std::string_view optimized_view() const
			{
				size_t size = s;
				auto* ptr = data + size;
				while (size > 0 && !*(--ptr))
					--size;

				return std::string_view((char*)data, size);
			}
			bool operator== (const storage_type& other) const
			{
				return equals(other.data);
			}
			bool operator< (const storage_type& other) const
			{
				for (size_t i = 0; i < s; ++i)
				{
					if (data[i] > other.data[i])
						return false;
					else if (data[i] < other.data[i])
						return true;
				}
				return false;
			}
		};

		using asset_id = uint256_t;
		using hashsig_t = storage_type<uint8_t, 65>;
		using seckey_t = storage_type<uint8_t, 32>;
		using pubkey_t = storage_type<uint8_t, 33>;
		using pubkeyhash_t = storage_type<uint8_t, 20>;
		typedef uint256_t(*hash_function)(const uint256_t&, const uint256_t&);

		class wesolowski
		{
		public:
			friend struct mpz;
			typedef string digest;

		public:
			struct distribution
			{
				string signature;
				uint256_t value = 0;
				uint256_t nonce = 0;

				uint256_t derive();
				uint256_t derive(const uint256_t& step) const;
			};

		public:
			static distribution random(uint64_t difficulty, const std::string_view& seed);
			static uint64_t calibrate(uint64_t confidence, uint64_t target_time = protocol::now().policy.consensus_proof_time);
			static uint64_t adjust(uint64_t prev_difficulty, uint64_t prev_time, uint64_t target_index);
			static uint64_t scale(uint64_t difficulty, const decimal& multiplier);
			static string evaluate(uint64_t difficulty, const std::string_view& message);
			static bool verify(uint64_t difficulty, const std::string_view& message, const std::string_view& proof);
			static int8_t compare(const std::string_view& proof1, const std::string_view& proof2);
			static uint64_t adjustment_interval();
			static uint64_t adjustment_index(uint64_t index);
			static decimal adjustment_scaling(uint64_t index);
			static schema* serialize(uint64_t difficulty, const std::string_view& proof, const decimal& scaling = decimal::nan());
			static uint128_t kdifficulty(uint64_t difficulty);

		private:
			static bool evaluate_or_proof(uint64_t difficulty, const std::string_view& message, const std::string_view& proof_in, string* proof_out);
		};

		class segwit
		{
		public:
			static int tweak(uint8_t* output, size_t* output_size, int32_t output_bits, const uint8_t* input, size_t input_size, int32_t input_bits, int32_t padding);
			static int encode(char* output, const char* prefix, int32_t version, const uint8_t* program, size_t program_size);
			static int decode(int* version, uint8_t* program, size_t* program_size, const char* prefix, const char* input);
		};

		class signing
		{
		private:
			static secp256k1_context* shared_context;

		public:
			static void initialize();
			static void deinitialize();
			static uint256_t message_hash(const std::string_view& signable_message);
			static string mnemonicgen(uint16_t strength = 256);
			static void keygen(seckey_t& secret_key);
			static bool recover(const uint256_t& hash, pubkey_t& public_key, const hashsig_t& signature);
			static bool recover_hash(const uint256_t& hash, pubkeyhash_t& public_key_hash, const hashsig_t& signature);
			static bool sign(const uint256_t& hash, const seckey_t& secret_key, hashsig_t& signature);
			static bool verify(const uint256_t& hash, const pubkey_t& public_key, const hashsig_t& signature);
			static bool verify_mnemonic(const std::string_view& mnemonic);
			static bool verify_secret_key(const seckey_t& secret_key);
			static bool verify_public_key(const pubkey_t& public_key);
			static bool verify_address(const std::string_view& address);
			static bool verify_encrypted_message(const std::string_view& ciphertext);
			static void derive_secret_key_from_mnemonic(const std::string_view& mnemonic, seckey_t& secret_key);
			static void derive_secret_key_from_parent(const seckey_t& secret_key, const uint256_t& entropy, seckey_t& child_secret_key);
			static void derive_secret_key(const uint256_t& entropy, seckey_t& secret_key);
			static bool derive_public_key(const seckey_t& secret_key, pubkey_t& public_key);
			static void derive_public_key_hash(const pubkey_t& public_key, pubkeyhash_t& public_key_hash);
			static bool scalar_add_secret_key(seckey_t& secret_key, const seckey_t& scalar);
			static bool scalar_mul_secret_key(seckey_t& secret_key, const seckey_t& scalar);
			static bool scalar_add_public_key(pubkey_t& public_key, const seckey_t& scalar);
			static bool scalar_mul_public_key(pubkey_t& public_key, const seckey_t& scalar);
			static bool point_add_public_key(pubkey_t& public_key, const pubkey_t& point);
			static option<string> public_encrypt(const pubkey_t& public_key, const std::string_view& plaintext, const uint256_t& entropy);
			static option<string> private_decrypt(const seckey_t& secret_key, const std::string_view& ciphertext);
			static bool decode_secret_key(const std::string_view& value, seckey_t& secret_key);
			static bool encode_secret_key(const seckey_t& secret_key, string& value);
			static bool decode_public_key(const std::string_view& value, pubkey_t& public_key);
			static bool encode_public_key(const pubkey_t& public_key, string& value);
			static bool decode_address(const std::string_view& address, pubkeyhash_t& public_key_hash);
			static bool encode_address(const pubkeyhash_t& public_key_hash, string& address);
			static string encode_address(const pubkeyhash_t& public_key_hash);
			static schema* serialize_secret_key(const seckey_t& secret_key);
			static schema* serialize_public_key(const pubkey_t& public_key);
			static schema* serialize_address(const pubkeyhash_t& public_key_hash);
			static secp256k1_context* get_context();
		};

		class encoding
		{
		public:
			static bool decode_bytes(const std::string_view& value, uint8_t* data, size_t data_size);
			static string encode_0xhex256(const uint256_t& data);
			static uint256_t decode_0xhex256(const std::string_view& data);
			static string encode_0xhex128(const uint128_t& data);
			static uint128_t decode_0xhex128(const std::string_view& data);
			static uint32_t type_of(const std::string_view& name);
			static schema* serialize_uint256(const uint256_t& data, bool always16 = false);
		};

		class hashing
		{
		public:
			static uint256_t sha256ci(const uint256_t& a, const uint256_t& b);
			static uint64_t sha64d(const uint8_t* buffer, size_t size);
			static uint64_t sha64d(const std::string_view& buffer);
			static uint32_t hash32d(const uint8_t* buffer, size_t size);
			static uint32_t hash32d(const std::string_view& buffer);
			static void hash160(const uint8_t* buffer, size_t size, uint8_t out_buffer[20]);
			static string hash160(const uint8_t* buffer, size_t size);
			static void hash256(const uint8_t* buffer, size_t size, uint8_t out_buffer[32]);
			static string hash256(const uint8_t* buffer, size_t size);
			static void hash512(const uint8_t* buffer, size_t size, uint8_t out_buffer[64]);
			static string hash512(const uint8_t* buffer, size_t size);
			static uint256_t hash256i(const uint8_t* buffer, size_t size);
			static uint256_t hash256i(const std::string_view& data);
			static uint64_t erd64(const uint256_t& seed, uint64_t order);
		};

		class arithmetic
		{
		public:
			template <typename t>
			inline static decimal fixed(const t& value)
			{
				return decimal(value).truncate(protocol::now().message.decimal_precision);
			}
			inline static decimal&& fixed(decimal&& value)
			{
				return std::move(value.truncate(protocol::now().message.decimal_precision));
			}
			inline static uint256_t fixed256(const decimal& value)
			{
				auto copy = value * decimal(std::pow<uint64_t>(10, protocol::now().message.decimal_precision));
				return uint256_t(copy.truncate(0).to_string(), 10);
			}
			template <typename t>
			inline static decimal range(const t& value)
			{
				uint256_t divisibility = 1;
				uint256_t decimals = std::min<uint256_t>(value, protocol::now().message.decimal_precision);
				for (uint256_t i = 0; i < decimals; i++)
					divisibility *= 10;
				return fixed(divisibility.to_string());
			}
			template <typename a, typename b>
			inline static decimal divide(const a& a_value, const b& b_value)
			{
				return a_value / fixed<b>(b_value);
			}
			inline static decimal ceil(const decimal& value)
			{
				decimal copy = value;
				copy.truncate(0);
				if (!copy.is_nan() && copy != value)
					++copy;
				return copy;
			}
		};

		class asset
		{
		public:
			static asset_id native();
			static asset_id id_of_handle(const std::string_view& handle);
			static asset_id id_of(const std::string_view& blockchain, const std::string_view& token = std::string_view(), const std::string_view& contract_address = std::string_view());
			static asset_id base_id_of(const asset_id& value);
			static string handle_of(const std::string_view& blockchain, const std::string_view& token = std::string_view(), const std::string_view& contract_address = std::string_view());
			static string handle_of(const asset_id& value);
			static string base_handle_of(const asset_id& value);
			static string blockchain_of(const asset_id& value);
			static string token_of(const asset_id& value);
			static string checksum_of(const asset_id& value);
			static string name_of(const asset_id& value);
			static bool is_any(const asset_id& value, bool require_no_token = false);
			static bool is_aux(const asset_id& value, bool require_no_token = false);
			static uint64_t expiry_of(const asset_id& value);
			static schema* serialize(const asset_id& value);
		};

		class composition
		{
		public:
			using cseckey_t = vector<uint8_t>;
			using cpubkey_t = vector<uint8_t>;
			using chashsig_t = vector<uint8_t>;

		public:
			enum class phase : uint8_t
			{
				any_input_after_reset,
				any_input,
				chosen_input_after_reset,
				chosen_input,
				finalized
			};

			enum class type : uint8_t
			{
				unknown,
				ed25519,
				ed25519_clsag,
				secp256k1,
				secp256k1_schnorr
			};

			struct secret_state
			{
				virtual ~secret_state() = default;
				virtual expects_lr<void> derive_from_seed(const uint256_t& seed) = 0;
				virtual expects_lr<void> derive_from_key(const cseckey_t& secret_key) = 0;
				virtual expects_lr<void> finalize(cseckey_t* output) const = 0;
				virtual bool store(format::wo_stream* stream) const = 0;
				virtual bool load(format::ro_stream& stream) = 0;
			};

			struct public_state
			{
				virtual ~public_state() = default;
				virtual expects_lr<void> derive_from_key(const cseckey_t& secret_key) = 0;
				virtual expects_lr<void> finalize(cpubkey_t* output) const = 0;
				virtual bool store(format::wo_stream* stream) const = 0;
				virtual bool load(format::ro_stream& stream) = 0;
			};

			struct signature_state
			{
				virtual ~signature_state() = default;
				virtual expects_lr<void> setup(const cpubkey_t& public_key, const uint8_t* message, size_t message_size, uint16_t participants) = 0;
				virtual expects_lr<void> aggregate(const cseckey_t& secret_key) = 0;
				virtual expects_lr<void> finalize(chashsig_t* output) const = 0;
				virtual phase next_phase() const = 0;
				virtual bool store(format::wo_stream* stream) const = 0;
				virtual bool load(format::ro_stream& stream) = 0;
				virtual bool prefer_over(const signature_state& other) const = 0;
			};

			struct keypair
			{
				cseckey_t secret_key;
				cpubkey_t public_key;
			};

		public:
			static expects_lr<keypair> derive_keypair(type alg, const uint256_t& seed);
			static expects_lr<uptr<secret_state>> make_secret_state(type alg);
			static expects_lr<uptr<secret_state>> load_secret_state(format::ro_stream& stream, type* alg = nullptr);
			static expects_lr<void> store_secret_state(type alg, const secret_state* state, format::wo_stream* stream);
			static expects_lr<uptr<public_state>> make_public_state(type alg);
			static expects_lr<uptr<public_state>> load_public_state(format::ro_stream& stream, type* alg = nullptr);
			static expects_lr<void> store_public_state(type alg, const public_state* state, format::wo_stream* stream);
			static expects_lr<uptr<signature_state>> make_signature_state(type alg);
			static expects_lr<uptr<signature_state>> make_signature_state(type alg, const cpubkey_t& public_key, const uint8_t* message, size_t message_size, uint16_t participants);
			static expects_lr<uptr<signature_state>> load_signature_state(format::ro_stream& stream, type* alg = nullptr);
			static expects_lr<void> store_signature_state(type alg, const signature_state* state, format::wo_stream* stream);

		public:
			template <typename T>
			static T to_cstorage(const std::string_view& value)
			{
				T result;
				result.resize(value.size());
				memcpy(result.data(), value.data(), value.size());
				return result;
			}
		};

		class keypair_utils
		{
		public:
			static void convert_to_secret_key_ed25519(uint8_t secret_key[32]);
			static void convert_to_scalar_ed25519(const uint8_t scalar[64], uint8_t reduced_scalar[32]);
			static void convert_to_scalar_ed25519(uint8_t scalar[32]);
		};

		struct merkle_tree
		{
			struct branch_path
			{
				vector<uint256_t> branch;
				size_t index = 0;

				uint256_t root(uint256_t hash, const hash_function hasher = &hashing::sha256ci) const;
				bool empty() const;
			};

			vector<uint256_t> nodes;
			size_t pivot = 0;

			branch_path path(const uint256_t& hash) const;
			uint256_t root() const;
			size_t size() const;
			static merkle_tree from(vector<uint256_t>&& elements, const hash_function hasher = &hashing::sha256ci);
		};
	}
}

namespace vitex
{
	namespace core
	{
		template <>
		struct key_hasher<tangent::algorithm::hashsig_t>
		{
			typedef int argument_type;
			typedef size_t result_type;
			using is_transparent = void;

			inline result_type operator()(const tangent::algorithm::hashsig_t& value) const noexcept
			{
				return key_hasher<std::string_view>()(std::string_view((char*)value.data, sizeof(value.data)));
			}
		};

		template <>
		struct key_hasher<tangent::algorithm::seckey_t>
		{
			typedef int argument_type;
			typedef size_t result_type;
			using is_transparent = void;

			inline result_type operator()(const tangent::algorithm::seckey_t& value) const noexcept
			{
				return key_hasher<std::string_view>()(std::string_view((char*)value.data, sizeof(value.data)));
			}
		};

		template <>
		struct key_hasher<tangent::algorithm::pubkey_t>
		{
			typedef int argument_type;
			typedef size_t result_type;
			using is_transparent = void;

			inline result_type operator()(const tangent::algorithm::pubkey_t& value) const noexcept
			{
				return key_hasher<std::string_view>()(std::string_view((char*)value.data, sizeof(value.data)));
			}
		};

		template <>
		struct key_hasher<tangent::algorithm::pubkeyhash_t>
		{
			typedef int argument_type;
			typedef size_t result_type;
			using is_transparent = void;

			inline result_type operator()(const tangent::algorithm::pubkeyhash_t& value) const noexcept
			{
				return key_hasher<std::string_view>()(std::string_view((char*)value.data, sizeof(value.data)));
			}
		};
	}
}
#endif