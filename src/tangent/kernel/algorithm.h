#ifndef TAN_KERNEL_ALGORITHM_H
#define TAN_KERNEL_ALGORITHM_H
#include "../layer/format.h"
#include <array>

typedef struct secp256k1_context_struct secp256k1_context;

namespace tangent
{
	namespace algorithm
	{
		using asset_id = uint256_t;
		using pubsig = uint8_t[64];
		using recpubsig = uint8_t[65];
		using seckey = uint8_t[32];
		using pubkey = uint8_t[33];
		using pubkeyhash = uint8_t[20];
		using subpubkeyhash = uint8_t[40];
		typedef uint256_t(*hash_function)(const uint256_t&, const uint256_t&);

		template <typename t, size_t s>
		struct storage_type
		{
			t data[s] = { 0 };

			storage_type() = default;
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
			storage_type(const storage_type&) = default;
			storage_type(storage_type&&) noexcept = default;
			storage_type& operator=(const storage_type&) = default;
			storage_type& operator=(storage_type&&) noexcept = default;
			bool equals(const t other[s]) const
			{
				return !memcmp(other, data, sizeof(data));
			}
			bool empty() const
			{
				t null[s] = { 0 };
				return !memcmp(data, null, sizeof(null));
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

		using pubsig_t = storage_type<uint8_t, sizeof(pubsig)>;
		using recpubsig_t = storage_type<uint8_t, sizeof(recpubsig)>;
		using seckey_t = storage_type<uint8_t, sizeof(seckey)>;
		using pubkey_t = storage_type<uint8_t, sizeof(pubkey)>;
		using pubkeyhash_t = storage_type<uint8_t, sizeof(pubkeyhash)>;
		using subpubkeyhash_t = storage_type<uint8_t, sizeof(subpubkeyhash)>;

		class wesolowski
		{
		public:
			typedef string digest;

		public:
			struct parameters
			{
				uint32_t length = 512;
				uint32_t bits = 256;
				uint64_t pow = 131072;

				uint128_t difficulty() const;
			};

			struct distribution
			{
				string signature;
				uint256_t value = 0;
				uint256_t nonce = 0;

				uint256_t derive();
				uint256_t derive(const uint256_t& step) const;
			};

		private:
			static parameters default_alg;

		public:
			static distribution random(const parameters& alg, const std::string_view& seed);
			static parameters calibrate(uint64_t confidence, uint64_t target_time = protocol::now().policy.consensus_proof_time);
			static parameters adjust(const parameters& prev_alg, uint64_t prev_time, uint64_t target_index);
			static parameters bump(const parameters& alg, double bump);
			static string evaluate(const parameters& alg, const std::string_view& message);
			static bool verify(const parameters& alg, const std::string_view& message, const std::string_view& sig);
			static int8_t compare(const std::string_view& sig1, const std::string_view& sig2);
			static uint64_t locktime(const std::string_view& sig);
			static uint64_t adjustment_interval();
			static uint64_t adjustment_index(uint64_t index);
			static void set_default(const parameters& alg);
			static const parameters& get_default();
		};

		class nakamoto
		{
		public:
			static uint256_t evaluate(const uint256_t& nonce, const std::string_view& message);
			static bool verify(const uint256_t& nonce, const std::string_view& message, const uint256_t& target, const uint256_t& solution);
			static void serialize(format::wo_stream& stream, const uint256_t& nonce, const std::string_view& message);
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
			static void keygen(seckey secret_key);
			static bool recover(const uint256_t& hash, pubkey public_key, const recpubsig signature);
			static bool recover_hash(const uint256_t& hash, pubkeyhash public_key_hash, const recpubsig signature);
			static bool sign(const uint256_t& hash, const seckey secret_key, recpubsig signature);
			static bool verify(const uint256_t& hash, const pubkey public_key, const recpubsig signature);
			static bool verify_mnemonic(const std::string_view& mnemonic);
			static bool verify_secret_key(const seckey secret_key);
			static bool verify_public_key(const pubkey public_key);
			static bool verify_address(const std::string_view& address);
			static bool verify_sealed_message(const std::string_view& ciphertext);
			static void derive_secret_key_from_mnemonic(const std::string_view& mnemonic, seckey secret_key);
			static void derive_secret_key(const std::string_view& seed, seckey secret_key);
			static bool derive_public_key(const seckey secret_key, pubkey public_key);
			static void derive_public_key_hash(const pubkey public_key, pubkeyhash public_key_hash);
			static void derive_cipher_keypair(const seckey secret_key, const uint256_t& nonce, seckey cipher_secret_key, pubkey cipher_public_key);
			static option<string> public_encrypt(const pubkey cipher_public_key, const std::string_view& plaintext, const std::string_view& entropy);
			static option<string> private_decrypt(const seckey cipher_secret_key, const pubkey cipher_public_key, const std::string_view& ciphertext);
			static bool decode_secret_key(const std::string_view& value, seckey secret_key);
			static bool encode_secret_key(const seckey secret_key, string& value);
			static bool decode_public_key(const std::string_view& value, pubkey public_key);
			static bool encode_public_key(const pubkey public_key, string& value);
			static bool decode_address(const std::string_view& address, pubkeyhash public_key_hash);
			static bool decode_subaddress(const std::string_view& address, subpubkeyhash sub_public_key_hash);
			static bool encode_address(const pubkeyhash public_key_hash, string& address);
			static bool encode_subaddress(const subpubkeyhash sub_public_key_hash, string& address);
			static schema* serialize_secret_key(const seckey secret_key);
			static schema* serialize_public_key(const pubkey public_key);
			static schema* serialize_address(const pubkeyhash public_key_hash);
			static schema* serialize_subaddress(const subpubkeyhash sub_public_key_hash);
			static schema* serialize_subaddress(const pubkeyhash public_key_hash, const pubkeyhash derivation_hash);
			static schema* serialize_subaddress(const pubkeyhash public_key_hash, const std::string_view& derivation_data);
			static secp256k1_context* get_context();
		};

		class encoding
		{
		public:
			static bool decode_uint_blob(const string& value, uint8_t* data, size_t data_size);
			static void encode_uint128(const uint8_t value[16], uint128_t& data);
			static void decode_uint128(const uint128_t& value, uint8_t data[16]);
			static void optimized_encode_uint128(const std::string_view& value, uint128_t& data);
			static void optimized_decode_uint128(const uint128_t& value, uint8_t data[16], size_t* data_size);
			static void encode_uint256(const uint8_t value[32], uint256_t& data);
			static void decode_uint256(const uint256_t& value, uint8_t data[32]);
			static void optimized_encode_uint256(const std::string_view& value, uint256_t& data);
			static void optimized_decode_uint256(const uint256_t& value, uint8_t data[32], size_t* data_size);
			static string encode_0xhex256(const uint256_t& data);
			static uint256_t decode_0xhex256(const std::string_view& data);
			static string encode_0xhex128(const uint128_t& data);
			static uint128_t decode_0xhex128(const std::string_view& data);
			static subpubkeyhash_t to_subaddress(const pubkeyhash public_key_hash, const pubkeyhash derivation_hash = nullptr);
			static subpubkeyhash_t to_subaddress(const pubkeyhash public_key_hash, const std::string_view& derivation_data);
			static pubkeyhash_t to_address(const subpubkeyhash sub_public_key_hash);
			static pubkeyhash_t to_derivation(const subpubkeyhash sub_public_key_hash);
			static uint32_t type_of(const std::string_view& name);
			static schema* serialize_uint256(const uint256_t& data);
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

		class asset
		{
		public:
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
			static bool is_valid(const asset_id& value);
			static uint64_t expiry_of(const asset_id& value);
			static schema* serialize(const asset_id& value);
		};

		class composition
		{
		public:
			using cseckey = uint8_t[64];
			using cpubkey = uint8_t[64];
			using cpubsig = uint8_t[65];
			using cseckey_t = storage_type<uint8_t, sizeof(cseckey)>;
			using cpubkey_t = storage_type<uint8_t, sizeof(cpubkey)>;
			using cpubsig_t = storage_type<uint8_t, sizeof(cpubsig)>;

		public:
			enum class type : uint8_t
			{
				unknown,
				ed25519,
				ed25519_clsag,
				secp256k1,
				schnorr,
				schnorr_taproot
			};

			enum class stage
			{
				configure,
				accumulate,
				finalize
			};

			struct keypair
			{
				cseckey secret_key = { 0 };
				cpubkey public_key = { 0 };
			};

		public:
			static expects_lr<void> derive_keypair(type alg, const uint256_t& seed, keypair* result);
			static expects_lr<void> accumulate_secret_key(type alg, const cseckey share_secret_key, cseckey inout);
			static expects_lr<void> accumulate_public_key(type alg, const cseckey share_secret_key, cpubkey inout);
			static expects_lr<void> accumulate_signature(type alg, const uint8_t* message, size_t message_size, const cpubkey final_public_key, const cseckey share_secret_key, cpubsig inout);
			static expects_lr<void> verify_signature(type alg, const uint8_t* message, size_t message_size, const cpubkey final_public_key, const cpubsig final_signature);
			static stage stage_of(const uint8_t* share_secret_key, const uint8_t* inout, size_t inout_size);
			static size_t size_of_secret_key(type alg, stage condition = stage::finalize);
			static size_t size_of_public_key(type alg, stage condition = stage::finalize);
			static size_t size_of_signature(type alg, stage condition = stage::finalize);
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
		struct key_hasher<tangent::algorithm::pubsig_t>
		{
			typedef float argument_type;
			typedef size_t result_type;
			using is_transparent = void;

			inline result_type operator()(const tangent::algorithm::pubsig_t& value) const noexcept
			{
				return key_hasher<std::string_view>()(std::string_view((char*)value.data, sizeof(value.data)));
			}
		};

		template <>
		struct key_hasher<tangent::algorithm::recpubsig_t>
		{
			typedef float argument_type;
			typedef size_t result_type;
			using is_transparent = void;

			inline result_type operator()(const tangent::algorithm::recpubsig_t& value) const noexcept
			{
				return key_hasher<std::string_view>()(std::string_view((char*)value.data, sizeof(value.data)));
			}
		};

		template <>
		struct key_hasher<tangent::algorithm::seckey_t>
		{
			typedef float argument_type;
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
			typedef float argument_type;
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
			typedef float argument_type;
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