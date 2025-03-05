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
		using sighash = uint8_t[64];
		using recsighash = uint8_t[65];
		using seckey = uint8_t[32];
		using pubkey = uint8_t[33];
		using pubkeyhash = uint8_t[20];
		typedef uint256_t(*hash_function)(const uint256_t&, const uint256_t&);

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
			static distribution random(const parameters& alg, const format::stream& seed);
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
			static void serialize(format::stream& stream, const uint256_t& nonce, const std::string_view& message);
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
			static bool recover(const uint256_t& hash, pubkey public_key, const recsighash signature);
			static bool recover_hash(const uint256_t& hash, pubkeyhash public_key_hash, const recsighash signature);
			static bool sign(const uint256_t& hash, const seckey secret_key, recsighash signature);
			static bool verify(const uint256_t& hash, const pubkey public_key, const recsighash signature);
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
			static bool encode_address(const pubkeyhash public_key_hash, string& address);
			static schema* serialize_secret_key(const seckey secret_key);
			static schema* serialize_public_key(const pubkey public_key);
			static schema* serialize_address(const pubkeyhash public_key_hash);
			static secp256k1_context* get_context();
		};

		class encoding
		{
		public:
			static bool decode_uint_blob(const string& value, uint8_t* data, size_t data_size);
			static void encode_uint128(const uint8_t value[16], uint128_t& data);
			static void decode_uint128(const uint128_t& value, uint8_t data[16]);
			static void encode_uint256(const uint8_t value[32], uint256_t& data);
			static void decode_uint256(const uint256_t& value, uint8_t data[32]);
			static string encode_0xhex256(const uint256_t& data);
			static uint256_t decode_0xhex256(const std::string_view& data);
			static string encode_0xhex128(const uint128_t& data);
			static uint128_t decode_0xhex128(const std::string_view& data);
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
			static bool is_valid(const asset_id& value);
			static uint64_t expiry_of(const asset_id& value);
			static schema* serialize(const asset_id& value);
		};

		class composition
		{
		public:
			using cseed = uint8_t[64];
			using cseckey = uint8_t[64];
			using cpubkey = uint8_t[64];

		public:
			enum class type
			{
				ED25519,
				SECP256K1
			};

		public:
			static expects_lr<void> derive_keypair(type alg, const cseed seed, cseckey secret_key, cpubkey public_key);
			static expects_lr<void> derive_public_key(type alg, const cpubkey public_key1, const cseckey secret_key2, cpubkey public_key, size_t* public_key_size);
			static expects_lr<void> derive_secret_key(type alg, const cseckey secret_key1, const cseckey secret_key2, cseckey secret_key, size_t* secret_key_size);
			static void convert_to_composite_hash(const uint8_t* a, size_t asize, const uint8_t* b, size_t bsize, uint8_t c[32]);
			static void convert_to_secret_key_ed25519(uint8_t secret_key[32]);
			static void convert_to_scalar_ed25519(uint8_t secret_key[32]);
			static void convert_to_secret_seed(const seckey secret_key, const std::string_view& entropy, cseed seed);
		};

		struct merkle_tree
		{
		public:
			struct path
			{
				friend merkle_tree;

			private:
				vector<uint256_t> nodes;
				size_t index = 0;

			public:
				hash_function hasher = &hashing::sha256ci;

			public:
				uint256_t calculate_root(uint256_t hash) const;
				vector<uint256_t>& get_branch();
				const vector<uint256_t>& get_branch() const;
				size_t get_index() const;
				bool empty();
			};

		private:
			vector<uint256_t> nodes;
			size_t hashes = 0;

		public:
			hash_function hasher = &hashing::sha256ci;

		public:
			merkle_tree();
			merkle_tree(const uint256_t& prev_merkle_root);
			merkle_tree(const merkle_tree&) = default;
			merkle_tree(merkle_tree&&) = default;
			merkle_tree& operator=(const merkle_tree&) = default;
			merkle_tree& operator=(merkle_tree&&) = default;
			merkle_tree& shift(const uint256_t& hash);
			merkle_tree& push(const uint256_t& hash);
			merkle_tree& reset();
			merkle_tree& calculate();
			path calculate_path(const uint256_t& hash);
			uint256_t calculate_root();
			const vector<uint256_t>& get_tree();
			const vector<uint256_t>& get_tree() const;
			size_t get_complexity() const;
			bool is_calculated() const;
		};
	}
}
#endif