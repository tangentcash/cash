#ifndef TAN_KERNEL_ALGORITHM_H
#define TAN_KERNEL_ALGORITHM_H
#include "format.h"
#include <array>

typedef struct secp256k1_context_struct secp256k1_context;

namespace tangent
{
	namespace algorithm
	{
		template <typename t, size_t s>
		struct storage_type
		{
			t blob[s] = { 0 };

			storage_type() = default;
			storage_type(std::nullptr_t) = delete;
			storage_type(const t new_blob[s])
			{
				if (new_blob != nullptr)
					memcpy(blob, new_blob, sizeof(blob));
			}
			storage_type(const t* new_blob, size_t new_size)
			{
				if (new_blob != nullptr)
					memcpy(blob, new_blob, std::min(new_size, sizeof(blob)));
			}
			storage_type(const std::string_view& new_blob)
			{
				memcpy(blob, new_blob.data(), std::min(new_blob.size(), sizeof(blob)));
			}
			storage_type(const vector<uint8_t>& new_blob)
			{
				memcpy(blob, new_blob.data(), std::min(new_blob.size(), sizeof(blob)));
			}
			storage_type(const storage_type&) = default;
			storage_type(storage_type&&) noexcept = default;
			storage_type& operator=(const storage_type&) = default;
			storage_type& operator=(storage_type&&) noexcept = default;
			constexpr size_t size() const
			{
				return s;
			}
			void clear()
			{
				memset(blob, 0, sizeof(blob));
			}
			bool equals(const storage_type& other) const
			{
				return !memcmp(other.blob, blob, sizeof(blob));
			}
			bool empty() const
			{
				t null[s] = { 0 };
				return !memcmp(blob, null, sizeof(null));
			}
			vector<uint8_t> container() const
			{
				vector<uint8_t> result;
				result.resize(s);
				memcpy(result.data(), blob, sizeof(blob));
				return result;
			}
			std::string_view view() const
			{
				return std::string_view((char*)blob, sizeof(blob));
			}
			std::string_view optimized_view() const
			{
				size_t size = s;
				auto* ptr = blob + size;
				while (size > 0 && !*(--ptr))
					--size;

				return std::string_view((char*)blob, size);
			}
			bool operator== (const storage_type& other) const
			{
				return equals(other.blob);
			}
			bool operator< (const storage_type& other) const
			{
				for (size_t i = 0; i < s; ++i)
				{
					if (blob[i] > other.blob[i])
						return false;
					else if (blob[i] < other.blob[i])
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
		using share_t = storage_type<uint8_t, 113>;
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
			static uint64_t calibrate(uint64_t confidence, uint64_t target_time = protocol::now().policy.pow.time);
			static uint64_t adjust(uint64_t prev_difficulty, uint64_t prev_time, uint64_t target_index);
			static uint64_t scale(uint64_t difficulty, const decimal& multiplier);
			static string evaluate(uint64_t difficulty, const std::string_view& message);
			static bool verify(uint64_t difficulty, const std::string_view& message, const std::string_view& proof);
			static int8_t compare(const std::string_view& proof1, const std::string_view& proof2);
			static uint64_t adjustment_interval();
			static uint64_t adjustment_index(uint64_t index);
			static decimal adjustment_scaling(uint64_t index);
			static format::tree serialize(uint64_t difficulty, const std::string_view& proof, const decimal& scaling = decimal::nan());
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
			static bool derive_seed_from_password(const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size);
			static bool split_secret_into_shares(const uint8_t message[64], uint8_t threshold, uint8_t count, btree_set<share_t>& shares);
			static bool combine_shares_into_secret(const btree_set<share_t>& shares, uint8_t message[64]);
			static uint8_t recovery_threshold(size_t shares);
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
			static format::variable serialize_secret_key(const seckey_t& secret_key);
			static format::variable serialize_public_key(const pubkey_t& public_key);
			static format::variable serialize_address(const pubkeyhash_t& public_key_hash);
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
			static format::variable serialize_uint256(const uint256_t& data, bool always16 = false);
			static expects_lr<string> pack_program(const std::string_view& unpacked_code);
			static expects_lr<string> unpack_program(const std::string_view& packed_code);
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
			static string ppc512(const std::string_view& unpacked_code);
			static string atca160ascii(const std::string_view& contract_address);
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
				if (!value.is_positive())
					return uint256_t(0);

				auto numeric = value.to_string();
				size_t index = numeric.find('.');
				size_t size = protocol::now().message.decimal_precision;
				size_t max_size = size + protocol::now().message.integer_precision;
				if (index != std::string::npos)
				{
					size_t delta = numeric.size() - index - 1;
					if (delta > size)
						numeric.resize(numeric.size() - (delta - size));
					if (delta < size)
						numeric.append(size - delta, '0');
					numeric.erase(index, 1);
				}
				else
					numeric.append(size, '0');

				if (numeric.size() > max_size)
					numeric.erase(0, numeric.size() - max_size);

				return uint256_t(numeric, 10);
			}
			inline static uint32_t fastmod256r32(const uint256_t& value, uint64_t order)
			{
				uint64_t w0 = value.low().low();
				uint64_t w1 = value.low().high();
				uint64_t w2 = value.high().low();
				uint64_t w3 = value.high().high();
				uint64_t w = (w0 % order) + (w1 % order) + (w2 % order) + (w3 % order);
				return static_cast<uint32_t>(w % order);
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
				auto result = a_value / fixed<b>(b_value);
				return result.truncate(protocol::now().message.decimal_precision);
			}
			inline static decimal ceil(const decimal& value)
			{
				decimal copy = value;
				copy.truncate(0);
				if (!copy.is_nan() && copy != value)
					++copy;
				return copy;
			}
			template <typename t>
			static t integer_sqrt(t n) noexcept
			{
				if (n == 0)
					return 0;

				uint16_t count = 0; t temp = n;
				const uint16_t bits = sizeof(t) * 8;
				for (int i = 0; i < bits; ++i)
				{
					if ((temp & (t(1) << (bits - 1))) != 0)
						break;
					temp <<= 1;
					count++;
				}

				t x = t(1) << (sizeof(t) * 8 - 1 - count) / 2;
				while (true)
				{
					t x_new = (x + n / x) / 2;
					if (x_new >= x)
						break;
					x = x_new;
				}

				while (x * x > n) x--;
				while ((x + 1) * (x + 1) <= n) x++;
				return x;
			}
			template <typename t>
			static t integer_pow(t a, t b) noexcept
			{
				t r = a;
				for (t i = t(1); i < b; i++)
					r *= a;
				return r;
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
			static string blockchain_of(const asset_id& value);
			static string token_of(const asset_id& value);
			static string checksum_of(const asset_id& value);
			static string name_of(const asset_id& value);
			static bool is_any(const asset_id& value, bool require_no_token = false, bool auxiliary_only = false);
			static bool is_aux(const asset_id& value, bool require_no_token = false);
			static format::tree serialize(const asset_id& value);
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

			struct compositor
			{
				virtual ~compositor() = default;
				virtual expects_lr<void> setup_public_key(const uint8_t* message, size_t message_size, uint16_t participants) = 0;
				virtual expects_lr<void> setup_signature(const cpubkey_t& public_key, const uint8_t* message, size_t message_size, uint16_t participants) = 0;
				virtual expects_lr<void> aggregate(const cseckey_t& secret_key) = 0;
				virtual expects_lr<void> to_partial_secret_key(const uint8_t* seed, size_t seed_size, cseckey_t* output) const = 0;
				virtual expects_lr<void> to_public_key(cpubkey_t* output) const = 0;
				virtual expects_lr<void> to_signature(chashsig_t* output) const = 0;
				virtual expects_lr<void> verify_signature(const uint8_t* message, size_t message_size, const chashsig_t& signature, const cpubkey_t& public_key) const = 0;
				virtual phase next_phase() const = 0;
				virtual uint32_t steps_left() const = 0;
				virtual bool store(format::wo_stream* stream) const = 0;
				virtual bool load(format::ro_stream& stream) = 0;
				virtual bool may_transition_to(const compositor& next) const = 0;
			};

			struct keypair
			{
				cseckey_t secret_key;
				cpubkey_t public_key;
			};

		public:
			static expects_lr<keypair> derive_keypair(type alg, const uint8_t* seed, size_t seed_size);
			static expects_lr<uptr<compositor>> make_compositor(type alg);
			static expects_lr<uptr<compositor>> make_public_key_compositor(type alg, const uint8_t* message, size_t message_size, uint16_t participants);
			static expects_lr<uptr<compositor>> make_signature_compositor(type alg, const cpubkey_t& public_key, const uint8_t* message, size_t message_size, uint16_t participants);
			static expects_lr<uptr<compositor>> load_compositor(format::ro_stream& stream, type* alg = nullptr);
			static expects_lr<void> store_compositor(type alg, const compositor* state, format::wo_stream* stream);

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

		struct exponential_distribution
		{
			void* state;

			exponential_distribution();
			exponential_distribution(const exponential_distribution&) = delete;
			exponential_distribution(exponential_distribution&& other) noexcept;
			~exponential_distribution();
			exponential_distribution& operator=(const exponential_distribution& other) = delete;
			exponential_distribution& operator=(exponential_distribution&& other) noexcept;
			uint32_t next(const uint256_t& seed, uint32_t order);
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
		template <typename t, size_t s>
		struct key_hash<tangent::algorithm::storage_type<t, s>>
		{
			typedef tangent::algorithm::storage_type<t, s> argument_type;
			typedef size_t result_type;
			using is_transparent = void;

			inline result_type operator()(const tangent::algorithm::storage_type<t, s>& value) const noexcept
			{
				return key_hash<std::string_view>()(value.view());
			}
		};
	}
}
#endif