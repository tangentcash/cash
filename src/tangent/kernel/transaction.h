#ifndef TAN_KERNEL_TRANSACTION_H
#define TAN_KERNEL_TRANSACTION_H
#include "algorithm.h"

namespace tangent
{
	namespace ledger
	{
		struct block_header;
		struct executor_context;
		struct transaction_receipt;
		struct transition_state;

		enum class state_level
		{
			uniform,
			multiform
		};

		struct uniform_serializer
		{
			uint256_t checksum;

			uniform_serializer();
			virtual ~uniform_serializer() = default;
			virtual bool store(format::wo_stream* stream) const;
			virtual bool load(format::ro_stream& stream);
			virtual bool store_payload(format::wo_stream* stream) const = 0;
			virtual bool load_payload(format::ro_stream& stream) = 0;
			virtual uint256_t as_hash(bool renew = false) const;
			virtual uint32_t as_type() const = 0;
			virtual std::string_view as_typename() const = 0;
			virtual format::tree as_tree() const = 0;
			virtual format::wo_stream as_message() const;
			virtual format::wo_stream as_signable() const;
		};

		struct authentic_serializer
		{
			algorithm::hashsig_t signature;
			uint256_t checksum;

			authentic_serializer();
			virtual ~authentic_serializer() = default;
			virtual bool store(format::wo_stream* stream) const;
			virtual bool load(format::ro_stream& stream);
			virtual bool store_payload(format::wo_stream* stream) const = 0;
			virtual bool load_payload(format::ro_stream& stream) = 0;
			virtual bool sign(const algorithm::seckey_t& secret_key);
			virtual bool verify(const algorithm::pubkey_t& public_key) const;
			virtual bool recover(algorithm::pubkey_t& public_key) const;
			virtual bool recover_hash(algorithm::pubkeyhash_t& public_key_hash) const;
			virtual uint256_t as_hash(bool renew = false) const;
			virtual uint32_t as_type() const = 0;
			virtual std::string_view as_typename() const = 0;
			virtual format::tree as_tree() const = 0;
			virtual format::wo_stream as_message() const;
			virtual format::wo_stream as_signable() const;
		};

		struct transaction_message : authentic_serializer
		{
			algorithm::asset_id asset = 0;
			decimal gas_price;
			uint256_t gas_limit = 0;
			uint64_t nonce = 0;

			virtual expects_lr<void> validate(uint64_t block_number) const;
			virtual expects_lr<void> execute(executor_context* executor) const;
			virtual bool store_payload(format::wo_stream* stream) const override;
			virtual bool load_payload(format::ro_stream& stream) override;
			virtual bool store_body(format::wo_stream* stream) const = 0;
			virtual bool load_body(format::ro_stream& stream) = 0;
			virtual bool recover_many(const executor_context* executor, const transaction_receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const;
			virtual bool recover_aliases(btree_set<uint256_t>& aliases) const;
			virtual bool sign(const algorithm::seckey_t& secret_key) override;
			virtual bool sign(const algorithm::seckey_t& secret_key, uint64_t new_nonce);
			virtual expects_lr<void> sign(const algorithm::seckey_t& secret_key, uint64_t new_nonce, const decimal& price);
			virtual expects_lr<void> set_optimal_gas(const decimal& price);
			virtual void set_gas(const decimal& price, const uint256_t& limit);
			virtual void set_asset(const std::string_view& blockchain, const std::string_view& token = std::string_view(), const std::string_view& contract_address = std::string_view());
			virtual uint64_t commitment_priority(uint256_t* event_hash) const;
			virtual uint256_t gas_asset() const;
			virtual format::tree as_tree() const override;
			virtual uint32_t as_delegation_type() const;
			virtual uint32_t as_type() const override = 0;
			virtual std::string_view as_typename() const override = 0;
		};

		struct commitment_message : transaction_message
		{
			commitment_message();
			virtual expects_lr<void> execute(executor_context* executor) const override;
			virtual bool store_payload(format::wo_stream* stream) const override;
			virtual bool load_payload(format::ro_stream& stream) override;
			virtual uint64_t commitment_priority(uint256_t* event_hash) const = 0;
		};

		struct transaction_receipt final : uniform_serializer
		{
			struct receipt_event
			{
				format::variables args;
				algorithm::pubkeyhash_t emitter;
				uint32_t event;
			};

			vector<receipt_event> events;
			algorithm::pubkeyhash_t from;
			uint256_t transaction_hash = 0;
			uint256_t absolute_gas_use = 0;
			uint256_t relative_gas_use = 0;
			uint64_t block_time = 0;
			uint64_t block_number = 0;
			bool successful = false;

			bool store_payload(format::wo_stream* stream) const override;
			bool load_payload(format::ro_stream& stream) override;
			void emit_event(uint32_t type, format::variables&& values);
			void emit_forwarded_event(uint32_t type, const algorithm::pubkeyhash_t& emitter, format::variables&& values);
			const receipt_event* find_event(uint32_t type, size_t offset = 0) const;
			const receipt_event* reverse_find_event(uint32_t type, size_t offset = 0) const;
			option<string> get_error_message() const;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			template <typename t>
			void emit_event(format::variables&& values)
			{
				emit_event(t::as_instance_type(), std::move(values));
			}
			template <typename t>
			void emit_forwarded_event(const algorithm::pubkeyhash_t& emitter, format::variables&& values)
			{
				emit_forwarded_event(t::as_instance_type(), std::move(values));
			}
			template <typename t>
			vector<const receipt_event*> find_events(size_t offset = 0) const
			{
				vector<const receipt_event*> result;
				while (true)
				{
					auto* event = find_event(t::as_instance_type(), offset++);
					if (!event)
						break;
					
					result.push_back(event);
				}
				return result;
			}
			template <typename t>
			const receipt_event* find_event(size_t offset = 0) const
			{
				return find_event(t::as_instance_type(), offset);
			}
			template <typename t>
			const receipt_event* reverse_find_event(size_t offset = 0) const
			{
				return reverse_find_event(t::as_instance_type(), offset);
			}
		};

		struct transition_state : uniform_serializer
		{
			uint64_t block_number = 0;

			transition_state(uint64_t new_block_number);
			transition_state(const block_header* new_block_header);
			virtual ~transition_state() = default;
			virtual expects_lr<void> transition(const transition_state* prev_state) = 0;
			virtual bool store(format::wo_stream* stream) const override;
			virtual bool load(format::ro_stream& stream) override;
			virtual bool store_optimized(format::wo_stream* stream) const;
			virtual bool load_optimized(format::ro_stream& stream);
			virtual bool store_payload(format::wo_stream* stream) const override = 0;
			virtual bool load_payload(format::ro_stream& stream) override = 0;
			virtual bool store_data(format::wo_stream* stream) const = 0;
			virtual bool load_data(format::ro_stream& stream) = 0;
			virtual bool is_permanent() const;
			virtual uint64_t time_lock_blocks(const transition_state* prev, uint64_t milliseconds) const;
			virtual format::tree as_tree() const override = 0;
			virtual state_level as_level() const = 0;
			virtual uint32_t as_type() const override = 0;
			virtual std::string_view as_typename() const override = 0;
		};

		struct uniform_state : transition_state
		{
			uniform_state(uint64_t new_block_number);
			uniform_state(const block_header* new_block_header);
			virtual bool store_payload(format::wo_stream* stream) const override;
			virtual bool load_payload(format::ro_stream& stream) override;
			virtual bool store_index(format::wo_stream* stream) const = 0;
			virtual bool load_index(format::ro_stream& stream) = 0;
			virtual format::tree as_tree() const override;
			virtual state_level as_level() const override;
			virtual string as_index() const;
		};

		struct multiform_state : transition_state
		{
			multiform_state(uint64_t new_block_number);
			multiform_state(const block_header* new_block_header);
			virtual bool store_payload(format::wo_stream* stream) const override;
			virtual bool load_payload(format::ro_stream& stream) override;
			virtual bool store_column(format::wo_stream* stream) const = 0;
			virtual bool load_column(format::ro_stream& stream) = 0;
			virtual bool store_row(format::wo_stream* stream) const = 0;
			virtual bool load_row(format::ro_stream& stream) = 0;
			virtual format::tree as_tree() const override;
			virtual state_level as_level() const override;
			virtual string as_column() const;
			virtual string as_row() const;
			virtual uint256_t as_rank() const = 0;
		};

		struct distribution_key : uniform_serializer
		{
			struct share_pair
			{
				algorithm::share_t recv;
				algorithm::share_t sent;
			};

			struct key_ref
			{
				algorithm::pubkeyhash_t owner;
				algorithm::asset_id asset;
				uint256_t hash;
			} ref;
			btree_map<algorithm::pubkeyhash_t, share_pair> shares;
			vector<uint8_t> key;

			~distribution_key();
			bool store_payload(format::wo_stream* stream) const override;
			bool load_payload(format::ro_stream& stream) override;
			format::tree as_tree() const override;
			format::wo_stream as_message() const override;
			format::wo_stream as_signable() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t as_ref_hash() const;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static uint256_t ref_hash(const algorithm::pubkeyhash_t& owner, const algorithm::asset_id& asset, const uint256_t& hash);
		};

		struct wallet : uniform_serializer
		{
			algorithm::seckey_t secret_key;
			algorithm::pubkey_t public_key;
			algorithm::pubkeyhash_t public_key_hash;

			~wallet();
			bool set_secret_key(const algorithm::seckey_t& value);
			void set_public_key(const algorithm::pubkey_t& value);
			void set_public_key_hash(const algorithm::pubkeyhash_t& value);
			bool verify_secret_key() const;
			bool verify_public_key() const;
			bool verify_address() const;
			bool verify(const authentic_serializer& message) const;
			bool recovers(const authentic_serializer& message) const;
			bool sign(authentic_serializer& message) const;
			bool store_payload(format::wo_stream* stream) const override;
			bool load_payload(format::ro_stream& stream) override;
			bool has_secret_key() const;
			bool has_public_key() const;
			bool has_public_key_hash() const;
			option<string> seal_message(const std::string_view& plaintext, const algorithm::pubkey_t& recipient_public_key, const uint256_t& entropy) const;
			option<string> open_message(const std::string_view& ciphertext) const;
			option<string> open_message(const std::string_view& ciphertext, const uint256_t& entropy) const;
			string get_secret_key() const;
			string get_public_key() const;
			string get_address() const;
			expects_lr<uint64_t> get_latest_nonce() const;
			format::tree as_tree() const override;
			format::tree as_secret_tree() const;
			format::wo_stream as_message() const override;
			format::wo_stream as_signable() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static wallet from_mnemonic(const std::string_view& mnemonic);
			static wallet from_seed(const std::string_view& seed = std::string_view());
			static wallet from_entropy(const uint256_t& entropy);
			static wallet from_secret_key(const algorithm::seckey_t& key);
			static wallet from_public_key(const algorithm::pubkey_t& key);
			static wallet from_public_key_hash(const algorithm::pubkeyhash_t& key);
		};

		struct node final : uniform_serializer
		{
			struct
			{
				btree_set<algorithm::pubkey_t> neighbors;
				uint64_t latency = (uint64_t)std::numeric_limits<int64_t>::max();
				uint64_t timestamp = 0;
				uint64_t calls = 0;
				uint64_t errors = 0;
				bool reachable = false;
			} availability;

			struct
			{
				uint16_t consensus = 0;
				uint16_t discovery = 0;
				uint16_t rpc = 0;
			} ports;

			struct
			{
				bool has_consensus = false;
				bool has_discovery = false;
				bool has_superchain = false;
				bool has_rpc = false;
				bool has_production = false;
				bool has_participation = false;
				bool has_attestation = false;
			} services;

			socket_address address;
			uint32_t fork_version = (uint32_t)FORK_VERSION;
			uint32_t patch_version = (uint32_t)PATCH_VERSION;

			bool store_payload(format::wo_stream* stream) const override;
			bool load_payload(format::ro_stream& stream) override;
			bool is_valid() const;
			uint64_t get_preference() const;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};
	}
}
#endif
