#ifndef TAN_KERNEL_TRANSACTION_H
#define TAN_KERNEL_TRANSACTION_H
#include "wallet.h"

namespace tangent
{
	namespace ledger
	{
		struct state;
		struct block_header;
		struct dispatch_context;
		struct transaction_context;
		struct receipt;

		enum class state_level
		{
			uniform,
			multiform
		};

		enum class transaction_level
		{
			functional,
			delegation,
			consensus,
			attestation,
		};

		struct transaction : messages::authentic
		{
			algorithm::asset_id asset = 0;
			decimal gas_price;
			uint256_t gas_limit = 0;
			uint64_t nonce = 0;
			bool conservative = false;

			virtual expects_lr<void> validate(uint64_t block_number) const;
			virtual expects_lr<void> execute(transaction_context* context) const;
			virtual expects_promise_rt<void> dispatch(const transaction_context* context, dispatch_context* dispatcher) const;
			virtual bool store_payload(format::stream* stream) const override;
			virtual bool load_payload(format::stream& stream) override;
			virtual bool store_body(format::stream* stream) const = 0;
			virtual bool load_body(format::stream& stream) = 0;
			virtual bool recover_many(const transaction_context* context, const receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const;
			virtual bool recover_aliases(const transaction_context* context, const receipt& receipt, ordered_set<uint256_t>& aliases) const;
			virtual bool sign(const algorithm::seckey secret_key) override;
			virtual bool sign(const algorithm::seckey secret_key, uint64_t new_nonce);
			virtual bool sign(const algorithm::seckey secret_key, uint64_t new_nonce, const decimal& price);
			virtual void set_optimal_gas(const decimal& price);
			virtual void set_estimate_gas(const decimal& price);
			virtual void set_gas(const decimal& price, const uint256_t& limit);
			virtual void set_asset(const std::string_view& blockchain, const std::string_view& token = std::string_view(), const std::string_view& contract_address = std::string_view());
			virtual bool is_payable() const;
			virtual bool is_consensus() const;
			virtual bool is_dispatchable() const;
			virtual algorithm::asset_id get_gas_asset() const;
			virtual transaction_level get_type() const;
			virtual uptr<schema> as_schema() const override;
			virtual uint32_t as_type() const override = 0;
			virtual std::string_view as_typename() const override = 0;
			virtual uint256_t get_gas_estimate() const = 0;
		};

		struct delegation_transaction : transaction
		{
			virtual expects_lr<void> execute(transaction_context* context) const override;
			virtual bool store_payload(format::stream* stream) const override;
			virtual bool load_payload(format::stream& stream) override;
			transaction_level get_type() const override;
		};

		struct consensus_transaction : transaction
		{
			virtual expects_lr<void> execute(transaction_context* context) const override;
			virtual bool store_payload(format::stream* stream) const override;
			virtual bool load_payload(format::stream& stream) override;
			transaction_level get_type() const override;
		};

		struct attestation_transaction : transaction
		{
			struct evaluation_branch
			{
				ordered_set<algorithm::recpubsig_t> signatures;
				format::stream message;
			};

			ordered_map<uint256_t, evaluation_branch> output_hashes;
			uint256_t input_hash = 0;

			virtual expects_lr<void> validate(uint64_t block_number) const override;
			virtual expects_lr<void> execute(transaction_context* context) const override;
			virtual bool merge(const transaction_context* context, const attestation_transaction& other);
			virtual bool store_payload(format::stream* stream) const override;
			virtual bool load_payload(format::stream& stream) override;
			virtual bool sign(const algorithm::seckey secret_key) override;
			virtual bool sign(const algorithm::seckey secret_key, uint64_t new_nonce) override;
			virtual bool sign(const algorithm::seckey secret_key, uint64_t new_nonce, const decimal& price) override;
			virtual bool verify(const algorithm::pubkey public_key) const override;
			virtual bool verify(const algorithm::pubkey public_key, const uint256_t& output_hash, size_t index) const;
			virtual bool recover(algorithm::pubkey public_key) const override;
			virtual bool recover(algorithm::pubkey public_key, const uint256_t& output_hash, size_t index) const;
			virtual bool recover_hash(algorithm::pubkeyhash public_key_hash) const override;
			virtual bool recover_hash(algorithm::pubkeyhash public_key_hash, const uint256_t& output_hash, size_t index) const;
			virtual bool is_signature_null() const override;
			virtual void set_optimal_gas(const decimal& price) override;
			virtual void set_statement(const uint256_t& new_input_hash, const format::stream& output_message);
			virtual void set_best_branch(const uint256_t& output_hash);
			virtual const evaluation_branch* get_best_branch(const transaction_context* context, ordered_map<algorithm::asset_id, size_t>* aggregators) const;
			virtual uint256_t get_branch_image(const uint256_t& output_hash) const;
			virtual uint256_t as_group_hash() const;
			virtual uptr<schema> as_schema() const override;
			transaction_level get_type() const override;
		};

		struct receipt final : messages::uniform
		{
			vector<std::pair<uint32_t, format::variables>> events;
			algorithm::pubkeyhash from = { 0 };
			uint256_t transaction_hash = 0;
			uint256_t absolute_gas_use = 0;
			uint256_t relative_gas_use = 0;
			uint256_t relative_gas_paid = 0;
			uint64_t generation_time = 0;
			uint64_t finalization_time = 0;
			uint64_t block_number = 0;
			bool successful = false;

			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			bool is_from_null() const;
			void emit_event(uint32_t type, format::variables&& values);
			const format::variables* find_event(uint32_t type, size_t offset = 0) const;
			const format::variables* reverse_find_event(uint32_t type, size_t offset = 0) const;
			option<string> get_error_messages() const;
			uptr<schema> as_schema() const override;
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
			vector<const format::variables*> find_events(size_t offset = 0) const
			{
				vector<const format::variables*> result;
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
			const format::variables* find_event(size_t offset = 0) const
			{
				return find_event(t::as_instance_type(), offset);
			}
			template <typename t>
			const format::variables* reverse_find_event(size_t offset = 0) const
			{
				return reverse_find_event(t::as_instance_type(), offset);
			}
		};

		struct state : messages::uniform
		{
			uint64_t block_number = 0;
			uint64_t block_nonce = 0;

			state(uint64_t new_block_number, uint64_t new_block_nonce);
			state(const block_header* new_block_header);
			virtual ~state() = default;
			virtual expects_lr<void> transition(const transaction_context* context, const state* prev_state) = 0;
			virtual bool store(format::stream* stream) const override;
			virtual bool load(format::stream& stream) override;
			virtual bool store_payload(format::stream* stream) const override = 0;
			virtual bool load_payload(format::stream& stream) override = 0;
			virtual state_level as_level() const = 0;
			virtual string as_composite() const = 0;
			virtual uptr<schema> as_schema() const override = 0;
			virtual uint32_t as_type() const override = 0;
			virtual std::string_view as_typename() const override = 0;
		};

		struct uniform : state
		{
			uniform(uint64_t new_block_number, uint64_t new_block_nonce);
			uniform(const block_header* new_block_header);
			virtual uptr<schema> as_schema() const override;
			virtual state_level as_level() const override;
			virtual string as_composite() const override;
			virtual string as_index() const = 0;
			static string as_instance_composite(const std::string_view& index);
		};

		struct multiform : state
		{
			multiform(uint64_t new_block_number, uint64_t new_block_nonce);
			multiform(const block_header* new_block_header);
			virtual uptr<schema> as_schema() const override;
			virtual state_level as_level() const override;
			virtual string as_composite() const override;
			virtual string as_column() const = 0;
			virtual string as_row() const = 0;
			virtual int64_t as_factor() const = 0;
			static string as_instance_composite(const std::string_view& column, const std::string_view& row);
		};

		class gas_util
		{
		public:
			static uint256_t get_gas_work(const uint128_t& difficulty, const uint256_t& gas_use, const uint256_t& gas_limit, uint64_t priority);
			static uint256_t get_operational_gas_estimate(size_t size, size_t operations);
			static uint256_t get_storage_gas_estimate(size_t bytes_in, size_t bytes_out);
			template <typename t, size_t operations>
			static uint256_t get_gas_estimate()
			{
				static uint256_t limit = get_operational_gas_estimate(t().as_message().data.size(), operations);
				return limit;
			}
		};
	}
}
#endif
