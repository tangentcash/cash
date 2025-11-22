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

		struct transaction : messages::authentic
		{
			algorithm::asset_id asset = 0;
			decimal gas_price;
			uint256_t gas_limit = 0;
			uint64_t nonce = 0;

			virtual expects_lr<void> validate(uint64_t block_number) const;
			virtual expects_lr<void> execute(transaction_context* context) const;
			virtual expects_promise_rt<void> dispatch(const transaction_context* context, dispatch_context* dispatcher) const;
			virtual bool store_payload(format::wo_stream* stream) const override;
			virtual bool load_payload(format::ro_stream& stream) override;
			virtual bool store_body(format::wo_stream* stream) const = 0;
			virtual bool load_body(format::ro_stream& stream) = 0;
			virtual bool recover_many(const transaction_context* context, const receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const;
			virtual bool recover_aliases(const transaction_context* context, const receipt& receipt, ordered_set<uint256_t>& aliases) const;
			virtual bool sign(const algorithm::seckey_t& secret_key) override;
			virtual bool sign(const algorithm::seckey_t& secret_key, uint64_t new_nonce);
			virtual expects_lr<void> sign(const algorithm::seckey_t& secret_key, uint64_t new_nonce, const decimal& price, const uint256_t& gas_padding = 0);
			virtual expects_lr<void> set_optimal_gas(const decimal& price);
			virtual void set_gas(const decimal& price, const uint256_t& limit);
			virtual void set_asset(const std::string_view& blockchain, const std::string_view& token = std::string_view(), const std::string_view& contract_address = std::string_view());
			virtual bool is_commitment() const;
			virtual bool is_dispatchable() const;
			virtual uptr<schema> as_schema() const override;
			virtual uint32_t as_type() const override = 0;
			virtual std::string_view as_typename() const override = 0;
		};

		struct commitment : transaction
		{
			commitment();
			virtual expects_lr<void> execute(transaction_context* context) const override;
			virtual bool store_payload(format::wo_stream* stream) const override;
			virtual bool load_payload(format::ro_stream& stream) override;
			virtual bool is_commitment() const override;
		};

		struct receipt final : messages::uniform
		{
			vector<std::pair<uint32_t, format::variables>> events;
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
			virtual bool store(format::wo_stream* stream) const override;
			virtual bool load(format::ro_stream& stream) override;
			virtual bool store_optimized(format::wo_stream* stream) const;
			virtual bool load_optimized(format::ro_stream& stream);
			virtual bool store_payload(format::wo_stream* stream) const override = 0;
			virtual bool load_payload(format::ro_stream& stream) override = 0;
			virtual bool store_data(format::wo_stream* stream) const = 0;
			virtual bool load_data(format::ro_stream& stream) = 0;
			virtual bool is_permanent() const;
			virtual uptr<schema> as_schema() const override = 0;
			virtual state_level as_level() const = 0;
			virtual uint32_t as_type() const override = 0;
			virtual std::string_view as_typename() const override = 0;
		};

		struct uniform : state
		{
			uniform(uint64_t new_block_number, uint64_t new_block_nonce);
			uniform(const block_header* new_block_header);
			virtual bool store_payload(format::wo_stream* stream) const override;
			virtual bool load_payload(format::ro_stream& stream) override;
			virtual bool store_index(format::wo_stream* stream) const = 0;
			virtual bool load_index(format::ro_stream& stream) = 0;
			virtual uptr<schema> as_schema() const override;
			virtual state_level as_level() const override;
			virtual string as_index() const;
		};

		struct multiform : state
		{
			multiform(uint64_t new_block_number, uint64_t new_block_nonce);
			multiform(const block_header* new_block_header);
			virtual bool store_payload(format::wo_stream* stream) const override;
			virtual bool load_payload(format::ro_stream& stream) override;
			virtual bool store_column(format::wo_stream* stream) const = 0;
			virtual bool load_column(format::ro_stream& stream) = 0;
			virtual bool store_row(format::wo_stream* stream) const = 0;
			virtual bool load_row(format::ro_stream& stream) = 0;
			virtual uptr<schema> as_schema() const override;
			virtual state_level as_level() const override;
			virtual string as_column() const;
			virtual string as_row() const;
			virtual uint256_t as_rank() const = 0;
		};
	}
}
#endif
