#ifndef TAN_POLICY_STATES_H
#define TAN_POLICY_STATES_H
#include "../kernel/transaction.h"

namespace tangent
{
	namespace states
	{
		enum class account_flags : uint8_t
		{
			as_is = 0,
			offline = 1 << 0,
			online = 1 << 1,
			founder = 1 << 2,
			outlaw = 1 << 3
		};

		enum class address_type : uint8_t
		{
			witness = 0,
			router,
			custodian,
			contribution
		};

		struct account_sequence final : ledger::uniform
		{
			algorithm::pubkeyhash owner = { 0 };
			uint64_t sequence = 0;

			account_sequence(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce);
			account_sequence(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			bool is_owner_null() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			string as_index() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_index(const algorithm::pubkeyhash owner);
		};

		struct account_work final : ledger::multiform
		{
			algorithm::pubkeyhash owner = { 0 };
			uint8_t flags = 0;
			uint64_t penalty = 0;
			uint256_t gas_input = 0;
			uint256_t gas_output = 0;

			account_work(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce);
			account_work(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			bool is_eligible(const ledger::block_header* block_header) const;
			bool is_matching(account_flags flag) const;
			bool is_online() const;
			bool is_owner_null() const;
			uint256_t get_gas_use() const;
			uint64_t get_closest_proposal_block_number() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			int64_t as_factor() const override;
			string as_column() const override;
			string as_row() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash owner);
			static string as_instance_row();
			static uint256_t get_gas_work_required(const ledger::block_header* block_header, const uint256_t& gas_use);
			static uint256_t get_adjusted_gas_paid(const uint256_t& gas_use, const uint256_t& gas_paid);
			static uint256_t get_adjusted_gas_output(const uint256_t& gas_use, const uint256_t& gas_paid);
		};

		struct account_observer final : ledger::multiform
		{
			algorithm::asset_id asset = 0;
			algorithm::pubkeyhash owner = { 0 };
			bool observing = false;

			account_observer(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce);
			account_observer(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			bool is_owner_null() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			int64_t as_factor() const override;
			string as_column() const override;
			string as_row() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash owner);
			static string as_instance_row(const algorithm::asset_id& asset);
		};

		struct account_program final : ledger::uniform
		{
			algorithm::pubkeyhash owner = { 0 };
			string hashcode;

			account_program(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce);
			account_program(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			bool is_owner_null() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			string as_index() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_index(const algorithm::pubkeyhash owner);
		};

		struct account_storage final : ledger::uniform
		{
			algorithm::pubkeyhash owner = { 0 };
			string location;
			string storage;

			account_storage(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce);
			account_storage(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			bool is_owner_null() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			string as_index() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_index(const algorithm::pubkeyhash owner, const std::string_view& location);
		};

		struct account_reward final : ledger::multiform
		{
			algorithm::pubkeyhash owner = { 0 };
			algorithm::asset_id asset = 0;
			decimal incoming_absolute_fee = decimal::zero();
			decimal incoming_relative_fee = decimal::zero();
			decimal outgoing_absolute_fee = decimal::zero();
			decimal outgoing_relative_fee = decimal::zero();

			account_reward(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce);
			account_reward(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			bool has_incoming_fee() const;
			bool has_outgoing_fee() const;
			bool is_owner_null() const;
			decimal calculate_incoming_fee(const decimal& value) const;
			decimal calculate_outgoing_fee(const decimal& value) const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			int64_t as_factor() const override;
			string as_column() const override;
			string as_row() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash owner);
			static string as_instance_row(const algorithm::asset_id& asset);
		};

		struct account_derivation final : ledger::uniform
		{
			algorithm::pubkeyhash owner = { 0 };
			algorithm::asset_id asset = 0;
			uint64_t max_address_index = 0;

			account_derivation(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce);
			account_derivation(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			bool is_owner_null() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			string as_index() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_index(const algorithm::pubkeyhash owner, const algorithm::asset_id& asset);
		};

		struct account_balance final : ledger::multiform
		{
			algorithm::pubkeyhash owner = { 0 };
			algorithm::asset_id asset = 0;
			decimal supply = decimal::zero();
			decimal reserve = decimal::zero();

			account_balance(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce);
			account_balance(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			bool is_owner_null() const;
			decimal get_balance() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			int64_t as_factor() const override;
			string as_column() const override;
			string as_row() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash owner);
			static string as_instance_row(const algorithm::asset_id& asset);
		};

		struct account_depository final : ledger::multiform
		{
			algorithm::pubkeyhash owner = { 0 };
			algorithm::asset_id asset = 0;
			address_value_map contributions;
			account_value_map reservations;
			ordered_set<uint256_t> transactions;
			decimal custody = decimal::zero();

			account_depository(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce);
			account_depository(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			bool is_owner_null() const;
			decimal get_reservation() const;
			decimal get_contribution(const std::string_view& address) const;
			decimal get_contribution(const ordered_set<string>& addresses) const;
			decimal get_contribution() const;
			decimal get_coverage(uint8_t flags) const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			int64_t as_factor() const override;
			string as_column() const override;
			string as_row() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash owner);
			static string as_instance_row(const algorithm::asset_id& asset);
		};

		struct witness_program final : ledger::uniform
		{
			string hashcode;
			string storage;

			witness_program(uint64_t new_block_number, uint64_t new_block_nonce);
			witness_program(const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			string as_index() const override;
			expects_lr<string> as_code() const;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_index(const std::string_view& program_hashcode);
		};

		struct witness_event final : ledger::uniform
		{
			uint256_t parent_transaction_hash;
			uint256_t child_transaction_hash;

			witness_event(uint64_t new_block_number, uint64_t new_block_nonce);
			witness_event(const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			string as_index() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_index(const uint256_t& transaction_hash);
		};

		struct witness_address final : ledger::multiform
		{
			algorithm::pubkeyhash owner = { 0 };
			algorithm::pubkeyhash proposer = { 0 };
			algorithm::asset_id asset = 0;
			address_type purpose = address_type::witness;
			address_map addresses;
			uint64_t address_index = 0;

			witness_address(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce);
			witness_address(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			void set_proposer(const algorithm::pubkeyhash new_value);
			bool is_witness_address() const;
			bool is_router_address() const;
			bool is_custodian_address() const;
			bool is_contribution_address() const;
			bool is_owner_null() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			int64_t as_factor() const override;
			string as_column() const override;
			string as_row() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash owner);
			static string as_instance_row(const algorithm::asset_id& asset, const std::string_view& address, uint64_t address_index);
		};

		struct witness_transaction final : ledger::uniform
		{
			algorithm::asset_id asset = 0;
			string transaction_id;

			witness_transaction(uint64_t new_block_number, uint64_t new_block_nonce);
			witness_transaction(const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			string as_index() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_index(const algorithm::asset_id& asset, const std::string_view& transaction_id);
		};

		class resolver
		{
		public:
			static ledger::state* init(uint32_t hash);
			static ledger::state* copy(const ledger::state* base);
			static unordered_set<uint32_t> get_hashes();
		};
	}
}
#endif