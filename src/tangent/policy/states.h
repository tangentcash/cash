#ifndef TAN_POLICY_STATES_H
#define TAN_POLICY_STATES_H
#include "../kernel/transaction.h"

namespace tangent
{
	namespace states
	{
		struct account_nonce final : ledger::uniform
		{
			algorithm::pubkeyhash owner = { 0 };
			uint64_t nonce = 0;

			account_nonce(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce);
			account_nonce(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header);
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

		struct account_delegation final : ledger::uniform
		{
			algorithm::pubkeyhash owner = { 0 };
			uint32_t delegations = 0;

			account_delegation(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce);
			account_delegation(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			bool is_owner_null() const;
			uint64_t get_delegation_zeroing_block(uint64_t current_block_number) const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			string as_index() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_index(const algorithm::pubkeyhash owner);
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

		struct validator_production final : ledger::multiform
		{
			algorithm::pubkeyhash owner = { 0 };
			uint256_t gas = 0;
			bool active = false;

			validator_production(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce);
			validator_production(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			bool is_eligible(const ledger::block_header* block_header) const;
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
			static string as_instance_row();
			static uint256_t get_gas_required(const ledger::block_header* block_header, const uint256_t& gas_use);
		};

		struct validator_participation final : ledger::multiform
		{
			algorithm::asset_id asset = 0;
			algorithm::pubkeyhash owner = { 0 };
			decimal stake = decimal::nan();
			uint64_t participations = 0;

			validator_participation(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce);
			validator_participation(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			bool is_owner_null() const;
			bool is_active() const;
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

		struct validator_attestation final : ledger::multiform
		{
			algorithm::asset_id asset = 0;
			algorithm::pubkeyhash owner = { 0 };
			decimal stake = decimal::nan();

			validator_attestation(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce);
			validator_attestation(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			bool is_owner_null() const;
			bool is_active() const;
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

		struct depository_reward final : ledger::multiform
		{
			algorithm::pubkeyhash owner = { 0 };
			algorithm::asset_id asset = 0;
			decimal incoming_fee = decimal::zero();
			decimal outgoing_fee = decimal::zero();

			depository_reward(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce);
			depository_reward(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header);
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

		struct depository_balance final : ledger::multiform
		{
			algorithm::pubkeyhash owner = { 0 };
			algorithm::asset_id asset = 0;
			decimal supply = decimal::zero();

			depository_balance(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce);
			depository_balance(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header);
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

		struct depository_policy final : ledger::multiform
		{
			algorithm::pubkeyhash owner = { 0 };
			algorithm::asset_id asset = 0;
			uint256_t queue_transaction_hash = 0;
			uint64_t accounts_under_management = 0;
			uint8_t security_level = (uint8_t)protocol::now().policy.participation_std_per_account;
			bool accepts_account_requests = false;
			bool accepts_withdrawal_requests = false;

			depository_policy(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce);
			depository_policy(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header);
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

		struct depository_account final : ledger::multiform
		{
			ordered_set<algorithm::pubkeyhash_t> group;
			algorithm::composition::cpubkey public_key = { 0 };
			algorithm::pubkeyhash owner = { 0 };
			algorithm::pubkeyhash manager = { 0 };
			algorithm::asset_id asset = 0;

			depository_account(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce);
			depository_account(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			void set_group(const algorithm::pubkeyhash new_manager, const algorithm::composition::cpubkey new_public_key, ordered_set<algorithm::pubkeyhash_t>&& new_group);
			bool is_owner_null() const;
			bool is_manager_null() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			int64_t as_factor() const override;
			string as_column() const override;
			string as_row() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash manager);
			static string as_instance_row(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner);
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

		struct witness_account final : ledger::multiform
		{
			enum class account_type : uint8_t
			{
				witness = 0,
				routing,
				depository
			};

			algorithm::pubkeyhash owner = { 0 };
			algorithm::pubkeyhash manager = { 0 };
			algorithm::asset_id asset = 0;
			address_map addresses;
			bool active = true;

			witness_account(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce);
			witness_account(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			bool is_witness_account() const;
			bool is_routing_account() const;
			bool is_depository_account() const;
			bool is_owner_null() const;
			bool is_manager_null() const;
			account_type get_type() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			int64_t as_factor() const override;
			string as_column() const override;
			string as_row() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash owner);
			static string as_instance_row(const algorithm::asset_id& asset, const std::string_view& address);
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
			static ledger::state* from_stream(format::stream& stream);
			static ledger::state* from_type(uint32_t hash);
			static ledger::state* from_copy(const ledger::state* base);
			static unordered_set<uint32_t> get_uniform_types();
			static unordered_set<uint32_t> get_multiform_types();
		};
	}
}
#endif