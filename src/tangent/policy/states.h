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
			bool store_index(format::wo_stream* stream) const override;
			bool load_index(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			bool is_owner_null() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
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
			bool store_index(format::wo_stream* stream) const override;
			bool load_index(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			bool is_owner_null() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_index(const algorithm::pubkeyhash owner);
		};

		struct account_uniform final : ledger::uniform
		{
			algorithm::pubkeyhash owner = { 0 };
			string index;
			string data;

			account_uniform(const algorithm::pubkeyhash new_owner, const std::string_view& new_index, uint64_t new_block_number, uint64_t new_block_nonce);
			account_uniform(const algorithm::pubkeyhash new_owner, const std::string_view& new_index, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_index(format::wo_stream* stream) const override;
			bool load_index(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			bool is_owner_null() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_index(const algorithm::pubkeyhash owner, const std::string_view& index);
		};

		struct account_multiform final : ledger::multiform
		{
			algorithm::pubkeyhash owner = { 0 };
			uint256_t filter;
			string column;
			string row;
			string data;

			account_multiform(const algorithm::pubkeyhash new_owner, const std::string_view& new_column, const std::string_view& new_row, uint64_t new_block_number, uint64_t new_block_nonce);
			account_multiform(const algorithm::pubkeyhash new_owner, const std::string_view& new_column, const std::string_view& new_row, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_column(format::wo_stream* stream) const override;
			bool load_column(format::ro_stream& stream) override;
			bool store_row(format::wo_stream* stream) const override;
			bool load_row(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			bool is_owner_null() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t as_rank() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash owner, const std::string_view& column);
			static string as_instance_row(const algorithm::pubkeyhash owner, const std::string_view& row);
		};

		struct account_delegation final : ledger::uniform
		{
			algorithm::pubkeyhash owner = { 0 };
			uint32_t delegations = 0;

			account_delegation(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce);
			account_delegation(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_index(format::wo_stream* stream) const override;
			bool load_index(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			bool is_owner_null() const;
			uint64_t get_delegation_zeroing_block(uint64_t current_block_number) const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_index(const algorithm::pubkeyhash owner);
		};

		struct account_balance final : ledger::multiform
		{
			algorithm::pubkeyhash owner = { 0 };
			algorithm::asset_id asset;
			decimal supply = decimal::zero();
			decimal reserve = decimal::zero();

			account_balance(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, uint64_t new_block_number, uint64_t new_block_nonce);
			account_balance(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_column(format::wo_stream* stream) const override;
			bool load_column(format::ro_stream& stream) override;
			bool store_row(format::wo_stream* stream) const override;
			bool load_row(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			bool is_owner_null() const;
			decimal get_balance() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t as_rank() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash owner);
			static string as_instance_row(const algorithm::asset_id& asset);
		};

		struct validator_production final : ledger::multiform
		{
			algorithm::pubkeyhash owner = { 0 };
			ordered_map<algorithm::asset_id, decimal> stakes;
			uint256_t gas = 0;
			bool active = false;

			validator_production(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce);
			validator_production(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_column(format::wo_stream* stream) const override;
			bool load_column(format::ro_stream& stream) override;
			bool store_row(format::wo_stream* stream) const override;
			bool load_row(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			bool is_owner_null() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t as_rank() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash owner);
			static string as_instance_row();
		};

		struct validator_participation final : ledger::multiform
		{
			algorithm::asset_id asset;
			algorithm::pubkeyhash owner = { 0 };
			decimal stake = decimal::nan();
			uint64_t participations = 0;

			validator_participation(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, uint64_t new_block_number, uint64_t new_block_nonce);
			validator_participation(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_column(format::wo_stream* stream) const override;
			bool load_column(format::ro_stream& stream) override;
			bool store_row(format::wo_stream* stream) const override;
			bool load_row(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			bool is_owner_null() const;
			bool is_active() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t as_rank() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash owner);
			static string as_instance_row(const algorithm::asset_id& asset);
		};

		struct validator_attestation final : ledger::multiform
		{
			algorithm::asset_id asset;
			algorithm::pubkeyhash owner = { 0 };
			decimal stake = decimal::nan();

			validator_attestation(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, uint64_t new_block_number, uint64_t new_block_nonce);
			validator_attestation(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_column(format::wo_stream* stream) const override;
			bool load_column(format::ro_stream& stream) override;
			bool store_row(format::wo_stream* stream) const override;
			bool load_row(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			bool is_owner_null() const;
			bool is_active() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t as_rank() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash owner);
			static string as_instance_row(const algorithm::asset_id& asset);
		};

		struct depository_reward final : ledger::multiform
		{
			algorithm::pubkeyhash owner = { 0 };
			algorithm::asset_id asset;
			decimal incoming_fee = decimal::zero();
			decimal outgoing_fee = decimal::zero();

			depository_reward(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, uint64_t new_block_number, uint64_t new_block_nonce);
			depository_reward(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_column(format::wo_stream* stream) const override;
			bool load_column(format::ro_stream& stream) override;
			bool store_row(format::wo_stream* stream) const override;
			bool load_row(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			bool is_owner_null() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t as_rank() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash owner);
			static string as_instance_row(const algorithm::asset_id& asset);
		};

		struct depository_balance final : ledger::multiform
		{
			algorithm::pubkeyhash owner = { 0 };
			algorithm::asset_id asset;
			decimal supply = decimal::zero();

			depository_balance(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, uint64_t new_block_number, uint64_t new_block_nonce);
			depository_balance(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_column(format::wo_stream* stream) const override;
			bool load_column(format::ro_stream& stream) override;
			bool store_row(format::wo_stream* stream) const override;
			bool load_row(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			bool is_owner_null() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t as_rank() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash owner);
			static string as_instance_row(const algorithm::asset_id& asset);
		};

		struct depository_policy final : ledger::multiform
		{
			algorithm::pubkeyhash owner = { 0 };
			algorithm::asset_id asset;
			uint256_t queue_transaction_hash = 0;
			uint64_t accounts_under_management = 0;
			uint8_t security_level = (uint8_t)protocol::now().policy.participation_std_per_account;
			bool accepts_account_requests = false;
			bool accepts_withdrawal_requests = false;

			depository_policy(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, uint64_t new_block_number, uint64_t new_block_nonce);
			depository_policy(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_column(format::wo_stream* stream) const override;
			bool load_column(format::ro_stream& stream) override;
			bool store_row(format::wo_stream* stream) const override;
			bool load_row(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			bool is_owner_null() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t as_rank() const override;
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
			algorithm::asset_id asset;

			depository_account(const algorithm::pubkeyhash new_manager, const algorithm::asset_id& new_asset, const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce);
			depository_account(const algorithm::pubkeyhash new_manager, const algorithm::asset_id& new_asset, const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_column(format::wo_stream* stream) const override;
			bool load_column(format::ro_stream& stream) override;
			bool store_row(format::wo_stream* stream) const override;
			bool load_row(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			void set_group(const algorithm::composition::cpubkey new_public_key, ordered_set<algorithm::pubkeyhash_t>&& new_group);
			bool is_owner_null() const;
			bool is_manager_null() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t as_rank() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash manager);
			static string as_instance_row(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner);
		};

		struct witness_program final : ledger::uniform
		{
			string hashcode;
			string storage;

			witness_program(const std::string_view& new_hashcode, uint64_t new_block_number, uint64_t new_block_nonce);
			witness_program(const std::string_view& new_hashcode, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_index(format::wo_stream* stream) const override;
			bool load_index(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			expects_lr<string> as_code() const;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_index(const std::string_view& program_hashcode);
			static string as_instance_packed_hashcode(const std::string_view& storage);
			static string as_instance_unpacked_hashcode(const std::string_view& storage);
		};

		struct witness_event final : ledger::uniform
		{
			uint256_t parent_transaction_hash;
			uint256_t child_transaction_hash;

			witness_event(const uint256_t& new_parent_transaction_hash, uint64_t new_block_number, uint64_t new_block_nonce);
			witness_event(const uint256_t& new_parent_transaction_hash, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_index(format::wo_stream* stream) const override;
			bool load_index(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
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
			algorithm::asset_id asset;
			address_map addresses;
			bool active = true;

			witness_account(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, const address_map& new_addresses, uint64_t new_block_number, uint64_t new_block_nonce);
			witness_account(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, const address_map& new_addresses, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_column(format::wo_stream* stream) const override;
			bool load_column(format::ro_stream& stream) override;
			bool store_row(format::wo_stream* stream) const override;
			bool load_row(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			bool is_witness_account() const;
			bool is_routing_account() const;
			bool is_depository_account() const;
			bool is_owner_null() const;
			bool is_manager_null() const;
			bool is_permanent() const override;
			account_type get_type() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t as_rank() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash owner);
			static string as_instance_row(const algorithm::asset_id& asset, const std::string_view& address);
		};

		struct witness_transaction final : ledger::uniform
		{
			algorithm::asset_id asset;
			string transaction_id;

			witness_transaction(const algorithm::asset_id& new_asset, const std::string_view& new_transaction_id, uint64_t new_block_number, uint64_t new_block_nonce);
			witness_transaction(const algorithm::asset_id& new_asset, const std::string_view& new_transaction_id, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const ledger::transaction_context* context, const ledger::state* prev_state) override;
			bool store_index(format::wo_stream* stream) const override;
			bool load_index(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			bool is_permanent() const override;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_index(const algorithm::asset_id& asset, const std::string_view& transaction_id);
		};

		class resolver
		{
		public:
			static ledger::state* from_stream(format::ro_stream& stream);
			static ledger::state* from_type(uint32_t hash);
			static ledger::state* from_copy(const ledger::state* base);
			static void value_copy(uint32_t hash, const ledger::state* from, ledger::state* to);
			static bool will_delete(const ledger::state* base, uptr<ledger::state>& cache);
			static std::array<uint32_t, 7> get_uniform_types();
			static std::array<uint32_t, 10> get_multiform_types();
		};
	}
}
#endif