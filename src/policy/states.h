#ifndef TAN_POLICY_STATES_H
#define TAN_POLICY_STATES_H
#include "../kernel/transaction.h"
#include <array>

namespace tangent
{
	namespace states
	{
		struct bridge_ref
		{
			algorithm::pubkeyhash_t owner;
			algorithm::asset_id asset;
			uint256_t hash;
		};

		struct account_nonce final : ledger::uniform_state
		{
			algorithm::pubkeyhash_t owner;
			uint64_t nonce = 0;

			account_nonce(const algorithm::pubkeyhash_t& new_owner, uint64_t new_block_number);
			account_nonce(const algorithm::pubkeyhash_t& new_owner, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const transition_state* prev_state) override;
			bool store_index(format::wo_stream* stream) const override;
			bool load_index(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_index(const algorithm::pubkeyhash_t& owner);
		};

		struct account_program final : ledger::uniform_state
		{
			algorithm::pubkeyhash_t owner;
			string hashcode;

			account_program(const algorithm::pubkeyhash_t& new_owner, uint64_t new_block_number);
			account_program(const algorithm::pubkeyhash_t& new_owner, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const transition_state* prev_state) override;
			bool store_index(format::wo_stream* stream) const override;
			bool load_index(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_index(const algorithm::pubkeyhash_t& owner);
		};

		struct account_uniform final : ledger::uniform_state
		{
			algorithm::pubkeyhash_t owner;
			string index;
			string data;

			account_uniform(const algorithm::pubkeyhash_t& new_owner, const std::string_view& new_index, uint64_t new_block_number);
			account_uniform(const algorithm::pubkeyhash_t& new_owner, const std::string_view& new_index, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const transition_state* prev_state) override;
			bool store_index(format::wo_stream* stream) const override;
			bool load_index(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_index(const algorithm::pubkeyhash_t& owner, const std::string_view& index);
		};

		struct account_multiform final : ledger::multiform_state
		{
			algorithm::pubkeyhash_t owner;
			string column;
			string row;
			string data;
			uint256_t filter;

			account_multiform(const algorithm::pubkeyhash_t& new_owner, const std::string_view& new_column, const std::string_view& new_row, uint64_t new_block_number);
			account_multiform(const algorithm::pubkeyhash_t& new_owner, const std::string_view& new_column, const std::string_view& new_row, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const transition_state* prev_state) override;
			bool store_column(format::wo_stream* stream) const override;
			bool load_column(format::ro_stream& stream) override;
			bool store_row(format::wo_stream* stream) const override;
			bool load_row(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t as_rank() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash_t& owner, const std::string_view& column);
			static string as_instance_row(const algorithm::pubkeyhash_t& owner, const std::string_view& row);
		};

		struct account_balance final : ledger::multiform_state
		{
			algorithm::pubkeyhash_t owner;
			algorithm::asset_id asset;
			decimal supply = decimal::zero();
			decimal reserve = decimal::zero();

			account_balance(const algorithm::pubkeyhash_t& new_owner, const algorithm::asset_id& new_asset, uint64_t new_block_number);
			account_balance(const algorithm::pubkeyhash_t& new_owner, const algorithm::asset_id& new_asset, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const transition_state* prev_state) override;
			bool store_column(format::wo_stream* stream) const override;
			bool load_column(format::ro_stream& stream) override;
			bool store_row(format::wo_stream* stream) const override;
			bool load_row(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			decimal get_balance() const;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t as_rank() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash_t& owner);
			static string as_instance_row(const algorithm::asset_id& asset);
		};

		struct validator_production final : ledger::multiform_state
		{
			algorithm::pubkeyhash_t owner;
			decimal stake = decimal::nan();

			validator_production(const algorithm::pubkeyhash_t& new_owner, uint64_t new_block_number);
			validator_production(const algorithm::pubkeyhash_t& new_owner, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const transition_state* prev_state) override;
			bool store_column(format::wo_stream* stream) const override;
			bool load_column(format::ro_stream& stream) override;
			bool store_row(format::wo_stream* stream) const override;
			bool load_row(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			bool is_active() const;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t as_rank() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash_t& owner);
			static string as_instance_row();
			static uint256_t to_rank(const decimal& threshold);
		};

		struct validator_production_reward final : ledger::multiform_state
		{
			algorithm::pubkeyhash_t owner;
			algorithm::asset_id asset;
			decimal reward = decimal::zero();

			validator_production_reward(const algorithm::pubkeyhash_t& new_owner, const algorithm::asset_id& new_asset, uint64_t new_block_number);
			validator_production_reward(const algorithm::pubkeyhash_t& new_owner, const algorithm::asset_id& new_asset, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const transition_state* prev_state) override;
			bool store_column(format::wo_stream* stream) const override;
			bool load_column(format::ro_stream& stream) override;
			bool store_row(format::wo_stream* stream) const override;
			bool load_row(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t as_rank() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash_t& owner);
			static string as_instance_row(const algorithm::asset_id& asset);
		};

		struct validator_participation final : ledger::multiform_state
		{
			algorithm::pubkeyhash_t owner;
			decimal stake = decimal::nan();

			validator_participation(const algorithm::pubkeyhash_t& new_owner, uint64_t new_block_number);
			validator_participation(const algorithm::pubkeyhash_t& new_owner, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const transition_state* prev_state) override;
			bool store_column(format::wo_stream* stream) const override;
			bool load_column(format::ro_stream& stream) override;
			bool store_row(format::wo_stream* stream) const override;
			bool load_row(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			bool is_active() const;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t as_rank() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash_t& owner);
			static string as_instance_row();
		};

		struct validator_participation_reward final : ledger::multiform_state
		{
			algorithm::pubkeyhash_t owner;
			algorithm::asset_id asset;
			decimal reward = decimal::zero();

			validator_participation_reward(const algorithm::pubkeyhash_t& new_owner, const algorithm::asset_id& new_asset, uint64_t new_block_number);
			validator_participation_reward(const algorithm::pubkeyhash_t& new_owner, const algorithm::asset_id& new_asset, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const transition_state* prev_state) override;
			bool store_column(format::wo_stream* stream) const override;
			bool load_column(format::ro_stream& stream) override;
			bool store_row(format::wo_stream* stream) const override;
			bool load_row(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t as_rank() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash_t& owner);
			static string as_instance_row(const algorithm::asset_id& asset);
		};

		struct validator_participation_ref final : ledger::multiform_state
		{
			algorithm::pubkeyhash_t owner;
			bridge_ref ref;
			bool active = false;

			validator_participation_ref(const algorithm::pubkeyhash_t& new_owner, const bridge_ref& new_ref, uint64_t new_block_number);
			validator_participation_ref(const algorithm::pubkeyhash_t& new_owner, const bridge_ref& new_ref, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const transition_state* prev_state) override;
			bool store_column(format::wo_stream* stream) const override;
			bool load_column(format::ro_stream& stream) override;
			bool store_row(format::wo_stream* stream) const override;
			bool load_row(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t as_rank() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash_t& owner);
			static string as_instance_row(const bridge_ref& ref);
		};

		struct validator_attestation final : ledger::multiform_state
		{
			algorithm::pubkeyhash_t owner;
			algorithm::asset_id asset;
			decimal stake = decimal::nan();
			decimal min_fee = decimal::zero();

			validator_attestation(const algorithm::pubkeyhash_t& new_owner, const algorithm::asset_id& new_asset, uint64_t new_block_number);
			validator_attestation(const algorithm::pubkeyhash_t& new_owner, const algorithm::asset_id& new_asset, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const transition_state* prev_state) override;
			bool store_column(format::wo_stream* stream) const override;
			bool load_column(format::ro_stream& stream) override;
			bool store_row(format::wo_stream* stream) const override;
			bool load_row(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			bool is_active() const;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t as_rank() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash_t& owner);
			static string as_instance_row(const algorithm::asset_id& asset);
		};

		struct validator_attestation_reward final : ledger::multiform_state
		{
			algorithm::pubkeyhash_t owner;
			algorithm::asset_id asset;
			decimal reward = decimal::zero();

			validator_attestation_reward(const algorithm::pubkeyhash_t& new_owner, const algorithm::asset_id& new_asset, uint64_t new_block_number);
			validator_attestation_reward(const algorithm::pubkeyhash_t& new_owner, const algorithm::asset_id& new_asset, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const transition_state* prev_state) override;
			bool store_column(format::wo_stream* stream) const override;
			bool load_column(format::ro_stream& stream) override;
			bool store_row(format::wo_stream* stream) const override;
			bool load_row(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t as_rank() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash_t& owner);
			static string as_instance_row(const algorithm::asset_id& asset);
		};

		struct bridge_instance final : ledger::multiform_state
		{
			bridge_ref ref;
			decimal fee_rate = decimal::zero();
			uint256_t transaction_hash = 0;
			uint64_t transaction_nonce = 0;
			uint64_t account_nonce = 0;
			uint8_t security_level = (uint8_t)kernel::params().policy.participation.min_per_account;

			bridge_instance(const bridge_ref& new_ref, uint64_t new_block_number);
			bridge_instance(const bridge_ref& new_ref, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const transition_state* prev_state) override;
			bool store_column(format::wo_stream* stream) const override;
			bool load_column(format::ro_stream& stream) override;
			bool store_row(format::wo_stream* stream) const override;
			bool load_row(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			bool is_permanent() const override;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t as_rank() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::asset_id& asset);
			static string as_instance_row(const uint256_t& bridge_hash);
		};

		struct bridge_queue final : ledger::multiform_state
		{
			algorithm::asset_id asset;
			uint256_t bridge_hash;
			uint256_t transaction_hash;
			uint64_t index = 0;

			bridge_queue(const algorithm::asset_id& new_asset, const uint256_t& new_bridge_hash, const uint256_t& new_transaction_hash, uint64_t new_block_number);
			bridge_queue(const algorithm::asset_id& new_asset, const uint256_t& new_bridge_hash, const uint256_t& new_transaction_hash, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const transition_state* prev_state) override;
			bool store_column(format::wo_stream* stream) const override;
			bool load_column(format::ro_stream& stream) override;
			bool store_row(format::wo_stream* stream) const override;
			bool load_row(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t as_rank() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::asset_id& asset, const uint256_t& bridge_hash);
			static string as_instance_row(const uint256_t& transaction_hash);
		};

		struct bridge_balance final : ledger::multiform_state
		{
			algorithm::asset_id asset;
			uint256_t bridge_hash;
			decimal supply = decimal::zero();

			bridge_balance(const algorithm::asset_id& new_asset, const uint256_t& new_bridge_hash, uint64_t new_block_number);
			bridge_balance(const algorithm::asset_id& new_asset, const uint256_t& new_bridge_hash, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const transition_state* prev_state) override;
			bool store_column(format::wo_stream* stream) const override;
			bool load_column(format::ro_stream& stream) override;
			bool store_row(format::wo_stream* stream) const override;
			bool load_row(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t as_rank() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::asset_id& asset);
			static string as_instance_row(const uint256_t& bridge_hash);
		};

		struct bridge_account final : ledger::multiform_state
		{
			btree_set<algorithm::pubkeyhash_t> group;
			algorithm::composition::cpubkey_t public_key;
			bridge_ref ref;

			bridge_account(const bridge_ref& new_ref, uint64_t new_block_number);
			bridge_account(const bridge_ref& new_ref, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const transition_state* prev_state) override;
			bool store_column(format::wo_stream* stream) const override;
			bool load_column(format::ro_stream& stream) override;
			bool store_row(format::wo_stream* stream) const override;
			bool load_row(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			void set_group(const algorithm::composition::cpubkey_t& new_public_key, btree_set<algorithm::pubkeyhash_t>&& new_group);
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t as_rank() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner);
			static string as_instance_row(const uint256_t& bridge_hash);
		};

		struct witness_program final : ledger::uniform_state
		{
			string hashcode;
			string storage;

			witness_program(const std::string_view& new_hashcode, uint64_t new_block_number);
			witness_program(const std::string_view& new_hashcode, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const transition_state* prev_state) override;
			bool store_index(format::wo_stream* stream) const override;
			bool load_index(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			expects_lr<string> as_code() const;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_index(const std::string_view& program_hashcode);
			static string as_instance_packed_hashcode(const std::string_view& storage);
			static string as_instance_unpacked_hashcode(const std::string_view& storage);
		};

		struct witness_event final : ledger::uniform_state
		{
			uint256_t parent_transaction_hash;
			uint256_t child_transaction_hash;

			witness_event(const uint256_t& new_parent_transaction_hash, uint64_t new_block_number);
			witness_event(const uint256_t& new_parent_transaction_hash, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const transition_state* prev_state) override;
			bool store_index(format::wo_stream* stream) const override;
			bool load_index(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_index(const uint256_t& transaction_hash);
		};

		struct witness_account final : ledger::multiform_state
		{
			enum class account_type : uint8_t
			{
				witness = 0,
				routing,
				bridge
			};

			address_map addresses;
			bridge_ref ref;
			bool active = true;

			witness_account(const bridge_ref& new_ref, const address_map& new_addresses, uint64_t new_block_number);
			witness_account(const bridge_ref& new_ref, const address_map& new_addresses, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const transition_state* prev_state) override;
			bool store_column(format::wo_stream* stream) const override;
			bool load_column(format::ro_stream& stream) override;
			bool store_row(format::wo_stream* stream) const override;
			bool load_row(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			bool is_witness_account() const;
			bool is_routing_account() const;
			bool is_bridge_account() const;
			bool is_permanent() const override;
			account_type get_type() const;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t as_rank() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_column(const algorithm::pubkeyhash_t& owner);
			static string as_instance_row(const algorithm::asset_id& asset, const std::string_view& address);
		};

		struct witness_transaction final : ledger::uniform_state
		{
			algorithm::asset_id asset;
			string transaction_id;

			witness_transaction(const algorithm::asset_id& new_asset, const std::string_view& new_transaction_id, uint64_t new_block_number);
			witness_transaction(const algorithm::asset_id& new_asset, const std::string_view& new_transaction_id, const ledger::block_header* new_block_header);
			expects_lr<void> transition(const transition_state* prev_state) override;
			bool store_index(format::wo_stream* stream) const override;
			bool load_index(format::ro_stream& stream) override;
			bool store_data(format::wo_stream* stream) const override;
			bool load_data(format::ro_stream& stream) override;
			bool is_permanent() const override;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string as_instance_index(const algorithm::asset_id& asset, const std::string_view& transaction_id);
		};

		class resolver
		{
		public:
			typedef std::array<uint32_t, 6> uniform_type_map;
			typedef std::array<uint32_t, 14> multiform_type_map;

		public:
			static ledger::transition_state* from_stream(format::ro_stream& stream);
			static ledger::transition_state* from_type(uint32_t hash);
			static ledger::transition_state* from_copy(const ledger::transition_state* base);
			static void value_copy(uint32_t hash, const ledger::transition_state* from, ledger::transition_state* to);
			static bool will_delete(const ledger::transition_state* base, uptr<ledger::transition_state>& cache);
			static uniform_type_map& get_uniform_types();
			static multiform_type_map& get_multiform_types();
		};
	}
}
#endif