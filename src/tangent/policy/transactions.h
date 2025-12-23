#ifndef TAN_POLICY_TRANSACTIONS_H
#define TAN_POLICY_TRANSACTIONS_H
#include "states.h"
#include "../kernel/superchain.h"

namespace tangent
{
	namespace ledger
	{
		struct block_transaction;
	}

	namespace transactions
	{
		struct transfer final : ledger::transaction
		{
			vector<std::pair<algorithm::pubkeyhash_t, decimal>> to;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::executor_context* executor) const override;
			bool store_body(format::wo_stream* stream) const override;
			bool load_body(format::ro_stream& stream) override;
			bool recover_many(const ledger::executor_context* executor, const ledger::receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const override;
			void set_to(const algorithm::pubkeyhash_t& new_to, const decimal& new_value);
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct deploy final : ledger::transaction
		{
			enum class data_type : uint8_t
			{
				program = 0x33,
				hashcode = 0x66
			};
			format::variables args;
			string data;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::executor_context* executor) const override;
			bool store_body(format::wo_stream* stream) const override;
			bool load_body(format::ro_stream& stream) override;
			bool recover_many(const ledger::executor_context* executor, const ledger::receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const override;
			void from_program(const std::string_view& new_data, format::variables&& new_args);
			void from_hashcode(const std::string_view& new_data, format::variables&& new_args);
			algorithm::pubkeyhash_t get_account() const;
			option<data_type> get_data_type() const;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct call final : ledger::transaction
		{
			algorithm::pubkeyhash_t callable;
			format::variables args;
			string function;
			decimal value;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::executor_context* executor) const override;
			expects_lr<void> subexecute(ledger::executor_context* executor, std::function<expects_lr<void>(void*)>&& callback) const;
			bool store_body(format::wo_stream* stream) const override;
			bool load_body(format::ro_stream& stream) override;
			bool recover_many(const ledger::executor_context* executor, const ledger::receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const override;
			void program_call(const algorithm::pubkeyhash_t& new_callable, const decimal& new_value, const std::string_view& new_function, format::variables&& new_args);
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct rollup final : ledger::transaction
		{
			btree_map<algorithm::asset_id, vector<uptr<ledger::transaction>>> transactions;

			rollup() = default;
			rollup(const rollup& other);
			rollup(rollup&&) noexcept = default;
			rollup& operator= (const rollup& other);
			rollup& operator= (rollup&&) noexcept = default;
			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::executor_context* executor) const override;
			expects_promise_rt<void> dispatch(const ledger::executor_context* executor, ledger::dispatcher_context* dispatcher) const override;
			bool store_body(format::wo_stream* stream) const override;
			bool load_body(format::ro_stream& stream) override;
			bool recover_many(const ledger::executor_context* executor, const ledger::receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const override;
			bool recover_aliases(btree_set<uint256_t>& aliases) const override;
			bool import_transaction(const ledger::transaction& transaction);
			bool import_internal_transaction(ledger::transaction& transaction, const algorithm::seckey_t& secret_key);
			bool import_external_transaction(ledger::transaction& transaction, const algorithm::seckey_t& secret_key, uint64_t nonce);
			bool is_dispatchable() const override;
			expects_lr<ledger::block_transaction> resolve_block_transaction(const ledger::receipt& receipt, const uint256_t& transaction_hash) const;
			const ledger::transaction* resolve_transaction(const uint256_t& transaction_hash) const;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static void normalize_transaction(ledger::transaction& transaction, const algorithm::asset_id& asset);
		};

		struct setup final : ledger::transaction
		{
			struct migration_ref
			{
				states::bridge_account account = states::bridge_account(algorithm::pubkeyhash_t(), 0, algorithm::pubkeyhash_t(), nullptr);
				algorithm::pubkeyhash_t old_participant;
				bool must_have_locally;
			};

			struct attestation_setup
			{
				option<bool> accepts_account_requests = optional::none;
				option<bool> accepts_withdrawal_requests = optional::none;
				option<uint8_t> security_level = optional::none;
				option<decimal> incoming_fee = optional::none;
				option<decimal> outgoing_fee = optional::none;
				option<decimal> participation_threshold = optional::none;
				decimal stake = decimal::nan();
			};

			btree_map<uint256_t, algorithm::pubkeyhash_t> migrations;
			btree_map<algorithm::asset_id, attestation_setup> attestations;
			option<decimal> participation = optional::none;
			option<decimal> production = optional::none;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::executor_context* executor) const override;
			expects_promise_rt<void> dispatch(const ledger::executor_context* executor, ledger::dispatcher_context* dispatcher) const override;
			bool store_body(format::wo_stream* stream) const override;
			bool load_body(format::ro_stream& stream) override;
			bool recover_many(const ledger::executor_context* executor, const ledger::receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const override;
			void allocate_production_stake(const decimal& value);
			void disable_production();
			void standby_on_production();
			void allocate_participation_stake(const decimal& value);
			void disable_participation();
			void standby_on_participation();
			void allocate_attestation_stake(const algorithm::asset_id& asset, const decimal& value);
			void configure_attestation_security(const algorithm::asset_id& asset, uint8_t new_security_level, const decimal& new_participation_threshold, bool new_accepts_account_requests, bool new_accepts_withdrawal_requests);
			void configure_attestation_reward(const algorithm::asset_id& asset, const decimal& new_incoming_fee, const decimal& new_outgoing_fee);
			void disable_attestation(const algorithm::asset_id& asset);
			void standby_on_attestation(const algorithm::asset_id& asset);
			void migrate_participant(const uint256_t& broadcast_hash, const algorithm::pubkeyhash_t& participant);
			void clear_migration(const uint256_t& broadcast_hash);
			bool is_dispatchable() const override;
			expects_lr<vector<migration_ref>> get_migration_refs(const ledger::executor_context* executor, const ledger::receipt& receipt) const;
			algorithm::pubkeyhash_t get_new_participant(const ledger::receipt& receipt, bool* requires_new_participant = nullptr) const;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct migrate final : ledger::commitment
		{
			uint256_t setup_hash = 0;
			algorithm::hashsig_t proof;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::executor_context* executor) const override;
			bool store_body(format::wo_stream* stream) const override;
			bool load_body(format::ro_stream& stream) override;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct attestate final : ledger::commitment
		{
			struct bridge_transfer
			{
				decimal input_supply = decimal::zero();
				decimal output_supply = decimal::zero();
				decimal incoming_fee = decimal::zero();
				decimal outgoing_fee = decimal::zero();
			};

			struct route_transfer
			{
				decimal input_supply = decimal::zero();
				decimal input_reserve = decimal::zero();
				decimal output_supply = decimal::zero();
				decimal output_reserve = decimal::zero();
			};

			struct bridge_transfer_batch
			{
				btree_set<algorithm::pubkeyhash_t> participants;
				btree_map<algorithm::asset_id, bridge_transfer> transfers;
			};

			btree_map<uint256_t, btree_set<algorithm::hashsig_t>> commitments;
			superchain::computed_transaction proof;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::executor_context* executor) const override;
			bool store_body(format::wo_stream* stream) const override;
			bool load_body(format::ro_stream& stream) override;
			bool recover_many(const ledger::executor_context* executor, const ledger::receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const override;
			void set_finalized_proof(uint64_t block_id, const std::string_view& transaction_id, const vector<superchain::value_transfer>& inputs, const vector<superchain::value_transfer>& outputs);
			void set_computed_proof(superchain::computed_transaction&& new_proof, btree_map<uint256_t, btree_set<algorithm::hashsig_t>>&& new_commitments);
			bool add_commitment(const algorithm::seckey_t& secret_key);
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static expects_lr<void> verify_proof_commitment(ledger::executor_context* executor, const algorithm::asset_id& asset, const btree_map<uint256_t, btree_set<algorithm::hashsig_t>>& commitments, uint256_t& best_commitment_hash, btree_map<uint256_t, btree_set<algorithm::pubkeyhash_t>>& attesters);
			static void strip_commitments(const ledger::executor_context* executor, const algorithm::asset_id& asset, btree_map<uint256_t, btree_set<algorithm::hashsig_t>>& commitments);
			static bool commit_to_proof(const superchain::computed_transaction& new_proof, const algorithm::seckey_t& secret_key, uint256_t& commitment_hash, algorithm::hashsig_t& commitment_signature);
		};

		struct route final : ledger::commitment
		{
			algorithm::pubkeyhash_t manager;
			string routing_address;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::executor_context* executor) const override;
			expects_promise_rt<void> dispatch(const ledger::executor_context* executor, ledger::dispatcher_context* dispatcher) const override;
			bool store_body(format::wo_stream* stream) const override;
			bool load_body(format::ro_stream& stream) override;
			bool recover_many(const ledger::executor_context* executor, const ledger::receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const override;
			bool is_dispatchable() const override;
			void set_routing_address(const std::string_view& new_address);
			void set_manager(const algorithm::pubkeyhash_t& new_manager);
			btree_set<algorithm::pubkeyhash_t> get_group(const ledger::receipt& receipt) const;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static void challenge(const uint256_t& route_hash, uint8_t message_hash[32]);
		};

		struct bind final : ledger::commitment
		{
			algorithm::composition::cpubkey_t group_public_key;
			algorithm::composition::chashsig_t group_signature;
			uint256_t route_hash = 0;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::executor_context* executor) const override;
			void set_witness(const uint256_t& new_route_hash, algorithm::composition::cpubkey_t&& new_group_public_key, algorithm::composition::chashsig_t&& new_group_signature);
			bool store_body(format::wo_stream* stream) const override;
			bool load_body(format::ro_stream& stream) override;
			bool recover_many(const ledger::executor_context* executor, const ledger::receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const override;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct withdraw final : ledger::transaction
		{
			algorithm::pubkeyhash_t manager;
			string to_address;
			decimal to_value = decimal::nan();
			bool only_if_not_in_queue = true;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::executor_context* executor) const override;
			expects_promise_rt<void> dispatch(const ledger::executor_context* executor, ledger::dispatcher_context* dispatcher) const override;
			bool store_body(format::wo_stream* stream) const override;
			bool load_body(format::ro_stream& stream) override;
			bool recover_many(const ledger::executor_context* executor, const ledger::receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const override;
			void set_to(const std::string_view& address, const decimal& value);
			void set_manager(const algorithm::pubkeyhash_t& new_manager);
			bool is_dispatchable() const override;
			algorithm::pubkeyhash_t get_new_manager(const ledger::receipt& receipt) const;
			decimal get_token_value(const ledger::executor_context* executor, const ledger::receipt& receipt) const;
			decimal get_fee_value(const ledger::executor_context* executor) const;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static expects_lr<states::witness_account> find_receiving_account(const ledger::executor_context* executor, const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& from_manager, const algorithm::pubkeyhash_t& to_manager);
		};

		struct broadcast final : ledger::commitment
		{
			uint256_t withdraw_hash = 0;
			expects_lr<superchain::finalized_transaction> proof = layer_exception();

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::executor_context* executor) const override;
			bool store_body(format::wo_stream* stream) const override;
			bool load_body(format::ro_stream& stream) override;
			bool recover_many(const ledger::executor_context* executor, const ledger::receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const override;
			void set_proof(const uint256_t& new_withdraw_hash, expects_lr<superchain::finalized_transaction>&& new_proof);
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static expects_lr<void> validate_possible_proof(const ledger::executor_context* executor, const withdraw* transaction, const ledger::receipt& receipt, const superchain::prepared_transaction& prepared);
			static expects_lr<void> validate_finalized_proof(const ledger::executor_context* executor, const withdraw* transaction, const ledger::receipt& receipt, const superchain::finalized_transaction& finalized);
		};

		class resolver
		{
		public:
			static ledger::transaction* from_stream(format::ro_stream& stream);
			static ledger::transaction* from_type(uint32_t hash);
			static ledger::transaction* from_copy(const ledger::transaction* base);
			static expects_promise_rt<superchain::prepared_transaction> prepare_transaction(const algorithm::asset_id& asset, const superchain::wallet_link& from_link, const superchain::value_transfer& to, const decimal& max_fee);
			static expects_lr<superchain::finalized_transaction> finalize_transaction(const algorithm::asset_id& asset, superchain::prepared_transaction&& prepared);
			static expects_promise_rt<void> broadcast_transaction(const algorithm::asset_id& asset, const uint256_t& external_id, superchain::finalized_transaction&& finalized, ledger::dispatcher_context* dispatcher, const ledger::wallet* runner_wallet);
		};
	}
}
#endif