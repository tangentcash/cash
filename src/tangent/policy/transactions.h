#ifndef TAN_POLICY_TRANSACTIONS_H
#define TAN_POLICY_TRANSACTIONS_H
#include "states.h"
#include "../kernel/mediator.h"

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
			struct batch
			{
				algorithm::pubkeyhash to = { 0 };
				decimal value;
				string memo;
			};

			vector<batch> transfers;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const override;
			void set_to(const algorithm::pubkeyhash new_to, const decimal& new_value, const std::string_view& new_memo = std::string_view());
			bool is_to_null() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct deployment final : ledger::transaction
		{
			enum class calldata_type : uint8_t
			{
				program = 0x33,
				hashcode = 0x66
			};
			algorithm::recpubsig location = { 0 };
			format::variables args;
			string calldata;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const override;
			bool sign_location(const algorithm::seckey secret_key);
			bool verify_location(const algorithm::pubkey public_key) const;
			bool recover_location(algorithm::pubkeyhash public_key_hash) const;
			bool is_location_null() const;
			void set_location(const algorithm::recpubsig new_value);
			void set_program_calldata(const std::string_view& new_calldata, format::variables&& new_args);
			void set_hashcode_calldata(const std::string_view& new_calldata, format::variables&& new_args);
			option<calldata_type> get_calldata_type() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct invocation final : ledger::transaction
		{
			algorithm::pubkeyhash to = { 0 };
			format::variables args;
			string function;
			uint32_t hashcode = 0;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const override;
			void set_calldata(const algorithm::pubkeyhash new_to, const std::string_view& new_function, format::variables&& new_args);
			void set_calldata(const algorithm::pubkeyhash new_to, uint32_t new_hashcode, const std::string_view& new_function, format::variables&& new_args);
			bool is_to_null() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct rollup final : ledger::transaction
		{
			ordered_map<algorithm::asset_id, vector<uptr<ledger::transaction>>> transactions;

			rollup() = default;
			rollup(const rollup& other);
			rollup(rollup&&) noexcept = default;
			rollup& operator= (const rollup& other);
			rollup& operator= (rollup&&) noexcept = default;
			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			expects_promise_rt<void> dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const override;
			bool recover_aliases(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<uint256_t>& aliases) const override;
			bool merge(const ledger::transaction& transaction);
			bool merge(ledger::transaction& transaction, const algorithm::seckey secret_key);
			bool merge(ledger::transaction& transaction, const algorithm::seckey secret_key, uint64_t sequence);
			bool is_dispatchable() const override;
			expects_lr<ledger::block_transaction> resolve_block_transaction(const ledger::receipt& receipt, const uint256_t& transaction_hash) const;
			const ledger::transaction* resolve_transaction(const uint256_t& transaction_hash) const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static void setup_child(ledger::transaction& transaction, const algorithm::asset_id& asset);
			static bool sign_child(ledger::transaction& transaction, const algorithm::seckey secret_key, const algorithm::asset_id& asset, uint16_t index);
		};

		struct certification final : ledger::transaction
		{
			ordered_map<algorithm::asset_id, bool> observers;
			option<bool> online = optional::none;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			void set_online();
			void set_online(const algorithm::asset_id& asset);
			void set_offline();
			void set_offline(const algorithm::asset_id& asset);
			void set_standby();
			void set_standby(const algorithm::asset_id& asset);
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct routing_account final : ledger::delegation_transaction
		{
			string address;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			void set_address(const std::string_view& new_address);
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct depository_account final : ledger::delegation_transaction
		{
			algorithm::pubkeyhash proposer = { 0 };

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			expects_promise_rt<void> dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const override;
			void set_proposer(const algorithm::pubkeyhash new_proposer);
			bool is_proposer_null() const;
			bool is_dispatchable() const override;
			ordered_set<algorithm::pubkeyhash_t> get_mpc(const ledger::receipt& receipt) const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct depository_account_finalization final : ledger::consensus_transaction
		{
			algorithm::composition::cpubkey mpc_public_key = { 0 };
			uint256_t depository_account_hash = 0;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			expects_promise_rt<void> dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const override;
			void set_witness(const uint256_t& new_depository_account_hash, const algorithm::composition::cpubkey new_mpc_public_key);
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const override;
			bool is_dispatchable() const override;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct depository_withdrawal final : ledger::transaction
		{
			vector<std::pair<string, decimal>> to;
			algorithm::pubkeyhash proposer = { 0 };
			algorithm::pubkeyhash migration_proposer = { 0 };
			bool only_if_not_in_queue = true;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			expects_promise_rt<void> dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const override;
			void set_to(const std::string_view& address, const decimal& value);
			void set_proposer(const algorithm::pubkeyhash new_proposer, const algorithm::pubkeyhash new_migration_proposer = nullptr);
			bool is_proposer_null() const;
			bool is_migration_proposer_null() const;
			bool is_dispatchable() const override;
			decimal get_total_value(const ledger::transaction_context* context) const;
			decimal get_fee_value(const ledger::transaction_context* context, const algorithm::pubkeyhash from, const decimal& total_value) const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static expects_lr<void> validate_prepared_transaction(const ledger::transaction_context* context, const depository_withdrawal* transaction, const mediator::prepared_transaction& prepared);
			static expects_lr<ordered_set<algorithm::pubkeyhash_t>> accumulate_prepared_mpc(const ledger::transaction_context* context, const depository_withdrawal* transaction, const mediator::prepared_transaction& prepared);
			static expects_lr<states::witness_account> find_migration_account(const ledger::transaction_context* context, const algorithm::asset_id& asset, const algorithm::pubkeyhash from_proposer, const algorithm::pubkeyhash to_proposer);
		};

		struct depository_withdrawal_finalization final : ledger::consensus_transaction
		{
			uint256_t depository_withdrawal_hash = 0;
			string transaction_id;
			string native_data;
			string error_message;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const override;
			void set_success_witness(const std::string_view& new_transaction_id, const std::string_view& new_native_data, const uint256_t& new_depository_withdrawal_hash);
			void set_failure_witness(const std::string_view& new_error_message, const uint256_t& new_depository_withdrawal_hash);
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct depository_transaction final : ledger::attestation_transaction
		{
			struct depository_transfer
			{
				decimal balance = decimal::zero();
			};

			struct balance_transfer
			{
				decimal supply = decimal::zero();
				decimal reserve = decimal::zero();
			};

			struct transition
			{
				ordered_map<algorithm::pubkeyhash_t, ordered_map<algorithm::asset_id, depository_transfer>> depositories;
				ordered_map<algorithm::pubkeyhash_t, ordered_map<algorithm::asset_id, balance_transfer>> transfers;
			};

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const override;
			void set_witness(uint64_t block_id, const std::string_view& transaction_id, const vector<mediator::value_transfer>& inputs, const vector<mediator::value_transfer>& outputs);
			void set_witness(const mediator::computed_transaction& witness);
			option<mediator::computed_transaction> get_assertion(const ledger::transaction_context* context) const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct depository_adjustment final : ledger::transaction
		{
			decimal incoming_absolute_fee = decimal::zero();
			decimal incoming_relative_fee = decimal::zero();
			decimal outgoing_absolute_fee = decimal::zero();
			decimal outgoing_relative_fee = decimal::zero();
			uint8_t security_level = 0;
			bool accepts_account_requests = true;
			bool accepts_withdrawal_requests = true;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			void set_incoming_fee(const decimal& absolute_fee, const decimal& relative_fee);
			void set_outgoing_fee(const decimal& absolute_fee, const decimal& relative_fee);
			void set_security(uint8_t new_security_level, bool new_accepts_account_requests, bool new_accepts_withdrawal_requests);
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct depository_migration final : ledger::transaction
		{
			struct mpc_migration
			{
				algorithm::asset_id asset = 0;
				algorithm::pubkeyhash proposer = { 0 };
				algorithm::pubkeyhash owner = { 0 };

				uint256_t hash() const
				{
					format::stream message;
					message.write_integer(asset);
					message.write_string(algorithm::pubkeyhash_t(proposer).optimized_view());
					message.write_string(algorithm::pubkeyhash_t(owner).optimized_view());
					return message.hash();
				}
			};

			ordered_map<uint256_t, mpc_migration> migrations;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			expects_promise_rt<void> dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			void migrate(const algorithm::asset_id& asset, const algorithm::pubkeyhash proposer, const algorithm::pubkeyhash owner);
			bool is_dispatchable() const override;
			algorithm::pubkeyhash_t get_new_proposer(const ledger::receipt& receipt) const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct depository_migration_preparation final : ledger::consensus_transaction
		{
			algorithm::pubkey cipher_public_key = { 0 };
			uint256_t depository_migration_hash = 0;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			expects_promise_rt<void> dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool is_dispatchable() const override;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct depository_migration_commitment final : ledger::consensus_transaction
		{
			ordered_map<uint256_t, string> encrypted_migrations;
			uint256_t depository_migration_preparation_hash = 0;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			expects_promise_rt<void> dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const override;
			expects_lr<void> transfer(const uint256_t& account_hash, const uint256_t& mpc_seed, const algorithm::pubkey new_proposer_cipher_public_key, const algorithm::seckey old_proposer_secret_key);
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool is_dispatchable() const override;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct depository_migration_finalization final : ledger::consensus_transaction
		{
			uint256_t depository_migration_commitment_hash = 0;
			bool successful = true;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		class resolver
		{
		public:
			static ledger::transaction* from_stream(format::stream& stream);
			static ledger::transaction* from_type(uint32_t hash);
			static ledger::transaction* from_copy(const ledger::transaction* base);
			static expects_promise_rt<mediator::prepared_transaction> prepare_transaction(const algorithm::asset_id& asset, const mediator::wallet_link& from_link, const vector<mediator::value_transfer>& to, option<mediator::computed_fee>&& fee = optional::none);
			static expects_promise_rt<mediator::finalized_transaction> finalize_and_broadcast_transaction(const algorithm::asset_id& asset, const uint256_t& external_id, mediator::prepared_transaction&& prepared, ledger::dispatch_context* dispatcher);
		};
	}
}
#endif