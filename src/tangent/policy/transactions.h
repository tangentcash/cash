#ifndef TAN_POLICY_TRANSACTIONS_H
#define TAN_POLICY_TRANSACTIONS_H
#include "states.h"
#include "../kernel/warden.h"

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
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			bool store_body(format::wo_stream* stream) const override;
			bool load_body(format::ro_stream& stream) override;
			bool recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const override;
			void set_to(const algorithm::pubkeyhash_t& new_to, const decimal& new_value);
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct upgrade final : ledger::transaction
		{
			enum class data_type : uint8_t
			{
				program = 0x33,
				hashcode = 0x66
			};
			format::variables args;
			string data;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			bool store_body(format::wo_stream* stream) const override;
			bool load_body(format::ro_stream& stream) override;
			bool recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const override;
			void from_program(const std::string_view& new_data, format::variables&& new_args);
			void from_hashcode(const std::string_view& new_data, format::variables&& new_args);
			algorithm::pubkeyhash_t get_account() const;
			option<data_type> get_data_type() const;
			uptr<schema> as_schema() const override;
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
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			bool store_body(format::wo_stream* stream) const override;
			bool load_body(format::ro_stream& stream) override;
			bool recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const override;
			void program_call(const algorithm::pubkeyhash_t& new_callable, const decimal& new_value, const std::string_view& new_function, format::variables&& new_args);
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
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
			bool store_body(format::wo_stream* stream) const override;
			bool load_body(format::ro_stream& stream) override;
			bool recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const override;
			bool recover_aliases(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<uint256_t>& aliases) const override;
			bool import_transaction(const ledger::transaction& transaction);
			bool import_internal_transaction(ledger::transaction& transaction, const algorithm::seckey_t& secret_key);
			bool import_external_transaction(ledger::transaction& transaction, const algorithm::seckey_t& secret_key, uint64_t nonce);
			bool is_dispatchable() const override;
			expects_lr<ledger::block_transaction> resolve_block_transaction(const ledger::receipt& receipt, const uint256_t& transaction_hash) const;
			const ledger::transaction* resolve_transaction(const uint256_t& transaction_hash) const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static void normalize_transaction(ledger::transaction& transaction, const algorithm::asset_id& asset);
		};

		struct validator_adjustment final : ledger::transaction
		{
			ordered_map<algorithm::asset_id, decimal> participation_stakes;
			ordered_map<algorithm::asset_id, decimal> attestation_stakes;
			option<bool> production = optional::none;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			bool store_body(format::wo_stream* stream) const override;
			bool load_body(format::ro_stream& stream) override;
			void enable_block_production();
			void disable_block_production();
			void standby_on_block_production();
			void allocate_participation_stake(const algorithm::asset_id& asset, const decimal& value);
			void deallocate_participation_stake(const algorithm::asset_id& asset, const decimal& value);
			void disable_participation(const algorithm::asset_id& asset);
			void standby_on_participation(const algorithm::asset_id& asset);
			void allocate_attestation_stake(const algorithm::asset_id& asset, const decimal& value);
			void deallocate_attestation_stake(const algorithm::asset_id& asset, const decimal& value);
			void disable_attestation(const algorithm::asset_id& asset);
			void standby_on_attestation(const algorithm::asset_id& asset);
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct depository_account final : ledger::delegation_transaction
		{
			string routing_address;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			expects_promise_rt<void> dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const override;
			bool store_body(format::wo_stream* stream) const override;
			bool load_body(format::ro_stream& stream) override;
			bool recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const override;
			bool is_dispatchable() const override;
			void set_routing_address(const std::string_view& new_address);
			ordered_set<algorithm::pubkeyhash_t> get_group(const ledger::receipt& receipt) const;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct depository_account_finalization final : ledger::consensus_transaction
		{
			algorithm::composition::cpubkey_t public_key;
			uint256_t depository_account_hash = 0;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			expects_promise_rt<void> dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const override;
			void set_witness(const uint256_t& new_depository_account_hash, const algorithm::composition::cpubkey_t& new_public_key);
			bool store_body(format::wo_stream* stream) const override;
			bool load_body(format::ro_stream& stream) override;
			bool recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const override;
			bool is_dispatchable() const override;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct depository_withdrawal final : ledger::transaction
		{
			vector<std::pair<string, decimal>> to;
			algorithm::pubkeyhash_t from_manager;
			algorithm::pubkeyhash_t to_manager;
			bool only_if_not_in_queue = true;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			expects_promise_rt<void> dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const override;
			bool store_body(format::wo_stream* stream) const override;
			bool load_body(format::ro_stream& stream) override;
			bool recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const override;
			void set_to(const std::string_view& address, const decimal& value);
			void set_manager(const algorithm::pubkeyhash_t& new_from_manager, const algorithm::pubkeyhash_t& new_to_manager = algorithm::pubkeyhash_t());
			bool is_dispatchable() const override;
			decimal get_token_value(const ledger::transaction_context* context) const;
			decimal get_fee_value(const ledger::transaction_context* context) const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static expects_lr<void> approve_or_revert(ledger::transaction_context* context, const ledger::block_transaction& transaction, bool approval);
			static expects_lr<states::witness_account> find_receiving_account(const ledger::transaction_context* context, const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& from_manager, const algorithm::pubkeyhash_t& to_manager);
		};

		struct depository_withdrawal_routing final : ledger::consensus_transaction
		{
			uint256_t depository_withdrawal_hash = 0;
			expects_lr<warden::finalized_transaction> proof = layer_exception();

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			expects_promise_rt<void> dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const override;
			bool store_body(format::wo_stream* stream) const override;
			bool load_body(format::ro_stream& stream) override;
			bool recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const override;
			void set_proof(const uint256_t& new_depository_withdrawal_hash, expects_lr<warden::finalized_transaction>&& new_proof);
			bool is_dispatchable() const override;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static expects_lr<void> validate_possible_proof(const ledger::transaction_context* context, const depository_withdrawal* transaction, const warden::prepared_transaction& prepared);
			static expects_lr<void> validate_finalized_proof(const ledger::transaction_context* context, const depository_withdrawal* transaction, const warden::finalized_transaction& finalized);
		};

		struct depository_withdrawal_finalization final : ledger::consensus_transaction
		{
			uint256_t depository_withdrawal_routing_hash = 0;
			string status;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			bool store_body(format::wo_stream* stream) const override;
			bool load_body(format::ro_stream& stream) override;
			bool recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const override;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct depository_transaction final : ledger::attestation_transaction
		{
			struct depository_transfer
			{
				decimal supply = decimal::zero();
				decimal incoming_fee = decimal::zero();
				decimal outgoing_fee = decimal::zero();
			};

			struct depository_transfer_batch
			{
				ordered_set<algorithm::pubkeyhash_t> participants;
				ordered_map<algorithm::asset_id, depository_transfer> transfers;
			};

			struct balance_transfer
			{
				decimal supply = decimal::zero();
				decimal reserve = decimal::zero();
			};

			struct weight_transfer
			{
				decimal accountable = decimal::zero();
				decimal unaccountable = decimal::zero();
			};

			struct transition
			{
				ordered_map<algorithm::pubkeyhash_t, depository_transfer_batch> depositories;
				ordered_map<algorithm::pubkeyhash_t, ordered_map<algorithm::asset_id, balance_transfer>> transfers;
				ordered_map<algorithm::asset_id, weight_transfer> weights;
			};

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			bool store_body(format::wo_stream* stream) const override;
			bool load_body(format::ro_stream& stream) override;
			bool recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const override;
			void set_finalized_witness(uint64_t block_id, const std::string_view& transaction_id, const vector<warden::value_transfer>& inputs, const vector<warden::value_transfer>& outputs);
			void set_computed_witness(const warden::computed_transaction& witness);
			option<warden::computed_transaction> get_assertion(const ledger::transaction_context* context) const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct depository_adjustment final : ledger::transaction
		{
			ordered_map<string, string> whitelist;
			decimal incoming_fee = decimal::zero();
			decimal outgoing_fee = decimal::zero();
			decimal participation_threshold = decimal::zero();
			uint8_t security_level = 0;
			bool accepts_account_requests = true;
			bool accepts_withdrawal_requests = true;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			bool store_body(format::wo_stream* stream) const override;
			bool load_body(format::ro_stream& stream) override;
			void set_reward(const decimal& new_incoming_fee, const decimal& new_outgoing_fee);
			void set_security(uint8_t new_security_level, const decimal& new_participation_threshold, bool new_accepts_account_requests, bool new_accepts_withdrawal_requests);
			void permanently_whitelist_token(const std::string_view& contract_address, const std::string_view& symbol);
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct depository_migration final : ledger::transaction
		{
			struct secret_share
			{
				algorithm::asset_id asset;
				algorithm::pubkeyhash_t manager;
				algorithm::pubkeyhash_t owner;

				secret_share() : asset(0)
				{
				}
				secret_share(const algorithm::asset_id& new_asset, const algorithm::pubkeyhash_t& new_manager, const algorithm::pubkeyhash_t& new_owner) : asset(new_asset), manager(new_manager), owner(new_owner)
				{
				}
				uint256_t as_hash() const
				{
					format::wo_stream message;
					message.write_integer(asset);
					message.write_string(manager.optimized_view());
					message.write_string(owner.optimized_view());
					return message.hash();
				}
			};

			ordered_map<uint256_t, secret_share> shares;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			expects_promise_rt<void> dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const override;
			bool store_body(format::wo_stream* stream) const override;
			bool load_body(format::ro_stream& stream) override;
			void add_share(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& manager, const algorithm::pubkeyhash_t& owner);
			bool is_dispatchable() const override;
			algorithm::pubkeyhash_t get_new_manager(const ledger::receipt& receipt) const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct depository_migration_finalization final : ledger::consensus_transaction
		{
			algorithm::hashsig_t confirmation_signature;
			uint256_t depository_migration_hash = 0;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			bool store_body(format::wo_stream* stream) const override;
			bool load_body(format::ro_stream& stream) override;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		class resolver
		{
		public:
			static ledger::transaction* from_stream(format::ro_stream& stream);
			static ledger::transaction* from_type(uint32_t hash);
			static ledger::transaction* from_copy(const ledger::transaction* base);
			static expects_promise_rt<warden::prepared_transaction> prepare_transaction(const algorithm::asset_id& asset, const warden::wallet_link& from_link, const vector<warden::value_transfer>& to, const decimal& max_fee, bool inclusive_fee);
			static expects_lr<warden::finalized_transaction> finalize_transaction(const algorithm::asset_id& asset, warden::prepared_transaction&& prepared);
			static expects_promise_rt<void> broadcast_transaction(const algorithm::asset_id& asset, const uint256_t& external_id, warden::finalized_transaction&& finalized, ledger::dispatch_context* dispatcher);
		};
	}
}
#endif