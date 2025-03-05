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
			algorithm::pubkeyhash to = { 0 };
			decimal value;
			string memo;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const override;
			void set_to(const algorithm::pubkeyhash new_to, const decimal& new_value, const std::string_view& new_memo = std::string_view());
			bool is_to_null() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct omnitransfer final : ledger::transaction
		{
			struct subtransfer
			{
				algorithm::pubkeyhash to = { 0 };
				decimal value;
				string memo;
			};
			vector<subtransfer> transfers;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const override;
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
			algorithm::recsighash location = { 0 };
			format::variables args;
			string calldata;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const override;
			bool sign_location(const algorithm::seckey secret_key);
			bool verify_location(const algorithm::pubkey public_key) const;
			bool recover_location(algorithm::pubkeyhash public_key_hash) const;
			bool is_location_null() const;
			void set_location(const algorithm::recsighash new_value);
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
			bool recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const override;
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

		struct withdrawal final : ledger::transaction
		{
			vector<std::pair<string, decimal>> to;
			algorithm::pubkeyhash proposer = { 0 };

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			expects_promise_rt<void> dispatch(const ledger::wallet& proposer, const ledger::transaction_context* context, vector<uptr<ledger::transaction>>* pipeline) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const override;
			void set_to(const std::string_view& address, const decimal& value);
			void set_proposer(const algorithm::pubkeyhash new_proposer);
			bool is_proposer_null() const;
			decimal get_total_value() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			uint64_t get_dispatch_offset() const override;
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
			expects_promise_rt<void> dispatch(const ledger::wallet& proposer, const ledger::transaction_context* context, vector<uptr<ledger::transaction>>* pipeline) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const override;
			bool recover_aliases(const ledger::receipt& receipt, ordered_set<uint256_t>& aliases) const override;
			bool merge(const ledger::transaction& transaction);
			bool merge(ledger::transaction& transaction, const algorithm::seckey secret_key);
			bool merge(ledger::transaction& transaction, const algorithm::seckey secret_key, uint64_t sequence);
			expects_lr<ledger::block_transaction> resolve_block_transaction(const ledger::receipt& receipt, const uint256_t& transaction_hash) const;
			const ledger::transaction* resolve_transaction(const uint256_t& transaction_hash) const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			uint64_t get_dispatch_offset() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static void setup_child(ledger::transaction& transaction, const algorithm::asset_id& asset);
			static bool sign_child(ledger::transaction& transaction, const algorithm::seckey secret_key, const algorithm::asset_id& asset, uint16_t index);
		};

		struct commitment final : ledger::transaction
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

		struct incoming_claim final : ledger::aggregation_transaction
		{
			struct custody_transfer
			{
				address_value_map contributions;
				account_value_map reservations;
				decimal custody = decimal::zero();
			};

			struct balance_transfer
			{
				decimal supply = decimal::zero();
				decimal reserve = decimal::zero();
			};

			struct transition
			{
				ordered_map<string, custody_transfer> contributions;
				ordered_map<string, balance_transfer> transfers;
			};

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const override;
			void set_witness(uint64_t block_height, const std::string_view& transaction_id, decimal&& fee, vector<mediator::transferer>&& senders, vector<mediator::transferer>&& receivers);
			void set_witness(const mediator::incoming_transaction& witness);
			option<mediator::incoming_transaction> get_assertion(const ledger::transaction_context* context) const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct outgoing_claim final : ledger::consensus_transaction
		{
			string transaction_id;
			string transaction_data;
			string transaction_message;
			uint256_t transaction_hash = 0;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const override;
			void set_success_witness(const std::string_view& transaction_id, const std::string_view& transaction_data, const uint256_t& transaction_hash);
			void set_failure_witness(const std::string_view& transaction_message, const uint256_t& transaction_hash);
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct address_account final : ledger::delegation_transaction
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

		struct pubkey_account final : ledger::delegation_transaction
		{
			string pubkey;
			string sighash;

			expects_lr<void> sign_pubkey(const secret_box& signing_key);
			expects_lr<void> verify_pubkey() const;
			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			void set_pubkey(const std::string_view& verifying_key);
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct delegation_account final : ledger::delegation_transaction
		{
			algorithm::pubkeyhash proposer = { 0 };

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			expects_promise_rt<void> dispatch(const ledger::wallet& proposer, const ledger::transaction_context* context, vector<uptr<ledger::transaction>>* pipeline) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const override;
			void set_proposer(const algorithm::pubkeyhash new_proposer);
			bool is_proposer_null() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			uint64_t get_dispatch_offset() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct custodian_account final : ledger::consensus_transaction
		{
			uint256_t delegation_account_hash = 0;
			algorithm::pubkeyhash owner = { 0 };
			uint64_t pubkey_index = 0;
			string pubkey;
			string sighash;

			expects_lr<void> set_wallet(const ledger::transaction_context* context, const ledger::wallet& proposer, const algorithm::pubkeyhash new_owner);
			expects_lr<void> sign_pubkey(const secret_box& signing_key);
			expects_lr<void> verify_pubkey() const;
			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			expects_promise_rt<void> dispatch(const ledger::wallet& proposer, const ledger::transaction_context* context, vector<uptr<ledger::transaction>>* pipeline) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const override;
			void set_witness(const uint256_t& delegation_account_hash);
			void set_pubkey(const std::string_view& verifying_key, uint64_t new_pubkey_index);
			void set_owner(const algorithm::pubkeyhash new_owner);
			bool is_owner_null() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			uint64_t get_dispatch_offset() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct contribution_allocation final : ledger::transaction
		{
			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			expects_promise_rt<void> dispatch(const ledger::wallet& proposer, const ledger::transaction_context* context, vector<uptr<ledger::transaction>>* pipeline) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			uint64_t get_dispatch_offset() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct contribution_selection final : ledger::consensus_transaction
		{
			uint256_t contribution_allocation_hash = 0;
			algorithm::composition::cpubkey public_key1 = { 0 };

			expects_lr<void> set_share1(const uint256_t& new_contribution_allocation_hash, const algorithm::seckey secret_key);
			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			expects_promise_rt<void> dispatch(const ledger::wallet& proposer, const ledger::transaction_context* context, vector<uptr<ledger::transaction>>* pipeline) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const override;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			uint64_t get_dispatch_offset() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct contribution_activation final : ledger::consensus_transaction
		{
			uint256_t contribution_selection_hash = 0;
			algorithm::composition::cpubkey public_key2 = { 0 };
			algorithm::composition::cpubkey public_key = { 0 };
			uint16_t public_key_size = 0;

			expects_lr<void> set_share2(const uint256_t& new_contribution_selection_hash, const algorithm::seckey secret_key, const algorithm::composition::cpubkey public_key1);
			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			expects_promise_rt<void> dispatch(const ledger::wallet& proposer, const ledger::transaction_context* context, vector<uptr<ledger::transaction>>* pipeline) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const override;
			expects_lr<mediator::derived_verifying_wallet> get_verifying_wallet() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			uint64_t get_dispatch_offset() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct contribution_deallocation final : ledger::transaction
		{
			uint256_t contribution_activation_hash = 0;
			algorithm::pubkey cipher_public_key1 = { 0 };
			algorithm::pubkey cipher_public_key2 = { 0 };

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			expects_promise_rt<void> dispatch(const ledger::wallet& proposer, const ledger::transaction_context* context, vector<uptr<ledger::transaction>>* pipeline) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			void set_witness(const algorithm::seckey secret_key, const uint256_t& contribution_activation_hash);
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			uint64_t get_dispatch_offset() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct contribution_deselection final : ledger::consensus_transaction
		{
			uint256_t contribution_deallocation_hash = 0;
			string encrypted_secret_key1;

			expects_lr<void> set_revealing_share1(const ledger::transaction_context* context, const uint256_t& contribution_deallocation_hash, const algorithm::seckey secret_key);
			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			expects_promise_rt<void> dispatch(const ledger::wallet& proposer, const ledger::transaction_context* context, vector<uptr<ledger::transaction>>* pipeline) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const override;
			option<string> get_secret_key1(const ledger::transaction_context* context, const algorithm::seckey secret_key) const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			uint64_t get_dispatch_offset() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct contribution_deactivation final : ledger::consensus_transaction
		{
			uint256_t contribution_deselection_hash = 0;
			string encrypted_secret_key2;

			expects_lr<void> set_revealing_share2(const ledger::transaction_context* context, const uint256_t& contribution_deselection_hash, const algorithm::seckey secret_key);
			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			expects_promise_rt<void> dispatch(const ledger::wallet& proposer, const ledger::transaction_context* context, vector<uptr<ledger::transaction>>* pipeline) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const override;
			option<string> get_secret_key1(const ledger::transaction_context* context, const algorithm::seckey secret_key) const;
			option<string> get_secret_key2(const ledger::transaction_context* context, const algorithm::seckey secret_key) const;
			expects_lr<mediator::derived_signing_wallet> get_signing_wallet(const ledger::transaction_context* context, const algorithm::seckey secret_key) const;
			expects_promise_rt<mediator::outgoing_transaction> withdraw_to_address(const ledger::transaction_context* context, const algorithm::seckey secret_key, const std::string_view& address);
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			uint64_t get_dispatch_offset() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct depository_adjustment final : ledger::transaction
		{
			decimal incoming_absolute_fee = decimal::zero();
			decimal incoming_relative_fee = decimal::zero();
			decimal outgoing_absolute_fee = decimal::zero();
			decimal outgoing_relative_fee = decimal::zero();

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			void set_incoming_fee(const decimal& absolute_fee, const decimal& relative_fee);
			void set_outgoing_fee(const decimal& absolute_fee, const decimal& relative_fee);
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct depository_migration final : ledger::transaction
		{
			algorithm::pubkeyhash proposer = { 0 };
			decimal value;

			expects_lr<void> validate(uint64_t block_number) const override;
			expects_lr<void> execute(ledger::transaction_context* context) const override;
			expects_promise_rt<void> dispatch(const ledger::wallet& proposer, const ledger::transaction_context* context, vector<uptr<ledger::transaction>>* pipeline) const override;
			bool store_body(format::stream* stream) const override;
			bool load_body(format::stream& stream) override;
			bool recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const override;
			void set_proposer(const algorithm::pubkeyhash new_proposer, const decimal& new_value);
			bool is_proposer_null() const;
			expects_lr<states::witness_address> get_destination(const ledger::transaction_context* context) const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uint256_t get_gas_estimate() const override;
			uint64_t get_dispatch_offset() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		class resolver
		{
		public:
			static ledger::transaction* init(uint32_t hash);
			static ledger::transaction* copy(const ledger::transaction* base);
			static expects_promise_rt<mediator::outgoing_transaction> emit_transaction(vector<uptr<ledger::transaction>>* pipeline, mediator::dynamic_wallet&& wallet, const algorithm::asset_id& asset, const uint256_t& transaction_hash, vector<mediator::transferer>&& to);
		};
	}
}
#endif