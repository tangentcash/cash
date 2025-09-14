#ifndef TAN_KERNEL_BLOCK_H
#define TAN_KERNEL_BLOCK_H
#include "wallet.h"
#include "../policy/states.h"

namespace tangent
{
	namespace warden
	{
		struct prepared_transaction;
	}

	namespace ledger
	{
		struct block;
		struct block_header;
		struct block_proof;
		struct block_evaluation;
		struct evaluation_context;

		typedef std::function<uptr<transaction>()> replace_transaction_callback;

		enum class filter_comparator
		{
			greater,
			greater_equal,
			equal,
			not_equal,
			less,
			less_equal
		};

		enum class filter_order
		{
			ascending,
			descending
		};

		enum class gas_cost
		{
			write_tx_byte = 48,
			write_byte = 32,
			erase_byte = 2,
			read_byte = 1,
			query_byte = 8,
			bulk_query_byte = 2,
			opcode = 1,
			memory_block = 1
		};

		struct block_transaction final : messages::uniform
		{
			uptr<ledger::transaction> transaction;
			ledger::receipt receipt;

			block_transaction() = default;
			block_transaction(uptr<ledger::transaction>&& new_transaction, ledger::receipt&& new_receipt);
			block_transaction(block_transaction&&) noexcept = default;
			block_transaction(const block_transaction& other);
			block_transaction& operator= (block_transaction&&) noexcept = default;
			block_transaction& operator= (const block_transaction& other);
			bool store_payload(format::wo_stream* stream) const override;
			bool load_payload(format::ro_stream& stream) override;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct block_state
		{
			struct state_change
			{
				uptr<ledger::state> state;
				bool erase;

				state_change() noexcept;
				state_change(uptr<ledger::state>&& new_state, bool new_erase) noexcept;
				state_change(const state_change& other) noexcept;
				state_change(state_change&& other) noexcept;
				state_change& operator=(const state_change& other) noexcept;
				state_change& operator=(state_change&& other) noexcept;
				uptr<schema> as_schema() const;
				bool empty() const;
			};

			ordered_map<string, state_change> finalized;
			ordered_map<string, state_change> pending;

			block_state() = default;
			block_state(const block_state& other);
			block_state(block_state&&) noexcept = default;
			block_state& operator= (const block_state& other);
			block_state& operator= (block_state&&) noexcept = default;
			option<uptr<state>> find(uint32_t type, const std::string_view& index) const;
			option<uptr<state>> find(uint32_t type, const std::string_view& column, const std::string_view& row) const;
			void erase(uint32_t type, const std::string_view& index);
			void erase(uint32_t type, const std::string_view& column, const std::string_view& row);
			bool push(state* value, bool will_delete);
			bool emplace(uptr<state>&& value, bool will_delete);
			string index_of(state* value) const;
			string index_of(uint32_t type, const std::string_view& index) const;
			string index_of(uint32_t type, const std::string_view& column, const std::string_view& row) const;
			void revert(bool fully = false);
			void commit();
		};

		struct block_changelog
		{
			struct
			{
				unordered_map<uint32_t, void*> topics;
				unordered_map<string, string> effects;
			} temporary_state;
			block_state outgoing;
			block_state incoming;

			block_changelog() noexcept;
			block_changelog(const block_changelog&) = delete;
			block_changelog(block_changelog&& other) noexcept;
			block_changelog& operator=(const block_changelog&) = delete;
			block_changelog& operator=(block_changelog&& other) noexcept;
			~block_changelog() noexcept;
			void clear_temporary_state();
			void clear();
			void revert();
			void commit();
		};

		struct block_checkpoint
		{
			uint64_t new_tip_block_number = 0;
			uint64_t old_tip_block_number = 0;
			uint64_t mempool_transactions = 0;
			int64_t transaction_delta = 0;
			int64_t block_delta = 0;
			int64_t state_delta = 0;
			bool is_fork = false;
		};

		struct block_header : messages::authentic
		{
			algorithm::wesolowski::digest proof;
			algorithm::wesolowski::parameters target;
			ordered_map<algorithm::asset_id, uint64_t> witnesses;
			uint256_t parent_hash = 0;
			uint256_t transaction_root = 0;
			uint256_t receipt_root = 0;
			uint256_t state_root = 0;
			uint256_t gas_use = 0;
			uint256_t gas_limit = 0;
			uint256_t absolute_work = 0;
			uint256_t slot_duration = 0;
			uint64_t generation_time = 0;
			uint64_t evaluation_time = 0;
			uint64_t priority = 0;
			uint64_t number = 0;
			uint64_t mutation_count = 0;
			uint32_t transaction_count = 0;
			uint32_t state_count = 0;

			virtual ~block_header() = default;
			virtual bool operator<(const block_header& other) const;
			virtual bool operator>(const block_header& other) const;
			virtual bool operator<=(const block_header& other) const;
			virtual bool operator>=(const block_header& other) const;
			virtual bool operator==(const block_header& other) const;
			virtual bool operator!=(const block_header& other) const;
			virtual expects_lr<void> verify_validity(const block_header* parent_block) const;
			virtual bool store_payload_proof(format::wo_stream* stream) const;
			virtual bool load_payload_proof(format::ro_stream& stream);
			virtual bool store_payload(format::wo_stream* stream) const override;
			virtual bool load_payload(format::ro_stream& stream) override;
			virtual bool sign(const algorithm::seckey_t& secret_key) override;
			virtual bool solve(const algorithm::seckey_t& secret_key);
			virtual bool verify(const algorithm::pubkey_t& public_key) const override;
			virtual bool recover(algorithm::pubkey_t& public_key) const override;
			virtual bool recover_hash(algorithm::pubkeyhash_t& public_key_hash) const override;
			virtual bool verify_proof() const;
			virtual void set_parent_block(const block_header* parent_block);
			virtual void set_witness_requirement(const algorithm::asset_id& asset, uint64_t block_number);
			virtual uint64_t get_witness_requirement(const algorithm::asset_id& asset) const;
			virtual int8_t get_relative_order(const block_header& other) const;
			virtual uint64_t get_slot_proof_duration_average() const;
			virtual uint64_t get_slot_length() const;
			virtual uint64_t get_proof_duration() const;
			virtual uint64_t get_proof_accounted_duration() const;
			virtual double get_proof_difficulty_multiplier() const;
			virtual algorithm::wesolowski::parameters get_proof_slot_target(const block_header* parent_block) const;
			virtual uint256_t as_hash(bool renew = false) const override;
			virtual uptr<schema> as_schema() const override;
			virtual format::wo_stream as_signable() const override;
			virtual format::wo_stream as_solution() const;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static uint64_t get_transaction_limit();
			static uint256_t get_gas_limit();
			static uint256_t get_gas_work(const uint128_t& difficulty, const uint256_t& gas_use, const uint256_t& gas_limit, uint64_t priority);
		};

		struct block final : block_header
		{
			vector<block_transaction> transactions;

			block() = default;
			block(const block_header& other);
			block(const block&) = default;
			block(block&&) = default;
			virtual ~block() override = default;
			block& operator=(const block&) = default;
			block& operator=(block&&) = default;
			expects_lr<block_state> evaluate(const block_header* parent_block, evaluation_context* environment, const replace_transaction_callback& callback);
			expects_lr<void> validate(const block_header* parent_block, block_evaluation* evaluated_result = nullptr) const;
			expects_lr<void> verify_integrity(const block_header* parent_block, const block_state* state) const;
			bool store_payload(format::wo_stream* stream) const override;
			bool load_payload(format::ro_stream& stream) override;
			bool store_header_payload(format::wo_stream* stream) const;
			bool load_header_payload(format::ro_stream& stream);
			bool store_body_payload(format::wo_stream* stream) const;
			bool load_body_payload(format::ro_stream& stream);
			void recalculate(const block_header* parent_block, const block_state* state);
			uptr<schema> as_schema() const override;
			block_header as_header() const;
			block_proof as_proof(const block_header* parent_block, const block_state* state) const;
			uint256_t as_hash(bool renew = false) const override;
		};

		struct block_proof final : messages::uniform
		{
			algorithm::merkle_tree transaction_tree;
			algorithm::merkle_tree receipt_tree;
			algorithm::merkle_tree state_tree;
			uint256_t transaction_root = 0;
			uint256_t receipt_root = 0;
			uint256_t state_root = 0;

			option<algorithm::merkle_tree::branch_path> find_transaction(const uint256_t& hash);
			option<algorithm::merkle_tree::branch_path> find_receipt(const uint256_t& hash);
			option<algorithm::merkle_tree::branch_path> find_state(const uint256_t& hash);
			bool store_payload(format::wo_stream* stream) const override;
			bool load_payload(format::ro_stream& stream) override;
			bool has_transaction(const uint256_t& hash);
			bool has_receipt(const uint256_t& hash);
			bool has_state(const uint256_t& hash);
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct block_evaluation
		{
			block block;
			block_state state;

			expects_lr<block_checkpoint> checkpoint(bool keep_reverted_transactions = true) const;
			uptr<schema> as_schema() const;
		};

		struct transaction_context
		{
		public:
			enum class execution_mode : uint8_t
			{
				pedantic = 1 << 0,
				evaluation = 1 << 1,
				replayable = 1 << 2
			};

			enum class production_type : uint8_t
			{
				burn_gas,
				burn_gas_and_deactivate,
				mint_gas,
				mint_gas_and_activate
			};

			enum class stake_type : uint8_t
			{
				lock,
				reward,
				unlock
			};

		private:
			uint8_t execution_flags;

		public:
			ordered_map<algorithm::asset_id, uint64_t> witnesses;
			const evaluation_context* environment;
			const ledger::transaction* transaction;
			ledger::block_changelog* changelog;
			ledger::block_header* block;
			ledger::receipt receipt;

		public:
			transaction_context();
			transaction_context(const ledger::evaluation_context* new_environment, ledger::block_header* new_block_header, block_changelog* new_changelog, const ledger::transaction* new_transaction, ledger::receipt&& new_receipt);
			transaction_context(const transaction_context& other);
			transaction_context(transaction_context&&) = default;
			transaction_context& operator=(const transaction_context& other);
			transaction_context& operator=(transaction_context&&) = default;
			expects_lr<void> load(state* value, bool paid);
			expects_lr<void> query_load(state* value, size_t results, bool paid);
			expects_lr<void> store(state* value, bool paid);
			expects_lr<void> emit_witness(const algorithm::asset_id& asset, uint64_t block_number);
			expects_lr<void> emit_event(uint32_t type, format::variables&& values, bool paid);
			expects_lr<void> burn_gas();
			expects_lr<void> burn_gas(const uint256_t& value);
			expects_lr<void> verify_account_nonce() const;
			expects_lr<void> verify_account_delegation(const algorithm::pubkeyhash_t& owner) const;
			expects_lr<void> verify_gas_transfer_balance() const;
			expects_lr<void> verify_transfer_balance(const algorithm::asset_id& asset, const decimal& value) const;
			expects_lr<void> verify_validator_attestation(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner) const;
			expects_lr<algorithm::wesolowski::distribution> calculate_random(const uint256_t& seed);
			expects_lr<size_t> calculate_attesters_size(const algorithm::asset_id& asset) const;
			expects_lr<vector<states::validator_production>> calculate_producers(size_t target_size);
			expects_lr<vector<states::validator_participation>> calculate_participants(const algorithm::asset_id& asset, ordered_set<algorithm::pubkeyhash_t>& exclusion, size_t target_size);
			expects_lr<states::account_nonce> apply_account_nonce(const algorithm::pubkeyhash_t& owner, uint64_t nonce);
			expects_lr<states::account_program> apply_account_program(const algorithm::pubkeyhash_t& owner, const std::string_view& program_hashcode);
			expects_lr<states::account_uniform> apply_account_uniform(const algorithm::pubkeyhash_t& owner, const std::string_view& index, const std::string_view& data);
			expects_lr<states::account_multiform> apply_account_multiform(const algorithm::pubkeyhash_t& owner, const std::string_view& column, const std::string_view& row, const std::string_view& data, const uint256_t& filter);
			expects_lr<states::account_delegation> apply_account_delegation(const algorithm::pubkeyhash_t& owner, uint32_t delegations);
			expects_lr<states::account_balance> apply_transfer(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, const decimal& supply, const decimal& reserve);
			expects_lr<states::account_balance> apply_fee_transfer(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, const decimal& value);
			expects_lr<states::account_balance> apply_payment(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& from, const algorithm::pubkeyhash_t& to, const decimal& value);
			expects_lr<states::validator_production> apply_validator_production(const algorithm::pubkeyhash_t& owner, production_type action, const uint256_t& gas, const ordered_map<algorithm::asset_id, decimal>& stakes);
			expects_lr<states::validator_participation> apply_validator_participation(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, stake_type type, int64_t participations, const ordered_map<algorithm::asset_id, decimal>& stakes);
			expects_lr<states::validator_attestation> apply_validator_attestation(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, stake_type type, const ordered_map<algorithm::asset_id, decimal>& stakes);
			expects_lr<states::depository_reward> apply_depository_reward(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, const decimal& incoming_fee, const decimal& outgoing_fee);
			expects_lr<states::depository_balance> apply_depository_balance(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, const ordered_map<algorithm::asset_id, decimal>& balances);
			expects_lr<states::depository_policy> apply_depository_policy_account(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, uint64_t new_accounts);
			expects_lr<states::depository_policy> apply_depository_policy_queue(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, const uint256_t& transaction_hash);
			expects_lr<states::depository_policy> apply_depository_policy(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, uint8_t security_level, bool accepts_account_requests, bool accepts_withdrawal_requests, ordered_set<algorithm::asset_id>&& whitelist);
			expects_lr<states::depository_account> apply_depository_account(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, const algorithm::pubkeyhash_t& manager, const algorithm::composition::cpubkey_t& public_key, ordered_set<algorithm::pubkeyhash_t>&& group);
			expects_lr<states::witness_program> apply_witness_program(const std::string_view& packed_program_code);
			expects_lr<states::witness_event> apply_witness_event(const uint256_t& parent_transaction_hash, const uint256_t& child_transaction_hash);
			expects_lr<states::witness_account> apply_witness_account(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, const address_map& addresses);
			expects_lr<states::witness_account> apply_witness_routing_account(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, const address_map& addresses);
			expects_lr<states::witness_account> apply_witness_depository_account(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, const algorithm::pubkeyhash_t& manager, const address_map& addresses, bool active = true);
			expects_lr<states::witness_transaction> apply_witness_transaction(const algorithm::asset_id& asset, const std::string_view& transaction_id);
			expects_lr<states::account_nonce> get_account_nonce(const algorithm::pubkeyhash_t& owner) const;
			expects_lr<states::account_program> get_account_program(const algorithm::pubkeyhash_t& owner) const;
			expects_lr<states::account_uniform> get_account_uniform(const algorithm::pubkeyhash_t& owner, const std::string_view& index) const;
			expects_lr<states::account_multiform> get_account_multiform(const algorithm::pubkeyhash_t& owner, const std::string_view& column, const std::string_view& row) const;
			expects_lr<vector<uptr<states::account_multiform>>> get_account_multiforms_by_column(const algorithm::pubkeyhash_t& owner, const std::string_view& column, size_t offset, size_t count) const;
			expects_lr<vector<uptr<states::account_multiform>>> get_account_multiforms_by_column_filter(const algorithm::pubkeyhash_t& owner, const std::string_view& column, const filter_comparator& comparator, const uint256_t& filter_value, filter_order order, size_t offset, size_t count) const;
			expects_lr<vector<uptr<states::account_multiform>>> get_account_multiforms_by_row(const algorithm::pubkeyhash_t& owner, const std::string_view& row, size_t offset, size_t count) const;
			expects_lr<vector<uptr<states::account_multiform>>> get_account_multiforms_by_row_filter(const algorithm::pubkeyhash_t& owner, const std::string_view& row, const filter_comparator& comparator, const uint256_t& filter_value, filter_order order, size_t offset, size_t count) const;
			expects_lr<states::account_delegation> get_account_delegation(const algorithm::pubkeyhash_t& owner) const;
			expects_lr<states::account_balance> get_account_balance(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner) const;
			expects_lr<states::validator_production> get_validator_production(const algorithm::pubkeyhash_t& owner) const;
			expects_lr<states::validator_participation> get_validator_participation(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner) const;
			expects_lr<vector<states::validator_participation>> get_validator_participations(const algorithm::pubkeyhash_t& owner, size_t offset, size_t count) const;
			expects_lr<states::validator_attestation> get_validator_attestation(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner) const;
			expects_lr<vector<states::validator_attestation>> get_validator_attestations(const algorithm::pubkeyhash_t& owner, size_t offset, size_t count) const;
			expects_lr<states::depository_reward> get_depository_reward(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner) const;
			expects_lr<states::depository_balance> get_depository_balance(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner) const;
			expects_lr<states::depository_policy> get_depository_policy(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner) const;
			expects_lr<vector<states::depository_account>> get_depository_accounts(const algorithm::pubkeyhash_t& manager, size_t offset, size_t count) const;
			expects_lr<states::depository_account> get_depository_account(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& manager, const algorithm::pubkeyhash_t& owner) const;
			expects_lr<states::witness_program> get_witness_program(const std::string_view& program_hashcode) const;
			expects_lr<states::witness_event> get_witness_event(const uint256_t& parent_transaction_hash) const;
			expects_lr<vector<states::witness_account>> get_witness_accounts(const algorithm::pubkeyhash_t& owner, size_t offset, size_t count) const;
			expects_lr<vector<states::witness_account>> get_witness_accounts_by_purpose(const algorithm::pubkeyhash_t& owner, states::witness_account::account_type purpose, size_t offset, size_t count) const;
			expects_lr<states::witness_account> get_witness_account(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, const std::string_view& address) const;
			expects_lr<states::witness_account> get_witness_account(const algorithm::asset_id& asset, const std::string_view& address, size_t offset) const;
			expects_lr<states::witness_account> get_witness_account_tagged(const algorithm::asset_id& asset, const std::string_view& address, size_t offset) const;
			expects_lr<states::witness_transaction> get_witness_transaction(const algorithm::asset_id& asset, const std::string_view& transaction_id) const;
			expects_lr<ledger::block_transaction> get_block_transaction_instance(const uint256_t& transaction_hash) const;
			uint64_t get_validation_nonce() const;
			uint256_t get_gas_use() const;
			uint256_t get_gas_left() const;
			decimal get_gas_cost() const;

		public:
			template <typename t>
			expects_lr<void> emit_event(format::variables&& values, bool paid = true)
			{
				return emit_event(t::as_instance_type(), std::move(values), paid);
			}
			template <typename t>
			expects_lr<ledger::block_transaction> get_block_transaction(const uint256_t& transaction_hash) const
			{
				auto transaction = get_block_transaction_instance(transaction_hash);
				if (!transaction)
					return transaction.error();

				if (transaction->transaction->as_type() != t::as_instance_type())
					return layer_exception("block transaction is not " + string(t::as_instance_typename()) + " transaction");

				return transaction;
			}

		public:
			static expects_lr<uint256_t> calculate_tx_gas(const ledger::transaction* transaction);
			static expects_lr<void> validate_tx(const ledger::transaction* new_transaction, const uint256_t& new_transaction_hash, algorithm::pubkeyhash_t& owner);
			static expects_lr<transaction_context> execute_tx(const ledger::evaluation_context* new_environment, ledger::block* new_block, block_changelog* changelog, const ledger::transaction* new_transaction, const uint256_t& new_transaction_hash, const algorithm::pubkeyhash_t& owner, size_t transaction_size, uint8_t execution_flags);
			static expects_promise_rt<void> dispatch_tx(dispatch_context* dispatcher, ledger::block_transaction* transaction);
		};

		struct dispatch_context
		{
			struct public_state
			{
				uptr<algorithm::composition::public_state> aggregator;
				ordered_set<algorithm::pubkeyhash_t> participants;

				bool load_message(format::ro_stream& stream);
				format::wo_stream as_message() const;
			};

			struct signature_state
			{
				uptr<algorithm::composition::signature_state> aggregator;
				ordered_set<algorithm::pubkeyhash_t> participants;
				uptr<warden::prepared_transaction> message;

				bool load_message_if_preferred(format::ro_stream& stream);
				format::wo_stream as_message() const;
			};

			ordered_map<uint256_t, string> errors;
			vector<uptr<transaction>> outputs;
			vector<uint256_t> inputs;
			vector<uint256_t> repeaters;

			dispatch_context() noexcept = default;
			dispatch_context(const dispatch_context& other) noexcept;
			dispatch_context(dispatch_context&&) noexcept = default;
			dispatch_context& operator=(const dispatch_context& other) noexcept;
			dispatch_context& operator=(dispatch_context&&) noexcept = default;
			virtual expects_lr<uint256_t> apply_group_share(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& validator, const algorithm::pubkeyhash_t& owner, const uint256_t& share);
			virtual expects_lr<uint256_t> recover_group_share(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& validator, const algorithm::pubkeyhash_t& owner) const;
			virtual expects_promise_rt<void> aggregate_validators(const uint256_t& transaction_hash, const ordered_set<algorithm::pubkeyhash_t>& validators) = 0;
			virtual expects_promise_rt<void> aggregate_public_state(const transaction_context* context, public_state& state, const algorithm::pubkeyhash_t& validator) = 0;
			virtual expects_promise_rt<void> aggregate_signature_state(const transaction_context* context, signature_state& state, const algorithm::pubkeyhash_t& validator) = 0;
			virtual expects_lr<void> checkpoint();
			virtual promise<void> dispatch_async(const block_header& target);
			virtual void dispatch_sync(const block_header& target);
			virtual void reset_for_checkpoint();
			virtual void emit_transaction(uptr<transaction>&& value);
			virtual void retry_later(const uint256_t& transaction_hash);
			virtual void report_trial(const uint256_t& transaction_hash);
			virtual void report_error(const uint256_t& transaction_hash, const std::string_view& error_message);
			virtual bool is_running_on(const algorithm::pubkeyhash_t& validator) const;
			virtual vector<uptr<transaction>>& get_sendable_transactions();
			virtual format::ro_stream pull_cache(const transaction_context* context);
			virtual void push_cache(const transaction_context* context, const format::wo_stream& message) const;
			virtual const wallet* get_wallet() const = 0;
		};

		struct evaluation_context
		{
			enum class include_decision
			{
				include_in_block,
				not_executable,
				not_includable
			};

			struct transaction_info
			{
				uint256_t hash = 0;
				algorithm::pubkeyhash_t owner;
				uptr<transaction> candidate;
				size_t size = 0;

				transaction_info() = default;
				transaction_info(const transaction_info& other);
				transaction_info(transaction_info&&) noexcept = default;
				transaction_info& operator= (const transaction_info& other);
				transaction_info& operator= (transaction_info&&) noexcept = default;
			};

			struct validation_info
			{
				transaction_context context;
				uint256_t current_gas_limit = 0;
				block_changelog changelog;
				bool tip = false;
			} validation;
			struct validator_context
			{
				algorithm::pubkeyhash_t public_key_hash;
				algorithm::seckey_t secret_key;
			} validator;
			option<block_header> tip = optional::none;
			ordered_map<algorithm::pubkeyhash_t, uint64_t> nonces;
			ordered_map<algorithm::asset_id, size_t> attesters;
			vector<states::validator_production> producers;
			vector<transaction_info> incoming;
			vector<uint256_t> outgoing;
			size_t precomputed = 0;

			option<uint64_t> configure_priority_from_validator(const algorithm::pubkeyhash_t& public_key_hash, const algorithm::seckey_t& secret_key, option<const block_header*>&& parent_block = optional::none);
			size_t try_include_transactions(vector<uptr<transaction>>&& candidates);
			transaction_info& force_include_transaction(uptr<transaction>&& candidate);
			include_decision decide_on_inclusion(const transaction_info& candidate, const uint256_t& current_gas_limit, const uint256_t& max_gas_limit) const;
			expects_lr<block_evaluation> evaluate_block(const replace_transaction_callback& callback);
			expects_lr<void> solve_evaluated_block(block& candidate);
			expects_lr<void> verify_solved_block(const block& candidate, const block_state* state);
			expects_lr<void> cleanup();
			static transaction_info precompute_transaction_element(uptr<transaction>&& candidate);
			static void precompute_transaction_list(vector<transaction_info>& candidates);
		};
	}
}
#endif