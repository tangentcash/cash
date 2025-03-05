#ifndef TAN_KERNEL_BLOCK_H
#define TAN_KERNEL_BLOCK_H
#include "wallet.h"
#include "../policy/states.h"

namespace tangent
{
	namespace ledger
	{
		struct block;
		struct block_header;
		struct block_proof;
		struct evaluation_context;

		typedef ordered_map<string, uptr<ledger::state>> state_work;

		enum class gas_cost
		{
			write_byte = 24,
			read_byte = 3,
			opcode = 1
		};

		enum class work_commitment
		{
			pending,
			finalized,
			__Count__
		};

		struct block_transaction final : messages::standard
		{
			uptr<ledger::transaction> transaction;
			ledger::receipt receipt;

			block_transaction() = default;
			block_transaction(uptr<ledger::transaction>&& new_transaction, ledger::receipt&& new_receipt);
			block_transaction(block_transaction&&) noexcept = default;
			block_transaction(const block_transaction& other);
			block_transaction& operator= (block_transaction&&) noexcept = default;
			block_transaction& operator= (const block_transaction& other);
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct block_work
		{
			state_work map[(size_t)work_commitment::__Count__];
			const block_work* parent_work = nullptr;

			block_work() = default;
			block_work(const block_work& other);
			block_work(block_work&&) noexcept = default;
			block_work& operator= (const block_work& other);
			block_work& operator= (block_work&&) noexcept = default;
			option<uptr<state>> find_uniform(const std::string_view& index) const;
			option<uptr<state>> find_multiform(const std::string_view& column, const std::string_view& row) const;
			void clear_uniform(const std::string_view& index);
			void clear_multiform(const std::string_view& column, const std::string_view& row);
			void copy_any(state* value);
			void move_any(uptr<state>&& value);
			const state_work& at(work_commitment level) const;
			state_work& clear();
			state_work& rollback();
			state_work& commit();
		};

		struct block_mutation
		{
			block_work cache;
			block_work* outgoing;
			block_work* incoming;

			block_mutation() noexcept;
			block_mutation(const block_mutation& other) noexcept;
			block_mutation(block_mutation&& other) noexcept;
			block_mutation& operator=(const block_mutation& other) noexcept;
			block_mutation& operator=(block_mutation&& other) noexcept;
		};

		struct block_dispatch
		{
			ordered_map<uint256_t, string> errors;
			vector<uint256_t> repeaters;
			vector<uint256_t> inputs;
			vector<uptr<transaction>> outputs;

			block_dispatch() noexcept = default;
			block_dispatch(const block_dispatch& other) noexcept;
			block_dispatch(block_dispatch&&) noexcept = default;
			block_dispatch& operator=(const block_dispatch& other) noexcept;
			block_dispatch& operator=(block_dispatch&&) noexcept = default;
			expects_lr<void> checkpoint() const;
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
			algorithm::wesolowski::digest wesolowski;
			algorithm::wesolowski::parameters target;
			ordered_map<algorithm::asset_id, uint64_t> witnesses;
			uint256_t parent_hash = 0;
			uint256_t transaction_root = 0;
			uint256_t receipt_root = 0;
			uint256_t state_root = 0;
			uint256_t gas_use = 0;
			uint256_t gas_limit = 0;
			uint256_t absolute_work = 0;
			uint256_t slot_gas_use = 0;
			uint256_t slot_gas_target = 0;
			uint256_t slot_duration = 0;
			uint8_t recovery = 0;
			uint64_t time = 0;
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
			virtual expects_lr<block_dispatch> dispatch_sync(const wallet& proposer) const;
			virtual expects_promise_lr<block_dispatch> dispatch_async(const wallet& proposer) const;
			virtual expects_lr<void> verify_validity(const block_header* parent_block) const;
			virtual bool store_payload_wesolowski(format::stream* stream) const;
			virtual bool load_payload_wesolowski(format::stream& stream);
			virtual bool store_payload(format::stream* stream) const override;
			virtual bool load_payload(format::stream& stream) override;
			virtual bool sign(const algorithm::seckey secret_key) override;
			virtual bool solve(const algorithm::seckey secret_key);
			virtual bool verify(const algorithm::pubkey public_key) const override;
			virtual bool recover(algorithm::pubkey public_key) const override;
			virtual bool recover_hash(algorithm::pubkeyhash public_key_hash) const override;
			virtual bool verify_wesolowski() const;
			virtual void set_parent_block(const block_header* parent_block);
			virtual void set_witness_requirement(const algorithm::asset_id& asset, uint64_t block_number);
			virtual uint64_t get_witness_requirement(const algorithm::asset_id& asset) const;
			virtual int8_t get_relative_order(const block_header& other) const;
			virtual uint256_t get_slot_gas_use() const;
			virtual uint256_t get_slot_gas_target() const;
			virtual uint64_t get_slot_duration() const;
			virtual uint64_t get_slot_length() const;
			virtual uint64_t get_duration() const;
			virtual uint64_t get_proof_time() const;
			virtual uint256_t as_hash(bool renew = false) const override;
			virtual uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static uint256_t get_gas_limit();
		};

		struct block final : block_header
		{
			vector<block_transaction> transactions;
			block_work states;

			block() = default;
			block(const block_header& other);
			block(const block&) = default;
			block(block&&) = default;
			virtual ~block() override = default;
			block& operator=(const block&) = default;
			block& operator=(block&&) = default;
			expects_lr<void> evaluate(const block_header* parent_block, evaluation_context* environment, string* errors = nullptr);
			expects_lr<void> validate(const block_header* parent_block, block* evaluated_block = nullptr) const;
			expects_lr<void> verify_integrity(const block_header* parent_block) const;
			expects_lr<block_checkpoint> checkpoint(bool keep_reverted_transactions = true) const;
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			bool store_header_payload(format::stream* stream) const;
			bool load_header_payload(format::stream& stream);
			bool store_body_payload(format::stream* stream) const;
			bool load_body_payload(format::stream& stream);
			void recalculate(const block_header* parent_block);
			void inherit_work(const block* parent_block);
			void inherit_work(const block_work* parent_work);
			uptr<schema> as_schema() const override;
			block_header as_header() const;
			block_proof as_proof(const block_header* parent_block) const;
			uint256_t as_hash(bool renew = false) const override;
		};

		struct block_proof final : messages::standard
		{
			struct internal_state
			{
				algorithm::merkle_tree transactions_tree;
				algorithm::merkle_tree receipts_tree;
				algorithm::merkle_tree states_tree;
			} internal;
			vector<uint256_t> transactions;
			vector<uint256_t> receipts;
			vector<uint256_t> states;
			uint256_t transaction_root = 0;
			uint256_t receipt_root = 0;
			uint256_t state_root = 0;

			block_proof(const block_header& from_block, const block_header* from_parent_block);
			option<algorithm::merkle_tree::path> find_transaction(const uint256_t& hash);
			option<algorithm::merkle_tree::path> find_receipt(const uint256_t& hash);
			option<algorithm::merkle_tree::path> find_state(const uint256_t& hash);
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			bool has_transaction(const uint256_t& hash);
			bool has_receipt(const uint256_t& hash);
			bool has_state(const uint256_t& hash);
			algorithm::merkle_tree& get_transactions_tree();
			algorithm::merkle_tree& get_receipts_tree();
			algorithm::merkle_tree& get_states_tree();
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct transaction_context
		{
		public:
			enum class execution_flags : uint8_t
			{
				only_successful = 1 << 0,
				skip_sequencing = 1 << 1
			};

		public:
			ordered_map<algorithm::asset_id, uint64_t> witnesses;
			const evaluation_context* environment;
			const ledger::transaction* transaction;
			ledger::block_header* block;
			ledger::receipt receipt;
			block_mutation delta;

		public:
			transaction_context();
			transaction_context(ledger::block* new_block);
			transaction_context(ledger::block_header* new_block_header);
			transaction_context(ledger::block* new_block, const ledger::evaluation_context* new_environment, const ledger::transaction* new_transaction, ledger::receipt&& new_receipt);
			transaction_context(ledger::block_header* new_block_header, const ledger::evaluation_context* new_environment, const ledger::transaction* new_transaction, ledger::receipt&& new_receipt);
			transaction_context(const transaction_context& other);
			transaction_context(transaction_context&&) = default;
			transaction_context& operator=(const transaction_context& other);
			transaction_context& operator=(transaction_context&&) = default;
			expects_lr<void> load(state* value, bool paid = true);
			expects_lr<void> store(state* value, bool paid = true);
			expects_lr<void> emit_witness(const algorithm::asset_id& asset, uint64_t block_number);
			expects_lr<void> emit_event(uint32_t type, format::variables&& values, bool paid = true);
			expects_lr<void> burn_gas();
			expects_lr<void> burn_gas(const uint256_t& value);
			expects_lr<void> verify_account_sequence() const;
			expects_lr<void> verify_gas_transfer_balance() const;
			expects_lr<void> verify_transfer_balance(const algorithm::asset_id& asset, const decimal& value) const;
			expects_lr<void> verify_account_work(const algorithm::pubkeyhash owner) const;
			expects_lr<void> verify_account_depository_work(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner) const;
			expects_lr<algorithm::wesolowski::distribution> calculate_random(const uint256_t& seed);
			expects_lr<size_t> calculate_aggregation_committee_size(const algorithm::asset_id& asset);
			expects_lr<vector<states::account_work>> calculate_proposal_committee(size_t target_size);
			expects_lr<vector<states::account_work>> calculate_sharing_committee(ordered_set<string>& hashset, size_t required_size);
			expects_lr<states::account_sequence> apply_account_sequence(const algorithm::pubkeyhash owner, uint64_t sequence);
			expects_lr<states::account_work> apply_account_work(const algorithm::pubkeyhash owner, states::account_flags flags, uint64_t penalty, const uint256_t& gas_input, const uint256_t& gas_output);
			expects_lr<states::account_observer> apply_account_observer(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, bool observing);
			expects_lr<states::account_program> apply_account_program(const algorithm::pubkeyhash owner, const std::string_view& program_hashcode);
			expects_lr<states::account_storage> apply_account_storage(const algorithm::pubkeyhash owner, const std::string_view& location, const std::string_view& storage);
			expects_lr<states::account_reward> apply_account_reward(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const decimal& incoming_absolute_fee, const decimal& incoming_relative_fee, const decimal& outgoing_absolute_fee, const decimal& outgoing_relative_fee);
			expects_lr<states::account_derivation> apply_account_derivation(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, uint64_t max_address_index);
			expects_lr<states::account_depository> apply_account_depository_custody(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const decimal& custody);
			expects_lr<states::account_depository> apply_account_depository_change(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const decimal& custody, address_value_map&& contributions, account_value_map&& reservations);
			expects_lr<states::account_depository> apply_account_depository_transaction(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const uint256_t& transaction_hash, int8_t direction);
			expects_lr<states::witness_program> apply_witness_program(const std::string_view& packed_program_code);
			expects_lr<states::witness_event> apply_witness_event(const uint256_t& parent_transaction_hash, const uint256_t& child_transaction_hash);
			expects_lr<states::witness_address> apply_witness_address(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const algorithm::pubkeyhash proposer, const address_map& addresses, uint64_t address_index, states::address_type purpose);
			expects_lr<states::witness_transaction> apply_witness_transaction(const algorithm::asset_id& asset, const std::string_view& transaction_id);
			expects_lr<states::account_balance> apply_transfer(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const decimal& supply, const decimal& reserve);
			expects_lr<states::account_balance> apply_payment(const algorithm::asset_id& asset, const algorithm::pubkeyhash from, const algorithm::pubkeyhash to, const decimal& value);
			expects_lr<states::account_balance> apply_funding(const algorithm::asset_id& asset, const algorithm::pubkeyhash from, const algorithm::pubkeyhash to, const decimal& value);
			expects_lr<states::account_sequence> get_account_sequence(const algorithm::pubkeyhash owner) const;
			expects_lr<states::account_work> get_account_work(const algorithm::pubkeyhash owner) const;
			expects_lr<states::account_observer> get_account_observer(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner) const;
			expects_lr<vector<states::account_observer>> get_account_observers(const algorithm::pubkeyhash owner, size_t offset, size_t count) const;
			expects_lr<states::account_program> get_account_program(const algorithm::pubkeyhash owner) const;
			expects_lr<states::account_storage> get_account_storage(const algorithm::pubkeyhash owner, const std::string_view& location) const;
			expects_lr<states::account_reward> get_account_reward(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner) const;
			expects_lr<states::account_derivation> get_account_derivation(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner) const;
			expects_lr<states::account_balance> get_account_balance(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner) const;
			expects_lr<states::account_depository> get_account_depository(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner) const;
			expects_lr<states::witness_program> get_witness_program(const std::string_view& program_hashcode) const;
			expects_lr<states::witness_event> get_witness_event(const uint256_t& parent_transaction_hash) const;
			expects_lr<vector<states::witness_address>> get_witness_addresses(const algorithm::pubkeyhash owner, size_t offset, size_t count) const;
			expects_lr<vector<states::witness_address>> get_witness_addresses_by_purpose(const algorithm::pubkeyhash owner, states::address_type purpose, size_t offset, size_t count) const;
			expects_lr<states::witness_address> get_witness_address(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const std::string_view& address, uint64_t address_index) const;
			expects_lr<states::witness_address> get_witness_address(const algorithm::asset_id& asset, const std::string_view& address, uint64_t address_index, size_t offset) const;
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
			static expects_lr<void> validate_tx(const ledger::transaction* new_transaction, const uint256_t& new_transaction_hash, algorithm::pubkeyhash owner);
			static expects_lr<transaction_context> execute_tx(ledger::block* new_block, const ledger::evaluation_context* new_environment, const ledger::transaction* new_transaction, const uint256_t& new_transaction_hash, const algorithm::pubkeyhash owner, block_work& cache, size_t transaction_size, uint8_t flags);
			static expects_lr<uint256_t> calculate_tx_gas(const ledger::transaction* transaction);
			static expects_promise_rt<void> dispatch_tx(const wallet& proposer, ledger::block_transaction* transaction, vector<uptr<ledger::transaction>>* pipeline);
		};

		struct evaluation_context
		{
			struct transaction_info
			{
				uint256_t hash = 0;
				algorithm::pubkeyhash owner = { 0 };
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
				uint256_t cumulative_gas = 0;
				block_work cache;
				bool tip = false;
			} validation;
			struct proposer_context
			{
				algorithm::pubkeyhash public_key_hash = { 0 };
				algorithm::seckey secret_key = { 0 };
			} proposer;
			option<block_header> tip = optional::none;
			ordered_map<algorithm::asset_id, size_t> aggregators;
			vector<states::account_work> proposers;
			vector<transaction_info> incoming;
			vector<uint256_t> outgoing;
			size_t precomputed = 0;

			option<uint64_t> priority(const algorithm::pubkeyhash public_key_hash, const algorithm::seckey secret_key, option<block_header*>&& parent_block = optional::none);
			size_t apply(vector<uptr<transaction>>&& candidates);
			transaction_info& include(uptr<transaction>&& candidate);
			expects_lr<block> evaluate(string* errors = nullptr);
			expects_lr<void> solve(block& candidate);
			expects_lr<void> verify(const block& candidate);
			expects_lr<void> precompute(block& candidate);
			expects_lr<void> cleanup();

		private:
			void precompute(vector<transaction_info>& candidates);
		};
	}
}
#endif