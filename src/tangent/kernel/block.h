#ifndef TAN_KERNEL_BLOCK_H
#define TAN_KERNEL_BLOCK_H
#include "wallet.h"
#include "../policy/states.h"

namespace tangent
{
	namespace superchain
	{
		struct prepared_transaction;
	}

	namespace ledger
	{
		struct block_header;
		struct block_body;
		struct block_proof;
		struct block_evaluation;
		struct solver_context;

		typedef btree_map<algorithm::asset_id, decimal> block_rewards;

		enum class filter_comparator : uint8_t
		{
			greater,
			greater_equal,
			equal,
			not_equal,
			less,
			less_equal
		};

		enum class filter_order : uint8_t
		{
			ascending,
			descending
		};

		enum class gas_cost
		{
			write_tx_byte = 64,
			write_byte = 32,
			erase_byte = 2,
			read_byte = 1,
			query_result = 8,
			program_byte = 16,
			program_memory = 1,
			program_iop = 3,
			program_mop = 16,
		};

		struct block_transaction final : messages::uniform
		{
			uptr<transaction_message> transaction;
			transaction_receipt receipt;

			block_transaction() = default;
			block_transaction(uptr<transaction_message>&& new_transaction, transaction_receipt&& new_receipt);
			block_transaction(block_transaction&&) noexcept = default;
			block_transaction(const block_transaction& other);
			block_transaction& operator= (block_transaction&&) noexcept = default;
			block_transaction& operator= (const block_transaction& other);
			bool store_payload(format::wo_stream* stream) const override;
			bool load_payload(format::ro_stream& stream) override;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct block_state
		{
			struct state_change
			{
				uptr<transition_state> state;
				bool erase;

				state_change() noexcept;
				state_change(uptr<transition_state>&& new_state, bool new_erase) noexcept;
				state_change(const state_change& other) noexcept;
				state_change(state_change&& other) noexcept;
				state_change& operator=(const state_change& other) noexcept;
				state_change& operator=(state_change&& other) noexcept;
				format::tree as_tree() const;
				bool empty() const;
			};

			btree_map<string, state_change> finalized;
			btree_map<string, state_change> pending;

			block_state() = default;
			block_state(const block_state& other);
			block_state(block_state&&) noexcept = default;
			block_state& operator= (const block_state& other);
			block_state& operator= (block_state&&) noexcept = default;
			option<uptr<transition_state>> find(uint32_t type, const std::string_view& index) const;
			option<uptr<transition_state>> find(uint32_t type, const std::string_view& column, const std::string_view& row) const;
			void erase(uint32_t type, const std::string_view& index);
			void erase(uint32_t type, const std::string_view& column, const std::string_view& row);
			bool push(transition_state* value, bool will_delete);
			bool emplace(uptr<transition_state>&& value, bool will_delete);
			string index_of(transition_state* value) const;
			string index_of(uint32_t type, const std::string_view& index) const;
			string index_of(uint32_t type, const std::string_view& column, const std::string_view& row) const;
			void revert(bool fully = false);
			void commit();
		};

		struct block_changelog
		{
			struct
			{
				hash_map<uint32_t, void*> topics;
				hash_map<string, string> effects;
			} temporary_state;
			struct
			{
				vector<task_callback> finalized;
				vector<task_callback> pending;
			} effects;
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
			btree_map<algorithm::asset_id, uint64_t> witnesses;
			uint256_t parent_hash = 0;
			uint256_t transaction_root = 0;
			uint256_t receipt_root = 0;
			uint256_t state_root = 0;
			uint256_t gas_use = 0;
			uint256_t gas_limit = 0;
			uint256_t absolute_work = 0;
			uint256_t slot_duration = 0;
			uint256_t slot_gas_use = 0;
			uint64_t difficulty = 0;
			uint64_t generation_time = 0;
			uint64_t evaluation_time = 0;
			uint64_t priority = 0;
			uint64_t number = 0;
			uint32_t transaction_count = 0;
			uint32_t transition_count = 0;

			virtual ~block_header() = default;
			virtual bool operator<(const block_header& other) const;
			virtual bool operator>(const block_header& other) const;
			virtual bool operator<=(const block_header& other) const;
			virtual bool operator>=(const block_header& other) const;
			virtual bool operator==(const block_header& other) const;
			virtual bool operator!=(const block_header& other) const;
			virtual expects_lr<void> verify_validity(const block_header* parent_block, const algorithm::pubkeyhash_t& recovered_producer = algorithm::pubkeyhash_t()) const;
			virtual bool store_payload(format::wo_stream* stream) const override;
			virtual bool load_payload(format::ro_stream& stream) override;
			virtual bool sign(const algorithm::seckey_t& secret_key) override;
			virtual bool solve(const algorithm::pubkeyhash_t& public_key_hash);
			virtual bool verify(const algorithm::pubkey_t& public_key) const override;
			virtual bool recover(algorithm::pubkey_t& public_key) const override;
			virtual bool recover_hash(algorithm::pubkeyhash_t& public_key_hash) const override;
			virtual bool verify_proof(const algorithm::pubkeyhash_t& public_key_hash) const;
			virtual void set_parent_block(const block_header* parent_block);
			virtual void set_witness_requirement(const algorithm::asset_id& asset, uint64_t block_number);
			virtual bool network_congestion() const;
			virtual decimal network_congestion_threshold() const;
			virtual uint64_t get_witness_requirement(const algorithm::asset_id& asset) const;
			virtual int8_t get_relative_order(const block_header& other) const;
			virtual uint64_t get_slot_proof_duration_average() const;
			virtual uint64_t get_slot_length() const;
			virtual uint64_t get_proof_duration() const;
			virtual uint64_t get_proof_accounted_duration() const;
			virtual decimal get_proof_difficulty_multiplier() const;
			virtual uint64_t get_proof_slot_target(const block_header* parent_block) const;
			virtual uint256_t as_hash(bool renew = false) const override;
			virtual format::tree as_tree() const override;
			virtual format::wo_stream as_signable() const override;
			virtual format::wo_stream as_solution(const algorithm::pubkeyhash_t& public_key_hash) const;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static uint256_t get_gas_limit();
			static uint256_t get_slot_gas_limit();
			static uint256_t get_gas_work(const uint256_t& gas_use, const uint256_t& gas_limit, uint64_t priority);
			static bool is_genesis_epoch(const uint64_t block_number);
			static decimal get_coinbase_value(const uint64_t block_number);
		};

		struct block_body final : block_header
		{
			vector<block_transaction> transactions;

			block_body() = default;
			block_body(const block_header& other);
			block_body(const block_body&) = default;
			block_body(block_body&&) = default;
			virtual ~block_body() override = default;
			block_body& operator=(const block_body&) = default;
			block_body& operator=(block_body&&) = default;
			expects_lr<void> verify_integrity(const block_header* parent_block, const block_state* state) const;
			bool store_payload(format::wo_stream* stream) const override;
			bool load_payload(format::ro_stream& stream) override;
			bool store_header_payload(format::wo_stream* stream) const;
			bool load_header_payload(format::ro_stream& stream);
			bool store_body_payload(format::wo_stream* stream) const;
			bool load_body_payload(format::ro_stream& stream);
			void recalculate(const block_header* parent_block, const block_state* state);
			format::tree as_tree() const override;
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
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct block_evaluation
		{
			block_body block;
			block_state state;
			vector<task_callback> effects;

			format::tree as_tree() const;
		};

		struct executor_context
		{
		public:
			enum class flags : uint8_t
			{
				pedantic = 1 << 0,
				evaluation = 1 << 1,
				replayable = 1 << 2,
				unrestricted = 1 << 3,
				congestion = 1 << 4
			};

			enum class staker : uint8_t
			{
				lock,
				reward_or_penalty,
				unlock
			};

		public:
			btree_map<algorithm::asset_id, uint64_t> witnesses;
			const solver_context* solver;
			const transaction_message* transaction;
			block_changelog* changelog;
			block_header* block;
			transaction_receipt receipt;
			uint8_t options;

		public:
			executor_context(block_changelog* new_changelog);
			executor_context(block_changelog* new_changelog, const solver_context* new_solver, block_header* new_block_header, const transaction_message* new_transaction, transaction_receipt&& new_receipt);
			executor_context(const executor_context& other);
			executor_context(executor_context&&) = default;
			executor_context& operator=(const executor_context& other);
			executor_context& operator=(executor_context&&) = default;
			void defer_side_effect(task_callback&& callback);
			expects_lr<void> query(transition_state* value, bool paid_in_full);
			expects_lr<void> load(transition_state* value, bool paid);
			expects_lr<void> store(transition_state* value, bool paid);
			expects_lr<void> emit_witness(const algorithm::asset_id& asset, uint64_t block_number);
			expects_lr<void> emit_event(uint32_t type, format::variables&& values, bool paid);
			expects_lr<void> burn_gas();
			expects_lr<void> burn_gas(const uint256_t& value);
			expects_lr<void> verify_account_nonce() const;
			expects_lr<void> verify_gas_transfer_balance() const;
			expects_lr<void> verify_transfer_balance(const algorithm::asset_id& asset, const decimal& value) const;
			expects_lr<algorithm::wesolowski::distribution> calculate_random(const uint256_t& seed);
			expects_lr<size_t> calculate_attesters_size(const algorithm::asset_id& asset) const;
			expects_lr<size_t> calculate_producers_size() const;
			expects_lr<vector<states::validator_production>> calculate_producers(size_t target_size);
			expects_lr<vector<states::validator_attestation>> calculate_attesters(const algorithm::asset_id& asset, size_t target_size);
			expects_lr<vector<states::validator_attestation>> calculate_attesters(const algorithm::asset_id& asset, size_t target_size, const decimal& fee_threshold, btree_set<algorithm::pubkeyhash_t>& exclusion);
			expects_lr<vector<states::validator_participation>> calculate_participants(size_t target_size, btree_set<algorithm::pubkeyhash_t>& exclusion);
			expects_lr<states::account_nonce> apply_account_nonce(const algorithm::pubkeyhash_t& owner, uint64_t nonce);
			expects_lr<states::account_program> apply_account_program(const algorithm::pubkeyhash_t& owner, const std::string_view& program_hashcode);
			expects_lr<states::account_uniform> apply_account_uniform(const algorithm::pubkeyhash_t& owner, const std::string_view& index, const std::string_view& data);
			expects_lr<states::account_multiform> apply_account_multiform(const algorithm::pubkeyhash_t& owner, const std::string_view& column, const std::string_view& row, const std::string_view& data, const uint256_t& filter);
			expects_lr<states::account_balance> apply_transfer(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, const decimal& supply, const decimal& reserve);
			expects_lr<states::account_balance> apply_fee_transfer(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, const decimal& value);
			expects_lr<states::account_balance> apply_payment(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& from, const algorithm::pubkeyhash_t& to, const decimal& value);
			expects_lr<states::validator_production> apply_validator_production(const algorithm::pubkeyhash_t& owner, staker type, const decimal& stake);
			expects_lr<states::validator_production_reward> apply_validator_production_reward(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, const decimal& reward);
			expects_lr<states::validator_participation> apply_validator_participation(const algorithm::pubkeyhash_t& owner, staker type, const decimal& stake);
			expects_lr<states::validator_participation_reward> apply_validator_participation_reward(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, const decimal& reward);
			expects_lr<states::validator_participation_ref> apply_validator_participation_ref(const algorithm::pubkeyhash_t& owner, const states::bridge_ref& ref, bool active);
			expects_lr<states::validator_attestation> apply_validator_attestation(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, staker type, const decimal& stake, const decimal& min_fee);
			expects_lr<states::validator_attestation_reward> apply_validator_attestation_reward(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, const decimal& reward);
			expects_lr<states::bridge_instance> apply_bridge_instance(const algorithm::asset_id& asset, const uint256_t& bridge_hash, uint8_t security_level, const decimal& fee);
			expects_lr<states::bridge_instance> apply_bridge_instance_log(const algorithm::asset_id& asset, const uint256_t& bridge_hash, const uint256_t& transaction_hash);
			expects_lr<states::bridge_instance> apply_bridge_instance_account(const algorithm::asset_id& asset, const uint256_t& bridge_hash, const algorithm::pubkeyhash_t& owner);
			expects_lr<states::bridge_queue> apply_bridge_queue(const algorithm::asset_id& asset, const uint256_t& bridge_hash, const uint256_t& transaction_hash, bool active);
			expects_lr<states::bridge_balance> apply_bridge_balance(const algorithm::asset_id& asset, const uint256_t& bridge_hash, const decimal& balance);
			expects_lr<states::bridge_account> apply_bridge_account(const algorithm::pubkeyhash_t& owner, const algorithm::asset_id& asset, const uint256_t& bridge_hash, const algorithm::composition::cpubkey_t& public_key, btree_set<algorithm::pubkeyhash_t>&& group);
			expects_lr<states::witness_program> apply_witness_program(const std::string_view& packed_program_code);
			expects_lr<states::witness_event> apply_witness_event(const uint256_t& parent_transaction_hash, const uint256_t& child_transaction_hash);
			expects_lr<states::witness_account> apply_witness_account(const algorithm::pubkeyhash_t& owner, const algorithm::asset_id& asset, const address_map& addresses);
			expects_lr<states::witness_account> apply_witness_routing_account(const algorithm::pubkeyhash_t& owner, const algorithm::asset_id& asset, const address_map& addresses);
			expects_lr<states::witness_account> apply_witness_bridge_account(const algorithm::pubkeyhash_t& owner, const algorithm::asset_id& asset, const uint256_t& bridge_hash, const address_map& addresses, bool active = true);
			expects_lr<states::witness_transaction> apply_witness_transaction(const algorithm::asset_id& asset, const std::string_view& transaction_id);
			expects_lr<states::account_nonce> get_account_nonce(const algorithm::pubkeyhash_t& owner) const;
			expects_lr<states::account_program> get_account_program(const algorithm::pubkeyhash_t& owner) const;
			expects_lr<states::account_uniform> get_account_uniform(const algorithm::pubkeyhash_t& owner, const std::string_view& index) const;
			expects_lr<states::account_multiform> get_account_multiform(const algorithm::pubkeyhash_t& owner, const std::string_view& column, const std::string_view& row) const;
			expects_lr<vector<uptr<states::account_multiform>>> get_account_multiforms_by_column(const algorithm::pubkeyhash_t& owner, const std::string_view& column, size_t offset, size_t count) const;
			expects_lr<vector<uptr<states::account_multiform>>> get_account_multiforms_by_column_filter(const algorithm::pubkeyhash_t& owner, const std::string_view& column, const filter_comparator& comparator, const uint256_t& filter_value, filter_order order, size_t offset, size_t count) const;
			expects_lr<vector<uptr<states::account_multiform>>> get_account_multiforms_by_row(const algorithm::pubkeyhash_t& owner, const std::string_view& row, size_t offset, size_t count) const;
			expects_lr<vector<uptr<states::account_multiform>>> get_account_multiforms_by_row_filter(const algorithm::pubkeyhash_t& owner, const std::string_view& row, const filter_comparator& comparator, const uint256_t& filter_value, filter_order order, size_t offset, size_t count) const;
			expects_lr<states::account_balance> get_account_balance(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner) const;
			expects_lr<states::validator_production> get_validator_production(const algorithm::pubkeyhash_t& owner) const;
			expects_lr<states::validator_production_reward> get_validator_production_reward(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner) const;
			expects_lr<vector<states::validator_production_reward>> get_validator_production_rewards(const algorithm::pubkeyhash_t& owner, size_t offset, size_t count) const;
			expects_lr<states::validator_participation> get_validator_participation(const algorithm::pubkeyhash_t& owner) const;
			expects_lr<states::validator_participation_reward> get_validator_participation_reward(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner) const;
			expects_lr<vector<states::validator_participation_reward>> get_validator_participation_rewards(const algorithm::pubkeyhash_t& owner, size_t offset, size_t count) const;
			expects_lr<vector<states::validator_participation_ref>> get_validator_participation_refs(const algorithm::pubkeyhash_t& owner, size_t offset, size_t count) const;
			expects_lr<states::validator_attestation> get_validator_attestation(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner) const;
			expects_lr<states::validator_attestation> get_verified_validator_attestation(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner) const;
			expects_lr<vector<states::validator_attestation>> get_validator_attestations(const algorithm::pubkeyhash_t& owner, size_t offset, size_t count) const;
			expects_lr<states::validator_attestation_reward> get_validator_attestation_reward(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner) const;
			expects_lr<vector<states::validator_attestation_reward>> get_validator_attestation_rewards(const algorithm::pubkeyhash_t& owner, size_t offset, size_t count) const;
			expects_lr<states::bridge_instance> get_bridge_instance(const algorithm::asset_id& asset, const uint256_t& bridge_hash) const;
			expects_lr<vector<states::bridge_instance>> get_bridge_instances(const algorithm::asset_id& asset, size_t offset, size_t count) const;
			expects_lr<states::bridge_queue> get_bridge_queue(const algorithm::asset_id& asset, const uint256_t& bridge_hash, int8_t side = 1) const;
			expects_lr<states::bridge_balance> get_bridge_balance(const algorithm::asset_id& asset, const uint256_t& bridge_hash) const;
			expects_lr<vector<states::bridge_balance>> get_bridge_balances(const uint256_t& bridge_hash, size_t offset, size_t count) const;
			expects_lr<vector<states::bridge_account>> get_bridge_accounts(const uint256_t& bridge_hash, size_t offset, size_t count) const;
			expects_lr<states::bridge_account> get_bridge_account(const algorithm::pubkeyhash_t& owner, const algorithm::asset_id& asset, const uint256_t& bridge_hash) const;
			expects_lr<states::witness_program> get_witness_program(const std::string_view& program_hashcode) const;
			expects_lr<states::witness_event> get_witness_event(const uint256_t& parent_transaction_hash) const;
			expects_lr<vector<states::witness_account>> get_witness_accounts(const algorithm::pubkeyhash_t& owner, size_t offset, size_t count) const;
			expects_lr<vector<states::witness_account>> get_witness_accounts_by_purpose(const algorithm::pubkeyhash_t& owner, states::witness_account::account_type purpose, size_t offset, size_t count) const;
			expects_lr<states::witness_account> get_witness_account(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, const std::string_view& address) const;
			expects_lr<states::witness_account> get_witness_account(const algorithm::asset_id& asset, const std::string_view& address, size_t offset) const;
			expects_lr<states::witness_account> get_witness_account_tagged(const algorithm::asset_id& asset, const std::string_view& address, size_t offset) const;
			expects_lr<states::witness_transaction> get_witness_transaction(const algorithm::asset_id& asset, const std::string_view& transaction_id) const;
			expects_lr<block_transaction> get_block_transaction_instance(const uint256_t& transaction_hash, bool may_have_distinct_asset = false) const;
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
			expects_lr<block_transaction> get_block_transaction(const uint256_t& transaction_hash, bool may_have_distinct_asset = false) const
			{
				auto result = get_block_transaction_instance(transaction_hash, may_have_distinct_asset);
				if (!result)
					return result.error();

				if (result->transaction->as_type() != t::as_instance_type())
					return layer_exception("block transaction is not " + string(t::as_instance_typename()) + " transaction");

				return result;
			}

		public:
			static expects_lr<uint256_t> calculate_tx_gas(const transaction_message* transaction, transaction_receipt* out_receipt = nullptr);
			static expects_lr<void> validate_tx(const transaction_message* new_transaction, const uint256_t& new_transaction_hash, algorithm::pubkeyhash_t& owner);
			static expects_lr<executor_context> execute_tx(const solver_context* new_solver, ledger::block_header* new_block, block_changelog* changelog, const transaction_message* new_transaction, const uint256_t& new_transaction_hash, const algorithm::pubkeyhash_t& owner, size_t transaction_size, uint8_t execution_flags, option<transaction_receipt>&& from_receipt = optional::none);
			static expects_promise_rt<void> dispatch_tx(dispatcher_context* dispatcher, block_transaction* transaction);
		};

		struct dispatcher_context
		{
			struct secret_entropy : messages::uniform
			{
				struct share_pair
				{
					algorithm::share_t input;
					algorithm::share_t output;
				};

				algorithm::pubkeyhash_t owner;
				algorithm::asset_id asset;
				uint256_t hash;
				algorithm::storage_type<uint8_t, 64> entropy;
				btree_map<algorithm::pubkeyhash_t, share_pair> shares;

				bool store_payload(format::wo_stream* stream) const override;
				bool load_payload(format::ro_stream& stream) override;
				format::tree as_tree() const override;
				uint32_t as_type() const override;
				std::string_view as_typename() const override;
				uint256_t as_ref_hash() const;
				static uint32_t as_instance_type();
				static std::string_view as_instance_typename();
				static uint256_t ref_hash(const algorithm::pubkeyhash_t& owner, const algorithm::asset_id& asset, const uint256_t& hash);
			};

			struct entropy_distribution_state
			{
				btree_map<algorithm::pubkeyhash_t, string> encrypted_shares;

				bool load_message(format::ro_stream& stream);
				format::wo_stream as_message() const;
			};

			struct entropy_aggregation_state
			{
				btree_map<uint256_t, btree_map<algorithm::pubkeyhash_t, string>> encrypted_shares;
				btree_set<algorithm::pubkeyhash_t> participants;
				algorithm::pubkey_t public_key;
				uint8_t attempt = 0;

				bool load_message(format::ro_stream& stream);
				format::wo_stream as_message() const;
			};

			struct entropy_recovery_state
			{
				btree_map<uint256_t, btree_map<algorithm::pubkeyhash_t, string>> encrypted_shares;
				btree_map<uint256_t, string> encrypted_entropies;
				algorithm::hashsig_t proof;

				bool load_message(format::ro_stream& stream);
				format::wo_stream as_message() const;
			};

			struct public_state
			{
				uptr<algorithm::composition::compositor> compositor;
				btree_map<algorithm::pubkey_t, btree_map<algorithm::pubkeyhash_t, string>> encrypted_shares;
				btree_set<algorithm::pubkeyhash_t> participants;
				algorithm::composition::type alg;
				uint8_t attempt = 0;
				bool distribution = false;

				bool load_compositor_transition(format::ro_stream& stream);
				bool load(format::ro_stream& stream);
				format::wo_stream as_message() const;
			};

			struct signature_state
			{
				uptr<algorithm::composition::compositor> compositor;
				btree_set<algorithm::pubkeyhash_t> participants;
				uptr<superchain::prepared_transaction> message;
				algorithm::composition::type alg;
				uint8_t attempt = 0;

				bool load_compositor_transition(format::ro_stream& stream);
				bool load(format::ro_stream& stream);
				format::wo_stream as_message() const;
			};

			btree_map<uint256_t, string> errors;
			vector<std::pair<const ledger::wallet*, uptr<transaction_message>>> outputs;
			vector<uint256_t> inputs;
			vector<uint256_t> repeaters;

			dispatcher_context() noexcept = default;
			dispatcher_context(const dispatcher_context& other) noexcept;
			dispatcher_context(dispatcher_context&&) noexcept = default;
			dispatcher_context& operator=(const dispatcher_context& other) noexcept;
			dispatcher_context& operator=(dispatcher_context&&) noexcept = default;
			virtual expects_lr<secret_entropy> apply_secret_entropy(const wallet* runner_wallet, const algorithm::pubkeyhash_t& owner, const algorithm::asset_id& asset, const uint256_t& hash, const algorithm::storage_type<uint8_t, 64>& entropy, btree_map<algorithm::pubkeyhash_t, secret_entropy::share_pair>&& shares);
			virtual expects_lr<secret_entropy> recover_secret_entropy(const wallet* runner_wallet, const algorithm::pubkeyhash_t& owner, const algorithm::asset_id& asset, const uint256_t& hash);
			virtual expects_promise_rt<void> aggregate_validators(const btree_set<algorithm::pubkeyhash_t>& validators) = 0;
			virtual expects_promise_rt<void> distribute_entropy_shares(const executor_context* executor, entropy_distribution_state& state, const algorithm::pubkeyhash_t& validator, const algorithm::pubkeyhash_t& authority) = 0;
			virtual expects_promise_rt<void> aggregate_entropy_shares(const executor_context* executor, entropy_aggregation_state& state, const algorithm::pubkeyhash_t& validator, const algorithm::pubkeyhash_t& authority) = 0;
			virtual expects_promise_rt<void> recover_entropy(const executor_context* executor, entropy_recovery_state& state, const algorithm::pubkeyhash_t& validator, const algorithm::pubkeyhash_t& authority) = 0;
			virtual expects_promise_rt<void> aggregate_public_key(const executor_context* executor, public_state& state, const algorithm::pubkeyhash_t& validator, const algorithm::pubkeyhash_t& authority) = 0;
			virtual expects_promise_rt<void> aggregate_signature(const executor_context* executor, signature_state& state, const algorithm::pubkeyhash_t& validator, const algorithm::pubkeyhash_t& authority) = 0;
			virtual expects_lr<void> checkpoint();
			virtual promise<void> dispatch_async(uint64_t block_number);
			virtual void dispatch_sync(uint64_t block_number);
			virtual void reset_for_checkpoint();
			virtual void emit_transaction(const wallet* runner_wallet, uptr<transaction_message>&& value);
			virtual void retry_later(const uint256_t& transaction_hash);
			virtual void report_trial(const uint256_t& transaction_hash);
			virtual void report_error(const uint256_t& transaction_hash, const std::string_view& error_message);
			virtual vector<std::pair<const ledger::wallet*, uptr<transaction_message>>>& get_sendable_transactions();
			virtual format::ro_stream pull_cache(const executor_context* executor);
			virtual void push_cache(const executor_context* executor, const format::wo_stream& message) const;
			virtual algorithm::pubkey_t get_public_key(const algorithm::pubkeyhash_t& validator) const = 0;
			virtual const wallet* get_runner_wallet(const algorithm::pubkeyhash_t& validator) const = 0;
		};

		struct solver_context
		{
			enum class include_decision
			{
				include_in_block,
				not_executable,
				not_includable
			};

			enum class state_origin
			{
				chain,
				chain_block,
				block
			};

			struct queued_transaction
			{
				uint256_t hash = 0;
				algorithm::pubkeyhash_t owner;
				uptr<transaction_message> candidate;
				size_t size = 0;

				queued_transaction() = default;
				queued_transaction(const queued_transaction& other);
				queued_transaction(queued_transaction&&) noexcept = default;
				queued_transaction& operator= (const queued_transaction& other);
				queued_transaction& operator= (queued_transaction&&) noexcept = default;
			};

			struct state_variables
			{
				algorithm::pubkeyhash_t public_key_hash;
				algorithm::seckey_t secret_key;
				uint256_t gas_usage = 0;
				uint8_t block_options = 0;
				bool validator_active = true;
				block_changelog changelog;
				executor_context executor = executor_context(&changelog);
				state_origin origin = state_origin::chain;
			} state;
			struct transaction_queue
			{
				vector<queued_transaction> pending;
				hash_set<uint256_t> failed;
				size_t queued = 0;
			} transactions;
			option<block_header> tip = optional::none;
			btree_map<algorithm::pubkeyhash_t, uint64_t> nonces;
			vector<states::validator_production> producers;

			void apply_temporary_state(block_header* abstract_block, const transaction_message* abstract_transaction, transaction_receipt&& abstract_receipt);
			option<uint64_t> apply_validator_state(const std::function<ledger::wallet* (size_t)>& try_producer, option<const block_header*>&& parent_block = optional::none);
			size_t try_include_transactions(vector<uptr<transaction_message>>&& candidates, hash_set<uint256_t>* hashes = nullptr);
			queued_transaction& force_include_transaction(uptr<transaction_message>&& candidate);
			include_decision decide_on_inclusion(const queued_transaction& candidate, const uint256_t& current_gas_limit, const uint256_t& max_gas_limit) const;
			expects_lr<void> block_evalution_prepare(block_evaluation& solution);
			expects_lr<void> block_evalution_update(block_evaluation& solution, block_rewards& rewards);
			expects_lr<void> block_evalution_finalize(block_evaluation& solution, block_rewards& rewards);
			expects_lr<block_evaluation> evaluate_block_inline();
			expects_lr<void> block_solution_solve(block_evaluation& evaluation);
			expects_lr<void> block_solution_sign(block_evaluation& evaluation);
			expects_lr<void> solve_block_inline(block_evaluation& evaluation);
			expects_lr<void> verify_block(const block_evaluation& solution, const algorithm::pubkeyhash_t& recovered_producer = algorithm::pubkeyhash_t());
			expects_lr<block_checkpoint> checkpoint_block(block_evaluation& solution, bool keep_reverted_transactions = true);
			expects_lr<void> erase_failed_transactions();
			bool can_accept_more_transactions();
			static expects_lr<void> solve_evaluated_block(block_evaluation& evaluation, const algorithm::pubkeyhash_t& public_key_hash, const algorithm::seckey_t& secret_key);
			static expects_lr<void> verify_solved_block(const block_header* parent_block, const block_evaluation& solution, const algorithm::pubkeyhash_t& recovered_producer = algorithm::pubkeyhash_t());
			static expects_lr<void> validate_solved_block(const block_header* parent_block, const block_body& child_block, block_evaluation* evaluated_result = nullptr);
			static expects_lr<block_checkpoint> checkpoint_solved_block(block_evaluation& solution, bool keep_reverted_transactions = true);
			static queued_transaction precompute_transaction_element(uptr<transaction_message>&& candidate);
			static void precompute_transaction_list(vector<queued_transaction>& candidates);
			static void sort_transaction_list(vector<uptr<transaction_message>>& candidates);
			static bool requires_reorganization(const block_evaluation& solution);
		};
	}
}
#endif