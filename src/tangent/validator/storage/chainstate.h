#ifndef TAN_STORAGE_CHAINSTATE_H
#define TAN_STORAGE_CHAINSTATE_H
#include "engine.h"
#include "../../kernel/block.h"

namespace tangent
{
	namespace storages
	{
		enum class position_condition
		{
			greater,
			greater_equal,
			equal,
			not_equal,
			less,
			less_equal
		};

		enum class block_details
		{
			transactions = 1 << 0,
			block_transactions = 1 << 1,
			states = 1 << 2
		};

		enum class pruning
		{
			block = 1 << 0,
			transaction = 1 << 1,
			state = 1 << 2
		};

		struct block_pair
		{
			uint64_t number;
			bool hidden;

			block_pair() = default;
			block_pair(const block_pair&) = default;
			block_pair(block_pair&&) noexcept = default;
			block_pair(uint64_t new_number, bool new_hidden) : number(new_number), hidden(new_hidden)
			{
			}
			block_pair& operator=(const block_pair&) = default;
			block_pair& operator=(block_pair&&) noexcept = default;
		};

		class account_cache : public singleton<account_cache>
		{
		private:
			unordered_map<algorithm::pubkeyhash_t, uint64_t> accounts;
			std::mutex mutex;

		public:
			account_cache() = default;
			virtual ~account_cache() = default;
			void clear_locations();
			void clear_account_location(const algorithm::pubkeyhash_t& account);
			void set_account_location(const algorithm::pubkeyhash_t& account, uint64_t location);
			option<uint64_t> get_account_location(const algorithm::pubkeyhash_t& account);
		};

		class uniform_cache : public singleton<uniform_cache>
		{
		private:
			unordered_map<string, uint64_t> indices;
			unordered_map<string, block_pair> blocks;
			std::mutex mutex;

		public:
			uniform_cache() = default;
			virtual ~uniform_cache() = default;
			void clear_locations();
			void clear_uniform_location(uint32_t type, const std::string_view& index);
			void clear_block_location(uint32_t type, const std::string_view& index);
			void set_index_location(uint32_t type, const std::string_view& index, uint64_t location);
			void set_block_location(uint32_t type, uint64_t location, uint64_t block_number, bool hidden);
			option<uint64_t> get_index_location(uint32_t type, const std::string_view& index);
			option<block_pair> get_block_location(uint32_t type, uint64_t location);

		private:
			string key_of_indices(uint32_t type, const std::string_view& index);
			string key_of_blocks(uint32_t type, uint64_t location);
		};

		class multiform_cache : public singleton<multiform_cache>
		{
		private:
			unordered_map<string, uint64_t> columns;
			unordered_map<string, uint64_t> rows;
			unordered_map<string, block_pair> blocks;
			std::mutex mutex;

		public:
			multiform_cache() = default;
			virtual ~multiform_cache() = default;
			void clear_locations();
			void clear_multiform_location(uint32_t type, const std::string_view& column, const std::string_view& row);
			void clear_block_location(uint32_t type, const std::string_view& column, const std::string_view& row);
			void set_multiform_location(uint32_t type, const std::string_view& column, const std::string_view& row, uint64_t column_location, uint64_t row_location);
			void set_column_location(uint32_t type, const std::string_view& column, uint64_t location);
			void set_row_location(uint32_t type, const std::string_view& row, uint64_t location);
			void set_block_location(uint32_t type, uint64_t column_location, uint64_t row_location, uint64_t block_number, bool hidden);
			option<uint64_t> get_column_location(uint32_t type, const std::string_view& column);
			option<uint64_t> get_row_location(uint32_t type, const std::string_view& row);
			option<block_pair> get_block_location(uint32_t type, uint64_t column_location, uint64_t row_location);

		private:
			string key_of_columns(uint32_t type, const std::string_view& column);
			string key_of_rows(uint32_t type, const std::string_view& row);
			string key_of_blocks(uint32_t type, uint64_t column_location, uint64_t row_location);
		};

		struct result_filter
		{
			position_condition condition = position_condition::equal;
			uint256_t value = 0;
			int8_t order = 0;

			string as_value() const;
			std::string_view as_condition() const;
			std::string_view as_order() const;
			static result_filter from(const std::string_view& query, const uint256_t& value, int8_t order);
			static result_filter greater(const uint256_t& value, int8_t order) { return { position_condition::greater, value, order }; }
			static result_filter greater_equal(const uint256_t& value, int8_t order) { return { position_condition::greater_equal, value, order }; }
			static result_filter equal(const uint256_t& value, int8_t order) { return { position_condition::equal, value, order }; }
			static result_filter not_equal(const uint256_t& value, int8_t order) { return { position_condition::not_equal, value, order }; }
			static result_filter less(const uint256_t& value, int8_t order) { return { position_condition::less, value, order }; }
			static result_filter less_equal(const uint256_t& value, int8_t order) { return { position_condition::less_equal, value, order }; }
		};

		struct result_window
		{
			virtual uint8_t type() const = 0;
		};

		struct result_range_window final : result_window
		{
			size_t offset;
			size_t count;

			result_range_window(size_t new_offset, size_t new_count) : offset(new_offset), count(new_count)
			{
			}
			uint8_t type() const override
			{
				return instance_type();
			}
			static uint8_t instance_type()
			{
				return 0;
			}
		};

		struct result_index_window final : result_window
		{
			vector<uint64_t> indices;

			uint8_t type() const override
			{
				return instance_type();
			}
			static uint8_t instance_type()
			{
				return 1;
			}
		};

		struct chainstate final
		{
		private:
			enum class resolver : uint8_t
			{
				find_exact_match = (1 << 0),
				disable_cache = (1 << 1)
			};

			struct uniform_location
			{
				option<uint64_t> index = optional::none;
				option<block_pair> block = optional::none;
			};

			struct multiform_location
			{
				option<uint64_t> column = optional::none;
				option<uint64_t> row = optional::none;
				option<block_pair> block = optional::none;
			};

			struct temporary_state_resolution
			{
				ledger::storage_index_ptr* storage;
				bool in_use;
			};

		private:
			unordered_map<uint32_t, ledger::storage_index_ptr> uniform_local_storage;
			unordered_map<uint32_t, ledger::storage_index_ptr> multiform_local_storage;
			ledger::storage_index_ptr block_local_storage;
			ledger::storage_index_ptr account_local_storage;
			ledger::storage_index_ptr tx_local_storage;
			ledger::storage_index_ptr party_local_storage;
			ledger::storage_index_ptr alias_local_storage;
			ledger::storage_blob_ptr blob_local_storage;
#ifndef NDEBUG
			std::thread::id local_id;
#endif
		public:
			chainstate() noexcept;
			chainstate(const chainstate&) = delete;
			chainstate(chainstate&&) noexcept = delete;
			chainstate& operator=(const chainstate&) = delete;
			chainstate& operator=(chainstate&&) noexcept = delete;
			~chainstate() noexcept;
			expects_lr<void> reorganize(int64_t* block_delta = nullptr, int64_t* transaction_delta = nullptr, int64_t* state_delta = nullptr);
			expects_lr<void> revert(uint64_t block_number, int64_t* block_delta = nullptr, int64_t* transaction_delta = nullptr, int64_t* state_delta = nullptr);
			expects_lr<void> dispatch(const vector<uint256_t>& finalized_transaction_hashes, const vector<uint256_t>& repeated_transaction_hashes);
			expects_lr<void> prune(uint32_t types, uint64_t block_number);
			expects_lr<void> checkpoint(const ledger::block_evaluation& evaluation, bool reorganization = false);
			expects_lr<uint64_t> get_checkpoint_block_number();
			expects_lr<uint64_t> get_latest_block_number();
			expects_lr<uint64_t> get_block_number_by_hash(const uint256_t& block_hash);
			expects_lr<uint256_t> get_block_hash_by_number(uint64_t block_number);
			expects_lr<decimal> get_block_gas_price(uint64_t block_number, const algorithm::asset_id& asset, double percentile);
			expects_lr<decimal> get_block_asset_price(uint64_t block_number, const algorithm::asset_id& price_of, const algorithm::asset_id& relative_to, double percentile);
			expects_lr<ledger::block> get_block_by_number(uint64_t block_number, size_t chunk = ELEMENTS_MANY, uint32_t details = (uint32_t)block_details::transactions | (uint32_t)block_details::block_transactions | (uint32_t)block_details::states);
			expects_lr<ledger::block> get_block_by_hash(const uint256_t& block_hash, size_t chunk = ELEMENTS_MANY, uint32_t details = (uint32_t)block_details::transactions | (uint32_t)block_details::block_transactions | (uint32_t)block_details::states);
			expects_lr<ledger::block> get_latest_block(size_t chunk = ELEMENTS_MANY, uint32_t details = (uint32_t)block_details::transactions | (uint32_t)block_details::block_transactions | (uint32_t)block_details::states);
			expects_lr<ledger::block_header> get_block_header_by_number(uint64_t block_number);
			expects_lr<ledger::block_header> get_block_header_by_hash(const uint256_t& block_hash);
			expects_lr<ledger::block_header> get_latest_block_header();
			expects_lr<ledger::block_proof> get_block_proof_by_number(uint64_t block_number);
			expects_lr<ledger::block_proof> get_block_proof_by_hash(const uint256_t& block_hash);
			expects_lr<vector<uint256_t>> get_block_transaction_hashset(uint64_t block_number);
			expects_lr<vector<uint256_t>> get_block_state_hashset(uint64_t block_number);
			expects_lr<vector<uint256_t>> get_block_hashset(uint64_t block_number, size_t count);
			expects_lr<vector<ledger::block_header>> get_block_headers(uint64_t block_number, size_t count);
			expects_lr<ledger::block_state> get_block_state_by_number(uint64_t block_number, size_t chunk = ELEMENTS_MANY);
			expects_lr<vector<uptr<ledger::transaction>>> get_transactions_by_number(uint64_t block_number, size_t offset, size_t count);
			expects_lr<vector<uptr<ledger::transaction>>> get_transactions_by_owner(uint64_t block_number, const algorithm::pubkeyhash_t& owner, int8_t direction, size_t offset, size_t count);
			expects_lr<vector<ledger::block_transaction>> get_block_transactions_by_number(uint64_t block_number, size_t offset, size_t count);
			expects_lr<vector<ledger::block_transaction>> get_block_transactions_by_owner(uint64_t block_number, const algorithm::pubkeyhash_t& owner, int8_t direction, size_t offset, size_t count);
			expects_lr<vector<ledger::receipt>> get_block_receipts_by_number(uint64_t block_number, size_t offset, size_t count);
			expects_lr<vector<ledger::block_transaction>> get_pending_block_transactions(uint64_t block_number, size_t offset, size_t count);
			expects_lr<uptr<ledger::transaction>> get_transaction_by_hash(const uint256_t& transaction_hash);
			expects_lr<ledger::block_transaction> get_block_transaction_by_hash(const uint256_t& transaction_hash);
			expects_lr<ledger::receipt> get_receipt_by_transaction_hash(const uint256_t& transaction_hash);
			expects_lr<uptr<ledger::state>> get_uniform(uint32_t type, const ledger::block_changelog* changelog, const std::string_view& index, uint64_t block_number);
			expects_lr<uptr<ledger::state>> get_multiform(uint32_t type, const ledger::block_changelog* changelog, const std::string_view& column, const std::string_view& row, uint64_t block_number);
			expects_lr<vector<uptr<ledger::state>>> get_multiforms_by_column(uint32_t type, ledger::block_changelog* changelog, const std::string_view& column, uint64_t block_number, size_t offset, size_t count);
			expects_lr<vector<uptr<ledger::state>>> get_multiforms_by_column_filter(uint32_t type, ledger::block_changelog* changelog, const std::string_view& column, const result_filter& filter, uint64_t block_number, const result_window& window);
			expects_lr<vector<uptr<ledger::state>>> get_multiforms_by_row(uint32_t type, ledger::block_changelog* changelog, const std::string_view& row, uint64_t block_number, size_t offset, size_t count);
			expects_lr<vector<uptr<ledger::state>>> get_multiforms_by_row_filter(uint32_t type, ledger::block_changelog* changelog, const std::string_view& row, const result_filter& filter, uint64_t block_number, const result_window& window);
			expects_lr<size_t> get_multiforms_count_by_column(uint32_t type, ledger::block_changelog* changelog, const std::string_view& column, uint64_t block_number);
			expects_lr<size_t> get_multiforms_count_by_column_filter(uint32_t type, ledger::block_changelog* changelog, const std::string_view& column, const result_filter& filter, uint64_t block_number);
			expects_lr<size_t> get_multiforms_count_by_row(uint32_t type, ledger::block_changelog* changelog, const std::string_view& row, uint64_t block_number);
			expects_lr<size_t> get_multiforms_count_by_row_filter(uint32_t type, ledger::block_changelog* changelog, const std::string_view& row, const result_filter& filter, uint64_t block_number);
			expects_lr<temporary_state_resolution> resolve_temporary_state(uint32_t type, ledger::block_changelog* changelog, const option<std::string_view>& column, const option<std::string_view>& row, uint64_t block_number);
			expects_lr<void> resolve_block_transactions(vector<ledger::block_transaction>& result, uint64_t block_number, bool fully, size_t chunk);
			expects_lr<uniform_location> resolve_uniform_location(uint32_t type, const std::string_view& index, uint8_t resolver_flags);
			expects_lr<multiform_location> resolve_multiform_location(uint32_t type, const option<std::string_view>& column, const option<std::string_view>& row, uint8_t resolver_flags);
			expects_lr<uint64_t> resolve_account_location(const algorithm::pubkeyhash_t& account);
			expects_lr<void> clear_temporary_state(ledger::block_changelog* changelog);
			ledger::storage_index_ptr& get_uniform_storage(uint32_t type);
			ledger::storage_index_ptr& get_multiform_storage(uint32_t type);
			ledger::storage_index_ptr& get_block_storage();
			ledger::storage_index_ptr& get_account_storage();
			ledger::storage_index_ptr& get_tx_storage();
			ledger::storage_index_ptr& get_party_storage();
			ledger::storage_index_ptr& get_alias_storage();
			ledger::storage_blob_ptr& get_blob_storage();
			unordered_map<uint32_t, ledger::storage_index_ptr>& get_uniform_multi_storage();
			unordered_map<uint32_t, ledger::storage_index_ptr>& get_multiform_multi_storage();
			ledger::storage_util::multi_storage_index_ptr get_multi_storage();
			void clear_indexer_cache();
			uint32_t get_queries() const;
			bool query_used() const;

		private:
			static bool make_schema(sqlite::connection* connection, const std::string_view& name);
		};
	}
}
#endif