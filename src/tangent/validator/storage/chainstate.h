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
			blocktrie = 1 << 0,
			transactiontrie = 1 << 1,
			statetrie = 1 << 2
		};

		class account_cache : public singleton<account_cache>
		{
		private:
			unordered_map<string, uint64_t> accounts;
			std::mutex mutex;

		public:
			account_cache() = default;
			virtual ~account_cache() = default;
			void clear_locations();
			void clear_account_location(const algorithm::pubkeyhash account);
			void set_account_location(const algorithm::pubkeyhash account, uint64_t location);
			option<uint64_t> get_account_location(const std::string_view& account);
		};

		class uniform_cache : public singleton<uniform_cache>
		{
		private:
			unordered_map<string, uint64_t> indices;
			unordered_map<uint64_t, uint64_t> blocks;
			std::mutex mutex;

		public:
			uniform_cache() = default;
			virtual ~uniform_cache() = default;
			void clear_locations();
			void clear_uniform_location(const std::string_view& index);
			void clear_block_location(const std::string_view& index);
			void set_index_location(const std::string_view& index, uint64_t location);
			void set_block_location(uint64_t location, uint64_t block_number);
			option<uint64_t> get_index_location(const std::string_view& index);
			option<uint64_t> get_block_location(uint64_t location);
		};

		class multiform_cache : public singleton<multiform_cache>
		{
		private:
			unordered_map<string, uint64_t> columns;
			unordered_map<string, uint64_t> rows;
			unordered_map<uint128_t, uint64_t> blocks;
			std::mutex mutex;

		public:
			multiform_cache() = default;
			virtual ~multiform_cache() = default;
			void clear_locations();
			void clear_multiform_location(const std::string_view& column, const std::string_view& row);
			void clear_block_location(const std::string_view& column, const std::string_view& row);
			void set_multiform_location(const std::string_view& column, const std::string_view& row, uint64_t column_location, uint64_t row_location);
			void set_column_location(const std::string_view& column, uint64_t location);
			void set_row_location(const std::string_view& row, uint64_t location);
			void set_block_location(uint64_t column_location, uint64_t row_location, uint64_t block_number);
			option<uint64_t> get_column_location(const std::string_view& column);
			option<uint64_t> get_row_location(const std::string_view& row);
			option<uint64_t> get_block_location(uint64_t column_location, uint64_t row_location);
		};

		struct factor_filter
		{
			position_condition condition = position_condition::equal;
			int64_t value = 0;
			int8_t order = 0;

			std::string_view as_condition() const;
			std::string_view as_order() const;
			static factor_filter from(const std::string_view& query, int64_t value, int8_t order);
			static factor_filter greater(int64_t value, int8_t order) { return { position_condition::greater, value, order }; }
			static factor_filter greater_equal(int64_t value, int8_t order) { return { position_condition::greater_equal, value, order }; }
			static factor_filter equal(int64_t value, int8_t order) { return { position_condition::equal, value, order }; }
			static factor_filter not_equal(int64_t value, int8_t order) { return { position_condition::not_equal, value, order }; }
			static factor_filter less(int64_t value, int8_t order) { return { position_condition::less, value, order }; }
			static factor_filter less_equal(int64_t value, int8_t order) { return { position_condition::less_equal, value, order }; }
		};

		struct factor_window
		{
			virtual uint8_t type() const = 0;
		};

		struct factor_range_window final : factor_window
		{
			size_t offset;
			size_t count;

			factor_range_window(size_t new_offset, size_t new_count) : offset(new_offset), count(new_count)
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

		struct factor_index_window final : factor_window
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

		struct chainstate : ledger::permanent_storage
		{
		private:
			struct uniform_location
			{
				option<uint64_t> index = optional::none;
				option<uint64_t> block = optional::none;
			};

			struct multiform_location
			{
				option<uint64_t> column = optional::none;
				option<uint64_t> row = optional::none;
				option<uint64_t> block = optional::none;
			};

		private:
			uptr<sqlite::connection> blockdata;
			uptr<sqlite::connection> accountdata;
			uptr<sqlite::connection> txdata;
			uptr<sqlite::connection> partydata;
			uptr<sqlite::connection> aliasdata;
			uptr<sqlite::connection> uniformdata;
			uptr<sqlite::connection> multiformdata;
			std::string_view label;
			bool borrows;

		public:
			chainstate(const std::string_view& new_label) noexcept;
			virtual ~chainstate() noexcept override;
			expects_lr<void> reorganize(int64_t* blocktrie = nullptr, int64_t* transactiontrie = nullptr, int64_t* statetrie = nullptr);
			expects_lr<void> revert(uint64_t block_number, int64_t* blocktrie = nullptr, int64_t* transactiontrie = nullptr, int64_t* statetrie = nullptr);
			expects_lr<void> dispatch(const vector<uint256_t>& finalized_transaction_hashes, const vector<uint256_t>& repeated_transaction_hashes);
			expects_lr<void> prune(uint32_t types, uint64_t block_number);
			expects_lr<void> checkpoint(const ledger::block& value, bool reorganization = false);
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
			expects_lr<vector<uint256_t>> get_block_statetrie_hashset(uint64_t block_number);
			expects_lr<vector<uint256_t>> get_block_hashset(uint64_t block_number, size_t count);
			expects_lr<vector<ledger::block_header>> get_block_headers(uint64_t block_number, size_t count);
			expects_lr<ledger::state_work> get_block_statetrie_by_number(uint64_t block_number, size_t offset, size_t count);
			expects_lr<vector<uptr<ledger::transaction>>> get_transactions_by_number(uint64_t block_number, size_t offset, size_t count);
			expects_lr<vector<uptr<ledger::transaction>>> get_transactions_by_owner(uint64_t block_number, const algorithm::pubkeyhash owner, int8_t direction, size_t offset, size_t count);
			expects_lr<vector<ledger::block_transaction>> get_block_transactions_by_number(uint64_t block_number, size_t offset, size_t count);
			expects_lr<vector<ledger::block_transaction>> get_block_transactions_by_owner(uint64_t block_number, const algorithm::pubkeyhash owner, int8_t direction, size_t offset, size_t count);
			expects_lr<vector<ledger::receipt>> get_block_receipts_by_number(uint64_t block_number, size_t offset, size_t count);
			expects_lr<vector<ledger::block_transaction>> get_pending_block_transactions(uint64_t block_number, size_t offset, size_t count);
			expects_lr<uptr<ledger::transaction>> get_transaction_by_hash(const uint256_t& transaction_hash);
			expects_lr<ledger::block_transaction> get_block_transaction_by_hash(const uint256_t& transaction_hash);
			expects_lr<ledger::receipt> get_receipt_by_transaction_hash(const uint256_t& transaction_hash);
			expects_lr<uptr<ledger::state>> get_uniform_by_index(const ledger::block_mutation* delta, const std::string_view& index, uint64_t block_number);
			expects_lr<uptr<ledger::state>> get_multiform_by_composition(const ledger::block_mutation* delta, const std::string_view& column, const std::string_view& row, uint64_t block_number);
			expects_lr<uptr<ledger::state>> get_multiform_by_column(const ledger::block_mutation* delta, const std::string_view& column, uint64_t block_number, size_t offset);
			expects_lr<uptr<ledger::state>> get_multiform_by_row(const ledger::block_mutation* delta, const std::string_view& row, uint64_t block_number, size_t offset);
			expects_lr<vector<uptr<ledger::state>>> get_multiforms_by_column(const ledger::block_mutation* delta, const std::string_view& column, uint64_t block_number, size_t offset, size_t count);
			expects_lr<vector<uptr<ledger::state>>> get_multiforms_by_column_filter(const ledger::block_mutation* delta, const std::string_view& column, const factor_filter& filter, uint64_t block_number, const factor_window& window);
			expects_lr<vector<uptr<ledger::state>>> get_multiforms_by_row(const ledger::block_mutation* delta, const std::string_view& row, uint64_t block_number, size_t offset, size_t count);
			expects_lr<vector<uptr<ledger::state>>> get_multiforms_by_row_filter(const ledger::block_mutation* delta, const std::string_view& row, const factor_filter& filter, uint64_t block_number, const factor_window& window);
			expects_lr<size_t> get_multiforms_count_by_column(const std::string_view& row, uint64_t block_number);
			expects_lr<size_t> get_multiforms_count_by_column_filter(const std::string_view& row, const factor_filter& filter, uint64_t block_number);
			expects_lr<size_t> get_multiforms_count_by_row(const std::string_view& row, uint64_t block_number);
			expects_lr<size_t> get_multiforms_count_by_row_filter(const std::string_view& row, const factor_filter& filter, uint64_t block_number);
			void clear_indexer_cache();

		private:
			expects_lr<size_t> resolve_block_transactions(ledger::block& value, bool fully, size_t offset, size_t count);
			expects_lr<size_t> resolve_block_statetrie(ledger::block& value, size_t offset, size_t count);
			expects_lr<uniform_location> resolve_uniform_location(const std::string_view& index, bool latest);
			expects_lr<multiform_location> resolve_multiform_location(const option<std::string_view>& column, const option<std::string_view>& row, bool latest);
			expects_lr<uint64_t> resolve_account_location(const algorithm::pubkeyhash account);

		protected:
			vector<sqlite::connection*> get_index_storages() override;
			bool reconstruct_index_storage(sqlite::connection* storage, const std::string_view& name) override;
		};
	}
}
#endif