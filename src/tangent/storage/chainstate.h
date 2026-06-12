#ifndef TAN_STORAGE_CHAINSTATE_H
#define TAN_STORAGE_CHAINSTATE_H
#include "engine.h"
#include "../kernel/block.h"

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

		struct state_result
		{
			uptr<ledger::transition_state> value;
			size_t index;
			bool cached;

			state_result() : index(0), cached(true)
			{
			}
			state_result(uptr<ledger::transition_state>&& new_value, bool new_cached, size_t new_index = 0) : value(std::move(new_value)), index(new_index), cached(new_cached)
			{
			}
			state_result(const state_result&) = delete;
			state_result(state_result&& other) noexcept : value(std::move(other.value)), index(other.index), cached(other.cached)
			{
			}
			state_result& operator= (const state_result&) = delete;
			state_result& operator= (state_result&& other) noexcept
			{
				if (this == &other)
					return *this;

				value = std::move(other.value);
				index = other.index;
				cached = other.cached;
				return *this;
			}
			explicit operator bool() const
			{
				return !!value;
			}
			template <typename t>
			t* as()
			{
				return (t*)*value;
			}
			ledger::transition_state* ptr()
			{
				return *value;
			}
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
		public:
			struct state_local_storage
			{
				ledger::storage_index_ptr local_storage;
				uint32_t type;
			};

			typedef std::array<state_local_storage, 6> uniform_storage_map;
			typedef std::array<state_local_storage, 14> multiform_storage_map;
			static_assert(std::tuple_size_v<states::resolver::uniform_type_map> == std::tuple_size_v<uniform_storage_map>, "uniform storage size mismatch");
			static_assert(std::tuple_size_v<states::resolver::multiform_type_map> == std::tuple_size_v<multiform_storage_map>, "multiform storage size mismatch");

		private:
			struct multiform_location
			{
				option<uint64_t> column = optional::none;
				option<uint64_t> row = optional::none;
			};

			struct temporary_state_resolution
			{
				ledger::storage_index_ptr* storage;
				bool in_use;
			};

		private:
			uniform_storage_map uniform_local_storage;
			multiform_storage_map multiform_local_storage;
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
			expects_lr<bool> compact(uint64_t block_number, uint64_t* last_checkpoint_block_number = nullptr);
			expects_lr<void> revert(uint64_t block_number, int64_t* block_delta = nullptr, int64_t* transaction_delta = nullptr, int64_t* state_delta = nullptr);
			expects_lr<void> checkpoint(const ledger::block_evaluation& evaluation, bool reorganization = false, uint64_t* checkpoint_block_number = nullptr);
			expects_lr<void> dispatch(const uint256_t& transaction_hash, uint64_t retry_after_block_number_or_zero);
			expects_lr<uint64_t> get_checkpoint_block_number();
			expects_lr<uint64_t> get_latest_block_number();
			expects_lr<uint64_t> get_block_number_by_hash(const uint256_t& block_hash);
			expects_lr<uint256_t> get_block_hash_by_number(uint64_t block_number);
			expects_lr<decimal> get_block_gas_price(uint64_t block_number, const algorithm::asset_id& asset, double percentile);
			expects_lr<decimal> get_block_asset_price(uint64_t block_number, const algorithm::asset_id& price_of, const algorithm::asset_id& relative_to, double percentile);
			expects_lr<ledger::block_body> get_block_by_number(uint64_t block_number, bool include_transactions = true);
			expects_lr<ledger::block_body> get_block_by_hash(const uint256_t& block_hash, bool include_transactions = true);
			expects_lr<ledger::block_body> get_latest_block(bool include_transactions = true);
			expects_lr<ledger::block_header> get_block_header_by_number(uint64_t block_number);
			expects_lr<ledger::block_header> get_block_header_by_hash(const uint256_t& block_hash);
			expects_lr<ledger::block_header> get_latest_block_header();
			expects_lr<ledger::block_proof> get_block_proof_by_number(uint64_t block_number);
			expects_lr<ledger::block_proof> get_block_proof_by_hash(const uint256_t& block_hash);
			expects_lr<vector<uint256_t>> get_block_transaction_hashset(uint64_t block_number);
			expects_lr<vector<uint256_t>> get_block_state_hashset(uint64_t block_number);
			expects_lr<vector<uint256_t>> get_block_hashset(uint64_t block_number, size_t count);
			expects_lr<vector<ledger::block_body>> get_blocks(uint64_t block_number, uint64_t count, const uint256_t& gas_limit, bool include_transactions = true);
			expects_lr<vector<ledger::block_header>> get_block_headers(uint64_t block_number, size_t count);
			expects_lr<ledger::block_state::log> get_block_state_by_number(uint64_t block_number);
			expects_lr<vector<ledger::block_transaction>> get_block_transactions(size_t offset, size_t count);
			expects_lr<vector<ledger::block_transaction>> get_block_transactions_by_number(uint64_t block_number, size_t offset, size_t count);
			expects_lr<vector<ledger::block_transaction>> get_block_transactions_by_owner(uint64_t block_number, const algorithm::pubkeyhash_t& owner, int8_t direction, size_t offset, size_t count);
			expects_lr<vector<ledger::block_transaction>> get_pending_block_transactions(uint64_t block_number, size_t offset, size_t count);
			expects_lr<bool> has_block_transaction(const uint256_t& transaction_hash);
			expects_lr<ledger::block_transaction> get_block_transaction_by_hash(const uint256_t& transaction_hash, bool include_aliases);
			expects_lr<vector<ledger::block_transaction>> get_block_transactions_by_hash(const uint256_t& transaction_hash, bool include_aliases);
			expects_lr<state_result> get_uniform(uint32_t type, const ledger::block_changelog* changelog, const std::string_view& index, uint64_t block_number);
			expects_lr<state_result> get_multiform(uint32_t type, const ledger::block_changelog* changelog, const std::string_view& column, const std::string_view& row, uint64_t block_number);
			expects_lr<vector<state_result>> get_multiforms_by_column(uint32_t type, ledger::block_changelog* changelog, const std::string_view& column, uint64_t block_number, size_t offset, size_t count);
			expects_lr<vector<state_result>> get_multiforms_by_column_filter(uint32_t type, ledger::block_changelog* changelog, const std::string_view& column, const result_filter& filter, uint64_t block_number, const result_window& window);
			expects_lr<vector<state_result>> get_multiforms_by_row(uint32_t type, ledger::block_changelog* changelog, const std::string_view& row, uint64_t block_number, size_t offset, size_t count);
			expects_lr<vector<state_result>> get_multiforms_by_row_filter(uint32_t type, ledger::block_changelog* changelog, const std::string_view& row, const result_filter& filter, uint64_t block_number, const result_window& window);
			expects_lr<size_t> get_multiforms_count_by_column(uint32_t type, ledger::block_changelog* changelog, const std::string_view& column, uint64_t block_number);
			expects_lr<size_t> get_multiforms_count_by_column_filter(uint32_t type, ledger::block_changelog* changelog, const std::string_view& column, const result_filter& filter, uint64_t block_number);
			expects_lr<size_t> get_multiforms_count_by_row(uint32_t type, ledger::block_changelog* changelog, const std::string_view& row, uint64_t block_number);
			expects_lr<size_t> get_multiforms_count_by_row_filter(uint32_t type, ledger::block_changelog* changelog, const std::string_view& row, const result_filter& filter, uint64_t block_number);
			expects_lr<temporary_state_resolution> resolve_temporary_state(uint32_t type, ledger::block_changelog* changelog, const option<std::string_view>& column, const option<std::string_view>& row, uint64_t block_number);
			expects_lr<void> resolve_block_transactions(vector<ledger::block_transaction>& result, uint64_t block_number);
			expects_lr<uint64_t> resolve_uniform_location(uint32_t type, const std::string_view& index);
			expects_lr<multiform_location> resolve_multiform_location(uint32_t type, const option<std::string_view>& column, const option<std::string_view>& row);
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
			uniform_storage_map& get_uniform_multi_storage();
			multiform_storage_map& get_multiform_multi_storage();
			ledger::storage_util::multi_storage_index_ptr get_multi_storage();
			uint32_t get_queries() const;

		private:
			expects_lr<void> revert_internal(uint64_t block_number, int64_t* block_delta, int64_t* transaction_delta, int64_t* state_delta);
			expects_lr<void> revert_reorganize_internal(int64_t* block_delta, int64_t* transaction_delta, int64_t* state_delta);
			expects_lr<void> checkpoint_internal(const ledger::block_evaluation& evaluation, bool reorganization, uint64_t* checkpoint_block_number);
			expects_lr<bool> compact_internal(uint64_t block_number, uint64_t* last_checkpoint_block_number);

		private:
			static bool make_schema(sqlite::connection* connection, const std::string_view& name);
		};
	}
}
#endif