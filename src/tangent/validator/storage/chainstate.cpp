#include "chainstate.h"
#include "../../policy/transactions.h"
#include "../../policy/states.h"
#define BLOB_BLOCK 'b'
#define BLOB_TRANSACTION 't'
#define BLOB_RECEIPT 'r'
#define BLOB_UNIFORM 'u'
#define BLOB_MULTIFORM 'm'
#undef NULL

namespace tangent
{
	namespace storages
	{
		struct transaction_alias_blob
		{
			uint8_t transaction_hash[32];
		};

		struct transaction_blob
		{
			uint8_t transaction_hash[32];
			format::wo_stream transaction_message;
			format::wo_stream receipt_message;
			uint64_t transaction_number;
			uint64_t block_nonce;
			bool dispatchable;
			ordered_set<algorithm::pubkeyhash_t> parties;
			vector<transaction_alias_blob> aliases;
			const ledger::block_transaction* context;
		};

		struct uniform_blob
		{
			format::wo_stream message;
			string index;
			const ledger::uniform* context;
			const ledger::block_state::state_change* change;
		};

		struct uniform_writer
		{
			vector<uniform_blob> blobs;
			sqlite::tstatement* erase_uniform_data;
			sqlite::tstatement* commit_uniform_index_data;
			sqlite::tstatement* commit_uniform_data;
			sqlite::tstatement* commit_snapshot_data;
			sqlite::connection* storage;
		};

		struct multiform_blob
		{
			format::wo_stream message;
			string column;
			string row;
			uint8_t rank[32];
			size_t rank_size;
			const ledger::multiform* context;
			const ledger::block_state::state_change* change;
		};

		struct multiform_writer
		{
			vector<multiform_blob> blobs;
			sqlite::tstatement* erase_multiform_data;
			sqlite::tstatement* commit_multiform_column_data;
			sqlite::tstatement* commit_multiform_row_data;
			sqlite::tstatement* commit_multiform_data;
			sqlite::tstatement* commit_snapshot_data;
			sqlite::connection* storage;
		};

		static void fill_multiform_writer_from_block_state(vector<multiform_blob>* blobs, uint32_t type, const ordered_map<string, ledger::block_state::state_change>& state)
		{
			for (auto& [index, change] : state)
			{
				if (change.state->as_level() == ledger::state_level::multiform && change.state->as_type() == type)
				{
					multiform_blob blob;
					blob.context = (ledger::multiform*)*change.state;
					blob.change = &change;
					blobs->emplace_back(std::move(blob));
				}
			}
		}
		static void fill_multiform_writer_from_block_changelog(vector<multiform_blob>* blobs, uint32_t type, const option<std::string_view>& column, const option<std::string_view>& row, const ledger::block_changelog* changelog)
		{
			auto fill_filter = [&](const ordered_map<string, ledger::block_state::state_change>& state)
			{
				for (auto& [index, change] : state)
				{
					if (change.state->as_level() != ledger::state_level::multiform || change.state->as_type() != type)
						continue;

					multiform_blob blob;
					blob.context = (ledger::multiform*)*change.state;
					blob.change = &change;
					if (column)
					{
						blob.column = blob.context->as_column();
						if (blob.column != *column)
							continue;
						blob.row = blob.context->as_row();
					}
					else if (row)
					{
						blob.row = blob.context->as_row();
						if (blob.row != *row)
							continue;
						blob.column = blob.context->as_column();
					}
					blob.message.write_typeless(blob.column.c_str(), (uint32_t)blob.column.size());
					blob.message.write_typeless(blob.row.c_str(), (uint32_t)blob.row.size());
					blobs->emplace_back(std::move(blob));
				}
			};
			fill_filter(changelog->outgoing.finalized);
			fill_filter(changelog->outgoing.pending);
		}
		static expects_lr<void> fill_multiform_writer_from_storage(multiform_writer* writer, sqlite::connection* multiform_storage)
		{
			auto erase_multiform_data = multiform_storage->prepare_statement("DELETE FROM multiforms WHERE column_number = ? AND row_number = ?", nullptr);
			if (!erase_multiform_data)
				return expects_lr<void>(layer_exception(std::move(erase_multiform_data.error().message())));

			auto commit_multiform_column_data = multiform_storage->prepare_statement("INSERT OR IGNORE INTO columns (column_number, column_hash, block_number) SELECT (SELECT COALESCE(MAX(column_number), 0) + 1 FROM columns), ?, ? ON CONFLICT DO UPDATE SET block_number = block_number RETURNING column_number", nullptr);
			if (!commit_multiform_column_data)
				return expects_lr<void>(layer_exception(std::move(commit_multiform_column_data.error().message())));

			auto commit_multiform_row_data = multiform_storage->prepare_statement("INSERT OR IGNORE INTO rows (row_number, row_hash, block_number) SELECT (SELECT COALESCE(MAX(row_number), 0) + 1 FROM rows), ?, ? ON CONFLICT DO UPDATE SET block_number = block_number RETURNING row_number", nullptr);
			if (!commit_multiform_row_data)
				return expects_lr<void>(layer_exception(std::move(commit_multiform_row_data.error().message())));

			auto commit_multiform_data = multiform_storage->prepare_statement("INSERT OR REPLACE INTO multiforms (column_number, row_number, block_number, rank) VALUES (?, ?, ?, ?)", nullptr);
			if (!commit_multiform_data)
				return expects_lr<void>(layer_exception(std::move(commit_multiform_data.error().message())));

			auto commit_snapshot_data = multiform_storage->prepare_statement("INSERT OR REPLACE INTO snapshots (column_number, row_number, block_number, rank, hidden) VALUES (?, ?, ?, ?, ?)", nullptr);
			if (!commit_snapshot_data)
				return expects_lr<void>(layer_exception(std::move(commit_snapshot_data.error().message())));

			writer->erase_multiform_data = *erase_multiform_data;
			writer->commit_multiform_column_data = *commit_multiform_column_data;
			writer->commit_multiform_row_data = *commit_multiform_row_data;
			writer->commit_multiform_data = *commit_multiform_data;
			writer->commit_snapshot_data = *commit_snapshot_data;
			writer->storage = multiform_storage;
			return expectation::met;
		}
		static void finalize_checksum(messages::uniform& message, const variant& column)
		{
			if (column.size() == sizeof(uint256_t))
				algorithm::encoding::encode_uint256(column.get_binary(), message.checksum);
		}
		static void finalize_checksum(messages::authentic& message, const variant& column)
		{
			if (column.size() == sizeof(uint256_t))
				algorithm::encoding::encode_uint256(column.get_binary(), message.checksum);
		}
		static uptr<ledger::state> state_from_blob(uint64_t block_number, uint32_t type, const std::string_view& index_or_column, const std::string_view& row_or_none, const std::string_view& optimized_blob)
		{
			auto state = uptr<ledger::state>(states::resolver::from_type(type));
			if (!state)
				return nullptr;

			switch (state->as_level())
			{
				case ledger::state_level::uniform:
				{
					auto message = format::ro_stream(index_or_column);
					if (!index_or_column.empty() && !((ledger::uniform*)*state)->load_index(message))
						return nullptr;

					message = format::ro_stream(optimized_blob);
					if (!optimized_blob.empty() && !state->load_optimized(message))
						return nullptr;

					if (!state->block_number)
					{
						state->block_number = block_number;
						state->block_nonce = 0;
					}

					return state;
				}
				case ledger::state_level::multiform:
				{
					auto message = format::ro_stream(index_or_column);
					if (!index_or_column.empty() && !((ledger::multiform*)*state)->load_column(message))
						return nullptr;

					message = format::ro_stream(row_or_none);
					if (!row_or_none.empty() && !((ledger::multiform*)*state)->load_row(message))
						return nullptr;

					message = format::ro_stream(optimized_blob);
					if (!optimized_blob.empty() && !state->load_optimized(message))
						return nullptr;

					if (!state->block_number)
					{
						state->block_number = block_number;
						state->block_nonce = 0;
					}

					return state;
				}
				default:
					return nullptr;
			}
		}
		static string get_block_label(const uint8_t hash[32])
		{
			string label;
			label.resize(33);
			label.front() = BLOB_BLOCK;
			memcpy(label.data() + 1, hash, sizeof(uint8_t) * 32);
			return label;
		}
		static string get_transaction_label(const uint8_t hash[32])
		{
			string label;
			label.resize(33);
			label.front() = BLOB_TRANSACTION;
			memcpy(label.data() + 1, hash, sizeof(uint8_t) * 32);
			return label;
		}
		static string get_receipt_label(const uint8_t hash[32])
		{
			string label;
			label.resize(33);
			label.front() = BLOB_RECEIPT;
			memcpy(label.data() + 1, hash, sizeof(uint8_t) * 32);
			return label;
		}
		static string get_uniform_label(uint32_t type, const std::string_view& index, uint64_t number)
		{
			format::wo_stream message;
			message.data.append(1, BLOB_UNIFORM);
			message.write_typeless(type);
			message.write_typeless(number);
			message.write_typeless(index.data(), (uint32_t)index.size());
			return message.data;
		}
		static string get_multiform_label(uint32_t type, const std::string_view& column, const std::string_view& row, uint64_t number)
		{
			format::wo_stream message;
			message.data.append(1, BLOB_UNIFORM);
			message.write_typeless(type);
			message.write_typeless(number);
			message.write_typeless(column.data(), (uint32_t)column.size());
			message.write_typeless(row.data(), (uint32_t)row.size());
			return message.data;
		}

		void account_cache::clear_locations()
		{
			umutex<std::mutex> unique(mutex);
			accounts.clear();
		}
		void account_cache::clear_account_location(const algorithm::pubkeyhash account)
		{
			umutex<std::mutex> unique(mutex);
			auto it = accounts.find(key_lookup_cast(std::string_view((char*)account, sizeof(algorithm::pubkeyhash))));
			if (it != accounts.end() && !it->second)
				accounts.erase(it);
		}
		void account_cache::set_account_location(const algorithm::pubkeyhash account, uint64_t location)
		{
			auto size = protocol::now().user.storage.location_cache_size;
			string target = string((char*)account, sizeof(algorithm::pubkeyhash));
			umutex<std::mutex> unique(mutex);
			if (accounts.size() >= size)
				accounts.clear();
			accounts[target] = location;
		}
		option<uint64_t> account_cache::get_account_location(const std::string_view& account)
		{
			umutex<std::mutex> unique(mutex);
			auto it = accounts.find(account);
			if (it == accounts.end())
				return optional::none;

			return it->second;
		}

		void uniform_cache::clear_locations()
		{
			umutex<std::mutex> unique(mutex);
			indices.clear();
			blocks.clear();
		}
		void uniform_cache::clear_uniform_location(uint32_t type, const std::string_view& index)
		{
			umutex<std::mutex> unique(mutex);
			auto index_iterator = indices.find(key_of_indices(type, index));
			if (index_iterator != indices.end())
				indices.erase(index_iterator);
		}
		void uniform_cache::clear_block_location(uint32_t type, const std::string_view& index)
		{
			umutex<std::mutex> unique(mutex);
			auto index_iterator = indices.find(key_of_indices(type, index));
			if (index_iterator != indices.end())
				blocks.erase(key_of_blocks(type, index_iterator->second));
		}
		void uniform_cache::set_index_location(uint32_t type, const std::string_view& index, uint64_t index_location)
		{
			umutex<std::mutex> unique(mutex);
			if (indices.size() >= protocol::now().user.storage.location_cache_size)
				indices.clear();
			indices[key_of_indices(type, index)] = index_location;
		}
		void uniform_cache::set_block_location(uint32_t type, uint64_t index_location, uint64_t block_number, bool hidden)
		{
			umutex<std::mutex> unique(mutex);
			if (blocks.size() >= protocol::now().user.storage.location_cache_size)
				blocks.clear();

			blocks[key_of_blocks(type, index_location)] = block_pair(block_number, hidden);
		}
		option<uint64_t> uniform_cache::get_index_location(uint32_t type, const std::string_view& index)
		{
			umutex<std::mutex> unique(mutex);
			auto it = indices.find(key_of_indices(type, index));
			if (it == indices.end())
				return optional::none;

			return it->second;
		}
		option<block_pair> uniform_cache::get_block_location(uint32_t type, uint64_t index_location)
		{
			umutex<std::mutex> unique(mutex);
			auto it = blocks.find(key_of_blocks(type, index_location));
			if (it == blocks.end())
				return optional::none;

			return it->second;
		}
		string uniform_cache::key_of_indices(uint32_t type, const std::string_view& index)
		{
			format::wo_stream message;
			message.write_typeless(type);
			message.write_typeless(index.data(), (uint32_t)index.size());
			return message.data;
		}
		string uniform_cache::key_of_blocks(uint32_t type, uint64_t location)
		{
			format::wo_stream message;
			message.write_typeless(type);
			message.write_typeless(location);
			return message.data;
		}

		void multiform_cache::clear_locations()
		{
			umutex<std::mutex> unique(mutex);
			columns.clear();
			rows.clear();
			blocks.clear();
		}
		void multiform_cache::clear_multiform_location(uint32_t type, const std::string_view& column, const std::string_view& row)
		{
			umutex<std::mutex> unique(mutex);
			auto column_iterator = columns.find(key_of_columns(type, column));
			if (column_iterator != columns.end())
				columns.erase(column_iterator);

			auto row_iterator = rows.find(key_of_rows(type, row));
			if (row_iterator != rows.end())
				rows.erase(row_iterator);
		}
		void multiform_cache::clear_block_location(uint32_t type, const std::string_view& column, const std::string_view& row)
		{
			umutex<std::mutex> unique(mutex);
			auto column_location = columns.find(key_of_columns(type, column));
			auto row_location = rows.find(key_of_rows(type, row));
			if (column_location != columns.end() && row_location != rows.end())
				blocks.erase(key_of_blocks(type, column_location->second, row_location->second));
		}
		void multiform_cache::set_multiform_location(uint32_t type, const std::string_view& column, const std::string_view& row, uint64_t column_location, uint64_t row_location)
		{
			umutex<std::mutex> unique(mutex);
			if (columns.size() >= protocol::now().user.storage.location_cache_size)
				columns.clear();
			if (rows.size() >= protocol::now().user.storage.location_cache_size)
				rows.clear();
			columns[key_of_columns(type, column)] = column_location;
			rows[key_of_rows(type, row)] = row_location;
		}
		void multiform_cache::set_column_location(uint32_t type, const std::string_view& column, uint64_t location)
		{
			umutex<std::mutex> unique(mutex);
			if (columns.size() >= protocol::now().user.storage.location_cache_size)
				columns.clear();
			columns[key_of_columns(type, column)] = location;
		}
		void multiform_cache::set_row_location(uint32_t type, const std::string_view& row, uint64_t location)
		{
			umutex<std::mutex> unique(mutex);
			if (rows.size() >= protocol::now().user.storage.location_cache_size)
				rows.clear();
			rows[key_of_rows(type, row)] = location;
		}
		void multiform_cache::set_block_location(uint32_t type, uint64_t column_location, uint64_t row_location, uint64_t block_number, bool hidden)
		{
			umutex<std::mutex> unique(mutex);
			if (blocks.size() >= protocol::now().user.storage.location_cache_size)
				blocks.clear();
			blocks[key_of_blocks(type, column_location, row_location)] = block_pair(block_number, hidden);
		}
		option<uint64_t> multiform_cache::get_column_location(uint32_t type, const std::string_view& column)
		{
			umutex<std::mutex> unique(mutex);
			auto it = columns.find(key_of_columns(type, column));
			if (it == columns.end())
				return optional::none;

			return it->second;
		}
		option<uint64_t> multiform_cache::get_row_location(uint32_t type, const std::string_view& row)
		{
			umutex<std::mutex> unique(mutex);
			auto it = rows.find(key_of_rows(type, row));
			if (it == rows.end())
				return optional::none;

			return it->second;
		}
		option<block_pair> multiform_cache::get_block_location(uint32_t type, uint64_t column_location, uint64_t row_location)
		{
			umutex<std::mutex> unique(mutex);
			auto it = blocks.find(key_of_blocks(type, column_location, row_location));
			if (it == blocks.end())
				return optional::none;

			return it->second;
		}
		string multiform_cache::key_of_columns(uint32_t type, const std::string_view& column)
		{
			format::wo_stream message;
			message.write_typeless(type);
			message.write_typeless(column.data(), (uint32_t)column.size());
			return message.data;
		}
		string multiform_cache::key_of_rows(uint32_t type, const std::string_view& row)
		{
			format::wo_stream message;
			message.write_typeless(type);
			message.write_typeless(row.data(), (uint32_t)row.size());
			return message.data;
		}
		string multiform_cache::key_of_blocks(uint32_t type, uint64_t column_location, uint64_t row_location)
		{
			format::wo_stream message;
			message.write_typeless(type);
			message.write_typeless(column_location);
			message.write_typeless(row_location);
			return message.data;
		}

		string result_filter::as_value() const
		{
			uint8_t data[32]; size_t data_size;
			algorithm::encoding::optimized_decode_uint256(value, data, &data_size);
			return string((char*)data, data_size);
		}
		std::string_view result_filter::as_condition() const
		{
			switch (condition)
			{
				case tangent::storages::position_condition::greater:
					return ">";
				case tangent::storages::position_condition::greater_equal:
					return ">=";
				case tangent::storages::position_condition::not_equal:
					return "<>";
				case tangent::storages::position_condition::less:
					return "<";
				case tangent::storages::position_condition::less_equal:
					return "<=";
				case tangent::storages::position_condition::equal:
				default:
					return "=";
			}
		}
		std::string_view result_filter::as_order() const
		{
			return order <= 0 ? "DESC" : "ASC";
		}
		result_filter result_filter::from(const std::string_view& query, const uint256_t& value, int8_t order)
		{
			if (query == "gt" || query == ">")
				return greater(value, order);
			else if (query == "gte" || query == ">=")
				return greater_equal(value, order);
			else if (query == "eq" || query == "=" || query == "==")
				return equal(value, order);
			else if (query == "neq" || query == "<>" || query == "!=")
				return not_equal(value, order);
			else if (query == "lt" || query == "<")
				return less(value, order);
			else if (query == "lte" || query == "<=")
				return less_equal(value, order);
			return equal(value, order);
		}

		static thread_local chainstate* latest_chainstate = nullptr;
		chainstate::chainstate(const std::string_view& new_label) noexcept : label(new_label), borrows(latest_chainstate != nullptr)
		{
			if (!borrows)
				latest_chainstate = this;
			else
				blob = latest_chainstate->blob;
		}
		chainstate::~chainstate() noexcept
		{
			unload_index_of(std::move(storages.block), borrows);
			unload_index_of(std::move(storages.account), borrows);
			unload_index_of(std::move(storages.tx), borrows);
			unload_index_of(std::move(storages.party), borrows);
			unload_index_of(std::move(storages.alias), borrows);
			for (auto& [type, data] : storages.uniform)
				unload_index_of(std::move(data), borrows);
			for (auto& [type, data] : storages.multiform)
				unload_index_of(std::move(data), borrows);
			if (latest_chainstate == this)
				latest_chainstate = nullptr;
		}
		expects_lr<void> chainstate::reorganize(int64_t* block_delta, int64_t* transaction_delta, int64_t* state_delta)
		{
			for (auto& [type, uniform_storage] : get_uniform_storage_max())
			{
				auto cursor = query(*uniform_storage, label, __func__,
					"DELETE FROM snapshots;"
					"DELETE FROM uniforms;"
					"DELETE FROM indices;");
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(error_of(cursor)));
			}

			for (auto& [type, multiform_storage] : get_multiform_storage_max())
			{
				auto cursor = query(*multiform_storage, label, __func__,
					"DELETE FROM snapshots;"
					"DELETE FROM multiforms;"
					"DELETE FROM columns;"
					"DELETE FROM rows;");
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(error_of(cursor)));
			}

			uint64_t current_number = 1;
			uint64_t checkpoint_number = get_checkpoint_block_number().or_else(0);
			uint64_t tip_number = get_latest_block_number().or_else(0);
			auto parent_block = expects_lr<ledger::block_header>(layer_exception());
			while (current_number <= tip_number)
			{
				auto candidate_block = get_block_by_number(current_number);
				if (!candidate_block)
					return layer_exception("block " + to_string(current_number) + (checkpoint_number >= current_number ? " reorganization failed: block data pruned" : " reorganization failed: block not found"));
				else if (current_number > 1 && checkpoint_number >= current_number - 1 && !parent_block)
					return layer_exception("block " + to_string(current_number - 1) + " reorganization failed: parent block data pruned");

				ledger::block_evaluation evaluation;
				auto validation = candidate_block->validate(parent_block.address(), &evaluation);
				if (!validation)
					return layer_exception("block " + to_string(current_number) + " validation failed: " + validation.error().message());

				auto finalization = checkpoint(evaluation, true);
				if (!finalization)
					return layer_exception("block " + to_string(current_number) + " checkpoint failed: " + finalization.error().message());

				if (protocol::now().user.storage.logging)
					VI_INFO("reorganization checkpoint at block number %" PRIu64 " (state_delta: +%i)", current_number, evaluation.block.state_count);

				parent_block = evaluation.block;
				++current_number;
				if (block_delta != nullptr)
					++(*block_delta);
				if (transaction_delta != nullptr)
					*transaction_delta += evaluation.block.transaction_count;
				if (state_delta != nullptr)
					*state_delta += evaluation.block.state_count;
			}

			return expectation::met;
		}
		expects_lr<void> chainstate::revert(uint64_t block_number, int64_t* block_delta, int64_t* transaction_delta, int64_t* state_delta)
		{
			schema_list map;
			map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(block_number));

			auto cursor = emplace_query(get_block_storage(), label, __func__,
				"DELETE FROM blocks WHERE block_number > ? RETURNING block_hash;"
				"DELETE FROM checkpoints WHERE block_number > ?;", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			auto response = cursor->first();
			parallel::wail_all(parallel::for_each_sequential(response.begin(), response.end(), response.size(), ELEMENTS_FEW, [&](sqlite::row row)
			{
				auto block_hash = row["block_hash"].get();
				store(label, __func__, get_block_label(block_hash.get_binary()), std::string_view());
			}));
			if (block_delta != nullptr)
				*block_delta -= response.size();

			map.clear();
			map.push_back(var::set::integer(block_number));

			cursor = emplace_query(get_tx_storage(), label, __func__, "DELETE FROM transactions WHERE block_number > ? RETURNING transaction_hash", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			response = cursor->first();
			parallel::wail_all(parallel::for_each_sequential(response.begin(), response.end(), response.size(), ELEMENTS_FEW, [&](sqlite::row row)
			{
				auto transaction_hash = row["transaction_hash"].get();
				store(label, __func__, get_transaction_label(transaction_hash.get_binary()), std::string_view());
				store(label, __func__, get_receipt_label(transaction_hash.get_binary()), std::string_view());
			}));
			if (transaction_delta != nullptr)
				*transaction_delta -= response.size();

			map.clear();
			map.push_back(var::set::integer(block_number));

			cursor = emplace_query(get_account_storage(), label, __func__, "DELETE FROM accounts WHERE block_number > ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			cursor = emplace_query(get_party_storage(), label, __func__, "DELETE FROM parties WHERE block_number > ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			cursor = emplace_query(get_alias_storage(), label, __func__, "DELETE FROM aliases WHERE block_number > ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			for (auto& [type, uniform_storage] : get_uniform_storage_max())
			{
				map.clear();
				map.push_back(var::set::integer(block_number));
				map.push_back(var::set::integer(block_number));
				map.push_back(var::set::integer(block_number));

				cursor = emplace_query(*uniform_storage, label, __func__,
					"DELETE FROM snapshots WHERE block_number > ?;"
					"INSERT OR REPLACE INTO uniforms (index_number, block_number) SELECT index_number, block_number FROM (SELECT index_number, hidden, MAX(block_number) AS block_number FROM snapshots WHERE block_number <= ? GROUP BY index_number) WHERE hidden = FALSE;"
					"DELETE FROM indices WHERE block_number > ?;", &map);
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(error_of(cursor)));
			}

			for (auto& [type, multiform_storage] : get_multiform_storage_max())
			{
				map.clear();
				map.push_back(var::set::integer(block_number));
				map.push_back(var::set::integer(block_number));
				map.push_back(var::set::integer(block_number));
				map.push_back(var::set::integer(block_number));

				cursor = emplace_query(*multiform_storage, label, __func__,
					"DELETE FROM snapshots WHERE block_number > ?;"
					"INSERT OR REPLACE INTO multiforms (column_number, row_number, rank, block_number) SELECT column_number, row_number, rank, block_number FROM (SELECT column_number, row_number, rank, hidden, MAX(block_number) AS block_number FROM snapshots WHERE block_number <= ? GROUP BY column_number, row_number) WHERE hidden = FALSE;"
					"DELETE FROM columns WHERE block_number > ?;"
					"DELETE FROM rows WHERE block_number > ?;", &map);
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(error_of(cursor)));
			}

			account_cache::get()->clear_locations();
			uniform_cache::get()->clear_locations();
			multiform_cache::get()->clear_locations();

			auto checkpoint_number = get_checkpoint_block_number();
			if (checkpoint_number && *checkpoint_number > block_number)
				return reorganize(block_delta, transaction_delta, state_delta);

			return expectation::met;
		}
		expects_lr<void> chainstate::dispatch(const vector<uint256_t>& finalized_transaction_hashes, const vector<uint256_t>& repeated_transaction_hashes)
		{
			unordered_set<uint256_t> exclusion;
			exclusion.reserve(repeated_transaction_hashes.size());
			for (auto& hash : repeated_transaction_hashes)
				exclusion.insert(hash);

			if (!finalized_transaction_hashes.empty())
			{
				uptr<schema> hashes = var::set::array();
				for (auto& item : finalized_transaction_hashes)
				{
					if (exclusion.find(item) != exclusion.end())
						continue;

					uint8_t hash[32];
					algorithm::encoding::decode_uint256(item, hash);
					hashes->push(var::binary(hash, sizeof(hash)));
				}

				if (!hashes->empty())
				{
					schema_list map;
					map.push_back(var::set::string(*sqlite::utils::inline_array(std::move(hashes))));

					auto cursor = emplace_query(get_tx_storage(), label, __func__, "UPDATE transactions SET dispatch_queue = NULL WHERE transaction_hash IN ($?)", &map);
					if (!cursor || cursor->error())
						return expects_lr<void>(layer_exception(error_of(cursor)));
				}
			}

			if (!repeated_transaction_hashes.empty())
			{
				uptr<schema> hashes = var::set::array();
				for (auto& item : repeated_transaction_hashes)
				{
					uint8_t hash[32];
					algorithm::encoding::decode_uint256(item, hash);
					hashes->push(var::binary(hash, sizeof(hash)));
				}

				schema_list map;
				map.push_back(var::set::integer(std::max<uint64_t>(1, (1000 * protocol::now().user.storage.transaction_dispatch_repeat_interval / protocol::now().policy.consensus_proof_time))));
				map.push_back(var::set::string(*sqlite::utils::inline_array(std::move(hashes))));

				auto cursor = emplace_query(get_tx_storage(), label, __func__, "UPDATE transactions SET dispatch_queue = dispatch_queue + ? WHERE transaction_hash IN ($?)", &map);
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(error_of(cursor)));
			}

			return expectation::met;
		}
		expects_lr<void> chainstate::prune(uint32_t types, uint64_t block_number)
		{
			size_t block_delta = 0;
			if (types & (uint32_t)pruning::block)
			{
				size_t offset = 0, count = 1024;
				schema_list map;
				map.push_back(var::set::integer(block_number));
				map.push_back(var::set::integer(count));
				map.push_back(var::set::integer(offset = 0));

				while (true)
				{
					map.back()->value = var::integer(offset);

					auto cursor = emplace_query(get_block_storage(), label, __func__, "SELECT block_hash FROM blocks WHERE block_number < ? LIMIT ? OFFSET ?", &map);
					if (!cursor || cursor->error())
						return expects_lr<void>(layer_exception(error_of(cursor)));

					auto response = cursor->first();
					parallel::wail_all(parallel::for_each_sequential(response.begin(), response.end(), response.size(), ELEMENTS_FEW, [&](sqlite::row row)
					{
						auto block_hash = row["block_hash"].get();
						store(label, __func__, get_block_label(block_hash.get_binary()), std::string_view());
					}));

					size_t results = cursor->first().size();
					offset += results;
					block_delta += results;
					if (results < count)
						break;
				}

				auto cursor = emplace_query(get_block_storage(), label, __func__, "DELETE FROM blocks WHERE block_number < ?", &map);
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(error_of(cursor)));
			}

			size_t transaction_delta = 0;
			if (types & (uint32_t)pruning::transaction)
			{
				size_t offset = 0, count = 1024;
				schema_list map;
				map.push_back(var::set::integer(block_number));
				map.push_back(var::set::integer(count));
				map.push_back(var::set::integer(offset));

				while (true)
				{
					map.back()->value = var::integer(offset);

					auto cursor = emplace_query(get_tx_storage(), label, __func__, "SELECT transaction_hash FROM transactions WHERE block_number < ? LIMIT ? OFFSET ?", &map);
					if (!cursor || cursor->error())
						return expects_lr<void>(layer_exception(error_of(cursor)));

					auto response = cursor->first();
					parallel::wail_all(parallel::for_each_sequential(response.begin(), response.end(), response.size(), ELEMENTS_FEW, [&](sqlite::row row)
					{
						auto transaction_hash = row["transaction_hash"].get();
						store(label, __func__, get_transaction_label(transaction_hash.get_binary()), std::string_view());
						store(label, __func__, get_receipt_label(transaction_hash.get_binary()), std::string_view());
					}));

					size_t results = cursor->first().size();
					offset += results;
					transaction_delta += results;
					if (results < count)
						break;
				}

				auto cursor = emplace_query(get_tx_storage(), label, __func__, "DELETE FROM transactions WHERE block_number < ?", &map);
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(error_of(cursor)));
			}

			size_t state_delta = 0;
			if (types & (uint32_t)pruning::state)
			{
				for (auto& [type, uniform_storage] : get_uniform_storage_max())
				{
					size_t offset = 0, count = 1024;
					schema_list map;
					map.push_back(var::set::integer(block_number));
					map.push_back(var::set::integer(count));
					map.push_back(var::set::integer(offset));

					while (true)
					{
						map.back()->value = var::integer(offset);

						auto cursor = emplace_query(*uniform_storage, label, __func__,
							"SELECT"
							" (COALESCE((SELECT TRUE FROM uniforms WHERE uniforms.index_number = snapshots.index_number AND uniforms.block_number = snapshots.block_number), FALSE)) AS latest,"
							" (SELECT index_hash FROM indices WHERE indices.index_number = snapshots.index_number) AS index_hash,"
							" block_number "
							"FROM snapshots WHERE block_number < ? LIMIT ? OFFSET ?", &map);
						if (!cursor || cursor->error())
							return expects_lr<void>(layer_exception(error_of(cursor)));

						std::atomic<size_t> skips = 0;
						auto response = cursor->first();
						parallel::wail_all(parallel::for_each_sequential(response.begin(), response.end(), response.size(), ELEMENTS_FEW, [&](sqlite::row row)
						{
							bool latest = row["latest"].get().get_boolean();
							if (latest)
							{
								++skips;
								return;
							}

							string index = row["index_hash"].get().get_blob();
							uint64_t number = row["block_number"].get().get_integer();
							store(label, __func__, get_uniform_label(type, index, number), std::string_view());
						}));

						size_t results = cursor->first().size();
						offset += results;
						state_delta += results - skips;
						if (results < count)
							break;
					}

					auto cursor = emplace_query(*uniform_storage, label, __func__, "DELETE FROM snapshots WHERE block_number < ?", &map);
					if (!cursor || cursor->error())
						return expects_lr<void>(layer_exception(error_of(cursor)));
				}

				for (auto& [type, multiform_storage] : get_multiform_storage_max())
				{
					size_t offset = 0, count = 1024;
					schema_list map;
					map.push_back(var::set::integer(block_number));
					map.push_back(var::set::integer(count));
					map.push_back(var::set::integer(offset));

					while (true)
					{
						map.back()->value = var::integer(offset);

						auto cursor = emplace_query(*multiform_storage, label, __func__,
							"SELECT"
							" (COALESCE((SELECT TRUE FROM multiforms WHERE multiforms.column_number = snapshots.column_number AND multiforms.row_number = snapshots.row_number AND multiforms.block_number = snapshots.block_number), FALSE)) AS latest,"
							" (SELECT column_hash FROM columns WHERE columns.column_number = snapshots.column_number) AS column_hash,"
							" (SELECT row_hash FROM rows WHERE rows.row_number = snapshots.row_number) AS row_hash,"
							" block_number "
							"FROM snapshots WHERE block_number < ? LIMIT ? OFFSET ?", &map);
						if (!cursor || cursor->error())
							return expects_lr<void>(layer_exception(error_of(cursor)));

						std::atomic<size_t> skips = 0;
						auto response = cursor->first();
						parallel::wail_all(parallel::for_each_sequential(response.begin(), response.end(), response.size(), ELEMENTS_FEW, [&](sqlite::row next)
						{
							bool latest = next["latest"].get().get_boolean();
							if (latest)
							{
								++skips;
								return;
							}

							string column = next["column_hash"].get().get_blob();
							string row = next["row_hash"].get().get_blob();
							uint64_t number = next["block_number"].get().get_integer();
							store(label, __func__, get_multiform_label(type, column, row, number), std::string_view());
						}));

						size_t results = cursor->first().size();
						offset += results;
						state_delta += results - skips;
						if (results < count)
							break;
					}

					auto cursor = emplace_query(*multiform_storage, label, __func__, "DELETE FROM snapshots WHERE block_number < ?", &map);
					if (!cursor || cursor->error())
						return expects_lr<void>(layer_exception(error_of(cursor)));
				}
			}

			schema_list map;
			map.push_back(var::set::integer(block_number));

			auto cursor = emplace_query(get_block_storage(), label, __func__, "INSERT OR IGNORE INTO checkpoints (block_number) VALUES (?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			if (protocol::now().user.storage.logging)
				VI_INFO("pruning checkpoint at block number %" PRIu64 " (block_delta: -%" PRIu64 ", transaction_delta: -%" PRIu64 ", state_delta: -%" PRIu64 ")", block_number, (uint64_t)block_delta, (uint64_t)transaction_delta, (uint64_t)state_delta);

			return expectation::met;
		}
		expects_lr<void> chainstate::checkpoint(const ledger::block_evaluation& evaluation, bool reorganization)
		{
			if (!reorganization)
			{
				format::wo_stream block_header_message;
				if (!evaluation.block.as_header().store(&block_header_message))
					return expects_lr<void>(layer_exception("block header serialization error"));

				uint8_t hash[32];
				algorithm::encoding::decode_uint256(evaluation.block.as_hash(), hash);

				auto status = store(label, __func__, get_block_label(hash), block_header_message.data);
				if (!status)
					return expects_lr<void>(layer_exception(error_of(status)));

				schema_list map;
				map.push_back(var::set::integer(evaluation.block.number));
				map.push_back(var::set::binary(hash, sizeof(hash)));

				auto cursor = emplace_query(get_block_storage(), label, __func__, "INSERT INTO blocks (block_number, block_hash) VALUES (?, ?)", &map);
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(error_of(cursor)));
			}

			auto commit_transaction_data = reorganization ? sqlite::expects_db<sqlite::tstatement*>(nullptr) : get_tx_storage()->prepare_statement("INSERT INTO transactions (transaction_number, transaction_hash, dispatch_queue, block_number, block_nonce) VALUES (?, ?, ?, ?, ?)", nullptr);
			if (!commit_transaction_data)
				return expects_lr<void>(layer_exception(std::move(commit_transaction_data.error().message())));

			auto commit_account_data = reorganization ? sqlite::expects_db<sqlite::tstatement*>(nullptr) : get_account_storage()->prepare_statement("INSERT OR IGNORE INTO accounts (account_number, account_hash, block_number) SELECT (SELECT COALESCE(MAX(account_number), 0) + 1 FROM accounts), ?, ? ON CONFLICT DO UPDATE SET block_number = block_number RETURNING account_number", nullptr);
			if (!commit_account_data)
				return expects_lr<void>(layer_exception(std::move(commit_account_data.error().message())));

			auto commit_party_data = reorganization ? sqlite::expects_db<sqlite::tstatement*>(nullptr) : get_party_storage()->prepare_statement("INSERT OR IGNORE INTO parties (transaction_number, transaction_account_number, block_number) VALUES (?, ?, ?)", nullptr);
			if (!commit_party_data)
				return expects_lr<void>(layer_exception(std::move(commit_party_data.error().message())));

			auto commit_alias_data = reorganization ? sqlite::expects_db<sqlite::tstatement*>(nullptr) : get_alias_storage()->prepare_statement("INSERT INTO aliases (transaction_number, transaction_hash, block_number) VALUES (?, ?, ?)", nullptr);
			if (!commit_alias_data)
				return expects_lr<void>(layer_exception(std::move(commit_alias_data.error().message())));

			unordered_map<uint32_t, uniform_writer> uniform_writers;
			for (auto& [type, uniform_storage] : get_uniform_storage_max())
			{
				vector<uniform_blob> blobs;
				blobs.reserve(evaluation.state.finalized.size());
				for (auto& [index, change] : evaluation.state.finalized)
				{
					if (change.state->as_level() == ledger::state_level::uniform && change.state->as_type() == type)
					{
						uniform_blob blob;
						blob.context = (ledger::uniform*)*change.state;
						blob.change = &change;
						blobs.emplace_back(std::move(blob));
					}
				}

				if (blobs.empty())
					continue;

				auto erase_uniform_data = uniform_storage->prepare_statement("DELETE FROM uniforms WHERE index_number = ?", nullptr);
				if (!erase_uniform_data)
					return expects_lr<void>(layer_exception(std::move(erase_uniform_data.error().message())));

				auto commit_uniform_index_data = uniform_storage->prepare_statement("INSERT OR IGNORE INTO indices (index_number, index_hash, block_number) SELECT (SELECT COALESCE(MAX(index_number), 0) + 1 FROM indices), ?, ? ON CONFLICT DO UPDATE SET block_number = block_number RETURNING index_number", nullptr);
				if (!commit_uniform_index_data)
					return expects_lr<void>(layer_exception(std::move(commit_uniform_index_data.error().message())));

				auto commit_uniform_data = uniform_storage->prepare_statement("INSERT OR REPLACE INTO uniforms (index_number, block_number) VALUES (?, ?)", nullptr);
				if (!commit_uniform_data)
					return expects_lr<void>(layer_exception(std::move(commit_uniform_data.error().message())));

				auto commit_snapshot_data = uniform_storage->prepare_statement("INSERT OR REPLACE INTO snapshots (index_number, block_number, hidden) VALUES (?, ?, ?)", nullptr);
				if (!commit_snapshot_data)
					return expects_lr<void>(layer_exception(std::move(commit_snapshot_data.error().message())));

				uniform_writer& writer = uniform_writers[type];
				writer.erase_uniform_data = *erase_uniform_data;
				writer.commit_uniform_index_data = *commit_uniform_index_data;
				writer.commit_uniform_data = *commit_uniform_data;
				writer.commit_snapshot_data = *commit_snapshot_data;
				writer.storage = *uniform_storage;
				writer.blobs = std::move(blobs);
			}

			unordered_map<uint32_t, multiform_writer> multiform_writers;
			for (auto& [type, multiform_storage] : get_multiform_storage_max())
			{
				vector<multiform_blob> blobs;
				fill_multiform_writer_from_block_state(&blobs, type, evaluation.state.finalized);
				if (blobs.empty())
					continue;

				multiform_writer& writer = multiform_writers[type];
				writer.blobs = std::move(blobs);

				auto status = fill_multiform_writer_from_storage(&writer, *multiform_storage);
				if (!status)
					return status;
			}

			vector<promise<void>> queue;
			vector<transaction_blob> transactions;
			size_t concurrency = std::max<size_t>(1, parallel::get_threads());
			bool transaction_to_account_index = protocol::now().user.storage.transaction_to_account_index;
			bool transaction_to_rollup_index = protocol::now().user.storage.transaction_to_rollup_index;
			if (!reorganization)
			{
				auto cursor = query(get_tx_storage(), label, __func__, "SELECT MAX(transaction_number) AS counter FROM transactions");
				if (!cursor || cursor->error_or_empty())
					return expects_lr<void>(layer_exception(error_of(cursor)));

				uint64_t transaction_nonce = (*cursor)["counter"].get().get_integer();
				transactions.resize(evaluation.block.transactions.size());
				for (size_t i = 0; i < transactions.size(); i++)
				{
					transaction_blob& blob = transactions[i];
					blob.transaction_number = ++transaction_nonce;
					blob.block_nonce = (uint64_t)i;
					blob.context = &evaluation.block.transactions[i];
				}

				for (auto& task : parallel::for_each(transactions.begin(), transactions.end(), ELEMENTS_FEW, [&](transaction_blob& item)
				{
					item.receipt_message.data.reserve(1024);
					item.context->transaction->store(&item.transaction_message);
					item.context->receipt.store(&item.receipt_message);
					item.dispatchable = item.context->transaction->is_dispatchable();
					algorithm::encoding::decode_uint256(item.context->receipt.transaction_hash, item.transaction_hash);
					if (transaction_to_account_index)
					{
						auto context = ledger::transaction_context();
						item.context->transaction->recover_many(&context, item.context->receipt, item.parties);
						item.parties.insert(algorithm::pubkeyhash_t(item.context->receipt.from));
					}
					if (transaction_to_rollup_index)
					{
						ordered_set<uint256_t> aliases;
						auto context = ledger::transaction_context();
						item.context->transaction->recover_aliases(&context, item.context->receipt, aliases);
						item.aliases.reserve(aliases.size());

						transaction_alias_blob alias;
						for (auto& hash : aliases)
						{
							algorithm::encoding::decode_uint256(hash, alias.transaction_hash);
							item.aliases.push_back(alias);
						}
					}
				}))
					queue.emplace_back(std::move(task));
			}

			for (auto& [type, writer] : uniform_writers)
			{
				vector<uptr<ledger::state>> state_cache(concurrency);
				for (auto& task : parallel::for_each(writer.blobs.begin(), writer.blobs.end(), ELEMENTS_FEW, [&](uniform_blob& item)
				{
					item.index = item.context->as_index();
					item.context->store_optimized(&item.message);
				}))
					queue.emplace_back(std::move(task));
			}

			for (auto& [type, writer] : multiform_writers)
			{
				vector<uptr<ledger::state>> state_cache(concurrency);
				for (auto& task : parallel::for_each(writer.blobs.begin(), writer.blobs.end(), ELEMENTS_FEW, [&](multiform_blob& item)
				{
					item.column = item.context->as_column();
					item.row = item.context->as_row();
					item.context->store_optimized(&item.message);
					algorithm::encoding::optimized_decode_uint256(item.context->as_rank(), item.rank, &item.rank_size);
				}))
					queue.emplace_back(std::move(task));
			}

			parallel::wail_all(std::move(queue));
			if (!reorganization)
			{
				auto* cache_a = account_cache::get();
				for (auto& data : transactions)
				{
					for (auto& party : data.parties)
						cache_a->clear_account_location(party.data);
				}
			}

			auto* cache_u = uniform_cache::get();
			for (auto& [type, writer] : uniform_writers)
			{
				for (auto& item : writer.blobs)
					cache_u->clear_block_location(type, item.index);
			}

			for (auto& [type, writer] : uniform_writers)
			{
				for (auto& item : writer.blobs)
					cache_u->clear_uniform_location(type, item.index);
			}

			auto* cache_m = multiform_cache::get();
			for (auto& [type, writer] : multiform_writers)
			{
				for (auto& item : writer.blobs)
					cache_m->clear_block_location(type, item.column, item.row);
			}

			for (auto& [type, writer] : multiform_writers)
			{
				for (auto& item : writer.blobs)
					cache_m->clear_multiform_location(type, item.column, item.row);
			}

			vector<promise<expects_lr<void>>> expectation_queue;
			expectation_queue.reserve(8 + uniform_writers.size() * 2 + multiform_writers.size() * 2);
			for (auto& [type, writer] : uniform_writers)
			{
				expectation_queue.emplace_back(cotask<expects_lr<void>>([&]() -> expects_lr<void>
				{
					sqlite::expects_db<sqlite::cursor> cursor = sqlite::database_exception(string());
					for (auto& item : writer.blobs)
					{
						auto* statement = writer.commit_uniform_index_data;
						writer.storage->bind_blob(statement, 0, item.index);
						writer.storage->bind_int64(statement, 1, evaluation.block.number);

						cursor = prepared_query(writer.storage, label, __func__, statement);
						if (!cursor || cursor->error_or_empty())
							return layer_exception(cursor->empty() ? "uniform state index not linked" : error_of(cursor));

						uint64_t index_number = cursor->first().front().get_column(0).get().get_integer();
						if (item.change->erase)
						{
							statement = writer.erase_uniform_data;
							writer.storage->bind_int64(statement, 0, index_number);
						}
						else
						{
							statement = writer.commit_uniform_data;
							writer.storage->bind_int64(statement, 0, index_number);
							writer.storage->bind_int64(statement, 1, evaluation.block.number);
						}

						cursor = prepared_query(writer.storage, label, __func__, statement);
						if (!cursor || cursor->error())
							return layer_exception(error_of(cursor));

						statement = writer.commit_snapshot_data;
						writer.storage->bind_int64(statement, 0, index_number);
						writer.storage->bind_int64(statement, 1, evaluation.block.number);
						writer.storage->bind_boolean(statement, 2, item.change->erase);

						cursor = prepared_query(writer.storage, label, __func__, statement);
						if (!cursor || cursor->error())
							return layer_exception(error_of(cursor));
					}
					return expectation::met;
				}, false));
				expectation_queue.emplace_back(cotask<expects_lr<void>>([&]() -> expects_lr<void>
				{
					sqlite::expects_db<void> status = expectation::met;
					for (auto& item : writer.blobs)
					{
						if (item.change->erase)
							continue;

						status = store(label, __func__, get_uniform_label(type, item.index, evaluation.block.number), item.message.data);
						if (!status)
							return layer_exception(error_of(status));
					}
					return expectation::met;
				}, false));
			}
			for (auto& [type, writer] : multiform_writers)
			{
				expectation_queue.emplace_back(cotask<expects_lr<void>>([&]() -> expects_lr<void>
				{
					sqlite::expects_db<sqlite::cursor> cursor = sqlite::database_exception(string());
					for (auto& item : writer.blobs)
					{
						auto* statement = writer.commit_multiform_column_data;
						writer.storage->bind_blob(statement, 0, item.column);
						writer.storage->bind_int64(statement, 1, evaluation.block.number);

						cursor = prepared_query(writer.storage, label, __func__, statement);
						if (!cursor || cursor->error_or_empty())
							return layer_exception(cursor->empty() ? "multiform state column not linked" : error_of(cursor));

						statement = writer.commit_multiform_row_data;
						writer.storage->bind_blob(statement, 0, item.row);
						writer.storage->bind_int64(statement, 1, evaluation.block.number);

						uint64_t column_number = cursor->first().front().get_column(0).get().get_integer();
						cursor = prepared_query(writer.storage, label, __func__, statement);
						if (!cursor || cursor->error_or_empty())
							return layer_exception(cursor->empty() ? "multiform state row not linked" : error_of(cursor));

						uint64_t row_number = cursor->first().front().get_column(0).get().get_integer();
						if (item.change->erase)
						{
							statement = writer.erase_multiform_data;
							writer.storage->bind_int64(statement, 0, column_number);
							writer.storage->bind_int64(statement, 1, row_number);
						}
						else
						{
							statement = writer.commit_multiform_data;
							writer.storage->bind_int64(statement, 0, column_number);
							writer.storage->bind_int64(statement, 1, row_number);
							writer.storage->bind_int64(statement, 2, evaluation.block.number);
							writer.storage->bind_blob(statement, 3, std::string_view((char*)item.rank, item.rank_size));
						}

						cursor = prepared_query(writer.storage, label, __func__, statement);
						if (!cursor || cursor->error())
							return layer_exception(error_of(cursor));

						statement = writer.commit_snapshot_data;
						writer.storage->bind_int64(statement, 0, column_number);
						writer.storage->bind_int64(statement, 1, row_number);
						writer.storage->bind_int64(statement, 2, evaluation.block.number);
						writer.storage->bind_blob(statement, 3, std::string_view((char*)item.rank, item.rank_size));
						writer.storage->bind_boolean(statement, 4, item.change->erase);

						cursor = prepared_query(writer.storage, label, __func__, statement);
						if (!cursor || cursor->error())
							return layer_exception(error_of(cursor));
					}
					return expectation::met;
				}, false));
				expectation_queue.emplace_back(cotask<expects_lr<void>>([&]() -> expects_lr<void>
				{
					sqlite::expects_db<void> status = expectation::met;
					for (auto& item : writer.blobs)
					{
						if (item.change->erase)
							continue;

						status = store(label, __func__, get_multiform_label(type, item.column, item.row, evaluation.block.number), item.message.data);
						if (!status)
							return layer_exception(error_of(status));
					}
					return expectation::met;
				}, false));
			}
			if (!reorganization)
			{
				expectation_queue.emplace_back(cotask<expects_lr<void>>([&]() -> expects_lr<void>
				{
					auto* txdata = get_tx_storage();
					auto* statement = *commit_transaction_data;
					sqlite::expects_db<sqlite::cursor> cursor = sqlite::database_exception(string());
					for (auto& data : transactions)
					{
						txdata->bind_int64(statement, 0, data.transaction_number);
						txdata->bind_blob(statement, 1, std::string_view((char*)data.transaction_hash, sizeof(data.transaction_hash)));
						if (data.dispatchable)
							txdata->bind_int64(statement, 2, evaluation.block.number);
						else
							txdata->bind_null(statement, 2);
						txdata->bind_int64(statement, 3, evaluation.block.number);
						txdata->bind_int64(statement, 4, data.block_nonce);

						cursor = prepared_query(get_tx_storage(), label, __func__, statement);
						if (!cursor || cursor->error())
							return layer_exception(error_of(cursor));
					}
					return expectation::met;
				}, false));
				expectation_queue.emplace_back(cotask<expects_lr<void>>([&]() -> expects_lr<void>
				{
					sqlite::expects_db<void> status = expectation::met;
					for (auto& data : transactions)
					{
						status = store(label, __func__, get_transaction_label(data.transaction_hash), data.transaction_message.data);
						if (!status)
							return layer_exception(error_of(status));

						status = store(label, __func__, get_receipt_label(data.transaction_hash), data.receipt_message.data);
						if (!status)
							return layer_exception(error_of(status));
					}
					return expectation::met;
				}, false));
				if (transaction_to_account_index)
				{
					expectation_queue.emplace_back(cotask<expects_lr<void>>([&]() -> expects_lr<void>
					{
						auto* accountdata = get_account_storage();
						auto* partydata = get_party_storage();
						sqlite::expects_db<sqlite::cursor> cursor = sqlite::database_exception(string());
						for (auto& data : transactions)
						{
							for (auto& party : data.parties)
							{
								auto* statement = *commit_account_data;
								accountdata->bind_blob(statement, 0, party.view());
								accountdata->bind_int64(statement, 1, evaluation.block.number);

								cursor = prepared_query(get_account_storage(), label, __func__, statement);
								if (!cursor || cursor->error_or_empty())
									return layer_exception(cursor->empty() ? "account not linked" : error_of(cursor));

								uint64_t account_number = cursor->first().front().get_column(0).get().get_integer();
								statement = *commit_party_data;
								partydata->bind_int64(statement, 0, data.transaction_number);
								partydata->bind_int64(statement, 1, account_number);
								partydata->bind_int64(statement, 2, evaluation.block.number);

								cursor = prepared_query(get_party_storage(), label, __func__, statement);
								if (!cursor || cursor->error())
									return layer_exception(error_of(cursor));
							}
						}
						return expectation::met;
					}, false));
				}
				if (transaction_to_rollup_index)
				{
					expectation_queue.emplace_back(cotask<expects_lr<void>>([&]() -> expects_lr<void>
					{
						auto* aliasdata = get_alias_storage();
						auto* statement = *commit_alias_data;
						sqlite::expects_db<sqlite::cursor> cursor = sqlite::database_exception(string());
						for (auto& data : transactions)
						{
							for (auto& alias : data.aliases)
							{
								aliasdata->bind_int64(statement, 0, data.transaction_number);
								aliasdata->bind_blob(statement, 1, std::string_view((char*)alias.transaction_hash, sizeof(alias.transaction_hash)));
								aliasdata->bind_int64(statement, 2, evaluation.block.number);

								cursor = prepared_query(get_alias_storage(), label, __func__, statement);
								if (!cursor || cursor->error())
									return layer_exception(error_of(cursor));
							}
						}
						return expectation::met;
					}, false));
				}
			}

			for (auto& status : parallel::inline_wait_all(std::move(expectation_queue)))
			{
				if (!status)
					return status;
			}

			auto checkpoint_size = protocol::now().user.storage.checkpoint_size;
			if (!checkpoint_size || evaluation.block.priority > 0)
				return expectation::met;

			auto checkpoint_number = evaluation.block.number - evaluation.block.number % checkpoint_size;
			if (checkpoint_number < evaluation.block.number)
				return expectation::met;

			auto latest_checkpoint = get_checkpoint_block_number().or_else(0);
			if (evaluation.block.number <= latest_checkpoint)
				return expectation::met;

			return prune(protocol::now().user.storage.prune_aggressively ? (uint32_t)pruning::block | (uint32_t)pruning::transaction | (uint32_t)pruning::state : (uint32_t)pruning::state, evaluation.block.number);
		}
		expects_lr<void> chainstate::resolve_block_transactions(vector<ledger::block_transaction>& result, uint64_t block_number, bool fully, size_t chunk)
		{
			schema_list map;
			map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(chunk));
			map.push_back(var::set::integer(0));

			size_t offset = 0;
			while (true)
			{
				auto cursor = emplace_query(get_tx_storage(), label, __func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce LIMIT ? OFFSET ?", &map);
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(error_of(cursor)));

				auto& response = cursor->first();
				size_t size = response.size();
				if (!size)
					break;

				size_t stride = result.size();
				result.resize(result.size() + size);
				parallel::wail_all(parallel::for_loop(size, ELEMENTS_FEW, [&](size_t i)
				{
					auto row = response[i];
					auto& next = result[i + stride];
					auto transaction_hash = row["transaction_hash"].get();
					auto transaction_blob = load(label, __func__, get_transaction_label(transaction_hash.get_binary())).or_else(string());
					auto transaction_message = format::ro_stream(transaction_blob);
					next.transaction = transactions::resolver::from_stream(transaction_message);
					if (next.transaction && next.transaction->load(transaction_message))
					{
						if (fully)
						{
							transaction_blob = load(label, __func__, get_receipt_label(transaction_hash.get_binary())).or_else(string());
							transaction_message = format::ro_stream(transaction_blob);
							if (next.receipt.load(transaction_message))
								finalize_checksum(**next.transaction, transaction_hash);
						}
						else
							finalize_checksum(**next.transaction, transaction_hash);
					}
				}));

				offset += size;
				map[2]->value = var::integer(offset);
				if (size < chunk)
					break;
			}

			auto it = std::remove_if(result.begin(), result.end(), [](const ledger::block_transaction& a) { return !a.transaction; });
			if (it != result.end())
				result.erase(it);

			return expectation::met;
		}
		expects_lr<chainstate::uniform_location> chainstate::resolve_uniform_location(uint32_t type, const std::string_view& index, uint8_t resolver_flags)
		{
			auto cache = uniform_cache::get();
			auto index_location = cache->get_index_location(type, index);
			auto block_location = (resolver_flags & (uint8_t)resolver::find_exact_match) && index_location ? cache->get_block_location(type, *index_location) : option<block_pair>(optional::none);
			if (!index_location)
			{
				auto uniform_storage = get_uniform_storage(type);
				auto find_index = uniform_storage->prepare_statement("SELECT index_number FROM indices WHERE index_hash = ?", nullptr);
				if (!find_index)
					return expects_lr<uniform_location>(layer_exception(std::move(find_index.error().message())));

				uniform_storage->bind_blob(*find_index, 0, index);
				auto cursor = prepared_query(uniform_storage, label, __func__, *find_index);
				if (!cursor || cursor->error())
					return expects_lr<uniform_location>(layer_exception(error_of(cursor)));

				index_location = (*cursor)["index_number"].get().get_integer();
				if (!(resolver_flags & (uint8_t)resolver::disable_cache))
					cache->set_index_location(type, index, *index_location);
			}

			uniform_location location;
			location.index = index_location && *index_location > 0 ? std::move(index_location) : option<uint64_t>(optional::none);
			location.block = block_location && block_location->number > 0 ? std::move(block_location) : option<block_pair>(optional::none);
			return location;
		}
		expects_lr<chainstate::multiform_location> chainstate::resolve_multiform_location(uint32_t type, const option<std::string_view>& column, const option<std::string_view>& row, uint8_t resolver_flags)
		{
			VI_ASSERT(column || row, "column or row should be set");
			auto cache = multiform_cache::get();
			bool update_column = false, update_row = false;
			auto column_location = column ? cache->get_column_location(type, *column) : option<uint64_t>(optional::none);
			auto row_location = row ? cache->get_row_location(type, *row) : option<uint64_t>(optional::none);
			auto block_location = (resolver_flags & (uint8_t)resolver::find_exact_match) && column_location && row_location ? cache->get_block_location(type, *column_location, *row_location) : option<block_pair>(optional::none);
			if (column && !column_location)
			{
				auto multiform_storage = get_multiform_storage(type);
				auto find_column = multiform_storage->prepare_statement("SELECT column_number FROM columns WHERE column_hash = ?", nullptr);
				if (!find_column)
					return expects_lr<multiform_location>(layer_exception(std::move(find_column.error().message())));

				multiform_storage->bind_blob(*find_column, 0, *column);
				auto cursor = prepared_query(multiform_storage, label, __func__, *find_column);
				if (!cursor || cursor->error())
					return expects_lr<multiform_location>(layer_exception(error_of(cursor)));

				column_location = (*cursor)["column_number"].get().get_integer();
				if (!(resolver_flags & (uint8_t)resolver::disable_cache))
					update_column = true;
			}

			if (row && !row_location)
			{
				auto multiform_storage = get_multiform_storage(type);
				auto find_row = multiform_storage->prepare_statement("SELECT row_number FROM rows WHERE row_hash = ?", nullptr);
				if (!find_row)
					return expects_lr<multiform_location>(layer_exception(std::move(find_row.error().message())));

				multiform_storage->bind_blob(*find_row, 0, *row);
				auto cursor = prepared_query(multiform_storage, label, __func__, *find_row);
				if (!cursor || cursor->error())
					return expects_lr<multiform_location>(layer_exception(error_of(cursor)));

				row_location = (*cursor)["row_number"].get().get_integer();
				if (!(resolver_flags & (uint8_t)resolver::disable_cache))
					update_row = true;
			}

			if (column && row)
			{
				if (!column_location.or_else(0) || !row_location.or_else(0))
					return layer_exception("multiform state location not found");
				else if (update_column || update_row)
					cache->set_multiform_location(type, *column, *row, *column_location, *row_location);
			}
			else if (column)
			{
				if (!column_location.or_else(0))
					return layer_exception("multiform state column not found");
				else if (update_column)
					cache->set_column_location(type, *column, *column_location);
			}
			else if (row)
			{
				if (!row_location.or_else(0))
					return layer_exception("multiform state row not found");
				else if (update_row)
					cache->set_row_location(type, *row, *row_location);
			}

			multiform_location location;
			location.column = column_location && *column_location > 0 ? std::move(column_location) : option<uint64_t>(optional::none);
			location.row = row_location && *row_location > 0 ? std::move(row_location) : option<uint64_t>(optional::none);
			location.block = block_location && block_location->number > 0 ? std::move(block_location) : option<block_pair>(optional::none);
			return location;
		}
		expects_lr<uint64_t> chainstate::resolve_account_location(const algorithm::pubkeyhash account)
		{
			VI_ASSERT(account, "account should be set");
			auto cache = account_cache::get();
			auto account_number_cache = cache->get_account_location(std::string_view((char*)account, sizeof(algorithm::pubkeyhash)));
			if (account_number_cache)
			{
				if (!*account_number_cache)
					return layer_exception("account not found");

				return account_number_cache.or_else(0);
			}

			auto* accountdata = get_account_storage();
			auto find_account = accountdata->prepare_statement("SELECT account_number FROM accounts WHERE account_hash = ?", nullptr);
			if (!find_account)
				return expects_lr<uint64_t>(layer_exception(std::move(find_account.error().message())));

			accountdata->bind_blob(*find_account, 0, std::string_view((char*)account, sizeof(algorithm::pubkeyhash)));
			auto cursor = prepared_query(get_account_storage(), label, __func__, *find_account);
			if (!cursor || cursor->error())
				return expects_lr<uint64_t>(layer_exception(error_of(cursor)));

			uint64_t account_number = (*cursor)["account_number"].get().get_integer();
			cache->set_account_location(account, account_number);
			if (!account_number)
				return layer_exception("account not found");

			return account_number;
		}
		expects_lr<uint64_t> chainstate::get_checkpoint_block_number()
		{
			auto cursor = query(get_block_storage(), label, __func__, "SELECT MAX(block_number) AS block_number FROM checkpoints");
			if (!cursor || cursor->error_or_empty())
				return expects_lr<uint64_t>(layer_exception(error_of(cursor)));

			return (uint64_t)(*cursor)["block_number"].get().get_integer();
		}
		expects_lr<uint64_t> chainstate::get_latest_block_number()
		{
			auto cursor = query(get_block_storage(), label, __func__, "SELECT block_number FROM blocks ORDER BY block_number DESC LIMIT 1");
			if (!cursor || cursor->error_or_empty())
				return expects_lr<uint64_t>(layer_exception(error_of(cursor)));

			uint64_t block_number = (*cursor)["block_number"].get().get_integer();
			return block_number;
		}
		expects_lr<uint64_t> chainstate::get_block_number_by_hash(const uint256_t& block_hash)
		{
			uint8_t hash[32];
			algorithm::encoding::decode_uint256(block_hash, hash);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));

			auto cursor = emplace_query(get_block_storage(), label, __func__, "SELECT block_number FROM blocks WHERE block_hash = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<uint64_t>(layer_exception(error_of(cursor)));

			return (uint64_t)(*cursor)["block_number"].get().get_integer();
		}
		expects_lr<uint256_t> chainstate::get_block_hash_by_number(uint64_t block_number)
		{
			schema_list map;
			map.push_back(var::set::integer(block_number));

			auto cursor = emplace_query(get_block_storage(), label, __func__, "SELECT block_hash FROM blocks WHERE block_number = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<uint256_t>(layer_exception(error_of(cursor)));

			string hash = (*cursor)["block_hash"].get().get_blob();
			if (hash.size() != sizeof(uint256_t))
				return expects_lr<uint256_t>(layer_exception("hash deserialization error"));

			uint256_t result;
			algorithm::encoding::encode_uint256((uint8_t*)hash.data(), result);
			return result;
		}
		expects_lr<decimal> chainstate::get_block_gas_price(uint64_t block_number, const algorithm::asset_id& asset, double percentile)
		{
			if (percentile < 0.0 || percentile > 1.0)
				return expects_lr<decimal>(layer_exception("invalid percentile"));

			vector<decimal> gas_prices;
			size_t offset = 0;
			size_t count = ELEMENTS_MANY;
			while (true)
			{
				schema_list map;
				map.push_back(var::set::integer(block_number));
				map.push_back(var::set::integer(count));
				map.push_back(var::set::integer(offset));

				auto cursor = emplace_query(get_tx_storage(), label, __func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce LIMIT ? OFFSET ?", &map);
				if (!cursor || cursor->error())
					return expects_lr<decimal>(layer_exception(error_of(cursor)));

				auto& response = cursor->first();
				size_t size = response.size(), stride = gas_prices.size();
				gas_prices.resize(gas_prices.size() + size);
				parallel::wail_all(parallel::for_loop(size, ELEMENTS_FEW, [&](size_t i)
				{
					auto row = response[i];
					auto& next = gas_prices[stride + i];
					auto transaction_hash = row["transaction_hash"].get();
					auto transaction_blob = load(label, __func__, get_transaction_label(transaction_hash.get_binary())).or_else(string());
					auto message = format::ro_stream(transaction_blob);
					uptr<ledger::transaction> value = transactions::resolver::from_stream(message);
					if (value && value->load(message) && value->asset == asset)
						next = std::move(value->gas_price);
					else
						next = decimal::nan();
				}));
				if (size < count)
					break;
			}

			auto it = std::remove_if(gas_prices.begin(), gas_prices.end(), [](const decimal& a) { return a.is_nan(); });
			if (it != gas_prices.end())
				gas_prices.erase(it);

			std::sort(gas_prices.begin(), gas_prices.end(), [](const decimal& a, const decimal& b) { return a > b; });
			if (gas_prices.empty())
				return expects_lr<decimal>(layer_exception("gas price not found"));

			size_t index = (size_t)std::floor((1.0 - percentile) * (gas_prices.size() - 1));
			return gas_prices[index];
		}
		expects_lr<decimal> chainstate::get_block_asset_price(uint64_t block_number, const algorithm::asset_id& price_of, const algorithm::asset_id& relative_to, double percentile)
		{
			auto a = get_block_gas_price(block_number, price_of, percentile);
			if (!a || a->is_zero())
				return decimal::zero();

			auto b = get_block_gas_price(block_number, relative_to, percentile);
			if (!b)
				return decimal::zero();

			return *b / a->truncate(protocol::now().message.precision);
		}
		expects_lr<ledger::block> chainstate::get_block_by_number(uint64_t block_number, size_t chunk, uint32_t details)
		{
			schema_list map;
			map.push_back(var::set::integer(block_number));

			auto cursor = emplace_query(get_block_storage(), label, __func__, "SELECT block_hash FROM blocks WHERE block_number = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<ledger::block>(layer_exception(error_of(cursor)));

			ledger::block_header header;
			auto block_hash = (*cursor)["block_hash"].get();
			auto block_blob = load(label, __func__, get_block_label(block_hash.get_binary())).or_else(string());
			auto message = format::ro_stream(block_blob);
			if (!header.load(message))
				return expects_lr<ledger::block>(layer_exception("block header deserialization error"));

			ledger::block result = ledger::block(header);
			if ((details & (uint32_t)block_details::transactions || details & (uint32_t)block_details::block_transactions) && chunk > 0)
			{
				auto resolve = resolve_block_transactions(result.transactions, result.number, details & (uint32_t)block_details::block_transactions, chunk);
				if (!resolve)
					return resolve.error();
			}
			finalize_checksum(header, block_hash);
			return result;
		}
		expects_lr<ledger::block> chainstate::get_block_by_hash(const uint256_t& block_hash, size_t chunk, uint32_t details)
		{
			uint8_t hash[32];
			algorithm::encoding::decode_uint256(block_hash, hash);

			ledger::block_header header;
			auto block_blob = load(label, __func__, get_block_label(hash)).or_else(string());
			auto message = format::ro_stream(block_blob);
			if (!header.load(message))
				return expects_lr<ledger::block>(layer_exception("block header deserialization error"));

			ledger::block result = ledger::block(header);
			if ((details & (uint32_t)block_details::transactions || details & (uint32_t)block_details::block_transactions) && chunk > 0)
			{
				auto resolve = resolve_block_transactions(result.transactions, result.number, details & (uint32_t)block_details::block_transactions, chunk);
				if (!resolve)
					return resolve.error();
			}
			finalize_checksum(header, var::binary(hash, sizeof(hash)));
			return result;
		}
		expects_lr<ledger::block> chainstate::get_latest_block(size_t chunk, uint32_t details)
		{
			auto cursor = query(get_block_storage(), label, __func__, "SELECT block_hash FROM blocks ORDER BY block_number DESC LIMIT 1");
			if (!cursor || cursor->error_or_empty())
				return expects_lr<ledger::block>(layer_exception(error_of(cursor)));

			ledger::block_header header;
			auto block_hash = (*cursor)["block_hash"].get();
			auto block_blob = load(label, __func__, get_block_label(block_hash.get_binary())).or_else(string());
			auto message = format::ro_stream(block_blob);
			if (!header.load(message))
				return expects_lr<ledger::block>(layer_exception("block header deserialization error"));

			ledger::block result = ledger::block(header);
			if ((details & (uint32_t)block_details::transactions || details & (uint32_t)block_details::block_transactions) && chunk > 0)
			{
				auto resolve = resolve_block_transactions(result.transactions, result.number, details & (uint32_t)block_details::block_transactions, chunk);
				if (!resolve)
					return resolve.error();
			}
			finalize_checksum(header, block_hash);
			return result;
		}
		expects_lr<ledger::block_header> chainstate::get_block_header_by_number(uint64_t block_number)
		{
			schema_list map;
			map.push_back(var::set::integer(block_number));

			auto cursor = emplace_query(get_block_storage(), label, __func__, "SELECT block_hash FROM blocks WHERE block_number = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<ledger::block_header>(layer_exception(error_of(cursor)));

			ledger::block_header header;
			auto block_hash = (*cursor)["block_hash"].get();
			auto block_blob = load(label, __func__, get_block_label(block_hash.get_binary())).or_else(string());
			auto message = format::ro_stream(block_blob);
			if (!header.load(message))
				return expects_lr<ledger::block_header>(layer_exception("block header deserialization error"));

			finalize_checksum(header, block_hash);
			return header;
		}
		expects_lr<ledger::block_header> chainstate::get_block_header_by_hash(const uint256_t& block_hash)
		{
			uint8_t hash[32];
			algorithm::encoding::decode_uint256(block_hash, hash);

			ledger::block_header header;
			auto block_blob = load(label, __func__, get_block_label(hash)).or_else(string());
			auto message = format::ro_stream(block_blob);
			if (!header.load(message))
				return expects_lr<ledger::block_header>(layer_exception("block header deserialization error"));

			finalize_checksum(header, var::binary(hash, sizeof(hash)));
			return header;
		}
		expects_lr<ledger::block_header> chainstate::get_latest_block_header()
		{
			auto cursor = query(get_block_storage(), label, __func__, "SELECT block_hash FROM blocks ORDER BY block_number DESC LIMIT 1");
			if (!cursor || cursor->error_or_empty())
				return expects_lr<ledger::block_header>(layer_exception(error_of(cursor)));

			ledger::block_header header;
			auto block_hash = (*cursor)["block_hash"].get();
			auto block_blob = load(label, __func__, get_block_label(block_hash.get_binary())).or_else(string());
			auto message = format::ro_stream(block_blob);
			if (!header.load(message))
				return expects_lr<ledger::block_header>(layer_exception("block header deserialization error"));

			finalize_checksum(header, block_hash);
			return header;
		}
		expects_lr<ledger::block_proof> chainstate::get_block_proof_by_number(uint64_t block_number)
		{
			auto child_block = get_block_header_by_number(block_number);
			if (!child_block)
				return child_block.error();

			ledger::block_proof proof;
			proof.transaction_root = child_block->transaction_root;
			proof.receipt_root = child_block->receipt_root;
			proof.state_root = child_block->state_root;

			auto parent_block = get_block_header_by_number(child_block->number - 1);
			if (parent_block)
			{
				proof.transaction_tree.nodes.push_back(parent_block->transaction_root);
				proof.receipt_tree.nodes.push_back(parent_block->receipt_root);
				proof.state_tree.nodes.push_back(parent_block->state_root);
			}

			schema_list map;
			map.push_back(var::set::integer(block_number));

			auto cursor = emplace_query(get_tx_storage(), label, __func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce;", &map);
			if (!cursor || cursor->error())
				return expects_lr<ledger::block_proof>(layer_exception(error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			size_t stride = proof.transaction_tree.nodes.size();
			proof.transaction_tree.nodes.resize(stride + size);
			proof.receipt_tree.nodes.resize(stride + size);
			parallel::wail_all(parallel::for_loop(size, ELEMENTS_FEW, [&](size_t i)
			{
				auto transaction_hash = response[i]["transaction_hash"].get().get_blob();
				if (transaction_hash.size() == sizeof(uint256_t))
				{
					algorithm::encoding::encode_uint256((uint8_t*)transaction_hash.data(), proof.transaction_tree.nodes[stride + i]);
					auto transaction_blob = load(label, __func__, get_receipt_label((uint8_t*)transaction_hash.data())).or_else(string());
					proof.receipt_tree.nodes[stride + i] = format::ro_stream(transaction_blob).hash();
				}
				else
				{
					proof.transaction_tree.nodes[stride + i] = 0;
					proof.receipt_tree.nodes[stride + i] = 0;
				}
			}));

			for (auto& [type, uniform_storage] : get_uniform_storage_max())
			{
				cursor = emplace_query(*uniform_storage, label, __func__, "SELECT (SELECT index_hash FROM indices WHERE indices.index_number = snapshots.index_number) AS index_hash FROM snapshots WHERE block_number = ?", &map);
				if (!cursor || cursor->error())
					return expects_lr<ledger::block_proof>(layer_exception(error_of(cursor)));

				auto subresponse = cursor->first();
				auto substride = proof.state_tree.nodes.size();
				auto count = subresponse.size();
				proof.state_tree.nodes.resize(substride + count);
				parallel::wail_all(parallel::for_loop(count, ELEMENTS_FEW, [&](size_t i)
				{
					auto index = subresponse[i]["index_hash"].get().get_blob();
					auto blob = load(label, __func__, get_uniform_label(type, index, block_number)).or_else(string());
					auto state = state_from_blob(block_number, type, index, std::string_view(), blob);
					proof.state_tree.nodes[substride + i] = state ? state->as_hash() : uint256_t(0);
				}));
			}

			for (auto& [type, multiform_storage] : get_multiform_storage_max())
			{
				cursor = emplace_query(*multiform_storage, label, __func__, "SELECT (SELECT column_hash FROM columns WHERE columns.column_number = snapshots.column_number) AS column_hash, (SELECT row_hash FROM rows WHERE rows.row_number = snapshots.row_number) AS row_hash FROM snapshots WHERE block_number = ?", &map);
				if (!cursor || cursor->error())
					return expects_lr<ledger::block_proof>(layer_exception(error_of(cursor)));

				auto subresponse = cursor->first();
				auto stride = proof.state_tree.nodes.size();
				auto count = subresponse.size();
				proof.state_tree.nodes.resize(stride + count);
				parallel::wail_all(parallel::for_loop(count, ELEMENTS_FEW, [&](size_t i)
				{
					auto column = subresponse[i]["column_hash"].get().get_blob();
					auto row = subresponse[i]["row_hash"].get().get_blob();
					auto blob = load(label, __func__, get_multiform_label(type, column, row, block_number)).or_else(string());
					auto state = state_from_blob(block_number, type, column, row, blob);
					proof.state_tree.nodes[stride + i] = state ? state->as_hash() : uint256_t(0);
				}));
			}

			proof.transaction_tree = algorithm::merkle_tree::from(std::move(proof.transaction_tree.nodes));
			proof.receipt_tree = algorithm::merkle_tree::from(std::move(proof.receipt_tree.nodes));
			proof.state_tree = algorithm::merkle_tree::from(std::move(proof.state_tree.nodes));
			return proof;
		}
		expects_lr<ledger::block_proof> chainstate::get_block_proof_by_hash(const uint256_t& block_hash)
		{
			auto block_number = get_block_number_by_hash(block_hash);
			if (!block_number)
				return block_number.error();

			return get_block_proof_by_number(*block_number);
		}
		expects_lr<vector<uint256_t>> chainstate::get_block_transaction_hashset(uint64_t block_number)
		{
			if (!block_number)
				return layer_exception("invalid block number");

			schema_list map;
			map.push_back(var::set::integer(block_number));

			auto cursor = emplace_query(get_tx_storage(), label, __func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<uint256_t>>(layer_exception(error_of(cursor)));

			vector<uint256_t> result;
			for (auto& response : *cursor)
			{
				size_t size = response.size();
				result.reserve(result.size() + size);
				for (size_t i = 0; i < size; i++)
				{
					auto in_hash = response[i]["transaction_hash"].get().get_blob();
					if (in_hash.size() != sizeof(uint256_t))
						continue;

					uint256_t out_hash;
					algorithm::encoding::encode_uint256((uint8_t*)in_hash.data(), out_hash);
					result.push_back(out_hash);
				}
			}

			return result;
		}
		expects_lr<vector<uint256_t>> chainstate::get_block_state_hashset(uint64_t block_number)
		{
			if (!block_number)
				return layer_exception("invalid block number");

			vector<uint256_t> result;
			schema_list map;
			map.push_back(var::set::integer(block_number));

			for (auto& [type, uniform_storage] : get_uniform_storage_max())
			{
				auto cursor = emplace_query(*uniform_storage, label, __func__, "SELECT (SELECT index_hash FROM indices WHERE indices.index_number = snapshots.index_number) AS index_hash FROM snapshots WHERE block_number = ?", &map);
				if (!cursor || cursor->error())
					return expects_lr<vector<uint256_t>>(layer_exception(error_of(cursor)));

				auto subresponse = cursor->first();
				auto stride = result.size();
				auto count = subresponse.size();
				result.resize(stride + count);
				parallel::wail_all(parallel::for_loop(count, ELEMENTS_FEW, [&](size_t i)
				{
					auto index = subresponse[i]["index_hash"].get().get_blob();
					auto blob = load(label, __func__, get_uniform_label(type, index, block_number)).or_else(string());
					auto state = state_from_blob(block_number, type, index, std::string_view(), blob);
					result[stride + i] = state ? state->as_hash() : uint256_t(0);
				}));
			}

			for (auto& [type, multiform_storage] : get_multiform_storage_max())
			{
				auto cursor = emplace_query(*multiform_storage, label, __func__, "SELECT (SELECT column_hash FROM columns WHERE columns.column_number = snapshots.column_number) AS column_hash, (SELECT row_hash FROM rows WHERE rows.row_number = snapshots.row_number) AS row_hash FROM snapshots WHERE block_number = ?", &map);
				if (!cursor || cursor->error())
					return expects_lr<vector<uint256_t>>(layer_exception(error_of(cursor)));

				auto subresponse = cursor->first();
				auto stride = result.size();
				auto count = subresponse.size();
				result.resize(stride + count);
				parallel::wail_all(parallel::for_loop(count, ELEMENTS_FEW, [&](size_t i)
				{
					auto column = subresponse[i]["column_hash"].get().get_blob();
					auto row = subresponse[i]["row_hash"].get().get_blob();
					auto blob = load(label, __func__, get_multiform_label(type, column, row, block_number)).or_else(string());
					auto state = state_from_blob(block_number, type, column, row, blob);
					result[stride + i] = state ? state->as_hash() : uint256_t(0);
				}));
			}

			std::sort(result.begin(), result.end());
			return result;
		}
		expects_lr<vector<uint256_t>> chainstate::get_block_hashset(uint64_t block_number, size_t count)
		{
			if (!count || !block_number)
				return layer_exception("invalid block range");

			schema_list map;
			map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(block_number + count));

			auto cursor = emplace_query(get_block_storage(), label, __func__, "SELECT block_hash FROM blocks WHERE block_number BETWEEN ? AND ? ORDER BY block_number DESC", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<uint256_t>>(layer_exception(error_of(cursor)));

			vector<uint256_t> result;
			for (auto& response : *cursor)
			{
				size_t size = response.size();
				result.reserve(result.size() + size);
				for (size_t i = 0; i < size; i++)
				{
					auto in_hash = response[i]["block_hash"].get().get_blob();
					if (in_hash.size() != sizeof(uint256_t))
						continue;

					uint256_t out_hash;
					algorithm::encoding::encode_uint256((uint8_t*)in_hash.data(), out_hash);
					result.push_back(out_hash);
				}
			}

			return result;
		}
		expects_lr<vector<ledger::block_header>> chainstate::get_block_headers(uint64_t block_number, size_t count)
		{
			if (!count || !block_number)
				return layer_exception("invalid block range");

			schema_list map;
			map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(block_number + count));

			auto cursor = emplace_query(get_block_storage(), label, __func__, "SELECT block_hash FROM blocks WHERE block_number BETWEEN ? AND ? ORDER BY block_number DESC", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<ledger::block_header>>(layer_exception(error_of(cursor)));

			vector<ledger::block_header> result;
			for (auto& response : *cursor)
			{
				size_t size = response.size();
				result.resize(result.size() + size);
				parallel::wail_all(parallel::for_loop(size, ELEMENTS_FEW, [&](size_t i)
				{
					auto block_hash = response[i]["block_hash"].get();
					auto block_blob = load(label, __func__, get_block_label(block_hash.get_binary())).or_else(string());
					auto message = format::ro_stream(block_blob);
					result[i].load(message);
				}));
			}

			return result;
		}
		expects_lr<ledger::block_state> chainstate::get_block_state_by_number(uint64_t block_number, size_t chunk)
		{
			schema_list map;
			map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(chunk));
			map.push_back(var::set::integer(0));

			ledger::block_state result;
			for (auto& [type, uniform_storage] : get_uniform_storage_max())
			{
				size_t offset = 0;
				map[2]->value = var::integer(offset);
				while (true)
				{
					auto cursor = emplace_query(*uniform_storage, label, __func__, "SELECT (SELECT index_hash FROM indices WHERE indices.index_number = snapshots.index_number) AS index_hash, hidden FROM snapshots WHERE block_number = ? LIMIT ? OFFSET ?", &map);
					if (!cursor || cursor->error())
						return expects_lr<ledger::block_state>(layer_exception(error_of(cursor)));

					auto& response = cursor->first();
					size_t size = response.size();
					for (size_t i = 0; i < size; i++)
					{
						auto next = response[i];
						auto index = next["index_hash"].get().get_blob();
						auto hidden = next["hidden"].get().get_boolean();
						auto blob = load(label, __func__, get_uniform_label(type, index, block_number)).or_else(string());
						auto next_state = state_from_blob(block_number, type, index, std::string_view(), blob);
						if (next_state)
							result.emplace(std::move(next_state), hidden);
					}

					offset += size;
					map[2]->value = var::integer(offset);
					if (size < chunk)
						break;
				}
			}

			for (auto& [type, multiform_storage] : get_multiform_storage_max())
			{
				size_t offset = 0;
				map[2]->value = var::integer(offset);
				while (true)
				{
					auto cursor = emplace_query(*multiform_storage, label, __func__, "SELECT (SELECT column_hash FROM columns WHERE columns.column_number = snapshots.column_number) AS column_hash, (SELECT row_hash FROM rows WHERE rows.row_number = snapshots.row_number) AS row_hash, hidden FROM snapshots WHERE block_number = ? LIMIT ? OFFSET ?", &map);
					if (!cursor || cursor->error())
						return expects_lr<ledger::block_state>(layer_exception(error_of(cursor)));

					auto& response = cursor->first();
					size_t size = response.size();
					for (size_t i = 0; i < size; i++)
					{
						auto next = response[i];
						auto column = next["column_hash"].get().get_blob();
						auto row = next["row_hash"].get().get_blob();
						auto hidden = next["hidden"].get().get_boolean();
						auto blob = load(label, __func__, get_multiform_label(type, column, row, block_number)).or_else(string());
						auto next_state = state_from_blob(block_number, type, column, row, blob);
						if (next_state)
							result.emplace(std::move(next_state), hidden);
					}

					offset += size;
					map[2]->value = var::integer(offset);
					if (size < chunk)
						break;
				}
			}

			result.commit();
			return expects_lr<ledger::block_state>(std::move(result));
		}
		expects_lr<vector<uptr<ledger::transaction>>> chainstate::get_transactions_by_number(uint64_t block_number, size_t offset, size_t count)
		{
			schema_list map;
			map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = emplace_query(get_tx_storage(), label, __func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<uptr<ledger::transaction>>>(layer_exception(error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			vector<uptr<ledger::transaction>> values;
			values.resize(size);

			parallel::wail_all(parallel::for_loop(size, ELEMENTS_FEW, [&](size_t i)
			{
				auto row = response[i];
				auto& value = values[i];
				auto transaction_hash = row["transaction_hash"].get();
				auto transaction_blob = load(label, __func__, get_transaction_label(transaction_hash.get_binary())).or_else(string());
				auto message = format::ro_stream(transaction_blob);
				value = transactions::resolver::from_stream(message);
				if (value && value->load(message))
					finalize_checksum(**value, transaction_hash);
			}));

			auto it = std::remove_if(values.begin(), values.end(), [](const uptr<ledger::transaction>& a) { return !a; });
			if (it != values.end())
				values.erase(it);
			return values;
		}
		expects_lr<vector<uptr<ledger::transaction>>> chainstate::get_transactions_by_owner(uint64_t block_number, const algorithm::pubkeyhash owner, int8_t direction, size_t offset, size_t count)
		{
			auto location = resolve_account_location(owner);
			if (!location)
				return expects_lr<vector<uptr<ledger::transaction>>>(vector<uptr<ledger::transaction>>());

			schema_list map;
			map.push_back(var::set::integer(*location));
			map.push_back(var::set::integer(block_number));
			map.push_back(var::set::string(direction < 0 ? "DESC" : "ASC"));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = emplace_query(get_party_storage(), label, __func__, "SELECT transaction_number FROM parties WHERE transaction_account_number = ? AND block_number <= ? ORDER BY transaction_number $? LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<uptr<ledger::transaction>>>(layer_exception(error_of(cursor)));
			else if (cursor->empty())
				return expects_lr<vector<uptr<ledger::transaction>>>(vector<uptr<ledger::transaction>>());

			string dynamic_query = "SELECT transaction_hash FROM transactions WHERE transaction_number IN (";
			for (auto row : cursor->first())
				dynamic_query.append(row.get_column(0).get().get_blob()).push_back(',');
			dynamic_query.pop_back();
			dynamic_query.append(") ORDER BY transaction_number ");
			dynamic_query.append(direction < 0 ? "DESC" : "ASC");

			cursor = query(get_tx_storage(), label, __func__, dynamic_query);
			if (!cursor || cursor->error())
				return expects_lr<vector<uptr<ledger::transaction>>>(layer_exception(error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			vector<uptr<ledger::transaction>> values;
			values.resize(size);

			parallel::wail_all(parallel::for_loop(size, ELEMENTS_FEW, [&](size_t i)
			{
				auto row = response[i];
				auto& value = values[i];
				auto transaction_hash = row["transaction_hash"].get();
				auto transaction_blob = load(label, __func__, get_transaction_label(transaction_hash.get_binary())).or_else(string());
				auto message = format::ro_stream(transaction_blob);
				value = transactions::resolver::from_stream(message);
				if (value && value->load(message))
					finalize_checksum(**value, transaction_hash);
			}));

			auto it = std::remove_if(values.begin(), values.end(), [](const uptr<ledger::transaction>& a) { return !a; });
			if (it != values.end())
				values.erase(it);
			return values;
		}
		expects_lr<vector<ledger::block_transaction>> chainstate::get_block_transactions_by_number(uint64_t block_number, size_t offset, size_t count)
		{
			schema_list map;
			map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = emplace_query(get_tx_storage(), label, __func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<ledger::block_transaction>>(layer_exception(error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			vector<ledger::block_transaction> values;
			values.resize(size);

			parallel::wail_all(parallel::for_loop(size, ELEMENTS_FEW, [&](size_t i)
			{
				auto row = response[i];
				auto& value = values[i];
				auto transaction_hash = row["transaction_hash"].get();
				auto transaction_blob = load(label, __func__, get_transaction_label(transaction_hash.get_binary())).or_else(string());
				auto receipt_blob = load(label, __func__, get_receipt_label(transaction_hash.get_binary())).or_else(string());
				auto transaction_message = format::ro_stream(transaction_blob);
				auto receipt_message = format::ro_stream(receipt_blob);
				value.transaction = transactions::resolver::from_stream(transaction_message);
				if (value.transaction && value.transaction->load(transaction_message) && value.receipt.load(receipt_message))
					finalize_checksum(**value.transaction, transaction_hash);
			}));

			auto it = std::remove_if(values.begin(), values.end(), [](const ledger::block_transaction& a) { return !a.transaction; });
			if (it != values.end())
				values.erase(it);
			return values;
		}
		expects_lr<vector<ledger::block_transaction>> chainstate::get_block_transactions_by_owner(uint64_t block_number, const algorithm::pubkeyhash owner, int8_t direction, size_t offset, size_t count)
		{
			auto location = resolve_account_location(owner);
			if (!location)
				return expects_lr<vector<ledger::block_transaction>>(vector<ledger::block_transaction>());

			schema_list map;
			map.push_back(var::set::integer(*location));
			map.push_back(var::set::integer(block_number));
			map.push_back(var::set::string(direction < 0 ? "DESC" : "ASC"));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = emplace_query(get_party_storage(), label, __func__, "SELECT transaction_number FROM parties WHERE transaction_account_number = ? AND block_number <= ? ORDER BY transaction_number $? LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<ledger::block_transaction>>(layer_exception(error_of(cursor)));
			else if (cursor->empty())
				return expects_lr<vector<ledger::block_transaction>>(vector<ledger::block_transaction>());

			string dynamic_query = "SELECT transaction_hash FROM transactions WHERE transaction_number IN (";
			for (auto row : cursor->first())
				dynamic_query.append(row.get_column(0).get().get_blob()).push_back(',');
			dynamic_query.pop_back();
			dynamic_query.append(") ORDER BY transaction_number ");
			dynamic_query.append(direction < 0 ? "DESC" : "ASC");

			cursor = query(get_tx_storage(), label, __func__, dynamic_query);
			if (!cursor || cursor->error())
				return expects_lr<vector<ledger::block_transaction>>(layer_exception(error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			vector<ledger::block_transaction> values;
			values.resize(size);

			parallel::wail_all(parallel::for_loop(size, ELEMENTS_FEW, [&](size_t i)
			{
				auto row = response[i];
				auto& value = values[i];
				auto transaction_hash = row["transaction_hash"].get();
				auto transaction_blob = load(label, __func__, get_transaction_label(transaction_hash.get_binary())).or_else(string());
				auto receipt_blob = load(label, __func__, get_receipt_label(transaction_hash.get_binary())).or_else(string());
				auto transaction_message = format::ro_stream(transaction_blob);
				auto receipt_message = format::ro_stream(receipt_blob);
				value.transaction = transactions::resolver::from_stream(transaction_message);
				if (value.transaction && value.transaction->load(transaction_message) && value.receipt.load(receipt_message))
					finalize_checksum(**value.transaction, transaction_hash);
			}));

			auto it = std::remove_if(values.begin(), values.end(), [](const ledger::block_transaction& a) { return !a.transaction; });
			if (it != values.end())
				values.erase(it);
			return values;
		}
		expects_lr<vector<ledger::receipt>> chainstate::get_block_receipts_by_number(uint64_t block_number, size_t offset, size_t count)
		{
			schema_list map;
			map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = emplace_query(get_tx_storage(), label, __func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<ledger::receipt>>(layer_exception(error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			vector<ledger::receipt> values;
			values.reserve(size);

			for (size_t i = 0; i < size; i++)
			{
				auto row = response[i];
				ledger::receipt value;
				auto transaction_hash = row["transaction_hash"].get();
				auto receipt_blob = load(label, __func__, get_receipt_label(transaction_hash.get_binary())).or_else(string());
				auto message = format::ro_stream(receipt_blob);
				if (value.load(message))
					values.emplace_back(std::move(value));
			}

			return values;
		}
		expects_lr<vector<ledger::block_transaction>> chainstate::get_pending_block_transactions(uint64_t block_number, size_t offset, size_t count)
		{
			schema_list map;
			map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = emplace_query(get_tx_storage(), label, __func__, "SELECT transaction_hash FROM transactions WHERE dispatch_queue IS NOT NULL AND dispatch_queue <= ? ORDER BY block_nonce LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<ledger::block_transaction>>(layer_exception(error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			vector<ledger::block_transaction> values;
			values.resize(size);

			parallel::wail_all(parallel::for_loop(size, ELEMENTS_FEW, [&](size_t i)
			{
				auto row = response[i];
				auto& value = values[i];
				auto transaction_hash = row["transaction_hash"].get();
				auto transaction_blob = load(label, __func__, get_transaction_label(transaction_hash.get_binary())).or_else(string());
				auto receipt_blob = load(label, __func__, get_receipt_label(transaction_hash.get_binary())).or_else(string());
				auto transaction_message = format::ro_stream(transaction_blob);
				auto receipt_message = format::ro_stream(receipt_blob);
				value.transaction = transactions::resolver::from_stream(transaction_message);
				if (value.transaction && value.transaction->load(transaction_message) && value.receipt.load(receipt_message))
					finalize_checksum(**value.transaction, transaction_hash);
			}));

			auto it = std::remove_if(values.begin(), values.end(), [](const ledger::block_transaction& a) { return !a.transaction; });
			if (it != values.end())
				values.erase(it);
			return values;
		}
		expects_lr<uptr<ledger::transaction>> chainstate::get_transaction_by_hash(const uint256_t& transaction_hash)
		{
			uint8_t hash[32];
			algorithm::encoding::decode_uint256(transaction_hash, hash);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));

			auto cursor = emplace_query(get_alias_storage(), label, __func__, "SELECT transaction_number FROM aliases WHERE transaction_hash = ?", &map);
			string dynamic_query = "SELECT transaction_hash FROM transactions WHERE transaction_hash = ?";
			if (cursor && !cursor->error_or_empty())
			{
				dynamic_query.append("OR transaction_number IN (");
				for (auto row : cursor->first())
					dynamic_query.append(row.get_column(0).get().get_blob()).push_back(',');
				dynamic_query.pop_back();
				dynamic_query.push_back(')');
			}
			dynamic_query.append(" ORDER BY transaction_number DESC LIMIT 1");

			cursor = emplace_query(get_tx_storage(), label, __func__, dynamic_query, &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<uptr<ledger::transaction>>(layer_exception(error_of(cursor)));

			auto parent_transaction_hash = (*cursor)["transaction_hash"].get();
			auto transaction_blob = load(label, __func__, get_transaction_label(parent_transaction_hash.get_binary())).or_else(string());
			auto transaction_message = format::ro_stream(transaction_blob);
			uptr<ledger::transaction> value = transactions::resolver::from_stream(transaction_message);
			if (!value || !value->load(transaction_message))
				return expects_lr<uptr<ledger::transaction>>(layer_exception("transaction deserialization error"));

			finalize_checksum(**value, parent_transaction_hash);
			return value;
		}
		expects_lr<ledger::block_transaction> chainstate::get_block_transaction_by_hash(const uint256_t& transaction_hash)
		{
			uint8_t hash[32];
			algorithm::encoding::decode_uint256(transaction_hash, hash);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));

			auto cursor = emplace_query(get_alias_storage(), label, __func__, "SELECT transaction_number FROM aliases WHERE transaction_hash = ?", &map);
			string dynamic_query = "SELECT transaction_hash FROM transactions WHERE transaction_hash = ?";
			if (cursor && !cursor->error_or_empty())
			{
				dynamic_query.append("OR transaction_number IN (");
				for (auto row : cursor->first())
					dynamic_query.append(row.get_column(0).get().get_blob()).push_back(',');
				dynamic_query.pop_back();
				dynamic_query.push_back(')');
			}
			dynamic_query.append(" ORDER BY transaction_number DESC LIMIT 1");

			cursor = emplace_query(get_tx_storage(), label, __func__, dynamic_query, &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<ledger::block_transaction>(layer_exception(error_of(cursor)));

			auto parent_transaction_hash = (*cursor)["transaction_hash"].get();
			auto transaction_blob = load(label, __func__, get_transaction_label(parent_transaction_hash.get_binary())).or_else(string());
			auto receipt_blob = load(label, __func__, get_receipt_label(parent_transaction_hash.get_binary())).or_else(string());
			auto transaction_message = format::ro_stream(transaction_blob);
			auto receipt_message = format::ro_stream(receipt_blob);
			ledger::block_transaction value;
			value.transaction = transactions::resolver::from_stream(transaction_message);
			if (!value.transaction || !value.transaction->load(transaction_message) || !value.receipt.load(receipt_message))
				return expects_lr<ledger::block_transaction>(layer_exception("block transaction deserialization error"));

			finalize_checksum(**value.transaction, parent_transaction_hash);
			return value;
		}
		expects_lr<ledger::receipt> chainstate::get_receipt_by_transaction_hash(const uint256_t& transaction_hash)
		{
			uint8_t hash[32];
			algorithm::encoding::decode_uint256(transaction_hash, hash);

			ledger::receipt value;
			auto receipt_blob = load(label, __func__, get_receipt_label(hash)).or_else(string());
			auto receipt_message = format::ro_stream(receipt_blob);
			if (!value.load(receipt_message))
				return expects_lr<ledger::receipt>(layer_exception("receipt deserialization error"));

			return value;
		}
		expects_lr<uptr<ledger::state>> chainstate::get_uniform(uint32_t type, const ledger::block_changelog* changelog, const std::string_view& index, uint64_t block_number)
		{
			if (changelog != nullptr)
			{
				auto candidate = changelog->outgoing.find(type, index);
				if (candidate)
					return std::move(*candidate);

				candidate = changelog->incoming.find(type, index);
				if (candidate)
					return std::move(*candidate);
			}

			auto location = resolve_uniform_location(type, index, block_number > 0 ? 0 : (uint8_t)resolver::find_exact_match);
			if (!location)
				return location.error();

			if (!location->block)
			{
				auto* uniform_storage = get_uniform_storage(type);
				auto find_state = uniform_storage->prepare_statement(!block_number ?
					"SELECT block_number FROM uniforms WHERE index_number = ?" :
					"SELECT block_number, hidden FROM snapshots WHERE index_number = ? AND block_number < ? ORDER BY block_number DESC LIMIT 1", nullptr);
				if (!find_state)
					return expects_lr<uptr<ledger::state>>(layer_exception(std::move(find_state.error().message())));

				uniform_storage->bind_int64(*find_state, 0, location->index.or_else(0));
				if (block_number > 0)
					uniform_storage->bind_int64(*find_state, 1, block_number);

				auto cursor = prepared_query(uniform_storage, label, __func__, *find_state);
				if (!cursor)
				{
					if (changelog != nullptr)
						((ledger::block_changelog*)changelog)->incoming.erase(type, index);
					return expects_lr<uptr<ledger::state>>(layer_exception(error_of(cursor)));
				}
				else if (cursor->empty())
				{
					if (changelog != nullptr)
						((ledger::block_changelog*)changelog)->incoming.erase(type, index);
					return expects_lr<uptr<ledger::state>>(layer_exception("uniform state not found"));
				}

				auto cache = uniform_cache::get();
				location->block = block_pair((*cursor)["block_number"].get().get_integer(), (*cursor)["hidden"].get().get_boolean());
				cache->set_block_location(type, location->index.or_else(0), location->block->number, location->block->hidden);
			}

			auto blob = load(label, __func__, get_uniform_label(type, index, location->block->number)).or_else(string());
			auto value = state_from_blob(location->block->number, type, index, std::string_view(), blob);
			if (!value)
			{
				if (changelog != nullptr)
					((ledger::block_changelog*)changelog)->incoming.erase(type, index);
				return expects_lr<uptr<ledger::state>>(layer_exception("uniform state deserialization error"));
			}

			if (changelog != nullptr)
				((ledger::block_changelog*)changelog)->incoming.push(*value, location->block->hidden);
			return value;
		}
		expects_lr<uptr<ledger::state>> chainstate::get_multiform(uint32_t type, const ledger::block_changelog* changelog, const std::string_view& column, const std::string_view& row, uint64_t block_number)
		{
			if (changelog != nullptr)
			{
				auto candidate = changelog->outgoing.find(type, column, row);
				if (candidate)
					return std::move(*candidate);

				candidate = changelog->incoming.find(type, column, row);
				if (candidate)
					return std::move(*candidate);
			}

			auto location = resolve_multiform_location(type, column, row, block_number > 0 ? 0 : (uint8_t)resolver::find_exact_match);
			if (!location)
				return location.error();

			if (!location->block)
			{
				auto* multiform_storage = get_multiform_storage(type);
				auto find_state = multiform_storage->prepare_statement(!block_number ?
					"SELECT block_number FROM multiforms WHERE column_number = ? AND row_number = ?" :
					"SELECT block_number, hidden FROM snapshots WHERE column_number = ? AND row_number = ? AND block_number < ? ORDER BY block_number DESC LIMIT 1", nullptr);
				if (!find_state)
					return expects_lr<uptr<ledger::state>>(layer_exception(std::move(find_state.error().message())));

				multiform_storage->bind_int64(*find_state, 0, location->column.or_else(0));
				multiform_storage->bind_int64(*find_state, 1, location->row.or_else(0));
				if (block_number > 0)
					multiform_storage->bind_int64(*find_state, 2, block_number);

				auto cursor = prepared_query(multiform_storage, label, __func__, *find_state);
				if (!cursor)
				{
					if (changelog != nullptr)
						((ledger::block_changelog*)changelog)->incoming.erase(type, column, row);
					return expects_lr<uptr<ledger::state>>(layer_exception(error_of(cursor)));
				}
				else if (cursor->empty())
				{
					if (changelog != nullptr)
						((ledger::block_changelog*)changelog)->incoming.erase(type, column, row);
					return expects_lr<uptr<ledger::state>>(layer_exception("multiform state not found"));
				}

				auto cache = multiform_cache::get();
				location->block = block_pair((*cursor)["block_number"].get().get_integer(), (*cursor)["hidden"].get().get_boolean());
				cache->set_block_location(type, location->column.or_else(0), location->row.or_else(0), location->block->number, location->block->hidden);
			}

			auto blob = load(label, __func__, get_multiform_label(type, column, row, location->block->number)).or_else(string());
			auto value = state_from_blob(location->block->number, type, column, row, blob);
			if (!value)
			{
				if (changelog != nullptr)
					((ledger::block_changelog*)changelog)->incoming.erase(type, column, row);
				return expects_lr<uptr<ledger::state>>(layer_exception("multiform state deserialization error"));
			}

			if (changelog != nullptr)
				((ledger::block_changelog*)changelog)->incoming.push(*value, location->block->hidden);
			return value;
		}
		expects_lr<vector<uptr<ledger::state>>> chainstate::get_multiforms_by_column(uint32_t type, ledger::block_changelog* changelog, const std::string_view& column, uint64_t block_number, size_t offset, size_t count)
		{
			auto temporary = resolve_temporary_state(type, changelog, column, optional::none, block_number);
			if (!temporary)
				return temporary.error();

			auto location = resolve_multiform_location(type, column, optional::none, temporary->in_use ? (uint8_t)resolver::disable_cache : 0);
			if (!location)
				return expects_lr<vector<uptr<ledger::state>>>(vector<uptr<ledger::state>>());

			schema_list map;
			map.push_back(var::set::integer(location->column.or_else(0)));
			if (block_number > 0)
				map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = emplace_query(temporary->storage, label, __func__, !block_number ?
				"SELECT (SELECT row_hash FROM rows WHERE rows.row_number = multiforms.row_number) AS row_hash, block_number FROM multiforms WHERE column_number = ? ORDER BY row_number LIMIT ? OFFSET ?" :
				"SELECT * FROM (SELECT (SELECT row_hash FROM rows WHERE rows.row_number = snapshots.row_number) AS row_hash, hidden, MAX(block_number) AS block_number FROM snapshots WHERE column_number = ? AND block_number < ? GROUP BY row_number ORDER BY row_number) WHERE hidden = FALSE LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<uptr<ledger::state>>>(layer_exception(error_of(cursor)));

			vector<uptr<ledger::state>> values;
			auto& response = cursor->first();
			size_t size = response.size();
			for (size_t i = 0; i < size; i++)
			{
				auto next = response[i];
				auto row = next["row_hash"].get().get_blob();
				if (changelog != nullptr)
				{
					auto candidate = changelog->outgoing.find(type, column, row);
					if (candidate)
					{
						values.push_back(std::move(*candidate));
						continue;
					}

					candidate = changelog->incoming.find(type, column, row);
					if (candidate)
					{
						values.push_back(std::move(*candidate));
						continue;
					}
				}

				auto state_block_number = next["block_number"].get().get_integer();
				auto blob = load(label, __func__, get_multiform_label(type, column, row, state_block_number)).or_else(string());
				auto next_state = state_from_blob(state_block_number, type, column, row, blob);
				if (!next_state)
				{
					if (next_state && changelog != nullptr)
						((ledger::block_changelog*)changelog)->incoming.erase(type, column, ((ledger::multiform*)*next_state)->as_row());
					continue;
				}
				else if (changelog != nullptr)
					((ledger::block_changelog*)changelog)->incoming.push(*next_state, false);
				values.push_back(std::move(next_state));
			}

			return values;
		}
		expects_lr<vector<uptr<ledger::state>>> chainstate::get_multiforms_by_column_filter(uint32_t type, ledger::block_changelog* changelog, const std::string_view& column, const result_filter& filter, uint64_t block_number, const result_window& window)
		{
			auto temporary = resolve_temporary_state(type, changelog, column, optional::none, block_number);
			if (!temporary)
				return temporary.error();

			auto location = resolve_multiform_location(type, column, optional::none, temporary->in_use ? (uint8_t)resolver::disable_cache : 0);
			if (!location)
				return expects_lr<vector<uptr<ledger::state>>>(vector<uptr<ledger::state>>());

			schema_list map; string pattern;
			if (window.type() == result_range_window::instance_type())
			{
				auto& range = *(result_range_window*)&window;
				map.push_back(var::set::integer(location->column.or_else(0)));
				if (block_number > 0)
					map.push_back(var::set::integer(block_number));
				map.push_back(var::set::string(filter.as_condition()));
				map.push_back(var::set::binary(filter.as_value()));
				map.push_back(var::set::string(filter.as_order()));
				map.push_back(var::set::integer(range.count));
				map.push_back(var::set::integer(range.offset));

				pattern = !block_number ?
					"SELECT (SELECT row_hash FROM rows WHERE rows.row_number = multiforms.row_number) AS row_hash, block_number FROM multiforms WHERE column_number = ? AND rank $? ? ORDER BY rank $?, row_number ASC LIMIT ? OFFSET ?" :
					"SELECT (SELECT row_hash FROM rows WHERE rows.row_number = queryforms.row_number) AS row_hash, block_number FROM (SELECT column_number, row_number, rank, hidden, MAX(block_number) AS block_number FROM snapshots WHERE column_number = ? AND block_number < ? GROUP BY row_number) AS queryforms WHERE hidden = FALSE AND rank $? ? ORDER BY rank $?, row_number ASC LIMIT ? OFFSET ?";
			}
			else if (window.type() == result_index_window::instance_type())
			{
				string indices;
				for (auto& item : ((result_index_window*)&window)->indices)
					indices += to_string(item + 1) + ",";

				map.push_back(var::set::string(filter.as_order()));
				map.push_back(var::set::integer(location->column.or_else(0)));
				if (block_number > 0)
					map.push_back(var::set::integer(block_number));
				map.push_back(var::set::string(filter.as_condition()));
				map.push_back(var::set::binary(filter.as_value()));
				map.push_back(var::set::string(indices.substr(0, indices.size() - 1)));

				pattern = !block_number ?
					"SELECT (SELECT row_hash FROM rows WHERE rows.row_number = sq.row_number) AS row_hash, block_number FROM (SELECT ROW_NUMBER() OVER (ORDER BY rank $?, row_number ASC) AS id, row_number, block_number FROM multiforms WHERE column_number = ? AND rank $? ?) AS sq WHERE sq.id IN ($?) ORDER BY sq.id ASC" :
					"SELECT (SELECT row_hash FROM rows WHERE rows.row_number = sq.row_number) AS row_hash, block_number FROM (SELECT ROW_NUMBER() OVER (ORDER BY rank $?, row_number ASC) AS id, row_number, block_number FROM (SELECT column_number, row_number, rank, hidden, MAX(block_number) AS block_number FROM snapshots WHERE column_number = ? AND block_number < ? GROUP BY row_number) AS queryforms WHERE hidden = FALSE AND rank $? ?) AS sq WHERE sq.id IN ($?) ORDER BY sq.id ASC";
			}

			auto cursor = emplace_query(temporary->storage, label, __func__, pattern, &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<uptr<ledger::state>>>(layer_exception(error_of(cursor)));

			vector<uptr<ledger::state>> values;
			auto& response = cursor->first();
			size_t size = response.size();
			for (size_t i = 0; i < size; i++)
			{
				auto next = response[i];
				auto row = next["row_hash"].get().get_blob();
				if (changelog != nullptr)
				{
					auto candidate = changelog->outgoing.find(type, column, row);
					if (candidate)
					{
						values.push_back(std::move(*candidate));
						continue;
					}

					candidate = changelog->incoming.find(type, column, row);
					if (candidate)
					{
						values.push_back(std::move(*candidate));
						continue;
					}
				}

				auto state_block_number = next["block_number"].get().get_integer();
				auto blob = load(label, __func__, get_multiform_label(type, column, row, state_block_number)).or_else(string());
				auto next_state = state_from_blob(state_block_number, type, column, row, blob);
				if (!next_state)
				{
					if (next_state && changelog != nullptr)
						((ledger::block_changelog*)changelog)->incoming.erase(type, column, ((ledger::multiform*)*next_state)->as_row());
					continue;
				}
				else if (changelog != nullptr)
					((ledger::block_changelog*)changelog)->incoming.push(*next_state, false);
				values.push_back(std::move(next_state));
			}

			return values;
		}
		expects_lr<vector<uptr<ledger::state>>> chainstate::get_multiforms_by_row(uint32_t type, ledger::block_changelog* changelog, const std::string_view& row, uint64_t block_number, size_t offset, size_t count)
		{
			auto temporary = resolve_temporary_state(type, changelog, optional::none, row, block_number);
			if (!temporary)
				return temporary.error();

			auto location = resolve_multiform_location(type, optional::none, row, temporary->in_use ? (uint8_t)resolver::disable_cache : 0);
			if (!location)
				return expects_lr<vector<uptr<ledger::state>>>(vector<uptr<ledger::state>>());

			schema_list map;
			map.push_back(var::set::integer(location->row.or_else(0)));
			if (block_number > 0)
				map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = emplace_query(temporary->storage, label, __func__, !block_number ?
				"SELECT (SELECT column_hash FROM columns WHERE columns.column_number = multiforms.column_number) AS column_hash, block_number FROM multiforms WHERE row_number = ? ORDER BY column_number LIMIT ? OFFSET ?" :
				"SELECT * FROM (SELECT (SELECT column_hash FROM columns WHERE columns.column_number = snapshots.column_number) AS column_hash, hidden, MAX(block_number) AS block_number FROM snapshots WHERE row_number = ? AND block_number < ? GROUP BY column_number ORDER BY column_number) WHERE hidden = FALSE LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<uptr<ledger::state>>>(layer_exception(error_of(cursor)));

			vector<uptr<ledger::state>> values;
			auto& response = cursor->first();
			size_t size = response.size();
			for (size_t i = 0; i < size; i++)
			{
				auto next = response[i];
				auto column = next["column_hash"].get().get_blob();
				if (changelog != nullptr)
				{
					auto candidate = changelog->outgoing.find(type, column, row);
					if (candidate)
					{
						values.push_back(std::move(*candidate));
						continue;
					}

					candidate = changelog->incoming.find(type, column, row);
					if (candidate)
					{
						values.push_back(std::move(*candidate));
						continue;
					}
				}

				auto state_block_number = next["block_number"].get().get_integer();
				auto blob = load(label, __func__, get_multiform_label(type, column, row, state_block_number)).or_else(string());
				auto next_state = state_from_blob(state_block_number, type, column, row, blob);
				if (!next_state)
				{
					if (next_state && changelog != nullptr)
						((ledger::block_changelog*)changelog)->incoming.erase(type, ((ledger::multiform*)*next_state)->as_column(), row);
					continue;
				}
				else if (changelog != nullptr)
					((ledger::block_changelog*)changelog)->incoming.push(*next_state, false);
				values.push_back(std::move(next_state));
			}

			return values;
		}
		expects_lr<vector<uptr<ledger::state>>> chainstate::get_multiforms_by_row_filter(uint32_t type, ledger::block_changelog* changelog, const std::string_view& row, const result_filter& filter, uint64_t block_number, const result_window& window)
		{
			auto temporary = resolve_temporary_state(type, changelog, optional::none, row, block_number);
			if (!temporary)
				return temporary.error();

			auto location = resolve_multiform_location(type, optional::none, row, temporary->in_use ? (uint8_t)resolver::disable_cache : 0);
			if (!location)
				return expects_lr<vector<uptr<ledger::state>>>(vector<uptr<ledger::state>>());

			schema_list map; string pattern;
			if (window.type() == result_range_window::instance_type())
			{
				auto& range = *(result_range_window*)&window;
				map.push_back(var::set::integer(location->row.or_else(0)));
				if (block_number > 0)
					map.push_back(var::set::integer(block_number));
				map.push_back(var::set::string(filter.as_condition()));
				map.push_back(var::set::binary(filter.as_value()));
				map.push_back(var::set::string(filter.as_order()));
				map.push_back(var::set::integer(range.count));
				map.push_back(var::set::integer(range.offset));

				pattern = !block_number ?
					"SELECT (SELECT column_hash FROM columns WHERE columns.column_number = multiforms.column_number) AS column_hash, block_number FROM multiforms WHERE row_number = ? AND rank $? ? ORDER BY rank $?, column_number ASC LIMIT ? OFFSET ?" :
					"SELECT (SELECT column_hash FROM columns WHERE columns.column_number = queryforms.column_number) AS column_hash, block_number FROM (SELECT column_number, row_number, rank, hidden, MAX(block_number) AS block_number FROM snapshots WHERE row_number = ? AND block_number < ? GROUP BY column_number) AS queryforms WHERE hidden = FALSE AND rank $? ? ORDER BY rank $?, column_number ASC LIMIT ? OFFSET ?";
			}
			else if (window.type() == result_index_window::instance_type())
			{
				string indices;
				for (auto& item : ((result_index_window*)&window)->indices)
					indices += to_string(item + 1) + ",";

				map.push_back(var::set::string(filter.as_order()));
				map.push_back(var::set::integer(location->row.or_else(0)));
				if (block_number > 0)
					map.push_back(var::set::integer(block_number));
				map.push_back(var::set::string(filter.as_condition()));
				map.push_back(var::set::binary(filter.as_value()));
				map.push_back(var::set::string(indices.substr(0, indices.size() - 1)));

				pattern = !block_number ?
					"SELECT (SELECT column_hash FROM columns WHERE columns.column_number = sq.column_number) AS column_hash, block_number FROM (SELECT ROW_NUMBER() OVER (ORDER BY rank $?, column_number ASC) AS id, column_number, block_number FROM multiforms WHERE row_number = ? AND rank $? ?) AS sq WHERE sq.id IN ($?) ORDER BY sq.id ASC" :
					"SELECT (SELECT column_hash FROM columns WHERE columns.column_number = sq.column_number) AS column_hash, block_number FROM (SELECT ROW_NUMBER() OVER (ORDER BY rank $?, column_number ASC) AS id, column_number, block_number FROM (SELECT column_number, row_number, rank, hidden, MAX(block_number) AS block_number FROM snapshots WHERE row_number = ? AND block_number < ? GROUP BY column_number) AS queryforms WHERE hidden = FALSE AND rank $? ?) AS sq WHERE sq.id IN ($?) ORDER BY sq.id ASC";
			}

			auto cursor = emplace_query(temporary->storage, label, __func__, pattern, &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<uptr<ledger::state>>>(layer_exception(error_of(cursor)));

			vector<uptr<ledger::state>> values;
			auto& response = cursor->first();
			size_t size = response.size();
			for (size_t i = 0; i < size; i++)
			{
				auto next = response[i];
				auto column = next["column_hash"].get().get_blob();
				if (changelog != nullptr)
				{
					auto candidate = changelog->outgoing.find(type, column, row);
					if (candidate)
					{
						values.push_back(std::move(*candidate));
						continue;
					}

					candidate = changelog->incoming.find(type, column, row);
					if (candidate)
					{
						values.push_back(std::move(*candidate));
						continue;
					}
				}

				auto state_block_number = next["block_number"].get().get_integer();
				auto blob = load(label, __func__, get_multiform_label(type, column, row, state_block_number)).or_else(string());
				auto next_state = state_from_blob(state_block_number, type, column, row, blob);
				if (!next_state)
				{
					if (next_state && changelog != nullptr)
						((ledger::block_changelog*)changelog)->incoming.erase(type, ((ledger::multiform*)*next_state)->as_column(), row);
					continue;
				}
				else if (changelog != nullptr)
					((ledger::block_changelog*)changelog)->incoming.push(*next_state, false);
				values.push_back(std::move(next_state));
			}

			return values;
		}
		expects_lr<size_t> chainstate::get_multiforms_count_by_column(uint32_t type, ledger::block_changelog* changelog, const std::string_view& column, uint64_t block_number)
		{
			auto temporary = resolve_temporary_state(type, changelog, column, optional::none, block_number);
			if (!temporary)
				return temporary.error();

			auto location = resolve_multiform_location(type, column, optional::none, temporary->in_use ? (uint8_t)resolver::disable_cache : 0);
			if (!location)
				return location.error();

			schema_list map;
			map.push_back(var::set::integer(location->column.or_else(0)));
			if (block_number > 0)
				map.push_back(var::set::integer(block_number));

			auto cursor = emplace_query(temporary->storage, label, __func__, !block_number ? "SELECT COUNT(1) AS multiform_count FROM multiforms WHERE column_number = ?" : "SELECT COUNT(1) AS multiform_count FROM (SELECT hidden, MAX(block_number) FROM snapshots WHERE column_number = ? AND block_number < ? GROUP BY row_number) WHERE hidden = FALSE", &map);
			if (!cursor || cursor->error())
				return expects_lr<size_t>(layer_exception(error_of(cursor)));

			size_t count = (*cursor)["multiform_count"].get().get_integer();
			return expects_lr<size_t>(count);
		}
		expects_lr<size_t> chainstate::get_multiforms_count_by_column_filter(uint32_t type, ledger::block_changelog* changelog, const std::string_view& column, const result_filter& filter, uint64_t block_number)
		{
			auto temporary = resolve_temporary_state(type, changelog, column, optional::none, block_number);
			if (!temporary)
				return temporary.error();

			auto location = resolve_multiform_location(type, column, optional::none, temporary->in_use ? (uint8_t)resolver::disable_cache : 0);
			if (!location)
				return location.error();

			schema_list map;
			map.push_back(var::set::integer(location->column.or_else(0)));
			if (block_number > 0)
				map.push_back(var::set::integer(block_number));
			map.push_back(var::set::string(filter.as_condition()));
			map.push_back(var::set::binary(filter.as_value()));

			auto cursor = emplace_query(temporary->storage, label, __func__, !block_number ? "SELECT COUNT(1) AS multiform_count FROM multiforms WHERE column_number = ? AND rank $? ?" : "SELECT COUNT(1) AS multiform_count FROM (SELECT rank, hidden, MAX(block_number) FROM snapshots WHERE column_number = ? AND block_number < ? GROUP BY row_number) WHERE hidden = FALSE AND rank $? ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<size_t>(layer_exception(error_of(cursor)));

			size_t count = (*cursor)["multiform_count"].get().get_integer();
			return expects_lr<size_t>(count);
		}
		expects_lr<size_t> chainstate::get_multiforms_count_by_row(uint32_t type, ledger::block_changelog* changelog, const std::string_view& row, uint64_t block_number)
		{
			auto temporary = resolve_temporary_state(type, changelog, optional::none, row, block_number);
			if (!temporary)
				return temporary.error();

			auto location = resolve_multiform_location(type, optional::none, row, temporary->in_use ? (uint8_t)resolver::disable_cache : 0);
			if (!location)
				return location.error();

			schema_list map;
			map.push_back(var::set::integer(location->row.or_else(0)));
			if (block_number > 0)
				map.push_back(var::set::integer(block_number));

			auto cursor = emplace_query(temporary->storage, label, __func__, !block_number ? "SELECT COUNT(1) AS multiform_count FROM multiforms WHERE row_number = ?" : "SELECT COUNT(1) AS multiform_count FROM (SELECT hidden, MAX(block_number) FROM snapshots WHERE row_number = ? AND block_number < ? GROUP BY column_number) WHERE hidden = FALSE", &map);
			if (!cursor || cursor->error())
				return expects_lr<size_t>(layer_exception(error_of(cursor)));

			size_t count = (*cursor)["multiform_count"].get().get_integer();
			return expects_lr<size_t>(count);
		}
		expects_lr<size_t> chainstate::get_multiforms_count_by_row_filter(uint32_t type, ledger::block_changelog* changelog, const std::string_view& row, const result_filter& filter, uint64_t block_number)
		{
			auto temporary = resolve_temporary_state(type, changelog, optional::none, row, block_number);
			if (!temporary)
				return temporary.error();

			auto location = resolve_multiform_location(type, optional::none, row, temporary->in_use ? (uint8_t)resolver::disable_cache : 0);
			if (!location)
				return location.error();

			schema_list map;
			map.push_back(var::set::integer(location->row.or_else(0)));
			if (block_number > 0)
				map.push_back(var::set::integer(block_number));
			map.push_back(var::set::string(filter.as_condition()));
			map.push_back(var::set::binary(filter.as_value()));

			auto cursor = emplace_query(temporary->storage, label, __func__, !block_number ? "SELECT COUNT(1) AS multiform_count FROM multiforms WHERE row_number = ? AND rank $? ?" : "SELECT COUNT(1) AS multiform_count FROM (SELECT rank, hidden, MAX(block_number) FROM snapshots WHERE row_number = ? AND block_number < ? GROUP BY column_number) WHERE hidden = FALSE AND rank $? ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<size_t>(layer_exception(error_of(cursor)));

			size_t count = (*cursor)["multiform_count"].get().get_integer();
			return expects_lr<size_t>(count);
		}
		expects_lr<chainstate::temporary_state_resolution> chainstate::resolve_temporary_state(uint32_t type, ledger::block_changelog* changelog, const option<std::string_view>& column, const option<std::string_view>& row, uint64_t block_number)
		{
			if (!changelog)
			{
				temporary_state_resolution result;
				result.storage = get_multiform_storage(type);
				result.in_use = false;
				return result;
			}

			multiform_writer writer;
			fill_multiform_writer_from_block_changelog(&writer.blobs, type, column, row, changelog);

			auto storage = changelog->temporary_state.topics.find(type);
			auto temporary = storage != changelog->temporary_state.topics.end();
			writer.storage = temporary ? (sqlite::connection*)storage->second : get_multiform_storage(type);
			writer.blobs.erase(std::remove_if(writer.blobs.begin(), writer.blobs.end(), [&](const multiform_blob& value)
			{
				auto it = changelog->temporary_state.effects.find(value.message.data);
				return it != changelog->temporary_state.effects.end() && it->second == std::string_view((char*)value.rank, value.rank_size);
			}), writer.blobs.end());

			temporary_state_resolution result;
			result.storage = writer.storage;
			result.in_use = temporary;
			if (writer.blobs.empty())
				return result;

			auto status = fill_multiform_writer_from_storage(&writer, writer.storage);
			if (!status)
				return status.error();

			if (!temporary)
			{
				auto transaction = writer.storage->tx_begin(sqlite::isolation::default_isolation);
				if (!transaction)
					return layer_exception(error_of(transaction));
			}

			sqlite::expects_db<sqlite::cursor> cursor = sqlite::database_exception(string());
			auto rollback_temporary_state = [&]()
			{
				changelog->temporary_state.effects.clear();
				changelog->temporary_state.topics.erase(type);
				writer.storage->tx_rollback(writer.storage->get_connection());
			};

			for (auto& item : writer.blobs)
			{
				auto* statement = writer.commit_multiform_column_data;
				writer.storage->bind_blob(statement, 0, item.column);
				writer.storage->bind_int64(statement, 1, 0);

				cursor = prepared_query(writer.storage, label, __func__, statement);
				if (!cursor || cursor->error_or_empty())
				{
					rollback_temporary_state();
					return layer_exception(cursor->empty() ? "multiform state column not linked" : error_of(cursor));
				}

				statement = writer.commit_multiform_row_data;
				writer.storage->bind_blob(statement, 0, item.row);
				writer.storage->bind_int64(statement, 1, 0);

				uint64_t column_number = cursor->first().front().get_column(0).get().get_integer();
				cursor = prepared_query(writer.storage, label, __func__, statement);
				if (!cursor || cursor->error_or_empty())
				{
					rollback_temporary_state();
					return layer_exception(cursor->empty() ? "multiform state row not linked" : error_of(cursor));
				}

				uint64_t row_number = cursor->first().front().get_column(0).get().get_integer();
				if (block_number > 0)
				{
					algorithm::encoding::optimized_decode_uint256(item.context->as_rank(), item.rank, &item.rank_size);
					statement = writer.commit_snapshot_data;
					writer.storage->bind_int64(statement, 0, column_number);
					writer.storage->bind_int64(statement, 1, row_number);
					writer.storage->bind_int64(statement, 2, 0);
					writer.storage->bind_blob(statement, 3, std::string_view((char*)item.rank, item.rank_size));
					writer.storage->bind_boolean(statement, 4, item.change->erase);
				}
				else if (item.change->erase)
				{
					statement = writer.erase_multiform_data;
					writer.storage->bind_int64(statement, 0, column_number);
					writer.storage->bind_int64(statement, 1, row_number);
				}
				else
				{
					algorithm::encoding::optimized_decode_uint256(item.context->as_rank(), item.rank, &item.rank_size);
					statement = writer.commit_multiform_data;
					writer.storage->bind_int64(statement, 0, column_number);
					writer.storage->bind_int64(statement, 1, row_number);
					writer.storage->bind_int64(statement, 2, 0);
					writer.storage->bind_blob(statement, 3, std::string_view((char*)item.rank, item.rank_size));
				}

				cursor = prepared_query(writer.storage, label, __func__, statement);
				if (!cursor || cursor->error())
				{
					rollback_temporary_state();
					return layer_exception(error_of(cursor));
				}
			}

			changelog->temporary_state.topics[type] = writer.storage;
			for (auto& item : writer.blobs)
				changelog->temporary_state.effects[item.message.data] = string((char*)item.rank, item.rank_size);

			return result;
		}
		expects_lr<void> chainstate::clear_temporary_state(ledger::block_changelog* changelog)
		{
			VI_ASSERT(changelog != nullptr, "changelog should be set");
			changelog->temporary_state.effects.clear();
			if (!changelog->temporary_state.topics.empty())
				return expectation::met;

			expects_lr<void> result = expectation::met;
			for (auto& topic : changelog->temporary_state.topics)
			{
				auto* storage = (sqlite::connection*)topic.second;
				auto status = storage->tx_rollback(storage->get_connection());
				if (!status)
					result = layer_exception(error_of(status));
			}

			changelog->temporary_state.topics.clear();
			return result;
		}
		sqlite::expects_db<string> chainstate::load(const std::string_view& label, const std::string_view& operation, const std::string_view& key)
		{
			preload_blob_storage();
			return permanent_storage::load(label, operation, key);
		}
		sqlite::expects_db<void> chainstate::store(const std::string_view& label, const std::string_view& operation, const std::string_view& key, const std::string_view& value)
		{
			preload_blob_storage();
			return permanent_storage::store(label, operation, key, value);
		}
		sqlite::expects_db<void> chainstate::clear(const std::string_view& label, const std::string_view& operation, const std::string_view& table_ids)
		{
			preload_blob_storage();
			return permanent_storage::clear(label, operation, table_ids);
		}
		sqlite::connection* chainstate::get_block_storage()
		{
			if (!storages.block)
			{
				if (borrows)
					storages.block = *latest_chainstate->storages.block;
				if (!storages.block)
				{
					storages.block = index_storage_of("chainindex", "blockdata");
					if (borrows)
						latest_chainstate->storages.block = *storages.block;
				}
			}
			return *storages.block;
		}
		sqlite::connection* chainstate::get_account_storage()
		{
			if (!storages.account)
			{
				if (borrows)
					storages.account = *latest_chainstate->storages.account;
				if (!storages.account)
				{
					storages.account = index_storage_of("chainindex", "accountdata");
					if (borrows)
						latest_chainstate->storages.account = *storages.account;
				}
			}
			return *storages.account;
		}
		sqlite::connection* chainstate::get_tx_storage()
		{
			if (!storages.tx)
			{
				if (borrows)
					storages.tx = *latest_chainstate->storages.tx;
				if (!storages.tx)
				{
					storages.tx = index_storage_of("chainindex", "txdata");
					if (borrows)
						latest_chainstate->storages.tx = *storages.tx;
				}
			}
			return *storages.tx;
		}
		sqlite::connection* chainstate::get_party_storage()
		{
			if (!storages.party)
			{
				if (borrows)
					storages.party = *latest_chainstate->storages.party;
				if (!storages.party)
				{
					storages.party = index_storage_of("chainindex", "partydata");
					if (borrows)
						latest_chainstate->storages.party = *storages.party;
				}
			}
			return *storages.party;
		}
		sqlite::connection* chainstate::get_alias_storage()
		{
			if (!storages.alias)
			{
				if (borrows)
					storages.alias = *latest_chainstate->storages.alias;
				if (!storages.alias)
				{
					storages.alias = index_storage_of("chainindex", "aliasdata");
					if (borrows)
						latest_chainstate->storages.alias = *storages.alias;
				}
			}
			return *storages.alias;
		}
		sqlite::connection* chainstate::get_uniform_storage(uint32_t type)
		{
			auto& data = storages.uniform[type];
			if (!data)
			{
				if (borrows)
					data = *latest_chainstate->storages.uniform[type];
				if (!data)
				{
					data = index_storage_of("chainindex", stringify::text("uniformdata.0x%x", type));
					if (borrows)
						latest_chainstate->storages.uniform[type] = *data;
				}
			}
			return *data;
		}
		unordered_map<uint32_t, uptr<sqlite::connection>>& chainstate::get_uniform_storage_max()
		{
			for (uint32_t type : states::resolver::get_uniform_types())
				get_uniform_storage(type);
			return storages.uniform;
		}
		sqlite::connection* chainstate::get_multiform_storage(uint32_t type)
		{
			auto& data = storages.multiform[type];
			if (!data)
			{
				if (borrows)
					data = *latest_chainstate->storages.multiform[type];
				if (!data)
				{
					data = index_storage_of("chainindex", stringify::text("multiformdata.0x%x", type));
					if (borrows)
						latest_chainstate->storages.multiform[type] = *data;
				}
			}
			return *data;
		}
		unordered_map<uint32_t, uptr<sqlite::connection>>& chainstate::get_multiform_storage_max()
		{
			for (uint32_t type : states::resolver::get_multiform_types())
				get_multiform_storage(type);
			return storages.multiform;
		}
		vector<sqlite::connection*> chainstate::get_index_storages()
		{
			vector<sqlite::connection*> index;
			index.reserve(32);
			index.push_back(get_block_storage());
			index.push_back(get_account_storage());
			index.push_back(get_tx_storage());
			index.push_back(get_party_storage());
			index.push_back(get_alias_storage());
			for (auto& [type, uniform_storage] : get_uniform_storage_max())
				index.push_back(*uniform_storage);
			for (auto& [type, multiform_storage] : get_multiform_storage_max())
				index.push_back(*multiform_storage);
			return index;
		}
		void chainstate::preload_blob_storage()
		{
			if (!blob)
				blob_storage_of("chainblob");
		}
		void chainstate::clear_indexer_cache()
		{
			account_cache::cleanup_instance();
			uniform_cache::cleanup_instance();
			multiform_cache::cleanup_instance();
		}
		bool chainstate::reconstruct_index_storage(sqlite::connection* storage, const std::string_view& name)
		{
			string command;
			if (name == "blockdata")
			{
				command = VI_STRINGIFY((
				CREATE TABLE IF NOT EXISTS blocks
				(
					block_number BIGINT NOT NULL,
					block_hash BLOB(32) NOT NULL,
					PRIMARY KEY(block_hash)
				) WITHOUT ROWID;
				CREATE UNIQUE INDEX IF NOT EXISTS blocks_block_number ON blocks(block_number);
				CREATE TABLE IF NOT EXISTS checkpoints
				(
					block_number BIGINT NOT NULL,
					PRIMARY KEY(block_number)
				) WITHOUT ROWID;));
			}
			else if (name == "accountdata")
			{
				command = VI_STRINGIFY((
				CREATE TABLE IF NOT EXISTS accounts
				(
					account_number BIGINT NOT NULL,
					account_hash BLOB(20) NOT NULL,
					block_number BIGINT NOT NULL,
					PRIMARY KEY(account_number)
				) WITHOUT ROWID;
				CREATE UNIQUE INDEX IF NOT EXISTS accounts_account_hash ON accounts(account_hash);
				CREATE INDEX IF NOT EXISTS accounts_block_number ON accounts(block_number);));
			}
			else if (name == "txdata")
			{
				command = VI_STRINGIFY((
				CREATE TABLE IF NOT EXISTS transactions
				(
					transaction_number BIGINT NOT NULL,
					transaction_hash BLOB(32) NOT NULL,
					dispatch_queue BIGINT DEFAULT NULL,
					block_number BIGINT NOT NULL,
					block_nonce BIGINT NOT NULL,
					PRIMARY KEY(transaction_hash)
				) WITHOUT ROWID;
				CREATE UNIQUE INDEX IF NOT EXISTS transactions_transaction_number ON transactions(transaction_number);
				CREATE INDEX IF NOT EXISTS transactions_dispatch_queue_block_nonce ON transactions(dispatch_queue, block_nonce) WHERE dispatch_queue IS NOT NULL;
				CREATE INDEX IF NOT EXISTS transactions_block_number_block_nonce ON transactions(block_number, block_nonce);));
			}
			else if (name == "partydata")
			{
				command = VI_STRINGIFY((
				CREATE TABLE IF NOT EXISTS parties
				(
					transaction_number BIGINT NOT NULL,
					transaction_account_number BIGINT NOT NULL,
					block_number BIGINT NOT NULL,
					PRIMARY KEY(transaction_account_number, block_number, transaction_number)
				) WITHOUT ROWID;
				CREATE INDEX IF NOT EXISTS parties_block_number ON parties(block_number);));
			}
			else if (name == "aliasdata")
			{
				command = VI_STRINGIFY((
				CREATE TABLE IF NOT EXISTS aliases
				(
					transaction_number BIGINT NOT NULL,
					transaction_hash BLOB(32) NOT NULL,
					block_number BIGINT NOT NULL,
					PRIMARY KEY(transaction_hash, transaction_number)
				) WITHOUT ROWID;
				CREATE INDEX IF NOT EXISTS aliases_block_number ON aliases(block_number);));
			}
			else if (stringify::starts_with(name, "uniformdata"))
			{
				command = VI_STRINGIFY((
				CREATE TABLE IF NOT EXISTS indices
				(
					index_number BIGINT NOT NULL,
					index_hash BLOB NOT NULL,
					block_number BIGINT NOT NULL,
					PRIMARY KEY(index_number)
				) WITHOUT ROWID;
				CREATE UNIQUE INDEX IF NOT EXISTS indices_index_hash ON indices(index_hash);
				CREATE INDEX IF NOT EXISTS indices_block_number ON indices(block_number);
				CREATE TABLE IF NOT EXISTS uniforms
				(
					index_number BIGINT NOT NULL,
					block_number BIGINT NOT NULL,
					PRIMARY KEY(index_number)
				) WITHOUT ROWID;
				CREATE INDEX IF NOT EXISTS uniforms_block_number ON uniforms(block_number);
				CREATE TABLE IF NOT EXISTS snapshots
				(
					index_number BIGINT NOT NULL,
					block_number BIGINT NOT NULL,
					hidden BOOLEAN NOT NULL,
					PRIMARY KEY(index_number, block_number)
				) WITHOUT ROWID;
				CREATE INDEX IF NOT EXISTS snapshots_block_number ON snapshots(block_number);));
			}
			else if (stringify::starts_with(name, "multiformdata"))
			{
				command = VI_STRINGIFY((
				CREATE TABLE IF NOT EXISTS columns
				(
					column_number BIGINT NOT NULL,
					column_hash BLOB NOT NULL,
					block_number BIGINT NOT NULL,
					PRIMARY KEY(column_number)
				) WITHOUT ROWID;
				CREATE UNIQUE INDEX IF NOT EXISTS columns_column_hash ON columns(column_hash);
				CREATE INDEX IF NOT EXISTS columns_block_number ON columns(block_number);
				CREATE TABLE IF NOT EXISTS rows
				(
					row_number BIGINT NOT NULL,
					row_hash BLOB NOT NULL,
					block_number BIGINT NOT NULL,
					PRIMARY KEY(row_number)
				) WITHOUT ROWID;
				CREATE UNIQUE INDEX IF NOT EXISTS rows_row_hash ON rows(row_hash);
				CREATE INDEX IF NOT EXISTS rows_block_number ON rows(block_number);
				CREATE TABLE IF NOT EXISTS multiforms
				(
					column_number BIGINT NOT NULL,
					row_number BIGINT NOT NULL,
					rank BLOB(32) NOT NULL,
					block_number BIGINT NOT NULL,
					PRIMARY KEY(column_number, row_number)
				) WITHOUT ROWID;
				CREATE INDEX IF NOT EXISTS multiforms_row_number_column_number ON multiforms(row_number, column_number);
				CREATE INDEX IF NOT EXISTS multiforms_row_number_rank ON multiforms(row_number, rank);
				CREATE INDEX IF NOT EXISTS multiforms_block_number ON multiforms(block_number);
				CREATE TABLE IF NOT EXISTS snapshots
				(
					column_number BIGINT NOT NULL,
					row_number BIGINT NOT NULL,
					rank BLOB(32) NOT NULL,
					block_number BIGINT NOT NULL,
					hidden BOOLEAN NOT NULL,
					PRIMARY KEY(column_number, row_number, block_number)
				) WITHOUT ROWID;
				CREATE INDEX IF NOT EXISTS snapshots_row_number_block_number ON snapshots(row_number, block_number);
				CREATE INDEX IF NOT EXISTS snapshots_column_number_block_number ON snapshots(column_number, block_number);
				CREATE INDEX IF NOT EXISTS snapshots_block_number ON snapshots(block_number);));
			}

			command.front() = ' ';
			command.back() = ' ';
			stringify::trim(command);
			auto cursor = query(storage, label, __func__, command);
			return (cursor && !cursor->error());
		}
	}
}
