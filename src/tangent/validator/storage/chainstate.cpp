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
			format::stream transaction_message;
			format::stream receipt_message;
			uint64_t transaction_number;
			uint64_t block_nonce;
			bool dispatchable;
			ordered_set<algorithm::pubkeyhash_t> parties;
			vector<transaction_alias_blob> aliases;
			const ledger::block_transaction* context;
		};

		struct uniform_blob
		{
			format::stream message;
			string index;
			const ledger::uniform* context;
		};

		struct multiform_blob
		{
			format::stream message;
			string column;
			string row;
			int64_t factor;
			const ledger::multiform* context;
		};

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
		static string get_uniform_label(const std::string_view& index, uint64_t number)
		{
			string label;
			label.resize(1 + index.size());
			label.front() = BLOB_UNIFORM;
			memcpy(label.data() + 1, index.data(), index.size());

			uint64_t numeric = os::hw::to_endianness(os::hw::endian::little, number);
			label.append(std::string_view((char*)&numeric, sizeof(numeric)));
			return label;
		}
		static string get_multiform_label(const std::string_view& column, const std::string_view& row, uint64_t number)
		{
			string label;
			label.resize(1 + column.size() + row.size());
			label.front() = BLOB_MULTIFORM;
			memcpy(label.data() + 1, column.data(), column.size());
			memcpy(label.data() + 1 + column.size(), row.data(), row.size());

			uint64_t numeric = os::hw::to_endianness(os::hw::endian::little, number);
			label.append(std::string_view((char*)&numeric, sizeof(numeric)));
			return label;
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
		void uniform_cache::clear_uniform_location(const std::string_view& index)
		{
			umutex<std::mutex> unique(mutex);
			auto index_iterator = indices.find(key_lookup_cast(index));
			if (index_iterator != indices.end())
				indices.erase(index_iterator);
		}
		void uniform_cache::clear_block_location(const std::string_view& index)
		{
			umutex<std::mutex> unique(mutex);
			auto index_iterator = indices.find(key_lookup_cast(index));
			if (index_iterator != indices.end())
				blocks.erase(index_iterator->second);
		}
		void uniform_cache::set_index_location(const std::string_view& index, uint64_t index_location)
		{
			auto size = protocol::now().user.storage.location_cache_size;
			string target_index = string(index);
			umutex<std::mutex> unique(mutex);
			if (indices.size() >= size)
				indices.clear();
			indices[target_index] = index_location;
		}
		void uniform_cache::set_block_location(uint64_t index_location, uint64_t block_number)
		{
			auto size = protocol::now().user.storage.location_cache_size;
			umutex<std::mutex> unique(mutex);
			if (blocks.size() >= size)
				blocks.clear();

			blocks[index_location] = block_number;
		}
		option<uint64_t> uniform_cache::get_index_location(const std::string_view& index)
		{
			umutex<std::mutex> unique(mutex);
			auto it = indices.find(index);
			if (it == indices.end())
				return optional::none;

			return it->second;
		}
		option<uint64_t> uniform_cache::get_block_location(uint64_t index_location)
		{
			umutex<std::mutex> unique(mutex);
			auto it = blocks.find(index_location);
			if (it == blocks.end())
				return optional::none;

			return it->second;
		}

		void multiform_cache::clear_locations()
		{
			umutex<std::mutex> unique(mutex);
			columns.clear();
			rows.clear();
			blocks.clear();
		}
		void multiform_cache::clear_multiform_location(const std::string_view& column, const std::string_view& row)
		{
			umutex<std::mutex> unique(mutex);
			auto column_iterator = columns.find(key_lookup_cast(column));
			if (column_iterator != columns.end())
				columns.erase(column_iterator);

			auto row_iterator = rows.find(key_lookup_cast(row));
			if (row_iterator != rows.end())
				rows.erase(row_iterator);
		}
		void multiform_cache::clear_block_location(const std::string_view& column, const std::string_view& row)
		{
			umutex<std::mutex> unique(mutex);
			auto column_location = columns.find(key_lookup_cast(column));
			auto row_location = rows.find(key_lookup_cast(row));
			if (column_location != columns.end() && row_location != rows.end())
			{
				uint128_t location;
				memcpy((char*)&location + sizeof(uint64_t) * 0, &column_location->second, sizeof(uint64_t));
				memcpy((char*)&location + sizeof(uint64_t) * 1, &row_location->second, sizeof(uint64_t));
				blocks.erase(location);
			}
		}
		void multiform_cache::set_multiform_location(const std::string_view& column, const std::string_view& row, uint64_t column_location, uint64_t row_location)
		{
			auto size = protocol::now().user.storage.location_cache_size;
			string target_column = string(column);
			string target_row = string(row);
			umutex<std::mutex> unique(mutex);
			if (columns.size() >= size)
				columns.clear();
			if (rows.size() >= size)
				rows.clear();
			columns[target_column] = column_location;
			rows[target_row] = row_location;
		}
		void multiform_cache::set_column_location(const std::string_view& column, uint64_t location)
		{
			auto size = protocol::now().user.storage.location_cache_size;
			string target = string(column);
			umutex<std::mutex> unique(mutex);
			if (columns.size() >= size)
				columns.clear();
			columns[target] = location;
		}
		void multiform_cache::set_row_location(const std::string_view& row, uint64_t location)
		{
			auto size = protocol::now().user.storage.location_cache_size;
			string target = string(row);
			umutex<std::mutex> unique(mutex);
			if (rows.size() >= size)
				rows.clear();
			rows[target] = location;
		}
		void multiform_cache::set_block_location(uint64_t column_location, uint64_t row_location, uint64_t block_number)
		{
			auto size = protocol::now().user.storage.location_cache_size;
			umutex<std::mutex> unique(mutex);
			if (blocks.size() >= size)
				blocks.clear();

			uint128_t location;
			memcpy((char*)&location + sizeof(uint64_t) * 0, &column_location, sizeof(uint64_t));
			memcpy((char*)&location + sizeof(uint64_t) * 1, &row_location, sizeof(uint64_t));
			blocks[location] = block_number;
		}
		option<uint64_t> multiform_cache::get_column_location(const std::string_view& column)
		{
			umutex<std::mutex> unique(mutex);
			auto it = columns.find(column);
			if (it == columns.end())
				return optional::none;

			return it->second;
		}
		option<uint64_t> multiform_cache::get_row_location(const std::string_view& row)
		{
			umutex<std::mutex> unique(mutex);
			auto it = rows.find(row);
			if (it == rows.end())
				return optional::none;

			return it->second;
		}
		option<uint64_t> multiform_cache::get_block_location(uint64_t column_location, uint64_t row_location)
		{
			uint128_t location;
			memcpy((char*)&location + sizeof(uint64_t) * 0, &column_location, sizeof(uint64_t));
			memcpy((char*)&location + sizeof(uint64_t) * 1, &row_location, sizeof(uint64_t));

			umutex<std::mutex> unique(mutex);
			auto it = blocks.find(location);
			if (it == blocks.end())
				return optional::none;

			return it->second;
		}

		std::string_view factor_filter::as_condition() const
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
		std::string_view factor_filter::as_order() const
		{
			return order <= 0 ? "DESC" : "ASC";
		}
		factor_filter factor_filter::from(const std::string_view& query, int64_t value, int8_t order)
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
			{
				blob_storage_of("chainblob");
				blockdata = index_storage_of("chainindex", "blockdata");
				accountdata = index_storage_of("chainindex", "accountdata");
				txdata = index_storage_of("chainindex", "txdata");
				partydata = index_storage_of("chainindex", "partydata");
				aliasdata = index_storage_of("chainindex", "aliasdata");
				uniformdata = index_storage_of("chainindex", "uniformdata");
				multiformdata = index_storage_of("chainindex", "multiformdata");
				latest_chainstate = this;
			}
			else
			{
				blob = latest_chainstate->blob;
				blockdata = *latest_chainstate->blockdata;
				accountdata = *latest_chainstate->accountdata;
				txdata = *latest_chainstate->txdata;
				partydata = *latest_chainstate->partydata;
				aliasdata = *latest_chainstate->aliasdata;
				uniformdata = *latest_chainstate->uniformdata;
				multiformdata = *latest_chainstate->multiformdata;
			}
		}
		chainstate::~chainstate() noexcept
		{
			unload_index_of(std::move(blockdata), borrows);
			unload_index_of(std::move(accountdata), borrows);
			unload_index_of(std::move(txdata), borrows);
			unload_index_of(std::move(partydata), borrows);
			unload_index_of(std::move(aliasdata), borrows);
			unload_index_of(std::move(uniformdata), borrows);
			unload_index_of(std::move(multiformdata), borrows);
			if (latest_chainstate == this)
				latest_chainstate = nullptr;
		}
		expects_lr<void> chainstate::reorganize(int64_t* blocktrie, int64_t* transactiontrie, int64_t* statetrie)
		{
			auto cursor = query(*uniformdata, label, __func__,
				"DELETE FROM uniformtries;"
				"DELETE FROM uniforms;"
				"DELETE FROM indices;");
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			cursor = query(*multiformdata, label, __func__,
				"DELETE FROM multiformtries;"
				"DELETE FROM multiforms;"
				"DELETE FROM columns;"
				"DELETE FROM rows;");
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

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

				ledger::block evaluated_block;
				auto validation = candidate_block->validate(parent_block.address(), &evaluated_block);
				if (!validation)
					return layer_exception("block " + to_string(current_number) + " validation failed: " + validation.error().message());

				auto finalization = checkpoint(evaluated_block, true);
				if (!finalization)
					return layer_exception("block " + to_string(current_number) + " checkpoint failed: " + finalization.error().message());

				if (protocol::now().user.storage.logging)
					VI_INFO("[chainstate] reorganization checkpoint at block number %" PRIu64 " (statetrie: +%i)", current_number, evaluated_block.state_count);

				parent_block = evaluated_block;
				++current_number;
				if (blocktrie != nullptr)
					++(*blocktrie);
				if (transactiontrie != nullptr)
					*transactiontrie += evaluated_block.transaction_count;
				if (statetrie != nullptr)
					*statetrie += evaluated_block.state_count;
			}

			return expectation::met;
		}
		expects_lr<void> chainstate::revert(uint64_t block_number, int64_t* blocktrie, int64_t* transactiontrie, int64_t* statetrie)
		{
			schema_list map;
			map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(block_number));

			auto cursor = emplace_query(*blockdata, label, __func__,
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
			if (blocktrie != nullptr)
				*blocktrie -= response.size();

			map.clear();
			map.push_back(var::set::integer(block_number));

			cursor = emplace_query(*txdata, label, __func__, "DELETE FROM transactions WHERE block_number > ? RETURNING transaction_hash", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			response = cursor->first();
			parallel::wail_all(parallel::for_each_sequential(response.begin(), response.end(), response.size(), ELEMENTS_FEW, [&](sqlite::row row)
			{
				auto transaction_hash = row["transaction_hash"].get();
				store(label, __func__, get_transaction_label(transaction_hash.get_binary()), std::string_view());
				store(label, __func__, get_receipt_label(transaction_hash.get_binary()), std::string_view());
			}));
			if (transactiontrie != nullptr)
				*transactiontrie -= response.size();

			map.clear();
			map.push_back(var::set::integer(block_number));

			cursor = emplace_query(*accountdata, label, __func__, "DELETE FROM accounts WHERE block_number > ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			cursor = emplace_query(*partydata, label, __func__, "DELETE FROM parties WHERE block_number > ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			cursor = emplace_query(*aliasdata, label, __func__, "DELETE FROM aliases WHERE block_number > ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			map.clear();
			map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(block_number));

			cursor = emplace_query(*uniformdata, label, __func__,
				"DELETE FROM uniformtries WHERE block_number > ?;"
				"INSERT OR REPLACE INTO uniforms (index_number, block_number) SELECT index_number, max(block_number) FROM uniformtries WHERE block_number <= ? GROUP BY index_number;"
				"DELETE FROM indices WHERE block_number > ?;", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			map.clear();
			map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(block_number));

			cursor = emplace_query(*multiformdata, label, __func__,
				"DELETE FROM multiformtries WHERE block_number > ?;"
				"INSERT OR REPLACE INTO multiforms (column_number, row_number, factor, block_number) SELECT column_number, row_number, factor, max(block_number) FROM multiformtries WHERE block_number <= ? GROUP BY column_number, row_number;"
				"DELETE FROM columns WHERE block_number > ?;"
				"DELETE FROM rows WHERE block_number > ?;", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			account_cache::get()->clear_locations();
			uniform_cache::get()->clear_locations();
			multiform_cache::get()->clear_locations();

			auto checkpoint_number = get_checkpoint_block_number();
			if (checkpoint_number && *checkpoint_number > block_number)
				return reorganize(blocktrie, transactiontrie, statetrie);

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

					auto cursor = emplace_query(*txdata, label, __func__, "UPDATE transactions SET dispatch_queue = NULL WHERE transaction_hash IN ($?)", &map);
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

				auto cursor = emplace_query(*txdata, label, __func__, "UPDATE transactions SET dispatch_queue = dispatch_queue + ? WHERE transaction_hash IN ($?)", &map);
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(error_of(cursor)));
			}

			return expectation::met;
		}
		expects_lr<void> chainstate::prune(uint32_t types, uint64_t block_number)
		{
			size_t blocktrie = 0;
			if (types & (uint32_t)pruning::blocktrie)
			{
				size_t offset = 0, count = 1024;
				schema_list map;
				map.push_back(var::set::integer(block_number));
				map.push_back(var::set::integer(count));
				map.push_back(var::set::integer(offset = 0));

				while (true)
				{
					map.back()->value = var::integer(offset);

					auto cursor = emplace_query(*blockdata, label, __func__, "SELECT block_hash FROM blocks WHERE block_number < ? LIMIT ? OFFSET ?", &map);
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
					blocktrie += results;
					if (results < count)
						break;
				}

				auto cursor = emplace_query(*blockdata, label, __func__, "DELETE FROM blocks WHERE block_number < ?", &map);
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(error_of(cursor)));
			}

			size_t transactiontrie = 0;
			if (types & (uint32_t)pruning::transactiontrie)
			{
				size_t offset = 0, count = 1024;
				schema_list map;
				map.push_back(var::set::integer(block_number));
				map.push_back(var::set::integer(count));
				map.push_back(var::set::integer(offset));

				while (true)
				{
					map.back()->value = var::integer(offset);

					auto cursor = emplace_query(*txdata, label, __func__, "SELECT transaction_hash FROM transactions WHERE block_number < ? LIMIT ? OFFSET ?", &map);
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
					transactiontrie += results;
					if (results < count)
						break;
				}

				auto cursor = emplace_query(*txdata, label, __func__, "DELETE FROM transactions WHERE block_number < ?", &map);
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(error_of(cursor)));
			}

			size_t statetrie = 0;
			if (types & (uint32_t)pruning::statetrie)
			{
				size_t offset = 0, count = 1024;
				schema_list map;
				map.push_back(var::set::integer(block_number));
				map.push_back(var::set::integer(count));
				map.push_back(var::set::integer(offset));

				while (true)
				{
					map.back()->value = var::integer(offset);

					auto cursor = emplace_query(*uniformdata, label, __func__,
						"SELECT"
						" (COALESCE((SELECT TRUE FROM uniforms WHERE uniforms.index_number = uniformtries.index_number AND uniforms.block_number = uniformtries.block_number), FALSE)) AS latest,"
						" (SELECT index_hash FROM indices WHERE indices.index_number = uniformtries.index_number) AS index_hash,"
						" block_number "
						"FROM uniformtries WHERE block_number < ? LIMIT ? OFFSET ?", &map);
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
						store(label, __func__, get_uniform_label(index, number), std::string_view());
					}));

					size_t results = cursor->first().size();
					offset += results;
					statetrie += results - skips;
					if (results < count)
						break;
				}

				auto cursor = emplace_query(*uniformdata, label, __func__, "DELETE FROM uniformtries WHERE block_number < ?", &map);
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(error_of(cursor)));

				map.back()->value = var::integer(offset = 0);
				while (true)
				{
					map.back()->value = var::integer(offset);

					auto cursor = emplace_query(*multiformdata, label, __func__,
						"SELECT"
						" (COALESCE((SELECT TRUE FROM multiforms WHERE multiforms.column_number = multiformtries.column_number AND multiforms.row_number = multiformtries.row_number AND multiforms.block_number = multiformtries.block_number), FALSE)) AS latest,"
						" (SELECT column_hash FROM columns WHERE columns.column_number = multiformtries.column_number) AS column_hash,"
						" (SELECT row_hash FROM rows WHERE rows.row_number = multiformtries.row_number) AS row_hash,"
						" block_number "
						"FROM multiformtries WHERE block_number < ? LIMIT ? OFFSET ?", &map);
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
						store(label, __func__, get_multiform_label(column, row, number), std::string_view());
					}));

					size_t results = cursor->first().size();
					offset += results;
					statetrie += results - skips;
					if (results < count)
						break;
				}

				cursor = emplace_query(*multiformdata, label, __func__, "DELETE FROM multiformtries WHERE block_number < ?", &map);
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(error_of(cursor)));
			}

			schema_list map;
			map.push_back(var::set::integer(block_number));

			auto cursor = emplace_query(*blockdata, label, __func__, "INSERT OR IGNORE INTO checkpoints (block_number) VALUES (?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			if (protocol::now().user.storage.logging)
				VI_INFO("[chainstate] pruning checkpoint at block number %" PRIu64 " (blocktrie: -%" PRIu64 ", transactiontrie: -%" PRIu64 ", statetrie: -%" PRIu64 ")", block_number, (uint64_t)blocktrie, (uint64_t)transactiontrie, (uint64_t)statetrie);

			return expectation::met;
		}
		expects_lr<void> chainstate::checkpoint(const ledger::block& value, bool reorganization)
		{
			if (!reorganization)
			{
				format::stream block_header_message;
				if (!value.as_header().store(&block_header_message))
					return expects_lr<void>(layer_exception("block header serialization error"));

				uint8_t hash[32];
				algorithm::encoding::decode_uint256(value.as_hash(), hash);

				auto status = store(label, __func__, get_block_label(hash), block_header_message.data);
				if (!status)
					return expects_lr<void>(layer_exception(error_of(status)));

				schema_list map;
				map.push_back(var::set::integer(value.number));
				map.push_back(var::set::binary(hash, sizeof(hash)));

				auto cursor = emplace_query(*blockdata, label, __func__, "INSERT INTO blocks (block_number, block_hash) VALUES (?, ?)", &map);
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(error_of(cursor)));
			}

			auto commit_transaction_data = reorganization ? sqlite::expects_db<sqlite::tstatement*>(nullptr) : txdata->prepare_statement("INSERT INTO transactions (transaction_number, transaction_hash, dispatch_queue, block_number, block_nonce) VALUES (?, ?, ?, ?, ?)", nullptr);
			if (!commit_transaction_data)
				return expects_lr<void>(layer_exception(std::move(commit_transaction_data.error().message())));

			auto commit_account_data = reorganization ? sqlite::expects_db<sqlite::tstatement*>(nullptr) : accountdata->prepare_statement("INSERT OR IGNORE INTO accounts (account_number, account_hash, block_number) SELECT (SELECT COALESCE(max(account_number), 0) + 1 FROM accounts), ?, ? ON CONFLICT DO UPDATE SET block_number = block_number RETURNING account_number", nullptr);
			if (!commit_account_data)
				return expects_lr<void>(layer_exception(std::move(commit_account_data.error().message())));

			auto commit_party_data = reorganization ? sqlite::expects_db<sqlite::tstatement*>(nullptr) : partydata->prepare_statement("INSERT OR IGNORE INTO parties (transaction_number, transaction_account_number, block_number) VALUES (?, ?, ?)", nullptr);
			if (!commit_party_data)
				return expects_lr<void>(layer_exception(std::move(commit_party_data.error().message())));

			auto commit_alias_data = reorganization ? sqlite::expects_db<sqlite::tstatement*>(nullptr) : aliasdata->prepare_statement("INSERT INTO aliases (transaction_number, transaction_hash, block_number) VALUES (?, ?, ?)", nullptr);
			if (!commit_alias_data)
				return expects_lr<void>(layer_exception(std::move(commit_alias_data.error().message())));

			auto commit_uniform_index_data = uniformdata->prepare_statement("INSERT OR IGNORE INTO indices (index_number, index_hash, block_number) SELECT (SELECT COALESCE(max(index_number), 0) + 1 FROM indices), ?, ? ON CONFLICT DO UPDATE SET block_number = block_number RETURNING index_number", nullptr);
			if (!commit_uniform_index_data)
				return expects_lr<void>(layer_exception(std::move(commit_uniform_index_data.error().message())));

			auto commit_uniform_data = uniformdata->prepare_statement("INSERT OR REPLACE INTO uniforms (index_number, block_number) VALUES (?, ?)", nullptr);
			if (!commit_uniform_data)
				return expects_lr<void>(layer_exception(std::move(commit_uniform_data.error().message())));

			auto commit_uniformtrie_data = uniformdata->prepare_statement("INSERT OR REPLACE INTO uniformtries (index_number, block_number) VALUES (?, ?)", nullptr);
			if (!commit_uniformtrie_data)
				return expects_lr<void>(layer_exception(std::move(commit_uniformtrie_data.error().message())));

			auto commit_multiform_column_data = multiformdata->prepare_statement("INSERT OR IGNORE INTO columns (column_number, column_hash, block_number) SELECT (SELECT COALESCE(max(column_number), 0) + 1 FROM columns), ?, ? ON CONFLICT DO UPDATE SET block_number = block_number RETURNING column_number", nullptr);
			if (!commit_multiform_column_data)
				return expects_lr<void>(layer_exception(std::move(commit_multiform_column_data.error().message())));

			auto commit_multiform_row_data = multiformdata->prepare_statement("INSERT OR IGNORE INTO rows (row_number, row_hash, block_number) SELECT (SELECT COALESCE(max(row_number), 0) + 1 FROM rows), ?, ? ON CONFLICT DO UPDATE SET block_number = block_number RETURNING row_number", nullptr);
			if (!commit_multiform_row_data)
				return expects_lr<void>(layer_exception(std::move(commit_multiform_row_data.error().message())));

			auto commit_multiform_data = multiformdata->prepare_statement("INSERT OR REPLACE INTO multiforms (column_number, row_number, block_number, factor) VALUES (?, ?, ?, ?)", nullptr);
			if (!commit_multiform_data)
				return expects_lr<void>(layer_exception(std::move(commit_multiform_data.error().message())));

			auto commit_multiformtrie_data = multiformdata->prepare_statement("INSERT OR REPLACE INTO multiformtries (column_number, row_number, block_number, factor) VALUES (?, ?, ?, ?)", nullptr);
			if (!commit_multiformtrie_data)
				return expects_lr<void>(layer_exception(std::move(commit_multiformtrie_data.error().message())));

			auto& states = value.states.at(ledger::work_commitment::finalized);
			auto state = states.begin();
			vector<uniform_blob> uniforms;
			vector<multiform_blob> multiforms;
			uniforms.reserve(states.size());
			multiforms.reserve(states.size());
			for (size_t i = 0; i < states.size(); i++, state++)
			{
				switch (state->second->as_level())
				{
					case ledger::state_level::uniform:
					{
						uniform_blob blob;
						blob.context = (ledger::uniform*)*state->second;
						uniforms.emplace_back(std::move(blob));
						break;
					}
					case ledger::state_level::multiform:
					{
						multiform_blob blob;
						blob.context = (ledger::multiform*)*state->second;
						multiforms.emplace_back(std::move(blob));
						break;
					}
					default:
						return expects_lr<void>(layer_exception("state level is not valid"));
				}
			}

			vector<promise<void>> queue1;
			vector<transaction_blob> transactions;
			bool transaction_to_account_index = protocol::now().user.storage.transaction_to_account_index;
			bool transaction_to_rollup_index = protocol::now().user.storage.transaction_to_rollup_index;
			if (!reorganization)
			{
				auto cursor = query(*txdata, label, __func__, "SELECT max(transaction_number) AS counter FROM transactions");
				if (!cursor || cursor->error_or_empty())
					return expects_lr<void>(layer_exception(error_of(cursor)));

				uint64_t transaction_nonce = (*cursor)["counter"].get().get_integer();
				transactions.resize(value.transactions.size());
				for (size_t i = 0; i < transactions.size(); i++)
				{
					transaction_blob& blob = transactions[i];
					blob.transaction_number = ++transaction_nonce;
					blob.block_nonce = (uint64_t)i;
					blob.context = &value.transactions[i];
				}
				queue1 = parallel::for_each(transactions.begin(), transactions.end(), ELEMENTS_FEW, [&](transaction_blob& item)
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
				});
			}

			auto queue2 = parallel::for_each(uniforms.begin(), uniforms.end(), ELEMENTS_FEW, [&](uniform_blob& item)
			{
				item.index = item.context->as_index();
				item.context->store(&item.message);
			});
			auto queue3 = parallel::for_each(multiforms.begin(), multiforms.end(), ELEMENTS_FEW, [&](multiform_blob& item)
			{
				item.column = item.context->as_column();
				item.row = item.context->as_row();
				item.factor = item.context->as_factor();
				item.context->store(&item.message);
			});
			parallel::wail_all(std::move(queue1));
			parallel::wail_all(std::move(queue2));
			parallel::wail_all(std::move(queue3));

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
			for (auto& item : uniforms)
				cache_u->clear_block_location(item.index);

			for (auto& item : uniforms)
				cache_u->clear_uniform_location(item.index);

			auto* cache_m = multiform_cache::get();
			for (auto& item : multiforms)
				cache_m->clear_block_location(item.column, item.row);

			for (auto& item : multiforms)
				cache_m->clear_multiform_location(item.column, item.row);

			vector<promise<expects_lr<void>>> queue4;
			queue4.emplace_back(cotask<expects_lr<void>>([&]() -> expects_lr<void>
			{
				sqlite::expects_db<sqlite::cursor> cursor = sqlite::database_exception(string());
				for (auto& item : uniforms)
				{
					auto* statement = *commit_uniform_index_data;
					uniformdata->bind_blob(statement, 0, item.index);
					uniformdata->bind_int64(statement, 1, value.number);

					cursor = prepared_query(*uniformdata, label, __func__, statement);
					if (!cursor || cursor->error_or_empty())
						return layer_exception(cursor->empty() ? "uniform index not linked" : error_of(cursor));

					uint64_t index_number = cursor->first().front().get_column(0).get().get_integer();
					statement = *commit_uniform_data;
					uniformdata->bind_int64(statement, 0, index_number);
					uniformdata->bind_int64(statement, 1, value.number);

					cursor = prepared_query(*uniformdata, label, __func__, statement);
					if (!cursor || cursor->error())
						return layer_exception(error_of(cursor));

					statement = *commit_uniformtrie_data;
					uniformdata->bind_int64(statement, 0, index_number);
					uniformdata->bind_int64(statement, 1, value.number);

					cursor = prepared_query(*uniformdata, label, __func__, statement);
					if (!cursor || cursor->error())
						return layer_exception(error_of(cursor));
				}
				return expectation::met;
			}, false));
			queue4.emplace_back(cotask<expects_lr<void>>([&]() -> expects_lr<void>
			{
				sqlite::expects_db<sqlite::cursor> cursor = sqlite::database_exception(string());
				for (auto& item : multiforms)
				{
					auto* multiformment = *commit_multiform_column_data;
					multiformdata->bind_blob(multiformment, 0, item.column);
					multiformdata->bind_int64(multiformment, 1, value.number);

					cursor = prepared_query(*multiformdata, label, __func__, multiformment);
					if (!cursor || cursor->error_or_empty())
						return layer_exception(cursor->empty() ? "multiform column not linked" : error_of(cursor));

					multiformment = *commit_multiform_row_data;
					multiformdata->bind_blob(multiformment, 0, item.row);
					multiformdata->bind_int64(multiformment, 1, value.number);

					uint64_t column_number = cursor->first().front().get_column(0).get().get_integer();
					cursor = prepared_query(*multiformdata, label, __func__, multiformment);
					if (!cursor || cursor->error_or_empty())
						return layer_exception(cursor->empty() ? "multiform row not linked" : error_of(cursor));

					uint64_t row_number = cursor->first().front().get_column(0).get().get_integer();
					multiformment = *commit_multiform_data;
					multiformdata->bind_int64(multiformment, 0, column_number);
					multiformdata->bind_int64(multiformment, 1, row_number);
					multiformdata->bind_int64(multiformment, 2, value.number);
					multiformdata->bind_int64(multiformment, 3, item.factor);

					cursor = prepared_query(*multiformdata, label, __func__, multiformment);
					if (!cursor || cursor->error())
						return layer_exception(error_of(cursor));

					multiformment = *commit_multiformtrie_data;
					multiformdata->bind_int64(multiformment, 0, column_number);
					multiformdata->bind_int64(multiformment, 1, row_number);
					multiformdata->bind_int64(multiformment, 2, value.number);
					multiformdata->bind_int64(multiformment, 3, item.factor);

					cursor = prepared_query(*multiformdata, label, __func__, multiformment);
					if (!cursor || cursor->error())
						return layer_exception(error_of(cursor));
				}
				return expectation::met;
			}, false));
			queue4.emplace_back(cotask<expects_lr<void>>([&]() -> expects_lr<void>
			{
				sqlite::expects_db<void> status = expectation::met;
				for (auto& item : uniforms)
				{
					status = store(label, __func__, get_uniform_label(item.index, value.number), item.message.data);
					if (!status)
						return layer_exception(error_of(status));
				}
				return expectation::met;
			}, false));
			queue4.emplace_back(cotask<expects_lr<void>>([&]() -> expects_lr<void>
			{
				sqlite::expects_db<void> status = expectation::met;
				for (auto& item : multiforms)
				{
					status = store(label, __func__, get_multiform_label(item.column, item.row, value.number), item.message.data);
					if (!status)
						return layer_exception(error_of(status));
				}
				return expectation::met;
			}, false));
			if (!reorganization)
			{
				queue4.emplace_back(cotask<expects_lr<void>>([&]() -> expects_lr<void>
				{
					auto* statement = *commit_transaction_data;
					sqlite::expects_db<sqlite::cursor> cursor = sqlite::database_exception(string());
					for (auto& data : transactions)
					{
						txdata->bind_int64(statement, 0, data.transaction_number);
						txdata->bind_blob(statement, 1, std::string_view((char*)data.transaction_hash, sizeof(data.transaction_hash)));
						if (data.dispatchable)
							txdata->bind_int64(statement, 2, value.number);
						else
							txdata->bind_null(statement, 2);
						txdata->bind_int64(statement, 3, value.number);
						txdata->bind_int64(statement, 4, data.block_nonce);

						cursor = prepared_query(*txdata, label, __func__, statement);
						if (!cursor || cursor->error())
							return layer_exception(error_of(cursor));
					}
					return expectation::met;
				}, false));
				queue4.emplace_back(cotask<expects_lr<void>>([&]() -> expects_lr<void>
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
					queue4.emplace_back(cotask<expects_lr<void>>([&]() -> expects_lr<void>
					{
						sqlite::expects_db<sqlite::cursor> cursor = sqlite::database_exception(string());
						for (auto& data : transactions)
						{
							for (auto& party : data.parties)
							{
								auto* statement = *commit_account_data;
								accountdata->bind_blob(statement, 0, party.view());
								accountdata->bind_int64(statement, 1, value.number);

								cursor = prepared_query(*accountdata, label, __func__, statement);
								if (!cursor || cursor->error_or_empty())
									return layer_exception(cursor->empty() ? "account not linked" : error_of(cursor));

								uint64_t account_number = cursor->first().front().get_column(0).get().get_integer();
								statement = *commit_party_data;
								partydata->bind_int64(statement, 0, data.transaction_number);
								partydata->bind_int64(statement, 1, account_number);
								partydata->bind_int64(statement, 2, value.number);

								cursor = prepared_query(*partydata, label, __func__, statement);
								if (!cursor || cursor->error())
									return layer_exception(error_of(cursor));
							}
						}
						return expectation::met;
					}, false));
				}
				if (transaction_to_rollup_index)
				{
					queue4.emplace_back(cotask<expects_lr<void>>([&]() -> expects_lr<void>
					{
						auto* statement = *commit_alias_data;
						sqlite::expects_db<sqlite::cursor> cursor = sqlite::database_exception(string());
						for (auto& data : transactions)
						{
							for (auto& alias : data.aliases)
							{
								aliasdata->bind_int64(statement, 0, data.transaction_number);
								aliasdata->bind_blob(statement, 1, std::string_view((char*)alias.transaction_hash, sizeof(alias.transaction_hash)));
								aliasdata->bind_int64(statement, 2, value.number);

								cursor = prepared_query(*aliasdata, label, __func__, statement);
								if (!cursor || cursor->error())
									return layer_exception(error_of(cursor));
							}
						}
						return expectation::met;
					}, false));
				}
			}

			for (auto& status : parallel::inline_wait_all(std::move(queue4)))
			{
				if (!status)
					return status;
			}

			auto checkpoint_size = protocol::now().user.storage.checkpoint_size;
			if (!checkpoint_size || value.priority > 0)
				return expectation::met;

			auto checkpoint_number = value.number - value.number % checkpoint_size;
			if (checkpoint_number < value.number)
				return expectation::met;

			auto latest_checkpoint = get_checkpoint_block_number().or_else(0);
			if (value.number <= latest_checkpoint)
				return expectation::met;

			return prune(protocol::now().user.storage.prune_aggressively ? (uint32_t)pruning::blocktrie | (uint32_t)pruning::transactiontrie | (uint32_t)pruning::statetrie : (uint32_t)pruning::statetrie, value.number);
		}
		expects_lr<size_t> chainstate::resolve_block_transactions(ledger::block& value, bool fully, size_t offset, size_t count)
		{
			schema_list map;
			map.push_back(var::set::integer(value.number));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = emplace_query(*txdata, label, __func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<size_t>(layer_exception(error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size(), stride = value.transactions.size();
			value.transactions.resize(value.transactions.size() + size);
			parallel::wail_all(parallel::for_loop(size, ELEMENTS_FEW, [&](size_t i)
			{
				auto row = response[i];
				auto& next = value.transactions[i + stride];
				auto transaction_hash = row["transaction_hash"].get();
				format::stream transaction_message = format::stream(load(label, __func__, get_transaction_label(transaction_hash.get_binary())).or_else(string()));
				next.transaction = transactions::resolver::from_stream(transaction_message);
				if (next.transaction && next.transaction->load(transaction_message))
				{
					if (fully)
					{
						format::stream receipt_message = format::stream(load(label, __func__, get_receipt_label(transaction_hash.get_binary())).or_else(string()));
						if (next.receipt.load(receipt_message))
							finalize_checksum(**next.transaction, transaction_hash);
					}
					else
						finalize_checksum(**next.transaction, transaction_hash);
				}
			}));

			auto it = std::remove_if(value.transactions.begin(), value.transactions.end(), [](const ledger::block_transaction& a) { return !a.transaction; });
			if (it != value.transactions.end())
				value.transactions.erase(it);
			return size;
		}
		expects_lr<size_t> chainstate::resolve_block_statetrie(ledger::block& value, size_t offset, size_t count)
		{
			schema_list map;
			map.push_back(var::set::integer(value.number));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor1 = emplace_query(*uniformdata, label, __func__, "SELECT (SELECT index_hash FROM indices WHERE indices.index_number = uniformtries.index_number) AS index_hash FROM uniformtries WHERE block_number = ? LIMIT ? OFFSET ?", &map);
			if (!cursor1 || cursor1->error())
				return expects_lr<size_t>(layer_exception(error_of(cursor1)));

			auto cursor2 = emplace_query(*multiformdata, label, __func__, "SELECT (SELECT column_hash FROM columns WHERE columns.column_number = multiformtries.column_number) AS column_hash, (SELECT row_hash FROM rows WHERE rows.row_number = multiformtries.row_number) AS row_hash FROM multiformtries WHERE block_number = ? LIMIT ? OFFSET ?", &map);
			if (!cursor2 || cursor2->error())
				return expects_lr<size_t>(layer_exception(error_of(cursor2)));

			size_t size1 = 0;
			if (!cursor1->empty())
			{
				auto& response = cursor1->first();
				size1 = response.size();
				for (size_t i = 0; i < size1; i++)
				{
					auto row = response[i];
					format::stream message = format::stream(load(label, __func__, get_uniform_label(row["index_hash"].get().get_blob(), value.number)).or_else(string()));
					uptr<ledger::state> next_state = states::resolver::from_stream(message);
					if (next_state && next_state->load(message))
						value.states.move_any(std::move(next_state));
				}
			}

			size_t size2 = 0;
			if (!cursor2->empty())
			{
				auto& response = cursor2->first();
				size2 = response.size();
				for (size_t i = 0; i < size2; i++)
				{
					auto row = response[i];
					format::stream message = format::stream(load(label, __func__, get_multiform_label(row["column_hash"].get().get_blob(), row["row_hash"].get().get_blob(), value.number)).or_else(string()));
					uptr<ledger::state> next_state = states::resolver::from_stream(message);
					if (next_state && next_state->load(message))
						value.states.move_any(std::move(next_state));
				}
			}

			value.states.commit();
			return size1 + size2;
		}
		expects_lr<chainstate::uniform_location> chainstate::resolve_uniform_location(const std::string_view& index, bool latest)
		{
			auto cache = uniform_cache::get();
			auto index_location = cache->get_index_location(index);
			auto block_location = latest && index_location ? cache->get_block_location(*index_location) : option<uint64_t>(optional::none);
			if (!index_location)
			{
				auto find_index = uniformdata->prepare_statement("SELECT index_number FROM indices WHERE index_hash = ?", nullptr);
				if (!find_index)
					return expects_lr<uniform_location>(layer_exception(std::move(find_index.error().message())));

				uniformdata->bind_blob(*find_index, 0, index);
				auto cursor = prepared_query(*uniformdata, label, __func__, *find_index);
				if (!cursor || cursor->error())
					return expects_lr<uniform_location>(layer_exception(error_of(cursor)));

				index_location = (*cursor)["index_number"].get().get_integer();
				cache->set_index_location(index, *index_location);
			}

			uniform_location location;
			location.index = index_location && *index_location > 0 ? std::move(index_location) : option<uint64_t>(optional::none);
			location.block = block_location && *block_location > 0 ? std::move(block_location) : option<uint64_t>(optional::none);
			return location;
		}
		expects_lr<chainstate::multiform_location> chainstate::resolve_multiform_location(const option<std::string_view>& column, const option<std::string_view>& row, bool latest)
		{
			VI_ASSERT(column || row, "column or row should be set");
			auto cache = multiform_cache::get();
			bool update_column = false, update_row = false;
			auto column_location = column ? cache->get_column_location(*column) : option<uint64_t>(optional::none);
			auto row_location = row ? cache->get_row_location(*row) : option<uint64_t>(optional::none);
			auto block_location = latest && column_location && row_location ? cache->get_block_location(*column_location, *row_location) : option<uint64_t>(optional::none);
			if (column && !column_location)
			{
				auto find_column = multiformdata->prepare_statement("SELECT column_number FROM columns WHERE column_hash = ?", nullptr);
				if (!find_column)
					return expects_lr<multiform_location>(layer_exception(std::move(find_column.error().message())));

				multiformdata->bind_blob(*find_column, 0, *column);
				auto cursor = prepared_query(*multiformdata, label, __func__, *find_column);
				if (!cursor || cursor->error())
					return expects_lr<multiform_location>(layer_exception(error_of(cursor)));

				column_location = (*cursor)["column_number"].get().get_integer();
				update_column = true;
			}

			if (row && !row_location)
			{
				auto find_row = multiformdata->prepare_statement("SELECT row_number FROM rows WHERE row_hash = ?", nullptr);
				if (!find_row)
					return expects_lr<multiform_location>(layer_exception(std::move(find_row.error().message())));

				multiformdata->bind_blob(*find_row, 0, *row);
				auto cursor = prepared_query(*multiformdata, label, __func__, *find_row);
				if (!cursor || cursor->error())
					return expects_lr<multiform_location>(layer_exception(error_of(cursor)));

				row_location = (*cursor)["row_number"].get().get_integer();
				update_row = true;
			}

			if (column && row)
			{
				if (!column_location.or_else(0) || !row_location.or_else(0))
					return layer_exception("multiform location not found");
				else if (update_column || update_row)
					cache->set_multiform_location(*column, *row, *column_location, *row_location);
			}
			else if (column)
			{
				if (!column_location.or_else(0))
					return layer_exception("multiform column not found");
				else if (update_column)
					cache->set_column_location(*column, *column_location);
			}
			else if (row)
			{
				if (!row_location.or_else(0))
					return layer_exception("multiform row not found");
				else if (update_row)
					cache->set_row_location(*row, *row_location);
			}

			multiform_location location;
			location.column = column_location && *column_location > 0 ? std::move(column_location) : option<uint64_t>(optional::none);
			location.row = row_location && *row_location > 0 ? std::move(row_location) : option<uint64_t>(optional::none);
			location.block = block_location && *block_location > 0 ? std::move(block_location) : option<uint64_t>(optional::none);
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

			auto find_account = accountdata->prepare_statement("SELECT account_number FROM accounts WHERE account_hash = ?", nullptr);
			if (!find_account)
				return expects_lr<uint64_t>(layer_exception(std::move(find_account.error().message())));

			accountdata->bind_blob(*find_account, 0, std::string_view((char*)account, sizeof(algorithm::pubkeyhash)));
			auto cursor = prepared_query(*accountdata, label, __func__, *find_account);
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
			auto cursor = query(*blockdata, label, __func__, "SELECT max(block_number) AS block_number FROM checkpoints");
			if (!cursor || cursor->error_or_empty())
				return expects_lr<uint64_t>(layer_exception(error_of(cursor)));

			return (uint64_t)(*cursor)["block_number"].get().get_integer();
		}
		expects_lr<uint64_t> chainstate::get_latest_block_number()
		{
			auto cursor = query(*blockdata, label, __func__, "SELECT block_number FROM blocks ORDER BY block_number DESC LIMIT 1");
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

			auto cursor = emplace_query(*blockdata, label, __func__, "SELECT block_number FROM blocks WHERE block_hash = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<uint64_t>(layer_exception(error_of(cursor)));

			return (uint64_t)(*cursor)["block_number"].get().get_integer();
		}
		expects_lr<uint256_t> chainstate::get_block_hash_by_number(uint64_t block_number)
		{
			schema_list map;
			map.push_back(var::set::integer(block_number));

			auto cursor = emplace_query(*blockdata, label, __func__, "SELECT block_hash FROM blocks WHERE block_number = ?", &map);
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

				auto cursor = emplace_query(*txdata, label, __func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce LIMIT ? OFFSET ?", &map);
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
					format::stream message = format::stream(load(label, __func__, get_transaction_label(transaction_hash.get_binary())).or_else(string()));
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

			auto cursor = emplace_query(*blockdata, label, __func__, "SELECT block_hash FROM blocks WHERE block_number = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<ledger::block>(layer_exception(error_of(cursor)));

			ledger::block_header header;
			auto block_hash = (*cursor)["block_hash"].get();
			format::stream message = format::stream(load(label, __func__, get_block_label(block_hash.get_binary())).or_else(string()));
			if (!header.load(message))
				return expects_lr<ledger::block>(layer_exception("block header deserialization error"));

			ledger::block result = ledger::block(header);
			size_t offset = 0;
			while ((details & (uint32_t)block_details::transactions || details & (uint32_t)block_details::block_transactions) && chunk > 0)
			{
				auto size = resolve_block_transactions(result, details & (uint32_t)block_details::block_transactions, offset, chunk);
				if (!size)
					return size.error();

				offset += *size;
				if (*size < chunk)
					break;
			}

			offset = 0;
			while (details & (uint32_t)block_details::states && chunk > 0)
			{
				auto size = resolve_block_statetrie(result, offset, chunk);
				if (!size)
					return size.error();

				offset += *size;
				if (*size < chunk)
					break;
			}

			finalize_checksum(header, block_hash);
			return result;
		}
		expects_lr<ledger::block> chainstate::get_block_by_hash(const uint256_t& block_hash, size_t chunk, uint32_t details)
		{
			uint8_t hash[32];
			algorithm::encoding::decode_uint256(block_hash, hash);

			ledger::block_header header;
			format::stream message = format::stream(load(label, __func__, get_block_label(hash)).or_else(string()));
			if (!header.load(message))
				return expects_lr<ledger::block>(layer_exception("block header deserialization error"));

			ledger::block result = ledger::block(header);
			size_t offset = 0;
			while ((details & (uint32_t)block_details::transactions || details & (uint32_t)block_details::block_transactions) && chunk > 0)
			{
				auto size = resolve_block_transactions(result, details & (uint32_t)block_details::block_transactions, offset, chunk);
				if (!size)
					return size.error();

				offset += *size;
				if (*size < chunk)
					break;
			}

			offset = 0;
			while (details & (uint32_t)block_details::states && chunk > 0)
			{
				auto size = resolve_block_statetrie(result, offset, chunk);
				if (!size)
					return size.error();

				offset += *size;
				if (*size < chunk)
					break;
			}

			finalize_checksum(header, var::binary(hash, sizeof(hash)));
			return result;
		}
		expects_lr<ledger::block> chainstate::get_latest_block(size_t chunk, uint32_t details)
		{
			auto cursor = query(*blockdata, label, __func__, "SELECT block_hash FROM blocks ORDER BY block_number DESC LIMIT 1");
			if (!cursor || cursor->error_or_empty())
				return expects_lr<ledger::block>(layer_exception(error_of(cursor)));

			ledger::block_header header;
			auto block_hash = (*cursor)["block_hash"].get();
			format::stream message = format::stream(load(label, __func__, get_block_label(block_hash.get_binary())).or_else(string()));
			if (!header.load(message))
				return expects_lr<ledger::block>(layer_exception("block header deserialization error"));

			ledger::block result = ledger::block(header);
			size_t offset = 0;
			while ((details & (uint32_t)block_details::transactions || details & (uint32_t)block_details::block_transactions) && chunk > 0)
			{
				auto size = resolve_block_transactions(result, details & (uint32_t)block_details::block_transactions, offset, chunk);
				if (!size)
					return size.error();

				offset += *size;
				if (*size < chunk)
					break;
			}

			offset = 0;
			while (details & (uint32_t)block_details::states && chunk > 0)
			{
				auto size = resolve_block_statetrie(result, offset, chunk);
				if (!size)
					return size.error();

				offset += *size;
				if (*size < chunk)
					break;
			}

			finalize_checksum(header, block_hash);
			return result;
		}
		expects_lr<ledger::block_header> chainstate::get_block_header_by_number(uint64_t block_number)
		{
			schema_list map;
			map.push_back(var::set::integer(block_number));

			auto cursor = emplace_query(*blockdata, label, __func__, "SELECT block_hash FROM blocks WHERE block_number = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<ledger::block_header>(layer_exception(error_of(cursor)));

			ledger::block_header header;
			auto block_hash = (*cursor)["block_hash"].get();
			format::stream message = format::stream(load(label, __func__, get_block_label(block_hash.get_binary())).or_else(string()));
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
			format::stream message = format::stream(load(label, __func__, get_block_label(hash)).or_else(string()));
			if (!header.load(message))
				return expects_lr<ledger::block_header>(layer_exception("block header deserialization error"));

			finalize_checksum(header, var::binary(hash, sizeof(hash)));
			return header;
		}
		expects_lr<ledger::block_header> chainstate::get_latest_block_header()
		{
			auto cursor = query(*blockdata, label, __func__, "SELECT block_hash FROM blocks ORDER BY block_number DESC LIMIT 1");
			if (!cursor || cursor->error_or_empty())
				return expects_lr<ledger::block_header>(layer_exception(error_of(cursor)));

			ledger::block_header header;
			auto block_hash = (*cursor)["block_hash"].get();
			format::stream message = format::stream(load(label, __func__, get_block_label(block_hash.get_binary())).or_else(string()));
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

			auto parent_block = get_block_header_by_number(child_block->number - 1);
			ledger::block_proof value = ledger::block_proof(*child_block, parent_block.address());

			schema_list map;
			map.push_back(var::set::integer(block_number));

			auto cursor = emplace_query(*txdata, label, __func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce;", &map);
			if (!cursor || cursor->error())
				return expects_lr<ledger::block_proof>(layer_exception(error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			value.transactions.resize(size);
			value.receipts.resize(size);
			parallel::wail_all(parallel::for_loop(size, ELEMENTS_FEW, [&](size_t i)
			{
				auto transaction_hash = response[i]["transaction_hash"].get().get_blob();
				if (transaction_hash.size() == sizeof(uint256_t))
				{
					algorithm::encoding::encode_uint256((uint8_t*)transaction_hash.data(), value.transactions[i]);
					value.receipts[i] = format::stream(load(label, __func__, get_receipt_label((uint8_t*)transaction_hash.data())).or_else(string())).hash();
				}
				else
				{
					value.transactions[i] = 0;
					value.receipts[i] = 0;
				}
			}));

			auto cursor1 = emplace_query(*uniformdata, label, __func__, "SELECT (SELECT index_hash FROM indices WHERE indices.index_number = uniformtries.index_number) AS index_hash FROM uniformtries WHERE block_number = ?", &map);
			if (!cursor1 || cursor1->error())
				return expects_lr<ledger::block_proof>(layer_exception(error_of(cursor1)));

			auto cursor2 = emplace_query(*multiformdata, label, __func__, "SELECT (SELECT column_hash FROM columns WHERE columns.column_number = multiformtries.column_number) AS column_hash, (SELECT row_hash FROM rows WHERE rows.row_number = multiformtries.row_number) AS row_hash FROM multiformtries WHERE block_number = ?", &map);
			if (!cursor2 || cursor2->error())
				return expects_lr<ledger::block_proof>(layer_exception(error_of(cursor2)));

			auto response1 = cursor1->first();
			auto response2 = cursor2->first();
			size_t size1 = response1.size();
			size_t size2 = response2.size();
			value.states.resize(size1 + size2);
			auto task_queue1 = parallel::for_loop(size, ELEMENTS_FEW, [&](size_t i)
			{
				value.states[i] = format::stream(load(label, __func__, get_uniform_label(response1[i]["index_hash"].get().get_blob(), block_number)).or_else(string())).hash();
			});
			auto task_queue2 = parallel::for_loop(size, ELEMENTS_FEW, [&](size_t i)
			{
				value.states[i + size1] = format::stream(load(label, __func__, get_uniform_label(response2[i]["index_hash"].get().get_blob(), block_number)).or_else(string())).hash();
			});
			parallel::wail_all(std::move(task_queue1));
			parallel::wail_all(std::move(task_queue2));
			return value;
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

			auto cursor = emplace_query(*txdata, label, __func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce", &map);
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
		expects_lr<vector<uint256_t>> chainstate::get_block_statetrie_hashset(uint64_t block_number)
		{
			if (!block_number)
				return layer_exception("invalid block number");

			schema_list map;
			map.push_back(var::set::integer(block_number));

			auto cursor1 = emplace_query(*uniformdata, label, __func__, "SELECT (SELECT index_hash FROM indices WHERE indices.index_number = uniformtries.index_number) AS index_hash FROM uniformtries WHERE block_number = ?", &map);
			if (!cursor1 || cursor1->error())
				return expects_lr<vector<uint256_t>>(layer_exception(error_of(cursor1)));

			auto cursor2 = emplace_query(*multiformdata, label, __func__, "SELECT (SELECT column_hash FROM columns WHERE columns.column_number = multiformtries.column_number) AS column_hash, (SELECT row_hash FROM rows WHERE rows.row_number = multiformtries.row_number) AS row_hash FROM multiformtries WHERE block_number = ?", &map);
			if (!cursor2 || cursor2->error())
				return expects_lr<vector<uint256_t>>(layer_exception(error_of(cursor2)));

			vector<uint256_t> result;
			for (auto& response : *cursor1)
			{
				size_t size = response.size();
				result.resize(result.size() + size);
				parallel::wail_all(parallel::for_loop(size, ELEMENTS_FEW, [&](size_t i)
				{
					result[i] = format::stream(load(label, __func__, get_uniform_label(response[i]["index_hash"].get().get_blob(), block_number)).or_else(string())).hash();
				}));
			}
			for (auto& response : *cursor2)
			{
				size_t size = response.size();
				size_t offset = result.size();
				result.resize(result.size() + size);
				parallel::wail_all(parallel::for_loop(size, ELEMENTS_FEW, [&](size_t i)
				{
					auto row = response[i];
					result[i + offset] = format::stream(load(label, __func__, get_multiform_label(row["column_hash"].get().get_blob(), row["row_hash"].get().get_blob(), block_number)).or_else(string())).hash();
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

			auto cursor = emplace_query(*blockdata, label, __func__, "SELECT block_hash FROM blocks WHERE block_number BETWEEN ? AND ? ORDER BY block_number DESC", &map);
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

			auto cursor = emplace_query(*blockdata, label, __func__, "SELECT block_hash FROM blocks WHERE block_number BETWEEN ? AND ? ORDER BY block_number DESC", &map);
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
					format::stream message = format::stream(load(label, __func__, get_block_label(block_hash.get_binary())).or_else(string()));
					result[i].load(message);
				}));
			}

			return result;
		}
		expects_lr<ledger::state_work> chainstate::get_block_statetrie_by_number(uint64_t block_number, size_t offset, size_t count)
		{
			schema_list map;
			map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor1 = emplace_query(*uniformdata, label, __func__, "SELECT (SELECT index_hash FROM indices WHERE indices.index_number = uniformtries.index_number) AS index_hash FROM uniformtries WHERE block_number = ? LIMIT ? OFFSET ?", &map);
			if (!cursor1 || cursor1->error())
				return expects_lr<ledger::state_work>(layer_exception(error_of(cursor1)));

			auto cursor2 = emplace_query(*multiformdata, label, __func__, "SELECT (SELECT column_hash FROM columns WHERE columns.column_number = multiformtries.column_number) AS column_hash, (SELECT row_hash FROM rows WHERE rows.row_number = multiformtries.row_number) AS row_hash FROM multiformtries WHERE block_number = ? LIMIT ? OFFSET ?", &map);
			if (!cursor2 || cursor2->error())
				return expects_lr<ledger::state_work>(layer_exception(error_of(cursor2)));

			auto result = expects_lr<ledger::state_work>(ledger::state_work());
			if (!cursor1->empty())
			{
				auto& response = cursor1->first();
				size_t size = response.size();
				for (size_t i = 0; i < size; i++)
				{
					auto row = response[i];
					auto message = format::stream(load(label, __func__, get_uniform_label(row["index_hash"].get().get_blob(), block_number)).or_else(string()));
					uptr<ledger::state> next_state = states::resolver::from_stream(message);
					if (next_state && next_state->load(message))
						(*result)[next_state->as_composite()] = std::move(next_state);
				}
			}
			if (!cursor2->empty())
			{
				auto& response = cursor2->first();
				size_t size = response.size();
				for (size_t i = 0; i < size; i++)
				{
					auto row = response[i];
					auto message = format::stream(load(label, __func__, get_multiform_label(row["column_hash"].get().get_blob(), row["row_hash"].get().get_blob(), block_number)).or_else(string()));
					uptr<ledger::state> next_state = states::resolver::from_stream(message);
					if (next_state && next_state->load(message))
						(*result)[next_state->as_composite()] = std::move(next_state);
				}
			}
			return result;
		}
		expects_lr<vector<uptr<ledger::transaction>>> chainstate::get_transactions_by_number(uint64_t block_number, size_t offset, size_t count)
		{
			schema_list map;
			map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = emplace_query(*txdata, label, __func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce LIMIT ? OFFSET ?", &map);
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
				format::stream message = format::stream(load(label, __func__, get_transaction_label(transaction_hash.get_binary())).or_else(string()));
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

			auto cursor = emplace_query(*partydata, label, __func__, "SELECT transaction_number FROM parties WHERE transaction_account_number = ? AND block_number <= ? ORDER BY transaction_number $? LIMIT ? OFFSET ?", &map);
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

			cursor = query(*txdata, label, __func__, dynamic_query);
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
				format::stream message = format::stream(load(label, __func__, get_transaction_label(transaction_hash.get_binary())).or_else(string()));
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

			auto cursor = emplace_query(*txdata, label, __func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce LIMIT ? OFFSET ?", &map);
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
				format::stream transaction_message = format::stream(load(label, __func__, get_transaction_label(transaction_hash.get_binary())).or_else(string()));
				format::stream receipt_message = format::stream(load(label, __func__, get_receipt_label(transaction_hash.get_binary())).or_else(string()));
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

			auto cursor = emplace_query(*partydata, label, __func__, "SELECT transaction_number FROM parties WHERE transaction_account_number = ? AND block_number <= ? ORDER BY transaction_number $? LIMIT ? OFFSET ?", &map);
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

			cursor = query(*txdata, label, __func__, dynamic_query);
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
				format::stream transaction_message = format::stream(load(label, __func__, get_transaction_label(transaction_hash.get_binary())).or_else(string()));
				format::stream receipt_message = format::stream(load(label, __func__, get_receipt_label(transaction_hash.get_binary())).or_else(string()));
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

			auto cursor = emplace_query(*txdata, label, __func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce LIMIT ? OFFSET ?", &map);
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
				format::stream message = format::stream(load(label, __func__, get_receipt_label(transaction_hash.get_binary())).or_else(string()));
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

			auto cursor = emplace_query(*txdata, label, __func__, "SELECT transaction_hash FROM transactions WHERE dispatch_queue IS NOT NULL AND dispatch_queue <= ? ORDER BY block_nonce LIMIT ? OFFSET ?", &map);
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
				format::stream transaction_message = format::stream(load(label, __func__, get_transaction_label(transaction_hash.get_binary())).or_else(string()));
				format::stream receipt_message = format::stream(load(label, __func__, get_receipt_label(transaction_hash.get_binary())).or_else(string()));
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

			auto cursor = emplace_query(*aliasdata, label, __func__, "SELECT transaction_number FROM aliases WHERE transaction_hash = ?", &map);
			string dynamic_query = "SELECT transaction_hash FROM transactions WHERE transaction_hash = ?";
			if (cursor && !cursor->error_or_empty())
			{
				dynamic_query.append("OR transaction_number IN (");
				for (auto row : cursor->first())
					dynamic_query.append(row.get_column(0).get().get_blob()).push_back(',');
				dynamic_query.pop_back();
				dynamic_query.push_back(')');
			}

			cursor = emplace_query(*txdata, label, __func__, dynamic_query, &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<uptr<ledger::transaction>>(layer_exception(error_of(cursor)));

			auto parent_transaction_hash = (*cursor)["transaction_hash"].get();
			format::stream message = format::stream(load(label, __func__, get_transaction_label(parent_transaction_hash.get_binary())).or_else(string()));
			uptr<ledger::transaction> value = transactions::resolver::from_stream(message);
			if (!value || !value->load(message))
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

			auto cursor = emplace_query(*aliasdata, label, __func__, "SELECT transaction_number FROM aliases WHERE transaction_hash = ?", &map);
			string dynamic_query = "SELECT transaction_hash FROM transactions WHERE transaction_hash = ?";
			if (cursor && !cursor->error_or_empty())
			{
				dynamic_query.append("OR transaction_number IN (");
				for (auto row : cursor->first())
					dynamic_query.append(row.get_column(0).get().get_blob()).push_back(',');
				dynamic_query.pop_back();
				dynamic_query.push_back(')');
			}

			cursor = emplace_query(*txdata, label, __func__, dynamic_query, &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<ledger::block_transaction>(layer_exception(error_of(cursor)));

			auto parent_transaction_hash = (*cursor)["transaction_hash"].get();
			format::stream transaction_message = format::stream(load(label, __func__, get_transaction_label(parent_transaction_hash.get_binary())).or_else(string()));
			format::stream receipt_message = format::stream(load(label, __func__, get_receipt_label(parent_transaction_hash.get_binary())).or_else(string()));
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
			format::stream message = format::stream(load(label, __func__, get_receipt_label(hash)).or_else(string()));
			if (!value.load(message))
				return expects_lr<ledger::receipt>(layer_exception("receipt deserialization error"));

			return value;
		}
		expects_lr<uptr<ledger::state>> chainstate::get_uniform_by_index(const ledger::block_mutation* delta, const std::string_view& index, uint64_t block_number)
		{
			if (delta != nullptr)
			{
				if (delta->outgoing != nullptr)
				{
					auto candidate = delta->outgoing->find_uniform(index);
					if (candidate)
						return std::move(*candidate);
				}

				if (delta->incoming != nullptr)
				{
					auto candidate = delta->incoming->find_uniform(index);
					if (candidate)
						return std::move(*candidate);
				}
			}

			auto location = resolve_uniform_location(index, !block_number);
			if (!location)
				return location.error();

			if (!location->block)
			{
				auto find_state = uniformdata->prepare_statement(!block_number ?
					"SELECT block_number FROM uniforms WHERE index_number = ?" :
					"SELECT block_number FROM uniformtries WHERE index_number = ? AND block_number < ? ORDER BY block_number DESC LIMIT 1", nullptr);
				if (!find_state)
					return expects_lr<uptr<ledger::state>>(layer_exception(std::move(find_state.error().message())));

				uniformdata->bind_int64(*find_state, 0, location->index.or_else(0));
				if (block_number > 0)
					uniformdata->bind_int64(*find_state, 1, block_number);

				auto cursor = prepared_query(*uniformdata, label, __func__, *find_state);
				if (!cursor || cursor->empty())
				{
					if (delta != nullptr && delta->incoming != nullptr)
						((ledger::block_mutation*)delta)->incoming->clear_uniform(index);
					return expects_lr<uptr<ledger::state>>(layer_exception(error_of(cursor)));
				}
				else if (cursor->empty())
				{
					if (delta != nullptr && delta->incoming != nullptr)
						((ledger::block_mutation*)delta)->incoming->clear_uniform(index);
					return expects_lr<uptr<ledger::state>>(layer_exception("uniform not found"));
				}

				auto cache = uniform_cache::get();
				location->block = (*cursor)["block_number"].get().get_integer();
				cache->set_block_location(location->index.or_else(0), location->block.or_else(0));
			}

			format::stream message = format::stream(load(label, __func__, get_uniform_label(index, location->block.or_else(0))).or_else(string()));
			uptr<ledger::state> value = states::resolver::from_stream(message);
			if (!value || !value->load(message))
			{
				if (delta != nullptr && delta->incoming != nullptr)
					((ledger::block_mutation*)delta)->incoming->clear_uniform(index);
				return expects_lr<uptr<ledger::state>>(layer_exception("uniform deserialization error"));
			}

			if (delta != nullptr && delta->incoming != nullptr)
				((ledger::block_mutation*)delta)->incoming->copy_any(*value);
			return value;
		}
		expects_lr<uptr<ledger::state>> chainstate::get_multiform_by_composition(const ledger::block_mutation* delta, const std::string_view& column, const std::string_view& row, uint64_t block_number)
		{
			if (delta != nullptr)
			{
				if (delta->outgoing != nullptr)
				{
					auto candidate = delta->outgoing->find_multiform(column, row);
					if (candidate)
						return std::move(*candidate);
				}

				if (delta->incoming != nullptr)
				{
					auto candidate = delta->incoming->find_multiform(column, row);
					if (candidate)
						return std::move(*candidate);
				}
			}

			auto location = resolve_multiform_location(column, row, !block_number);
			if (!location)
				return location.error();

			if (!location->block)
			{
				auto find_state = multiformdata->prepare_statement(!block_number ?
					"SELECT block_number FROM multiforms WHERE column_number = ? AND row_number = ?" :
					"SELECT block_number FROM multiformtries WHERE column_number = ? AND row_number = ? AND block_number < ? ORDER BY block_number DESC LIMIT 1", nullptr);
				if (!find_state)
					return expects_lr<uptr<ledger::state>>(layer_exception(std::move(find_state.error().message())));

				multiformdata->bind_int64(*find_state, 0, location->column.or_else(0));
				multiformdata->bind_int64(*find_state, 1, location->row.or_else(0));
				if (block_number > 0)
					multiformdata->bind_int64(*find_state, 2, block_number);

				auto cursor = prepared_query(*multiformdata, label, __func__, *find_state);
				if (!cursor || cursor->empty())
				{
					if (delta != nullptr && delta->incoming != nullptr)
						((ledger::block_mutation*)delta)->incoming->clear_multiform(column, row);
					return expects_lr<uptr<ledger::state>>(layer_exception(error_of(cursor)));
				}
				else if (cursor->empty())
				{
					if (delta != nullptr && delta->incoming != nullptr)
						((ledger::block_mutation*)delta)->incoming->clear_multiform(column, row);
					return expects_lr<uptr<ledger::state>>(layer_exception("multiform not found"));
				}

				auto cache = multiform_cache::get();
				location->block = (*cursor)["block_number"].get().get_integer();
				cache->set_block_location(location->column.or_else(0), location->row.or_else(0), location->block.or_else(0));
			}

			format::stream message = format::stream(load(label, __func__, get_multiform_label(column, row, location->block.or_else(0))).or_else(string()));
			uptr<ledger::state> value = states::resolver::from_stream(message);
			if (!value || !value->load(message))
			{
				if (delta != nullptr && delta->incoming != nullptr)
					((ledger::block_mutation*)delta)->incoming->clear_multiform(column, row);
				return expects_lr<uptr<ledger::state>>(layer_exception("multiform deserialization error"));
			}

			if (delta != nullptr && delta->incoming != nullptr)
				((ledger::block_mutation*)delta)->incoming->copy_any(*value);
			return value;
		}
		expects_lr<uptr<ledger::state>> chainstate::get_multiform_by_column(const ledger::block_mutation* delta, const std::string_view& column, uint64_t block_number, size_t offset)
		{
			auto location = resolve_multiform_location(column, optional::none, false);
			if (!location)
				return location.error();

			schema_list map;
			map.push_back(var::set::integer(location->column.or_else(0)));
			if (block_number > 0)
				map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(offset));

			auto cursor = emplace_query(*multiformdata, label, __func__, !block_number ?
				"SELECT (SELECT row_hash FROM rows WHERE rows.row_number = multiforms.row_number) AS row_hash, block_number FROM multiforms WHERE column_number = ? ORDER BY row_number LIMIT 1 OFFSET ?" :
				"SELECT (SELECT row_hash FROM rows WHERE rows.row_number = multiformtries.row_number) AS row_hash, max(block_number) AS block_number FROM multiformtries WHERE column_number = ? AND block_number < ? GROUP BY row_number ORDER BY row_number LIMIT 1 OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<uptr<ledger::state>>(layer_exception(error_of(cursor)));
			else if (cursor->empty())
				return expects_lr<uptr<ledger::state>>(layer_exception("multiform not found"));

			format::stream message = format::stream(load(label, __func__, get_multiform_label(column, (*cursor)["row_hash"].get().get_blob(), (*cursor)["block_number"].get().get_integer())).or_else(string()));
			uptr<ledger::state> value = states::resolver::from_stream(message);
			if (!value || !value->load(message))
			{
				if (value && delta != nullptr && delta->incoming != nullptr)
					((ledger::block_mutation*)delta)->incoming->clear_multiform(column, ((ledger::multiform*)*value)->as_row());
				return expects_lr<uptr<ledger::state>>(layer_exception("multiform deserialization error"));
			}

			if (delta != nullptr && delta->incoming != nullptr)
				((ledger::block_mutation*)delta)->incoming->copy_any(*value);
			return value;
		}
		expects_lr<uptr<ledger::state>> chainstate::get_multiform_by_row(const ledger::block_mutation* delta, const std::string_view& row, uint64_t block_number, size_t offset)
		{
			auto location = resolve_multiform_location(optional::none, row, false);
			if (!location)
				return location.error();

			schema_list map;
			map.push_back(var::set::integer(location->row.or_else(0)));
			if (block_number > 0)
				map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(offset));

			auto cursor = emplace_query(*multiformdata, label, __func__, !block_number ?
				"SELECT (SELECT column_hash FROM columns WHERE columns.column_number = multiforms.column_number) AS column_hash, block_number FROM multiforms WHERE row_number = ? ORDER BY column_number LIMIT 1 OFFSET ?" :
				"SELECT (SELECT column_hash FROM columns WHERE columns.column_number = multiformtries.column_number) AS column_hash, max(block_number) AS block_number FROM multiformtries WHERE row_number = ? AND block_number < ? GROUP BY column_number ORDER BY column_number LIMIT 1 OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<uptr<ledger::state>>(layer_exception(error_of(cursor)));
			else if (cursor->empty())
				return expects_lr<uptr<ledger::state>>(layer_exception("multiform not found"));

			format::stream message = format::stream(load(label, __func__, get_multiform_label((*cursor)["column_hash"].get().get_blob(), row, (*cursor)["block_number"].get().get_integer())).or_else(string()));
			uptr<ledger::state> value = states::resolver::from_stream(message);
			if (!value || !value->load(message))
			{
				if (value && delta != nullptr && delta->incoming != nullptr)
					((ledger::block_mutation*)delta)->incoming->clear_multiform(((ledger::multiform*)*value)->as_column(), row);
				return expects_lr<uptr<ledger::state>>(layer_exception("multiform deserialization error"));
			}

			if (delta != nullptr && delta->incoming != nullptr)
				((ledger::block_mutation*)delta)->incoming->copy_any(*value);
			return value;
		}
		expects_lr<vector<uptr<ledger::state>>> chainstate::get_multiforms_by_column(const ledger::block_mutation* delta, const std::string_view& column, uint64_t block_number, size_t offset, size_t count)
		{
			auto location = resolve_multiform_location(column, optional::none, false);
			if (!location)
				return expects_lr<vector<uptr<ledger::state>>>(vector<uptr<ledger::state>>());

			schema_list map;
			map.push_back(var::set::integer(location->column.or_else(0)));
			if (block_number > 0)
				map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = emplace_query(*multiformdata, label, __func__, !block_number ?
				"SELECT (SELECT row_hash FROM rows WHERE rows.row_number = multiforms.row_number) AS row_hash, block_number FROM multiforms WHERE column_number = ? ORDER BY row_number LIMIT ? OFFSET ?" :
				"SELECT (SELECT row_hash FROM rows WHERE rows.row_number = multiformtries.row_number) AS row_hash, max(block_number) AS block_number FROM multiformtries WHERE column_number = ? AND block_number < ? GROUP BY row_number ORDER BY row_number LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<uptr<ledger::state>>>(layer_exception(error_of(cursor)));

			vector<uptr<ledger::state>> values;
			auto& response = cursor->first();
			size_t size = response.size();
			for (size_t i = 0; i < size; i++)
			{
				auto next = response[i];
				format::stream message = format::stream(load(label, __func__, get_multiform_label(column, next["row_hash"].get().get_blob(), next["block_number"].get().get_integer())).or_else(string()));
				uptr<ledger::state> next_state = states::resolver::from_stream(message);
				if (!next_state || !next_state->load(message))
				{
					if (next_state && delta != nullptr && delta->incoming != nullptr)
						((ledger::block_mutation*)delta)->incoming->clear_multiform(column, ((ledger::multiform*)*next_state)->as_row());
					continue;
				}
				else if (delta != nullptr && delta->incoming != nullptr)
					((ledger::block_mutation*)delta)->incoming->copy_any(*next_state);
				values.push_back(std::move(next_state));
			}

			return values;
		}
		expects_lr<vector<uptr<ledger::state>>> chainstate::get_multiforms_by_column_filter(const ledger::block_mutation* delta, const std::string_view& column, const factor_filter& filter, uint64_t block_number, const factor_window& window)
		{
			auto location = resolve_multiform_location(column, optional::none, false);
			if (!location)
				return expects_lr<vector<uptr<ledger::state>>>(vector<uptr<ledger::state>>());

			schema_list map; string pattern;
			if (window.type() == factor_range_window::instance_type())
			{
				auto& range = *(factor_range_window*)&window;
				map.push_back(var::set::integer(location->column.or_else(0)));
				if (block_number > 0)
					map.push_back(var::set::integer(block_number));
				map.push_back(var::set::string(filter.as_condition()));
				map.push_back(var::set::integer(filter.value));
				map.push_back(var::set::string(filter.as_order()));
				map.push_back(var::set::integer(range.count));
				map.push_back(var::set::integer(range.offset));

				pattern = !block_number ?
					"SELECT (SELECT row_hash FROM rows WHERE rows.row_number = multiforms.row_number) AS row_hash, block_number FROM multiforms WHERE column_number = ? AND factor $? ? ORDER BY factor $?, row_number ASC LIMIT ? OFFSET ?" :
					"SELECT (SELECT row_hash FROM rows WHERE rows.row_number = queryforms.row_number) AS row_hash, block_number FROM (SELECT column_number, row_number, factor, max(block_number) AS block_number FROM multiformtries WHERE column_number = ? AND block_number < ? GROUP BY row_number) AS queryforms WHERE factor $? ? ORDER BY factor $?, row_number ASC LIMIT ? OFFSET ?";
			}
			else if (window.type() == factor_index_window::instance_type())
			{
				string indices;
				for (auto& item : ((factor_index_window*)&window)->indices)
					indices += to_string(item + 1) + ",";

				map.push_back(var::set::string(filter.as_order()));
				map.push_back(var::set::integer(location->column.or_else(0)));
				if (block_number > 0)
					map.push_back(var::set::integer(block_number));
				map.push_back(var::set::string(filter.as_condition()));
				map.push_back(var::set::integer(filter.value));
				map.push_back(var::set::string(indices.substr(0, indices.size() - 1)));

				pattern = !block_number ?
					"SELECT (SELECT row_hash FROM rows WHERE rows.row_number = sq.row_number) AS row_hash, block_number FROM (SELECT ROW_NUMBER() OVER (ORDER BY factor $?, row_number ASC) AS id, row_number, block_number FROM multiforms WHERE column_number = ? AND factor $? ?) AS sq WHERE sq.id IN ($?)" :
					"SELECT (SELECT row_hash FROM rows WHERE rows.row_number = sq.row_number) AS row_hash, block_number FROM (SELECT ROW_NUMBER() OVER (ORDER BY factor $?, row_number ASC) AS id, row_number, block_number FROM (SELECT column_number, row_number, factor, max(block_number) AS block_number FROM multiformtries WHERE column_number = ? AND block_number < ? GROUP BY row_number) AS queryforms WHERE factor $? ?) AS sq WHERE sq.id IN ($?)";
			}

			auto cursor = emplace_query(*multiformdata, label, __func__, pattern, &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<uptr<ledger::state>>>(layer_exception(error_of(cursor)));

			vector<uptr<ledger::state>> values;
			auto& response = cursor->first();
			size_t size = response.size();
			for (size_t i = 0; i < size; i++)
			{
				auto next = response[i];
				format::stream message = format::stream(load(label, __func__, get_multiform_label(column, next["row_hash"].get().get_blob(), next["block_number"].get().get_integer())).or_else(string()));
				uptr<ledger::state> next_state = states::resolver::from_stream(message);
				if (!next_state || !next_state->load(message))
				{
					if (next_state && delta != nullptr && delta->incoming != nullptr)
						((ledger::block_mutation*)delta)->incoming->clear_multiform(column, ((ledger::multiform*)*next_state)->as_row());
					continue;
				}
				else if (delta != nullptr && delta->incoming != nullptr)
					((ledger::block_mutation*)delta)->incoming->copy_any(*next_state);
				values.push_back(std::move(next_state));
			}

			return values;
		}
		expects_lr<vector<uptr<ledger::state>>> chainstate::get_multiforms_by_row(const ledger::block_mutation* delta, const std::string_view& row, uint64_t block_number, size_t offset, size_t count)
		{
			auto location = resolve_multiform_location(optional::none, row, false);
			if (!location)
				return expects_lr<vector<uptr<ledger::state>>>(vector<uptr<ledger::state>>());

			schema_list map;
			map.push_back(var::set::integer(location->column.or_else(0)));
			if (block_number > 0)
				map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = emplace_query(*multiformdata, label, __func__, !block_number ?
				"SELECT (SELECT column_hash FROM columns WHERE columns.column_number = multiforms.column_number) AS column_hash, block_number FROM multiforms WHERE row_number = ? ORDER BY column_number LIMIT ? OFFSET ?" :
				"SELECT (SELECT column_hash FROM columns WHERE columns.column_number = multiformtries.column_number) AS column_hash, max(block_number) AS block_number FROM multiformtries WHERE row_number = ? AND block_number < ? GROUP BY column_number ORDER BY column_number LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<uptr<ledger::state>>>(layer_exception(error_of(cursor)));

			vector<uptr<ledger::state>> values;
			auto& response = cursor->first();
			size_t size = response.size();
			for (size_t i = 0; i < size; i++)
			{
				auto next = response[i];
				format::stream message = format::stream(load(label, __func__, get_multiform_label(next["column_hash"].get().get_blob(), row, next["block_number"].get().get_integer())).or_else(string()));
				uptr<ledger::state> next_state = states::resolver::from_stream(message);
				if (!next_state || !next_state->load(message))
				{
					if (next_state && delta != nullptr && delta->incoming != nullptr)
						((ledger::block_mutation*)delta)->incoming->clear_multiform(((ledger::multiform*)*next_state)->as_column(), row);
					continue;
				}
				else if (delta != nullptr && delta->incoming != nullptr)
					((ledger::block_mutation*)delta)->incoming->copy_any(*next_state);
				values.push_back(std::move(next_state));
			}

			return values;
		}
		expects_lr<vector<uptr<ledger::state>>> chainstate::get_multiforms_by_row_filter(const ledger::block_mutation* delta, const std::string_view& row, const factor_filter& filter, uint64_t block_number, const factor_window& window)
		{
			auto location = resolve_multiform_location(optional::none, row, false);
			if (!location)
				return expects_lr<vector<uptr<ledger::state>>>(vector<uptr<ledger::state>>());

			schema_list map; string pattern;
			if (window.type() == factor_range_window::instance_type())
			{
				auto& range = *(factor_range_window*)&window;
				map.push_back(var::set::integer(location->row.or_else(0)));
				if (block_number > 0)
					map.push_back(var::set::integer(block_number));
				map.push_back(var::set::string(filter.as_condition()));
				map.push_back(var::set::integer(filter.value));
				map.push_back(var::set::string(filter.as_order()));
				map.push_back(var::set::integer(range.count));
				map.push_back(var::set::integer(range.offset));

				pattern = !block_number ?
					"SELECT (SELECT column_hash FROM columns WHERE columns.column_number = multiforms.column_number) AS column_hash, block_number FROM multiforms WHERE row_number = ? AND factor $? ? ORDER BY factor $?, column_number ASC LIMIT ? OFFSET ?" :
					"SELECT (SELECT column_hash FROM columns WHERE columns.column_number = queryforms.column_number) AS column_hash, block_number FROM (SELECT column_number, row_number, factor, max(block_number) AS block_number FROM multiformtries WHERE row_number = ? AND block_number < ? GROUP BY column_number) AS queryforms WHERE factor $? ? ORDER BY factor $?, column_number ASC LIMIT ? OFFSET ?";
			}
			else if (window.type() == factor_index_window::instance_type())
			{
				string indices;
				for (auto& item : ((factor_index_window*)&window)->indices)
					indices += to_string(item + 1) + ",";

				map.push_back(var::set::string(filter.as_order()));
				map.push_back(var::set::integer(location->row.or_else(0)));
				if (block_number > 0)
					map.push_back(var::set::integer(block_number));
				map.push_back(var::set::string(filter.as_condition()));
				map.push_back(var::set::integer(filter.value));
				map.push_back(var::set::string(indices.substr(0, indices.size() - 1)));

				pattern = !block_number ?
					"SELECT (SELECT column_hash FROM columns WHERE columns.column_number = sq.column_number) AS column_hash, block_number FROM (SELECT ROW_NUMBER() OVER (ORDER BY factor $?, column_number ASC) AS id, column_number, block_number FROM multiforms WHERE row_number = ? AND factor $? ?) AS sq WHERE sq.id IN ($?) ORDER BY sq.id ASC" :
					"SELECT (SELECT column_hash FROM columns WHERE columns.column_number = sq.column_number) AS column_hash, block_number FROM (SELECT ROW_NUMBER() OVER (ORDER BY factor $?, column_number ASC) AS id, column_number, block_number FROM (SELECT column_number, row_number, factor, max(block_number) AS block_number FROM multiformtries WHERE row_number = ? AND block_number < ? GROUP BY column_number) AS queryforms WHERE factor $? ?) AS sq WHERE sq.id IN ($?) ORDER BY sq.id ASC";
			}

			auto cursor = emplace_query(*multiformdata, label, __func__, pattern, &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<uptr<ledger::state>>>(layer_exception(error_of(cursor)));

			vector<uptr<ledger::state>> values;
			auto& response = cursor->first();
			size_t size = response.size();
			for (size_t i = 0; i < size; i++)
			{
				auto next = response[i];
				format::stream message = format::stream(load(label, __func__, get_multiform_label(next["column_hash"].get().get_blob(), row, next["block_number"].get().get_integer())).or_else(string()));
				uptr<ledger::state> next_state = states::resolver::from_stream(message);
				if (!next_state || !next_state->load(message))
				{
					if (next_state && delta != nullptr && delta->incoming != nullptr)
						((ledger::block_mutation*)delta)->incoming->clear_multiform(((ledger::multiform*)*next_state)->as_column(), row);
					continue;
				}
				else if (delta != nullptr && delta->incoming != nullptr)
					((ledger::block_mutation*)delta)->incoming->copy_any(*next_state);
				values.push_back(std::move(next_state));
			}

			return values;
		}
		expects_lr<size_t> chainstate::get_multiforms_count_by_column(const std::string_view& column, uint64_t block_number)
		{
			auto location = resolve_multiform_location(column, optional::none, false);
			if (!location)
				return location.error();

			schema_list map;
			map.push_back(var::set::integer(location->column.or_else(0)));
			if (block_number > 0)
				map.push_back(var::set::integer(block_number));

			auto cursor = emplace_query(*multiformdata, label, __func__, !block_number ? "SELECT COUNT(1) AS multiform_count FROM multiforms WHERE column_number = ?" : "SELECT COUNT(1) AS multiform_count FROM (SELECT max(block_number) FROM multiformtries WHERE column_number = ? AND block_number < ? GROUP BY row_number)", &map);
			if (!cursor || cursor->error())
				return expects_lr<size_t>(layer_exception(error_of(cursor)));

			size_t count = (*cursor)["multiform_count"].get().get_integer();
			return expects_lr<size_t>(count);
		}
		expects_lr<size_t> chainstate::get_multiforms_count_by_column_filter(const std::string_view& column, const factor_filter& filter, uint64_t block_number)
		{
			auto location = resolve_multiform_location(column, optional::none, false);
			if (!location)
				return location.error();

			schema_list map;
			map.push_back(var::set::integer(location->column.or_else(0)));
			if (block_number > 0)
				map.push_back(var::set::integer(block_number));
			map.push_back(var::set::string(filter.as_condition()));
			map.push_back(var::set::integer(filter.value));

			auto cursor = emplace_query(*multiformdata, label, __func__, !block_number ? "SELECT COUNT(1) AS multiform_count FROM multiforms WHERE column_number = ? AND factor $? ?" : "SELECT COUNT(1) AS multiform_count FROM (SELECT factor, max(block_number) FROM multiformtries WHERE column_number = ? AND block_number < ? GROUP BY row_number) WHERE factor $? ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<size_t>(layer_exception(error_of(cursor)));

			size_t count = (*cursor)["multiform_count"].get().get_integer();
			return expects_lr<size_t>(count);
		}
		expects_lr<size_t> chainstate::get_multiforms_count_by_row(const std::string_view& row, uint64_t block_number)
		{
			auto location = resolve_multiform_location(optional::none, row, false);
			if (!location)
				return location.error();

			schema_list map;
			map.push_back(var::set::integer(location->row.or_else(0)));
			if (block_number > 0)
				map.push_back(var::set::integer(block_number));

			auto cursor = emplace_query(*multiformdata, label, __func__, !block_number ? "SELECT COUNT(1) AS multiform_count FROM multiforms WHERE row_number = ?" : "SELECT COUNT(1) AS multiform_count FROM (SELECT max(block_number) FROM multiformtries WHERE row_number = ? AND block_number < ? GROUP BY column_number)", &map);
			if (!cursor || cursor->error())
				return expects_lr<size_t>(layer_exception(error_of(cursor)));

			size_t count = (*cursor)["multiform_count"].get().get_integer();
			return expects_lr<size_t>(count);
		}
		expects_lr<size_t> chainstate::get_multiforms_count_by_row_filter(const std::string_view& row, const factor_filter& filter, uint64_t block_number)
		{
			auto location = resolve_multiform_location(optional::none, row, false);
			if (!location)
				return location.error();

			schema_list map;
			map.push_back(var::set::integer(location->row.or_else(0)));
			if (block_number > 0)
				map.push_back(var::set::integer(block_number));
			map.push_back(var::set::string(filter.as_condition()));
			map.push_back(var::set::integer(filter.value));

			auto cursor = emplace_query(*multiformdata, label, __func__, !block_number ? "SELECT COUNT(1) AS multiform_count FROM multiforms WHERE row_number = ? AND factor $? ?" : "SELECT COUNT(1) AS multiform_count FROM (SELECT factor, max(block_number) FROM multiformtries WHERE row_number = ? AND block_number < ? GROUP BY column_number) WHERE factor $? ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<size_t>(layer_exception(error_of(cursor)));

			size_t count = (*cursor)["multiform_count"].get().get_integer();
			return expects_lr<size_t>(count);
		}
		void chainstate::clear_indexer_cache()
		{
			account_cache::cleanup_instance();
			uniform_cache::cleanup_instance();
			multiform_cache::cleanup_instance();
		}
		vector<sqlite::connection*> chainstate::get_index_storages()
		{
			vector<sqlite::connection*> index;
			index.push_back(*blockdata);
			index.push_back(*accountdata);
			index.push_back(*txdata);
			index.push_back(*partydata);
			index.push_back(*aliasdata);
			index.push_back(*uniformdata);
			index.push_back(*multiformdata);
			return index;
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
						block_hash BINARY(32) NOT NULL,
						PRIMARY KEY (block_hash)
					) WITHOUT ROWID;
					CREATE UNIQUE INDEX IF NOT EXISTS blocks_block_number ON blocks (block_number);
					CREATE TABLE IF NOT EXISTS checkpoints
					(
						block_number BIGINT NOT NULL,
						PRIMARY KEY (block_number)
					) WITHOUT ROWID;));
			}
			else if (name == "accountdata")
			{
				command = VI_STRINGIFY((
					CREATE TABLE IF NOT EXISTS accounts
					(
						account_number BIGINT NOT NULL,
						account_hash BINARY(20) NOT NULL,
						block_number BIGINT NOT NULL,
						PRIMARY KEY (account_number)
					) WITHOUT ROWID;
					CREATE UNIQUE INDEX IF NOT EXISTS accounts_account_hash ON accounts (account_hash);
					CREATE INDEX IF NOT EXISTS accounts_block_number ON accounts (block_number);));
			}
			else if (name == "txdata")
			{
				command = VI_STRINGIFY((
					CREATE TABLE IF NOT EXISTS transactions
					(
						transaction_number BIGINT NOT NULL,
						transaction_hash BINARY(32) NOT NULL,
						dispatch_queue BIGINT DEFAULT NULL,
						block_number BIGINT NOT NULL,
						block_nonce BIGINT NOT NULL,
						PRIMARY KEY (transaction_hash)
					) WITHOUT ROWID;
					CREATE UNIQUE INDEX IF NOT EXISTS transactions_transaction_number ON transactions (transaction_number);
					CREATE INDEX IF NOT EXISTS transactions_dispatch_queue_block_nonce ON transactions (dispatch_queue, block_nonce) WHERE dispatch_queue IS NOT NULL;
					CREATE INDEX IF NOT EXISTS transactions_block_number_block_nonce ON transactions (block_number, block_nonce);));
			}
			else if (name == "partydata")
			{
				command = VI_STRINGIFY((
					CREATE TABLE IF NOT EXISTS parties
					(
						transaction_number BIGINT NOT NULL,
						transaction_account_number BIGINT NOT NULL,
						block_number BIGINT NOT NULL,
						PRIMARY KEY (transaction_account_number, block_number, transaction_number)
					) WITHOUT ROWID;
					CREATE INDEX IF NOT EXISTS parties_block_number ON parties (block_number);));
			}
			else if (name == "aliasdata")
			{
				command = VI_STRINGIFY((
					CREATE TABLE IF NOT EXISTS aliases
					(
						transaction_number BIGINT NOT NULL,
						transaction_hash BINARY(32) NOT NULL,
						block_number BIGINT NOT NULL,
						PRIMARY KEY (transaction_hash, transaction_number)
					) WITHOUT ROWID;
					CREATE INDEX IF NOT EXISTS aliases_block_number ON aliases (block_number);));
			}
			else if (name == "uniformdata")
			{
				command = VI_STRINGIFY((
					CREATE TABLE IF NOT EXISTS indices
					(
						index_number BIGINT NOT NULL,
						index_hash BINARY NOT NULL,
						block_number BIGINT NOT NULL,
						PRIMARY KEY (index_number)
					) WITHOUT ROWID;
					CREATE UNIQUE INDEX IF NOT EXISTS indices_index_hash ON indices (index_hash);
					CREATE INDEX IF NOT EXISTS indices_block_number ON indices (block_number);
					CREATE TABLE IF NOT EXISTS uniforms
					(
						index_number BIGINT NOT NULL,
						block_number BIGINT NOT NULL,
						PRIMARY KEY (index_number)
					) WITHOUT ROWID;
					CREATE INDEX IF NOT EXISTS uniforms_block_number ON uniforms (block_number);
					CREATE TABLE IF NOT EXISTS uniformtries
					(
						index_number BIGINT NOT NULL,
						block_number BIGINT NOT NULL,
						PRIMARY KEY (index_number, block_number)
					) WITHOUT ROWID;
					CREATE INDEX IF NOT EXISTS uniformtries_block_number ON uniformtries (block_number);));
			}
			else if (name == "multiformdata")
			{
				command = VI_STRINGIFY((
					CREATE TABLE IF NOT EXISTS columns
					(
						column_number BIGINT NOT NULL,
						column_hash BINARY NOT NULL,
						block_number BIGINT NOT NULL,
						PRIMARY KEY (column_number)
					) WITHOUT ROWID;
					CREATE UNIQUE INDEX IF NOT EXISTS columns_column_hash ON columns (column_hash);
					CREATE INDEX IF NOT EXISTS columns_block_number ON columns (block_number);
					CREATE TABLE IF NOT EXISTS rows
					(
						row_number BIGINT NOT NULL,
						row_hash BINARY NOT NULL,
						block_number BIGINT NOT NULL,
						PRIMARY KEY (row_number)
					) WITHOUT ROWID;
					CREATE UNIQUE INDEX IF NOT EXISTS rows_row_hash ON rows (row_hash);
					CREATE INDEX IF NOT EXISTS rows_block_number ON rows (block_number);
					CREATE TABLE IF NOT EXISTS multiforms
					(
						column_number BIGINT NOT NULL,
						row_number BIGINT NOT NULL,
						factor BIGINT NOT NULL,
						block_number BIGINT NOT NULL,
						PRIMARY KEY (column_number, row_number)
					) WITHOUT ROWID;
					CREATE INDEX IF NOT EXISTS multiforms_row_number_column_number ON multiforms (row_number, column_number);
					CREATE INDEX IF NOT EXISTS multiforms_row_number_factor ON multiforms (row_number, factor);
					CREATE INDEX IF NOT EXISTS multiforms_block_number ON multiforms (block_number);
					CREATE TABLE IF NOT EXISTS multiformtries
					(
						column_number BIGINT NOT NULL,
						row_number BIGINT NOT NULL,
						factor BIGINT NOT NULL,
						block_number BIGINT NOT NULL,
						PRIMARY KEY (column_number, row_number, block_number)
					) WITHOUT ROWID;
					CREATE INDEX IF NOT EXISTS multiformtries_row_number_block_number ON multiformtries (row_number, block_number);
					CREATE INDEX IF NOT EXISTS multiformtries_column_number_block_number ON multiformtries (column_number, block_number);
					CREATE INDEX IF NOT EXISTS multiformtries_block_number ON multiformtries (block_number);));
			}

			command.front() = ' ';
			command.back() = ' ';
			stringify::trim(command);
			auto cursor = query(storage, label, __func__, command);
			return (cursor && !cursor->error());
		}
	}
}