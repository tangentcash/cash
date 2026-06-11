#include "chainstate.h"
#include "../policy/transactions.h"
#include "../policy/states.h"
#define BLOB_BLOCK 'b'
#define BLOB_TRANSACTION 't'
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
			format::wo_stream message;
			uint64_t transaction_number;
			uint64_t block_nonce;
			bool dispatchable;
			btree_set<algorithm::pubkeyhash_t> parties;
			vector<transaction_alias_blob> aliases;
			const ledger::block_transaction* context;
		};

		struct uniform_blob
		{
			format::wo_stream message;
			string index;
			const ledger::uniform_state* context;
			const ledger::block_state::state_change* change;
		};

		struct uniform_writer
		{
			vector<uniform_blob> blobs;
			sqlite::tstatement* erase_uniform_data;
			sqlite::tstatement* commit_uniform_index_data;
			sqlite::tstatement* commit_uniform_data;
			sqlite::tstatement* commit_snapshot_data;
			ledger::storage_index_ptr* storage;
		};

		struct multiform_blob
		{
			format::wo_stream message;
			string column;
			string row;
			uint8_t rank[32];
			const ledger::multiform_state* context;
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
			ledger::storage_index_ptr* storage;
		};

		static void fill_multiform_writer_from_block_state(vector<multiform_blob>* blobs, uint32_t type, const ledger::block_state::log& state)
		{
			for (auto& [index, change] : state)
			{
				if (change.state->as_level() == ledger::state_level::multiform && change.state->as_type() == type)
				{
					multiform_blob blob;
					blob.context = (ledger::multiform_state*)*change.state;
					blob.change = &change;
					blobs->emplace_back(std::move(blob));
				}
			}
		}
		static void fill_multiform_writer_from_block_changelog(vector<multiform_blob>* blobs, uint32_t type, const option<std::string_view>& column, const option<std::string_view>& row, const ledger::block_changelog* changelog)
		{
			auto fill_filter = [&](const btree_map<string, ledger::block_state::state_change>& state)
			{
				for (auto& [index, change] : state)
				{
					if (change.state->as_level() != ledger::state_level::multiform || change.state->as_type() != type)
						continue;

					multiform_blob blob;
					blob.context = (ledger::multiform_state*)*change.state;
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
					blob.message.write_typeless(blob.column.c_str(), blob.column.size());
					blob.message.write_typeless(blob.row.c_str(), blob.row.size());
					blobs->emplace_back(std::move(blob));
				}
			};
			fill_filter(changelog->outgoing.finalized);
			fill_filter(changelog->outgoing.pending);
		}
		static expects_lr<void> fill_multiform_writer_from_storage(multiform_writer* writer, ledger::storage_index_ptr* multiform_storage)
		{
			auto erase_multiform_data = multiform_storage->prepare_statement(__func__, "DELETE FROM multiforms WHERE column_number = ? AND row_number = ?");
			if (!erase_multiform_data)
				return expects_lr<void>(layer_exception(std::move(erase_multiform_data.error().message())));

			auto commit_multiform_column_data = multiform_storage->prepare_statement(__func__, "INSERT OR IGNORE INTO columns (column_number, column_hash, block_number) SELECT (SELECT COALESCE(MAX(column_number), 0) + 1 FROM columns), ?, ? ON CONFLICT DO UPDATE SET block_number = block_number RETURNING column_number");
			if (!commit_multiform_column_data)
				return expects_lr<void>(layer_exception(std::move(commit_multiform_column_data.error().message())));

			auto commit_multiform_row_data = multiform_storage->prepare_statement(__func__, "INSERT OR IGNORE INTO rows (row_number, row_hash, block_number) SELECT (SELECT COALESCE(MAX(row_number), 0) + 1 FROM rows), ?, ? ON CONFLICT DO UPDATE SET block_number = block_number RETURNING row_number");
			if (!commit_multiform_row_data)
				return expects_lr<void>(layer_exception(std::move(commit_multiform_row_data.error().message())));

			auto commit_multiform_data = multiform_storage->prepare_statement(__func__, "INSERT OR REPLACE INTO multiforms (column_number, row_number, block_number, rank) VALUES (?, ?, ?, ?)");
			if (!commit_multiform_data)
				return expects_lr<void>(layer_exception(std::move(commit_multiform_data.error().message())));

			auto commit_snapshot_data = multiform_storage->prepare_statement(__func__, "INSERT OR REPLACE INTO snapshots (column_number, row_number, block_number, rank, hidden) VALUES (?, ?, ?, ?, ?)");
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
		static void finalize_checksum(ledger::authentic_serializer& message, const variant& column)
		{
			if (column.size() == sizeof(uint256_t))
				message.checksum.decode(column.get_binary());
		}
		static uptr<ledger::transition_state> state_from_blob(uint64_t block_number, uint32_t type, const std::string_view& index_or_column, const std::string_view& row_or_none, const std::string_view& optimized_blob)
		{
			auto state = uptr<ledger::transition_state>(states::resolver::from_type(type));
			if (!state)
				return nullptr;

			switch (state->as_level())
			{
				case ledger::state_level::uniform:
				{
					auto message = format::ro_stream(index_or_column);
					if (!index_or_column.empty() && !((ledger::uniform_state*)*state)->load_index(message))
						return nullptr;

					message = format::ro_stream(optimized_blob);
					if (!optimized_blob.empty() && !state->load_optimized(message))
						return nullptr;

					if (!state->block_number)
						state->block_number = block_number;

					return state;
				}
				case ledger::state_level::multiform:
				{
					auto message = format::ro_stream(index_or_column);
					if (!index_or_column.empty() && !((ledger::multiform_state*)*state)->load_column(message))
						return nullptr;

					message = format::ro_stream(row_or_none);
					if (!row_or_none.empty() && !((ledger::multiform_state*)*state)->load_row(message))
						return nullptr;

					message = format::ro_stream(optimized_blob);
					if (!optimized_blob.empty() && !state->load_optimized(message))
						return nullptr;

					if (!state->block_number)
						state->block_number = block_number;

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
		static string get_block_transaction_label(const uint8_t hash[32])
		{
			string label;
			label.resize(33);
			label.front() = BLOB_TRANSACTION;
			memcpy(label.data() + 1, hash, sizeof(uint8_t) * 32);
			return label;
		}
		static string get_uniform_label(uint32_t type, const std::string_view& index, uint64_t number)
		{
			format::wo_stream message;
			message.data.append(1, BLOB_UNIFORM);
			message.write_typeless(type);
			message.write_typeless(number);
			message.write_typeless(index.data(), index.size());
			return message.data;
		}
		static string get_multiform_label(uint32_t type, const std::string_view& column, const std::string_view& row, uint64_t number)
		{
			format::wo_stream message;
			message.data.append(1, BLOB_UNIFORM);
			message.write_typeless(type);
			message.write_typeless(number);
			message.write_typeless(column.data(), column.size());
			message.write_typeless(row.data(), row.size());
			return message.data;
		}

		string result_filter::as_value() const
		{
			uint8_t data[sizeof(value)];
			value.encode(data);
			return string((char*)data, sizeof(data));
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

		static thread_local chainstate* parent_chainstate = nullptr;
		chainstate::chainstate() noexcept
		{
			auto& uniform_types = states::resolver::get_uniform_types();
			auto& multiform_types = states::resolver::get_multiform_types();
			for (size_t i = 0; i < uniform_types.size(); i++)
				uniform_local_storage[i].type = uniform_types[i];
			for (size_t i = 0; i < multiform_types.size(); i++)
				multiform_local_storage[i].type = multiform_types[i];
#ifndef NDEBUG
			local_id = std::this_thread::get_id();
#endif
			if (!parent_chainstate)
				parent_chainstate = this;
		}
		chainstate::~chainstate() noexcept
		{
#ifndef NDEBUG
			VI_ASSERT(local_id == std::this_thread::get_id(), "mempoolstate thread must not change");
#endif
			if (parent_chainstate == this)
				parent_chainstate = nullptr;
		}
		expects_lr<void> chainstate::revert(uint64_t block_number, int64_t* block_delta, int64_t* transaction_delta, int64_t* state_delta)
		{
			auto state = get_multi_storage();
			auto begin = ledger::storage_util::multi_tx_begin(__func__, sqlite::isolation::default_isolation, state);
			if (!begin)
				return layer_exception(std::move(begin.error().message()));

			auto status = revert_internal(block_number, block_delta, transaction_delta, state_delta);
			if (!status)
			{
				ledger::storage_util::multi_tx_rollback(__func__, std::move(state)).report("state rollback failed");
				return status.error();
			}

			auto commit = ledger::storage_util::multi_tx_commit(__func__, std::move(state));
			if (!commit)
				return layer_exception(std::move(commit.error().message()));

			return expectation::met;
		}
		expects_lr<void> chainstate::revert_internal(uint64_t block_number, int64_t* block_delta, int64_t* transaction_delta, int64_t* state_delta)
		{
			schema_list map;
			map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(block_number));
			
			auto checkpoint_number = get_checkpoint_block_number();
			auto cursor = get_block_storage().emplace_query(__func__,
				"DELETE FROM blocks WHERE block_number > ? RETURNING block_hash;"
				"DELETE FROM checkpoints WHERE block_number > ?;", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto block_response = cursor->first();
			map.clear();
			map.push_back(var::set::integer(block_number));

			cursor = get_tx_storage().emplace_query(__func__, "DELETE FROM transactions WHERE block_number > ? RETURNING transaction_hash", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto transaction_response = cursor->first();
			map.clear();
			map.push_back(var::set::integer(block_number));

			cursor = get_account_storage().emplace_query(__func__, "DELETE FROM accounts WHERE block_number > ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			cursor = get_party_storage().emplace_query(__func__, "DELETE FROM parties WHERE block_number > ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			cursor = get_alias_storage().emplace_query(__func__, "DELETE FROM aliases WHERE block_number > ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			bool reorganized = false;
			if (checkpoint_number && *checkpoint_number > block_number)
			{
				auto reorganization_result = revert_reorganize_internal(block_delta, transaction_delta, state_delta);
				if (!reorganization_result)
					return reorganization_result.error();

				reorganized = true;
			}

			auto& blob_storage = get_blob_storage();
			parallel::wail_all(parallel::for_each_sequential(block_response.begin(), block_response.end(), block_response.size(), ELEMENTS_FEW, [&](sqlite::row row)
			{
				auto block_hash = row["block_hash"].get();
				blob_storage.store(__func__, get_block_label(block_hash.get_binary()), std::string_view());
			}));
			parallel::wail_all(parallel::for_each_sequential(transaction_response.begin(), transaction_response.end(), transaction_response.size(), ELEMENTS_FEW, [&](sqlite::row row)
			{
				auto transaction_hash = row["transaction_hash"].get();
				blob_storage.store(__func__, get_block_transaction_label(transaction_hash.get_binary()), std::string_view());
			}));

			if (block_delta != nullptr)
				*block_delta -= block_response.size();
			
			if (transaction_delta != nullptr)
				*transaction_delta -= transaction_response.size();

			if (reorganized)
				return expectation::met;

			for (auto& [uniform_storage, type] : get_uniform_multi_storage())
			{
				size_t offset = 0, count = ELEMENTS_HUGE;
				map.clear();
				map.push_back(var::set::integer(block_number));
				map.push_back(var::set::integer(count));
				map.push_back(var::set::integer(offset));

				while (true)
				{
					map.back()->value = var::integer(offset);
					cursor = uniform_storage.emplace_query(__func__, "SELECT (SELECT index_hash FROM indices WHERE indices.index_number = snapshots.index_number) AS index_hash, block_number FROM snapshots WHERE block_number > ? LIMIT ? OFFSET ?", &map);
					if (!cursor || cursor->error())
						return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

					auto response = cursor->first();
					parallel::wail_all(parallel::for_each_sequential(response.begin(), response.end(), response.size(), ELEMENTS_FEW, [&](sqlite::row row)
					{
						string index = row["index_hash"].get().get_blob();
						uint64_t number = row["block_number"].get().get_integer();
						blob_storage.store(__func__, get_uniform_label(type, index, number), std::string_view());
					}));

					size_t results = cursor->first().size();
					offset += results;
					if (state_delta != nullptr)
						*state_delta += results;
					if (results < count)
						break;
				}

				map.clear();
				map.push_back(var::set::integer(block_number));
				map.push_back(var::set::integer(block_number));
				map.push_back(var::set::integer(block_number));
				map.push_back(var::set::integer(block_number));

				cursor = uniform_storage.emplace_query(__func__,
					"DELETE FROM snapshots WHERE block_number > ?;"
					"DELETE FROM uniforms WHERE block_number > ?;"
					"INSERT OR REPLACE INTO uniforms (index_number, block_number) SELECT index_number, block_number FROM (SELECT index_number, hidden, MAX(block_number) AS block_number FROM snapshots WHERE block_number <= ? GROUP BY index_number) WHERE hidden = FALSE;"
					"DELETE FROM indices WHERE block_number > ?;", &map);
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));
			}

			for (auto& [multiform_storage, type] : get_multiform_multi_storage())
			{
				size_t offset = 0, count = ELEMENTS_HUGE;
				map.clear();
				map.push_back(var::set::integer(block_number));
				map.push_back(var::set::integer(count));
				map.push_back(var::set::integer(offset));

				while (true)
				{
					map.back()->value = var::integer(offset);
					cursor = multiform_storage.emplace_query(__func__, "SELECT (SELECT column_hash FROM columns WHERE columns.column_number = snapshots.column_number) AS column_hash, (SELECT row_hash FROM rows WHERE rows.row_number = snapshots.row_number) AS row_hash, block_number FROM snapshots WHERE block_number > ? LIMIT ? OFFSET ?", &map);
					if (!cursor || cursor->error())
						return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

					auto response = cursor->first();
					parallel::wail_all(parallel::for_each_sequential(response.begin(), response.end(), response.size(), ELEMENTS_FEW, [&](sqlite::row next)
					{
						string column = next["column_hash"].get().get_blob();
						string row = next["row_hash"].get().get_blob();
						uint64_t number = next["block_number"].get().get_integer();
						blob_storage.store(__func__, get_multiform_label(type, column, row, number), std::string_view());
					}));

					size_t results = cursor->first().size();
					offset += results;
					if (state_delta != nullptr)
						*state_delta += results;
					if (results < count)
						break;
				}

				map.clear();
				map.push_back(var::set::integer(block_number));
				map.push_back(var::set::integer(block_number));
				map.push_back(var::set::integer(block_number));
				map.push_back(var::set::integer(block_number));
				map.push_back(var::set::integer(block_number));

				cursor = multiform_storage.emplace_query(__func__,
					"DELETE FROM snapshots WHERE block_number > ?;"
					"DELETE FROM multiforms WHERE block_number > ?;"
					"INSERT OR REPLACE INTO multiforms (column_number, row_number, rank, block_number) SELECT column_number, row_number, rank, block_number FROM (SELECT column_number, row_number, rank, hidden, MAX(block_number) AS block_number FROM snapshots WHERE block_number <= ? GROUP BY column_number, row_number) WHERE hidden = FALSE;"
					"DELETE FROM columns WHERE block_number > ?;"
					"DELETE FROM rows WHERE block_number > ?;", &map);
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));
			}

			return expectation::met;
		}
		expects_lr<void> chainstate::revert_reorganize_internal(int64_t* block_delta, int64_t* transaction_delta, int64_t* state_delta)
		{
			auto cursor = get_block_storage().query(__func__, "DELETE FROM checkpoints");
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			for (auto& [uniform_storage, type] : get_uniform_multi_storage())
			{
				cursor = uniform_storage.query(__func__,
					"DELETE FROM snapshots;"
					"DELETE FROM uniforms;"
					"DELETE FROM indices;");
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));
			}

			for (auto& [multiform_storage, type] : get_multiform_multi_storage())
			{
				cursor = multiform_storage.query(__func__,
					"DELETE FROM snapshots;"
					"DELETE FROM multiforms;"
					"DELETE FROM columns;"
					"DELETE FROM rows;");
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));
			}

			auto& blob_storage = get_blob_storage();
			blob_storage.clear(__func__, string(1, BLOB_UNIFORM));
			blob_storage.clear(__func__, string(1, BLOB_MULTIFORM));

			uint64_t current_number = 1;
			uint64_t checkpoint_number = get_checkpoint_block_number().or_else(0);
			uint64_t tip_number = get_latest_block_number().or_else(0);
			auto solver = ledger::solver_context();
			auto parent_block = expects_lr<ledger::block_header>(layer_exception());
			while (current_number <= tip_number)
			{
				auto candidate_block = get_block_by_number(current_number);
				if (!candidate_block)
					return layer_exception("block " + to_string(current_number) + (checkpoint_number >= current_number ? " reorganization failed: block data pruned" : " reorganization failed: block not found"));
				else if (current_number > 1 && checkpoint_number >= current_number - 1 && !parent_block)
					return layer_exception("block " + to_string(current_number - 1) + " reorganization failed: parent block data pruned");

				ledger::block_evaluation evaluation;
				auto validation = ledger::solver_context::validate_solved_block(solver, parent_block.address(), *candidate_block, &evaluation);
				if (!validation)
					return layer_exception("block " + to_string(current_number) + " validation failed: " + validation.error().message());

				auto finalization = checkpoint_internal(evaluation, true, &checkpoint_number);
				if (!finalization)
					return layer_exception("block " + to_string(current_number) + " checkpoint failed: " + finalization.error().message());

				if (protocol::now().user.storage.logging)
					VI_INFO("block %s re-executed (number: %" PRIu64 ", tape: %.2f%%)", algorithm::encoding::encode_0xhex256(candidate_block->as_hash()).c_str(), current_number, 100.0 * (double)current_number / tip_number);

				parent_block = evaluation.block;
				++current_number;
				if (block_delta != nullptr)
					++(*block_delta);
				if (transaction_delta != nullptr)
					*transaction_delta += evaluation.block.transaction_count;
				if (state_delta != nullptr)
					*state_delta += evaluation.block.transition_count;
			}

			return expectation::met;
		}
		expects_lr<void> chainstate::checkpoint(const ledger::block_evaluation& evaluation, bool reorganization, uint64_t* checkpoint_block_number)
		{
			auto state = get_multi_storage();
			auto begin = ledger::storage_util::multi_tx_begin(__func__, sqlite::isolation::default_isolation, state);
			if (!begin)
				return layer_exception(std::move(begin.error().message()));

			auto status = checkpoint_internal(evaluation, reorganization, checkpoint_block_number);
			if (!status)
			{
				ledger::storage_util::multi_tx_rollback(__func__, std::move(state)).report("state rollback failed");
				return status.error();
			}

			auto commit = ledger::storage_util::multi_tx_commit(__func__, std::move(state));
			if (!commit)
				return layer_exception(std::move(commit.error().message()));

			return expectation::met;
		}
		expects_lr<void> chainstate::checkpoint_internal(const ledger::block_evaluation& evaluation, bool reorganization, uint64_t* checkpoint_block_number)
		{
			auto fetch_transaction_nonce = reorganization ? sqlite::expects_db<sqlite::tstatement*>(nullptr) : get_tx_storage().prepare_statement(__func__, "SELECT MAX(transaction_number) AS counter FROM transactions");
			if (!fetch_transaction_nonce)
				return expects_lr<void>(layer_exception(std::move(fetch_transaction_nonce.error().message())));

			auto commit_transaction_data = reorganization ? sqlite::expects_db<sqlite::tstatement*>(nullptr) : get_tx_storage().prepare_statement(__func__, "INSERT INTO transactions (transaction_number, transaction_hash, dispatch_queue, block_number, block_nonce) VALUES (?, ?, ?, ?, ?)");
			if (!commit_transaction_data)
				return expects_lr<void>(layer_exception(std::move(commit_transaction_data.error().message())));

			auto commit_account_data = reorganization ? sqlite::expects_db<sqlite::tstatement*>(nullptr) : get_account_storage().prepare_statement(__func__, "INSERT OR IGNORE INTO accounts (account_number, account_hash, block_number) SELECT (SELECT COALESCE(MAX(account_number), 0) + 1 FROM accounts), ?, ? ON CONFLICT DO UPDATE SET block_number = block_number RETURNING account_number");
			if (!commit_account_data)
				return expects_lr<void>(layer_exception(std::move(commit_account_data.error().message())));

			auto commit_party_data = reorganization ? sqlite::expects_db<sqlite::tstatement*>(nullptr) : get_party_storage().prepare_statement(__func__, "INSERT OR IGNORE INTO parties (transaction_number, transaction_account_number, block_number) VALUES (?, ?, ?)");
			if (!commit_party_data)
				return expects_lr<void>(layer_exception(std::move(commit_party_data.error().message())));

			auto commit_alias_data = reorganization ? sqlite::expects_db<sqlite::tstatement*>(nullptr) : get_alias_storage().prepare_statement(__func__, "INSERT INTO aliases (transaction_number, transaction_hash, block_number) VALUES (?, ?, ?)");
			if (!commit_alias_data)
				return expects_lr<void>(layer_exception(std::move(commit_alias_data.error().message())));

			hash_map<uint32_t, uniform_writer> uniform_writers;
			for (auto& [uniform_storage, type] : get_uniform_multi_storage())
			{
				vector<uniform_blob> blobs;
				blobs.reserve(evaluation.state.size());
				for (auto& [index, change] : evaluation.state)
				{
					if (change.state->as_level() == ledger::state_level::uniform && change.state->as_type() == type)
					{
						uniform_blob blob;
						blob.context = (ledger::uniform_state*)*change.state;
						blob.change = &change;
						blobs.emplace_back(std::move(blob));
					}
				}

				if (blobs.empty())
					continue;

				auto erase_uniform_data = uniform_storage.prepare_statement(__func__, "DELETE FROM uniforms WHERE index_number = ?");
				if (!erase_uniform_data)
					return expects_lr<void>(layer_exception(std::move(erase_uniform_data.error().message())));

				auto commit_uniform_index_data = uniform_storage.prepare_statement(__func__, "INSERT OR IGNORE INTO indices (index_number, index_hash, block_number) SELECT (SELECT COALESCE(MAX(index_number), 0) + 1 FROM indices), ?, ? ON CONFLICT DO UPDATE SET block_number = block_number RETURNING index_number");
				if (!commit_uniform_index_data)
					return expects_lr<void>(layer_exception(std::move(commit_uniform_index_data.error().message())));

				auto commit_uniform_data = uniform_storage.prepare_statement(__func__, "INSERT OR REPLACE INTO uniforms (index_number, block_number) VALUES (?, ?)");
				if (!commit_uniform_data)
					return expects_lr<void>(layer_exception(std::move(commit_uniform_data.error().message())));

				auto commit_snapshot_data = uniform_storage.prepare_statement(__func__, "INSERT OR REPLACE INTO snapshots (index_number, block_number, hidden) VALUES (?, ?, ?)");
				if (!commit_snapshot_data)
					return expects_lr<void>(layer_exception(std::move(commit_snapshot_data.error().message())));

				uniform_writer& writer = uniform_writers[type];
				writer.erase_uniform_data = *erase_uniform_data;
				writer.commit_uniform_index_data = *commit_uniform_index_data;
				writer.commit_uniform_data = *commit_uniform_data;
				writer.commit_snapshot_data = *commit_snapshot_data;
				writer.storage = &uniform_storage;
				writer.blobs = std::move(blobs);
			}

			hash_map<uint32_t, multiform_writer> multiform_writers;
			for (auto& [multiform_storage, type] : get_multiform_multi_storage())
			{
				vector<multiform_blob> blobs;
				fill_multiform_writer_from_block_state(&blobs, type, evaluation.state);
				if (blobs.empty())
					continue;

				multiform_writer& writer = multiform_writers[type];
				writer.blobs = std::move(blobs);

				auto status = fill_multiform_writer_from_storage(&writer, &multiform_storage);
				if (!status)
					return status;
			}

			uint8_t hash[32];
			auto& blob_storage = get_blob_storage();
			auto expectation_queue = vector<promise<expects_lr<void>>>();
			expectation_queue.reserve(10 + uniform_writers.size() * 2 + multiform_writers.size() * 2);
			if (!reorganization)
			{
				evaluation.block.as_hash().encode(hash);
				expectation_queue.push_back(cotask<expects_lr<void>>([&]()
				{
					format::wo_stream block_header_message;
					if (!evaluation.block.as_header().store(&block_header_message))
						return expects_lr<void>(layer_exception("block header serialization error"));

					auto status = blob_storage.store(__func__, get_block_label(hash), block_header_message.data);
					if (!status)
						return expects_lr<void>(layer_exception(ledger::storage_util::error_of(status)));

					return expects_lr<void>(expectation::met);
				}));
				expectation_queue.push_back(cotask<expects_lr<void>>([&]()
				{
					auto& block_storage = get_block_storage();
					auto commit_block_data = block_storage.prepare_statement(__func__, "INSERT INTO blocks (block_number, block_hash) VALUES (?, ?)");
					if (!commit_block_data)
						return expects_lr<void>(layer_exception(std::move(commit_block_data.error().message())));

					block_storage.ptr()->bind_int64(*commit_block_data, 0, evaluation.block.number);
					block_storage.ptr()->bind_blob(*commit_block_data, 1, std::string_view((char*)hash, sizeof(hash)));

					auto cursor = block_storage.prepared_query(__func__, *commit_block_data);
					if (!cursor || cursor->error())
						return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

					return expects_lr<void>(expectation::met);
				}));
			}

			vector<promise<void>> queue;
			vector<transaction_blob> transactions;
			size_t concurrency = std::max<size_t>(1, parallel::get_threads());
			bool transaction_to_account_index = protocol::now().user.storage.transaction_to_account_index;
			bool transaction_to_alias_index = protocol::now().user.storage.transaction_to_alias_index;
			if (!reorganization)
			{
				auto cursor = get_tx_storage().prepared_query(__func__, *fetch_transaction_nonce);
				if (!cursor || cursor->error_or_empty())
					return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

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
					item.message.data.reserve(1024);
					item.context->store(&item.message);
					item.dispatchable = item.context->receipt.successful && item.context->transaction->as_delegation_type() > 0;
					item.context->receipt.transaction_hash.encode(item.transaction_hash);
					if (transaction_to_account_index)
					{
						auto executor = ledger::executor_context(nullptr);
						item.context->transaction->recover_many(&executor, item.context->receipt, item.parties);
						item.parties.insert(algorithm::pubkeyhash_t(item.context->receipt.from));
					}
					if (transaction_to_alias_index)
					{
						btree_set<uint256_t> aliases;
						item.context->transaction->recover_aliases(aliases);
						item.aliases.reserve(aliases.size());
						if (!aliases.empty())
						{
							transaction_alias_blob alias;
							for (auto& hash : aliases)
							{
								hash.encode(alias.transaction_hash);
								item.aliases.push_back(alias);
							}
						}
					}
				}))
					queue.emplace_back(std::move(task));
			}

			for (auto& [type, writer] : uniform_writers)
			{
				vector<state_result> state_cache(concurrency);
				for (auto& task : parallel::for_each(writer.blobs.begin(), writer.blobs.end(), ELEMENTS_FEW, [&](uniform_blob& item)
				{
					item.index = item.context->as_index();
					item.context->store_optimized(&item.message);
				}))
					queue.emplace_back(std::move(task));
			}

			for (auto& [type, writer] : multiform_writers)
			{
				vector<state_result> state_cache(concurrency);
				for (auto& task : parallel::for_each(writer.blobs.begin(), writer.blobs.end(), ELEMENTS_FEW, [&](multiform_blob& item)
				{
					item.column = item.context->as_column();
					item.row = item.context->as_row();
					item.context->store_optimized(&item.message);
					item.context->as_rank().encode(item.rank);
				}))
					queue.emplace_back(std::move(task));
			}

			parallel::wail_all(std::move(queue));
			bool must_write_transaction_data = !reorganization;
			for (auto& [type, writer] : uniform_writers)
			{
				expectation_queue.emplace_back(cotask<expects_lr<void>>([&]() -> expects_lr<void>
				{
					sqlite::expects_db<sqlite::cursor> cursor = sqlite::database_exception(string());
					auto* storage_ptr = writer.storage->ptr();
					for (auto& item : writer.blobs)
					{
						auto* statement = writer.commit_uniform_index_data;
						storage_ptr->bind_blob(statement, 0, item.index);
						storage_ptr->bind_int64(statement, 1, evaluation.block.number);

						cursor = writer.storage->prepared_query(__func__, statement);
						if (!cursor || cursor->error_or_empty())
							return layer_exception(cursor->empty() ? "uniform state index not linked" : ledger::storage_util::error_of(cursor));

						uint64_t index_number = cursor->first().front().get_column(0).get().get_integer();
						if (item.change->erase)
						{
							statement = writer.erase_uniform_data;
							storage_ptr->bind_int64(statement, 0, index_number);
						}
						else
						{
							statement = writer.commit_uniform_data;
							storage_ptr->bind_int64(statement, 0, index_number);
							storage_ptr->bind_int64(statement, 1, evaluation.block.number);
						}

						cursor = writer.storage->prepared_query(__func__, statement);
						if (!cursor || cursor->error())
							return layer_exception(ledger::storage_util::error_of(cursor));

						statement = writer.commit_snapshot_data;
						storage_ptr->bind_int64(statement, 0, index_number);
						storage_ptr->bind_int64(statement, 1, evaluation.block.number);
						storage_ptr->bind_boolean(statement, 2, item.change->erase);

						cursor = writer.storage->prepared_query(__func__, statement);
						if (!cursor || cursor->error())
							return layer_exception(ledger::storage_util::error_of(cursor));
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

						status = blob_storage.store(__func__, get_uniform_label(type, item.index, evaluation.block.number), item.message.data);
						if (!status)
							return layer_exception(ledger::storage_util::error_of(status));
					}
					return expectation::met;
				}, false));
			}
			for (auto& [type, writer] : multiform_writers)
			{
				expectation_queue.emplace_back(cotask<expects_lr<void>>([&]() -> expects_lr<void>
				{
					sqlite::expects_db<sqlite::cursor> cursor = sqlite::database_exception(string());
					auto* storage_ptr = writer.storage->ptr();
					for (auto& item : writer.blobs)
					{
						auto* statement = writer.commit_multiform_column_data;
						storage_ptr->bind_blob(statement, 0, item.column);
						storage_ptr->bind_int64(statement, 1, evaluation.block.number);

						cursor = writer.storage->prepared_query(__func__, statement);
						if (!cursor || cursor->error_or_empty())
							return layer_exception(cursor->empty() ? "multiform state column not linked" : ledger::storage_util::error_of(cursor));

						statement = writer.commit_multiform_row_data;
						storage_ptr->bind_blob(statement, 0, item.row);
						storage_ptr->bind_int64(statement, 1, evaluation.block.number);

						uint64_t column_number = cursor->first().front().get_column(0).get().get_integer();
						cursor = writer.storage->prepared_query(__func__, statement);
						if (!cursor || cursor->error_or_empty())
							return layer_exception(cursor->empty() ? "multiform state row not linked" : ledger::storage_util::error_of(cursor));

						uint64_t row_number = cursor->first().front().get_column(0).get().get_integer();
						if (item.change->erase)
						{
							statement = writer.erase_multiform_data;
							storage_ptr->bind_int64(statement, 0, column_number);
							storage_ptr->bind_int64(statement, 1, row_number);
						}
						else
						{
							statement = writer.commit_multiform_data;
							storage_ptr->bind_int64(statement, 0, column_number);
							storage_ptr->bind_int64(statement, 1, row_number);
							storage_ptr->bind_int64(statement, 2, evaluation.block.number);
							storage_ptr->bind_blob(statement, 3, std::string_view((char*)item.rank, sizeof(item.rank)));
						}

						cursor = writer.storage->prepared_query(__func__, statement);
						if (!cursor || cursor->error())
							return layer_exception(ledger::storage_util::error_of(cursor));

						statement = writer.commit_snapshot_data;
						storage_ptr->bind_int64(statement, 0, column_number);
						storage_ptr->bind_int64(statement, 1, row_number);
						storage_ptr->bind_int64(statement, 2, evaluation.block.number);
						storage_ptr->bind_blob(statement, 3, std::string_view((char*)item.rank, sizeof(item.rank)));
						storage_ptr->bind_boolean(statement, 4, item.change->erase);

						cursor = writer.storage->prepared_query(__func__, statement);
						if (!cursor || cursor->error())
							return layer_exception(ledger::storage_util::error_of(cursor));
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

						status = blob_storage.store(__func__, get_multiform_label(type, item.column, item.row, evaluation.block.number), item.message.data);
						if (!status)
							return layer_exception(ledger::storage_util::error_of(status));
					}
					return expectation::met;
				}, false));
			}
			if (must_write_transaction_data)
			{
				expectation_queue.emplace_back(cotask<expects_lr<void>>([this, &transactions, &evaluation, &commit_transaction_data]() -> expects_lr<void>
				{
					auto& tx_storage = get_tx_storage();
					auto* tx_storage_ptr = tx_storage.ptr();
					auto* statement = *commit_transaction_data;
					sqlite::expects_db<sqlite::cursor> cursor = sqlite::database_exception(string());
					for (auto& data : transactions)
					{
						tx_storage_ptr->bind_int64(statement, 0, data.transaction_number);
						tx_storage_ptr->bind_blob(statement, 1, std::string_view((char*)data.transaction_hash, sizeof(data.transaction_hash)));
						if (data.dispatchable)
							tx_storage_ptr->bind_int64(statement, 2, evaluation.block.number);
						else
							tx_storage_ptr->bind_null(statement, 2);
						tx_storage_ptr->bind_int64(statement, 3, evaluation.block.number);
						tx_storage_ptr->bind_int64(statement, 4, data.block_nonce);

						cursor = tx_storage.prepared_query(__func__, statement);
						if (!cursor || cursor->error())
							return layer_exception(ledger::storage_util::error_of(cursor));
					}
					return expectation::met;
				}, false));
				expectation_queue.emplace_back(cotask<expects_lr<void>>([this, &transactions, &evaluation, transaction_to_account_index, &commit_account_data, &commit_party_data]() -> expects_lr<void>
				{
					if (!transaction_to_account_index)
						return expectation::met;

					auto& account_storage = get_account_storage();
					auto* account_storage_ptr = account_storage.ptr();
					auto& party_storage = get_party_storage();
					auto* party_storage_ptr = party_storage.ptr();
					sqlite::expects_db<sqlite::cursor> cursor = sqlite::database_exception(string());
					for (auto& data : transactions)
					{
						for (auto& party : data.parties)
						{
							auto* statement = *commit_account_data;
							account_storage_ptr->bind_blob(statement, 0, party.view());
							account_storage_ptr->bind_int64(statement, 1, evaluation.block.number);

							cursor = account_storage.prepared_query(__func__, statement);
							if (!cursor || cursor->error_or_empty())
								return layer_exception(cursor->empty() ? "account not linked" : ledger::storage_util::error_of(cursor));

							uint64_t account_number = cursor->first().front().get_column(0).get().get_integer();
							statement = *commit_party_data;
							party_storage_ptr->bind_int64(statement, 0, data.transaction_number);
							party_storage_ptr->bind_int64(statement, 1, account_number);
							party_storage_ptr->bind_int64(statement, 2, evaluation.block.number);

							cursor = party_storage.prepared_query(__func__, statement);
							if (!cursor || cursor->error())
								return layer_exception(ledger::storage_util::error_of(cursor));
						}
					}
					return expectation::met;
				}, false));
				expectation_queue.emplace_back(cotask<expects_lr<void>>([this, &transactions, &evaluation, transaction_to_alias_index, &commit_alias_data]() -> expects_lr<void>
				{
					if (!transaction_to_alias_index)
						return expectation::met;

					auto& alias_storage = get_alias_storage();
					auto* alias_storage_ptr = alias_storage.ptr();
					auto* statement = *commit_alias_data;
					sqlite::expects_db<sqlite::cursor> cursor = sqlite::database_exception(string());
					for (auto& data : transactions)
					{
						for (auto& alias : data.aliases)
						{
							alias_storage_ptr->bind_int64(statement, 0, data.transaction_number);
							alias_storage_ptr->bind_blob(statement, 1, std::string_view((char*)alias.transaction_hash, sizeof(alias.transaction_hash)));
							alias_storage_ptr->bind_int64(statement, 2, evaluation.block.number);

							cursor = alias_storage.prepared_query(__func__, statement);
							if (!cursor || cursor->error())
								return layer_exception(ledger::storage_util::error_of(cursor));
						}
					}
					return expectation::met;
				}, false));
				expectation_queue.emplace_back(cotask<expects_lr<void>>([&transactions, &blob_storage]() -> expects_lr<void>
				{
					sqlite::expects_db<void> status = expectation::met;
					for (auto& data : transactions)
					{
						status = blob_storage.store(__func__, get_block_transaction_label(data.transaction_hash), data.message.data);
						if (!status)
							return layer_exception(ledger::storage_util::error_of(status));
					}
					return expectation::met;
				}, false));
			}

			for (auto& status : parallel::inline_wait_all(std::move(expectation_queue)))
			{
				if (!status)
					return status;
			}

			if (evaluation.block.priority > 0)
				return expectation::met;

			auto compaction = compact_internal(evaluation.block.number, checkpoint_block_number);
			if (!compaction)
				return compaction.error();

			return expectation::met;
		}
		expects_lr<bool> chainstate::compact(uint64_t block_number, uint64_t* checkpoint_block_number)
		{
			auto state = get_multi_storage();
			auto begin = ledger::storage_util::multi_tx_begin(__func__, sqlite::isolation::default_isolation, state);
			if (!begin)
				return layer_exception(std::move(begin.error().message()));

			auto status = compact_internal(block_number, checkpoint_block_number);
			if (!status)
			{
				ledger::storage_util::multi_tx_rollback(__func__, std::move(state)).report("state rollback failed");
				return status.error();
			}

			auto commit = ledger::storage_util::multi_tx_commit(__func__, std::move(state));
			if (!commit)
				return layer_exception(std::move(commit.error().message()));

			return status;
		}
		expects_lr<bool> chainstate::compact_internal(uint64_t block_number, uint64_t* cached_checkpoint_block_number)
		{
			auto checkpoint_size = protocol::now().user.storage.checkpoint_size;
			if (!checkpoint_size)
				return expects_lr<bool>(false);

			auto checkpoint_number = block_number - block_number % checkpoint_size;
			if (checkpoint_number < block_number || block_number < checkpoint_size * 2)
				return expects_lr<bool>(false);

			uint64_t checkpoint_block_number = cached_checkpoint_block_number ? *cached_checkpoint_block_number : 0;
			if (checkpoint_block_number)
			{
				checkpoint_block_number = get_checkpoint_block_number().or_else(0);
				if (cached_checkpoint_block_number)
					*cached_checkpoint_block_number = checkpoint_block_number;
			}

			if (block_number <= checkpoint_block_number)
				return expects_lr<bool>(false);

			auto& blob_storage = get_blob_storage();
			uint64_t state_delta = 0;
			uint64_t compaction_block_number = block_number - checkpoint_size;
			for (auto& [uniform_storage, type] : get_uniform_multi_storage())
			{
				auto fetch_state = uniform_storage.prepare_statement(__func__,
					"SELECT (SELECT index_hash FROM indices WHERE indices.index_number = snapshots.index_number) AS index_hash, block_number "
					"FROM snapshots WHERE block_number < ? AND EXISTS (SELECT 1 FROM uniforms WHERE uniforms.index_number = snapshots.index_number AND uniforms.block_number > snapshots.block_number) LIMIT ? OFFSET ?");
				if (!fetch_state)
					return expects_lr<bool>(layer_exception(std::move(fetch_state.error().message())));

				auto prune_state = uniform_storage.prepare_statement(__func__, "DELETE FROM snapshots WHERE block_number < ? AND EXISTS (SELECT 1 FROM uniforms WHERE uniforms.index_number = snapshots.index_number AND uniforms.block_number > snapshots.block_number)");
				if (!prune_state)
					return expects_lr<bool>(layer_exception(std::move(prune_state.error().message())));

				size_t offset = 0, count = ELEMENTS_HUGE;
				uniform_storage.ptr()->bind_int64(*fetch_state, 0, compaction_block_number);
				uniform_storage.ptr()->bind_int64(*fetch_state, 1, count);
				while (true)
				{
					uniform_storage.ptr()->bind_int64(*fetch_state, 2, offset);
					auto cursor = uniform_storage.prepared_query(__func__, *fetch_state);
					if (!cursor || cursor->error())
						return expects_lr<bool>(layer_exception(ledger::storage_util::error_of(cursor)));

					auto response = cursor->first();
					parallel::wail_all(parallel::for_each_sequential(response.begin(), response.end(), response.size(), ELEMENTS_FEW, [&](sqlite::row row)
					{
						string index = row["index_hash"].get().get_blob();
						uint64_t number = row["block_number"].get().get_integer();
						blob_storage.store(__func__, get_uniform_label(type, index, number), std::string_view());
					}));

					size_t results = cursor->first().size();
					offset += results;
					state_delta += results;
					if (results < count)
						break;
				}

				uniform_storage.ptr()->bind_int64(*prune_state, 0, compaction_block_number);
				auto cursor = uniform_storage.prepared_query(__func__, *prune_state);
				if (!cursor || cursor->error())
					return expects_lr<bool>(layer_exception(ledger::storage_util::error_of(cursor)));
			}

			for (auto& [multiform_storage, type] : get_multiform_multi_storage())
			{
				auto fetch_state = multiform_storage.prepare_statement(__func__,
					"SELECT (SELECT column_hash FROM columns WHERE columns.column_number = snapshots.column_number) AS column_hash, (SELECT row_hash FROM rows WHERE rows.row_number = snapshots.row_number) AS row_hash, block_number "
					"FROM snapshots WHERE block_number < ? AND EXISTS (SELECT 1 FROM multiforms WHERE multiforms.column_number = snapshots.column_number AND multiforms.row_number = snapshots.row_number AND multiforms.block_number > snapshots.block_number) LIMIT ? OFFSET ?");
				if (!fetch_state)
					return expects_lr<bool>(layer_exception(std::move(fetch_state.error().message())));

				auto prune_state = multiform_storage.prepare_statement(__func__, "DELETE FROM snapshots WHERE block_number < ? AND EXISTS (SELECT 1 FROM multiforms WHERE multiforms.column_number = snapshots.column_number AND multiforms.row_number = snapshots.row_number AND multiforms.block_number > snapshots.block_number)");
				if (!prune_state)
					return expects_lr<bool>(layer_exception(std::move(prune_state.error().message())));

				size_t offset = 0, count = ELEMENTS_HUGE;
				multiform_storage.ptr()->bind_int64(*fetch_state, 0, compaction_block_number);
				multiform_storage.ptr()->bind_int64(*fetch_state, 1, count);
				while (true)
				{
					multiform_storage.ptr()->bind_int64(*fetch_state, 2, offset);
					auto cursor = multiform_storage.prepared_query(__func__, *fetch_state);
					if (!cursor || cursor->error())
						return expects_lr<bool>(layer_exception(ledger::storage_util::error_of(cursor)));

					auto response = cursor->first();
					parallel::wail_all(parallel::for_each_sequential(response.begin(), response.end(), response.size(), ELEMENTS_FEW, [&](sqlite::row next)
					{
						string column = next["column_hash"].get().get_blob();
						string row = next["row_hash"].get().get_blob();
						uint64_t number = next["block_number"].get().get_integer();
						blob_storage.store(__func__, get_multiform_label(type, column, row, number), std::string_view());
					}));

					size_t results = cursor->first().size();
					offset += results;
					state_delta += results;
					if (results < count)
						break;
				}

				multiform_storage.ptr()->bind_int64(*prune_state, 0, compaction_block_number);
				auto cursor = multiform_storage.prepared_query(__func__, *prune_state);
				if (!cursor || cursor->error())
					return expects_lr<bool>(layer_exception(ledger::storage_util::error_of(cursor)));
			}

			auto& block_storage = get_block_storage();
			auto commit_checkpoint = block_storage.prepare_statement(__func__, "INSERT OR IGNORE INTO checkpoints (block_number) VALUES (?)");
			if (!commit_checkpoint)
				return expects_lr<bool>(layer_exception(std::move(commit_checkpoint.error().message())));

			block_storage.ptr()->bind_int64(*commit_checkpoint, 0, compaction_block_number);
			auto cursor = block_storage.prepared_query(__func__, *commit_checkpoint);
			if (!cursor || cursor->error())
				return expects_lr<bool>(layer_exception(ledger::storage_util::error_of(cursor)));

			if (protocol::now().user.storage.logging)
				VI_INFO("state compaction checkpoint %" PRIu64 " (state_delta: -%" PRIu64 ")", compaction_block_number, state_delta);

			if (cached_checkpoint_block_number)
				*cached_checkpoint_block_number = compaction_block_number;

			return expects_lr<bool>(true);
		}
		expects_lr<void> chainstate::dispatch(const uint256_t& transaction_hash, uint64_t retry_after_block_number_or_zero)
		{
			uint8_t hash[32];
			transaction_hash.encode(hash);

			schema_list map;
			if (retry_after_block_number_or_zero > 0)
				map.push_back(var::set::integer(retry_after_block_number_or_zero));
			map.push_back(var::set::binary(hash, sizeof(hash)));

			auto cursor = get_tx_storage().emplace_query(__func__, stringify::text("UPDATE transactions SET dispatch_queue = %s WHERE transaction_hash = ?", retry_after_block_number_or_zero > 0 ? "?" : "NULL"), &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> chainstate::resolve_block_transactions(vector<ledger::block_transaction>& result, uint64_t block_number, size_t chunk)
		{
			auto& blob_storage = get_blob_storage();
			auto& tx_storage = get_tx_storage();
			auto find_transactions = tx_storage.prepare_statement(__func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce LIMIT ? OFFSET ?");
			if (!find_transactions)
				return expects_lr<void>(layer_exception(std::move(find_transactions.error().message())));

			size_t offset = 0;
			tx_storage.ptr()->bind_int64(*find_transactions, 0, block_number);
			tx_storage.ptr()->bind_int64(*find_transactions, 1, chunk);
			while (true)
			{
				tx_storage.ptr()->bind_int64(*find_transactions, 2, offset);
				auto cursor = get_tx_storage().prepared_query(__func__, *find_transactions);
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

				auto& response = cursor->first();
				size_t size = response.size();
				if (!size)
					break;

				size_t stride = result.size();
				result.resize(result.size() + size);
				parallel::wail_all(parallel::for_loop(size, ELEMENTS_FEW, [&](size_t i)
				{
					auto transaction_hash = response[i]["transaction_hash"].get();
					auto transaction_blob = blob_storage.load(__func__, get_block_transaction_label(transaction_hash.get_binary())).or_else(string());
					auto transaction_message = format::ro_stream(transaction_blob);
					auto& next = result[i + stride];
					if (next.load(transaction_message))
						finalize_checksum(**next.transaction, transaction_hash);
				}));

				offset += size;
				if (size < chunk)
					break;
			}

			result.erase(std::remove_if(result.begin(), result.end(), [](const ledger::block_transaction& a) { return !a.transaction; }), result.end());
			return expectation::met;
		}
		expects_lr<uint64_t> chainstate::resolve_uniform_location(uint32_t type, const std::string_view& index)
		{
			auto& uniform_storage = get_uniform_storage(type);
			auto find_index = uniform_storage.prepare_statement(__func__, "SELECT index_number FROM indices WHERE index_hash = ?");
			if (!find_index)
				return expects_lr<uint64_t>(layer_exception(std::move(find_index.error().message())));

			uniform_storage.ptr()->bind_blob(*find_index, 0, index);
			auto cursor = uniform_storage.prepared_query(__func__, *find_index);
			if (!cursor || cursor->error())
				return expects_lr<uint64_t>(layer_exception(ledger::storage_util::error_of(cursor)));

			uint64_t index_location = (*cursor)["index_number"].get().get_integer();
			if (!index_location)
				return layer_exception("uniform state index not found");

			return index_location;
		}
		expects_lr<chainstate::multiform_location> chainstate::resolve_multiform_location(uint32_t type, const option<std::string_view>& column, const option<std::string_view>& row)
		{
			VI_ASSERT(column || row, "column or row should be set");
			uint64_t column_location = 0, row_location = 0;
			if (!column || !row)
			{
				if (column)
				{
					auto& multiform_storage = get_multiform_storage(type);
					auto find_column = multiform_storage.prepare_statement(__func__, "SELECT column_number FROM columns WHERE column_hash = ?");
					if (!find_column)
						return expects_lr<multiform_location>(layer_exception(std::move(find_column.error().message())));

					multiform_storage.ptr()->bind_blob(*find_column, 0, *column);
					auto cursor = multiform_storage.prepared_query(__func__, *find_column);
					if (!cursor || cursor->error())
						return expects_lr<multiform_location>(layer_exception(ledger::storage_util::error_of(cursor)));

					column_location = (*cursor)["column_number"].get().get_integer();
					if (!column_location)
						return layer_exception("multiform state column not found");
				}

				if (row)
				{
					auto& multiform_storage = get_multiform_storage(type);
					auto find_row = multiform_storage.prepare_statement(__func__, "SELECT row_number FROM rows WHERE row_hash = ?");
					if (!find_row)
						return expects_lr<multiform_location>(layer_exception(std::move(find_row.error().message())));

					multiform_storage.ptr()->bind_blob(*find_row, 0, *row);
					auto cursor = multiform_storage.prepared_query(__func__, *find_row);
					if (!cursor || cursor->error())
						return expects_lr<multiform_location>(layer_exception(ledger::storage_util::error_of(cursor)));

					row_location = (*cursor)["row_number"].get().get_integer();
					if (!row_location)
						return layer_exception("multiform state row not found");
				}
			}
			else
			{
				auto& multiform_storage = get_multiform_storage(type);
				auto find_column_and_row = multiform_storage.prepare_statement(__func__, "SELECT (SELECT column_number FROM columns WHERE column_hash = ?) AS column_number, (SELECT row_number FROM rows WHERE row_hash = ?) AS row_number");
				if (!find_column_and_row)
					return expects_lr<multiform_location>(layer_exception(std::move(find_column_and_row.error().message())));

				multiform_storage.ptr()->bind_blob(*find_column_and_row, 0, *column);
				multiform_storage.ptr()->bind_blob(*find_column_and_row, 1, *row);
				auto cursor = multiform_storage.prepared_query(__func__, *find_column_and_row);
				if (!cursor || cursor->error())
					return expects_lr<multiform_location>(layer_exception(ledger::storage_util::error_of(cursor)));

				column_location = (*cursor)["column_number"].get().get_integer();
				row_location = (*cursor)["row_number"].get().get_integer();
				if (!column_location || !row_location)
					return layer_exception("multiform state column not found");
			}

			multiform_location location;
			location.column = column_location > 0 ? std::move(column_location) : option<uint64_t>(optional::none);
			location.row = row_location > 0 ? std::move(row_location) : option<uint64_t>(optional::none);
			return location;
		}
		expects_lr<uint64_t> chainstate::resolve_account_location(const algorithm::pubkeyhash_t& account)
		{
			auto& account_storage = get_account_storage();
			auto find_account = account_storage.prepare_statement(__func__, "SELECT account_number FROM accounts WHERE account_hash = ?");
			if (!find_account)
				return expects_lr<uint64_t>(layer_exception(std::move(find_account.error().message())));

			account_storage.ptr()->bind_blob(*find_account, 0, account.view());
			auto cursor = get_account_storage().prepared_query(__func__, *find_account);
			if (!cursor || cursor->error())
				return expects_lr<uint64_t>(layer_exception(ledger::storage_util::error_of(cursor)));

			uint64_t account_number = (*cursor)["account_number"].get().get_integer();
			if (!account_number)
				return layer_exception("account not found");
			
			return account_number;
		}
		expects_lr<uint64_t> chainstate::get_checkpoint_block_number()
		{
			auto& block_storage = get_block_storage();
			auto fetch_checkpoint_block_number = block_storage.prepare_statement(__func__, "SELECT MAX(block_number) AS block_number FROM checkpoints");
			if (!fetch_checkpoint_block_number)
				return expects_lr<uint64_t>(layer_exception(std::move(fetch_checkpoint_block_number.error().message())));

			auto cursor = block_storage.prepared_query(__func__, *fetch_checkpoint_block_number);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<uint64_t>(layer_exception(ledger::storage_util::error_of(cursor)));

			return (uint64_t)(*cursor)["block_number"].get().get_integer();
		}
		expects_lr<uint64_t> chainstate::get_latest_block_number()
		{
			auto& block_storage = get_block_storage();
			auto fetch_latest_block_number = block_storage.prepare_statement(__func__, "SELECT MAX(block_number) AS block_number FROM blocks");
			if (!fetch_latest_block_number)
				return expects_lr<uint64_t>(layer_exception(std::move(fetch_latest_block_number.error().message())));

			auto cursor = block_storage.prepared_query(__func__, *fetch_latest_block_number);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<uint64_t>(layer_exception(ledger::storage_util::error_of(cursor)));

			uint64_t block_number = (*cursor)["block_number"].get().get_integer();
			return block_number;
		}
		expects_lr<uint64_t> chainstate::get_block_number_by_hash(const uint256_t& block_hash)
		{
			uint8_t hash[32];
			block_hash.encode(hash);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));

			auto cursor = get_block_storage().emplace_query(__func__, "SELECT block_number FROM blocks WHERE block_hash = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<uint64_t>(layer_exception(ledger::storage_util::error_of(cursor)));

			return (uint64_t)(*cursor)["block_number"].get().get_integer();
		}
		expects_lr<uint256_t> chainstate::get_block_hash_by_number(uint64_t block_number)
		{
			schema_list map;
			map.push_back(var::set::integer(block_number));

			auto cursor = get_block_storage().emplace_query(__func__, "SELECT block_hash FROM blocks WHERE block_number = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<uint256_t>(layer_exception(ledger::storage_util::error_of(cursor)));

			string hash = (*cursor)["block_hash"].get().get_blob();
			if (hash.size() != sizeof(uint256_t))
				return expects_lr<uint256_t>(layer_exception("hash deserialization error"));

			uint256_t result;
			result.decode((uint8_t*)hash.data());
			return result;
		}
		expects_lr<decimal> chainstate::get_block_gas_price(uint64_t block_number, const algorithm::asset_id& asset, double percentile)
		{
			if (percentile < 0.0 || percentile > 1.0)
				return expects_lr<decimal>(layer_exception("invalid percentile"));

			auto& blob_storage = get_blob_storage();
			vector<decimal> gas_prices;
			size_t offset = 0, count = ELEMENTS_HUGE;
			while (true)
			{
				schema_list map;
				map.push_back(var::set::integer(block_number));
				map.push_back(var::set::integer(count));
				map.push_back(var::set::integer(offset));

				auto cursor = get_tx_storage().emplace_query(__func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce LIMIT ? OFFSET ?", &map);
				if (!cursor || cursor->error())
					return expects_lr<decimal>(layer_exception(ledger::storage_util::error_of(cursor)));

				auto& response = cursor->first();
				size_t size = response.size(), stride = gas_prices.size();
				gas_prices.resize(gas_prices.size() + size);
				parallel::wail_all(parallel::for_loop(size, ELEMENTS_FEW, [&](size_t i)
				{
					auto& price = gas_prices[stride + i];
					auto transaction_hash = response[i]["transaction_hash"].get();
					auto transaction_blob = blob_storage.load(__func__, get_block_transaction_label(transaction_hash.get_binary())).or_else(string());
					auto transaction_message = format::ro_stream(transaction_blob);
					auto next = ledger::block_transaction();
					if (next.load(transaction_message) && next.transaction->asset == asset)
						price = std::move(next.transaction->gas_price);
					else
						price = decimal::nan();
				}));
				if (size < count)
					break;
			}

			gas_prices.erase(std::remove_if(gas_prices.begin(), gas_prices.end(), [](const decimal& a) { return a.is_nan(); }), gas_prices.end());
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

			return algorithm::arithmetic::divide(*b, *a);
		}
		expects_lr<ledger::block_body> chainstate::get_block_by_number(uint64_t block_number, size_t chunk, uint32_t details)
		{
			schema_list map;
			map.push_back(var::set::integer(block_number));

			auto cursor = get_block_storage().emplace_query(__func__, "SELECT block_hash FROM blocks WHERE block_number = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<ledger::block_body>(layer_exception(ledger::storage_util::error_of(cursor)));

			ledger::block_header header;
			auto block_hash = (*cursor)["block_hash"].get();
			auto block_blob = get_blob_storage().load(__func__, get_block_label(block_hash.get_binary())).or_else(string());
			auto message = format::ro_stream(block_blob);
			if (!header.load(message))
				return expects_lr<ledger::block_body>(layer_exception("block header deserialization error"));

			ledger::block_body result = ledger::block_body(header);
			if ((details & (uint32_t)block_details::transactions) && chunk > 0)
			{
				auto resolve = resolve_block_transactions(result.transactions, result.number, chunk);
				if (!resolve)
					return resolve.error();
			}
			finalize_checksum(header, block_hash);
			return result;
		}
		expects_lr<ledger::block_body> chainstate::get_block_by_hash(const uint256_t& block_hash, size_t chunk, uint32_t details)
		{
			uint8_t hash[32];
			block_hash.encode(hash);

			ledger::block_header header;
			auto block_blob = get_blob_storage().load(__func__, get_block_label(hash)).or_else(string());
			auto message = format::ro_stream(block_blob);
			if (!header.load(message))
				return expects_lr<ledger::block_body>(layer_exception("block header deserialization error"));

			ledger::block_body result = ledger::block_body(header);
			if ((details & (uint32_t)block_details::transactions) && chunk > 0)
			{
				auto resolve = resolve_block_transactions(result.transactions, result.number, chunk);
				if (!resolve)
					return resolve.error();
			}
			finalize_checksum(header, var::binary(hash, sizeof(hash)));
			return result;
		}
		expects_lr<ledger::block_body> chainstate::get_latest_block(size_t chunk, uint32_t details)
		{
			auto& block_storage = get_block_storage();
			auto fetch_latest_block_hash = block_storage.prepare_statement(__func__, "SELECT block_hash FROM blocks ORDER BY block_number DESC LIMIT 1");
			if (!fetch_latest_block_hash)
				return expects_lr<ledger::block_body>(layer_exception(std::move(fetch_latest_block_hash.error().message())));

			auto cursor = block_storage.prepared_query(__func__, *fetch_latest_block_hash);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<ledger::block_body>(layer_exception(ledger::storage_util::error_of(cursor)));

			ledger::block_header header;
			auto block_hash = (*cursor)["block_hash"].get();
			auto block_blob = get_blob_storage().load(__func__, get_block_label(block_hash.get_binary())).or_else(string());
			auto message = format::ro_stream(block_blob);
			if (!header.load(message))
				return expects_lr<ledger::block_body>(layer_exception("block header deserialization error"));

			ledger::block_body result = ledger::block_body(header);
			if ((details & (uint32_t)block_details::transactions) && chunk > 0)
			{
				auto resolve = resolve_block_transactions(result.transactions, result.number, chunk);
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

			auto cursor = get_block_storage().emplace_query(__func__, "SELECT block_hash FROM blocks WHERE block_number = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<ledger::block_header>(layer_exception(ledger::storage_util::error_of(cursor)));

			ledger::block_header header;
			auto block_hash = (*cursor)["block_hash"].get();
			auto block_blob = get_blob_storage().load(__func__, get_block_label(block_hash.get_binary())).or_else(string());
			auto message = format::ro_stream(block_blob);
			if (!header.load(message))
				return expects_lr<ledger::block_header>(layer_exception("block header deserialization error"));

			finalize_checksum(header, block_hash);
			return header;
		}
		expects_lr<ledger::block_header> chainstate::get_block_header_by_hash(const uint256_t& block_hash)
		{
			uint8_t hash[32];
			block_hash.encode(hash);

			ledger::block_header header;
			auto block_blob = get_blob_storage().load(__func__, get_block_label(hash)).or_else(string());
			auto message = format::ro_stream(block_blob);
			if (!header.load(message))
				return expects_lr<ledger::block_header>(layer_exception("block header deserialization error"));

			finalize_checksum(header, var::binary(hash, sizeof(hash)));
			return header;
		}
		expects_lr<ledger::block_header> chainstate::get_latest_block_header()
		{
			auto& block_storage = get_block_storage();
			auto fetch_latest_block_hash = block_storage.prepare_statement(__func__, "SELECT block_hash FROM blocks ORDER BY block_number DESC LIMIT 1");
			if (!fetch_latest_block_hash)
				return expects_lr<ledger::block_header>(layer_exception(std::move(fetch_latest_block_hash.error().message())));

			auto cursor = block_storage.prepared_query(__func__, *fetch_latest_block_hash);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<ledger::block_header>(layer_exception(ledger::storage_util::error_of(cursor)));

			ledger::block_header header;
			auto block_hash = (*cursor)["block_hash"].get();
			auto block_blob = get_blob_storage().load(__func__, get_block_label(block_hash.get_binary())).or_else(string());
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

			auto cursor = get_tx_storage().emplace_query(__func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce;", &map);
			if (!cursor || cursor->error())
				return expects_lr<ledger::block_proof>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto& blob_storage = get_blob_storage();
			auto& response = cursor->first();
			size_t size = response.size();
			size_t stride = proof.transaction_tree.nodes.size();
			proof.transaction_tree.nodes.resize(stride + size);
			proof.receipt_tree.nodes.resize(stride + size);
			parallel::wail_all(parallel::for_loop(size, ELEMENTS_FEW, [&](size_t i)
			{
				auto transaction_hash = response[i]["transaction_hash"].get();
				auto transaction_blob = transaction_hash.size() == sizeof(uint256_t) ? blob_storage.load(__func__, get_block_transaction_label(transaction_hash.get_binary())).or_else(string()) : string();
				auto transaction_message = format::ro_stream(transaction_blob);
				auto next = ledger::block_transaction();
				if (!transaction_blob.empty() && next.load(transaction_message))
				{
					proof.transaction_tree.nodes[stride + i] = next.receipt.transaction_hash;
					proof.receipt_tree.nodes[stride + i] = next.receipt.as_hash();
				}
				else
				{
					proof.transaction_tree.nodes[stride + i] = 0;
					proof.receipt_tree.nodes[stride + i] = 0;
				}
			}));

			for (auto& [uniform_storage, type] : get_uniform_multi_storage())
			{
				cursor = uniform_storage.emplace_query(__func__, "SELECT (SELECT index_hash FROM indices WHERE indices.index_number = snapshots.index_number) AS index_hash FROM snapshots WHERE block_number = ?", &map);
				if (!cursor || cursor->error())
					return expects_lr<ledger::block_proof>(layer_exception(ledger::storage_util::error_of(cursor)));

				auto subresponse = cursor->first();
				auto substride = proof.state_tree.nodes.size();
				auto count = subresponse.size();
				proof.state_tree.nodes.resize(substride + count);
				parallel::wail_all(parallel::for_loop(count, ELEMENTS_FEW, [&](size_t i)
				{
					auto index = subresponse[i]["index_hash"].get().get_blob();
					auto blob = blob_storage.load(__func__, get_uniform_label(type, index, block_number)).or_else(string());
					auto state = state_from_blob(block_number, type, index, std::string_view(), blob);
					proof.state_tree.nodes[substride + i] = state ? state->as_hash() : uint256_t(0);
				}));
			}

			for (auto& [multiform_storage, type] : get_multiform_multi_storage())
			{
				cursor = multiform_storage.emplace_query(__func__, "SELECT (SELECT column_hash FROM columns WHERE columns.column_number = snapshots.column_number) AS column_hash, (SELECT row_hash FROM rows WHERE rows.row_number = snapshots.row_number) AS row_hash FROM snapshots WHERE block_number = ?", &map);
				if (!cursor || cursor->error())
					return expects_lr<ledger::block_proof>(layer_exception(ledger::storage_util::error_of(cursor)));

				auto subresponse = cursor->first();
				auto substride = proof.state_tree.nodes.size();
				auto count = subresponse.size();
				proof.state_tree.nodes.resize(substride + count);
				parallel::wail_all(parallel::for_loop(count, ELEMENTS_FEW, [&](size_t i)
				{
					auto column = subresponse[i]["column_hash"].get().get_blob();
					auto row = subresponse[i]["row_hash"].get().get_blob();
					auto blob = blob_storage.load(__func__, get_multiform_label(type, column, row, block_number)).or_else(string());
					auto state = state_from_blob(block_number, type, column, row, blob);
					proof.state_tree.nodes[substride + i] = state ? state->as_hash() : uint256_t(0);
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

			auto cursor = get_tx_storage().emplace_query(__func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<uint256_t>>(layer_exception(ledger::storage_util::error_of(cursor)));

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
					out_hash.decode((uint8_t*)in_hash.data());
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

			auto& blob_storage = get_blob_storage();
			for (auto& [uniform_storage, type] : get_uniform_multi_storage())
			{
				auto cursor = uniform_storage.emplace_query(__func__, "SELECT (SELECT index_hash FROM indices WHERE indices.index_number = snapshots.index_number) AS index_hash FROM snapshots WHERE block_number = ?", &map);
				if (!cursor || cursor->error())
					return expects_lr<vector<uint256_t>>(layer_exception(ledger::storage_util::error_of(cursor)));

				auto subresponse = cursor->first();
				auto stride = result.size();
				auto count = subresponse.size();
				result.resize(stride + count);
				parallel::wail_all(parallel::for_loop(count, ELEMENTS_FEW, [&](size_t i)
				{
					auto index = subresponse[i]["index_hash"].get().get_blob();
					auto blob = blob_storage.load(__func__, get_uniform_label(type, index, block_number)).or_else(string());
					auto state = state_from_blob(block_number, type, index, std::string_view(), blob);
					result[stride + i] = state ? state->as_hash() : uint256_t(0);
				}));
			}

			for (auto& [multiform_storage, type] : get_multiform_multi_storage())
			{
				auto cursor = multiform_storage.emplace_query(__func__, "SELECT (SELECT column_hash FROM columns WHERE columns.column_number = snapshots.column_number) AS column_hash, (SELECT row_hash FROM rows WHERE rows.row_number = snapshots.row_number) AS row_hash FROM snapshots WHERE block_number = ?", &map);
				if (!cursor || cursor->error())
					return expects_lr<vector<uint256_t>>(layer_exception(ledger::storage_util::error_of(cursor)));

				auto subresponse = cursor->first();
				auto stride = result.size();
				auto count = subresponse.size();
				result.resize(stride + count);
				parallel::wail_all(parallel::for_loop(count, ELEMENTS_FEW, [&](size_t i)
				{
					auto column = subresponse[i]["column_hash"].get().get_blob();
					auto row = subresponse[i]["row_hash"].get().get_blob();
					auto blob = blob_storage.load(__func__, get_multiform_label(type, column, row, block_number)).or_else(string());
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

			auto cursor = get_block_storage().emplace_query(__func__, "SELECT block_hash FROM blocks WHERE block_number BETWEEN ? AND ? ORDER BY block_number DESC", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<uint256_t>>(layer_exception(ledger::storage_util::error_of(cursor)));

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
					out_hash.decode((uint8_t*)in_hash.data());
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

			auto cursor = get_block_storage().emplace_query(__func__, "SELECT block_hash FROM blocks WHERE block_number BETWEEN ? AND ? ORDER BY block_number ASC", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<ledger::block_header>>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto& blob_storage = get_blob_storage();
			vector<ledger::block_header> result;
			for (auto& response : *cursor)
			{
				size_t size = response.size();
				result.resize(result.size() + size);
				parallel::wail_all(parallel::for_loop(size, ELEMENTS_FEW, [&](size_t i)
				{
					auto block_hash = response[i]["block_hash"].get();
					auto block_blob = blob_storage.load(__func__, get_block_label(block_hash.get_binary())).or_else(string());
					auto message = format::ro_stream(block_blob);
					result[i].load(message);
				}));
			}

			return result;
		}
		expects_lr<ledger::block_state::log> chainstate::get_block_state_by_number(uint64_t block_number, size_t chunk)
		{
			auto& blob_storage = get_blob_storage();
			schema_list map;
			map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(chunk));
			map.push_back(var::set::integer(0));

			ledger::block_state result;
			for (auto& [uniform_storage, type] : get_uniform_multi_storage())
			{
				size_t offset = 0;
				map[2]->value = var::integer(offset);
				while (true)
				{
					auto cursor = uniform_storage.emplace_query(__func__, "SELECT (SELECT index_hash FROM indices WHERE indices.index_number = snapshots.index_number) AS index_hash, hidden FROM snapshots WHERE block_number = ? LIMIT ? OFFSET ?", &map);
					if (!cursor || cursor->error())
						return expects_lr<ledger::block_state::log>(layer_exception(ledger::storage_util::error_of(cursor)));

					auto& response = cursor->first();
					size_t size = response.size();
					for (size_t i = 0; i < size; i++)
					{
						auto next = response[i];
						auto index = next["index_hash"].get().get_blob();
						auto hidden = next["hidden"].get().get_boolean();
						auto blob = blob_storage.load(__func__, get_uniform_label(type, index, block_number)).or_else(string());
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

			for (auto& [multiform_storage, type] : get_multiform_multi_storage())
			{
				size_t offset = 0;
				map[2]->value = var::integer(offset);
				while (true)
				{
					auto cursor = multiform_storage.emplace_query(__func__, "SELECT (SELECT column_hash FROM columns WHERE columns.column_number = snapshots.column_number) AS column_hash, (SELECT row_hash FROM rows WHERE rows.row_number = snapshots.row_number) AS row_hash, hidden FROM snapshots WHERE block_number = ? LIMIT ? OFFSET ?", &map);
					if (!cursor || cursor->error())
						return expects_lr<ledger::block_state::log>(layer_exception(ledger::storage_util::error_of(cursor)));

					auto& response = cursor->first();
					size_t size = response.size();
					for (size_t i = 0; i < size; i++)
					{
						auto next = response[i];
						auto column = next["column_hash"].get().get_blob();
						auto row = next["row_hash"].get().get_blob();
						auto hidden = next["hidden"].get().get_boolean();
						auto blob = blob_storage.load(__func__, get_multiform_label(type, column, row, block_number)).or_else(string());
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

			return expects_lr<ledger::block_state::log>(std::move(result.pending));
		}
		expects_lr<vector<ledger::block_transaction>> chainstate::get_block_transactions(size_t offset, size_t count)
		{
			schema_list map;
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = get_tx_storage().emplace_query(__func__, "SELECT transaction_hash FROM transactions ORDER BY transaction_number DESC LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<ledger::block_transaction>>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			vector<ledger::block_transaction> values;
			values.resize(size);

			auto& blob_storage = get_blob_storage();
			parallel::wail_all(parallel::for_loop(size, ELEMENTS_FEW, [&](size_t i)
			{
				auto transaction_hash = response[i]["transaction_hash"].get();
				auto transaction_blob = blob_storage.load(__func__, get_block_transaction_label(transaction_hash.get_binary())).or_else(string());
				auto transaction_message = format::ro_stream(transaction_blob);
				auto& next = values[i];
				if (next.load(transaction_message))
					finalize_checksum(**next.transaction, transaction_hash);
			}));

			values.erase(std::remove_if(values.begin(), values.end(), [](const ledger::block_transaction& a) { return !a.transaction; }), values.end());
			return values;
		}
		expects_lr<vector<ledger::block_transaction>> chainstate::get_block_transactions_by_number(uint64_t block_number, size_t offset, size_t count)
		{
			schema_list map;
			map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = get_tx_storage().emplace_query(__func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<ledger::block_transaction>>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			vector<ledger::block_transaction> values;
			values.resize(size);

			auto& blob_storage = get_blob_storage();
			parallel::wail_all(parallel::for_loop(size, ELEMENTS_FEW, [&](size_t i)
			{
				auto transaction_hash = response[i]["transaction_hash"].get();
				auto transaction_blob = blob_storage.load(__func__, get_block_transaction_label(transaction_hash.get_binary())).or_else(string());
				auto transaction_message = format::ro_stream(transaction_blob);
				auto& next = values[i];
				if (next.load(transaction_message))
					finalize_checksum(**next.transaction, transaction_hash);
			}));

			values.erase(std::remove_if(values.begin(), values.end(), [](const ledger::block_transaction& a) { return !a.transaction; }), values.end());
			return values;
		}
		expects_lr<vector<ledger::block_transaction>> chainstate::get_block_transactions_by_owner(uint64_t block_number, const algorithm::pubkeyhash_t& owner, int8_t direction, size_t offset, size_t count)
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

			auto cursor = get_party_storage().emplace_query(__func__, "SELECT transaction_number FROM parties WHERE transaction_account_number = ? AND block_number <= ? ORDER BY transaction_number $? LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<ledger::block_transaction>>(layer_exception(ledger::storage_util::error_of(cursor)));
			else if (cursor->empty())
				return expects_lr<vector<ledger::block_transaction>>(vector<ledger::block_transaction>());

			string dynamic_query = "SELECT transaction_hash FROM transactions WHERE transaction_number IN (";
			for (auto row : cursor->first())
				dynamic_query.append(row.get_column(0).get().get_blob()).push_back(',');
			dynamic_query.pop_back();
			dynamic_query.append(") ORDER BY transaction_number ");
			dynamic_query.append(direction < 0 ? "DESC" : "ASC");

			cursor = get_tx_storage().query(__func__, dynamic_query);
			if (!cursor || cursor->error())
				return expects_lr<vector<ledger::block_transaction>>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			vector<ledger::block_transaction> values;
			values.resize(size);

			auto& blob_storage = get_blob_storage();
			parallel::wail_all(parallel::for_loop(size, ELEMENTS_FEW, [&](size_t i)
			{
				auto transaction_hash = response[i]["transaction_hash"].get();
				auto transaction_blob = blob_storage.load(__func__, get_block_transaction_label(transaction_hash.get_binary())).or_else(string());
				auto transaction_message = format::ro_stream(transaction_blob);
				auto& next = values[i];
				if (next.load(transaction_message))
					finalize_checksum(**next.transaction, transaction_hash);
			}));

			values.erase(std::remove_if(values.begin(), values.end(), [](const ledger::block_transaction& a) { return !a.transaction; }), values.end());
			return values;
		}
		expects_lr<vector<ledger::block_transaction>> chainstate::get_pending_block_transactions(uint64_t block_number, size_t offset, size_t count)
		{
			schema_list map;
			map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = get_tx_storage().emplace_query(__func__, "SELECT transaction_hash FROM transactions WHERE dispatch_queue IS NOT NULL AND dispatch_queue <= ? ORDER BY block_nonce LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<ledger::block_transaction>>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			vector<ledger::block_transaction> values;
			values.resize(size);

			auto& blob_storage = get_blob_storage();
			parallel::wail_all(parallel::for_loop(size, ELEMENTS_FEW, [&](size_t i)
			{
				auto transaction_hash = response[i]["transaction_hash"].get();
				auto transaction_blob = blob_storage.load(__func__, get_block_transaction_label(transaction_hash.get_binary())).or_else(string());
				auto transaction_message = format::ro_stream(transaction_blob);
				auto& next = values[i];
				if (next.load(transaction_message))
					finalize_checksum(**next.transaction, transaction_hash);
			}));

			values.erase(std::remove_if(values.begin(), values.end(), [](const ledger::block_transaction& a) { return !a.transaction; }), values.end());
			return values;
		}
		expects_lr<bool> chainstate::has_block_transaction(const uint256_t& transaction_hash)
		{
			uint8_t hash[32];
			transaction_hash.encode(hash);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));

			auto cursor = get_tx_storage().emplace_query(__func__, "SELECT TRUE FROM transactions WHERE transaction_hash = ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<bool>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expects_lr<bool>(!cursor->empty());
		}
		expects_lr<ledger::block_transaction> chainstate::get_block_transaction_by_hash(const uint256_t& transaction_hash, bool include_aliases)
		{
			auto result = get_block_transactions_by_hash(transaction_hash, include_aliases);
			if (!result)
				return result.error();
			else if (result->empty())
				return layer_exception("transaction not found");

			return expects_lr<ledger::block_transaction>(std::move(result->front()));
		}
		expects_lr<vector<ledger::block_transaction>> chainstate::get_block_transactions_by_hash(const uint256_t& transaction_hash, bool include_aliases)
		{
			uint8_t hash[32];
			transaction_hash.encode(hash);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));

			string dynamic_query = "SELECT transaction_hash FROM transactions WHERE transaction_hash = ?";
			if (include_aliases)
			{
				auto cursor = get_alias_storage().emplace_query(__func__, "SELECT transaction_number FROM aliases WHERE transaction_hash = ?", &map);
				if (cursor && !cursor->error_or_empty())
				{
					dynamic_query.append("OR transaction_number IN (");
					for (auto row : cursor->first())
						dynamic_query.append(row.get_column(0).get().get_blob()).push_back(',');
					dynamic_query.pop_back();
					dynamic_query.push_back(')');
				}
				dynamic_query.append(" ORDER BY transaction_number DESC");
			}

			auto cursor = get_tx_storage().emplace_query(__func__, dynamic_query, &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<vector<ledger::block_transaction>>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto& blob_storage = get_blob_storage();
			auto& response = cursor->first();
			size_t size = response.size();
			vector<ledger::block_transaction> values;
			values.reserve(size);
			for (size_t i = 0; i < size; i++)
			{
				auto parent_transaction_hash = response[i]["transaction_hash"].get();
				auto parent_transaction_blob = blob_storage.load(__func__, get_block_transaction_label(parent_transaction_hash.get_binary())).or_else(string());
				auto parent_transaction_message = format::ro_stream(parent_transaction_blob);
				auto next = ledger::block_transaction();
				if (next.load(parent_transaction_message))
				{
					finalize_checksum(**next.transaction, parent_transaction_hash);
					values.push_back(std::move(next));
				}
			}
			return values;
		}
		expects_lr<state_result> chainstate::get_uniform(uint32_t type, const ledger::block_changelog* changelog, const std::string_view& index, uint64_t block_number)
		{
			if (changelog != nullptr)
			{
				auto candidate = changelog->outgoing.find(type, index);
				if (candidate)
					return state_result(std::move(*candidate), true);

				candidate = changelog->incoming.find(type, index);
				if (candidate)
					return state_result(std::move(*candidate), true);
			}

			auto location = resolve_uniform_location(type, index);
			if (!location)
				return location.error();

			auto& uniform_storage = get_uniform_storage(type);
			auto find_state = uniform_storage.prepare_statement(__func__, !block_number ?
				"SELECT block_number FROM uniforms WHERE index_number = ?" :
				"SELECT block_number, hidden FROM snapshots WHERE index_number = ? AND block_number < ? ORDER BY block_number DESC LIMIT 1");
			if (!find_state)
				return expects_lr<state_result>(layer_exception(std::move(find_state.error().message())));

			uniform_storage.ptr()->bind_int64(*find_state, 0, location.or_else(0));
			if (block_number > 0)
				uniform_storage.ptr()->bind_int64(*find_state, 1, block_number);

			auto cursor = uniform_storage.prepared_query(__func__, *find_state);
			if (!cursor)
			{
				if (changelog != nullptr)
					((ledger::block_changelog*)changelog)->incoming.erase(type, index);
				return expects_lr<state_result>(layer_exception(ledger::storage_util::error_of(cursor)));
			}
			else if (cursor->empty())
			{
				if (changelog != nullptr)
					((ledger::block_changelog*)changelog)->incoming.erase(type, index);
				return expects_lr<state_result>(layer_exception("uniform state not found"));
			}

			uint64_t location_block_number = (*cursor)["block_number"].get().get_integer();
			bool location_hidden = (*cursor)["hidden"].get().get_boolean();
			auto blob = get_blob_storage().load(__func__, get_uniform_label(type, index, location_block_number)).or_else(string());
			auto value = state_from_blob(location_block_number, type, index, std::string_view(), blob);
			if (!value)
			{
				if (changelog != nullptr)
					((ledger::block_changelog*)changelog)->incoming.erase(type, index);
				return expects_lr<state_result>(layer_exception("uniform state deserialization error"));
			}

			if (changelog != nullptr)
				((ledger::block_changelog*)changelog)->incoming.push(*value, location_hidden);
			if (location_hidden)
				return expects_lr<state_result>(layer_exception("uniform state not found"));

			return state_result(std::move(value), false);
		}
		expects_lr<state_result> chainstate::get_multiform(uint32_t type, const ledger::block_changelog* changelog, const std::string_view& column, const std::string_view& row, uint64_t block_number)
		{
			if (changelog != nullptr)
			{
				auto candidate = changelog->outgoing.find(type, column, row);
				if (candidate)
					return state_result(std::move(*candidate), true);

				candidate = changelog->incoming.find(type, column, row);
				if (candidate)
					return state_result(std::move(*candidate), true);
			}

			auto location = resolve_multiform_location(type, column, row);
			if (!location)
				return location.error();

			auto& multiform_storage = get_multiform_storage(type);
			auto find_state = multiform_storage.prepare_statement(__func__, !block_number ?
				"SELECT block_number FROM multiforms WHERE column_number = ? AND row_number = ?" :
				"SELECT block_number, hidden FROM snapshots WHERE column_number = ? AND row_number = ? AND block_number < ? ORDER BY block_number DESC LIMIT 1");
			if (!find_state)
				return expects_lr<state_result>(layer_exception(std::move(find_state.error().message())));

			auto* multiform_storage_ptr = multiform_storage.ptr();
			multiform_storage_ptr->bind_int64(*find_state, 0, location->column.or_else(0));
			multiform_storage_ptr->bind_int64(*find_state, 1, location->row.or_else(0));
			if (block_number > 0)
				multiform_storage_ptr->bind_int64(*find_state, 2, block_number);

			auto cursor = multiform_storage.prepared_query(__func__, *find_state);
			if (!cursor)
			{
				if (changelog != nullptr)
					((ledger::block_changelog*)changelog)->incoming.erase(type, column, row);
				return expects_lr<state_result>(layer_exception(ledger::storage_util::error_of(cursor)));
			}
			else if (cursor->empty())
			{
				if (changelog != nullptr)
					((ledger::block_changelog*)changelog)->incoming.erase(type, column, row);
				return expects_lr<state_result>(layer_exception("multiform state not found"));
			}

			uint64_t location_block_number = (*cursor)["block_number"].get().get_integer();
			bool location_hidden = (*cursor)["hidden"].get().get_boolean();
			auto blob = get_blob_storage().load(__func__, get_multiform_label(type, column, row, location_block_number)).or_else(string());
			auto value = state_from_blob(location_block_number, type, column, row, blob);
			if (!value)
			{
				if (changelog != nullptr)
					((ledger::block_changelog*)changelog)->incoming.erase(type, column, row);
				return expects_lr<state_result>(layer_exception("multiform state deserialization error"));
			}

			if (changelog != nullptr)
				((ledger::block_changelog*)changelog)->incoming.push(*value, location_hidden);
			if (location_hidden)
				return expects_lr<state_result>(layer_exception("multiform state not found"));

			return state_result(std::move(value), false);
		}
		expects_lr<vector<state_result>> chainstate::get_multiforms_by_column(uint32_t type, ledger::block_changelog* changelog, const std::string_view& column, uint64_t block_number, size_t offset, size_t count)
		{
			auto temporary = resolve_temporary_state(type, changelog, column, optional::none, block_number);
			if (!temporary)
				return temporary.error();

			auto location = resolve_multiform_location(type, column, optional::none);
			if (!location)
				return expects_lr<vector<state_result>>(vector<state_result>());

			auto fetch_state = temporary->storage->prepare_statement(__func__, !block_number ?
				"SELECT rq.row_hash, multiforms.block_number FROM multiforms JOIN rows AS rq ON rq.row_number = multiforms.row_number WHERE column_number = ? ORDER BY multiforms.row_number LIMIT ? OFFSET ?" :
				"SELECT rq.row_hash, sq.block_number FROM (SELECT row_number, hidden, MAX(block_number) AS block_number FROM snapshots WHERE column_number = ? AND block_number < ? GROUP BY row_number ORDER BY row_number) AS sq JOIN rows AS rq ON rq.row_number = sq.row_number WHERE hidden = FALSE LIMIT ? OFFSET ?");
			if (!fetch_state)
				return expects_lr<vector<state_result>>(layer_exception(std::move(fetch_state.error().message())));

			temporary->storage->ptr()->bind_int64(*fetch_state, 0, location->column.or_else(0));
			if (block_number > 0)
			{
				temporary->storage->ptr()->bind_int64(*fetch_state, 1, block_number);
				temporary->storage->ptr()->bind_int64(*fetch_state, 2, count);
				temporary->storage->ptr()->bind_int64(*fetch_state, 3, offset);
			}
			else
			{
				temporary->storage->ptr()->bind_int64(*fetch_state, 1, count);
				temporary->storage->ptr()->bind_int64(*fetch_state, 2, offset);
			}

			auto cursor = temporary->storage->prepared_query(__func__, *fetch_state);
			if (!cursor || cursor->error())
				return expects_lr<vector<state_result>>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto& blob_storage = get_blob_storage();
			auto& response = cursor->first();
			vector<state_result> values;
			values.resize(response.size());
			parallel::wail_all(parallel::for_loop(values.size(), ELEMENTS_FEW, [&](size_t i)
			{
				auto next = response[i];
				auto row = next["row_hash"].get().get_blob();
				if (changelog != nullptr)
				{
					auto candidate = changelog->outgoing.find(type, column, row);
					if (!candidate)
						candidate = changelog->incoming.find(type, column, row);
					if (candidate)
					{
						values[i] = state_result(std::move(*candidate), true);
						return;
					}
				}

				auto state_block_number = next["block_number"].get().get_integer();
				auto blob = blob_storage.load(__func__, get_multiform_label(type, column, row, state_block_number)).or_else(string());
				auto next_state = state_from_blob(state_block_number, type, column, row, blob);
				if (!next_state)
				{
					if (next_state && changelog != nullptr)
						((ledger::block_changelog*)changelog)->incoming.erase(type, column, ((ledger::multiform_state*)*next_state)->as_row());
					return;
				}
				else if (changelog != nullptr)
					((ledger::block_changelog*)changelog)->incoming.push(*next_state, false);

				values[i] = state_result(std::move(next_state), false);
			}));

			values.erase(std::remove_if(values.begin(), values.end(), [](const state_result& a) { return !a.value; }), values.end());
			return values;
		}
		expects_lr<vector<state_result>> chainstate::get_multiforms_by_column_filter(uint32_t type, ledger::block_changelog* changelog, const std::string_view& column, const result_filter& filter, uint64_t block_number, const result_window& window)
		{
			auto temporary = resolve_temporary_state(type, changelog, column, optional::none, block_number);
			if (!temporary)
				return temporary.error();

			auto location = resolve_multiform_location(type, column, optional::none);
			if (!location)
				return expects_lr<vector<state_result>>(vector<state_result>());

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
					"SELECT rq.row_hash, multiforms.block_number FROM multiforms JOIN rows AS rq ON rq.row_number = multiforms.row_number WHERE column_number = ? AND rank $? ? ORDER BY rank $?, multiforms.row_number ASC LIMIT ? OFFSET ?" :
					"SELECT rq.row_hash, fq.block_number FROM (SELECT column_number, row_number, rank, hidden, MAX(block_number) AS block_number FROM snapshots WHERE column_number = ? AND block_number < ? GROUP BY row_number) AS fq JOIN rows AS rq ON rq.row_number = fq.row_number WHERE hidden = FALSE AND rank $? ? ORDER BY rank $?, fq.row_number ASC LIMIT ? OFFSET ?";
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
				map.push_back(var::set::string(std::string_view(indices).substr(0, indices.size() - 1)));

				pattern = !block_number ?
					"SELECT rq.row_hash, sq.block_number, (id - 1) AS id FROM (SELECT ROW_NUMBER() OVER (ORDER BY rank $?, row_number ASC) AS id, row_number, block_number FROM multiforms WHERE column_number = ? AND rank $? ?) AS sq JOIN rows AS rq ON rq.row_number = sq.row_number WHERE sq.id IN ($?) ORDER BY sq.id ASC" :
					"SELECT rq.row_hash, sq.block_number, (id - 1) AS id FROM (SELECT ROW_NUMBER() OVER (ORDER BY rank $?, row_number ASC) AS id, row_number, block_number FROM (SELECT column_number, row_number, rank, hidden, MAX(block_number) AS block_number FROM snapshots WHERE column_number = ? AND block_number < ? GROUP BY row_number) AS fq WHERE hidden = FALSE AND rank $? ?) AS sq JOIN rows AS rq ON rq.row_number = sq.row_number WHERE sq.id IN ($?) ORDER BY sq.id ASC";
			}

			auto cursor = temporary->storage->emplace_query(__func__, pattern, &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<state_result>>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto& blob_storage = get_blob_storage();
			auto& response = cursor->first();
			vector<state_result> values;
			values.resize(response.size());
			parallel::wail_all(parallel::for_loop(values.size(), ELEMENTS_FEW, [&](size_t i)
			{
				auto next = response[i];
				auto row = next["row_hash"].get().get_blob();
				auto index = (size_t)next["id"].get().get_integer();
				if (changelog != nullptr)
				{
					auto candidate = changelog->outgoing.find(type, column, row);
					if (!candidate)
						candidate = changelog->incoming.find(type, column, row);
					if (candidate)
					{
						values[i] = state_result(std::move(*candidate), true, index);
						return;
					}
				}

				auto state_block_number = next["block_number"].get().get_integer();
				auto blob = blob_storage.load(__func__, get_multiform_label(type, column, row, state_block_number)).or_else(string());
				auto next_state = state_from_blob(state_block_number, type, column, row, blob);
				if (!next_state)
				{
					if (next_state && changelog != nullptr)
						((ledger::block_changelog*)changelog)->incoming.erase(type, column, ((ledger::multiform_state*)*next_state)->as_row());
					return;
				}
				else if (changelog != nullptr)
					((ledger::block_changelog*)changelog)->incoming.push(*next_state, false);

				values[i] = state_result(std::move(next_state), false, index);
			}));

			values.erase(std::remove_if(values.begin(), values.end(), [](const state_result& a) { return !a.value; }), values.end());
			if (window.type() == result_index_window::instance_type())
			{
				auto* index_window = (result_index_window*)&window;
				std::sort(values.begin(), values.end(), [&index_window](const state_result& a, const state_result& b)
				{
					auto index_a = std::find(index_window->indices.begin(), index_window->indices.end(), a.index);
					auto index_b = std::find(index_window->indices.begin(), index_window->indices.end(), b.index);
					return index_a < index_b;
				});
			}

			return values;
		}
		expects_lr<vector<state_result>> chainstate::get_multiforms_by_row(uint32_t type, ledger::block_changelog* changelog, const std::string_view& row, uint64_t block_number, size_t offset, size_t count)
		{
			auto temporary = resolve_temporary_state(type, changelog, optional::none, row, block_number);
			if (!temporary)
				return temporary.error();

			auto location = resolve_multiform_location(type, optional::none, row);
			if (!location)
				return expects_lr<vector<state_result>>(vector<state_result>());

			auto fetch_state = temporary->storage->prepare_statement(__func__, !block_number ?
				"SELECT cq.column_hash, multiforms.block_number FROM multiforms JOIN columns AS cq ON cq.column_number = multiforms.column_number WHERE row_number = ? ORDER BY multiforms.column_number LIMIT ? OFFSET ?" :
				"SELECT cq.column_hash, sq.block_number FROM (SELECT column_number, hidden, MAX(block_number) AS block_number FROM snapshots WHERE row_number = ? AND block_number < ? GROUP BY column_number ORDER BY column_number) AS sq JOIN columns AS cq ON cq.column_number = sq.column_number WHERE hidden = FALSE LIMIT ? OFFSET ?");
			if (!fetch_state)
				return expects_lr<vector<state_result>>(layer_exception(std::move(fetch_state.error().message())));

			temporary->storage->ptr()->bind_int64(*fetch_state, 0, location->row.or_else(0));
			if (block_number > 0)
			{
				temporary->storage->ptr()->bind_int64(*fetch_state, 1, block_number);
				temporary->storage->ptr()->bind_int64(*fetch_state, 2, count);
				temporary->storage->ptr()->bind_int64(*fetch_state, 3, offset);
			}
			else
			{
				temporary->storage->ptr()->bind_int64(*fetch_state, 1, count);
				temporary->storage->ptr()->bind_int64(*fetch_state, 2, offset);
			}

			auto cursor = temporary->storage->prepared_query(__func__, *fetch_state);
			if (!cursor || cursor->error())
				return expects_lr<vector<state_result>>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto& blob_storage = get_blob_storage();
			auto& response = cursor->first();
			vector<state_result> values;
			values.resize(response.size());
			parallel::wail_all(parallel::for_loop(values.size(), ELEMENTS_FEW, [&](size_t i)
			{
				auto next = response[i];
				auto column = next["column_hash"].get().get_blob();
				if (changelog != nullptr)
				{
					auto candidate = changelog->outgoing.find(type, column, row);
					if (!candidate)
						candidate = changelog->incoming.find(type, column, row);
					if (candidate)
					{
						values[i] = state_result(std::move(*candidate), true);
						return;
					}
				}

				auto state_block_number = next["block_number"].get().get_integer();
				auto blob = blob_storage.load(__func__, get_multiform_label(type, column, row, state_block_number)).or_else(string());
				auto next_state = state_from_blob(state_block_number, type, column, row, blob);
				if (!next_state)
				{
					if (next_state && changelog != nullptr)
						((ledger::block_changelog*)changelog)->incoming.erase(type, ((ledger::multiform_state*)*next_state)->as_column(), row);
					return;
				}
				else if (changelog != nullptr)
					((ledger::block_changelog*)changelog)->incoming.push(*next_state, false);

				values[i] = state_result(std::move(next_state), false);
			}));

			values.erase(std::remove_if(values.begin(), values.end(), [](const state_result& a) { return !a.value; }), values.end());
			return values;
		}
		expects_lr<vector<state_result>> chainstate::get_multiforms_by_row_filter(uint32_t type, ledger::block_changelog* changelog, const std::string_view& row, const result_filter& filter, uint64_t block_number, const result_window& window)
		{
			auto temporary = resolve_temporary_state(type, changelog, optional::none, row, block_number);
			if (!temporary)
				return temporary.error();

			auto location = resolve_multiform_location(type, optional::none, row);
			if (!location)
				return expects_lr<vector<state_result>>(vector<state_result>());

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
					"SELECT cq.column_hash, multiforms.block_number FROM multiforms JOIN columns AS cq ON cq.column_number = multiforms.column_number WHERE row_number = ? AND rank $? ? ORDER BY rank $?, multiforms.column_number ASC LIMIT ? OFFSET ?" :
					"SELECT cq.column_hash, fq.block_number FROM (SELECT column_number, row_number, rank, hidden, MAX(block_number) AS block_number FROM snapshots WHERE row_number = ? AND block_number < ? GROUP BY column_number) AS fq JOIN columns AS cq ON cq.column_number = fq.column_number WHERE hidden = FALSE AND rank $? ? ORDER BY rank $?, fq.column_number ASC LIMIT ? OFFSET ?";
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
				map.push_back(var::set::string(std::string_view(indices).substr(0, indices.size() - 1)));

				pattern = !block_number ?
					"SELECT cq.column_hash, sq.block_number, (id - 1) AS id FROM (SELECT ROW_NUMBER() OVER (ORDER BY rank $?, column_number ASC) AS id, column_number, block_number FROM multiforms WHERE row_number = ? AND rank $? ?) AS sq JOIN columns AS cq ON cq.column_number = sq.column_number WHERE sq.id IN ($?) ORDER BY sq.id ASC" :
					"SELECT cq.column_hash, sq.block_number, (id - 1) AS id FROM (SELECT ROW_NUMBER() OVER (ORDER BY rank $?, column_number ASC) AS id, column_number, block_number FROM (SELECT column_number, row_number, rank, hidden, MAX(block_number) AS block_number FROM snapshots WHERE row_number = ? AND block_number < ? GROUP BY column_number) AS fq WHERE hidden = FALSE AND rank $? ?) AS sq JOIN columns AS cq ON cq.column_number = sq.column_number WHERE sq.id IN ($?) ORDER BY sq.id ASC";
			}

			auto cursor = temporary->storage->emplace_query(__func__, pattern, &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<state_result>>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto& blob_storage = get_blob_storage();
			auto& response = cursor->first();
			vector<state_result> values;
			values.resize(response.size());
			parallel::wail_all(parallel::for_loop(values.size(), ELEMENTS_FEW, [&](size_t i)
			{
				auto next = response[i];
				auto column = next["column_hash"].get().get_blob();
				auto index = (size_t)next["id"].get().get_integer();
				if (changelog != nullptr)
				{
					auto candidate = changelog->outgoing.find(type, column, row);
					if (!candidate)
						candidate = changelog->incoming.find(type, column, row);
					if (candidate)
					{
						values[i] = state_result(std::move(*candidate), true, index);
						return;
					}
				}

				auto state_block_number = next["block_number"].get().get_integer();
				auto blob = blob_storage.load(__func__, get_multiform_label(type, column, row, state_block_number)).or_else(string());
				auto next_state = state_from_blob(state_block_number, type, column, row, blob);
				if (!next_state)
				{
					if (next_state && changelog != nullptr)
						((ledger::block_changelog*)changelog)->incoming.erase(type, ((ledger::multiform_state*)*next_state)->as_column(), row);
					return;
				}
				else if (changelog != nullptr)
					((ledger::block_changelog*)changelog)->incoming.push(*next_state, false);

				values[i] = state_result(std::move(next_state), false, index);
			}));

			values.erase(std::remove_if(values.begin(), values.end(), [](const state_result& a) { return !a.value; }), values.end());
			if (window.type() == result_index_window::instance_type())
			{
				auto* index_window = (result_index_window*)&window;
				std::sort(values.begin(), values.end(), [&index_window](const state_result& a, const state_result& b)
				{
					auto index_a = std::find(index_window->indices.begin(), index_window->indices.end(), a.index);
					auto index_b = std::find(index_window->indices.begin(), index_window->indices.end(), b.index);
					return index_a < index_b;
				});
			}

			return values;
		}
		expects_lr<size_t> chainstate::get_multiforms_count_by_column(uint32_t type, ledger::block_changelog* changelog, const std::string_view& column, uint64_t block_number)
		{
			auto temporary = resolve_temporary_state(type, changelog, column, optional::none, block_number);
			if (!temporary)
				return temporary.error();

			auto location = resolve_multiform_location(type, column, optional::none);
			if (!location)
				return location.error();

			auto fetch_count = temporary->storage->prepare_statement(__func__, !block_number ? "SELECT COUNT(1) AS multiform_count FROM multiforms WHERE column_number = ?" : "SELECT COUNT(1) AS multiform_count FROM (SELECT hidden, MAX(block_number) FROM snapshots WHERE column_number = ? AND block_number < ? GROUP BY row_number) WHERE hidden = FALSE");
			if (!fetch_count)
				return expects_lr<size_t>(layer_exception(std::move(fetch_count.error().message())));

			temporary->storage->ptr()->bind_int64(*fetch_count, 0, location->column.or_else(0));
			temporary->storage->ptr()->bind_int64(*fetch_count, 1, block_number);

			auto cursor = temporary->storage->prepared_query(__func__, *fetch_count);
			if (!cursor || cursor->error())
				return expects_lr<size_t>(layer_exception(ledger::storage_util::error_of(cursor)));

			size_t count = (*cursor)["multiform_count"].get().get_integer();
			return expects_lr<size_t>(count);
		}
		expects_lr<size_t> chainstate::get_multiforms_count_by_column_filter(uint32_t type, ledger::block_changelog* changelog, const std::string_view& column, const result_filter& filter, uint64_t block_number)
		{
			auto temporary = resolve_temporary_state(type, changelog, column, optional::none, block_number);
			if (!temporary)
				return temporary.error();

			auto location = resolve_multiform_location(type, column, optional::none);
			if (!location)
				return location.error();

			auto query = string(!block_number ? "SELECT COUNT(1) AS multiform_count FROM multiforms WHERE column_number = ? AND rank $? ?" : "SELECT COUNT(1) AS multiform_count FROM (SELECT rank, hidden, MAX(block_number) FROM snapshots WHERE column_number = ? AND block_number < ? GROUP BY row_number) WHERE hidden = FALSE AND rank $? ?");
			auto fetch_count = temporary->storage->prepare_statement(__func__, stringify::replace(query, "$?", filter.as_condition()));
			if (!fetch_count)
				return expects_lr<size_t>(layer_exception(std::move(fetch_count.error().message())));

			auto rank = filter.as_value();
			temporary->storage->ptr()->bind_int64(*fetch_count, 0, location->column.or_else(0));
			if (block_number > 0)
			{
				temporary->storage->ptr()->bind_int64(*fetch_count, 1, block_number);
				temporary->storage->ptr()->bind_blob(*fetch_count, 2, rank);
			}
			else
				temporary->storage->ptr()->bind_blob(*fetch_count, 1, rank);

			auto cursor = temporary->storage->prepared_query(__func__, *fetch_count);
			if (!cursor || cursor->error())
				return expects_lr<size_t>(layer_exception(ledger::storage_util::error_of(cursor)));

			size_t count = (*cursor)["multiform_count"].get().get_integer();
			return expects_lr<size_t>(count);
		}
		expects_lr<size_t> chainstate::get_multiforms_count_by_row(uint32_t type, ledger::block_changelog* changelog, const std::string_view& row, uint64_t block_number)
		{
			auto temporary = resolve_temporary_state(type, changelog, optional::none, row, block_number);
			if (!temporary)
				return temporary.error();

			auto location = resolve_multiform_location(type, optional::none, row);
			if (!location)
				return location.error();

			auto fetch_count = temporary->storage->prepare_statement(__func__, !block_number ? "SELECT COUNT(1) AS multiform_count FROM multiforms WHERE row_number = ?" : "SELECT COUNT(1) AS multiform_count FROM (SELECT hidden, MAX(block_number) FROM snapshots WHERE row_number = ? AND block_number < ? GROUP BY column_number) WHERE hidden = FALSE");
			if (!fetch_count)
				return expects_lr<size_t>(layer_exception(std::move(fetch_count.error().message())));

			temporary->storage->ptr()->bind_int64(*fetch_count, 0, location->row.or_else(0));
			temporary->storage->ptr()->bind_int64(*fetch_count, 1, block_number);

			auto cursor = temporary->storage->prepared_query(__func__, *fetch_count);
			if (!cursor || cursor->error())
				return expects_lr<size_t>(layer_exception(ledger::storage_util::error_of(cursor)));

			size_t count = (*cursor)["multiform_count"].get().get_integer();
			return expects_lr<size_t>(count);
		}
		expects_lr<size_t> chainstate::get_multiforms_count_by_row_filter(uint32_t type, ledger::block_changelog* changelog, const std::string_view& row, const result_filter& filter, uint64_t block_number)
		{
			auto temporary = resolve_temporary_state(type, changelog, optional::none, row, block_number);
			if (!temporary)
				return temporary.error();

			auto location = resolve_multiform_location(type, optional::none, row);
			if (!location)
				return location.error();

			auto query = string(!block_number ? "SELECT COUNT(1) AS multiform_count FROM multiforms WHERE row_number = ? AND rank $? ?" : "SELECT COUNT(1) AS multiform_count FROM (SELECT rank, hidden, MAX(block_number) FROM snapshots WHERE row_number = ? AND block_number < ? GROUP BY column_number) WHERE hidden = FALSE AND rank $? ?");
			auto fetch_count = temporary->storage->prepare_statement(__func__, stringify::replace(query, "$?", filter.as_condition()));
			if (!fetch_count)
				return expects_lr<size_t>(layer_exception(std::move(fetch_count.error().message())));

			auto rank = filter.as_value();
			temporary->storage->ptr()->bind_int64(*fetch_count, 0, location->row.or_else(0));
			if (block_number > 0)
			{
				temporary->storage->ptr()->bind_int64(*fetch_count, 1, block_number);
				temporary->storage->ptr()->bind_blob(*fetch_count, 2, rank);
			}
			else
				temporary->storage->ptr()->bind_blob(*fetch_count, 1, rank);

			auto cursor = temporary->storage->prepared_query(__func__, *fetch_count);
			if (!cursor || cursor->error())
				return expects_lr<size_t>(layer_exception(ledger::storage_util::error_of(cursor)));

			size_t count = (*cursor)["multiform_count"].get().get_integer();
			return expects_lr<size_t>(count);
		}
		expects_lr<chainstate::temporary_state_resolution> chainstate::resolve_temporary_state(uint32_t type, ledger::block_changelog* changelog, const option<std::string_view>& column, const option<std::string_view>& row, uint64_t block_number)
		{
			auto& multiform_storage = get_multiform_storage(type);
			temporary_state_resolution result;
			result.storage = &multiform_storage;
			result.in_use = false;
			if (!changelog)
				return result;

			auto uses = multiform_storage.uses();
			auto storage = changelog->temporary_state.topics.find(type);
			auto temporary = storage != changelog->temporary_state.topics.end();
			if (temporary)
				multiform_storage = ledger::storage_index_ptr((sqlite::connection*)storage->second);
			
			multiform_writer writer;
			fill_multiform_writer_from_block_changelog(&writer.blobs, type, column, row, changelog);
			writer.blobs.erase(std::remove_if(writer.blobs.begin(), writer.blobs.end(), [&](const multiform_blob& value)
			{
				auto it = changelog->temporary_state.effects.find(value.message.data);
				return it != changelog->temporary_state.effects.end() && it->second == std::string_view((char*)value.rank, sizeof(value.rank));
			}), writer.blobs.end());
			result.in_use = temporary;
			if (writer.blobs.empty())
			{
				multiform_storage.set_uses(uses);
				return result;
			}

			auto status = fill_multiform_writer_from_storage(&writer, &multiform_storage);
			if (!status)
			{
				multiform_storage.set_uses(uses);
				return status.error();
			}

			if (!temporary)
			{
				auto transaction = multiform_storage.tx_begin(__func__, sqlite::isolation::default_isolation);
				if (!transaction)
				{
					multiform_storage.set_uses(uses);
					return layer_exception(ledger::storage_util::error_of(transaction));
				}
			}

			sqlite::expects_db<sqlite::cursor> cursor = sqlite::database_exception(string());
			auto rollback_temporary_state = [&]()
			{
				changelog->temporary_state.effects.clear();
				changelog->temporary_state.topics.erase(type);
				multiform_storage.tx_rollback(__func__);
				multiform_storage.set_uses(uses);
			};

			auto* storage_ptr = multiform_storage.ptr();
			for (auto& item : writer.blobs)
			{
				auto* statement = writer.commit_multiform_column_data;
				storage_ptr->bind_blob(statement, 0, item.column);
				storage_ptr->bind_int64(statement, 1, 0);

				cursor = multiform_storage.prepared_query(__func__, statement);
				if (!cursor || cursor->error_or_empty())
				{
					rollback_temporary_state();
					return layer_exception(cursor->empty() ? "multiform state column not linked" : ledger::storage_util::error_of(cursor));
				}

				statement = writer.commit_multiform_row_data;
				storage_ptr->bind_blob(statement, 0, item.row);
				storage_ptr->bind_int64(statement, 1, 0);

				uint64_t column_number = cursor->first().front().get_column(0).get().get_integer();
				cursor = multiform_storage.prepared_query(__func__, statement);
				if (!cursor || cursor->error_or_empty())
				{
					rollback_temporary_state();
					return layer_exception(cursor->empty() ? "multiform state row not linked" : ledger::storage_util::error_of(cursor));
				}

				uint64_t row_number = cursor->first().front().get_column(0).get().get_integer();
				if (block_number > 0)
				{
					item.context->as_rank().encode(item.rank);
					statement = writer.commit_snapshot_data;
					storage_ptr->bind_int64(statement, 0, column_number);
					storage_ptr->bind_int64(statement, 1, row_number);
					storage_ptr->bind_int64(statement, 2, 0);
					storage_ptr->bind_blob(statement, 3, std::string_view((char*)item.rank, sizeof(item.rank)));
					storage_ptr->bind_boolean(statement, 4, item.change->erase);
				}
				else if (item.change->erase)
				{
					statement = writer.erase_multiform_data;
					storage_ptr->bind_int64(statement, 0, column_number);
					storage_ptr->bind_int64(statement, 1, row_number);
				}
				else
				{
					item.context->as_rank().encode(item.rank);
					statement = writer.commit_multiform_data;
					storage_ptr->bind_int64(statement, 0, column_number);
					storage_ptr->bind_int64(statement, 1, row_number);
					storage_ptr->bind_int64(statement, 2, 0);
					storage_ptr->bind_blob(statement, 3, std::string_view((char*)item.rank, sizeof(item.rank)));
				}

				cursor = multiform_storage.prepared_query(__func__, statement);
				if (!cursor || cursor->error())
				{
					rollback_temporary_state();
					return layer_exception(ledger::storage_util::error_of(cursor));
				}
			}

			storage_ptr->add_ref();
			multiform_storage.set_uses(uses);
			changelog->temporary_state.topics[type] = storage_ptr;
			for (auto& item : writer.blobs)
				changelog->temporary_state.effects[item.message.data] = string((char*)item.rank, sizeof(item.rank));

			return result;
		}
		expects_lr<void> chainstate::clear_temporary_state(ledger::block_changelog* changelog)
		{
			VI_ASSERT(changelog != nullptr, "changelog should be set");
			changelog->temporary_state.effects.clear();
			if (changelog->temporary_state.topics.empty())
				return expectation::met;

			expects_lr<void> result = expectation::met;
			for (auto& topic : changelog->temporary_state.topics)
			{
				auto storage = ledger::storage_index_ptr((sqlite::connection*)topic.second, true);
				auto status = storage.tx_rollback(__func__);
				if (!status)
					result = layer_exception(ledger::storage_util::error_of(status));
			}

			changelog->temporary_state.topics.clear();
			return result;
		}
		ledger::storage_index_ptr& chainstate::get_uniform_storage(uint32_t type)
		{
			for (size_t i = 0; i < uniform_local_storage.size(); i++)
			{
				auto& child = uniform_local_storage[i];
				if (child.type != type)
					continue;

				if (!child.local_storage.may_use())
				{
					auto& parent = parent_chainstate->uniform_local_storage[i];
					if (!parent.local_storage.may_use())
						parent.local_storage = ledger::storage_index_ptr(ledger::storage_util::index_storage_named_of("chainindex", stringify::text("uniformdata.0x%x", type), &chainstate::make_schema));
					child.local_storage = parent.local_storage;
				}

				return child.local_storage;
			}

			VI_PANIC(false, "uniform storage type not recognized");
			return alias_local_storage;
		}
		ledger::storage_index_ptr& chainstate::get_multiform_storage(uint32_t type)
		{
			for (size_t i = 0; i < multiform_local_storage.size(); i++)
			{
				auto& child = multiform_local_storage[i];
				if (child.type != type)
					continue;

				if (!child.local_storage.may_use())
				{
					auto& parent = parent_chainstate->multiform_local_storage[i];
					if (!parent.local_storage.may_use())
						parent.local_storage = ledger::storage_index_ptr(ledger::storage_util::index_storage_named_of("chainindex", stringify::text("multiformdata.0x%x", type), &chainstate::make_schema));
					child.local_storage = parent.local_storage;
				}

				return child.local_storage;
			}

			VI_PANIC(false, "multiform storage type not recognized");
			return alias_local_storage;
		}
		ledger::storage_index_ptr& chainstate::get_block_storage()
		{
			if (!block_local_storage.may_use())
			{
				if (!parent_chainstate->block_local_storage.may_use())
					parent_chainstate->block_local_storage = ledger::storage_index_ptr(ledger::storage_util::index_storage_named_of("chainindex", "blockdata", &chainstate::make_schema));
				block_local_storage = parent_chainstate->block_local_storage;
			}
			return block_local_storage;
		}
		ledger::storage_index_ptr& chainstate::get_account_storage()
		{
			if (!account_local_storage.may_use())
			{
				if (!parent_chainstate->account_local_storage.may_use())
					parent_chainstate->account_local_storage = ledger::storage_index_ptr(ledger::storage_util::index_storage_named_of("chainindex", "accountdata", &chainstate::make_schema));
				account_local_storage = parent_chainstate->account_local_storage;
			}
			return account_local_storage;
		}
		ledger::storage_index_ptr& chainstate::get_tx_storage()
		{
			if (!tx_local_storage.may_use())
			{
				if (!parent_chainstate->tx_local_storage.may_use())
					parent_chainstate->tx_local_storage = ledger::storage_index_ptr(ledger::storage_util::index_storage_named_of("chainindex", "txdata", &chainstate::make_schema));
				tx_local_storage = parent_chainstate->tx_local_storage;
			}
			return tx_local_storage;
		}
		ledger::storage_index_ptr& chainstate::get_party_storage()
		{
			if (!party_local_storage.may_use())
			{
				if (!parent_chainstate->party_local_storage.may_use())
					parent_chainstate->party_local_storage = ledger::storage_index_ptr(ledger::storage_util::index_storage_named_of("chainindex", "partydata", &chainstate::make_schema));
				party_local_storage = parent_chainstate->party_local_storage;
			}
			return party_local_storage;
		}
		ledger::storage_index_ptr& chainstate::get_alias_storage()
		{
			if (!alias_local_storage.may_use())
			{
				if (!parent_chainstate->alias_local_storage.may_use())
					parent_chainstate->alias_local_storage = ledger::storage_index_ptr(ledger::storage_util::index_storage_named_of("chainindex", "aliasdata", &chainstate::make_schema));
				alias_local_storage = parent_chainstate->alias_local_storage;
			}
			return alias_local_storage;
		}
		ledger::storage_blob_ptr& chainstate::get_blob_storage()
		{
			if (!blob_local_storage.may_use())
			{
				if (!parent_chainstate->blob_local_storage.may_use())
					parent_chainstate->blob_local_storage = ledger::storage_blob_ptr(ledger::storage_util::blob_storage_of("chainblob"));
				blob_local_storage = parent_chainstate->blob_local_storage;
			}
			return blob_local_storage;
		}
		chainstate::uniform_storage_map& chainstate::get_uniform_multi_storage()
		{
			for (uint32_t type : states::resolver::get_uniform_types())
				get_uniform_storage(type);
			return uniform_local_storage;
		}
		chainstate::multiform_storage_map& chainstate::get_multiform_multi_storage()
		{
			for (uint32_t type : states::resolver::get_multiform_types())
				get_multiform_storage(type);
			return multiform_local_storage;
		}
		ledger::storage_util::multi_storage_index_ptr chainstate::get_multi_storage()
		{
			auto& uniform_multi_storage = get_uniform_multi_storage();
			auto& multiform_multi_storage = get_multiform_multi_storage();
			auto& block_storage = get_block_storage();
			auto& account_storage = get_account_storage();
			auto& tx_storage = get_tx_storage();
			auto& party_storage = get_party_storage();
			auto& alias_storage = get_alias_storage();
			auto result = ledger::storage_util::multi_storage_index_ptr();
			result.reserve(uniform_local_storage.size() + multiform_local_storage.size() + 5);
			for (auto& [uniform_storage, type] : uniform_multi_storage)
				result.insert(&uniform_storage);
			for (auto& [multiform_storage, type] : multiform_multi_storage)
				result.insert(&multiform_storage);
			result.insert(&block_storage);
			result.insert(&account_storage);
			result.insert(&tx_storage);
			result.insert(&party_storage);
			result.insert(&alias_storage);
			return result;
		}
		uint32_t chainstate::get_queries() const
		{
			uint32_t queries = blob_local_storage.uses() + block_local_storage.uses() + account_local_storage.uses() + tx_local_storage.uses() + party_local_storage.uses() + alias_local_storage.uses();
			for (auto& [uniform_storage, type] : uniform_local_storage)
				queries += uniform_storage.uses();
			for (auto& [multiform_storage, type] : multiform_local_storage)
				queries += multiform_storage.uses();
			return queries;
		}
		bool chainstate::make_schema(sqlite::connection* connection, const std::string_view& name)
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
			command.front() = command.back() = ' ';
			stringify::trim(command);

			auto cursor = connection->query(command);
			cursor.report("chainstate configuration failed");
			return (cursor && !cursor->error());
		}
	}
}