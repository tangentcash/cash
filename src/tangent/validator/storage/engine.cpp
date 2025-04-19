#include "engine.h"
#ifdef TAN_ROCKSDB
#include "rocksdb/db.h"
#endif

namespace tangent
{
	namespace ledger
	{
#ifdef TAN_ROCKSDB
		static const rocksdb::ReadOptions& get_blob_read_options()
		{
			static rocksdb::ReadOptions options;
			return options;
		}
		static const rocksdb::WriteOptions& get_blob_write_options()
		{
			static rocksdb::WriteOptions options;
			return options;
		}
#endif
		static sqlite::session_id resolve_transaction_session(sqlite::connection* storage, uptr<permanent_storage::multi_session_id>& transaction)
		{
			if (!transaction || transaction->empty())
				return nullptr;

			auto it = transaction->find(storage);
			return it != transaction->end() ? it->second : nullptr;
		}
		static thread_local std::atomic<uint64_t> thread_queries = 0;
		uint64_t storage_util::get_thread_queries()
		{
			return thread_queries;
		}

		mutable_storage::~mutable_storage()
		{
			if (storage)
				protocol::change().database.unload_index(std::move(storage));
		}
		sqlite::expects_db<void> mutable_storage::tx_begin(const std::string_view& label, const std::string_view& operation, sqlite::isolation type)
		{
			if (transaction != nullptr)
				return sqlite::database_exception("rollback or commit current transaction");

			VI_ASSERT(storage, "storage connection not initialized (transaction begin)");
			auto cursor = storage->tx_begin(type);
#ifdef _DEBUG
			string error = error_of(cursor);
			if (!error.empty() && protocol::now().user.storage.logging)
				VI_ERR("[indexdb] operation %.*s::%.*s error (transaction begin): %s", (int)label.size(), label.data(), (int)operation.size(), operation.data(), error.c_str());
#endif
			++queries; ++thread_queries;
			transaction = *cursor;
			return expectation::met;
		}
		sqlite::expects_db<void> mutable_storage::tx_commit(const std::string_view& label, const std::string_view& operation)
		{
			if (!transaction)
				return sqlite::database_exception("current transaction not found");

			VI_ASSERT(storage, "storage connection not initialized (transaction commit)");
			auto cursor = storage->tx_commit(transaction);
#ifdef _DEBUG
			string error = error_of(cursor);
			if (!error.empty() && protocol::now().user.storage.logging)
				VI_ERR("[indexdb] operation %.*s::%.*s error (transaction commit): %s", (int)label.size(), label.data(), (int)operation.size(), operation.data(), error.c_str());
#endif
			++queries; ++thread_queries;
			transaction = nullptr;
			return cursor;
		}
		sqlite::expects_db<void> mutable_storage::tx_rollback(const std::string_view& label, const std::string_view& operation)
		{
			if (!transaction)
				return sqlite::database_exception("current transaction not found");

			VI_ASSERT(storage, "storage connection not initialized (transaction rollback)");
			auto cursor = storage->tx_rollback(transaction);
#ifdef _DEBUG
			string error = error_of(cursor);
			if (!error.empty() && protocol::now().user.storage.logging)
				VI_ERR("[indexdb] operation %.*s::%.*s error (transaction rollback): %s", (int)label.size(), label.data(), (int)operation.size(), operation.data(), error.c_str());
#endif
			++queries; ++thread_queries;
			transaction = nullptr;
			return cursor;
		}
		sqlite::expects_db<sqlite::cursor> mutable_storage::query(const std::string_view& label, const std::string_view& operation, const std::string_view& command, size_t query_ops)
		{
			VI_ASSERT(storage, "storage connection not initialized (operation: %.*s::%.*s)", (int)label.size(), label.data(), (int)operation.size(), operation.data());
			auto cursor = storage->query(command, query_ops, transaction);
#ifdef _DEBUG
			string error = error_of(cursor);
			if (!error.empty() && protocol::now().user.storage.logging)
				VI_ERR("[indexdb] operation %.*s::%.*s failed: %s", (int)label.size(), label.data(), (int)operation.size(), operation.data(), error.c_str());
#endif
			++queries; ++thread_queries;
			return cursor;
		}
		sqlite::expects_db<sqlite::cursor> mutable_storage::emplace_query(const std::string_view& label, const std::string_view& operation, const std::string_view& command, schema_list* map, size_t query_ops)
		{
			VI_ASSERT(storage, "storage connection not initialized (operation: %.*s::%.*s)", (int)label.size(), label.data(), (int)operation.size(), operation.data());
			auto cursor = storage->emplace_query(command, map, query_ops, transaction);
#ifdef _DEBUG
			string error = error_of(cursor);
			if (!error.empty() && protocol::now().user.storage.logging)
				VI_ERR("[indexdb] operation %.*s::%.*s failed: %s", (int)label.size(), label.data(), (int)operation.size(), operation.data(), error.c_str());
#endif
			++queries; ++thread_queries;
			return cursor;
		}
		string mutable_storage::error_of(sqlite::expects_db<sqlite::session_id>& cursor)
		{
			string error;
			if (!cursor)
				error = cursor.what();
			return error;
		}
		string mutable_storage::error_of(sqlite::expects_db<void>& cursor)
		{
			string error;
			if (!cursor)
				error = cursor.what();
			return error;
		}
		string mutable_storage::error_of(sqlite::expects_db<sqlite::cursor>& cursor)
		{
			string error;
			if (cursor)
			{
				if (cursor->error())
				{
					for (auto& response : *cursor)
					{
						if (response.error())
						{
							if (!error.empty())
								error += "; ";
							error += response.get_status_text();
						}
					}
				}
			}
			else
				error = cursor.what();
			return error;
		}
		void mutable_storage::storage_of(const std::string_view& path)
		{
			storage = protocol::change().database.load_index(path, [this, &path](sqlite::connection* intermediate)
			{
				size_t last_queries = queries;
				storage = intermediate;
				VI_PANIC(reconstruct_storage(), "storage verification error (path = %.*s)", (int)path.size(), path.data());
				storage.reset();
				queries = last_queries;
			});
			VI_PANIC(storage, "storage connection error (path = %.*s)", (int)path.size(), path.data());
		}
		bool mutable_storage::query_used() const
		{
			return queries > 0;
		}
		size_t mutable_storage::get_queries() const
		{
			return queries;
		}

		sqlite::expects_db<void> permanent_storage::multi_tx_begin(const std::string_view& label, const std::string_view& operation, sqlite::isolation type)
		{
			if (transaction)
				return sqlite::database_exception("rollback or commit current transaction");

			auto index = get_index_storages();
			transaction = memory::init<multi_session_id>();
			transaction->reserve(index.size());
			for (auto& storage : index)
				(**transaction)[storage] = nullptr;

			std::mutex mutex;
			sqlite::expects_db<void> status = expectation::met;
			parallel::wail_all(parallel::for_each_sequential(index.begin(), index.end(), index.size(), ELEMENTS_FEW, [&](sqlite::connection* storage)
			{
				auto result = tx_begin(storage, label, operation, type);
				if (!result)
				{
					umutex<std::mutex> unique(mutex);
					if (!status)
						status = sqlite::database_exception(status.error().message() + ", " + result.error().message());
					else
						status = std::move(result.error());
				}
				else
					(**transaction)[storage] = *result;
			}));
			if (status)
				return expectation::met;

			for (auto& substorage : **transaction)
			{
				if (substorage.second != nullptr)
					tx_rollback(substorage.first, label, operation, substorage.second);
			}
			return status.error();
		}
		sqlite::expects_db<void> permanent_storage::multi_tx_commit(const std::string_view& label, const std::string_view& operation)
		{
			if (!transaction)
				return sqlite::database_exception("current transaction not found");

			std::mutex mutex;
			sqlite::expects_db<void> status = expectation::met;
			parallel::wail_all(parallel::for_each_sequential(transaction->begin(), transaction->end(), transaction->size(), ELEMENTS_FEW, [&](const std::pair<sqlite::connection* const, sqlite::session_id>& storage)
			{
				auto result = tx_commit(storage.first, label, operation, storage.second);
				if (result)
					return;

				umutex<std::mutex> unique(mutex);
				if (!status)
					status = sqlite::database_exception(status.error().message() + ", " + result.error().message());
				else
					status = std::move(result.error());
			}));
			transaction.destroy();
			return status;
		}
		sqlite::expects_db<void> permanent_storage::multi_tx_rollback(const std::string_view& label, const std::string_view& operation)
		{
			if (!transaction)
				return sqlite::database_exception("current transaction not found");

			std::mutex mutex;
			sqlite::expects_db<void> status = expectation::met;
			parallel::wail_all(parallel::for_each_sequential(transaction->begin(), transaction->end(), transaction->size(), ELEMENTS_FEW, [&](const std::pair<sqlite::connection* const, sqlite::session_id>& storage)
			{
				auto result = tx_rollback(storage.first, label, operation, storage.second);
				if (result)
					return;

				umutex<std::mutex> unique(mutex);
				if (!status)
					status = sqlite::database_exception(status.error().message() + ", " + result.error().message());
				else
					status = std::move(result.error());
			}));
			transaction.destroy();
			return status;
		}
		sqlite::expects_db<sqlite::session_id> permanent_storage::tx_begin(sqlite::connection* storage, const std::string_view& label, const std::string_view& operation, sqlite::isolation type)
		{
			VI_ASSERT(storage, "storage connection not initialized (transaction begin)");
			auto cursor = storage->tx_begin(type);
#ifdef _DEBUG
			string error = error_of(cursor);
			if (!error.empty() && protocol::now().user.storage.logging)
				VI_ERR("[indexdb] operation %.*s::%.*s error (transaction begin): %s", (int)label.size(), label.data(), (int)operation.size(), operation.data(), error.c_str());
#endif
			++queries; ++thread_queries;
			return cursor;
		}
		sqlite::expects_db<void> permanent_storage::tx_commit(sqlite::connection* storage, const std::string_view& label, const std::string_view& operation, sqlite::session_id session)
		{
			VI_ASSERT(storage, "storage connection not initialized (transaction commit)");
			auto cursor = storage->tx_commit(session);
#ifdef _DEBUG
			string error = error_of(cursor);
			if (!error.empty() && protocol::now().user.storage.logging)
				VI_ERR("[indexdb] operation %.*s::%.*s error (transaction commit): %s", (int)label.size(), label.data(), (int)operation.size(), operation.data(), error.c_str());
#endif
			++queries; ++thread_queries;
			return cursor;
		}
		sqlite::expects_db<void> permanent_storage::tx_rollback(sqlite::connection* storage, const std::string_view& label, const std::string_view& operation, sqlite::session_id session)
		{
			VI_ASSERT(storage, "storage connection not initialized (transaction rollback)");
			auto cursor = storage->tx_rollback(session);
#ifdef _DEBUG
			string error = error_of(cursor);
			if (!error.empty() && protocol::now().user.storage.logging)
				VI_ERR("[indexdb] operation %.*s::%.*s error (transaction rollback): %s", (int)label.size(), label.data(), (int)operation.size(), operation.data(), error.c_str());
#endif
			++queries; ++thread_queries;
			return cursor;
		}
		sqlite::expects_db<sqlite::cursor> permanent_storage::query(sqlite::connection* storage, const std::string_view& label, const std::string_view& operation, const std::string_view& command, size_t query_ops)
		{
			VI_ASSERT(storage, "storage connection not initialized (operation: %.*s::%.*s)", (int)label.size(), label.data(), (int)operation.size(), operation.data());
			auto cursor = storage->query(command, query_ops, resolve_transaction_session(storage, transaction));
#ifdef _DEBUG
			string error = error_of(cursor);
			if (!error.empty() && protocol::now().user.storage.logging)
				VI_ERR("[indexdb] operation %.*s::%.*s failed: %s", (int)label.size(), label.data(), (int)operation.size(), operation.data(), error.c_str());
#endif
			++queries; ++thread_queries;
			return cursor;
		}
		sqlite::expects_db<sqlite::cursor> permanent_storage::emplace_query(sqlite::connection* storage, const std::string_view& label, const std::string_view& operation, const std::string_view& command, schema_list* map, size_t query_ops)
		{
			VI_ASSERT(storage, "storage connection not initialized (operation: %.*s::%.*s)", (int)label.size(), label.data(), (int)operation.size(), operation.data());
			auto cursor = storage->emplace_query(command, map, query_ops, resolve_transaction_session(storage, transaction));
#ifdef _DEBUG
			string error = error_of(cursor);
			if (!error.empty() && protocol::now().user.storage.logging)
				VI_ERR("[indexdb] operation %.*s::%.*s failed: %s", (int)label.size(), label.data(), (int)operation.size(), operation.data(), error.c_str());
#endif
			++queries; ++thread_queries;
			return cursor;
		}
		sqlite::expects_db<sqlite::cursor> permanent_storage::prepared_query(sqlite::connection* storage, const std::string_view& label, const std::string_view& operation, sqlite::tstatement* statement)
		{
			VI_ASSERT(storage, "storage connection not initialized (operation: %.*s::%.*s)", (int)label.size(), label.data(), (int)operation.size(), operation.data());
			auto cursor = storage->prepared_query(statement, resolve_transaction_session(storage, transaction));
#ifdef _DEBUG
			string error = error_of(cursor);
			if (!error.empty() && protocol::now().user.storage.logging)
				VI_ERR("[indexdb] operation %.*s::%.*s failed: %s", (int)label.size(), label.data(), (int)operation.size(), operation.data(), error.c_str());
#endif
			++queries; ++thread_queries;
			return cursor;
		}
		sqlite::expects_db<string> permanent_storage::load(const std::string_view& label, const std::string_view& operation, const std::string_view& key)
		{
#ifdef TAN_ROCKSDB
			VI_ASSERT(blob, "storage connection not initialized (operation: %.*s::%.*s)", (int)label.size(), label.data(), (int)operation.size(), operation.data());
			rocksdb::PinnableSlice value;
			auto status = blob->Get(get_blob_read_options(), blob->DefaultColumnFamily(), rocksdb::Slice(key.data(), key.size()), &value);
			++queries; ++thread_queries;
			if (!status.ok())
			{
				auto message = status.ToString();
				if (!status.IsNotFound() && protocol::now().user.storage.logging)
					VI_ERR("[blobdb] operation %.*s::%.*s failed: %s", (int)label.size(), label.data(), (int)operation.size(), operation.data(), message.c_str());
				return sqlite::expects_db<string>(sqlite::database_exception(string(message.begin(), message.end())));
			}

			string result = string(value.data(), value.size());
			return sqlite::expects_db<string>(std::move(result));
#else
			return sqlite::database_exception("blob db not supported");
#endif
		}
		sqlite::expects_db<void> permanent_storage::store(const std::string_view& label, const std::string_view& operation, const std::string_view& key, const std::string_view& value)
		{
#ifdef TAN_ROCKSDB
			VI_ASSERT(blob, "storage connection not initialized (operation: %.*s::%.*s)", (int)label.size(), label.data(), (int)operation.size(), operation.data());
			auto status = value.empty() ? blob->Delete(get_blob_write_options(), rocksdb::Slice(key.data(), key.size())) : blob->Put(get_blob_write_options(), rocksdb::Slice(key.data(), key.size()), rocksdb::Slice(value.data(), value.size()));
			++queries; ++thread_queries;
			if (!status.ok())
			{
				auto message = status.ToString();
				if (!status.IsNotFound() && protocol::now().user.storage.logging)
					VI_ERR("[blobdb] operation %.*s::%.*s failed: %s", (int)label.size(), label.data(), (int)operation.size(), operation.data(), message.c_str());
				return sqlite::database_exception(string(message.begin(), message.end()));
			}

			return expectation::met;
#else
			return sqlite::database_exception("blob db not supported");
#endif
		}
		sqlite::expects_db<void> permanent_storage::clear(const std::string_view& label, const std::string_view& operation, const std::string_view& table_ids)
		{
#ifdef TAN_ROCKSDB
			VI_ASSERT(blob, "storage connection not initialized (operation: %.*s::%.*s)", (int)label.size(), label.data(), (int)operation.size(), operation.data());
			auto& read = get_blob_read_options();
			auto& write = get_blob_write_options();
			auto it = blob->NewIterator(read);
			it->SeekToFirst();
			while (it->Valid())
			{
				if (table_ids.find(*it->key().data()))
					blob->Delete(write, it->key());
				it->Next();
			}
			delete it;
			return expectation::met;
#else
			return sqlite::database_exception("blob db not supported");
#endif
		}
		string permanent_storage::error_of(sqlite::expects_db<sqlite::session_id>& cursor)
		{
			string error;
			if (!cursor)
				error = cursor.what();
			return error;
		}
		string permanent_storage::error_of(sqlite::expects_db<void>& cursor)
		{
			string error;
			if (!cursor)
				error = cursor.what();
			return error;
		}
		string permanent_storage::error_of(sqlite::expects_db<sqlite::cursor>& cursor)
		{
			string error;
			if (cursor)
			{
				if (cursor->error())
				{
					for (auto& response : *cursor)
					{
						if (response.error())
						{
							if (!error.empty())
								error += "; ";
							error += response.get_status_text();
						}
					}
				}
			}
			else
				error = cursor.what();
			return error;
		}
		uptr<sqlite::connection> permanent_storage::index_storage_of(const std::string_view& path, const std::string_view& name)
		{
			uptr<sqlite::connection> storage = protocol::change().database.load_index(string(path) + "." + string(name), [this, &path, &name](sqlite::connection* intermediate)
			{
				size_t last_queries = queries;
				VI_PANIC(reconstruct_index_storage(intermediate, name), "storage verification error (path = %.*s)", (int)path.size(), path.data());
				queries = last_queries;
			});
			VI_PANIC(storage, "index storage connection error (path = %.*s)", (int)path.size(), path.data());
			return storage;
		}
		void permanent_storage::blob_storage_of(const std::string_view& path)
		{
			blob = protocol::change().database.load_blob(path);
			VI_PANIC(blob, "blob storage connection error (path = %.*s)", (int)path.size(), path.data());
#ifdef TAN_ROCKSDB
			auto threads = os::hw::get_quantity_info().physical;
			auto options = blob->GetOptions();
			if (protocol::now().user.storage.compaction_threads_ratio > 0.0)
				options.env->SetBackgroundThreads((int)std::max(std::ceil(threads * protocol::now().user.storage.compaction_threads_ratio), 1.0), rocksdb::Env::Priority::LOW);
			if (protocol::now().user.storage.flush_threads_ratio > 0.0)
				options.env->SetBackgroundThreads((int)std::max(std::ceil(threads * protocol::now().user.storage.flush_threads_ratio), 1.0), rocksdb::Env::Priority::HIGH);
#endif
		}
		void permanent_storage::unload_index_of(uptr<sqlite::connection>&& storage, bool borrows)
		{
			if (borrows)
				storage.reset();
			else if (storage)
				protocol::change().database.unload_index(std::move(storage));
		}
		bool permanent_storage::query_used() const
		{
			return queries > 0;
		}
		size_t permanent_storage::get_queries() const
		{
			return queries;
		}
	}
}