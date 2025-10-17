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
		static thread_local uint32_t thread_invocations = 0;
		sqlite::expects_db<void> storage_util::multi_tx_begin(const std::string_view& operation, sqlite::isolation type, multi_storage_index_ptr& ptr)
		{
			std::mutex mutex;
			sqlite::expects_db<void> status = expectation::met;
			parallel::wail_all(parallel::for_each_sequential(ptr.begin(), ptr.end(), ptr.size(), ELEMENTS_FEW, [&](storage_index_ptr* target)
			{
				auto result = target->tx_begin(operation, type);
				if (result)
					return;

				umutex<std::mutex> unique(mutex);
				if (!status)
					status = sqlite::database_exception(status.error().message() + ", " + result.error().message());
				else
					status = std::move(result.error());
			}));
			if (status)
				return expectation::met;

			for (auto& target : ptr)
			{
				if (target->in_transaction())
					target->tx_rollback(operation);
			}
			return status.error();
		}
		sqlite::expects_db<void> storage_util::multi_tx_commit(const std::string_view& operation, multi_storage_index_ptr&& ptr)
		{
			std::mutex mutex;
			sqlite::expects_db<void> status = expectation::met;
			parallel::wail_all(parallel::for_each_sequential(ptr.begin(), ptr.end(), ptr.size(), ELEMENTS_FEW, [&](storage_index_ptr* target)
			{
				auto result = target->tx_commit(operation);
				if (result)
					return;

				umutex<std::mutex> unique(mutex);
				if (!status)
					status = sqlite::database_exception(status.error().message() + ", " + result.error().message());
				else
					status = std::move(result.error());
			}));
			ptr.clear();
			return status;
		}
		sqlite::expects_db<void> storage_util::multi_tx_rollback(const std::string_view& operation, multi_storage_index_ptr&& ptr)
		{
			std::mutex mutex;
			sqlite::expects_db<void> status = expectation::met;
			parallel::wail_all(parallel::for_each_sequential(ptr.begin(), ptr.end(), ptr.size(), ELEMENTS_FEW, [&](storage_index_ptr* target)
			{
				auto result = target->tx_rollback(operation);
				if (result)
					return;

				umutex<std::mutex> unique(mutex);
				if (!status)
					status = sqlite::database_exception(status.error().message() + ", " + result.error().message());
				else
					status = std::move(result.error());
			}));
			ptr.clear();
			return status;
		}
		uref<sqlite::connection> storage_util::index_storage_of(const std::string_view& location, const std::function<bool(sqlite::connection*)>& callback)
		{
			auto connection = protocol::change().database.pull_index(location, [&location, &callback](sqlite::connection* connection)
			{
				VI_PANIC(callback(connection), "index configuration error (path: %.*s)", (int)location.size(), location.data());
			});
			VI_PANIC(connection, "index connection error (path: %.*s)", (int)location.size(), location.data());
			return connection;
		}
		uref<sqlite::connection> storage_util::index_storage_named_of(const std::string_view& location, const std::string_view& name, const std::function<bool(sqlite::connection*, const std::string_view&)>& callback)
		{
			string full_location = string(location) + "." + string(name);
			return index_storage_of(full_location, std::bind(callback, std::placeholders::_1, name));
		}
		rocksdb::DB* storage_util::blob_storage_of(const std::string_view& location)
		{
			auto* connection = protocol::change().database.pull_blob_ref(location);
			VI_PANIC(connection, "blob connection error (path: %.*s)", (int)location.size(), location.data());
			return connection;
		}
		string storage_util::error_of(sqlite::expects_db<sqlite::session_id>& cursor)
		{
			string error;
			if (!cursor)
				error = cursor.what();
			return error;
		}
		string storage_util::error_of(sqlite::expects_db<void>& cursor)
		{
			string error;
			if (!cursor)
				error = cursor.what();
			return error;
		}
		string storage_util::error_of(sqlite::expects_db<sqlite::cursor>& cursor)
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
		string storage_util::error_of(sqlite::expects_db<sqlite::tstatement*>& cursor)
		{
			string error;
			if (!cursor)
				error = cursor.what();
			return error;
		}
		uint64_t storage_util::get_thread_invocations()
		{
			return thread_invocations;
		}

		storage_index_ptr::storage_index_ptr() : invocations(0), transaction(false)
		{
		}
		storage_index_ptr::storage_index_ptr(uref<sqlite::connection>&& new_connection, bool in_transaction) : connection(std::move(new_connection)), invocations(0), transaction(in_transaction)
		{
			VI_PANIC(connection, "index connection required");
		}
		storage_index_ptr::storage_index_ptr(const storage_index_ptr& other) : connection(other.connection), invocations(0), transaction(false)
		{
		}
		storage_index_ptr::storage_index_ptr(storage_index_ptr&& other) noexcept : connection(std::move(other.connection)), invocations(other.invocations), transaction(other.transaction)
		{
			other.invocations = 0;
			other.transaction = false;
		}
		storage_index_ptr::~storage_index_ptr()
		{
			if (connection)
				protocol::change().database.push_index(std::move(connection));
		}
		storage_index_ptr& storage_index_ptr::operator=(const storage_index_ptr& other)
		{
			if (this == &other)
				return *this;

			this->~storage_index_ptr();
			connection = other.connection;
			invocations = 0;
			transaction = false;
			return *this;
		}
		storage_index_ptr& storage_index_ptr::operator=(storage_index_ptr&& other) noexcept
		{
			if (this == &other)
				return *this;

			this->~storage_index_ptr();
			connection = std::move(other.connection);
			invocations = other.invocations;
			transaction = other.transaction;
			other.invocations = 0;
			other.transaction = false;
			return *this;
		}
		sqlite::expects_db<void> storage_index_ptr::tx_begin(const std::string_view& operation, sqlite::isolation type)
		{
			if (transaction)
				return sqlite::database_exception("rollback or commit current transaction");

			VI_ASSERT(connection, "connection not initialized (transaction begin)");
			auto cursor = connection->tx_begin(type);
#ifndef NDEBUG
			string error = storage_util::error_of(cursor);
			if (!error.empty() && protocol::now().user.storage.logging)
				VI_ERR("index storage operation %.*s error (transaction begin): %s", (int)operation.size(), operation.data(), error.c_str());
#endif
			++invocations; ++thread_invocations;
			if (!cursor)
				return cursor.error();

			transaction = true;
			return expectation::met;
		}
		sqlite::expects_db<void> storage_index_ptr::tx_commit(const std::string_view& operation)
		{
			if (!transaction)
				return sqlite::database_exception("current transaction not found");

			VI_ASSERT(connection, "connection not initialized (transaction commit)");
			auto cursor = connection->tx_commit(connection->get_connection());
#ifndef NDEBUG
			string error = storage_util::error_of(cursor);
			if (!error.empty() && protocol::now().user.storage.logging)
				VI_ERR("index storage operation %.*s error (transaction commit): %s", (int)operation.size(), operation.data(), error.c_str());
#endif
			++invocations; ++thread_invocations;
			transaction = false;
			return cursor;
		}
		sqlite::expects_db<void> storage_index_ptr::tx_rollback(const std::string_view& operation)
		{
			if (!transaction)
				return sqlite::database_exception("current transaction not found");

			VI_ASSERT(connection, "connection not initialized (transaction rollback)");
			auto cursor = connection->tx_rollback(connection->get_connection());
#ifndef NDEBUG
			string error = storage_util::error_of(cursor);
			if (!error.empty() && protocol::now().user.storage.logging)
				VI_ERR("index storage operation %.*s error (transaction rollback): %s", (int)operation.size(), operation.data(), error.c_str());
#endif
			++invocations; ++thread_invocations;
			transaction = false;
			return cursor;
		}
		sqlite::expects_db<sqlite::cursor> storage_index_ptr::query(const std::string_view& operation, const std::string_view& command, size_t query_ops)
		{
			VI_ASSERT(connection, "connection not initialized (operation: %.*s)", (int)operation.size(), operation.data());
			auto cursor = connection->query(command, query_ops, transaction ? connection->get_connection() : nullptr);
#ifndef NDEBUG
			string error = storage_util::error_of(cursor);
			if (!error.empty() && protocol::now().user.storage.logging)
				VI_ERR("index storage operation %.*s failed: %s", (int)operation.size(), operation.data(), error.c_str());
#endif
			++invocations; ++thread_invocations;
			return cursor;
		}
		sqlite::expects_db<sqlite::cursor> storage_index_ptr::emplace_query(const std::string_view& operation, const std::string_view& command, schema_list* map, size_t query_ops)
		{
			VI_ASSERT(connection, "connection not initialized (operation: %.*s)", (int)operation.size(), operation.data());
			auto cursor = connection->emplace_query(command, map, query_ops, transaction ? connection->get_connection() : nullptr);
#ifndef NDEBUG
			string error = storage_util::error_of(cursor);
			if (!error.empty() && protocol::now().user.storage.logging)
				VI_ERR("index storage operation %.*s failed: %s", (int)operation.size(), operation.data(), error.c_str());
#endif
			++invocations; ++thread_invocations;
			return cursor;
		}
		sqlite::expects_db<sqlite::cursor> storage_index_ptr::prepared_query(const std::string_view& operation, sqlite::tstatement* statement)
		{
			VI_ASSERT(connection, "connection not initialized (operation: %.*s)", (int)operation.size(), operation.data());
			auto cursor = connection->prepared_query(statement, transaction ? connection->get_connection() : nullptr);
#ifndef NDEBUG
			string error = storage_util::error_of(cursor);
			if (!error.empty() && protocol::now().user.storage.logging)
				VI_ERR("index storage operation %.*s failed: %s", (int)operation.size(), operation.data(), error.c_str());
#endif
			++invocations; ++thread_invocations;
			return cursor;
		}
		sqlite::expects_db<sqlite::tstatement*> storage_index_ptr::prepare_statement(const std::string_view& operation, const std::string_view& command)
		{
			VI_ASSERT(connection, "connection not initialized (operation: %.*s)", (int)operation.size(), operation.data());
			auto cursor = connection->prepare_statement(command, nullptr);
#ifndef NDEBUG
			string error = storage_util::error_of(cursor);
			if (!error.empty() && protocol::now().user.storage.logging)
				VI_ERR("index storage operation %.*s failed: %s", (int)operation.size(), operation.data(), error.c_str());
#endif
			return cursor;
		}
		sqlite::connection* storage_index_ptr::ptr() const
		{
			return *connection;
		}
		void storage_index_ptr::set_uses(uint32_t value)
		{
			invocations = value;
		}
		uint32_t storage_index_ptr::uses() const
		{
			return invocations;
		}
		bool storage_index_ptr::in_use() const
		{
			return invocations > 0;
		}
		bool storage_index_ptr::in_transaction() const
		{
			return transaction;
		}
		bool storage_index_ptr::may_use() const
		{
			return !!connection;
		}

		storage_blob_ptr::storage_blob_ptr() : connection(nullptr), invocations(0)
		{
		}
		storage_blob_ptr::storage_blob_ptr(rocksdb::DB* new_connection) : connection(new_connection), invocations(0)
		{
			VI_PANIC(connection, "blob connection required");
		}
		storage_blob_ptr::storage_blob_ptr(const storage_blob_ptr& other) : connection(other.connection), invocations(0)
		{
		}
		storage_blob_ptr::storage_blob_ptr(storage_blob_ptr&& other) noexcept : connection(other.connection), invocations(other.invocations)
		{
			other.connection = nullptr;
			other.invocations = 0;
		}
		storage_blob_ptr::~storage_blob_ptr()
		{
		}
		storage_blob_ptr& storage_blob_ptr::operator=(const storage_blob_ptr& other)
		{
			if (this == &other)
				return *this;

			this->~storage_blob_ptr();
			connection = other.connection;
			invocations = 0;
			return *this;
		}
		storage_blob_ptr& storage_blob_ptr::operator=(storage_blob_ptr&& other) noexcept
		{
			if (this == &other)
				return *this;

			this->~storage_blob_ptr();
			connection = other.connection;
			invocations = other.invocations;
			other.connection = nullptr;
			other.invocations = 0;
			return *this;
		}
		sqlite::expects_db<string> storage_blob_ptr::load(const std::string_view& operation, const std::string_view& key)
		{
#ifdef TAN_ROCKSDB
			VI_ASSERT(connection, "connection not initialized (operation: %.*s)", (int)operation.size(), operation.data());
			rocksdb::PinnableSlice value;
			auto status = connection->Get(get_blob_read_options(), connection->DefaultColumnFamily(), rocksdb::Slice(key.data(), key.size()), &value);
			++invocations; ++thread_invocations;
			if (!status.ok())
			{
				auto message = status.ToString();
				if (!status.IsNotFound() && protocol::now().user.storage.logging)
					VI_ERR("blob storage operation %.*s failed: %s", (int)operation.size(), operation.data(), message.c_str());
				return sqlite::expects_db<string>(sqlite::database_exception(string(message.begin(), message.end())));
			}

			string result = string(value.data(), value.size());
			return sqlite::expects_db<string>(std::move(result));
#else
			return sqlite::database_exception("blob db not supported");
#endif
		}
		sqlite::expects_db<void> storage_blob_ptr::store(const std::string_view& operation, const std::string_view& key, const std::string_view& value)
		{
#ifdef TAN_ROCKSDB
			VI_ASSERT(connection, "connection not initialized (operation: %.*s)", (int)operation.size(), operation.data());
			auto status = value.empty() ? connection->Delete(get_blob_write_options(), rocksdb::Slice(key.data(), key.size())) : connection->Put(get_blob_write_options(), rocksdb::Slice(key.data(), key.size()), rocksdb::Slice(value.data(), value.size()));
			++invocations; ++thread_invocations;
			if (!status.ok())
			{
				auto message = status.ToString();
				if (!status.IsNotFound() && protocol::now().user.storage.logging)
					VI_ERR("connection storage operation %.*s failed: %s", (int)operation.size(), operation.data(), message.c_str());
				return sqlite::database_exception(string(message.begin(), message.end()));
			}

			return expectation::met;
#else
			return sqlite::database_exception("blob db not supported");
#endif
		}
		sqlite::expects_db<void> storage_blob_ptr::clear(const std::string_view& operation, const std::string_view& table_ids)
		{
#ifdef TAN_ROCKSDB
			VI_ASSERT(connection, "connection not initialized (operation: %.*s)", (int)operation.size(), operation.data());
			auto& read = get_blob_read_options();
			auto& write = get_blob_write_options();
			auto it = connection->NewIterator(read);
			it->SeekToFirst();
			while (it->Valid())
			{
				if (table_ids.find(*it->key().data()))
				{
					connection->Delete(write, it->key());
					++invocations; ++thread_invocations;
				}
				it->Next();
			}
			delete it;
			return expectation::met;
#else
			return sqlite::database_exception("blob db not supported");
#endif
		}
		void storage_blob_ptr::set_uses(uint32_t value)
		{
			invocations = value;
		}
		uint32_t storage_blob_ptr::uses() const
		{
			return invocations;
		}
		bool storage_blob_ptr::in_use() const
		{
			return invocations > 0;
		}
		bool storage_blob_ptr::may_use() const
		{
			return connection != nullptr;
		}
	}
}