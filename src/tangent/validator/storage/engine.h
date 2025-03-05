#ifndef TAN_STORAGE_ENGINE_H
#define TAN_STORAGE_ENGINE_H
#include "../../kernel/chain.h"

namespace tangent
{
	namespace ledger
	{
		class storage_util
		{
		public:
			static uint64_t get_thread_queries();
		};

		struct mutable_storage
		{
		private:
			std::atomic<uint64_t> queries = 0;

		protected:
			uptr<sqlite::connection> storage;
			sqlite::session_id transaction = nullptr;

		public:
			mutable_storage() = default;
			mutable_storage(const mutable_storage&) = delete;
			mutable_storage(mutable_storage&&) = delete;
			virtual ~mutable_storage();
			mutable_storage& operator=(const mutable_storage&) = delete;
			mutable_storage& operator=(mutable_storage&&) = delete;
			bool query_used() const;
			size_t get_queries() const;

		public:
			virtual sqlite::expects_db<void> tx_begin(const std::string_view& label, const std::string_view& operation, sqlite::isolation type);
			virtual sqlite::expects_db<void> tx_commit(const std::string_view& label, const std::string_view& operation);
			virtual sqlite::expects_db<void> tx_rollback(const std::string_view& label, const std::string_view& operation);

		protected:
			virtual sqlite::expects_db<sqlite::cursor> query(const std::string_view& label, const std::string_view& operation, const std::string_view& command, size_t query_ops = 0);
			virtual sqlite::expects_db<sqlite::cursor> emplace_query(const std::string_view& label, const std::string_view& operation, const std::string_view& command, schema_list* map, size_t query_ops = 0);
			virtual string error_of(sqlite::expects_db<sqlite::session_id>& cursor);
			virtual string error_of(sqlite::expects_db<void>& cursor);
			virtual string error_of(sqlite::expects_db<sqlite::cursor>& cursor);
			virtual void storage_of(const std::string_view& location);
			virtual bool reconstruct_storage() = 0;
		};

		struct permanent_storage
		{
		public:
			typedef unordered_map<sqlite::connection*, sqlite::session_id> multi_session_id;

		private:
			std::atomic<uint64_t> queries = 0;

		protected:
			uptr<multi_session_id> transaction;
			rocksdb::DB* blob = nullptr;

		public:
			permanent_storage() = default;
			permanent_storage(const permanent_storage&) = delete;
			permanent_storage(permanent_storage&&) = delete;
			virtual ~permanent_storage() = default;
			permanent_storage& operator=(const permanent_storage&) = delete;
			permanent_storage& operator=(permanent_storage&&) = delete;
			bool query_used() const;
			size_t get_queries() const;

		public:
			virtual sqlite::expects_db<void> multi_tx_begin(const std::string_view& label, const std::string_view& operation, sqlite::isolation type);
			virtual sqlite::expects_db<void> multi_tx_commit(const std::string_view& label, const std::string_view& operation);
			virtual sqlite::expects_db<void> multi_tx_rollback(const std::string_view& label, const std::string_view& operation);

		protected:
			virtual sqlite::expects_db<sqlite::session_id> tx_begin(sqlite::connection* storage, const std::string_view& label, const std::string_view& operation, sqlite::isolation type);
			virtual sqlite::expects_db<void> tx_commit(sqlite::connection* storage, const std::string_view& label, const std::string_view& operation, sqlite::session_id session);
			virtual sqlite::expects_db<void> tx_rollback(sqlite::connection* storage, const std::string_view& label, const std::string_view& operation, sqlite::session_id session);
			virtual sqlite::expects_db<sqlite::cursor> query(sqlite::connection* storage, const std::string_view& label, const std::string_view& operation, const std::string_view& command, size_t query_ops = 0);
			virtual sqlite::expects_db<sqlite::cursor> emplace_query(sqlite::connection* storage, const std::string_view& label, const std::string_view& operation, const std::string_view& command, schema_list* map, size_t query_ops = 0);
			virtual sqlite::expects_db<sqlite::cursor> prepared_query(sqlite::connection* storage, const std::string_view& label, const std::string_view& operation, sqlite::tstatement* statement);
			virtual sqlite::expects_db<string> load(const std::string_view& label, const std::string_view& operation, const std::string_view& key);
			virtual sqlite::expects_db<void> store(const std::string_view& label, const std::string_view& operation, const std::string_view& key, const std::string_view& value);
			virtual sqlite::expects_db<void> clear(const std::string_view& label, const std::string_view& operation, const std::string_view& table_ids);
			virtual string error_of(sqlite::expects_db<sqlite::session_id>& cursor);
			virtual string error_of(sqlite::expects_db<void>& cursor);
			virtual string error_of(sqlite::expects_db<sqlite::cursor>& cursor);
			virtual uptr<sqlite::connection> index_storage_of(const std::string_view& location, const std::string_view& name);
			virtual void blob_storage_of(const std::string_view& location);
			virtual void unload_index_of(uptr<sqlite::connection>&& storage, bool borrows);
			virtual bool reconstruct_index_storage(sqlite::connection* storage, const std::string_view& name) = 0;
			virtual vector<sqlite::connection*> get_index_storages() = 0;
		};
	}
}
#endif