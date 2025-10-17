#ifndef TAN_STORAGE_ENGINE_H
#define TAN_STORAGE_ENGINE_H
#include "../../kernel/chain.h"

namespace tangent
{
	namespace ledger
	{
		struct storage_index_ptr;

		class storage_util
		{
		public:
			typedef unordered_set<storage_index_ptr*> multi_storage_index_ptr;

		public:
			static sqlite::expects_db<void> multi_tx_begin(const std::string_view& operation, sqlite::isolation type, multi_storage_index_ptr& ptr);
			static sqlite::expects_db<void> multi_tx_commit(const std::string_view& operation, multi_storage_index_ptr&& ptr);
			static sqlite::expects_db<void> multi_tx_rollback(const std::string_view& operation, multi_storage_index_ptr&& ptr);
			static uref<sqlite::connection> index_storage_of(const std::string_view& location, const std::function<bool(sqlite::connection*)>& callback);
			static uref<sqlite::connection> index_storage_named_of(const std::string_view& location, const std::string_view& name, const std::function<bool(sqlite::connection*, const std::string_view&)>& callback);
			static rocksdb::DB* blob_storage_of(const std::string_view& location);
			static string error_of(sqlite::expects_db<sqlite::session_id>& cursor);
			static string error_of(sqlite::expects_db<void>& cursor);
			static string error_of(sqlite::expects_db<sqlite::cursor>& cursor);
			static string error_of(sqlite::expects_db<sqlite::tstatement*>& cursor);
			static uint64_t get_thread_invocations();
		};

		struct storage_index_ptr
		{
		private:
			uref<sqlite::connection> connection;
			uint32_t invocations;
			bool transaction;

		public:
			storage_index_ptr();
			storage_index_ptr(uref<sqlite::connection>&& new_connection, bool in_transaction = false);
			storage_index_ptr(const storage_index_ptr& other);
			storage_index_ptr(storage_index_ptr&& other) noexcept;
			~storage_index_ptr();
			storage_index_ptr& operator=(const storage_index_ptr& other);
			storage_index_ptr& operator=(storage_index_ptr&& other) noexcept;
			sqlite::expects_db<void> tx_begin(const std::string_view& operation, sqlite::isolation type);
			sqlite::expects_db<void> tx_commit(const std::string_view& operation);
			sqlite::expects_db<void> tx_rollback(const std::string_view& operation);
			sqlite::expects_db<sqlite::cursor> query(const std::string_view& operation, const std::string_view& command, size_t query_ops = 0);
			sqlite::expects_db<sqlite::cursor> emplace_query(const std::string_view& operation, const std::string_view& command, schema_list* map, size_t query_ops = 0);
			sqlite::expects_db<sqlite::cursor> prepared_query(const std::string_view& operation, sqlite::tstatement* statement);
			sqlite::expects_db<sqlite::tstatement*> prepare_statement(const std::string_view& operation, const std::string_view& command);
			sqlite::connection* ptr() const;
			void set_uses(uint32_t value);
			uint32_t uses() const;
			bool in_use() const;
			bool in_transaction() const;
			bool may_use() const;
		};

		struct storage_blob_ptr
		{
		private:
			rocksdb::DB* connection = nullptr;
			uint32_t invocations;

		public:
			storage_blob_ptr();
			storage_blob_ptr(rocksdb::DB* new_connection);
			storage_blob_ptr(const storage_blob_ptr& other);
			storage_blob_ptr(storage_blob_ptr&& other) noexcept;
			~storage_blob_ptr();
			storage_blob_ptr& operator=(const storage_blob_ptr& other);
			storage_blob_ptr& operator=(storage_blob_ptr&& other) noexcept;
			sqlite::expects_db<string> load(const std::string_view& operation, const std::string_view& key);
			sqlite::expects_db<void> store(const std::string_view& operation, const std::string_view& key, const std::string_view& value);
			sqlite::expects_db<void> clear(const std::string_view& operation, const std::string_view& key_prefix);
			rocksdb::DB* ptr() const;
			void set_uses(uint32_t value);
			uint32_t uses() const;
			bool in_use() const;
			bool may_use() const;
		};
	}
}
#endif