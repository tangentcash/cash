#ifndef TAN_KERNEL_STORAGE_H
#define TAN_KERNEL_STORAGE_H
#include "chain.h"

namespace Tangent
{
	namespace Ledger
	{
		class StorageUtil
		{
		public:
			static uint64_t GetThreadQueries();
		};

		struct MutableStorage
		{
		private:
			std::atomic<uint64_t> Queries = 0;

		protected:
			UPtr<LDB::Connection> Storage;

		public:
			MutableStorage() = default;
			MutableStorage(const MutableStorage&) = delete;
			MutableStorage(MutableStorage&&) = delete;
			virtual ~MutableStorage();
			MutableStorage& operator=(const MutableStorage&) = delete;
			MutableStorage& operator=(MutableStorage&&) = delete;
			explicit operator bool() const;
			bool QueryUsed() const;
			size_t GetQueries() const;

		public:
			virtual LDB::ExpectsDB<LDB::SessionId> TxBegin(const std::string_view& Label, const std::string_view& Operation, LDB::Isolation Type);
			virtual LDB::ExpectsDB<void> TxCommit(const std::string_view& Label, const std::string_view& Operation, LDB::SessionId Session);
			virtual LDB::ExpectsDB<void> TxRollback(const std::string_view& Label, const std::string_view& Operation, LDB::SessionId Session);

		protected:
			virtual LDB::ExpectsDB<LDB::Cursor> Query(const std::string_view& Label, const std::string_view& Operation, const std::string_view& Command, size_t QueryOps = 0, LDB::SessionId Session = nullptr);
			virtual LDB::ExpectsDB<LDB::Cursor> EmplaceQuery(const std::string_view& Label, const std::string_view& Operation, const std::string_view& Command, SchemaList* Map, size_t QueryOps = 0, LDB::SessionId Session = nullptr);
			virtual String ErrorOf(LDB::ExpectsDB<LDB::SessionId>& Cursor);
			virtual String ErrorOf(LDB::ExpectsDB<void>& Cursor);
			virtual String ErrorOf(LDB::ExpectsDB<LDB::Cursor>& Cursor);
			virtual void StorageOf(const std::string_view& Location);
			virtual bool Verify() = 0;
		};

		struct PermanentStorage
		{
		public:
			typedef UnorderedMap<LDB::Connection*, LDB::SessionId> MultiSessionId;

		private:
			std::atomic<uint64_t> Queries = 0;

		protected:
			UnorderedMap<String, UPtr<LDB::Connection>> Index;
			rocksdb::DB* Blob = nullptr;

		public:
			PermanentStorage() = default;
			PermanentStorage(const PermanentStorage&) = delete;
			PermanentStorage(PermanentStorage&&) = delete;
			virtual ~PermanentStorage();
			PermanentStorage& operator=(const PermanentStorage&) = delete;
			PermanentStorage& operator=(PermanentStorage&&) = delete;
			explicit operator bool() const;
			bool QueryUsed() const;
			size_t GetQueries() const;

		public:
			virtual LDB::ExpectsDB<MultiSessionId> MultiTxBegin(const std::string_view& Label, const std::string_view& Operation, LDB::Isolation Type);
			virtual LDB::ExpectsDB<void> MultiTxCommit(const std::string_view& Label, const std::string_view& Operation, const MultiSessionId& Session);
			virtual LDB::ExpectsDB<void> MultiTxRollback(const std::string_view& Label, const std::string_view& Operation, const MultiSessionId& Session);

		protected:
			virtual LDB::ExpectsDB<LDB::SessionId> TxBegin(LDB::Connection* Storage, const std::string_view& Label, const std::string_view& Operation, LDB::Isolation Type);
			virtual LDB::ExpectsDB<void> TxCommit(LDB::Connection* Storage, const std::string_view& Label, const std::string_view& Operation, LDB::SessionId Session);
			virtual LDB::ExpectsDB<void> TxRollback(LDB::Connection* Storage, const std::string_view& Label, const std::string_view& Operation, LDB::SessionId Session);
			virtual LDB::ExpectsDB<LDB::Cursor> Query(LDB::Connection* Storage, const std::string_view& Label, const std::string_view& Operation, const std::string_view& Command, size_t QueryOps = 0, LDB::SessionId Session = nullptr);
			virtual LDB::ExpectsDB<LDB::Cursor> EmplaceQuery(LDB::Connection* Storage, const std::string_view& Label, const std::string_view& Operation, const std::string_view& Command, SchemaList* Map, size_t QueryOps = 0, LDB::SessionId Session = nullptr);
			virtual LDB::ExpectsDB<LDB::Cursor> PreparedQuery(LDB::Connection* Storage, const std::string_view& Label, const std::string_view& Operation, LDB::TStatement* Statement);
			virtual LDB::ExpectsDB<String> Load(const std::string_view& Label, const std::string_view& Operation, const std::string_view& Key);
			virtual LDB::ExpectsDB<void> Store(const std::string_view& Label, const std::string_view& Operation, const std::string_view& Key, const std::string_view& Value);
			virtual String ErrorOf(LDB::ExpectsDB<LDB::SessionId>& Cursor);
			virtual String ErrorOf(LDB::ExpectsDB<void>& Cursor);
			virtual String ErrorOf(LDB::ExpectsDB<LDB::Cursor>& Cursor);
			virtual void IndexStorageOf(const std::string_view& Location, const std::string_view& Name);
			virtual void BlobStorageOf(const std::string_view& Location);
			virtual bool Verify(LDB::Connection* Storage, const std::string_view& Name) = 0;
		};
	}
}
#endif