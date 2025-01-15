#ifndef TAN_STORAGE_ENGINE_H
#define TAN_STORAGE_ENGINE_H
#include "../kernel/chain.h"

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
			LDB::SessionId Transaction = nullptr;

		public:
			MutableStorage() = default;
			MutableStorage(const MutableStorage&) = delete;
			MutableStorage(MutableStorage&&) = delete;
			virtual ~MutableStorage();
			MutableStorage& operator=(const MutableStorage&) = delete;
			MutableStorage& operator=(MutableStorage&&) = delete;
			bool QueryUsed() const;
			size_t GetQueries() const;

		public:
			virtual LDB::ExpectsDB<void> TxBegin(const std::string_view& Label, const std::string_view& Operation, LDB::Isolation Type);
			virtual LDB::ExpectsDB<void> TxCommit(const std::string_view& Label, const std::string_view& Operation);
			virtual LDB::ExpectsDB<void> TxRollback(const std::string_view& Label, const std::string_view& Operation);

		protected:
			virtual LDB::ExpectsDB<LDB::Cursor> Query(const std::string_view& Label, const std::string_view& Operation, const std::string_view& Command, size_t QueryOps = 0);
			virtual LDB::ExpectsDB<LDB::Cursor> EmplaceQuery(const std::string_view& Label, const std::string_view& Operation, const std::string_view& Command, SchemaList* Map, size_t QueryOps = 0);
			virtual String ErrorOf(LDB::ExpectsDB<LDB::SessionId>& Cursor);
			virtual String ErrorOf(LDB::ExpectsDB<void>& Cursor);
			virtual String ErrorOf(LDB::ExpectsDB<LDB::Cursor>& Cursor);
			virtual void StorageOf(const std::string_view& Location);
			virtual bool ReconstructStorage() = 0;
		};

		struct PermanentStorage
		{
		public:
			typedef UnorderedMap<LDB::Connection*, LDB::SessionId> MultiSessionId;

		private:
			std::atomic<uint64_t> Queries = 0;

		protected:
			UPtr<MultiSessionId> Transaction;
			rocksdb::DB* Blob = nullptr;

		public:
			PermanentStorage() = default;
			PermanentStorage(const PermanentStorage&) = delete;
			PermanentStorage(PermanentStorage&&) = delete;
			virtual ~PermanentStorage() = default;
			PermanentStorage& operator=(const PermanentStorage&) = delete;
			PermanentStorage& operator=(PermanentStorage&&) = delete;
			bool QueryUsed() const;
			size_t GetQueries() const;

		public:
			virtual LDB::ExpectsDB<void> MultiTxBegin(const std::string_view& Label, const std::string_view& Operation, LDB::Isolation Type);
			virtual LDB::ExpectsDB<void> MultiTxCommit(const std::string_view& Label, const std::string_view& Operation);
			virtual LDB::ExpectsDB<void> MultiTxRollback(const std::string_view& Label, const std::string_view& Operation);

		protected:
			virtual LDB::ExpectsDB<LDB::SessionId> TxBegin(LDB::Connection* Storage, const std::string_view& Label, const std::string_view& Operation, LDB::Isolation Type);
			virtual LDB::ExpectsDB<void> TxCommit(LDB::Connection* Storage, const std::string_view& Label, const std::string_view& Operation, LDB::SessionId Session);
			virtual LDB::ExpectsDB<void> TxRollback(LDB::Connection* Storage, const std::string_view& Label, const std::string_view& Operation, LDB::SessionId Session);
			virtual LDB::ExpectsDB<LDB::Cursor> Query(LDB::Connection* Storage, const std::string_view& Label, const std::string_view& Operation, const std::string_view& Command, size_t QueryOps = 0);
			virtual LDB::ExpectsDB<LDB::Cursor> EmplaceQuery(LDB::Connection* Storage, const std::string_view& Label, const std::string_view& Operation, const std::string_view& Command, SchemaList* Map, size_t QueryOps = 0);
			virtual LDB::ExpectsDB<LDB::Cursor> PreparedQuery(LDB::Connection* Storage, const std::string_view& Label, const std::string_view& Operation, LDB::TStatement* Statement);
			virtual LDB::ExpectsDB<String> Load(const std::string_view& Label, const std::string_view& Operation, const std::string_view& Key);
			virtual LDB::ExpectsDB<void> Store(const std::string_view& Label, const std::string_view& Operation, const std::string_view& Key, const std::string_view& Value);
			virtual LDB::ExpectsDB<void> Clear(const std::string_view& Label, const std::string_view& Operation, const std::string_view& TableIds);
			virtual String ErrorOf(LDB::ExpectsDB<LDB::SessionId>& Cursor);
			virtual String ErrorOf(LDB::ExpectsDB<void>& Cursor);
			virtual String ErrorOf(LDB::ExpectsDB<LDB::Cursor>& Cursor);
			virtual UPtr<LDB::Connection> IndexStorageOf(const std::string_view& Location, const std::string_view& Name);
			virtual void BlobStorageOf(const std::string_view& Location);
			virtual void UnloadIndexOf(UPtr<LDB::Connection>&& Storage, bool Borrows);
			virtual bool ReconstructIndexStorage(LDB::Connection* Storage, const std::string_view& Name) = 0;
			virtual Vector<LDB::Connection*> GetIndexStorages() = 0;
		};
	}
}
#endif