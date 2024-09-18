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
			size_t Queries = 0;

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
		private:
			size_t Queries = 0;

		protected:
			UPtr<LDB::Connection> HottestStorage;
			String PartitionLocation;

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
			virtual LDB::ExpectsDB<LDB::SessionId> TxBegin(const std::string_view& Label, const std::string_view& Operation, LDB::Isolation Type);
			virtual LDB::ExpectsDB<void> TxCommit(const std::string_view& Label, const std::string_view& Operation, LDB::SessionId Session);
			virtual LDB::ExpectsDB<void> TxRollback(const std::string_view& Label, const std::string_view& Operation, LDB::SessionId Session);

		protected:
			virtual LDB::ExpectsDB<LDB::Cursor> Query(const std::string_view& Label, const std::string_view& Operation, const std::string_view& Command, size_t QueryOps = 0, LDB::SessionId Session = nullptr);
			virtual LDB::ExpectsDB<LDB::Cursor> PreparedQuery(const std::string_view& Label, const std::string_view& Operation, LDB::TStatement* Statement);
			virtual LDB::ExpectsDB<LDB::Cursor> EmplaceQuery(const std::string_view& Label, const std::string_view& Operation, const std::string_view& Command, SchemaList* Map, size_t QueryOps = 0, LDB::SessionId Session = nullptr);
			virtual LDB::ExpectsDB<LDB::Cursor> ArchiveQuery(const std::string_view& Label, const std::string_view& Operation, const std::string_view& Command, size_t QueryOps = 0);
			virtual LDB::ExpectsDB<LDB::Cursor> ArchivePreparedQuery(const std::string_view& Label, const std::string_view& Operation, LDB::TStatement* Statement);
			virtual LDB::ExpectsDB<LDB::Cursor> ArchiveEmplaceQuery(const std::string_view& Label, const std::string_view& Operation, const std::string_view& Command, SchemaList* Map, size_t QueryOps = 0);
			virtual LDB::ExpectsDB<LDB::Cursor> ArchiveQueryRecursive(const std::string_view& Label, const std::string_view& Operation, const std::string_view& Command, size_t QueryOps = 0);
			virtual LDB::ExpectsDB<LDB::Cursor> ArchiveEmplaceQueryRecursive(const std::string_view& Label, const std::string_view& Operation, const std::string_view& Command, SchemaList* Map, size_t QueryOps = 0);
			virtual String ErrorOf(LDB::ExpectsDB<LDB::SessionId>& Cursor);
			virtual String ErrorOf(LDB::ExpectsDB<void>& Cursor);
			virtual String ErrorOf(LDB::ExpectsDB<LDB::Cursor>& Cursor);
			virtual void StorageOf(const std::string_view& Location);
			virtual bool Verify() = 0;

		private:
			UPtr<LDB::Connection> UseStorageOf(size_t Epoch);
		};
	}
}
#endif