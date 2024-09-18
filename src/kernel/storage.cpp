#include "storage.h"

namespace Tangent
{
	namespace Ledger
	{
		static thread_local uint64_t ThreadQueries = 0;
		uint64_t StorageUtil::GetThreadQueries()
		{
			return ThreadQueries;
		}

		MutableStorage::~MutableStorage()
		{
			if (Storage)
				Protocol::Change().Database.Free(std::move(Storage));
		}
		LDB::ExpectsDB<LDB::SessionId> MutableStorage::TxBegin(const std::string_view& Label, const std::string_view& Operation, LDB::Isolation Type)
		{
			VI_ASSERT(Storage, "storage connection not initialized (transaction begin)");
			auto Cursor = Storage->TxBegin(Type);
#ifdef _DEBUG
			String Error = ErrorOf(Cursor);
			if (!Error.empty())
				VI_ERR("[storage] operation %.*s::%.*s error (transaction begin): %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
#endif
			++Queries; ++ThreadQueries;
			return Cursor;
		}
		LDB::ExpectsDB<void> MutableStorage::TxCommit(const std::string_view& Label, const std::string_view& Operation, LDB::SessionId Session)
		{
			VI_ASSERT(Storage, "storage connection not initialized (transaction commit)");
			auto Cursor = Storage->TxCommit(Session);
#ifdef _DEBUG
			String Error = ErrorOf(Cursor);
			if (!Error.empty())
				VI_ERR("[storage] operation %.*s::%.*s error (transaction commit): %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
#endif
			++Queries; ++ThreadQueries;
			return Cursor;
		}
		LDB::ExpectsDB<void> MutableStorage::TxRollback(const std::string_view& Label, const std::string_view& Operation, LDB::SessionId Session)
		{
			VI_ASSERT(Storage, "storage connection not initialized (transaction rollback)");
			auto Cursor = Storage->TxRollback(Session);
#ifdef _DEBUG
			String Error = ErrorOf(Cursor);
			if (!Error.empty())
				VI_ERR("[storage] operation %.*s::%.*s error (transaction rollback): %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
#endif
			++Queries; ++ThreadQueries;
			return Cursor;
		}
		LDB::ExpectsDB<LDB::Cursor> MutableStorage::Query(const std::string_view& Label, const std::string_view& Operation, const std::string_view& Command, size_t QueryOps, LDB::SessionId Session)
		{
			VI_ASSERT(Storage, "storage connection not initialized (operation: %.*s::%.*s)", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data());
			auto Cursor = Storage->Query(Command, QueryOps, Session);
#ifdef _DEBUG
			String Error = ErrorOf(Cursor);
			if (!Error.empty())
				VI_ERR("[storage] operation %.*s::%.*s failed: %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
#endif
			++Queries; ++ThreadQueries;
			return Cursor;
		}
		LDB::ExpectsDB<LDB::Cursor> MutableStorage::EmplaceQuery(const std::string_view& Label, const std::string_view& Operation, const std::string_view& Command, SchemaList* Map, size_t QueryOps, LDB::SessionId Session)
		{
			VI_ASSERT(Storage, "storage connection not initialized (operation: %.*s::%.*s)", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data());
			auto Cursor = Storage->EmplaceQuery(Command, Map, QueryOps, Session);
#ifdef _DEBUG
			String Error = ErrorOf(Cursor);
			if (!Error.empty())
				VI_ERR("[storage] operation %.*s::%.*s failed: %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
#endif
			++Queries; ++ThreadQueries;
			return Cursor;
		}
		String MutableStorage::ErrorOf(LDB::ExpectsDB<LDB::SessionId>& Cursor)
		{
			String Error;
			if (!Cursor)
				Error = Cursor.What();
			return Error;
		}
		String MutableStorage::ErrorOf(LDB::ExpectsDB<void>& Cursor)
		{
			String Error;
			if (!Cursor)
				Error = Cursor.What();
			return Error;
		}
		String MutableStorage::ErrorOf(LDB::ExpectsDB<LDB::Cursor>& Cursor)
		{
			String Error;
			if (Cursor)
			{
				if (Cursor->Error())
				{
					for (auto& Response : *Cursor)
					{
						if (Response.Error())
						{
							if (!Error.empty())
								Error += "; ";
							Error += Response.GetStatusText();
						}
					}
				}
			}
			else
				Error = Cursor.What();
			return Error;
		}
		void MutableStorage::StorageOf(const std::string_view& Path)
		{
			Storage = Protocol::Change().Database.Use(0, Path, [this, &Path](LDB::Connection* Intermediate)
			{
				size_t LastQueries = Queries;
				Storage = Intermediate;
				VI_PANIC(Verify(), "storage verification error (path = %.*s)", (int)Path.size(), Path.data());
				Storage.Reset();
				Queries = LastQueries;
			});
			VI_PANIC(Storage, "storage connection error (path = %.*s)", (int)Path.size(), Path.data());
		}
		MutableStorage::operator bool() const
		{
			return !!Storage;
		}
		bool MutableStorage::QueryUsed() const
		{
			return Queries > 0;
		}
		size_t MutableStorage::GetQueries() const
		{
			return Queries;
		}

		PermanentStorage::~PermanentStorage()
		{
			if (HottestStorage)
				Protocol::Change().Database.Free(std::move(HottestStorage));
		}
		LDB::ExpectsDB<LDB::SessionId> PermanentStorage::TxBegin(const std::string_view& Label, const std::string_view& Operation, LDB::Isolation Type)
		{
			VI_ASSERT(HottestStorage, "storage connection not initialized (transaction begin)");
			auto Cursor = HottestStorage->TxBegin(Type);
#ifdef _DEBUG
			String Error = ErrorOf(Cursor);
			if (!Error.empty())
				VI_ERR("[storage] operation %.*s::%.*s error (transaction begin): %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
#endif
			++Queries; ++ThreadQueries;
			return Cursor;
		}
		LDB::ExpectsDB<void> PermanentStorage::TxCommit(const std::string_view& Label, const std::string_view& Operation, LDB::SessionId Session)
		{
			VI_ASSERT(HottestStorage, "storage connection not initialized (transaction commit)");
			auto Cursor = HottestStorage->TxCommit(Session);
#ifdef _DEBUG
			String Error = ErrorOf(Cursor);
			if (!Error.empty())
				VI_ERR("[storage] operation %.*s::%.*s error (transaction commit): %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
#endif
			++Queries; ++ThreadQueries;
			return Cursor;
		}
		LDB::ExpectsDB<void> PermanentStorage::TxRollback(const std::string_view& Label, const std::string_view& Operation, LDB::SessionId Session)
		{
			VI_ASSERT(HottestStorage, "storage connection not initialized (transaction rollback)");
			auto Cursor = HottestStorage->TxRollback(Session);
#ifdef _DEBUG
			String Error = ErrorOf(Cursor);
			if (!Error.empty())
				VI_ERR("[storage] operation %.*s::%.*s error (transaction rollback): %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
#endif
			++Queries; ++ThreadQueries;
			return Cursor;
		}
		LDB::ExpectsDB<LDB::Cursor> PermanentStorage::Query(const std::string_view& Label, const std::string_view& Operation, const std::string_view& Command, size_t QueryOps, LDB::SessionId Session)
		{
			VI_ASSERT(HottestStorage, "storage connection not initialized (operation: %.*s::%.*s)", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data());
			auto Cursor = HottestStorage->Query(Command, QueryOps, Session);
#ifdef _DEBUG
			String Error = ErrorOf(Cursor);
			if (!Error.empty())
				VI_ERR("[storage] operation %.*s::%.*s failed: %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
#endif
			++Queries; ++ThreadQueries;
			return Cursor;
		}
		LDB::ExpectsDB<LDB::Cursor> PermanentStorage::PreparedQuery(const std::string_view& Label, const std::string_view& Operation, LDB::TStatement* Statement)
		{
			VI_ASSERT(HottestStorage, "storage connection not initialized (operation: %.*s::%.*s)", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data());
			auto Cursor = HottestStorage->PreparedQuery(Statement);
#ifdef _DEBUG
			String Error = ErrorOf(Cursor);
			if (!Error.empty())
				VI_ERR("[storage] operation %.*s::%.*s failed: %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
#endif
			++Queries; ++ThreadQueries;
			return Cursor;
		}
		LDB::ExpectsDB<LDB::Cursor> PermanentStorage::EmplaceQuery(const std::string_view& Label, const std::string_view& Operation, const std::string_view& Command, SchemaList* Map, size_t QueryOps, LDB::SessionId Session)
		{
			VI_ASSERT(HottestStorage, "storage connection not initialized (operation: %.*s::%.*s)", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data());
			auto Cursor = HottestStorage->EmplaceQuery(Command, Map, QueryOps, Session);
#ifdef _DEBUG
			String Error = ErrorOf(Cursor);
			if (!Error.empty())
				VI_ERR("[storage] operation %.*s::%.*s failed: %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
#endif
			++Queries; ++ThreadQueries;
			return Cursor;
		}
		LDB::ExpectsDB<LDB::Cursor> PermanentStorage::ArchiveQuery(const std::string_view& Label, const std::string_view& Operation, const std::string_view& Command, size_t QueryOps)
		{
			auto Cursor = Query(Label, Operation, Command, QueryOps);
			if (!Cursor || Cursor->Error() || !Cursor->Empty())
				return Cursor;

			auto& Database = Protocol::Change().Database;
			size_t Epoch = Database.EpochOf(PartitionLocation);
			if (!Epoch)
				return Cursor;

			while (Epoch > 0)
			{
				auto Storage = UseStorageOf(--Epoch);
				Cursor = Storage->Query(Command, QueryOps);
				Database.Free(std::move(Storage));
#ifdef _DEBUG
				String Error = ErrorOf(Cursor);
				if (!Error.empty())
					VI_ERR("[storage] operation %.*s::%.*s failed: %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
#endif
				++Queries; ++ThreadQueries;
				if (!Cursor || Cursor->Error() || !Cursor->Empty())
					return Cursor;
			}

			return Cursor;
		}
		LDB::ExpectsDB<LDB::Cursor> PermanentStorage::ArchivePreparedQuery(const std::string_view& Label, const std::string_view& Operation, LDB::TStatement* Statement)
		{
			auto Cursor = PreparedQuery(Label, Operation, Statement);
			if (!Cursor || Cursor->Error() || !Cursor->Empty())
				return Cursor;

			auto& Database = Protocol::Change().Database;
			size_t Epoch = Database.EpochOf(PartitionLocation);
			if (!Epoch)
				return Cursor;

			while (Epoch > 0)
			{
				auto Storage = UseStorageOf(--Epoch);
				Cursor = Storage->PreparedQuery(Statement);
				Database.Free(std::move(Storage));
#ifdef _DEBUG
				String Error = ErrorOf(Cursor);
				if (!Error.empty())
					VI_ERR("[storage] operation %.*s::%.*s failed: %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
#endif
				++Queries; ++ThreadQueries;
				if (!Cursor || Cursor->Error() || !Cursor->Empty())
					return Cursor;
			}

			return Cursor;
		}
		LDB::ExpectsDB<LDB::Cursor> PermanentStorage::ArchiveEmplaceQuery(const std::string_view& Label, const std::string_view& Operation, const std::string_view& Command, SchemaList* Map, size_t QueryOps)
		{
			auto Cursor = EmplaceQuery(Label, Operation, Command, Map, QueryOps);
			if (!Cursor || Cursor->Error() || !Cursor->Empty())
				return Cursor;

			auto& Database = Protocol::Change().Database;
			size_t Epoch = Database.EpochOf(PartitionLocation);
			if (!Epoch)
				return Cursor;

			while (Epoch > 0)
			{
				auto Storage = UseStorageOf(--Epoch);
				Cursor = Storage->EmplaceQuery(Command, Map, QueryOps);
				Database.Free(std::move(Storage));
#ifdef _DEBUG
				String Error = ErrorOf(Cursor);
				if (!Error.empty())
					VI_ERR("[storage] operation %.*s::%.*s failed: %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
#endif
				++Queries; ++ThreadQueries;
				if (!Cursor || Cursor->Error() || !Cursor->Empty())
					return Cursor;
			}

			return Cursor;
		}
		LDB::ExpectsDB<LDB::Cursor> PermanentStorage::ArchiveQueryRecursive(const std::string_view& Label, const std::string_view& Operation, const std::string_view& Command, size_t QueryOps)
		{
			auto Cursor = Query(Label, Operation, Command, QueryOps);
			if (!Cursor || Cursor->Error())
				return Cursor;

			auto& Database = Protocol::Change().Database;
			size_t Epoch = Database.EpochOf(PartitionLocation);
			if (!Epoch)
				return Cursor;

			while (Epoch > 0)
			{
				auto Storage = UseStorageOf(--Epoch);
				auto Subcursor = Storage->Query(Command, QueryOps);
				Database.Free(std::move(Storage));
#ifdef _DEBUG
				String Error = ErrorOf(Subcursor);
				if (!Error.empty())
					VI_ERR("[storage] operation %.*s::%.*s failed: %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
#endif
				++Queries; ++ThreadQueries;
				if (!Subcursor || Subcursor->Error())
					return Subcursor;

				Cursor->Base.insert(Cursor->Base.end(), std::make_move_iterator(Subcursor->Base.begin()), std::make_move_iterator(Subcursor->Base.end()));
			}

			return Cursor;
		}
		LDB::ExpectsDB<LDB::Cursor> PermanentStorage::ArchiveEmplaceQueryRecursive(const std::string_view& Label, const std::string_view& Operation, const std::string_view& Command, SchemaList* Map, size_t QueryOps)
		{
			auto Cursor = EmplaceQuery(Label, Operation, Command, Map, QueryOps);
			if (!Cursor || Cursor->Error())
				return Cursor;

			auto& Database = Protocol::Change().Database;
			size_t Epoch = Database.EpochOf(PartitionLocation);
			if (!Epoch)
				return Cursor;

			while (Epoch > 0)
			{
				auto Storage = UseStorageOf(--Epoch);
				auto Subcursor = Storage->EmplaceQuery(Command, Map, QueryOps);
				Database.Free(std::move(Storage));
#ifdef _DEBUG
				String Error = ErrorOf(Subcursor);
				if (!Error.empty())
					VI_ERR("[storage] operation %.*s::%.*s failed: %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
#endif
				++Queries; ++ThreadQueries;
				if (!Subcursor || Subcursor->Error())
					return Subcursor;

				Cursor->Base.insert(Cursor->Base.end(), std::make_move_iterator(Subcursor->Base.begin()), std::make_move_iterator(Subcursor->Base.end()));
			}

			return Cursor;
		}
		UPtr<LDB::Connection> PermanentStorage::UseStorageOf(size_t Epoch)
		{
			auto Storage = Protocol::Change().Database.Use(Epoch, PartitionLocation, [this, Epoch](LDB::Connection* Intermediate)
			{
				size_t LastQueries = Queries;
				auto* LastStorage = HottestStorage.Reset();
				HottestStorage = Intermediate;
				VI_PANIC(Verify(), "storage verification error (path = %s, epoch = %i)", PartitionLocation.c_str(), (int)Epoch);
				HottestStorage.Reset();
				HottestStorage = LastStorage;
				Queries = LastQueries;
			});
			VI_PANIC(Storage, "storage connection error (path = %s, epoch = %i)", PartitionLocation.c_str(), (int)Epoch);
			return Storage;
		}
		String PermanentStorage::ErrorOf(LDB::ExpectsDB<LDB::SessionId>& Cursor)
		{
			String Error;
			if (!Cursor)
				Error = Cursor.What();
			return Error;
		}
		String PermanentStorage::ErrorOf(LDB::ExpectsDB<void>& Cursor)
		{
			String Error;
			if (!Cursor)
				Error = Cursor.What();
			return Error;
		}
		String PermanentStorage::ErrorOf(LDB::ExpectsDB<LDB::Cursor>& Cursor)
		{
			String Error;
			if (Cursor)
			{
				if (Cursor->Error())
				{
					for (auto& Response : *Cursor)
					{
						if (Response.Error())
						{
							if (!Error.empty())
								Error += "; ";
							Error += Response.GetStatusText();
						}
					}
				}
			}
			else
				Error = Cursor.What();
			return Error;
		}
		void PermanentStorage::StorageOf(const std::string_view& Location)
		{
			auto& Config = Protocol::Change();
			size_t Epoch = Config.Database.EpochOf(Location);
			auto Path = Config.Database.PathOf(Epoch, Location);
			auto State = OS::File::GetState(Path);
			if (State && (uint64_t)State->Size > Config.User.Storage.PartitionSize)
				Epoch = (size_t)Repository::NEW_EPOCH;

			PartitionLocation = Location;
			HottestStorage = UseStorageOf(Epoch);
		}
		PermanentStorage::operator bool() const
		{
			return !!HottestStorage;
		}
		bool PermanentStorage::QueryUsed() const
		{
			return Queries > 0;
		}
		size_t PermanentStorage::GetQueries() const
		{
			return Queries;
		}
	}
}