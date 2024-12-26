#include "engine.h"
#ifdef TAN_ROCKSDB
#include "rocksdb/db.h"
#endif

namespace Tangent
{
	namespace Ledger
	{
#ifdef TAN_ROCKSDB
		static const rocksdb::ReadOptions& GetBlobReadOptions()
		{
			static rocksdb::ReadOptions Options;
			return Options;
		}
		static const rocksdb::WriteOptions& GetBlobWriteOptions()
		{
			static rocksdb::WriteOptions Options;
			return Options;
		}
#endif
		static thread_local std::atomic<uint64_t> ThreadQueries = 0;
		uint64_t StorageUtil::GetThreadQueries()
		{
			return ThreadQueries;
		}

		MutableStorage::~MutableStorage()
		{
			if (Storage)
				Protocol::Change().Database.UnloadIndex(std::move(Storage));
		}
		LDB::ExpectsDB<LDB::SessionId> MutableStorage::TxBegin(const std::string_view& Label, const std::string_view& Operation, LDB::Isolation Type)
		{
			VI_ASSERT(Storage, "storage connection not initialized (transaction begin)");
			auto Cursor = Storage->TxBegin(Type);
#ifdef _DEBUG
			String Error = ErrorOf(Cursor);
			if (!Error.empty() && Protocol::Now().User.Storage.Logging)
				VI_ERR("[indexdb] operation %.*s::%.*s error (transaction begin): %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
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
			if (!Error.empty() && Protocol::Now().User.Storage.Logging)
				VI_ERR("[indexdb] operation %.*s::%.*s error (transaction commit): %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
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
			if (!Error.empty() && Protocol::Now().User.Storage.Logging)
				VI_ERR("[indexdb] operation %.*s::%.*s error (transaction rollback): %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
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
			if (!Error.empty() && Protocol::Now().User.Storage.Logging)
				VI_ERR("[indexdb] operation %.*s::%.*s failed: %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
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
			if (!Error.empty() && Protocol::Now().User.Storage.Logging)
				VI_ERR("[indexdb] operation %.*s::%.*s failed: %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
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
			Storage = Protocol::Change().Database.LoadIndex(Path, [this, &Path](LDB::Connection* Intermediate)
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
			for (auto& Storage : Index)
			{
				if (Storage.second)
					Protocol::Change().Database.UnloadIndex(std::move(Storage.second));
			}
		}
		LDB::ExpectsDB<PermanentStorage::MultiSessionId> PermanentStorage::MultiTxBegin(const std::string_view& Label, const std::string_view& Operation, LDB::Isolation Type)
		{
			MultiSessionId Session;
			Session.reserve(Index.size());
			for (auto& Storage : Index)
				Session[*Storage.second] = nullptr;

			std::mutex Mutex;
			LDB::ExpectsDB<void> Status = Expectation::Met;
			Parallel::WailAll(ParallelForEachNode(Index.begin(), Index.end(), Index.size(), [&](std::pair<const String, UPtr<LDB::Connection>>& Storage)
			{
				auto Result = TxBegin(*Storage.second, Label, Operation, Type);
				if (!Result)
				{
					UMutex<std::mutex> Unique(Mutex);
					if (!Status)
						Status = LDB::DatabaseException(Status.Error().message() + ", " + Result.Error().message());
					else
						Status = std::move(Result.Error());
				}
				else
					Session[*Storage.second] = *Result;
			}));
			if (Status)
				return Session;

			for (auto& Substorage : Session)
			{
				if (Substorage.second != nullptr)
					TxRollback(Substorage.first, Label, Operation, Substorage.second);
			}
			return Status.Error();
		}
		LDB::ExpectsDB<void> PermanentStorage::MultiTxCommit(const std::string_view& Label, const std::string_view& Operation, const MultiSessionId& Session)
		{
			std::mutex Mutex;
			LDB::ExpectsDB<void> Status = Expectation::Met;
			Parallel::WailAll(ParallelForEachNode(Session.begin(), Session.end(), Session.size(), [&](const std::pair<LDB::Connection* const, LDB::SessionId>& Storage)
			{
				auto Result = TxCommit(Storage.first, Label, Operation, Storage.second);
				if (Result)
					return;

				UMutex<std::mutex> Unique(Mutex);
				if (!Status)
					Status = LDB::DatabaseException(Status.Error().message() + ", " + Result.Error().message());
				else
					Status = std::move(Result.Error());
			}));
			return Status;
		}
		LDB::ExpectsDB<void> PermanentStorage::MultiTxRollback(const std::string_view& Label, const std::string_view& Operation, const MultiSessionId& Session)
		{
			std::mutex Mutex;
			LDB::ExpectsDB<void> Status = Expectation::Met;
			Parallel::WailAll(ParallelForEachNode(Session.begin(), Session.end(), Session.size(), [&](const std::pair<LDB::Connection* const, LDB::SessionId>& Storage)
			{
				auto Result = TxRollback(Storage.first, Label, Operation, Storage.second);
				if (Result)
					return;

				UMutex<std::mutex> Unique(Mutex);
				if (!Status)
					Status = LDB::DatabaseException(Status.Error().message() + ", " + Result.Error().message());
				else
					Status = std::move(Result.Error());
			}));
			return Status;
		}
		LDB::ExpectsDB<LDB::SessionId> PermanentStorage::TxBegin(LDB::Connection* Storage, const std::string_view& Label, const std::string_view& Operation, LDB::Isolation Type)
		{
			VI_ASSERT(Storage, "storage connection not initialized (transaction begin)");
			auto Cursor = Storage->TxBegin(Type);
#ifdef _DEBUG
			String Error = ErrorOf(Cursor);
			if (!Error.empty() && Protocol::Now().User.Storage.Logging)
				VI_ERR("[indexdb] operation %.*s::%.*s error (transaction begin): %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
#endif
			++Queries; ++ThreadQueries;
			return Cursor;
		}
		LDB::ExpectsDB<void> PermanentStorage::TxCommit(LDB::Connection* Storage, const std::string_view& Label, const std::string_view& Operation, LDB::SessionId Session)
		{
			VI_ASSERT(Storage, "storage connection not initialized (transaction commit)");
			auto Cursor = Storage->TxCommit(Session);
#ifdef _DEBUG
			String Error = ErrorOf(Cursor);
			if (!Error.empty() && Protocol::Now().User.Storage.Logging)
				VI_ERR("[indexdb] operation %.*s::%.*s error (transaction commit): %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
#endif
			++Queries; ++ThreadQueries;
			return Cursor;
		}
		LDB::ExpectsDB<void> PermanentStorage::TxRollback(LDB::Connection* Storage, const std::string_view& Label, const std::string_view& Operation, LDB::SessionId Session)
		{
			VI_ASSERT(Storage, "storage connection not initialized (transaction rollback)");
			auto Cursor = Storage->TxRollback(Session);
#ifdef _DEBUG
			String Error = ErrorOf(Cursor);
			if (!Error.empty() && Protocol::Now().User.Storage.Logging)
				VI_ERR("[indexdb] operation %.*s::%.*s error (transaction rollback): %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
#endif
			++Queries; ++ThreadQueries;
			return Cursor;
		}
		LDB::ExpectsDB<LDB::Cursor> PermanentStorage::Query(LDB::Connection* Storage, const std::string_view& Label, const std::string_view& Operation, const std::string_view& Command, size_t QueryOps, LDB::SessionId Session)
		{
			VI_ASSERT(Storage, "storage connection not initialized (operation: %.*s::%.*s)", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data());
			auto Cursor = Storage->Query(Command, QueryOps, Session);
#ifdef _DEBUG
			String Error = ErrorOf(Cursor);
			if (!Error.empty() && Protocol::Now().User.Storage.Logging)
				VI_ERR("[indexdb] operation %.*s::%.*s failed: %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
#endif
			++Queries; ++ThreadQueries;
			return Cursor;
		}
		LDB::ExpectsDB<LDB::Cursor> PermanentStorage::EmplaceQuery(LDB::Connection* Storage, const std::string_view& Label, const std::string_view& Operation, const std::string_view& Command, SchemaList* Map, size_t QueryOps, LDB::SessionId Session)
		{
			VI_ASSERT(Storage, "storage connection not initialized (operation: %.*s::%.*s)", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data());
			auto Cursor = Storage->EmplaceQuery(Command, Map, QueryOps, Session);
#ifdef _DEBUG
			String Error = ErrorOf(Cursor);
			if (!Error.empty() && Protocol::Now().User.Storage.Logging)
				VI_ERR("[indexdb] operation %.*s::%.*s failed: %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
#endif
			++Queries; ++ThreadQueries;
			return Cursor;
		}
		LDB::ExpectsDB<LDB::Cursor> PermanentStorage::PreparedQuery(LDB::Connection* Storage, const std::string_view& Label, const std::string_view& Operation, LDB::TStatement* Statement)
		{
			VI_ASSERT(Storage, "storage connection not initialized (operation: %.*s::%.*s)", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data());
			auto Cursor = Storage->PreparedQuery(Statement);
#ifdef _DEBUG
			String Error = ErrorOf(Cursor);
			if (!Error.empty() && Protocol::Now().User.Storage.Logging)
				VI_ERR("[indexdb] operation %.*s::%.*s failed: %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Error.c_str());
#endif
			++Queries; ++ThreadQueries;
			return Cursor;
		}
		LDB::ExpectsDB<String> PermanentStorage::Load(const std::string_view& Label, const std::string_view& Operation, const std::string_view& Key)
		{
#ifdef TAN_ROCKSDB
			VI_ASSERT(Blob, "storage connection not initialized (operation: %.*s::%.*s)", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data());
			rocksdb::PinnableSlice Value;
			auto Status = Blob->Get(GetBlobReadOptions(), Blob->DefaultColumnFamily(), rocksdb::Slice(Key.data(), Key.size()), &Value);
			++Queries; ++ThreadQueries;
			if (!Status.ok())
			{
				auto Message = Status.ToString();
				if (!Status.IsNotFound() && Protocol::Now().User.Storage.Logging)
					VI_ERR("[blobdb] operation %.*s::%.*s failed: %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Message.c_str());
				return LDB::ExpectsDB<String>(LDB::DatabaseException(String(Message.begin(), Message.end())));
			}

			String Result = String(Value.data(), Value.size());
			return LDB::ExpectsDB<String>(std::move(Result));
#else
			return LDB::DatabaseException("blob db not supported");
#endif
		}
		LDB::ExpectsDB<void> PermanentStorage::Store(const std::string_view& Label, const std::string_view& Operation, const std::string_view& Key, const std::string_view& Value)
		{
#ifdef TAN_ROCKSDB
			VI_ASSERT(Blob, "storage connection not initialized (operation: %.*s::%.*s)", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data());
			auto Status = Value.empty() ? Blob->Delete(GetBlobWriteOptions(), rocksdb::Slice(Key.data(), Key.size())) : Blob->Put(GetBlobWriteOptions(), rocksdb::Slice(Key.data(), Key.size()), rocksdb::Slice(Value.data(), Value.size()));
			++Queries; ++ThreadQueries;
			if (!Status.ok())
			{
				auto Message = Status.ToString();
				if (!Status.IsNotFound() && Protocol::Now().User.Storage.Logging)
					VI_ERR("[blobdb] operation %.*s::%.*s failed: %s", (int)Label.size(), Label.data(), (int)Operation.size(), Operation.data(), Message.c_str());
				return LDB::DatabaseException(String(Message.begin(), Message.end()));
			}

			return Expectation::Met;
#else
			return LDB::DatabaseException("blob db not supported");
#endif
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
		void PermanentStorage::IndexStorageOf(const std::string_view& Path, const std::string_view& Name)
		{
			auto& Storage = Index[String(Name)];
			Storage = Protocol::Change().Database.LoadIndex(String(Path) + "." + String(Name), [this, &Path, &Name](LDB::Connection* Intermediate)
			{
				size_t LastQueries = Queries;
				VI_PANIC(Verify(Intermediate, Name), "storage verification error (path = %.*s)", (int)Path.size(), Path.data());
				Queries = LastQueries;
			});
			VI_PANIC(Storage, "index storage connection error (path = %.*s)", (int)Path.size(), Path.data());
		}
		void PermanentStorage::BlobStorageOf(const std::string_view& Path)
		{
			Blob = Protocol::Change().Database.LoadBlob(Path);
			VI_PANIC(Blob, "blob storage connection error (path = %.*s)", (int)Path.size(), Path.data());

			auto Threads = OS::CPU::GetQuantityInfo().Physical;
			auto Options = Blob->GetOptions();
			if (Protocol::Now().User.CompactionThreadsRatio > 0.0)
				Options.env->SetBackgroundThreads((int)std::max(std::ceil(Threads * Protocol::Now().User.CompactionThreadsRatio), 1.0), rocksdb::Env::Priority::LOW);
			if (Protocol::Now().User.FlushThreadsRatio > 0.0)
				Options.env->SetBackgroundThreads((int)std::max(std::ceil(Threads * Protocol::Now().User.FlushThreadsRatio), 1.0), rocksdb::Env::Priority::HIGH);
		}
		PermanentStorage::operator bool() const
		{
			if (!Blob)
				return false;

			for (auto& Storage : Index)
			{
				if (!Storage.second)
					return false;
			}

			return true;
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