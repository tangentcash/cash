#include "chain.h"
#include "script.h"
#include "../validator/storage/chainstate.h"
#include "../validator/service/nss.h"
#ifdef TAN_ROCKSDB
#include "rocksdb/db.h"
#include "rocksdb/table.h"
#endif
#define KEY_FRONT 32
#define KEY_BACK 32
#define KEY_SIZE 2048

namespace Tangent
{
#ifdef TAN_ROCKSDB
	static rocksdb::Options BlobStorageConfiguration(uint64_t BlobCacheSize)
	{
		rocksdb::BlockBasedTableOptions TableOptions;
		TableOptions.block_cache = rocksdb::NewLRUCache(BlobCacheSize);

		rocksdb::Options Options;
		Options.create_if_missing = true;
		Options.table_factory.reset(rocksdb::NewBlockBasedTableFactory(TableOptions));

		return Options;
	}
#endif
	static String IndexStorageConfiguration(StorageOptimization Type, uint64_t IndexPageSize, int64_t IndexCacheSize)
	{
		switch (Type)
		{
			case Tangent::StorageOptimization::Speed:
				return Stringify::Text(
					"PRAGMA journal_mode = WAL;"
					"PRAGMA synchronous = off;"
					"PRAGMA temp_store = memory;"
					"PRAGMA mmap_size = 68719476736;"
					"PRAGMA page_size = %" PRIu64 ";"
					"PRAGMA cache_size = %" PRIi64 ";", IndexPageSize, IndexCacheSize);
			case Tangent::StorageOptimization::Safety:
			default:
				return Stringify::Text(
					"PRAGMA journal_mode = WAL;"
					"PRAGMA synchronous = normal;"
					"PRAGMA temp_store = file;"
					"PRAGMA mmap_size = 68719476736;"
					"PRAGMA page_size = %" PRIu64 ";"
					"PRAGMA cache_size = %" PRIi64 ";", IndexPageSize, IndexCacheSize);
		}
	}

	LayerException::LayerException() : std::exception()
	{
	}
	LayerException::LayerException(String&& Text) : std::exception(), Message(std::move(Text))
	{
	}
	const char* LayerException::what() const noexcept
	{
		return Message.c_str();
	}
	String&& LayerException::message() noexcept
	{
		return std::move(Message);
	}

	RemoteException::RemoteException(int8_t NewStatus) : std::exception(), Status(NewStatus)
	{
	}
	RemoteException::RemoteException(String&& Text) : std::exception(), Message(std::move(Text)), Status(0)
	{
	}
	const char* RemoteException::what() const noexcept
	{
		if (Status > 0)
			return "retry again later (minor failure)";
		else if (Status < 0)
			return "retry again later (major failure)";
		return Message.c_str();
	}
	String&& RemoteException::message() noexcept
	{
		if (Message.empty() && Status > 0)
			Message = "retry again later (minor failure)";
		else if (Message.empty() && Status < 0)
			Message = "retry again later (major failure)";
		return std::move(Message);
	}
	bool RemoteException::retry() const noexcept
	{
		return Status > 0;
	}
	bool RemoteException::shutdown() const noexcept
	{
		return Status < 0;
	}
	RemoteException RemoteException::Retry()
	{
		return RemoteException(1);
	}
	RemoteException RemoteException::Shutdown()
	{
		return RemoteException(-1);
	}

	rocksdb::DB* Repository::LoadBlob(const std::string_view& Location)
	{
#ifdef TAN_ROCKSDB
		UMutex<std::mutex> Unique(Mutex);
		if (TargetPath.empty())
			Resolve(Protocol::Now().User.Network, Protocol::Now().User.Storage.Directory);

		String Address = Stringify::Text("%s%.*sdb", TargetPath.c_str(), (int)Location.size(), Location.data());
		auto It = Blobs.find(Address);
		if (It != Blobs.end() && It->second)
			return It->second;
		
		rocksdb::DB* Result = nullptr;
		auto Status = rocksdb::DB::Open(BlobStorageConfiguration(Protocol::Now().User.Storage.BlobCacheSize), std::string(Address.begin(), Address.end()), &Result);
		if (!Status.ok())
		{
			if (Protocol::Now().User.Storage.Logging)
				VI_ERR("[blobdb] wal append error: %s (location: %s)", Status.ToString().c_str(), Address.c_str());

			return nullptr;
		}

		if (Protocol::Now().User.Storage.Logging)
			VI_DEBUG("[blobdb] wal append on %s (handle: 0x%" PRIXPTR ")", Address.c_str(), (uintptr_t)Result);

		Blobs[Address] = Result;
		return Result;
#else
		return nullptr;
#endif
	}
	UPtr<LDB::Connection> Repository::LoadIndex(const std::string_view& Location, std::function<void(LDB::Connection*)>&& Initializer)
	{
		UMutex<std::mutex> Unique(Mutex);
		if (TargetPath.empty())
			Resolve(Protocol::Now().User.Network, Protocol::Now().User.Storage.Directory);

		UPtr<LDB::Connection> Result;
		String Address = Stringify::Text("file:///%s%.*s.db", TargetPath.c_str(), (int)Location.size(), Location.data());
		auto& Queue = Indices[Address];
		if (!Queue.empty())
		{
			Result = std::move(Queue.front());
			Queue.pop();
			return Result;
		}

		Result = new LDB::Connection();
		auto Status = Result->Connect(Address);
		if (!Status)
		{
			if (Protocol::Now().User.Storage.Logging)
				VI_ERR("[indexdb] wal append error: %s (location: %s)", Status.Error().what(), Address.c_str());
			
			return Result;
		}
		else if (!Result->Query(IndexStorageConfiguration(Protocol::Now().User.Storage.Optimization, Protocol::Now().User.Storage.IndexPageSize, Protocol::Now().User.Storage.IndexCacheSize)))
			return Result;
		else if (Initializer)
			Initializer(*Result);

		if (Protocol::Now().User.Storage.Logging)
			VI_DEBUG("[indexdb] wal append on %s (handle: 0x%" PRIXPTR ")", Address.c_str(), (uintptr_t)*Result);
		
		return Result;
	}
	void Repository::UnloadIndex(UPtr<LDB::Connection>&& Value)
	{
		VI_ASSERT(Value, "connection should be set");
		UMutex<std::mutex> Unique(Mutex);
		auto& Queue = Indices[Value->GetAddress()];
		Queue.push(std::move(Value));
	}
	void Repository::Reset()
	{
		UMutex<std::mutex> Unique(Mutex);
#ifdef TAN_ROCKSDB
		for (auto& Handle : Blobs)
			delete Handle.second;
#endif
		Blobs.clear();
		Indices.clear();
		TargetPath.clear();
	}
	void Repository::Checkpoint()
	{
#ifdef TAN_ROCKSDB
		UMutex<std::mutex> Unique(Mutex);
		for (auto& Handle : Blobs)
		{
			if (!Handle.second)
				continue;

			rocksdb::FlushOptions Options;
			Options.allow_write_stall = true;
			Options.wait = true;

			auto Status = Handle.second->Flush(Options);
			if (Protocol::Now().User.Storage.Logging)
			{
				if (Status.ok())
					VI_DEBUG("[blobdb] wal checkpoint on %s", Handle.first.c_str());
				else
					VI_ERR("[blobdb] wal checkpoint error on: %s (location: %s)", Status.ToString().c_str(), Handle.first.c_str());
			}
		}
#endif
		for (auto& Queue : Indices)
		{
			if (Queue.second.empty())
				continue;

			auto& Handle = Queue.second.front();
			auto States = Handle->WalCheckpoint(LDB::CheckpointMode::Truncate);
			if (Protocol::Now().User.Storage.Logging)
			{
				for (auto& State : States)
					VI_DEBUG("[indexdb] wal checkpoint on %s (db: %s, fc: %i, fs: %i, stat: %i)", Queue.first.c_str(), State.Database.empty() ? "all" : State.Database.c_str(), State.FramesCount, State.FramesSize, State.Status);
			}
		}
	}
	const String& Repository::Resolve(NetworkType Type, const std::string_view& Path)
	{
		if (!TargetPath.empty())
			return TargetPath;

		auto ModuleDirectory = OS::Directory::GetModule();
		if (!ModuleDirectory->empty() && ModuleDirectory->back() != '/' && ModuleDirectory->back() != '\\')
			*ModuleDirectory += VI_SPLITTER;

		auto AbsoluteDirectory = OS::Path::Resolve(Path, *ModuleDirectory, true);
		String BaseDirectory = AbsoluteDirectory ? *AbsoluteDirectory : *ModuleDirectory + String(Path);
		if (!BaseDirectory.empty() && BaseDirectory.back() != '/' && BaseDirectory.back() != '\\')
			BaseDirectory += VI_SPLITTER;

		switch (Type)
		{
			case NetworkType::Regtest:
				BaseDirectory += "regtest";
				break;
			case NetworkType::Testnet:
				BaseDirectory += "testnet";
				break;
			case NetworkType::Mainnet:
				BaseDirectory += "mainnet";
				break;
			default:
				VI_PANIC(false, "invalid network type");
				break;
		}

		BaseDirectory += VI_SPLITTER;
		auto TargetDirectory = OS::Path::Resolve(BaseDirectory);
		VI_PANIC(TargetDirectory && OS::Directory::Patch(*TargetDirectory), "invalid storage path: %s", BaseDirectory.c_str());
		TargetPath = std::move(*TargetDirectory);
		if (!TargetPath.empty() && TargetPath.back() != '/' && TargetPath.back() != '\\')
			TargetPath += VI_SPLITTER;
		return TargetPath;
	}
	const String Repository::Location() const
	{
		return TargetPath;
	}

	String Vectorstate::New()
	{
		auto Data = *Crypto::RandomBytes(KEY_SIZE);
		auto Checksum = *Crypto::HashRaw(Digests::SHA256(), Data);
		return Data + Checksum;
	}
	void Vectorstate::Use(NetworkType Type, const std::string_view& Data)
	{
		VI_PANIC(Data.size() == KEY_SIZE + 32, "invalid key size");
		VI_PANIC(*Crypto::HashRaw(Digests::SHA256(), Data.substr(0, KEY_SIZE)) == Data.substr(KEY_SIZE), "invalid key checksum");
		String Blob = ToString((uint8_t)Type) + String(Data);
		for (size_t i = 0; i < Data.size(); i++)
			Blob = *Crypto::HashRaw(Digests::SHA256(), Blob);
		Key = PrivateKey(Blob);
	}
	ExpectsLR<String> Vectorstate::EncryptBlob(const std::string_view& Data) const
	{
		auto Front = *Crypto::RandomBytes(KEY_FRONT), Back = *Crypto::RandomBytes(KEY_BACK);
		auto Salt = Crypto::HashRaw(Digests::SHA256(), Front + Back);
		auto Result = Crypto::Encrypt(Ciphers::AES_256_CBC(), Data, Key, PrivateKey::GetPlain(*Salt));
		if (!Result)
			return LayerException(std::move(Result.Error().message()));

		Result->insert(Result->begin(), Front.begin(), Front.end());
		Result->append(Back);
		return *Result;
	}
	ExpectsLR<String> Vectorstate::DecryptBlob(const std::string_view& Data) const
	{
		if (Data.size() <= KEY_FRONT + KEY_BACK)
			return LayerException("invalid blob");

		auto Front = Data.substr(0, KEY_FRONT), Back = Data.substr(Data.size() - KEY_BACK);
		auto Salt = Crypto::HashRaw(Digests::SHA256(), String(Front) + String(Back));
		auto Result = Crypto::Decrypt(Ciphers::AES_256_CBC(), Data.substr(KEY_FRONT, Data.size() - KEY_FRONT - KEY_BACK), Key, PrivateKey::GetPlain(*Salt));
		if (!Result)
			return LayerException(std::move(Result.Error().message()));

		return *Result;
	}
	ExpectsLR<String> Vectorstate::EncryptKey(const PrivateKey& Data) const
	{
		auto Value = Data.Expose<2048>();
		return EncryptBlob(Value.View);
	}
	ExpectsLR<PrivateKey> Vectorstate::DecryptKey(const std::string_view& Data) const
	{
		auto Result = DecryptBlob(Data);
		if (!Result)
			return Result.Error();

		return PrivateKey(*Result);
	}

	String Timepoint::Adjust(const SocketAddress& Address, int64_t MillisecondsDelta)
	{
		String Source = Address.GetIpAddress().Or("[bad_address]") + ":" + ToString(Address.GetIpPort().Or(0));
		UMutex<std::mutex> Unique(Mutex);
		size_t Sources = Offsets.size();
		if (MillisecondsDelta != 0)
		{
			auto It = Offsets.find(Source);
			if (It == Offsets.end())
			{
				Offsets[Source] = MillisecondsDelta;
				++Sources;
			}
			else
				It->second = MillisecondsDelta;
		}
		else
			Offsets.erase(Source);

		if (Offsets.size() < 5 || Offsets.size() % 2 != 1)
			return String();

		using TimeSource = std::pair<std::string_view, int64_t>;
		Vector<TimeSource> TimeOffsets;
		TimeOffsets.reserve(Offsets.size());
		for (auto& Item : Offsets)
			TimeOffsets.push_back(std::make_pair(std::string_view(Item.first), Item.second));

		auto& Peer = Protocol::Now().User.P2P;
		std::sort(TimeOffsets.begin(), TimeOffsets.end(), [](const TimeSource& A, const TimeSource& B)
		{
			return A.second < B.second;
		});
		
		bool IsSevereDesync = false;
		auto& MedianTime = TimeOffsets[TimeOffsets.size() / 2];
		if (MedianTime.second > (int64_t)Peer.TimeOffset)
		{
			MedianTime.second = (int64_t)Peer.TimeOffset;
			IsSevereDesync = true;
		}
		else if (MedianTime.second < -(int64_t)Peer.TimeOffset)
		{
			MedianTime.second = -(int64_t)Peer.TimeOffset;
			IsSevereDesync = true;
		}

		MillisecondsOffset = MedianTime.second;
		if (IsSevereDesync)
			return String(MedianTime.first);

		return String();
	}
	uint64_t Timepoint::Now() const
	{
		return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count() + MillisecondsOffset;
	}
	uint64_t Timepoint::NowCPU() const
	{
		return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	}

	void Protocol::Logger::Output(const std::string_view& Message)
	{
		if (!Resource || Message.empty())
			return;

		time_t Time = time(nullptr);
		UMutex<std::recursive_mutex> Unique(Mutex);
		Resource->Write((uint8_t*)Message.data(), Message.size());
		if (Message.back() != '\r' && Message.back() != '\n')
			Resource->Write((uint8_t*)"\n", 1);

		if (!Protocol::Bound() || Time - RepackTime < (int64_t)Protocol::Now().User.Logs.ArchiveRepackInterval)
			return;

		auto State = OS::File::GetProperties(Resource->VirtualName());
		size_t CurrentSize = State ? State->Size : 0;
		RepackTime = Time;
		if (CurrentSize <= Protocol::Now().User.Logs.ArchiveSize)
			return;

		String Path = String(Resource->VirtualName());
		Resource = OS::File::OpenArchive(Path, Protocol::Now().User.Logs.ArchiveSize).Or(nullptr);
	}

	Protocol::Protocol(int Argc, char** Argv)
	{
		auto Environment = Argc > 0 && Argv != nullptr ? OS::Process::ParseArgs(Argc, Argv, (size_t)ArgsFormat::KeyValue) : InlineArgs();
		if (!Environment.Params.empty())
			Path = std::move(Environment.Params.back());

		auto Module = OS::Directory::GetModule();
		if (!Path.empty())
		{
			Path = OS::Path::Resolve(Path, *Module, true).Or(String(Path));
			ErrorHandling::SetFlag(LogOption::Pretty, true);
			ErrorHandling::SetFlag(LogOption::Dated, true);
			ErrorHandling::SetFlag(LogOption::Active, true);
			OS::Directory::SetWorking(Module->c_str());
			Console::Get()->Attach();
		}

		auto Config = UPtr<Schema>(Path.empty() ? (Schema*)nullptr : Schema::FromJSON(OS::File::ReadAsString(Path).Or(String())));
		if (!Environment.Args.empty())
		{
			if (!Config)
				Config = Var::Set::Object();
			for (auto& [Key, Value] : Environment.Args)
			{
				auto Parent = *Config;
				for (auto& Name : Stringify::Split(Key, '.'))
				{
					auto Child = Parent->Get(Name);
					Parent = (Child ? Child : Parent->Set(Name, Var::Set::Object()));
				}
				Parent->Value = Var::Auto(Value);
			}
		}
		if (Config)
		{
			auto* Value = Config->Get("network");
			if (Value != nullptr && Value->Value.Is(VarType::String))
			{
				auto Type = Value->Value.GetBlob();
				if (Type == "mainnet")
					User.Network = NetworkType::Mainnet;
				else if (Type == "testnet")
					User.Network = NetworkType::Testnet;
				else if (Type == "regtest")
					User.Network = NetworkType::Regtest;
			}

			Value = Config->Get("vectorstate");
			if (Value != nullptr && Value->Value.Is(VarType::String))
				User.Vectorstate = Value->Value.GetBlob();

			Value = Config->Get("nodes");
			if (Value != nullptr && Value->Value.GetType() == VarType::Array)
			{
				for (auto& Seed : Value->GetChilds())
				{
					if (Seed->Value.Is(VarType::String))
						User.Nodes.insert(Seed->Value.GetBlob());
				}
			}

			Value = Config->Get("seeds");
			if (Value != nullptr && Value->Value.GetType() == VarType::Array)
			{
				for (auto& Seed : Value->GetChilds())
				{
					if (Seed->Value.Is(VarType::String))
						User.Seeds.insert(Seed->Value.GetBlob());
				}
			}

			Value = Config->Fetch("logs.state");
			if (Value != nullptr && Value->Value.Is(VarType::String))
				User.Logs.State = Value->Value.GetBlob();

			Value = Config->Fetch("logs.message");
			if (Value != nullptr && Value->Value.Is(VarType::String))
				User.Logs.Message = Value->Value.GetBlob();

			Value = Config->Fetch("logs.data");
			if (Value != nullptr && Value->Value.Is(VarType::String))
				User.Logs.Data = Value->Value.GetBlob();

			Value = Config->Fetch("logs.archive_size");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.Logs.ArchiveSize = Value->Value.GetInteger();

			Value = Config->Fetch("logs.archive_repack_interval");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.Logs.ArchiveRepackInterval = Value->Value.GetInteger();

			Value = Config->Fetch("p2p.address");
			if (Value != nullptr && Value->Value.Is(VarType::String))
				User.P2P.Address = Value->Value.GetBlob();

			Value = Config->Fetch("p2p.port");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.P2P.Port = Value->Value.GetInteger();

			Value = Config->Fetch("p2p.time_offset");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.P2P.TimeOffset = Value->Value.GetInteger();

			Value = Config->Fetch("p2p.max_inbound_connections");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.P2P.MaxInboundConnections = (uint32_t)Value->Value.GetInteger();

			Value = Config->Fetch("p2p.max_outbound_connections");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.P2P.MaxOutboundConnections = (uint32_t)Value->Value.GetInteger();

			Value = Config->Fetch("p2p.inventory_size");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.P2P.InventorySize = Value->Value.GetInteger();

			Value = Config->Fetch("p2p.inventory_timeout");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.P2P.InventoryTimeout = Value->Value.GetInteger();

			Value = Config->Fetch("p2p.inventory_cleanup_timeout");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.P2P.InventoryCleanupTimeout = Value->Value.GetInteger();

			Value = Config->Fetch("p2p.rediscovery_timeout");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.P2P.RediscoveryTimeout = Value->Value.GetInteger();

			Value = Config->Fetch("p2p.cursor_size");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.P2P.CursorSize = Value->Value.GetInteger();

			Value = Config->Fetch("p2p.proposer");
			if (Value != nullptr && Value->Value.Is(VarType::Boolean))
				User.P2P.Proposer = Value->Value.GetBoolean();

			Value = Config->Fetch("p2p.server");
			if (Value != nullptr && Value->Value.Is(VarType::Boolean))
				User.P2P.Server = Value->Value.GetBoolean();

			Value = Config->Fetch("p2p.logging");
			if (Value != nullptr && Value->Value.Is(VarType::Boolean))
				User.P2P.Logging = Value->Value.GetBoolean();

			Value = Config->Fetch("rpc.address");
			if (Value != nullptr && Value->Value.Is(VarType::String))
				User.RPC.Address = Value->Value.GetBlob();

			Value = Config->Fetch("rpc.port");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.RPC.Port = Value->Value.GetInteger();

			Value = Config->Fetch("rpc.admin_username");
			if (Value != nullptr && Value->Value.Is(VarType::String))
				User.RPC.AdminUsername = Value->Value.GetBlob();

			Value = Config->Fetch("rpc.admin_password");
			if (Value != nullptr && Value->Value.Is(VarType::String))
				User.RPC.AdminPassword = Value->Value.GetBlob();

			Value = Config->Fetch("rpc.user_useranme");
			if (Value != nullptr && Value->Value.Is(VarType::String))
				User.RPC.UserUsername = Value->Value.GetBlob();

			Value = Config->Fetch("rpc.user_password");
			if (Value != nullptr && Value->Value.Is(VarType::String))
				User.RPC.UserPassword = Value->Value.GetBlob();

			Value = Config->Fetch("rpc.cursor_size");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.RPC.CursorSize = Value->Value.GetInteger();

			Value = Config->Fetch("rpc.page_size");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.RPC.PageSize = Value->Value.GetInteger();

			Value = Config->Fetch("rpc.messaging");
			if (Value != nullptr && Value->Value.Is(VarType::Boolean))
				User.RPC.Messaging = Value->Value.GetBoolean();

			Value = Config->Fetch("rpc.websockets");
			if (Value != nullptr && Value->Value.Is(VarType::Boolean))
				User.RPC.WebSockets = Value->Value.GetBoolean();

			Value = Config->Fetch("rpc.server");
			if (Value != nullptr && Value->Value.Is(VarType::Boolean))
				User.RPC.Server = Value->Value.GetBoolean();

			Value = Config->Fetch("rpc.logging");
			if (Value != nullptr && Value->Value.Is(VarType::Boolean))
				User.RPC.Logging = Value->Value.GetBoolean();

			Value = Config->Fetch("nds.address");
			if (Value != nullptr && Value->Value.Is(VarType::String))
				User.NDS.Address = Value->Value.GetBlob();

			Value = Config->Fetch("nds.port");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.NDS.Port = Value->Value.GetInteger();

			Value = Config->Fetch("nds.cursor_size");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.NDS.CursorSize = Value->Value.GetInteger();

			Value = Config->Fetch("nds.server");
			if (Value != nullptr && Value->Value.Is(VarType::Boolean))
				User.NDS.Server = Value->Value.GetBoolean();

			Value = Config->Fetch("nds.logging");
			if (Value != nullptr && Value->Value.Is(VarType::Boolean))
				User.NDS.Logging = Value->Value.GetBoolean();

			Value = Config->Fetch("nss.block_replay_multiplier");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.NSS.BlockReplayMultiplier = Value->Value.GetInteger();

			Value = Config->Fetch("nss.relaying_timeout");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.NSS.RelayingTimeout = Value->Value.GetInteger();

			Value = Config->Fetch("nss.relaying_retry_timeout");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.NSS.RelayingRetryTimeout = Value->Value.GetInteger();

			Value = Config->Fetch("nss.cache_short_size");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.NSS.CacheShortSize = (uint32_t)Value->Value.GetInteger();

			Value = Config->Fetch("nss.cache_extended_size");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.NSS.CacheExtendedSize = (uint32_t)Value->Value.GetInteger();

			Value = Config->Fetch("nss.fee_estimation_seconds");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.NSS.FeeEstimationSeconds = Value->Value.GetInteger();

			Value = Config->Fetch("nss.withdrawal_time");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.NSS.WithdrawalTime = Value->Value.GetInteger();

			Value = Config->Fetch("nss.server");
			if (Value != nullptr && Value->Value.Is(VarType::Boolean))
				User.NSS.Server = Value->Value.GetBoolean();

			Value = Config->Fetch("nss.logging");
			if (Value != nullptr && Value->Value.Is(VarType::Boolean))
				User.NSS.Logging = Value->Value.GetBoolean();

			Value = Config->Fetch("tcp.tls_trusted_peers");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.TCP.TlsTrustedPeers = Value->Value.GetInteger();

			Value = Config->Fetch("tcp.timeout");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.TCP.Timeout = Value->Value.GetInteger();

			Value = Config->Fetch("storage.directory");
			if (Value != nullptr && Value->Value.Is(VarType::String))
				User.Storage.Directory = Value->Value.GetBlob();

			Value = Config->Fetch("storage.optimization");
			if (Value != nullptr && Value->Value.Is(VarType::String))
			{
				auto Type = Value->Value.GetBlob();
				if (Type == "speed")
					User.Storage.Optimization = StorageOptimization::Speed;
				else if (Type == "safety")
					User.Storage.Optimization = StorageOptimization::Safety;
			}

			Value = Config->Fetch("storage.checkpoint_size");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.Storage.CheckpointSize = Value->Value.GetInteger();
				
			Value = Config->Fetch("storage.transaction_timeout");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.Storage.TransactionTimeout = Value->Value.GetInteger();

			Value = Config->Fetch("storage.transaction_dispatch_repeat_interval");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.Storage.TransactionDispatchRepeatInterval = Value->Value.GetInteger();

			Value = Config->Fetch("storage.location_cache_size");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.Storage.LocationCacheSize = Value->Value.GetInteger();

			Value = Config->Fetch("storage.script_cache_size");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.Storage.ScriptCacheSize = Value->Value.GetInteger();

			Value = Config->Fetch("storage.blob_cache_size");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.Storage.BlobCacheSize = Value->Value.GetInteger();

			Value = Config->Fetch("storage.index_page_size");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.Storage.IndexPageSize = Value->Value.GetInteger();

			Value = Config->Fetch("storage.index_cache_size");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.Storage.IndexCacheSize = Value->Value.GetInteger();

			Value = Config->Fetch("storage.flush_threads_ratio");
			if (Value != nullptr && Value->Value.Is(VarType::Number))
				User.Storage.FlushThreadsRatio = Value->Value.GetNumber();

			Value = Config->Fetch("storage.compaction_threads_ratio");
			if (Value != nullptr && Value->Value.Is(VarType::Number))
				User.Storage.CompactionThreadsRatio = Value->Value.GetNumber();

			Value = Config->Fetch("storage.computation_threads_ratio");
			if (Value != nullptr && Value->Value.Is(VarType::Number))
				User.Storage.ComputationThreadsRatio = Value->Value.GetNumber();

			Value = Config->Fetch("storage.prune_aggressively");
			if (Value != nullptr && Value->Value.Is(VarType::Boolean))
				User.Storage.PruneAggressively = Value->Value.GetBoolean();

			Value = Config->Fetch("storage.transaction_to_account_index");
			if (Value != nullptr && Value->Value.Is(VarType::Boolean))
				User.Storage.TransactionToAccountIndex = Value->Value.GetBoolean();

			Value = Config->Fetch("storage.transaction_to_rollup_index");
			if (Value != nullptr && Value->Value.Is(VarType::Boolean))
				User.Storage.TransactionToRollupIndex = Value->Value.GetBoolean();

			Value = Config->Fetch("storage.logging");
			if (Value != nullptr && Value->Value.Is(VarType::Boolean))
				User.Storage.Logging = Value->Value.GetBoolean();

			User.NSS.Options = Config->Get("nss");
			if (User.NSS.Options)
				User.NSS.Options->Unlink();
		}

		if (!User.Logs.State.empty())
		{
			auto LogBase = Database.Resolve(User.Network, User.Storage.Directory) + User.Logs.State;
			auto LogPath = OS::Path::Resolve(OS::Path::Resolve(LogBase, *Module, true).Or(User.Logs.State)).Or(User.Logs.State);
			Stringify::EvalEnvs(LogPath, OS::Path::GetDirectory(LogPath.c_str()), Vitex::Network::Utils::GetHostIpAddresses());
			OS::Directory::Patch(OS::Path::GetDirectory(LogPath.c_str()));
			if (!LogPath.empty())
			{
				Logs.State.Resource = OS::File::OpenArchive(LogPath, User.Logs.ArchiveSize).Or(nullptr);
				if (Logs.State.Resource)
					ErrorHandling::SetCallback([this](ErrorHandling::Details& Data) { Logs.State.Output(ErrorHandling::GetMessageText(Data)); });
			}
		}

		if (!User.Logs.Message.empty())
		{
			auto LogBase = Database.Resolve(User.Network, User.Storage.Directory) + User.Logs.Message;
			auto LogPath = OS::Path::Resolve(OS::Path::Resolve(LogBase, *Module, true).Or(User.Logs.Message)).Or(User.Logs.Message);
			Stringify::EvalEnvs(LogPath, OS::Path::GetDirectory(LogPath.c_str()), Vitex::Network::Utils::GetHostIpAddresses());
			OS::Directory::Patch(OS::Path::GetDirectory(LogPath.c_str()));
			if (!LogPath.empty())
				Logs.Message.Resource = OS::File::OpenArchive(LogPath, User.Logs.ArchiveSize).Or(nullptr);
		}

		if (!User.Logs.Data.empty())
		{
			auto LogBase = Database.Resolve(User.Network, User.Storage.Directory) + User.Logs.Data;
			auto LogPath = OS::Path::Resolve(OS::Path::Resolve(LogBase, *Module, true).Or(User.Logs.Data)).Or(User.Logs.Data);
			Stringify::EvalEnvs(LogPath, OS::Path::GetDirectory(LogPath.c_str()), Vitex::Network::Utils::GetHostIpAddresses());
			OS::Directory::Patch(OS::Path::GetDirectory(LogPath.c_str()));
			if (!LogPath.empty())
			{
				Logs.Data.Resource = OS::File::OpenArchive(LogPath, User.Logs.ArchiveSize).Or(nullptr);
				if (Logs.Data.Resource)
					LDB::Driver::Get()->SetQueryLog([this](const std::string_view& Data) { Logs.Data.Output(String(Data)); });
			}
		}

		Instance = this;
		if (Config)
		{
			auto VectorstateBase = Database.Resolve(User.Network, User.Storage.Directory) + User.Vectorstate;
			auto VectorstatePath = OS::Path::Resolve(OS::Path::Resolve(VectorstateBase, *Module, true).Or(User.Vectorstate)).Or(User.Vectorstate);
			auto VectorstateFile = OS::File::ReadAsString(VectorstatePath);
			if (!VectorstateFile)
			{
				VectorstateFile = Key.New();
				VI_PANIC(Location(VectorstatePath).Protocol == "file", "cannot save vectorstate into %s", VectorstatePath.c_str());
				OS::Directory::Patch(OS::Path::GetDirectory(VectorstatePath)).Expect("cannot save vectorstate into " + VectorstatePath);
				OS::File::Write(VectorstatePath, (uint8_t*)VectorstateFile->data(), VectorstateFile->size()).Expect("cannot save vectorstate into " + VectorstatePath);
			}
			Key.Use(User.Network, *VectorstateFile);
		}
		else
			Key.Use(User.Network, Key.New());

		switch (User.Network)
		{
			case Tangent::NetworkType::Regtest:
				Message.PacketMagic = 0xe249c307;
				Account.SecretKeyPrefix = "secrt";
				Account.PublicKeyPrefix = "pubrt";
				Account.AddressPrefix = "tcrt";
				Account.SecretKeyVersion = 0xD;
				Account.PublicKeyVersion = 0xC;
				Account.AddressVersion = 0x6;
				Policy.AccountContributionRequired = 0.0;
				Policy.AccountGasWorkRequired = 0.0;
				Policy.ConsensusProofTime = 30;
				Policy.TransactionThroughput = 21000;
				User.NSS.WithdrawalTime = Policy.ConsensusProofTime;
				break;
			case Tangent::NetworkType::Testnet:
				Message.PacketMagic = 0xf815c95c;
				Account.SecretKeyPrefix = "sect";
				Account.PublicKeyPrefix = "pubt";
				Account.AddressPrefix = "tct";
				Account.SecretKeyVersion = 0xE;
				Account.PublicKeyVersion = 0xD;
				Account.AddressVersion = 0x5;
				break;
			case Tangent::NetworkType::Mainnet:
				break;
			default:
				VI_PANIC(false, "bad network type");
				break;
		}

		Uplinks::LinkInstance();
		Algorithm::Signing::Initialize();
	}
	Protocol::~Protocol()
	{
		Database.Checkpoint();
		Storages::AccountCache::CleanupInstance();
		Storages::UniformCache::CleanupInstance();
		Storages::MultiformCache::CleanupInstance();
		NSS::ServerNode::CleanupInstance();
		Ledger::ScriptHost::CleanupInstance();
		Algorithm::Signing::Deinitialize();
		ErrorHandling::SetCallback(nullptr);
		if (Instance == this)
			Instance = nullptr;
	}
	bool Protocol::Is(NetworkType Type) const
	{
		return User.Network == Type;
	}
	Protocol::Logger& Protocol::StateLog()
	{
		return Logs.State;
	}
	Protocol::Logger& Protocol::MessageLog()
	{
		return Logs.Message;
	}
	Protocol::Logger& Protocol::DataLog()
	{
		return Logs.Data;
	}
	bool Protocol::Bound()
	{
		return Instance != nullptr;
	}
	Protocol& Protocol::Change()
	{
		VI_ASSERT(Instance != nullptr, "chain parameters are not set!");
		return *Instance;
	}
	const Protocol& Protocol::Now()
	{
		VI_ASSERT(Instance != nullptr, "chain parameters are not set!");
		return *Instance;
	}
	Protocol* Protocol::Instance = nullptr;
}
