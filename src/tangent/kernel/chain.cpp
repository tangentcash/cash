#include "chain.h"
#include "script.h"
#ifdef TAN_VALIDATOR
#include "oracle.h"
#include "../policy/storages.h"
#ifdef TAN_ROCKSDB
#include "rocksdb/db.h"
#include "rocksdb/table.h"
#endif
#endif
extern "C"
{
#include "../../utils/tiny-bitcoin/ecc.h"
}
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
	LayerException::LayerException(String&& Text) : std::exception(), Info(std::move(Text))
	{
	}
	const char* LayerException::what() const noexcept
	{
		return Info.c_str();
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
			return It->second.get();
		
		rocksdb::DB* Result = nullptr;
		auto Status = rocksdb::DB::Open(BlobStorageConfiguration(Protocol::Now().User.Storage.BlobCacheSize), std::string(Address.begin(), Address.end()), &Result);
		if (!Status.ok())
		{
			VI_ERR("[blobdb] wal append error: %s (location: %s)", Status.ToString().c_str(), Address.c_str());
			return nullptr;
		}

		VI_DEBUG("[blobdb] wal append on %s (handle: 0x%" PRIXPTR ")", Address.c_str(), (uintptr_t)Result);
		Blobs[Address] = std::unique_ptr<rocksdb::DB>(Result);
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
			VI_ERR("[indexdb] wal append error: %s (location: %s)", Status.Error().what(), Address.c_str());
			return Result;
		}
		else if (!Result->Query(IndexStorageConfiguration(Protocol::Now().User.Storage.Optimization, Protocol::Now().User.Storage.IndexPageSize, Protocol::Now().User.Storage.IndexCacheSize)))
			return Result;
		else if (Initializer)
			Initializer(*Result);

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
		Blobs.clear();
		Indices.clear();
		TargetPath.clear();
	}
	void Repository::Checkpoint()
	{
		UMutex<std::mutex> Unique(Mutex);
		for (auto& Handle : Blobs)
		{
			if (!Handle.second)
				continue;

			rocksdb::FlushOptions Options;
			Options.allow_write_stall = true;
			Options.wait = true;

			auto Status = Handle.second->Flush(Options);
			if (Status.ok())
				VI_DEBUG("[blobdb] wal checkpoint on %s", Handle.first.c_str());
			else
				VI_ERR("[blobdb] wal checkpoint error on: %s (location: %s)", Status.ToString().c_str(), Handle.first.c_str());
		}
		for (auto& Queue : Indices)
		{
			if (Queue.second.empty())
				continue;

			auto& Handle = Queue.second.front();
			auto States = Handle->WalCheckpoint(LDB::CheckpointMode::Truncate);
			for (auto& State : States)
				VI_DEBUG("[indexdb] wal checkpoint on %s (db: %s, fc: %i, fs: %i, stat: %i)", Queue.first.c_str(), State.Database.empty() ? "all" : State.Database.c_str(), State.FramesCount, State.FramesSize, State.Status);
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
		return EncryptBlob(std::string_view(Value.Key, Value.Size));
	}
	ExpectsLR<PrivateKey> Vectorstate::DecryptKey(const std::string_view& Data) const
	{
		auto Result = DecryptBlob(Data);
		if (!Result)
			return Result.Error();

		return PrivateKey(*Result);
	}

	String Timepoint::Adjust(const String& Source, int64_t MillisecondsDelta)
	{
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
		if (MedianTime.second > (int64_t)Peer.NodeTimeOffset)
		{
			MedianTime.second = (int64_t)Peer.NodeTimeOffset;
			IsSevereDesync = true;
		}
		else if (MedianTime.second < -(int64_t)Peer.NodeTimeOffset)
		{
			MedianTime.second = -(int64_t)Peer.NodeTimeOffset;
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

	Protocol::Protocol(const std::string_view& ConfigPath)
	{
#ifdef TAN_VALIDATOR
		auto Module = OS::Directory::GetModule();
		Path = OS::Path::Resolve(ConfigPath, *Module, true).Or(String(ConfigPath));

		auto Config = UPtr<Schema>(Schema::FromJSON(OS::File::ReadAsString(Path).Or(String())));
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

			Value = Config->Get("seeds");
			if (Value != nullptr && Value->Value.GetType() == VarType::Array)
			{
				for (auto& Seed : Value->GetChilds())
				{
					if (Seed->Value.Is(VarType::String))
						User.Seeds.insert(Seed->Value.GetBlob());
				}
			}

			Value = Config->Fetch("p2p.node_address");
			if (Value != nullptr && Value->Value.Is(VarType::String))
				User.P2P.NodeAddress = Value->Value.GetBlob();

			Value = Config->Fetch("p2p.node_timeout");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.P2P.NodeTimeout = Value->Value.GetInteger();

			Value = Config->Fetch("p2p.node_time_offset");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.P2P.NodeTimeOffset = Value->Value.GetInteger();

			Value = Config->Fetch("p2p.tls_trusted_peers");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.P2P.TlsTrustedPeers = Value->Value.GetInteger();

			Value = Config->Fetch("p2p.tls_validity_days");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.P2P.TlsValidityDays = Value->Value.GetInteger();

			Value = Config->Fetch("p2p.cursor_size");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.P2P.CursorSize = Value->Value.GetInteger();

			Value = Config->Fetch("p2p.max_inbound_connections");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.P2P.MaxInboundConnections = Value->Value.GetInteger();

			Value = Config->Fetch("p2p.max_outbound_connections");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.P2P.MaxOutboundConnections = Value->Value.GetInteger();

			Value = Config->Fetch("p2p.proposer");
			if (Value != nullptr && Value->Value.Is(VarType::Boolean))
				User.P2P.Proposer = Value->Value.GetBoolean();

			Value = Config->Fetch("p2p.server");
			if (Value != nullptr && Value->Value.Is(VarType::Boolean))
				User.P2P.Server = Value->Value.GetBoolean();

			Value = Config->Fetch("rpc.node_address");
			if (Value != nullptr && Value->Value.Is(VarType::String))
				User.RPC.NodeAddress = Value->Value.GetBlob();

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

			Value = Config->Fetch("p2p.cursor_size");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.RPC.CursorSize = Value->Value.GetInteger();

			Value = Config->Fetch("p2p.page_size");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.RPC.PageSize = Value->Value.GetInteger();

			Value = Config->Fetch("rpc.server");
			if (Value != nullptr && Value->Value.Is(VarType::Boolean))
				User.RPC.Server = Value->Value.GetBoolean();

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

			Value = Config->Fetch("storage.transaction_to_account_index");
			if (Value != nullptr && Value->Value.Is(VarType::Boolean))
				User.Storage.TransactionToAccountIndex = Value->Value.GetBoolean();

			Value = Config->Fetch("storage.transaction_to_rollup_index");
			if (Value != nullptr && Value->Value.Is(VarType::Boolean))
				User.Storage.TransactionToRollupIndex = Value->Value.GetBoolean();

			Value = Config->Fetch("storage.full_block_history");
			if (Value != nullptr && Value->Value.Is(VarType::Boolean))
				User.Storage.FullBlockHistory = Value->Value.GetBoolean();

			Value = Config->Fetch("oracle.block_replay_multiplier");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.Oracle.BlockReplayMultiplier = Value->Value.GetInteger();

			Value = Config->Fetch("oracle.relaying_timeout");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.Oracle.RelayingTimeout = Value->Value.GetInteger();

			Value = Config->Fetch("oracle.relaying_retry_timeout");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.Oracle.RelayingRetryTimeout = Value->Value.GetInteger();

			Value = Config->Fetch("oracle.cache_short_size");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.Oracle.CacheShortSize = Value->Value.GetInteger();

			Value = Config->Fetch("oracle.cache_extended_size");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.Oracle.CacheExtendedSize = Value->Value.GetInteger();

			Value = Config->Fetch("oracle.fee_estimation_seconds");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.Oracle.FeeEstimationSeconds = Value->Value.GetInteger();

			Value = Config->Fetch("oracle.withdrawal_time");
			if (Value != nullptr && Value->Value.Is(VarType::Integer))
				User.Oracle.WithdrawalTime = Value->Value.GetInteger();

			Value = Config->Fetch("oracle.observer");
			if (Value != nullptr && Value->Value.Is(VarType::Boolean))
				User.Oracle.Observer = Value->Value.GetBoolean();
		}
		if (Config)
			VI_DEBUG("[chain] open handle: %s", Path.c_str());

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
#endif
		switch (User.Network)
		{
			case Tangent::NetworkType::Regtest:
				Message.PacketVersion = 0xe249c307;
				Message.MinDataVersion = 0x1;
				Message.MaxDataVersion = 0x1;
				Account.PrivateKeyPrefix = "prvrt";
				Account.PublicKeyPrefix = "pubrt";
				Account.AddressPrefix = "tanrt";
				Account.SealingPrivateKeyPrefix = "sprvrt";
				Account.SealingPublicKeyPrefix = "spubrt";
				Account.PrivateKeyVersion = 0xD;
				Account.PublicKeyVersion = 0xC;
				Account.AddressVersion = 0x6;
				Account.SealingPrivateKeyVersion = 0xB;
				Account.SealingPublicKeyVersion = 0xA;
				Policy.AccountContributionRequired = 0.0;
				Policy.AccountGasWorkRequired = 0.0;
				User.Oracle.WithdrawalTime = Policy.ConsensusProofTime;
				break;
			case Tangent::NetworkType::Testnet:
				Message.PacketVersion = 0xf815c95c;
				Message.MinDataVersion = 0x2;
				Message.MaxDataVersion = 0x2;
				Account.PrivateKeyPrefix = "prvt";
				Account.PublicKeyPrefix = "pubt";
				Account.AddressPrefix = "tant";
				Account.SealingPrivateKeyPrefix = "sprvt";
				Account.SealingPublicKeyPrefix = "spubt";
				Account.PrivateKeyVersion = 0xE;
				Account.PublicKeyVersion = 0xD;
				Account.AddressVersion = 0x5;
				Account.SealingPrivateKeyVersion = 0xC;
				Account.SealingPublicKeyVersion = 0xB;
				break;
			case Tangent::NetworkType::Mainnet:
			default:
				break;
		}

		Instance = this;
		btc_ecc_start();
		Console::Get()->Attach();
		ErrorHandling::SetFlag(LogOption::Active, true);
		ErrorHandling::SetFlag(LogOption::Dated, true);
		Uplinks::LinkInstance();
#ifdef TAN_VALIDATOR
		OS::Directory::SetWorking(Module->c_str());
		Oracle::Bridge::Open(*Config, User.Oracle.Observer);
#endif
	}
	Protocol::~Protocol()
	{
		Database.Checkpoint();
#ifdef TAN_VALIDATOR
		if (!Path.empty())
			VI_DEBUG("[chain] close handle: %s", Path.c_str());
		Oracle::Bridge::Close();
		Storages::LocationCache::CleanupInstance();
#endif
		Ledger::ScriptHost::CleanupInstance();
		btc_ecc_stop();
		if (Instance == this)
			Instance = nullptr;
	}
	bool Protocol::Is(NetworkType Type) const
	{
		return User.Network == Type;
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