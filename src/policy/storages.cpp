#include "storages.h"
#include "transactions.h"
#include "states.h"
#undef NULL

namespace Tangent
{
	namespace Storages
	{
		struct TransactionPartyBlob
		{
			Algorithm::Pubkeyhash Owner;
		};

		struct TransactionAliasBlob
		{
			uint8_t TransactionHash[32];
		};

		struct TransactionBlob
		{
			Algorithm::Pubkeyhash Owner;
			uint8_t TransactionHash[32];
			uint8_t ReceiptHash[32];
			Format::Stream TransactionMessage;
			Format::Stream ReceiptMessage;
			uint64_t TransactionNumber;
			uint64_t BlockNonce;
			uint64_t DispatchNumber;
			Vector<TransactionPartyBlob> Parties;
			Vector<TransactionAliasBlob> Aliases;
			const Ledger::BlockTransaction* Context;
		};

		struct StateBlob
		{
			Format::Stream Message;
			String Address;
			String Stride;
			int64_t Weight;
			const Ledger::State* Context;
		};

		static void FinalizeChecksum(Messages::Generic& Message, const LDB::Column& Column)
		{
			auto Hash = Column.Get().GetBlob();
			if (Hash.size() == sizeof(uint256_t))
				Algorithm::Encoding::EncodeUint256((uint8_t*)Hash.data(), Message.Checksum);
		}
		static void FinalizeChecksum(Messages::Authentic& Message, const LDB::Column& Column)
		{
			auto Hash = Column.Get().GetBlob();
			if (Hash.size() == sizeof(uint256_t))
				Algorithm::Encoding::EncodeUint256((uint8_t*)Hash.data(), Message.Checksum);
		}

		void LocationCache::ClearLocations()
		{
			UMutex<std::mutex> Unique(Mutex);
			Addresses.clear();
			Strides.clear();
			Owners.clear();
		}
		void LocationCache::ClearLocation(const Option<String>& Address, const Option<String>& Stride, const Option<String>& Owner)
		{
			UMutex<std::mutex> Unique(Mutex);
			if (Address)
			{
				auto It = Addresses.find(*Address);
				if (It != Addresses.end() && !It->second)
					Addresses.erase(It);
			}
			if (Stride)
			{
				auto It = Strides.find(*Stride);
				if (It != Strides.end() && !It->second)
					Strides.erase(It);
			}
			if (Owner)
			{
				auto It = Owners.find(*Owner);
				if (It != Owners.end() && !It->second)
					Owners.erase(It);
			}
		}
		void LocationCache::SetStateLocation(const std::string_view& Address, const std::string_view& Stride, uint64_t AddressLocation, uint64_t StrideLocation)
		{
			auto Size = Protocol::Now().User.Storage.LocationCacheSize;
			String TargetAddress = String(Address);
			String TargetStride = String(Stride);
			UMutex<std::mutex> Unique(Mutex);
			if (Addresses.size() >= Size)
				Addresses.clear();
			if (Strides.size() >= Size)
				Strides.clear();
			Addresses[TargetAddress] = AddressLocation;
			Strides[TargetStride] = StrideLocation;
		}
		void LocationCache::SetAddressLocation(const std::string_view& Hash, uint64_t Location)
		{
			auto Size = Protocol::Now().User.Storage.LocationCacheSize;
			String Target = String(Hash);
			UMutex<std::mutex> Unique(Mutex);
			if (Addresses.size() >= Size)
				Addresses.clear();
			Addresses[Target] = Location;
		}
		void LocationCache::SetStrideLocation(const std::string_view& Hash, uint64_t Location)
		{
			auto Size = Protocol::Now().User.Storage.LocationCacheSize;
			String Target = String(Hash);
			UMutex<std::mutex> Unique(Mutex);
			if (Strides.size() >= Size)
				Strides.clear();
			Strides[Target] = Location;
		}
		void LocationCache::SetOwnerLocation(const std::string_view& Hash, uint64_t Location)
		{
			auto Size = Protocol::Now().User.Storage.LocationCacheSize;
			String Target = String(Hash);
			UMutex<std::mutex> Unique(Mutex);
			if (Owners.size() >= Size)
				Owners.clear();
			Owners[Target] = Location;
		}
		Option<uint64_t> LocationCache::GetAddressLocation(const std::string_view& Hash)
		{
			UMutex<std::mutex> Unique(Mutex);
			auto It = Addresses.find(Hash);
			if (It == Addresses.end())
				return Optional::None;

			return It->second;
		}
		Option<uint64_t> LocationCache::GetStrideLocation(const std::string_view& Hash)
		{
			UMutex<std::mutex> Unique(Mutex);
			auto It = Strides.find(Hash);
			if (It == Strides.end())
				return Optional::None;

			return It->second;
		}
		Option<uint64_t> LocationCache::GetOwnerLocation(const std::string_view& Hash)
		{
			UMutex<std::mutex> Unique(Mutex);
			auto It = Owners.find(Hash);
			if (It == Owners.end())
				return Optional::None;

			return It->second;
		}

		std::string_view WeightQuery::AsCondition() const
		{
			switch (Condition)
			{
				case Tangent::Storages::PositionCondition::Greater:
					return ">";
				case Tangent::Storages::PositionCondition::GreaterEqual:
					return ">=";
				case Tangent::Storages::PositionCondition::NotEqual:
					return "<>";
				case Tangent::Storages::PositionCondition::Less:
					return "<";
				case Tangent::Storages::PositionCondition::LessEqual:
					return "<=";
				case Tangent::Storages::PositionCondition::Equal:
				default:
					return "=";
			}
		}
		std::string_view WeightQuery::AsOrder() const
		{
			return Order <= 0 ? "DESC" : "ASC";
		}
		WeightQuery WeightQuery::From(const std::string_view& Query, int64_t Value, int8_t Order)
		{
			if (Query == "gt" || Query == ">")
				return Greater(Value, Order);
			else if (Query == "gte" || Query == ">=")
				return GreaterEqual(Value, Order);
			else if (Query == "eq" || Query == "=" || Query == "==")
				return Equal(Value, Order);
			else if (Query == "neq" || Query == "<>" || Query == "!=")
				return NotEqual(Value, Order);
			else if (Query == "lt" || Query == "<")
				return Less(Value, Order);
			else if (Query == "lte" || Query == "<=")
				return LessEqual(Value, Order);
			return Equal(Value, Order);
		}

		static thread_local Chainstate* LatestChainstate = nullptr;
		Chainstate::Chainstate(const std::string_view& NewLabel) noexcept : Label(NewLabel), Borrows(false)
		{
			if (LatestChainstate != nullptr)
			{
				HottestStorage = *LatestChainstate->HottestStorage;
				Borrows = !!HottestStorage;
			}
			if (!Borrows)
			{
				StorageOf("chainstate");
				if (HottestStorage)
					LatestChainstate = this;
			}
		}
		Chainstate::~Chainstate() noexcept
		{
			if (Borrows)
				HottestStorage.Reset();
			if (LatestChainstate == this)
				LatestChainstate = nullptr;
		}
		ExpectsLR<void> Chainstate::Revert(uint64_t BlockNumber)
		{
			auto CheckpointNumber = GetCheckpointBlockNumber();
			if (CheckpointNumber && *CheckpointNumber > BlockNumber)
				return ExpectsLR<void>(LayerException("revert failed due to a checkpoint at block " + ToString(*CheckpointNumber)));

			SchemaList Map;
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(BlockNumber));

			auto Cursor = ArchiveEmplaceQueryRecursive(Label, __func__,
				"DELETE FROM checkpoints WHERE block_number > ?;"
				"DELETE FROM parties WHERE block_number > ?;"
				"DELETE FROM owners WHERE block_number > ?;"
				"DELETE FROM aliases WHERE block_number > ?;"
				"DELETE FROM transactions WHERE block_number > ?;"
				"DELETE FROM statetries WHERE block_number > ?;"
				"INSERT OR REPLACE INTO states (address_number, stride_number, block_number, weight, message) SELECT address_number, stride_number, MAX(block_number), weight, message FROM statetries WHERE block_number <= ? GROUP BY address_number, stride_number;"
				"DELETE FROM addresses WHERE block_number > ?;"
				"DELETE FROM strides WHERE block_number > ?;"
				"DELETE FROM blocks WHERE block_number > ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			auto* Cache = LocationCache::Get();
			Cache->ClearLocations();
			return Expectation::Met;
		}
		ExpectsLR<void> Chainstate::Dispatch(const Vector<uint256_t>& TransactionHashes)
		{
			if (TransactionHashes.empty())
				return Expectation::Met;

			UPtr<Schema> Hashes = Var::Set::Array();
			for (auto& Item : TransactionHashes)
			{
				uint8_t Hash[32];
				Algorithm::Encoding::DecodeUint256(Item, Hash);
				Hashes->Push(Var::Binary(Hash, sizeof(Hash)));
			}

			SchemaList Map;
			Map.push_back(Var::Set::String(*LDB::Utils::InlineArray(std::move(Hashes))));

			auto Cursor = ArchiveEmplaceQuery(Label, __func__, "UPDATE transactions SET dispatch_queue = NULL WHERE transaction_hash IN ($?)", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<void> Chainstate::Prune(Pruning Type, uint64_t BlockNumber)
		{
			auto LatestCheckpoint = GetCheckpointBlockNumber().Or(0);
			if (BlockNumber <= LatestCheckpoint)
				return Expectation::Met;

			SchemaList Map;
			Map.push_back(Var::Set::Integer(BlockNumber));

			String Query = "INSERT OR IGNORE INTO checkpoints (block_number) VALUES (?);";
			switch (Type)
			{
				case Tangent::Storages::Pruning::Statetrie:
					Map.push_back(Var::Set::Integer(BlockNumber));
					Query += "DELETE FROM statetries WHERE block_number < ?; VACUUM";
					break;
				case Tangent::Storages::Pruning::Blocktrie:
					Map.push_back(Var::Set::Integer(BlockNumber));
					Query += "UPDATE blocks SET message = '' WHERE block_number < ?; VACUUM";
					break;
				case Tangent::Storages::Pruning::Transactiontrie:
					Map.push_back(Var::Set::Integer(BlockNumber));
					Map.push_back(Var::Set::Integer(BlockNumber));
					Map.push_back(Var::Set::Integer(BlockNumber));
					Query += "UPDATE transactions SET message = '' WHERE block_number < ?; VACUUM";
					break;
				default:
					return ExpectsLR<void>(LayerException("invalid prune type"));
			}

			auto Cursor = ArchiveEmplaceQueryRecursive(Label, __func__, Query, &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<void> Chainstate::Checkpoint(const Ledger::Block& Value)
		{
			Format::Stream BlockHeaderMessage;
			if (!Value.AsHeader().Store(&BlockHeaderMessage))
				return ExpectsLR<void>(LayerException("block header serialization error"));

			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(Value.AsHash(), Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Integer(Value.Number));
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));
			Map.push_back(Var::Set::Binary(BlockHeaderMessage.Data));

			auto* Cache = LocationCache::Get();
			auto Cursor = EmplaceQuery(Label, __func__, "INSERT INTO blocks (block_number, block_hash, message) VALUES (?, ?, ?); SELECT MAX(transaction_number) AS counter FROM transactions", &Map);
			if (!Cursor || Cursor->Error() || Cursor->Size() != 2)
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			auto CommitTransactionData = HottestStorage->PrepareStatement("INSERT INTO transactionviews (transaction_number, transaction_owner_hash, transaction_hash, receipt_hash, dispatch_queue, block_number, block_nonce, transaction_message, receipt_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", nullptr);
			if (!CommitTransactionData)
				return ExpectsLR<void>(LayerException(std::move(CommitTransactionData.Error().message())));

			auto CommitTransactionParty = HottestStorage->PrepareStatement("INSERT INTO partyviews (transaction_number, transaction_owner_hash, block_number) VALUES (?, ?, ?)", nullptr);
			if (!CommitTransactionParty)
				return ExpectsLR<void>(LayerException(std::move(CommitTransactionParty.Error().message())));

			auto CommitTransactionAlias = HottestStorage->PrepareStatement("INSERT INTO aliases (transaction_number, transaction_hash, block_number) VALUES (?, ?, ?)", nullptr);
			if (!CommitTransactionAlias)
				return ExpectsLR<void>(LayerException(std::move(CommitTransactionAlias.Error().message())));

			auto CommitStateData = HottestStorage->PrepareStatement("INSERT INTO stateviews (address_hash, stride_hash, block_number, weight, message) VALUES (?, ?, ?, ?, ?)", nullptr);
			if (!CommitStateData)
				return ExpectsLR<void>(LayerException(std::move(CommitStateData.Error().message())));

			uint64_t TransactionCounter = Cursor->At(1).Front()["counter"].Get().GetInteger();
			Vector<TransactionBlob> Transactions;
			Transactions.resize(Value.Transactions.size());
			for (size_t i = 0; i < Transactions.size(); i++)
			{
				TransactionBlob& Blob = Transactions[i];
				Blob.TransactionNumber = ++TransactionCounter;
				Blob.BlockNonce = (uint64_t)i;
				Blob.Context = &Value.Transactions[i];
			}
			ParallelForEach(Transactions.begin(), Transactions.end(), [&](TransactionBlob& Item)
			{
				Item.ReceiptMessage.Data.reserve(1024);
				Item.Context->Transaction->Store(&Item.TransactionMessage);
				Item.Context->Receipt.Store(&Item.ReceiptMessage);
				Item.DispatchNumber = Item.Context->Transaction->GetDispatchOffset();
				Algorithm::Encoding::DecodeUint256(Item.Context->Receipt.TransactionHash, Item.TransactionHash);
				Algorithm::Encoding::DecodeUint256(Item.Context->Receipt.AsHash(), Item.ReceiptHash);
				memcpy(Item.Owner, Item.Context->Receipt.From, sizeof(Item.Owner));

				OrderedSet<String> Output;
				Item.Context->Transaction->RecoverAlt(Item.Context->Receipt, Output);
				Item.Parties.reserve(Item.Parties.size() + Output.size());

				OrderedSet<uint256_t> Aliases;
				Item.Context->Transaction->RecoverAlt(Item.Context->Receipt, Aliases);
				Item.Parties.reserve(Aliases.size());

				TransactionPartyBlob Party;
				for (auto& Owner : Output)
				{
					memcpy(Party.Owner, Owner.data(), std::min(Owner.size(), sizeof(Algorithm::Pubkeyhash)));
					Item.Parties.push_back(Party);
				}

				TransactionAliasBlob Alias;
				for (auto& Hash : Aliases)
				{
					Algorithm::Encoding::DecodeUint256(Hash, Alias.TransactionHash);
					Item.Aliases.push_back(Alias);
				}
			});

			for (auto& Data : Transactions)
			{
				auto* Statement = *CommitTransactionData;
				HottestStorage->BindInt64(Statement, 0, Data.TransactionNumber);
				HottestStorage->BindBlob(Statement, 1, std::string_view((char*)Data.Owner, sizeof(Data.Owner)));
				HottestStorage->BindBlob(Statement, 2, std::string_view((char*)Data.TransactionHash, sizeof(Data.TransactionHash)));
				HottestStorage->BindBlob(Statement, 3, std::string_view((char*)Data.ReceiptHash, sizeof(Data.ReceiptHash)));
				if (Data.DispatchNumber > 0)
					HottestStorage->BindInt64(Statement, 4, Value.Number + (Data.DispatchNumber - 1));
				else
					HottestStorage->BindNull(Statement, 4);
				HottestStorage->BindInt64(Statement, 5, Value.Number);
				HottestStorage->BindInt64(Statement, 6, Data.BlockNonce);
				HottestStorage->BindBlob(Statement, 7, Data.TransactionMessage.Data);
				HottestStorage->BindBlob(Statement, 8, Data.ReceiptMessage.Data);

				Cursor = PreparedQuery(Label, __func__, Statement);
				if (!Cursor || Cursor->Error())
					return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

				Statement = *CommitTransactionParty;
				for (auto& Party : Data.Parties)
				{
					HottestStorage->BindInt64(Statement, 0, Data.TransactionNumber);
					HottestStorage->BindBlob(Statement, 1, std::string_view((char*)Party.Owner, sizeof(Party.Owner)));
					HottestStorage->BindInt64(Statement, 2, Value.Number);

					Cursor = PreparedQuery(Label, __func__, Statement);
					if (!Cursor || Cursor->Error())
						return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

					Cache->ClearLocation(Optional::None, Optional::None, String((char*)Party.Owner, sizeof(Party.Owner)));
				}

				Statement = *CommitTransactionAlias;
				for (auto& Alias : Data.Aliases)
				{
					HottestStorage->BindInt64(Statement, 0, Data.TransactionNumber);
					HottestStorage->BindBlob(Statement, 1, std::string_view((char*)Alias.TransactionHash, sizeof(Alias.TransactionHash)));
					HottestStorage->BindInt64(Statement, 2, Value.Number);

					Cursor = PreparedQuery(Label, __func__, Statement);
					if (!Cursor || Cursor->Error())
						return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));
				}
			}

			auto& StateTree = Value.States.At(Ledger::WorkCommitment::Finalized);
			auto State = StateTree.begin();
			Vector<StateBlob> States;
			States.resize(StateTree.size());
			for (size_t i = 0; i < States.size(); i++, State++)
			{
				StateBlob& Blob = States[i];
				Blob.Context = *State->second;
			}
			ParallelForEach(States.begin(), States.end(), [&](StateBlob& Item)
			{
				Item.Address = Item.Context->AsAddress();
				Item.Stride = Item.Context->AsStride();
				Item.Weight = Item.Context->AsWeight();
				Item.Context->Store(&Item.Message);
			});

			for (auto& Item : States)
			{
				auto* Statement = *CommitStateData;
				HottestStorage->BindBlob(Statement, 0, Item.Address);
				HottestStorage->BindBlob(Statement, 1, Item.Stride);
				HottestStorage->BindInt64(Statement, 2, Value.Number);
				HottestStorage->BindInt64(Statement, 3, Item.Weight);
				HottestStorage->BindBlob(Statement, 4, Item.Message.Data);

				Cursor = PreparedQuery(Label, __func__, Statement);
				if (!Cursor || Cursor->Error())
					return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

				Cache->ClearLocation(Item.Address, Item.Stride, Optional::None);
			}

			auto CheckpointSize = Protocol::Now().User.Storage.CheckpointSize;
			if (!CheckpointSize)
				return Expectation::Met;

			auto CheckpointNumber = Value.Number - Value.Number % CheckpointSize;
			if (CheckpointNumber < Value.Number)
				return Expectation::Met;

			Map[0]->Value = Var::Integer(Value.Number);
			Map[1]->Value = Var::Integer(Value.Number);
			Cursor = ArchiveEmplaceQueryRecursive(Label, __func__,
				"DELETE FROM statetries WHERE block_number < ?;"
				"INSERT OR IGNORE INTO checkpoints (block_number) VALUES (?)", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<size_t> Chainstate::ResolveBlockTransactions(Ledger::Block& Value, size_t Offset, size_t Count)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Integer(Value.Number));
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = ArchiveEmplaceQuery(Label, __func__, "SELECT transaction_hash, transaction_message, receipt_hash, receipt_message FROM transactions WHERE block_number = ? ORDER BY block_nonce LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<size_t>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Value.Transactions.reserve(Value.Transactions.size() + Size);
			for (size_t i = 0; i < Size; i++)
			{
				auto Row = Response[i];
				Format::Stream TransactionMessage = Format::Stream(Row["transaction_message"].Get().GetBlob());
				UPtr<Ledger::Transaction> NextTransaction = Transactions::Resolver::New(Messages::Authentic::ResolveType(TransactionMessage).Or(0));
				if (NextTransaction && NextTransaction->Load(TransactionMessage))
				{
					Ledger::Receipt NextReceipt;
					Format::Stream ReceiptMessage = Format::Stream(Row["receipt_message"].Get().GetBlob());
					if (NextReceipt.Load(ReceiptMessage))
					{
						FinalizeChecksum(**NextTransaction, Row["transaction_hash"]);
						FinalizeChecksum(NextReceipt, Row["receipt_hash"]);
						Value.Transactions.emplace_back(std::move(NextTransaction), std::move(NextReceipt));
					}
				}
			}
			return Size;
		}
		ExpectsLR<size_t> Chainstate::ResolveBlockStatetrie(Ledger::Block& Value, size_t Offset, size_t Count)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Integer(Value.Number));
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = ArchiveEmplaceQuery(Label, __func__, "SELECT message FROM statetries WHERE block_number = ? ORDER BY rowid LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<size_t>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			for (size_t i = 0; i < Size; i++)
			{
				auto Row = Response[i];
				Format::Stream Message = Format::Stream(Row["message"].Get().GetBlob());
				UPtr<Ledger::State> NextState = States::Resolver::New(Messages::Generic::ResolveType(Message).Or(0));
				if (NextState && NextState->Load(Message))
					Value.States.MoveInto(std::move(NextState));
			}

			Value.States.Commit();
			return Size;
		}
		ExpectsLR<std::pair<uint64_t, uint64_t>> Chainstate::ResolveStateLocation(const Option<std::string_view>& Address, const Option<std::string_view>& Stride)
		{
			VI_ASSERT(Address || Stride, "address or stride should be set");
			auto Cache = LocationCache::Get();
			auto AddressNumberCache = Address ? Cache->GetAddressLocation(*Address) : Option<uint64_t>(Optional::None);
			auto StrideNumberCache = Stride ? Cache->GetStrideLocation(*Stride) : Option<uint64_t>(Optional::None);
			if (!!AddressNumberCache == !!Address && !!StrideNumberCache == !!Stride)
			{
				if (Address && !*AddressNumberCache)
					return LayerException("state address not found");

				if (Stride && !*StrideNumberCache)
					return LayerException("state stride not found");

				return std::make_pair(AddressNumberCache.Or(0), StrideNumberCache.Or(0));
			}

			uint64_t AddressNumber = AddressNumberCache.Or(0);
			if (Address && !AddressNumberCache)
			{
				auto FindAddress = HottestStorage->PrepareStatement("SELECT address_number FROM addresses WHERE address_hash = ?", nullptr);
				if (!FindAddress)
					return ExpectsLR<std::pair<uint64_t, uint64_t>>(LayerException(std::move(FindAddress.Error().message())));

				HottestStorage->BindBlob(*FindAddress, 0, *Address);
				auto Cursor = ArchivePreparedQuery(Label, __func__, *FindAddress);
				if (!Cursor || Cursor->Error())
					return ExpectsLR<std::pair<uint64_t, uint64_t>>(LayerException(ErrorOf(Cursor)));

				AddressNumber = (*Cursor)["address_number"].Get().GetInteger();
			}

			uint64_t StrideNumber = StrideNumberCache.Or(0);
			if (Stride && !StrideNumberCache)
			{
				auto FindStride = HottestStorage->PrepareStatement("SELECT stride_number FROM strides WHERE stride_hash = ?", nullptr);
				if (!FindStride)
					return ExpectsLR<std::pair<uint64_t, uint64_t>>(LayerException(std::move(FindStride.Error().message())));

				HottestStorage->BindBlob(*FindStride, 0, *Stride);
				auto Cursor = ArchivePreparedQuery(Label, __func__, *FindStride);
				if (!Cursor || Cursor->Error())
					return ExpectsLR<std::pair<uint64_t, uint64_t>>(LayerException(ErrorOf(Cursor)));

				StrideNumber = (*Cursor)["stride_number"].Get().GetInteger();
			}

			if (Address && Stride)
				Cache->SetStateLocation(*Address, *Stride, AddressNumber, StrideNumber);
			else if (Address)
				Cache->SetAddressLocation(*Address, AddressNumber);
			else if (Stride)
				Cache->SetStrideLocation(*Stride, StrideNumber);
			
			if (Address && !AddressNumber)
				return LayerException("state address not found");

			if (Stride && !StrideNumber)
				return LayerException("state stride not found");

			return std::make_pair(AddressNumber, StrideNumber);
		}
		ExpectsLR<uint64_t> Chainstate::ResolveOwnerLocation(const Algorithm::Pubkeyhash Owner)
		{
			VI_ASSERT(Owner, "owner should be set");
			auto Cache = LocationCache::Get();
			auto OwnerNumberCache = Cache->GetOwnerLocation(std::string_view((char*)Owner, sizeof(Algorithm::Pubkeyhash)));
			if (OwnerNumberCache)
			{
				if (!*OwnerNumberCache)
					return LayerException("owner not found");

				return OwnerNumberCache.Or(0);
			}

			auto FindOwner = HottestStorage->PrepareStatement("SELECT owner_number FROM owners WHERE owner_hash = ?", nullptr);
			if (!FindOwner)
				return ExpectsLR<uint64_t>(LayerException(std::move(FindOwner.Error().message())));

			HottestStorage->BindBlob(*FindOwner, 0, std::string_view((char*)Owner, sizeof(Algorithm::Pubkeyhash)));
			auto Cursor = ArchivePreparedQuery(Label, __func__, *FindOwner);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<uint64_t>(LayerException(ErrorOf(Cursor)));

			uint64_t OwnerNumber = (*Cursor)["owner_number"].Get().GetInteger();
			Cache->SetOwnerLocation(std::string_view((char*)Owner, sizeof(Algorithm::Pubkeyhash)), OwnerNumber);
			if (!OwnerNumber)
				return LayerException("owner not found");

			return OwnerNumber;
		}
		ExpectsLR<uint64_t> Chainstate::GetCheckpointBlockNumber()
		{
			auto Cursor = ArchiveQuery(Label, __func__, "SELECT MAX(block_number) AS block_number FROM checkpoints");
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<uint64_t>(LayerException(ErrorOf(Cursor)));

			return (uint64_t)(*Cursor)["block_number"].Get().GetInteger();
		}
		ExpectsLR<uint64_t> Chainstate::GetLatestBlockNumber()
		{
			auto Cursor = ArchiveQuery(Label, __func__, "SELECT block_number FROM blocks ORDER BY block_number DESC LIMIT 1");
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<uint64_t>(LayerException(ErrorOf(Cursor)));

			uint64_t BlockNumber = (*Cursor)["block_number"].Get().GetInteger();
			return BlockNumber;
		}
		ExpectsLR<uint64_t> Chainstate::GetBlockNumberByHash(const uint256_t& BlockHash)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(BlockHash, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));

			auto Cursor = ArchiveEmplaceQuery(Label, __func__, "SELECT block_number FROM blocks WHERE block_hash = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<uint64_t>(LayerException(ErrorOf(Cursor)));

			return (uint64_t)(*Cursor)["block_number"].Get().GetInteger();
		}
		ExpectsLR<uint256_t> Chainstate::GetBlockHashByNumber(uint64_t BlockNumber)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Integer(BlockNumber));

			auto Cursor = ArchiveEmplaceQuery(Label, __func__, "SELECT block_hash FROM blocks WHERE block_number = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<uint256_t>(LayerException(ErrorOf(Cursor)));

			String Hash = (*Cursor)["block_hash"].Get().GetBlob();
			if (Hash.size() != sizeof(uint256_t))
				return ExpectsLR<uint256_t>(LayerException("hash deserialization error"));

			uint256_t Result;
			Algorithm::Encoding::EncodeUint256((uint8_t*)Hash.data(), Result);
			return Result;
		}
		ExpectsLR<Decimal> Chainstate::GetBlockGasPrice(uint64_t BlockNumber, const Algorithm::AssetId& Asset, double Percentile)
		{
			if (Percentile < 0.0 || Percentile > 1.0)
				return ExpectsLR<Decimal>(LayerException("invalid percentile"));

			Vector<Decimal> GasPrices;
			size_t Offset = 0;
			size_t Count = 512;
			while (true)
			{
				SchemaList Map;
				Map.push_back(Var::Set::Integer(BlockNumber));
				Map.push_back(Var::Set::Integer(Count));
				Map.push_back(Var::Set::Integer(Offset));

				auto Cursor = ArchiveEmplaceQuery(Label, __func__, "SELECT transaction_message FROM transactions WHERE block_number = ? ORDER BY block_nonce LIMIT ? OFFSET ?", &Map);
				if (!Cursor || Cursor->Error())
					return ExpectsLR<Decimal>(LayerException(ErrorOf(Cursor)));

				auto& Response = Cursor->First();
				size_t Size = Response.Size();
				for (size_t i = 0; i < Size; i++)
				{
					auto Row = Response[i];
					Format::Stream Message = Format::Stream(Row["transaction_message"].Get().GetBlob());
					UPtr<Ledger::Transaction> Value = Transactions::Resolver::New(Messages::Authentic::ResolveType(Message).Or(0));
					if (Value && Value->Load(Message) && Value->Asset == Asset)
						GasPrices.push_back(Value->GasPrice);

				}
				if (Size < Count)
					break;
			}

			std::sort(GasPrices.begin(), GasPrices.end(), [](const Decimal& A, const Decimal& B) { return A > B; });
			if (GasPrices.empty())
				return ExpectsLR<Decimal>(LayerException("gas price not found"));

			size_t Index = (size_t)std::floor((1.0 - Percentile) * (GasPrices.size() - 1));
			return GasPrices[Index];
		}
		ExpectsLR<Decimal> Chainstate::GetBlockAssetPrice(uint64_t BlockNumber, const Algorithm::AssetId& PriceOf, const Algorithm::AssetId& RelativeTo, double Percentile)
		{
			auto A = GetBlockGasPrice(BlockNumber, PriceOf, Percentile);
			if (!A || A->IsZero())
				return Decimal::Zero();

			auto B = GetBlockGasPrice(BlockNumber, RelativeTo, Percentile);
			if (!B)
				return Decimal::Zero();

			return *B / A->Truncate(Protocol::Now().Message.Precision);
		}
		ExpectsLR<Ledger::Block> Chainstate::GetBlockByNumber(uint64_t BlockNumber, size_t LoadRate)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Integer(BlockNumber));

			auto Cursor = ArchiveEmplaceQuery(Label, __func__, "SELECT block_hash, message FROM blocks WHERE block_number = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Ledger::Block>(LayerException(ErrorOf(Cursor)));

			Ledger::BlockHeader Header;
			Format::Stream Message = Format::Stream((*Cursor)["message"].Get().GetBlob());
			if (!Header.Load(Message))
				return ExpectsLR<Ledger::Block>(LayerException("block header deserialization error"));

			Ledger::Block Result = Ledger::Block(Header);
			size_t Offset = 0;
			while (LoadRate > 0)
			{
				auto Size = ResolveBlockTransactions(Result, Offset, LoadRate);
				if (!Size)
					return Size.Error();
				
				Offset += *Size;
				if (*Size < LoadRate)
					break;
			}

			Offset = 0;
			while (LoadRate > 0)
			{
				auto Size = ResolveBlockStatetrie(Result, Offset, LoadRate);
				if (!Size)
					return Size.Error();

				Offset += *Size;
				if (*Size < LoadRate)
					break;
			}

			FinalizeChecksum(Header, (*Cursor)["block_hash"]);
			return Result;
		}
		ExpectsLR<Ledger::Block> Chainstate::GetBlockByHash(const uint256_t& BlockHash, size_t LoadRate)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(BlockHash, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));

			auto Cursor = ArchiveEmplaceQuery(Label, __func__, "SELECT block_hash, message FROM blocks WHERE block_hash = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Ledger::Block>(LayerException(ErrorOf(Cursor)));

			Ledger::BlockHeader Header;
			Format::Stream Message = Format::Stream((*Cursor)["message"].Get().GetBlob());
			if (!Header.Load(Message))
				return ExpectsLR<Ledger::Block>(LayerException("block header deserialization error"));

			Ledger::Block Result = Ledger::Block(Header);
			size_t Offset = 0;
			while (LoadRate > 0)
			{
				auto Size = ResolveBlockTransactions(Result, Offset, LoadRate);
				if (!Size)
					return Size.Error();

				Offset += *Size;
				if (*Size < LoadRate)
					break;
			}

			Offset = 0;
			while (LoadRate > 0)
			{
				auto Size = ResolveBlockStatetrie(Result, Offset, LoadRate);
				if (!Size)
					return Size.Error();

				Offset += *Size;
				if (*Size < LoadRate)
					break;
			}

			FinalizeChecksum(Header, (*Cursor)["block_hash"]);
			return Result;
		}
		ExpectsLR<Ledger::Block> Chainstate::GetLatestBlock(size_t LoadRate)
		{
			auto Cursor = ArchiveQuery(Label, __func__, "SELECT block_hash, message FROM blocks ORDER BY block_number DESC LIMIT 1");
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Ledger::Block>(LayerException(ErrorOf(Cursor)));

			Ledger::BlockHeader Header;
			Format::Stream Message = Format::Stream((*Cursor)["message"].Get().GetBlob());
			if (!Header.Load(Message))
				return ExpectsLR<Ledger::Block>(LayerException("block header deserialization error"));

			Ledger::Block Result = Ledger::Block(Header);
			size_t Offset = 0;
			while (LoadRate > 0)
			{
				auto Size = ResolveBlockTransactions(Result, Offset, LoadRate);
				if (!Size)
					return Size.Error();

				Offset += *Size;
				if (*Size < LoadRate)
					break;
			}

			Offset = 0;
			while (LoadRate > 0)
			{
				auto Size = ResolveBlockStatetrie(Result, Offset, LoadRate);
				if (!Size)
					return Size.Error();

				Offset += *Size;
				if (*Size < LoadRate)
					break;
			}

			FinalizeChecksum(Header, (*Cursor)["block_hash"]);
			return Result;
		}
		ExpectsLR<Ledger::BlockHeader> Chainstate::GetBlockHeaderByNumber(uint64_t BlockNumber)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Integer(BlockNumber));

			auto Cursor = ArchiveEmplaceQuery(Label, __func__, "SELECT block_hash, message FROM blocks WHERE block_number = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Ledger::BlockHeader>(LayerException(ErrorOf(Cursor)));

			Ledger::BlockHeader Value;
			Format::Stream Message = Format::Stream((*Cursor)["message"].Get().GetBlob());
			if (!Value.Load(Message))
				return ExpectsLR<Ledger::BlockHeader>(LayerException("block header deserialization error"));

			FinalizeChecksum(Value, (*Cursor)["block_hash"]);
			return Value;
		}
		ExpectsLR<Ledger::BlockHeader> Chainstate::GetBlockHeaderByHash(const uint256_t& BlockHash)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(BlockHash, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));

			auto Cursor = ArchiveEmplaceQuery(Label, __func__, "SELECT block_hash, message FROM blocks WHERE block_hash = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Ledger::BlockHeader>(LayerException(ErrorOf(Cursor)));

			Ledger::BlockHeader Value;
			Format::Stream Message = Format::Stream((*Cursor)["message"].Get().GetBlob());
			if (!Value.Load(Message))
				return ExpectsLR<Ledger::BlockHeader>(LayerException("block header deserialization error"));

			FinalizeChecksum(Value, (*Cursor)["block_hash"]);
			return Value;
		}
		ExpectsLR<Ledger::BlockHeader> Chainstate::GetLatestBlockHeader()
		{
			auto Cursor = ArchiveQuery(Label, __func__, "SELECT block_hash, message FROM blocks ORDER BY block_number DESC LIMIT 1");
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Ledger::BlockHeader>(LayerException(ErrorOf(Cursor)));

			Ledger::BlockHeader Value;
			Format::Stream Message = Format::Stream((*Cursor)["message"].Get().GetBlob());
			if (!Value.Load(Message))
				return ExpectsLR<Ledger::BlockHeader>(LayerException("block header deserialization error"));

			FinalizeChecksum(Value, (*Cursor)["block_hash"]);
			return Value;
		}
		ExpectsLR<Ledger::BlockProof> Chainstate::GetBlockProofByNumber(uint64_t BlockNumber)
		{
			auto ChildBlock = GetBlockHeaderByNumber(BlockNumber);
			if (!ChildBlock)
				return ChildBlock.Error();

			auto ParentBlock = GetBlockHeaderByNumber(ChildBlock->Number - 1);
			Ledger::BlockProof Value = Ledger::BlockProof(*ChildBlock, ParentBlock.Address());

			SchemaList Map;
			Map.push_back(Var::Set::Integer(BlockNumber));

			auto Cursor = ArchiveEmplaceQuery(Label, __func__,
				"SELECT transaction_hash, receipt_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce;"
				"SELECT message FROM statetries WHERE block_number = ? ORDER BY rowid", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Ledger::BlockProof>(LayerException(ErrorOf(Cursor)));

			if (Cursor->Size() > 0)
			{
				size_t Size = Cursor->At(0).Size();
				Value.Transactions.reserve(Size);
				Value.Receipts.reserve(Size);
				for (auto Row : Cursor->At(0))
				{
					auto TransactionHash = Row["transaction_hash"].Get().GetBlob();
					if (TransactionHash.size() == sizeof(uint256_t))
					{
						uint256_t Hash;
						Algorithm::Encoding::EncodeUint256((uint8_t*)TransactionHash.data(), Hash);
						Value.Transactions.push_back(Hash);
					}

					auto ReceiptHash = Row["receipt_hash"].Get().GetBlob();
					if (ReceiptHash.size() == sizeof(uint256_t))
					{
						uint256_t Hash;
						Algorithm::Encoding::EncodeUint256((uint8_t*)ReceiptHash.data(), Hash);
						Value.Receipts.push_back(Hash);
					}
				}
			}

			if (Cursor->Size() > 1)
			{
				Value.States.reserve(Cursor->At(1).Size());
				for (auto Row : Cursor->At(1))
				{
					auto Message = Format::Stream(Row["message"].Get().GetBlob());
					Value.States.push_back(Message.Hash());
				}
			}

			return Value;
		}
		ExpectsLR<Ledger::BlockProof> Chainstate::GetBlockProofByHash(const uint256_t& BlockHash)
		{
			auto BlockNumber = GetBlockNumberByHash(BlockHash);
			if (!BlockNumber)
				return BlockNumber.Error();

			return GetBlockProofByNumber(*BlockNumber);
		}
		ExpectsLR<Vector<uint256_t>> Chainstate::GetBlockTransactionHashset(uint64_t BlockNumber)
		{
			if (!BlockNumber)
				return LayerException("invalid block number");

			SchemaList Map;
			Map.push_back(Var::Set::Integer(BlockNumber));

			auto Cursor = ArchiveEmplaceQuery(Label, __func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<uint256_t>>(LayerException(ErrorOf(Cursor)));

			Vector<uint256_t> Result;
			for (auto& Response : *Cursor)
			{
				size_t Size = Response.Size();
				Result.reserve(Result.size() + Size);
				for (size_t i = 0; i < Size; i++)
				{
					auto InHash = Response[i]["transaction_hash"].Get().GetBlob();
					if (InHash.size() != sizeof(uint256_t))
						continue;

					uint256_t OutHash;
					Algorithm::Encoding::EncodeUint256((uint8_t*)InHash.data(), OutHash);
					Result.push_back(OutHash);
				}
			}

			return Result;
		}
		ExpectsLR<Vector<uint256_t>> Chainstate::GetBlockStatetrieHashset(uint64_t BlockNumber)
		{
			if (!BlockNumber)
				return LayerException("invalid block number");

			SchemaList Map;
			Map.push_back(Var::Set::Integer(BlockNumber));

			auto Cursor = ArchiveEmplaceQuery(Label, __func__, "SELECT message FROM statetries WHERE block_number = ? ORDER BY rowid", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<uint256_t>>(LayerException(ErrorOf(Cursor)));

			Vector<uint256_t> Result;
			for (auto& Response : *Cursor)
			{
				size_t Size = Response.Size();
				Result.reserve(Result.size() + Size);
				for (size_t i = 0; i < Size; i++)
					Result.push_back(Format::Stream(Response[i]["message"].Get().GetBlob()).Hash());
			}

			std::sort(Result.begin(), Result.end());
			return Result;
		}
		ExpectsLR<Vector<uint256_t>> Chainstate::GetBlockHashset(uint64_t BlockNumber, size_t Count)
		{
			if (!Count || !BlockNumber)
				return LayerException("invalid block range");

			SchemaList Map;
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(BlockNumber + Count));

			auto Cursor = ArchiveEmplaceQueryRecursive(Label, __func__, "SELECT block_hash FROM blocks WHERE block_number BETWEEN ? AND ? ORDER BY block_number DESC", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<uint256_t>>(LayerException(ErrorOf(Cursor)));

			Vector<uint256_t> Result;
			for (auto& Response : *Cursor)
			{
				size_t Size = Response.Size();
				Result.reserve(Result.size() + Size);
				for (size_t i = 0; i < Size; i++)
				{
					auto InHash = Response[i]["block_hash"].Get().GetBlob();
					if (InHash.size() != sizeof(uint256_t))
						continue;

					uint256_t OutHash;
					Algorithm::Encoding::EncodeUint256((uint8_t*)InHash.data(), OutHash);
					Result.push_back(OutHash);
				}
			}

			return Result;
		}
		ExpectsLR<Vector<Ledger::BlockHeader>> Chainstate::GetBlockHeaders(uint64_t BlockNumber, size_t Count)
		{
			if (!Count || !BlockNumber)
				return LayerException("invalid block range");

			SchemaList Map;
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(BlockNumber + Count));

			auto Cursor = ArchiveEmplaceQueryRecursive(Label, __func__, "SELECT message FROM blocks WHERE block_number BETWEEN ? AND ? ORDER BY block_number DESC", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<Ledger::BlockHeader>>(LayerException(ErrorOf(Cursor)));

			Vector<Ledger::BlockHeader> Result;
			for (auto& Response : *Cursor)
			{
				size_t Size = Response.Size();
				Result.reserve(Result.size() + Size);
				for (size_t i = 0; i < Size; i++)
				{
					Ledger::BlockHeader Value;
					Format::Stream Message = Format::Stream(Response[i]["message"].Get().GetBlob());
					if (Value.Load(Message))
						Result.push_back(std::move(Value));
				}
			}

			return Result;
		}
		ExpectsLR<Ledger::StateWork> Chainstate::GetBlockStatetrieByNumber(uint64_t BlockNumber, size_t Offset, size_t Count)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = ArchiveEmplaceQuery(Label, __func__, "SELECT message FROM statetries WHERE block_number = ? ORDER BY rowid LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Ledger::StateWork>(LayerException(ErrorOf(Cursor)));

			auto Result = ExpectsLR<Ledger::StateWork>(Ledger::StateWork());
			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			for (size_t i = 0; i < Size; i++)
			{
				auto Row = Response[i];
				Format::Stream Message = Format::Stream(Row["message"].Get().GetBlob());
				UPtr<Ledger::State> NextState = States::Resolver::New(Messages::Generic::ResolveType(Message).Or(0));
				if (NextState && NextState->Load(Message))
					(*Result)[NextState->AsAddress() + NextState->AsStride()] = std::move(NextState);
			}

			return Result;
		}
		ExpectsLR<Vector<UPtr<Ledger::Transaction>>> Chainstate::GetTransactionsByNumber(uint64_t BlockNumber, size_t Offset, size_t Count)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT transaction_hash, transaction_message FROM transactions WHERE block_number = ? ORDER BY block_nonce LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<UPtr<Ledger::Transaction>>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Vector<UPtr<Ledger::Transaction>> Values;
			Values.reserve(Size);

			for (size_t i = 0; i < Size; i++)
			{
				auto Row = Response[i];
				Format::Stream Message = Format::Stream(Row["transaction_message"].Get().GetBlob());
				UPtr<Ledger::Transaction> Value = Transactions::Resolver::New(Messages::Authentic::ResolveType(Message).Or(0));
				if (Value && Value->Load(Message))
				{
					FinalizeChecksum(**Value, Row["transaction_hash"]);
					Values.emplace_back(std::move(Value));
				}
			}

			return Values;
		}
		ExpectsLR<Vector<UPtr<Ledger::Transaction>>> Chainstate::GetTransactionsByOwner(uint64_t BlockNumber, const Algorithm::Pubkeyhash Owner, size_t Offset, size_t Count)
		{
			auto Location = ResolveOwnerLocation(Owner);
			if (!Location)
				return Location.Error();

			SchemaList Map;
			Map.push_back(Var::Set::Integer(*Location));
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(Label, __func__,
				"SELECT transaction_hash, transaction_message FROM parties"
				" INNER JOIN transactions ON transactions.transaction_number = parties.transaction_number "
				"WHERE parties.transaction_owner_number = ? AND parties.block_number <= ? ORDER BY parties.transaction_number LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<UPtr<Ledger::Transaction>>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Vector<UPtr<Ledger::Transaction>> Values;
			Values.reserve(Size);

			for (size_t i = 0; i < Size; i++)
			{
				auto Row = Response[i];
				Format::Stream Message = Format::Stream(Row["transaction_message"].Get().GetBlob());
				UPtr<Ledger::Transaction> Value = Transactions::Resolver::New(Messages::Authentic::ResolveType(Message).Or(0));
				if (Value && Value->Load(Message))
				{
					FinalizeChecksum(**Value, Row["transaction_hash"]);
					Values.emplace_back(std::move(Value));
				}
			}

			return Values;
		}
		ExpectsLR<Vector<Ledger::BlockTransaction>> Chainstate::GetBlockTransactionsByNumber(uint64_t BlockNumber, size_t Offset, size_t Count)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT transaction_hash, transaction_message, receipt_hash, receipt_message FROM transactions WHERE block_number = ? ORDER BY block_nonce LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<Ledger::BlockTransaction>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Vector<Ledger::BlockTransaction> Values;
			Values.reserve(Size);

			for (size_t i = 0; i < Size; i++)
			{
				auto Row = Response[i];
				Format::Stream TransactionMessage = Format::Stream(Row["transaction_message"].Get().GetBlob());
				Format::Stream ReceiptMessage = Format::Stream(Row["receipt_message"].Get().GetBlob());
				Ledger::BlockTransaction Value;
				Value.Transaction = Transactions::Resolver::New(Messages::Authentic::ResolveType(TransactionMessage).Or(0));
				if (Value.Transaction && Value.Transaction->Load(TransactionMessage) && Value.Receipt.Load(ReceiptMessage))
				{
					FinalizeChecksum(**Value.Transaction, Row["transaction_hash"]);
					FinalizeChecksum(Value.Receipt, Row["receipt_hash"]);
					Values.emplace_back(std::move(Value));
				}
			}

			return Values;
		}
		ExpectsLR<Vector<Ledger::BlockTransaction>> Chainstate::GetBlockTransactionsByOwner(uint64_t BlockNumber, const Algorithm::Pubkeyhash Owner, size_t Offset, size_t Count)
		{
			auto Location = ResolveOwnerLocation(Owner);
			if (!Location)
				return Location.Error();

			SchemaList Map;
			Map.push_back(Var::Set::Integer(*Location));
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(Label, __func__,
				"SELECT transaction_hash, transaction_message, receipt_hash, receipt_message FROM parties"
				" INNER JOIN transactions ON transactions.transaction_number = parties.transaction_number "
				"WHERE parties.transaction_owner_number = ? AND parties.block_number <= ? ORDER BY parties.transaction_number LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<Ledger::BlockTransaction>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Vector<Ledger::BlockTransaction> Values;
			Values.reserve(Size);

			for (size_t i = 0; i < Size; i++)
			{
				auto Row = Response[i];
				Format::Stream TransactionMessage = Format::Stream(Row["transaction_message"].Get().GetBlob());
				Format::Stream ReceiptMessage = Format::Stream(Row["receipt_message"].Get().GetBlob());
				Ledger::BlockTransaction Value;
				Value.Transaction = Transactions::Resolver::New(Messages::Authentic::ResolveType(TransactionMessage).Or(0));
				if (Value.Transaction && Value.Transaction->Load(TransactionMessage) && Value.Receipt.Load(ReceiptMessage))
				{
					FinalizeChecksum(**Value.Transaction, Row["transaction_hash"]);
					FinalizeChecksum(Value.Receipt, Row["receipt_hash"]);
					Values.emplace_back(std::move(Value));
				}
			}

			return Values;
		}
		ExpectsLR<Vector<Ledger::Receipt>> Chainstate::GetBlockReceiptsByNumber(uint64_t BlockNumber, size_t Offset, size_t Count)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT receipt_hash, receipt_message FROM transactions WHERE block_number = ? ORDER BY block_nonce LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<Ledger::Receipt>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Vector<Ledger::Receipt> Values;
			Values.reserve(Size);

			for (size_t i = 0; i < Size; i++)
			{
				auto Row = Response[i];
				Ledger::Receipt Value;
				Format::Stream Message = Format::Stream(Row["receipt_message"].Get().GetBlob());
				if (Value.Load(Message))
				{
					FinalizeChecksum(Value, Row["receipt_hash"]);
					Values.emplace_back(std::move(Value));
				}
			}

			return Values;
		}
		ExpectsLR<Vector<Ledger::BlockTransaction>> Chainstate::GetPendingBlockTransactions(uint64_t BlockNumber, size_t Offset, size_t Count)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT transaction_hash, transaction_message, receipt_hash, receipt_message FROM transactions WHERE dispatch_queue IS NOT NULL AND dispatch_queue <= ? ORDER BY block_nonce LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<Ledger::BlockTransaction>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Vector<Ledger::BlockTransaction> Values;
			Values.reserve(Size);

			for (size_t i = 0; i < Size; i++)
			{
				auto Row = Response[i];
				Format::Stream TransactionMessage = Format::Stream(Row["transaction_message"].Get().GetBlob());
				Format::Stream ReceiptMessage = Format::Stream(Row["receipt_message"].Get().GetBlob());
				Ledger::BlockTransaction Value;
				Value.Transaction = Transactions::Resolver::New(Messages::Authentic::ResolveType(TransactionMessage).Or(0));
				if (Value.Transaction && Value.Transaction->Load(TransactionMessage) && Value.Receipt.Load(ReceiptMessage))
				{
					FinalizeChecksum(**Value.Transaction, Row["transaction_hash"]);
					FinalizeChecksum(Value.Receipt, Row["receipt_hash"]);
					Values.emplace_back(std::move(Value));
				}
			}

			return Values;
		}
		ExpectsLR<UPtr<Ledger::Transaction>> Chainstate::GetTransactionByHash(const uint256_t& TransactionHash)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(TransactionHash, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));

			auto Cursor = ArchiveEmplaceQuery(Label, __func__, "SELECT transaction_hash, transaction_message FROM transactions WHERE transaction_hash = ? OR transaction_number IN (SELECT transaction_number FROM aliases WHERE aliases.transaction_hash = ?)", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<UPtr<Ledger::Transaction>>(LayerException(ErrorOf(Cursor)));

			Format::Stream Message = Format::Stream((*Cursor)["transaction_message"].Get().GetBlob());
			UPtr<Ledger::Transaction> Value = Transactions::Resolver::New(Messages::Authentic::ResolveType(Message).Or(0));
			if (!Value || !Value->Load(Message))
				return ExpectsLR<UPtr<Ledger::Transaction>>(LayerException("transaction deserialization error"));

			FinalizeChecksum(**Value, (*Cursor)["transaction_hash"]);
			return Value;
		}
		ExpectsLR<UPtr<Ledger::Transaction>> Chainstate::GetTransactionByReceiptHash(const uint256_t& ReceiptHash)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(ReceiptHash, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));

			auto Cursor = ArchiveEmplaceQuery(Label, __func__, "SELECT transaction_hash, transaction_message FROM transactions WHERE receipt_hash = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<UPtr<Ledger::Transaction>>(LayerException(ErrorOf(Cursor)));

			Format::Stream Message = Format::Stream((*Cursor)["transaction_message"].Get().GetBlob());
			UPtr<Ledger::Transaction> Value = Transactions::Resolver::New(Messages::Authentic::ResolveType(Message).Or(0));
			if (!Value || !Value->Load(Message))
				return ExpectsLR<UPtr<Ledger::Transaction>>(LayerException("transaction deserialization error"));

			FinalizeChecksum(**Value, (*Cursor)["transaction_hash"]);
			return Value;
		}
		ExpectsLR<Ledger::BlockTransaction> Chainstate::GetBlockTransactionByHash(const uint256_t& TransactionHash)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(TransactionHash, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));

			auto Cursor = ArchiveEmplaceQuery(Label, __func__, "SELECT transaction_hash, transaction_message, receipt_hash, receipt_message FROM transactions WHERE transaction_hash = ? OR transaction_number IN (SELECT transaction_number FROM aliases WHERE aliases.transaction_hash = ?)", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Ledger::BlockTransaction>(LayerException(ErrorOf(Cursor)));

			Format::Stream TransactionMessage = Format::Stream((*Cursor)["transaction_message"].Get().GetBlob());
			Format::Stream ReceiptMessage = Format::Stream((*Cursor)["receipt_message"].Get().GetBlob());
			Ledger::BlockTransaction Value;
			Value.Transaction = Transactions::Resolver::New(Messages::Authentic::ResolveType(TransactionMessage).Or(0));
			if (!Value.Transaction || !Value.Transaction->Load(TransactionMessage) || !Value.Receipt.Load(ReceiptMessage))
				return ExpectsLR<Ledger::BlockTransaction>(LayerException("block transaction deserialization error"));

			FinalizeChecksum(**Value.Transaction, (*Cursor)["transaction_hash"]);
			FinalizeChecksum(Value.Receipt, (*Cursor)["receipt_hash"]);
			return Value;
		}
		ExpectsLR<Ledger::BlockTransaction> Chainstate::GetBlockTransactionByReceiptHash(const uint256_t& ReceiptHash)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(ReceiptHash, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));

			auto Cursor = ArchiveEmplaceQuery(Label, __func__, "SELECT transaction_hash, transaction_message, receipt_hash, receipt_message FROM transactions WHERE receipt_hash = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Ledger::BlockTransaction>(LayerException(ErrorOf(Cursor)));

			Format::Stream TransactionMessage = Format::Stream((*Cursor)["transaction_message"].Get().GetBlob());
			Format::Stream ReceiptMessage = Format::Stream((*Cursor)["receipt_message"].Get().GetBlob());
			Ledger::BlockTransaction Value;
			Value.Transaction = Transactions::Resolver::New(Messages::Authentic::ResolveType(TransactionMessage).Or(0));
			if (!Value.Transaction || !Value.Transaction->Load(TransactionMessage) || !Value.Receipt.Load(ReceiptMessage))
				return ExpectsLR<Ledger::BlockTransaction>(LayerException("block transaction deserialization error"));

			FinalizeChecksum(**Value.Transaction, (*Cursor)["transaction_hash"]);
			FinalizeChecksum(Value.Receipt, (*Cursor)["receipt_hash"]);
			return Value;
		}
		ExpectsLR<Ledger::Receipt> Chainstate::GetReceiptByHash(const uint256_t& ReceiptHash)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(ReceiptHash, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));

			auto Cursor = ArchiveEmplaceQuery(Label, __func__, "SELECT receipt_hash, receipt_message FROM transactions WHERE receipt_hash = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Ledger::Receipt>(LayerException(ErrorOf(Cursor)));

			Ledger::Receipt Value;
			Format::Stream Message = Format::Stream((*Cursor)["receipt_message"].Get().GetBlob());
			if (!Value.Load(Message))
				return ExpectsLR<Ledger::Receipt>(LayerException("receipt deserialization error"));

			FinalizeChecksum(Value, (*Cursor)["receipt_hash"]);
			return Value;
		}
		ExpectsLR<Ledger::Receipt> Chainstate::GetReceiptByTransactionHash(const uint256_t& TransactionHash)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(TransactionHash, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));

			auto Cursor = ArchiveEmplaceQuery(Label, __func__, "SELECT receipt_hash, receipt_message FROM transactions WHERE transaction_hash = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Ledger::Receipt>(LayerException(ErrorOf(Cursor)));

			Ledger::Receipt Value;
			Format::Stream Message = Format::Stream((*Cursor)["receipt_message"].Get().GetBlob());
			if (!Value.Load(Message))
				return ExpectsLR<Ledger::Receipt>(LayerException("receipt deserialization error"));

			FinalizeChecksum(Value, (*Cursor)["receipt_hash"]);
			return Value;
		}
		ExpectsLR<UPtr<Ledger::State>> Chainstate::GetStateByComposition(const Ledger::BlockMutation* Delta, const std::string_view& Address, const std::string_view& Stride, uint64_t BlockNumber)
		{
			if (Delta != nullptr)
			{
				if (Delta->Outgoing != nullptr)
				{
					auto Candidate = Delta->Outgoing->Resolve(Address, Stride);
					if (Candidate)
						return std::move(*Candidate);
				}

				if (Delta->Incoming != nullptr)
				{
					auto Candidate = Delta->Incoming->Resolve(Address, Stride);
					if (Candidate)
						return std::move(*Candidate);
				}
			}

			auto Location = ResolveStateLocation(Address, Stride);
			if (!Location)
				return Location.Error();

			auto FindState = HottestStorage->PrepareStatement(!BlockNumber ? "SELECT message FROM states WHERE address_number = ? AND stride_number = ?" : "SELECT message FROM statetries WHERE address_number = ? AND stride_number = ? AND block_number < ? ORDER BY block_number DESC LIMIT 1", nullptr);
			if (!FindState)
				return ExpectsLR<UPtr<Ledger::State>>(LayerException(std::move(FindState.Error().message())));

			HottestStorage->BindInt64(*FindState, 0, Location->first);
			HottestStorage->BindInt64(*FindState, 1, Location->second);
			if (BlockNumber > 0)
				HottestStorage->BindInt64(*FindState, 2, BlockNumber);

			auto Cursor = ArchivePreparedQuery(Label, __func__, *FindState);
			if (!Cursor || Cursor->Empty())
			{
				if (Delta != nullptr && Delta->Incoming != nullptr)
					((Ledger::BlockMutation*)Delta)->Incoming->ClearInto(Address, Stride);
				return ExpectsLR<UPtr<Ledger::State>>(LayerException(ErrorOf(Cursor)));
			}
			else if (Cursor->Empty())
			{
				if (Delta != nullptr && Delta->Incoming != nullptr)
					((Ledger::BlockMutation*)Delta)->Incoming->ClearInto(Address, Stride);
				return ExpectsLR<UPtr<Ledger::State>>(LayerException("state not found"));
			}

			Format::Stream Message = Format::Stream((*Cursor)["message"].Get().GetBlob());
			UPtr<Ledger::State> Value = States::Resolver::New(Messages::Generic::ResolveType(Message).Or(0));
			if (!Value || !Value->Load(Message))
			{
				if (Delta != nullptr && Delta->Incoming != nullptr)
					((Ledger::BlockMutation*)Delta)->Incoming->ClearInto(Address, Stride);
				return ExpectsLR<UPtr<Ledger::State>>(LayerException("state deserialization error"));
			}

			if (Delta != nullptr && Delta->Incoming != nullptr)
				((Ledger::BlockMutation*)Delta)->Incoming->CopyInto(*Value);
			return Value;
		}
		ExpectsLR<UPtr<Ledger::State>> Chainstate::GetStateByAddress(const Ledger::BlockMutation* Delta, const std::string_view& Address, uint64_t BlockNumber, size_t Offset)
		{
			auto Location = ResolveStateLocation(Address, Optional::None);
			if (!Location)
				return Location.Error();

			SchemaList Map;
			Map.push_back(Var::Set::Integer(Location->first));
			if (BlockNumber > 0)
				Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = ArchiveEmplaceQuery(Label, __func__, !BlockNumber ? "SELECT message FROM states WHERE address_number = ? ORDER BY stride_number LIMIT 1 OFFSET ?" : "SELECT message, MAX(block_number) FROM statetries WHERE address_number = ? AND block_number < ? GROUP BY stride_number ORDER BY stride_number LIMIT 1 OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<UPtr<Ledger::State>>(LayerException(ErrorOf(Cursor)));
			else if (Cursor->Empty())
				return ExpectsLR<UPtr<Ledger::State>>(LayerException("state not found"));

			Format::Stream Message = Format::Stream((*Cursor)["message"].Get().GetBlob());
			UPtr<Ledger::State> Value = States::Resolver::New(Messages::Generic::ResolveType(Message).Or(0));
			if (!Value || !Value->Load(Message))
			{
				if (Value && Delta != nullptr && Delta->Incoming != nullptr)
					((Ledger::BlockMutation*)Delta)->Incoming->ClearInto(Address, Value->AsStride());
				return ExpectsLR<UPtr<Ledger::State>>(LayerException("state deserialization error"));
			}

			if (Delta != nullptr && Delta->Incoming != nullptr)
				((Ledger::BlockMutation*)Delta)->Incoming->CopyInto(*Value);
			return Value;
		}
		ExpectsLR<UPtr<Ledger::State>> Chainstate::GetStateByStride(const Ledger::BlockMutation* Delta, const std::string_view& Stride, uint64_t BlockNumber, size_t Offset)
		{
			auto Location = ResolveStateLocation(Optional::None, Stride);
			if (!Location)
				return Location.Error();

			SchemaList Map;
			Map.push_back(Var::Set::Integer(Location->second));
			if (BlockNumber > 0)
				Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = ArchiveEmplaceQuery(Label, __func__, !BlockNumber ? "SELECT message FROM states WHERE stride_number = ? ORDER BY address_number LIMIT 1 OFFSET ?" : "SELECT message, MAX(block_number) FROM statetries WHERE stride_number = ? AND block_number < ? GROUP BY address_number ORDER BY address_number LIMIT 1 OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<UPtr<Ledger::State>>(LayerException(ErrorOf(Cursor)));
			else if (Cursor->Empty())
				return ExpectsLR<UPtr<Ledger::State>>(LayerException("state not found"));

			Format::Stream Message = Format::Stream((*Cursor)["message"].Get().GetBlob());
			UPtr<Ledger::State> Value = States::Resolver::New(Messages::Generic::ResolveType(Message).Or(0));
			if (!Value || !Value->Load(Message))
			{
				if (Value && Delta != nullptr && Delta->Incoming != nullptr)
					((Ledger::BlockMutation*)Delta)->Incoming->ClearInto(Value->AsAddress(), Stride);
				return ExpectsLR<UPtr<Ledger::State>>(LayerException("state deserialization error"));
			}

			if (Delta != nullptr && Delta->Incoming != nullptr)
				((Ledger::BlockMutation*)Delta)->Incoming->CopyInto(*Value);
			return Value;
		}
		ExpectsLR<Vector<UPtr<Ledger::State>>> Chainstate::GetStatesByAddress(const Ledger::BlockMutation* Delta, const std::string_view& Address, uint64_t BlockNumber, size_t Offset, size_t Count)
		{
			auto Location = ResolveStateLocation(Address, Optional::None);
			if (!Location)
				return Location.Error();

			SchemaList Map;
			Map.push_back(Var::Set::Integer(Location->first));
			if (BlockNumber > 0)
				Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = ArchiveEmplaceQuery(Label, __func__, !BlockNumber ? "SELECT message FROM states WHERE address_number = ? ORDER BY stride_number LIMIT ? OFFSET ?" : "SELECT message, MAX(block_number) FROM statetries WHERE address_number = ? AND block_number < ? GROUP BY stride_number ORDER BY stride_number LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<UPtr<Ledger::State>>>(LayerException(ErrorOf(Cursor)));

			Vector<UPtr<Ledger::State>> Values;
			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			for (size_t i = 0; i < Size; i++)
			{
				auto Row = Response[i];
				Format::Stream Message = Format::Stream(Row["message"].Get().GetBlob());
				UPtr<Ledger::State> NextState = States::Resolver::New(Messages::Generic::ResolveType(Message).Or(0));
				if (!NextState || !NextState->Load(Message))
				{
					if (NextState && Delta != nullptr && Delta->Incoming != nullptr)
						((Ledger::BlockMutation*)Delta)->Incoming->ClearInto(Address, NextState->AsStride());
					continue;
				}
				else if (Delta != nullptr && Delta->Incoming != nullptr)
					((Ledger::BlockMutation*)Delta)->Incoming->CopyInto(*NextState);
				Values.push_back(std::move(NextState));
			}

			return Values;
		}
		ExpectsLR<Vector<UPtr<Ledger::State>>> Chainstate::GetStatesByStride(const Ledger::BlockMutation* Delta, const std::string_view& Stride, const WeightQuery& Weight, uint64_t BlockNumber, size_t Offset, size_t Count)
		{
			auto Location = ResolveStateLocation(Optional::None, Stride);
			if (!Location)
				return Location.Error();

			SchemaList Map;
			Map.push_back(Var::Set::Integer(Location->second));
			if (BlockNumber > 0)
				Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::String(Weight.AsCondition()));
			Map.push_back(Var::Set::Integer(Weight.Value));
			Map.push_back(Var::Set::String(Weight.AsOrder()));
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = ArchiveEmplaceQuery(Label, __func__, !BlockNumber ? "SELECT message FROM states WHERE stride_number = ? AND weight $? ? ORDER BY weight $? LIMIT ? OFFSET ?" : "SELECT message, MAX(block_number) FROM statetries WHERE stride_number = ? AND block_number < ? AND weight $? ? GROUP BY address_number ORDER BY weight $? LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<UPtr<Ledger::State>>>(LayerException(ErrorOf(Cursor)));

			Vector<UPtr<Ledger::State>> Values;
			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			for (size_t i = 0; i < Size; i++)
			{
				auto Row = Response[i];
				Format::Stream Message = Format::Stream(Row["message"].Get().GetBlob());
				UPtr<Ledger::State> NextState = States::Resolver::New(Messages::Generic::ResolveType(Message).Or(0));
				if (!NextState || !NextState->Load(Message))
				{
					if (NextState && Delta != nullptr && Delta->Incoming != nullptr)
						((Ledger::BlockMutation*)Delta)->Incoming->ClearInto(NextState->AsAddress(), Stride);
					continue;
				}
				else if (Delta != nullptr && Delta->Incoming != nullptr)
					((Ledger::BlockMutation*)Delta)->Incoming->CopyInto(*NextState);
				Values.push_back(std::move(NextState));
			}

			return Values;
		}
		ExpectsLR<size_t> Chainstate::GetStatesCountByStride(const std::string_view& Stride, const WeightQuery& Weight, uint64_t BlockNumber)
		{
			auto Location = ResolveStateLocation(Optional::None, Stride);
			if (!Location)
				return Location.Error();

			SchemaList Map;
			Map.push_back(Var::Set::Integer(Location->second));
			if (BlockNumber > 0)
				Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::String(Weight.AsCondition()));
			Map.push_back(Var::Set::Integer(Weight.Value));

			auto Cursor = ArchiveEmplaceQuery(Label, __func__, !BlockNumber ? "SELECT COUNT(1) AS state_count FROM states WHERE stride_number = ? AND weight $? ?" : "SELECT COUNT(1) AS state_count FROM (SELECT MAX(block_number) FROM statetries WHERE stride_number = ? AND block_number < ? AND weight $? ? GROUP BY address_number)", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<size_t>(LayerException(ErrorOf(Cursor)));

			size_t Count = (*Cursor)["state_count"].Get().GetInteger();
			return ExpectsLR<size_t>(Count);
		}
		bool Chainstate::Verify()
		{
			String Command = VI_STRINGIFY((
				CREATE TABLE IF NOT EXISTS blocks
				(
					block_number BIGINT NOT NULL,
					block_hash BINARY(32) NOT NULL,
					message BINARY NOT NULL,
					PRIMARY KEY (block_hash)
				);
				CREATE UNIQUE INDEX IF NOT EXISTS blocks_block_number ON blocks (block_number);
				CREATE TABLE IF NOT EXISTS checkpoints
				(
					block_number BIGINT NOT NULL,
					PRIMARY KEY (block_number)
				);
				CREATE TABLE IF NOT EXISTS addresses
				(
					address_number BIGINT NOT NULL,
					address_hash BINARY NOT NULL,
					block_number BIGINT REFERENCES blocks (block_number),
					PRIMARY KEY (address_number)
				);
				CREATE UNIQUE INDEX IF NOT EXISTS addresses_address_hash ON addresses (address_hash);
				CREATE INDEX IF NOT EXISTS addresses_block_number ON addresses (block_number);
				CREATE TABLE IF NOT EXISTS strides
				(
					stride_number BIGINT NOT NULL,
					stride_hash BINARY NOT NULL,
					block_number BIGINT REFERENCES blocks (block_number),
					PRIMARY KEY (stride_number)
				);
				CREATE UNIQUE INDEX IF NOT EXISTS strides_stride_hash ON strides (stride_hash);
				CREATE INDEX IF NOT EXISTS strides_block_number ON strides (block_number);
				CREATE TABLE IF NOT EXISTS owners
				(
					owner_number BIGINT NOT NULL,
					owner_hash BINARY(20) NOT NULL,
					block_number BIGINT REFERENCES blocks (block_number),
					PRIMARY KEY (owner_number)
				);
				CREATE UNIQUE INDEX IF NOT EXISTS owners_owner_hash ON owners (owner_hash);
				CREATE INDEX IF NOT EXISTS owners_block_number ON owners (block_number);
				CREATE TABLE IF NOT EXISTS parties
				(
					transaction_number BIGINT REFERENCES transactions (transaction_number),
					transaction_owner_number BIGINT REFERENCES owners (owner_number),
					block_number BIGINT REFERENCES blocks (block_number),
					PRIMARY KEY (transaction_owner_number, block_number, transaction_number)
				);
				CREATE INDEX IF NOT EXISTS parties_block_number ON parties (block_number);
				CREATE VIEW IF NOT EXISTS partyviews
				(
					transaction_number,
					transaction_owner_hash,
					block_number
				) AS SELECT NULL, NULL, NULL WHERE FALSE;
				CREATE TRIGGER IF NOT EXISTS partyviews_push INSTEAD OF INSERT ON partyviews FOR EACH ROW BEGIN
					INSERT OR IGNORE INTO owners (owner_number, owner_hash, block_number)
					SELECT (SELECT COALESCE(MAX(owner_number), 0) + 1 FROM owners), NEW.transaction_owner_hash, NEW.block_number;
					INSERT OR IGNORE INTO parties (transaction_number, transaction_owner_number, block_number)
					SELECT NEW.transaction_number, owner_number, block_number FROM owners WHERE owner_hash = NEW.transaction_owner_hash;
				END;
				CREATE TABLE IF NOT EXISTS aliases
				(
					transaction_number BIGINT REFERENCES transactions (transaction_number),
					transaction_hash BINARY(32) NOT NULL,
					block_number BIGINT REFERENCES blocks (block_number),
					PRIMARY KEY (transaction_hash, transaction_number)
				);
				CREATE INDEX IF NOT EXISTS aliases_block_number ON aliases (block_number);
				CREATE TABLE IF NOT EXISTS transactions
				(
					transaction_number BIGINT NOT NULL,
					transaction_hash BINARY(32) NOT NULL,
					receipt_hash BINARY(32) NOT NULL,
					dispatch_queue BIGINT DEFAULT NULL,
					block_number BIGINT REFERENCES blocks (block_number),
					block_nonce BIGINT NOT NULL,
					transaction_message BINARY NOT NULL,
					receipt_message BINARY NOT NULL,
					PRIMARY KEY (transaction_hash)
				);
				CREATE UNIQUE INDEX IF NOT EXISTS transactions_transaction_number ON transactions (transaction_number);
				CREATE INDEX IF NOT EXISTS transactions_receipt_hash ON transactions (receipt_hash);
				CREATE INDEX IF NOT EXISTS transactions_dispatch_queue_block_nonce ON transactions (dispatch_queue, block_nonce);
				CREATE INDEX IF NOT EXISTS transactions_block_number_block_nonce ON transactions (block_number, block_nonce);
				CREATE VIEW IF NOT EXISTS transactionviews
				(
					transaction_number,
					transaction_owner_hash,
					transaction_hash,
					receipt_hash,
					dispatch_queue,
					block_number,
					block_nonce,
					transaction_message,
					receipt_message
				) AS SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL WHERE FALSE;
				CREATE TRIGGER IF NOT EXISTS transactionviews_push INSTEAD OF INSERT ON transactionviews FOR EACH ROW BEGIN
					INSERT INTO transactions (transaction_number, transaction_hash, receipt_hash, dispatch_queue, block_number, block_nonce, transaction_message, receipt_message)
					SELECT NEW.transaction_number, NEW.transaction_hash, NEW.receipt_hash, NEW.dispatch_queue, NEW.block_number, NEW.block_nonce, NEW.transaction_message, NEW.receipt_message;
					INSERT OR IGNORE INTO owners (owner_number, owner_hash, block_number)
					SELECT (SELECT COALESCE(MAX(owner_number), 0) + 1 FROM owners), NEW.transaction_owner_hash, NEW.block_number;
					INSERT OR IGNORE INTO parties (transaction_number, transaction_owner_number, block_number)
					SELECT NEW.transaction_number, owner_number, block_number FROM owners WHERE owner_hash = NEW.transaction_owner_hash;
				END;
				CREATE TABLE IF NOT EXISTS states
				(
					address_number BIGINT REFERENCES addresses (address_number),
					stride_number BIGINT REFERENCES strides (stride_number),
					block_number BIGINT REFERENCES blocks (block_number),
					weight BIGINT NOT NULL,
					message BINARY NOT NULL,
					PRIMARY KEY (address_number, stride_number)
				);
				CREATE INDEX IF NOT EXISTS states_stride_number_address_number ON states (stride_number, address_number);
				CREATE INDEX IF NOT EXISTS states_stride_number_weight ON states (stride_number, weight);
				CREATE INDEX IF NOT EXISTS states_block_number ON states (block_number);
				CREATE TABLE IF NOT EXISTS statetries
				(
					address_number BIGINT REFERENCES addresses (address_number),
					stride_number BIGINT REFERENCES strides (stride_number),
					block_number BIGINT REFERENCES blocks (block_number),
					weight BIGINT NOT NULL,
					message BINARY NOT NULL,
					PRIMARY KEY (address_number, stride_number, block_number)
				);
				CREATE INDEX IF NOT EXISTS statetries_stride_number_block_number_address_number ON statetries (stride_number, block_number, address_number);
				CREATE INDEX IF NOT EXISTS statetries_block_number ON statetries (block_number);
				CREATE VIEW IF NOT EXISTS stateviews
				(
					address_hash,
					stride_hash,
					block_number,
					weight,
					message
				) AS SELECT NULL, NULL, NULL, NULL, NULL WHERE FALSE;
				CREATE TRIGGER IF NOT EXISTS stateviews_push INSTEAD OF INSERT ON stateviews FOR EACH ROW BEGIN
					INSERT OR IGNORE INTO strides (stride_number, stride_hash, block_number)
					SELECT (SELECT COALESCE(MAX(stride_number), 0) + 1 FROM strides), NEW.stride_hash, NEW.block_number;
					INSERT OR IGNORE INTO addresses (address_number, address_hash, block_number)
					SELECT (SELECT COALESCE(MAX(address_number), 0) + 1 FROM addresses), NEW.address_hash, NEW.block_number;
					INSERT OR REPLACE INTO states (address_number, stride_number, block_number, weight, message)
					SELECT (SELECT address_number FROM addresses WHERE addresses.address_hash = NEW.address_hash), (SELECT stride_number FROM strides WHERE strides.stride_hash = NEW.stride_hash), NEW.block_number, NEW.weight, NEW.message;
					INSERT OR REPLACE INTO statetries (address_number, stride_number, block_number, weight, message)
					SELECT (SELECT address_number FROM addresses WHERE addresses.address_hash = NEW.address_hash), (SELECT stride_number FROM strides WHERE strides.stride_hash = NEW.stride_hash), NEW.block_number, NEW.weight, NEW.message;
				END;));

			Command.front() = ' ';
			Command.back() = ' ';
			Stringify::Trim(Command);

			auto Cursor = Query(Label, __func__, Command);
			return (Cursor && !Cursor->Error());
		}

		static thread_local Mempoolstate* LatestMempoolstate = nullptr;
		Mempoolstate::Mempoolstate(const std::string_view& NewLabel) noexcept : Label(NewLabel), Borrows(false)
		{
			if (LatestMempoolstate != nullptr)
			{
				Storage = *LatestMempoolstate->Storage;
				Borrows = !!Storage;
			}
			if (!Borrows)
			{
				StorageOf("mempoolstate");
				if (Storage)
					LatestMempoolstate = this;
			}
		}
		Mempoolstate::~Mempoolstate() noexcept
		{
			if (Borrows)
				Storage.Reset();
			if (LatestMempoolstate == this)
				LatestMempoolstate = nullptr;
		}
		ExpectsLR<void> Mempoolstate::SetSeed(const std::string_view& Address)
		{
			if (Address.empty())
				return ExpectsLR<void>(LayerException("invalid ip address"));

			if (GetValidatorByAddress(Address))
				return ExpectsLR<void>(LayerException("ip address and port found"));

			SchemaList Map;
			Map.push_back(Var::Set::String(Address));

			auto Cursor = EmplaceQuery(Label, __func__, "INSERT OR IGNORE INTO seeds (address) VALUES (?)", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<void> Mempoolstate::SetValidator(const Ledger::Edge& Value, Option<Ledger::Wallet>&& Wallet)
		{
			Format::Stream EdgeMessage;
			if (!Value.Store(&EdgeMessage))
				return ExpectsLR<void>(LayerException("edge serialization error"));

			Format::Stream WalletMessage;
			if (Wallet && !Wallet->Store(&WalletMessage))
				return ExpectsLR<void>(LayerException("wallet serialization error"));

			if (!Wallet)
			{
				SchemaList Map;
				Map.push_back(Var::Set::String(Value.Address));

				auto Cursor = EmplaceQuery(Label, __func__, "SELECT wallet_message FROM validators WHERE address = ? AND wallet_message IS NOT NULL", &Map);
				if (Cursor && !Cursor->ErrorOrEmpty())
				{
					WalletMessage.Data = (*Cursor)["wallet_message"].Get().GetBlob();
					Wallet = Ledger::Wallet();
				}
			}
			else
			{
				auto Blob = Protocol::Now().Key.EncryptBlob(WalletMessage.Data);
				if (!Blob)
					return Blob.Error();

				WalletMessage.Data = std::move(*Blob);
			}

			SchemaList Map;
			Map.push_back(Var::Set::String(Value.Address));
			Map.push_back(Var::Set::Integer(Value.GetPreference()));
			Map.push_back(Var::Set::Binary(EdgeMessage.Data));
			Map.push_back(Wallet ? Var::Set::Binary(WalletMessage.Data) : Var::Set::Null());

			auto Cursor = EmplaceQuery(Label, __func__, "INSERT OR REPLACE INTO validators (address, preference, edge_message, wallet_message) VALUES (?, ?, ?, ?)", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<void> Mempoolstate::ClearValidator(const std::string_view& ValidatorAddress)
		{
			SchemaList Map;
			Map.push_back(Var::Set::String(ValidatorAddress));

			auto Cursor = EmplaceQuery(Label, __func__, "DELETE FROM validators WHERE address = ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<std::pair<Ledger::Edge, Ledger::Wallet>> Mempoolstate::GetValidatorByOwnership(size_t Offset)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT edge_message, wallet_message FROM validators WHERE NOT (wallet_message IS NULL) LIMIT 1 OFFSET ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<std::pair<Ledger::Edge, Ledger::Wallet>>(LayerException(ErrorOf(Cursor)));

			auto Blob = Protocol::Now().Key.DecryptBlob((*Cursor)["wallet_message"].Get().GetBlob());
			if (!Blob)
				return Blob.Error();

			Ledger::Edge Node;
			Format::Stream EdgeMessage = Format::Stream((*Cursor)["edge_message"].Get().GetBlob());
			if (!Node.Load(EdgeMessage))
				return ExpectsLR<std::pair<Ledger::Edge, Ledger::Wallet>>(LayerException("edge deserialization error"));

			Ledger::Wallet Wallet;
			Format::Stream WalletMessage = Format::Stream(std::move(*Blob));
			if (!Wallet.Load(WalletMessage))
				return ExpectsLR<std::pair<Ledger::Edge, Ledger::Wallet>>(LayerException("wallet deserialization error"));

			return std::make_pair(std::move(Node), std::move(Wallet));
		}
		ExpectsLR<Ledger::Edge> Mempoolstate::GetValidatorByAddress(const std::string_view& ValidatorAddress)
		{
			SchemaList Map;
			Map.push_back(Var::Set::String(ValidatorAddress));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT edge_message FROM validators WHERE address = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Ledger::Edge>(LayerException(ErrorOf(Cursor)));

			Ledger::Edge Value;
			Format::Stream Message = Format::Stream((*Cursor)["edge_message"].Get().GetBlob());
			if (!Value.Load(Message))
				return ExpectsLR<Ledger::Edge>(LayerException("edge deserialization error"));

			return Value;
		}
		ExpectsLR<Ledger::Edge> Mempoolstate::GetValidatorByPreference(size_t Offset)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT edge_message FROM validators WHERE wallet_message IS NULL ORDER BY preference DESC LIMIT 1 OFFSET ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Ledger::Edge>(LayerException(ErrorOf(Cursor)));

			Ledger::Edge Value;
			Format::Stream Message = Format::Stream((*Cursor)["edge_message"].Get().GetBlob());
			if (!Value.Load(Message))
				return ExpectsLR<Ledger::Edge>(LayerException("edge deserialization error"));

			return Value;
		}
		ExpectsLR<Vector<String>> Mempoolstate::GetSeeds(size_t Count)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Integer(Count));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT edge_message FROM validators WHERE wallet_message IS NULL ORDER BY preference DESC LIMIT ? OFFSET 0", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<String>>(LayerException(ErrorOf(Cursor)));

			Vector<String> Result;
			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			for (size_t i = 0; i < Size; i++)
			{
				Ledger::Edge Value;
				Format::Stream Message = Format::Stream(Response[i]["edge_message"].Get().GetBlob());
				if (Value.Load(Message))
					Result.push_back(std::move(Value.Address));
			}

			return Result;
		}
		ExpectsLR<String> Mempoolstate::PopSeed()
		{
			auto Cursor = Query(Label, __func__, "SELECT address FROM seeds ORDER BY random() LIMIT 1");
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<String>(LayerException(ErrorOf(Cursor)));

			String Address = (*Cursor)["address"].Get().GetBlob();
			SchemaList Map;
			Map.push_back(Var::Set::String(Address));

			Cursor = EmplaceQuery(Label, __func__, "DELETE FROM seeds WHERE address = ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<String>(LayerException(ErrorOf(Cursor)));

			return Address;
		}
		ExpectsLR<size_t> Mempoolstate::GetValidatorsCount()
		{
			auto Cursor = Query(Label, __func__, "SELECT COUNT(1) AS counter FROM validators WHERE wallet_message IS NULL");
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<size_t>(LayerException(ErrorOf(Cursor)));

			return (size_t)(*Cursor)["counter"].Get().GetInteger();
		}
		ExpectsLR<Decimal> Mempoolstate::GetGasPrice(const Algorithm::AssetId& Asset, double PriorityPercentile)
		{
			if (PriorityPercentile < 0.0 || PriorityPercentile > 1.0)
				return ExpectsLR<Decimal>(LayerException("invalid priority percentile"));

			uint8_t Hash[16];
			Algorithm::Encoding::DecodeUint128(Asset, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));
			Map.push_back(Var::Set::Number(1.0 - PriorityPercentile));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT price FROM transactions WHERE asset = ? ORDER BY preference DESC NULLS LAST LIMIT 1 OFFSET (SELECT CAST((COUNT(1) * ?) AS INT) FROM transactions)", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Decimal>(LayerException(ErrorOf(Cursor)));

			Decimal Price = (*Cursor)["price"].Get().GetDecimal();
			return Price;
		}
		ExpectsLR<Decimal> Mempoolstate::GetAssetPrice(const Algorithm::AssetId& PriceOf, const Algorithm::AssetId& RelativeTo, double PriorityPercentile)
		{
			auto A = GetGasPrice(PriceOf, PriorityPercentile);
			if (!A || A->IsZero())
				return Decimal::Zero();

			auto B = GetGasPrice(RelativeTo, PriorityPercentile);
			if (!B)
				return Decimal::Zero();

			return *B / A->Truncate(Protocol::Now().Message.Precision);
		}
		ExpectsLR<void> Mempoolstate::AddTransaction(Ledger::Transaction& Value)
		{
			Format::Stream Message;
			if (!Value.Store(&Message))
				return ExpectsLR<void>(LayerException("transaction serialization error"));

			Algorithm::Pubkeyhash Owner;
			if (!Value.Recover(Owner))
				return ExpectsLR<void>(LayerException("transaction owner recovery error"));

			uint256_t Group = 0;
			Decimal Preference = Decimal::NaN();
			switch (Value.GetType())
			{
				case Ledger::TransactionLevel::OwnerAccount:
				{
					auto MedianGasPrice = GetGasPrice(Value.Asset, FeePercentile(FeePriority::Medium));
					Decimal DeltaGas = MedianGasPrice && MedianGasPrice->IsPositive() ? Value.GasPrice / *MedianGasPrice : 1.0;
					Decimal MaxGas = DeltaGas.IsPositive() ? Value.GasPrice * Value.GasLimit.ToDecimal() / DeltaGas.Truncate(Protocol::Now().Message.Precision) : Decimal::Zero();
					Decimal Multiplier = 2 << 20;
					Preference = MaxGas * Multiplier;
					break;
				}
				case Ledger::TransactionLevel::ProposerAccount:
					break;
				case Ledger::TransactionLevel::CumulativeAccount:
				{
					Vector<uint256_t> Merges;
					size_t Offset = 0, Count = 64;
					auto* Cumulative = ((Ledger::CumulativeEventTransaction*)&Value);
					Group = Cumulative->GetCumulativeHash();
					while (true)
					{
						auto Transactions = GetCumulativeEventTransactions(Group, Offset, Count);
						if (!Transactions || Transactions->empty())
							break;

						for (auto& Item : *Transactions)
						{
							Merges.push_back(Item->AsHash());
							if (Item->GetType() == Ledger::TransactionLevel::CumulativeAccount)
								Cumulative->Merge(*(Ledger::CumulativeEventTransaction*)*Item);
						}

						Offset += Transactions->size();
						if (Transactions->size() != Count)
							break;
					}

					auto Status = RemoveTransactions(Merges);
					if (!Status)
						return Status;
					break;
				}
				default:
					break;
			}

			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(Value.AsHash(), Hash);

			uint8_t GroupHash[32];
			Algorithm::Encoding::DecodeUint256(Group, GroupHash);

			uint8_t Asset[16];
			Algorithm::Encoding::DecodeUint128(Value.Asset, Asset);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));
			Map.push_back(Var::Set::Binary(GroupHash, sizeof(GroupHash)));
			Map.push_back(Var::Set::Binary(Owner, sizeof(Owner)));
			Map.push_back(Var::Set::Binary(Asset, sizeof(Asset)));
			Map.push_back(Var::Set::Integer(Value.Sequence));
			Map.push_back(Preference.IsNaN() ? Var::Set::Null() : Var::Set::Integer(Preference.ToUInt64()));
			Map.push_back(Var::Set::String(Value.GasPrice.ToString()));
			Map.push_back(Var::Set::Binary(Message.Data));
			Map.push_back(Var::Set::Binary(Owner, sizeof(Owner)));

			auto Cursor = EmplaceQuery(Label, __func__,
				"INSERT OR REPLACE INTO transactions (hash, attestation, owner, asset, sequence, preference, price, message) VALUES (?, ?, ?, ?, ?, ?, ?, ?);"
				"WITH epochs AS (SELECT rowid, ROW_NUMBER() OVER (ORDER BY sequence) AS epoch FROM transactions WHERE owner = ?) UPDATE transactions SET epoch = epochs.epoch FROM epochs WHERE transactions.rowid = epochs.rowid", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<void> Mempoolstate::RemoveTransactions(const Vector<uint256_t>& TransactionHashes)
		{
			if (TransactionHashes.empty())
				return Expectation::Met;

			UPtr<Schema> HashList = Var::Set::Array();
			HashList->Reserve(TransactionHashes.size());
			for (auto& Item : TransactionHashes)
			{
				uint8_t Hash[32];
				Algorithm::Encoding::DecodeUint256(Item, Hash);
				HashList->Push(Var::Binary(Hash, sizeof(Hash)));
			}

			SchemaList Map;
			Map.push_back(Var::Set::String(*LDB::Utils::InlineArray(std::move(HashList))));

			auto Cursor = EmplaceQuery(Label, __func__, "DELETE FROM transactions WHERE hash IN ($?)", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<void> Mempoolstate::RemoveTransactions(const UnorderedSet<uint256_t>& TransactionHashes)
		{
			if (TransactionHashes.empty())
				return Expectation::Met;

			UPtr<Schema> HashList = Var::Set::Array();
			HashList->Reserve(TransactionHashes.size());
			for (auto& Item : TransactionHashes)
			{
				uint8_t Hash[32];
				Algorithm::Encoding::DecodeUint256(Item, Hash);
				HashList->Push(Var::Binary(Hash, sizeof(Hash)));
			}

			SchemaList Map;
			Map.push_back(Var::Set::String(*LDB::Utils::InlineArray(std::move(HashList))));

			auto Cursor = EmplaceQuery(Label, __func__, "DELETE FROM transactions WHERE hash IN ($?)", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<bool> Mempoolstate::HasTransaction(const uint256_t& TransactionHash)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(TransactionHash, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT TRUE FROM transactions WHERE hash = ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<bool>(LayerException(ErrorOf(Cursor)));

			return !Cursor->Empty();
		}
		ExpectsLR<uint64_t> Mempoolstate::GetLowestTransactionSequence(const Algorithm::Pubkeyhash Owner)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Binary(Owner, sizeof(Owner)));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT MIN(sequence) FROM transactions WHERE owner = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<uint64_t>(LayerException(ErrorOf(Cursor)));

			uint64_t Sequence = (*Cursor)["sequence"].Get().GetInteger();
			return Sequence;
		}
		ExpectsLR<uint64_t> Mempoolstate::GetHighestTransactionSequence(const Algorithm::Pubkeyhash Owner)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Binary(Owner, sizeof(Owner)));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT MAX(sequence) FROM transactions WHERE owner = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<uint64_t>(LayerException(ErrorOf(Cursor)));

			uint64_t Sequence = (*Cursor)["sequence"].Get().GetInteger();
			return Sequence;
		}
		ExpectsLR<UPtr<Ledger::Transaction>> Mempoolstate::GetTransactionByHash(const uint256_t& TransactionHash)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(TransactionHash, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT hash, message FROM transactions WHERE hash = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<UPtr<Ledger::Transaction>>(LayerException(ErrorOf(Cursor)));

			Format::Stream Message = Format::Stream((*Cursor)["message"].Get().GetBlob());
			UPtr<Ledger::Transaction> Value = Transactions::Resolver::New(Messages::Authentic::ResolveType(Message).Or(0));
			if (!Value || !Value->Load(Message))
				return ExpectsLR<UPtr<Ledger::Transaction>>(LayerException("transaction deserialization error"));

			FinalizeChecksum(**Value, (*Cursor)["hash"]);
			return Value;
		}
		ExpectsLR<Vector<UPtr<Ledger::Transaction>>> Mempoolstate::GetTransactions(size_t Offset, size_t Count)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT message FROM transactions ORDER BY epoch ASC, preference DESC NULLS FIRST LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<UPtr<Ledger::Transaction>>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Vector<UPtr<Ledger::Transaction>> Values;
			Values.reserve(Size);

			for (size_t i = 0; i < Size; i++)
			{
				auto Row = Response[i];
				Format::Stream Message = Format::Stream(Row["message"].Get().GetBlob());
				UPtr<Ledger::Transaction> Value = Transactions::Resolver::New(Messages::Authentic::ResolveType(Message).Or(0));
				if (Value && Value->Load(Message))
				{
					FinalizeChecksum(**Value, Row["hash"]);
					Values.emplace_back(std::move(Value));
				}
			}

			return Values;
		}
		ExpectsLR<Vector<UPtr<Ledger::Transaction>>> Mempoolstate::GetCumulativeEventTransactions(const uint256_t& CumulativeHash, size_t Offset, size_t Count)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(CumulativeHash, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT message FROM transactions WHERE attestation = ? ORDER BY attestation ASC LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<UPtr<Ledger::Transaction>>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Vector<UPtr<Ledger::Transaction>> Values;
			Values.reserve(Size);

			for (size_t i = 0; i < Size; i++)
			{
				auto Row = Response[i];
				Format::Stream Message = Format::Stream(Row["message"].Get().GetBlob());
				UPtr<Ledger::Transaction> Value = Transactions::Resolver::New(Messages::Authentic::ResolveType(Message).Or(0));
				if (Value && Value->Load(Message))
				{
					FinalizeChecksum(**Value, Row["hash"]);
					Values.emplace_back(std::move(Value));
				}
			}

			return Values;
		}
		ExpectsLR<Vector<uint256_t>> Mempoolstate::GetTransactionHashset(size_t Offset, size_t Count)
		{
			if (!Count)
				return LayerException("invalid count");

			SchemaList Map;
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT hash FROM transactions ORDER BY hash ASC LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<uint256_t>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Vector<uint256_t> Result;
			Result.reserve(Result.size() + Size);
			for (size_t i = 0; i < Size; i++)
			{
				auto InHash = Response[i]["hash"].Get().GetBlob();
				if (InHash.size() != sizeof(uint256_t))
					continue;

				uint256_t OutHash;
				Algorithm::Encoding::EncodeUint256((uint8_t*)InHash.data(), OutHash);
				Result.push_back(OutHash);
			}

			return Result;
		}
		double Mempoolstate::FeePercentile(FeePriority Priority)
		{
			switch (Priority)
			{
				case Tangent::Storages::FeePriority::Fastest:
					return 0.90;
				case Tangent::Storages::FeePriority::Fast:
					return 0.75;
				case Tangent::Storages::FeePriority::Medium:
					return 0.50;
				case Tangent::Storages::FeePriority::Slow:
					return 0.25;
				default:
					return 1.00;
			}
		}
		bool Mempoolstate::Verify()
		{
			String Command = VI_STRINGIFY(
				CREATE TABLE IF NOT EXISTS validators
				(
					address TEXT NOT NULL,
					preference INTEGER NOT NULL,
					edge_message BINARY NOT NULL,
					wallet_message BINARY DEFAULT NULL,
					PRIMARY KEY (address)
				);
				CREATE INDEX IF NOT EXISTS validators_wallet_message_preference ON validators (wallet_message IS NULL, preference);
				CREATE TABLE IF NOT EXISTS seeds
				(
					address TEXT NOT NULL,
					PRIMARY KEY (address)
				);
				CREATE TABLE IF NOT EXISTS transactions
				(
					hash BINARY(32) NOT NULL,
					attestation BINARY(32) DEFAULT NULL,
					owner BINARY(20) NOT NULL,
					asset BINARY(16) NOT NULL,
					sequence BIGINT NOT NULL,
					epoch INTEGER DEFAULT 0,
					preference INTEGER DEFAULT NULL,
					price TEXT NOT NULL,
					message BINARY NOT NULL,
					PRIMARY KEY (hash)
				);
				CREATE INDEX IF NOT EXISTS transactions_attestation ON transactions (attestation);
				CREATE INDEX IF NOT EXISTS transactions_owner_sequence ON transactions (owner, sequence);
				CREATE INDEX IF NOT EXISTS transactions_asset_preference ON transactions (asset ASC, preference DESC);
				CREATE INDEX IF NOT EXISTS transactions_epoch_preference ON transactions (epoch ASC, preference DESC););

			auto Cursor = Query(Label, __func__, Command);
			return (Cursor && !Cursor->Error());
		}

		Sidechainstate::Sidechainstate(const std::string_view& NewLabel, const Algorithm::AssetId& NewAsset) noexcept : Asset(NewAsset), Label(NewLabel)
		{
			String Blockchain = Algorithm::Asset::BlockchainOf(Asset);
			StorageOf("sidechainstate_" + Stringify::ToLower(Blockchain));
		}
		ExpectsLR<void> Sidechainstate::AddMasterWallet(const Oracle::MasterWallet& Value)
		{
			Format::Stream Message;
			if (!Value.Store(&Message))
				return ExpectsLR<void>(LayerException("wallet serialization error"));

			auto Blob = Protocol::Now().Key.EncryptBlob(Message.Data);
			if (!Blob)
				return Blob.Error();

			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(Value.AsHash(), Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));
			Map.push_back(Var::Set::Integer(DateTime().Milliseconds()));
			Map.push_back(Var::Set::Binary(*Blob));

			auto Cursor = EmplaceQuery(Label, __func__, "INSERT OR REPLACE INTO wallets (hash, address_index, nonce, message) VALUES (?, -1, ?, ?)", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<Oracle::MasterWallet> Sidechainstate::GetMasterWallet()
		{
			auto Cursor = Query(Label, __func__, "SELECT message FROM wallets WHERE address_index = -1 ORDER BY nonce DESC LIMIT 1");
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Oracle::MasterWallet>(LayerException(ErrorOf(Cursor)));

			auto Blob = Protocol::Now().Key.DecryptBlob((*Cursor)["message"].Get().GetBlob());
			if (!Blob)
				return Blob.Error();

			Oracle::MasterWallet Value;
			Format::Stream Message = Format::Stream(std::move(*Blob));
			if (!Value.Load(Message))
				return ExpectsLR<Oracle::MasterWallet>(LayerException("wallet deserialization error"));

			return Value;
		}
		ExpectsLR<Oracle::MasterWallet> Sidechainstate::GetMasterWalletByHash(const uint256_t& MasterWalletHash)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(MasterWalletHash, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT message FROM wallets WHERE hash = ? AND address_index = -1", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Oracle::MasterWallet>(LayerException(ErrorOf(Cursor)));

			auto Blob = Protocol::Now().Key.DecryptBlob((*Cursor)["message"].Get().GetBlob());
			if (!Blob)
				return Blob.Error();

			Oracle::MasterWallet Value;
			Format::Stream Message = Format::Stream(std::move(*Blob));
			if (!Value.Load(Message))
				return ExpectsLR<Oracle::MasterWallet>(LayerException("wallet deserialization error"));

			return Value;
		}
		ExpectsLR<void> Sidechainstate::AddDerivedWallet(const Oracle::MasterWallet& Parent, const Oracle::DerivedSigningWallet& Value)
		{
			if (!Value.IsValid())
				return ExpectsLR<void>(LayerException("invalid wallet"));

			Format::Stream Message;
			if (!Value.Store(&Message))
				return ExpectsLR<void>(LayerException("wallet serialization error"));

			auto Blob = Protocol::Now().Key.EncryptBlob(Message.Data);
			if (!Blob)
				return Blob.Error();

			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(Parent.AsHash(), Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));
			Map.push_back(Var::Set::Integer(Value.AddressIndex.Or(0)));
			Map.push_back(Var::Set::Integer(DateTime().Milliseconds()));
			Map.push_back(Var::Set::Binary(*Blob));

			auto Cursor = EmplaceQuery(Label, __func__, "INSERT OR REPLACE INTO wallets (hash, address_index, nonce, message) VALUES (?, ?, ?, ?)", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return AddMasterWallet(Parent);
		}
		ExpectsLR<Oracle::DerivedSigningWallet> Sidechainstate::GetDerivedWallet(const uint256_t& MasterWalletHash, uint64_t AddressIndex)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(MasterWalletHash, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));
			Map.push_back(Var::Set::Integer(AddressIndex));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT message FROM wallets WHERE hash = ? AND address_index = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Oracle::DerivedSigningWallet>(LayerException(ErrorOf(Cursor)));

			auto Blob = Protocol::Now().Key.DecryptBlob((*Cursor)["message"].Get().GetBlob());
			if (!Blob)
				return Blob.Error();

			Oracle::DerivedSigningWallet Value;
			Format::Stream Message = Format::Stream(std::move(*Blob));
			if (!Value.Load(Message))
				return ExpectsLR<Oracle::DerivedSigningWallet>(LayerException("wallet deserialization error"));

			return Value;
		}
		ExpectsLR<void> Sidechainstate::AddUTXO(const Oracle::IndexUTXO& Value)
		{
			Format::Stream Message;
			if (!Value.Store(&Message))
				return ExpectsLR<void>(LayerException("utxo serialization error"));

			SchemaList Map;
			Map.push_back(Var::Set::Binary(GetCoinLocation(Value.UTXO.TransactionId, Value.UTXO.Index)));
			Map.push_back(Var::Set::Binary(Value.Binding));
			Map.push_back(Var::Set::Boolean(false));
			Map.push_back(Var::Set::Binary(Message.Data));
			
			auto Cursor = EmplaceQuery(Label, __func__, "INSERT OR REPLACE INTO coins (location, binding, spent, message) VALUES (?, ?, ?, ?)", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<void> Sidechainstate::RemoveUTXO(const std::string_view& TransactionId, uint32_t Index)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Binary(GetCoinLocation(TransactionId, Index)));

			auto Cursor = EmplaceQuery(Label, __func__, "UPDATE coins SET spent = TRUE WHERE location = ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<Oracle::IndexUTXO> Sidechainstate::GetSTXO(const std::string_view& TransactionId, uint32_t Index)
		{
			SchemaList Map;
			Map.push_back(Var::Set::String(String(TransactionId) + ":" + ToString(Index)));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT message FROM coins WHERE location = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Oracle::IndexUTXO>(LayerException(ErrorOf(Cursor)));

			Oracle::IndexUTXO Value;
			Format::Stream Message = Format::Stream((*Cursor)["message"].Get().GetBlob());
			if (!Value.Load(Message))
				return ExpectsLR<Oracle::IndexUTXO>(LayerException("utxo deserialization error"));

			return Value;
		}
		ExpectsLR<Oracle::IndexUTXO> Sidechainstate::GetUTXO(const std::string_view& TransactionId, uint32_t Index)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Binary(GetCoinLocation(TransactionId, Index)));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT message FROM coins WHERE location = ? AND spent = FALSE", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Oracle::IndexUTXO>(LayerException(ErrorOf(Cursor)));

			Oracle::IndexUTXO Value;
			Format::Stream Message = Format::Stream((*Cursor)["message"].Get().GetBlob());
			if (!Value.Load(Message))
				return ExpectsLR<Oracle::IndexUTXO>(LayerException("utxo deserialization error"));

			return Value;
		}
		ExpectsLR<Vector<Oracle::IndexUTXO>> Sidechainstate::GetUTXOs(const std::string_view& Binding, size_t Offset, size_t Count)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Binary(Binding));
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT message FROM coins WHERE spent = FALSE AND binding = ? LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<Oracle::IndexUTXO>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Vector<Oracle::IndexUTXO> Values;
			Values.reserve(Size);

			for (size_t i = 0; i < Size; i++)
			{
				Oracle::IndexUTXO Value;
				Format::Stream Message = Format::Stream(Response[i]["message"].Get().GetBlob());
				if (Value.Load(Message))
					Values.emplace_back(std::move(Value));
			}

			return Values;
		}
		ExpectsLR<void> Sidechainstate::AddIncomingTransaction(const Oracle::IncomingTransaction& Value, uint64_t BlockId)
		{
			auto* Chain = Oracle::Datamaster::GetChain(Value.Asset);
			if (!Chain)
				return ExpectsLR<void>(LayerException("invalid witness transaction asset"));

			Format::Stream Message;
			if (!Value.Store(&Message))
				return ExpectsLR<void>(LayerException("witness transaction serialization error"));

			SchemaList Map;
			Map.push_back(Var::Set::Binary(GetTransactionLocation(Value.TransactionId)));
			Map.push_back(Var::Set::Null());
			Map.push_back(Var::Set::Integer(Value.BlockId));
			Map.push_back(Var::Set::Boolean(Value.BlockId <= BlockId ? BlockId - Value.BlockId >= Chain->GetBlockLatency() : false));
			Map.push_back(Var::Set::Binary(Message.Data));

			auto Cursor = EmplaceQuery(Label, __func__, "INSERT INTO transactions (location, binding, block_id, approved, message) VALUES (?, ?, ?, ?, ?) ON CONFLICT (location) DO UPDATE SET binding = (CASE WHEN binding IS NOT NULL THEN binding ELSE EXCLUDED.binding END), block_id = EXCLUDED.block_id, approved = EXCLUDED.approved, message = EXCLUDED.message", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<void> Sidechainstate::AddOutgoingTransaction(const Oracle::IncomingTransaction& Value, const uint256_t ExternalId)
		{
			Format::Stream Message;
			if (!Value.Store(&Message))
				return ExpectsLR<void>(LayerException("witness transaction serialization error"));

			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(ExternalId, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(GetTransactionLocation(Value.TransactionId)));
			Map.push_back(ExternalId > 0 ? Var::Set::Binary(Hash, sizeof(Hash)) : Var::Set::Null());
			Map.push_back(Var::Set::Integer(Value.BlockId));
			Map.push_back(Var::Set::Boolean(false));
			Map.push_back(Var::Set::Binary(Message.Data));

			auto Cursor = EmplaceQuery(Label, __func__, "INSERT INTO transactions (location, external_id, block_id, approved, message) VALUES (?, ?, ?, ?, ?) ON CONFLICT (location) DO UPDATE SET external_id = (CASE WHEN external_id IS NOT NULL THEN external_id ELSE EXCLUDED.external_id END), block_id = EXCLUDED.block_id, approved = EXCLUDED.approved, message = EXCLUDED.message", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<Oracle::IncomingTransaction> Sidechainstate::GetTransaction(const std::string_view& TransactionId, const uint256_t& ExternalId)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(ExternalId, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(GetTransactionLocation(TransactionId)));
			Map.push_back(ExternalId > 0 ? Var::Set::Binary(Hash, sizeof(Hash)) : Var::Set::Null());

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT message FROM transactions WHERE location = ? OR binding = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Oracle::IncomingTransaction>(LayerException(ErrorOf(Cursor)));

			Oracle::IncomingTransaction Value;
			Format::Stream Message = Format::Stream((*Cursor)["message"].Get().GetBlob());
			if (!Value.Load(Message))
				return ExpectsLR<Oracle::IncomingTransaction>(LayerException("witness transaction deserialization error"));

			return Value;
		}
		ExpectsLR<Vector<Oracle::IncomingTransaction>> Sidechainstate::ApproveTransactions(uint64_t BlockHeight, uint64_t BlockLatency)
		{
			if (!BlockHeight || !BlockLatency)
				return ExpectsLR<Vector<Oracle::IncomingTransaction>>(LayerException("invalid block height or block latency"));
			else if (BlockHeight <= BlockLatency)
				return ExpectsLR<Vector<Oracle::IncomingTransaction>>(Vector<Oracle::IncomingTransaction>());

			SchemaList Map;
			Map.push_back(Var::Set::Integer(BlockHeight - BlockLatency));
			Map.push_back(Var::Set::Integer(BlockHeight - BlockLatency));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT message FROM transactions WHERE block_id <= ? AND approved = FALSE", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<Oracle::IncomingTransaction>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Vector<Oracle::IncomingTransaction> Values;
			Values.reserve(Size);

			for (size_t i = 0; i < Size; i++)
			{
				Oracle::IncomingTransaction Value;
				Format::Stream Message = Format::Stream(Response[i]["message"].Get().GetBlob());
				if (!Value.Load(Message))
					continue;

				if (Value.BlockId > 0)
				{
					if (AddIncomingTransaction(Value, BlockHeight))
						Values.emplace_back(std::move(Value));
				}
				else
				{
					Value.BlockId = BlockHeight;
					AddIncomingTransaction(Value, BlockHeight);
				}
			}

			return ExpectsLR<Vector<Oracle::IncomingTransaction>>(std::move(Values));
		}
		ExpectsLR<void> Sidechainstate::SetProperty(const std::string_view& Key, UPtr<Schema>&& Value)
		{
			Format::Stream Message;
			Message.WriteVariative(*Value);

			SchemaList Map;
			Map.push_back(Var::Set::String(Algorithm::Asset::BlockchainOf(Asset) + ":" + String(Key)));
			Map.push_back(Var::Set::Binary(Message.Compress()));

			if (Value)
			{
				auto Cursor = EmplaceQuery(Label, __func__, "INSERT OR REPLACE INTO properties (key, message) VALUES (?, ?)", &Map);
				if (!Cursor || Cursor->Error())
					return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));
			}
			else
			{
				auto Cursor = EmplaceQuery(Label, __func__, "DELETE FROM properties WHERE key = ?", &Map);
				if (!Cursor || Cursor->Error())
					return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));
			}

			return Expectation::Met;
		}
		ExpectsLR<Schema*> Sidechainstate::GetProperty(const std::string_view& Key)
		{
			SchemaList Map;
			Map.push_back(Var::Set::String(Algorithm::Asset::BlockchainOf(Asset) + ":" + String(Key)));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT message FROM properties WHERE key = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Schema*>(LayerException(ErrorOf(Cursor)));

			Schema* Value = nullptr;
			Format::Stream Message = Format::Stream::Decompress((*Cursor)["message"].Get().GetString());
			if (!Message.ReadVariative(Message.ReadType(), &Value))
				return ExpectsLR<Schema*>(LayerException("state value deserialization error"));

			return Value;
		}
		ExpectsLR<void> Sidechainstate::SetCache(Oracle::CachePolicy Policy, const std::string_view& Key, UPtr<Schema>&& Value)
		{
			Format::Stream Message;
			Message.WriteVariative(*Value);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Format::Util::IsHexEncoding(Key) ? Codec::HexDecode(Key) : String(Key)));
			Map.push_back(Var::Set::Binary(Message.Compress()));

			if (Value)
			{
				auto Cursor = EmplaceQuery(Label, __func__, Stringify::Text("INSERT INTO %s (key, message) VALUES (?, ?)", GetCacheLocation(Policy).data()), &Map);
				if (!Cursor || Cursor->Error())
					return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));
			}
			else
			{
				auto Cursor = EmplaceQuery(Label, __func__, Stringify::Text("DELETE FROM %s WHERE key = ?", GetCacheLocation(Policy).data()), &Map);
				if (!Cursor || Cursor->Error())
					return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));
			}

			return Expectation::Met;
		}
		ExpectsLR<Schema*> Sidechainstate::GetCache(Oracle::CachePolicy Policy, const std::string_view& Key)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Binary(Format::Util::IsHexEncoding(Key) ? Codec::HexDecode(Key) : String(Key)));

			auto Cursor = EmplaceQuery(Label, __func__, Stringify::Text("SELECT message FROM %s WHERE key = ?", GetCacheLocation(Policy).data()), &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Schema*>(LayerException(ErrorOf(Cursor)));

			Schema* Value = nullptr;
			Format::Stream Message = Format::Stream::Decompress((*Cursor)["message"].Get().GetString());
			if (!Message.ReadVariative(Message.ReadType(), &Value))
				return ExpectsLR<Schema*>(LayerException("cache value deserialization error"));

			return Value;
		}
		ExpectsLR<void> Sidechainstate::SetAddressIndex(const std::string_view& Address, const Oracle::IndexAddress& Value)
		{
			Format::Stream Message;
			if (!Value.Store(&Message))
				return ExpectsLR<void>(LayerException("address index serialization error"));

			SchemaList Map;
			Map.push_back(Var::Set::Binary(GetAddressLocation(Address)));
			Map.push_back(Var::Set::Binary(Message.Data));

			auto Cursor = EmplaceQuery(Label, __func__, "INSERT OR REPLACE INTO addresses (location, message) VALUES (?, ?)", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<Oracle::IndexAddress> Sidechainstate::GetAddressIndex(const std::string_view& Address)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Binary(GetAddressLocation(Address)));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT message FROM addresses WHERE location = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Oracle::IndexAddress>(LayerException(ErrorOf(Cursor)));

			Oracle::IndexAddress Value;
			Format::Stream Message = Format::Stream((*Cursor)["message"].Get().GetBlob());
			if (!Value.Load(Message))
				return ExpectsLR<Oracle::IndexAddress>(LayerException("address index deserialization error"));

			return Value;
		}
		ExpectsLR<UnorderedMap<String, Oracle::IndexAddress>> Sidechainstate::GetAddressIndices(const UnorderedSet<String>& Addresses)
		{
			UPtr<Schema> AddressList = Var::Set::Array();
			AddressList->Reserve(Addresses.size());
			for (auto& Item : Addresses)
			{
				if (!Item.empty())
					AddressList->Push(Var::Binary(GetAddressLocation(Item)));
			}
			if (AddressList->Empty())
				return ExpectsLR<UnorderedMap<String, Oracle::IndexAddress>>(LayerException("no locations"));

			SchemaList Map;
			Map.push_back(Var::Set::String(*LDB::Utils::InlineArray(std::move(AddressList))));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT message FROM addresses WHERE location IN ($?)", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<UnorderedMap<String, Oracle::IndexAddress>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			UnorderedMap<String, Oracle::IndexAddress> Values;
			Values.reserve(Size);

			for (size_t i = 0; i < Size; i++)
			{
				Oracle::IndexAddress Value;
				Format::Stream Message = Format::Stream(Response[i]["message"].Get().GetBlob());
				if (Value.Load(Message))
					Values[Value.Address] = std::move(Value);
			}

			return Values;
		}
		ExpectsLR<Vector<String>> Sidechainstate::GetAddressIndices()
		{
			auto Cursor = Query(Label, __func__, "SELECT message FROM addresses");
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<String>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Vector<String> Values;
			Values.reserve(Size);

			for (size_t i = 0; i < Size; i++)
			{
				Oracle::IndexAddress Value;
				Format::Stream Message = Format::Stream(Response[i]["message"].Get().GetBlob());
				if (Value.Load(Message))
					Values.emplace_back(std::move(Value.Address));
			}

			return Values;
		}
		std::string_view Sidechainstate::GetCacheLocation(Oracle::CachePolicy Policy)
		{
			switch (Policy)
			{
				case Oracle::CachePolicy::Persistent:
					return "persistent_caches";
				case Oracle::CachePolicy::Extended:
					return "extended_caches";
				case Oracle::CachePolicy::Greedy:
				case Oracle::CachePolicy::Lazy:
				case Oracle::CachePolicy::Shortened:
				default:
					return "shortened_caches";
			}
		}
		String Sidechainstate::GetAddressLocation(const std::string_view& Address)
		{
			Format::Stream Message;
			Message.WriteString(Address);
			return Message.Data;
		}
		String Sidechainstate::GetTransactionLocation(const std::string_view& TransactionId)
		{
			Format::Stream Message;
			Message.WriteString(TransactionId);
			return Message.Data;
		}
		String Sidechainstate::GetCoinLocation(const std::string_view& TransactionId, uint32_t Index)
		{
			Format::Stream Message;
			Message.WriteString(TransactionId);
			Message.WriteTypeless(Index);
			return Message.Data;
		}
		bool Sidechainstate::Verify()
		{
			const uint32_t MaxECacheCapacity = Protocol::Now().User.Oracle.CacheExtendedSize;
			const uint32_t MaxSCacheCapacity = Protocol::Now().User.Oracle.CacheShortSize;
			String Command = VI_STRINGIFY(
				CREATE TABLE IF NOT EXISTS wallets
				(
					hash BINARY(32) NOT NULL,
					address_index INTEGER NOT NULL,
					nonce INTEGER NOT NULL,
					message BINARY NOT NULL,
  					PRIMARY KEY (hash, address_index)
				);
				CREATE INDEX IF NOT EXISTS wallets_nonce_address_index ON wallets (nonce, address_index);
				CREATE TABLE IF NOT EXISTS coins
				(
					location BINARY NOT NULL,
					binding BINARY(32) NOT NULL,
					spent BOOLEAN NOT NULL,
					message BINARY NOT NULL,
  					PRIMARY KEY (location)
				);
				CREATE INDEX IF NOT EXISTS coins_spent_binding ON coins (spent, binding);
				CREATE TABLE IF NOT EXISTS transactions
				(
					location BINARY NOT NULL,
					binding BINARY(32) DEFAULT NULL,
					block_id BIGINT NOT NULL,
					approved BOOLEAN NOT NULL,
					message BINARY NOT NULL,
  					PRIMARY KEY (location)
				);
				CREATE INDEX IF NOT EXISTS transactions_binding ON transactions (binding);
				CREATE INDEX IF NOT EXISTS transactions_block_id_approved ON transactions (block_id, approved);
				CREATE TABLE IF NOT EXISTS addresses
				(
					location BINARY NOT NULL,
					message BINARY NOT NULL,
					PRIMARY KEY (location)
				);
				CREATE TABLE IF NOT EXISTS properties
				(
					key TEXT NOT NULL,
					message BINARY NOT NULL,
  					PRIMARY KEY (key)
				);
				CREATE TABLE IF NOT EXISTS persistent_caches
				(
					key BINARY NOT NULL,
					message BINARY NOT NULL,
  					PRIMARY KEY (key)
				);
				CREATE TABLE IF NOT EXISTS extended_caches
				(
					id INTEGER NOT NULL,
					key BINARY NOT NULL,
					message BINARY NOT NULL,
  					PRIMARY KEY (id),
					UNIQUE (key)
				);
				CREATE TRIGGER IF NOT EXISTS extended_caches_capacity AFTER INSERT ON extended_caches BEGIN
					DELETE FROM extended_caches WHERE id = (SELECT id FROM extended_caches ORDER BY id ASC) AND (SELECT COUNT(1) FROM extended_caches) > max_extended_cache_capacity;
				END;
				CREATE TABLE IF NOT EXISTS shortened_caches
				(
					id INTEGER NOT NULL,
					key BINARY NOT NULL,
					message BINARY NOT NULL,
  					PRIMARY KEY (id),
					UNIQUE (key)
				);
				CREATE TRIGGER IF NOT EXISTS shortened_caches_capacity AFTER INSERT ON shortened_caches BEGIN
					DELETE FROM shortened_caches WHERE id = (SELECT id FROM shortened_caches ORDER BY id ASC) AND (SELECT COUNT(1) FROM shortened_caches) > max_shortened_cache_capacity;
				END;);
			Stringify::Replace(Command, "max_extended_cache_capacity", ToString(MaxECacheCapacity));
			Stringify::Replace(Command, "max_shortened_cache_capacity", ToString(MaxSCacheCapacity));

			auto Cursor = Query(Label, __func__, Command);
			return (Cursor && !Cursor->Error());
		}
	}
}