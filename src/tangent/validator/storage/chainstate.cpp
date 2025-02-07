#include "chainstate.h"
#include "../../policy/transactions.h"
#include "../../policy/states.h"
#define BLOB_BLOCK 'b'
#define BLOB_TRANSACTION 't'
#define BLOB_RECEIPT 'r'
#define BLOB_UNIFORM 'u'
#define BLOB_MULTIFORM 'm'
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
			uint8_t TransactionHash[32];
			Format::Stream TransactionMessage;
			Format::Stream ReceiptMessage;
			uint64_t TransactionNumber;
			uint64_t BlockNonce;
			uint64_t DispatchNumber;
			Vector<TransactionPartyBlob> Parties;
			Vector<TransactionAliasBlob> Aliases;
			const Ledger::BlockTransaction* Context;
		};

		struct UniformBlob
		{
			Format::Stream Message;
			String Index;
			const Ledger::Uniform* Context;
		};

		struct MultiformBlob
		{
			Format::Stream Message;
			String Column;
			String Row;
			int64_t Factor;
			const Ledger::Multiform* Context;
		};

		static void FinalizeChecksum(Messages::Generic& Message, const Variant& Column)
		{
			if (Column.Size() == sizeof(uint256_t))
				Algorithm::Encoding::EncodeUint256(Column.GetBinary(), Message.Checksum);
		}
		static void FinalizeChecksum(Messages::Authentic& Message, const Variant& Column)
		{
			if (Column.Size() == sizeof(uint256_t))
				Algorithm::Encoding::EncodeUint256(Column.GetBinary(), Message.Checksum);
		}
		static String GetBlockLabel(const uint8_t Hash[32])
		{
			String Label;
			Label.resize(33);
			Label.front() = BLOB_BLOCK;
			memcpy(Label.data() + 1, Hash, sizeof(uint8_t) * 32);
			return Label;
		}
		static String GetTransactionLabel(const uint8_t Hash[32])
		{
			String Label;
			Label.resize(33);
			Label.front() = BLOB_TRANSACTION;
			memcpy(Label.data() + 1, Hash, sizeof(uint8_t) * 32);
			return Label;
		}
		static String GetReceiptLabel(const uint8_t Hash[32])
		{
			String Label;
			Label.resize(33);
			Label.front() = BLOB_RECEIPT;
			memcpy(Label.data() + 1, Hash, sizeof(uint8_t) * 32);
			return Label;
		}
		static String GetUniformLabel(const std::string_view& Index, uint64_t Number)
		{
			String Label;
			Label.resize(1 + Index.size());
			Label.front() = BLOB_UNIFORM;
			memcpy(Label.data() + 1, Index.data(), Index.size());

			uint64_t Numeric = OS::CPU::ToEndianness(OS::CPU::Endian::Little, Number);
			Label.append(std::string_view((char*)&Numeric, sizeof(Numeric)));
			return Label;
		}
		static String GetMultiformLabel(const std::string_view& Column, const std::string_view& Row, uint64_t Number)
		{
			String Label;
			Label.resize(1 + Column.size() + Row.size());
			Label.front() = BLOB_MULTIFORM;
			memcpy(Label.data() + 1, Column.data(), Column.size());
			memcpy(Label.data() + 1 + Column.size(), Row.data(), Row.size());

			uint64_t Numeric = OS::CPU::ToEndianness(OS::CPU::Endian::Little, Number);
			Label.append(std::string_view((char*)&Numeric, sizeof(Numeric)));
			return Label;
		}

		void AccountCache::ClearLocations()
		{
			UMutex<std::mutex> Unique(Mutex);
			Accounts.clear();
		}
		void AccountCache::ClearAccountLocation(const Algorithm::Pubkeyhash Account)
		{
			UMutex<std::mutex> Unique(Mutex);
			auto It = Accounts.find(KeyLookupCast(std::string_view((char*)Account, sizeof(Algorithm::Pubkeyhash))));
			if (It != Accounts.end() && !It->second)
				Accounts.erase(It);
		}
		void AccountCache::SetAccountLocation(const Algorithm::Pubkeyhash Account, uint64_t Location)
		{
			auto Size = Protocol::Now().User.Storage.LocationCacheSize;
			String Target = String((char*)Account, sizeof(Algorithm::Pubkeyhash));
			UMutex<std::mutex> Unique(Mutex);
			if (Accounts.size() >= Size)
				Accounts.clear();
			Accounts[Target] = Location;
		}
		Option<uint64_t> AccountCache::GetAccountLocation(const std::string_view& Account)
		{
			UMutex<std::mutex> Unique(Mutex);
			auto It = Accounts.find(Account);
			if (It == Accounts.end())
				return Optional::None;

			return It->second;
		}

		void UniformCache::ClearLocations()
		{
			UMutex<std::mutex> Unique(Mutex);
			Indices.clear();
			Blocks.clear();
		}
		void UniformCache::ClearUniformLocation(const std::string_view& Index)
		{
			UMutex<std::mutex> Unique(Mutex);
			auto IndexIterator = Indices.find(KeyLookupCast(Index));
			if (IndexIterator != Indices.end())
				Indices.erase(IndexIterator);
		}
		void UniformCache::ClearBlockLocation(const std::string_view& Index)
		{
			UMutex<std::mutex> Unique(Mutex);
			auto IndexIterator = Indices.find(KeyLookupCast(Index));
			if (IndexIterator != Indices.end())
				Blocks.erase(IndexIterator->second);
		}
		void UniformCache::SetIndexLocation(const std::string_view& Index, uint64_t IndexLocation)
		{
			auto Size = Protocol::Now().User.Storage.LocationCacheSize;
			String TargetIndex = String(Index);
			UMutex<std::mutex> Unique(Mutex);
			if (Indices.size() >= Size)
				Indices.clear();
			Indices[TargetIndex] = IndexLocation;
		}
		void UniformCache::SetBlockLocation(uint64_t IndexLocation, uint64_t BlockNumber)
		{
			auto Size = Protocol::Now().User.Storage.LocationCacheSize;
			UMutex<std::mutex> Unique(Mutex);
			if (Blocks.size() >= Size)
				Blocks.clear();

			Blocks[IndexLocation] = BlockNumber;
		}
		Option<uint64_t> UniformCache::GetIndexLocation(const std::string_view& Index)
		{
			UMutex<std::mutex> Unique(Mutex);
			auto It = Indices.find(Index);
			if (It == Indices.end())
				return Optional::None;

			return It->second;
		}
		Option<uint64_t> UniformCache::GetBlockLocation(uint64_t IndexLocation)
		{
			UMutex<std::mutex> Unique(Mutex);
			auto It = Blocks.find(IndexLocation);
			if (It == Blocks.end())
				return Optional::None;

			return It->second;
		}

		void MultiformCache::ClearLocations()
		{
			UMutex<std::mutex> Unique(Mutex);
			Columns.clear();
			Rows.clear();
			Blocks.clear();
		}
		void MultiformCache::ClearMultiformLocation(const std::string_view& Column, const std::string_view& Row)
		{
			UMutex<std::mutex> Unique(Mutex);
			auto ColumnIterator = Columns.find(KeyLookupCast(Column));
			if (ColumnIterator != Columns.end())
				Columns.erase(ColumnIterator);

			auto RowIterator = Rows.find(KeyLookupCast(Row));
			if (RowIterator != Rows.end())
				Rows.erase(RowIterator);
		}
		void MultiformCache::ClearBlockLocation(const std::string_view& Column, const std::string_view& Row)
		{
			UMutex<std::mutex> Unique(Mutex);
			auto ColumnLocation = Columns.find(KeyLookupCast(Column));
			auto RowLocation = Rows.find(KeyLookupCast(Row));
			if (ColumnLocation != Columns.end() && RowLocation != Rows.end())
			{
				uint128_t Location;
				memcpy((char*)&Location + sizeof(uint64_t) * 0, &ColumnLocation->second, sizeof(uint64_t));
				memcpy((char*)&Location + sizeof(uint64_t) * 1, &RowLocation->second, sizeof(uint64_t));
				Blocks.erase(Location);
			}
		}
		void MultiformCache::SetMultiformLocation(const std::string_view& Column, const std::string_view& Row, uint64_t ColumnLocation, uint64_t RowLocation)
		{
			auto Size = Protocol::Now().User.Storage.LocationCacheSize;
			String TargetColumn = String(Column);
			String TargetRow = String(Row);
			UMutex<std::mutex> Unique(Mutex);
			if (Columns.size() >= Size)
				Columns.clear();
			if (Rows.size() >= Size)
				Rows.clear();
			Columns[TargetColumn] = ColumnLocation;
			Rows[TargetRow] = RowLocation;
		}
		void MultiformCache::SetColumnLocation(const std::string_view& Column, uint64_t Location)
		{
			auto Size = Protocol::Now().User.Storage.LocationCacheSize;
			String Target = String(Column);
			UMutex<std::mutex> Unique(Mutex);
			if (Columns.size() >= Size)
				Columns.clear();
			Columns[Target] = Location;
		}
		void MultiformCache::SetRowLocation(const std::string_view& Row, uint64_t Location)
		{
			auto Size = Protocol::Now().User.Storage.LocationCacheSize;
			String Target = String(Row);
			UMutex<std::mutex> Unique(Mutex);
			if (Rows.size() >= Size)
				Rows.clear();
			Rows[Target] = Location;
		}
		void MultiformCache::SetBlockLocation(uint64_t ColumnLocation, uint64_t RowLocation, uint64_t BlockNumber)
		{
			auto Size = Protocol::Now().User.Storage.LocationCacheSize;
			UMutex<std::mutex> Unique(Mutex);
			if (Blocks.size() >= Size)
				Blocks.clear();

			uint128_t Location;
			memcpy((char*)&Location + sizeof(uint64_t) * 0, &ColumnLocation, sizeof(uint64_t));
			memcpy((char*)&Location + sizeof(uint64_t) * 1, &RowLocation, sizeof(uint64_t));
			Blocks[Location] = BlockNumber;
		}
		Option<uint64_t> MultiformCache::GetColumnLocation(const std::string_view& Column)
		{
			UMutex<std::mutex> Unique(Mutex);
			auto It = Columns.find(Column);
			if (It == Columns.end())
				return Optional::None;

			return It->second;
		}
		Option<uint64_t> MultiformCache::GetRowLocation(const std::string_view& Row)
		{
			UMutex<std::mutex> Unique(Mutex);
			auto It = Rows.find(Row);
			if (It == Rows.end())
				return Optional::None;

			return It->second;
		}
		Option<uint64_t> MultiformCache::GetBlockLocation(uint64_t ColumnLocation, uint64_t RowLocation)
		{
			uint128_t Location;
			memcpy((char*)&Location + sizeof(uint64_t) * 0, &ColumnLocation, sizeof(uint64_t));
			memcpy((char*)&Location + sizeof(uint64_t) * 1, &RowLocation, sizeof(uint64_t));

			UMutex<std::mutex> Unique(Mutex);
			auto It = Blocks.find(Location);
			if (It == Blocks.end())
				return Optional::None;

			return It->second;
		}

		std::string_view FactorFilter::AsCondition() const
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
		std::string_view FactorFilter::AsOrder() const
		{
			return Order <= 0 ? "DESC" : "ASC";
		}
		FactorFilter FactorFilter::From(const std::string_view& Query, int64_t Value, int8_t Order)
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
		Chainstate::Chainstate(const std::string_view& NewLabel) noexcept : Label(NewLabel), Borrows(LatestChainstate != nullptr)
		{
			if (!Borrows)
			{
				BlobStorageOf("chainblob");
				Blockdata = IndexStorageOf("chainindex", "blockdata");
				Accountdata = IndexStorageOf("chainindex", "accountdata");
				Txdata = IndexStorageOf("chainindex", "txdata");
				Partydata = IndexStorageOf("chainindex", "partydata");
				Aliasdata = IndexStorageOf("chainindex", "aliasdata");
				Uniformdata = IndexStorageOf("chainindex", "uniformdata");
				Multiformdata = IndexStorageOf("chainindex", "multiformdata");
				LatestChainstate = this;
			}
			else
			{
				Blob = LatestChainstate->Blob;
				Blockdata = *LatestChainstate->Blockdata;
				Accountdata = *LatestChainstate->Accountdata;
				Txdata = *LatestChainstate->Txdata;
				Partydata = *LatestChainstate->Partydata;
				Aliasdata = *LatestChainstate->Aliasdata;
				Uniformdata = *LatestChainstate->Uniformdata;
				Multiformdata = *LatestChainstate->Multiformdata;
			}
		}
		Chainstate::~Chainstate() noexcept
		{
			UnloadIndexOf(std::move(Blockdata), Borrows);
			UnloadIndexOf(std::move(Accountdata), Borrows);
			UnloadIndexOf(std::move(Txdata), Borrows);
			UnloadIndexOf(std::move(Partydata), Borrows);
			UnloadIndexOf(std::move(Aliasdata), Borrows);
			UnloadIndexOf(std::move(Uniformdata), Borrows);
			UnloadIndexOf(std::move(Multiformdata), Borrows);
			if (LatestChainstate == this)
				LatestChainstate = nullptr;
		}
		ExpectsLR<void> Chainstate::Reorganize(int64_t* Blocktrie, int64_t* Transactiontrie, int64_t* Statetrie)
		{
			auto Cursor = Query(*Uniformdata, Label, __func__,
				"DELETE FROM uniformtries;"
				"DELETE FROM uniforms;"
				"DELETE FROM indices;");
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			Cursor = Query(*Multiformdata, Label, __func__,
				"DELETE FROM multiformtries;"
				"DELETE FROM multiforms;"
				"DELETE FROM columns;"
				"DELETE FROM rows;");
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			uint64_t CurrentNumber = 1;
			uint64_t CheckpointNumber = GetCheckpointBlockNumber().Or(0);
			uint64_t TipNumber = GetLatestBlockNumber().Or(0);
			auto ParentBlock = ExpectsLR<Ledger::BlockHeader>(LayerException());
			while (CurrentNumber <= TipNumber)
			{
				auto CandidateBlock = GetBlockByNumber(CurrentNumber);
				if (!CandidateBlock)
					return LayerException("block " + ToString(CurrentNumber) + (CheckpointNumber >= CurrentNumber ? " reorganization failed: block data pruned" : " reorganization failed: block not found"));
				else if (CurrentNumber > 1 && CheckpointNumber >= CurrentNumber - 1 && !ParentBlock)
					return LayerException("block " + ToString(CurrentNumber - 1) + " reorganization failed: parent block data pruned");

				Ledger::Block EvaluatedBlock;
				auto Validation = CandidateBlock->Validate(ParentBlock.Address(), &EvaluatedBlock);
				if (!Validation)
					return LayerException("block " + ToString(CurrentNumber) + " validation failed: " + Validation.Error().message());

				auto Finalization = Checkpoint(EvaluatedBlock, true);
				if (!Finalization)
					return LayerException("block " + ToString(CurrentNumber) + " finalization failed: " + Finalization.Error().message());

				if (Protocol::Now().User.Storage.Logging)
					VI_INFO("[chainstate] reorganization checkpoint at block number %" PRIu64 " (statetrie: +%i)", CurrentNumber, EvaluatedBlock.StateCount);

				ParentBlock = EvaluatedBlock;
				++CurrentNumber;
				if (Blocktrie != nullptr)
					++(*Blocktrie);
				if (Transactiontrie != nullptr)
					*Transactiontrie += EvaluatedBlock.TransactionCount;
				if (Statetrie != nullptr)
					*Statetrie += EvaluatedBlock.StateCount;
			}

			return Expectation::Met;
		}
		ExpectsLR<void> Chainstate::Revert(uint64_t BlockNumber, int64_t* Blocktrie, int64_t* Transactiontrie, int64_t* Statetrie)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(BlockNumber));

			auto Cursor = EmplaceQuery(*Blockdata, Label, __func__,
				"DELETE FROM blocks WHERE block_number > ? RETURNING block_hash;"
				"DELETE FROM checkpoints WHERE block_number > ?;", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			auto Response = Cursor->First();
			Parallel::WailAll(ParallelForEachNode(Response.begin(), Response.end(), Response.Size(), [&](LDB::Row Row)
			{
				auto BlockHash = Row["block_hash"].Get();
				Store(Label, __func__, GetBlockLabel(BlockHash.GetBinary()), std::string_view());
			}));
			if (Blocktrie != nullptr)
				*Blocktrie -= Response.Size();

			Map.clear();
			Map.push_back(Var::Set::Integer(BlockNumber));

			Cursor = EmplaceQuery(*Txdata, Label, __func__, "DELETE FROM transactions WHERE block_number > ? RETURNING transaction_hash", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			Response = Cursor->First();
			Parallel::WailAll(ParallelForEachNode(Response.begin(), Response.end(), Response.Size(), [&](LDB::Row Row)
			{
				auto TransactionHash = Row["transaction_hash"].Get();
				Store(Label, __func__, GetTransactionLabel(TransactionHash.GetBinary()), std::string_view());
				Store(Label, __func__, GetReceiptLabel(TransactionHash.GetBinary()), std::string_view());
			}));
			if (Transactiontrie != nullptr)
				*Transactiontrie -= Response.Size();

			Map.clear();
			Map.push_back(Var::Set::Integer(BlockNumber));

			Cursor = EmplaceQuery(*Accountdata, Label, __func__, "DELETE FROM accounts WHERE block_number > ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			Cursor = EmplaceQuery(*Partydata, Label, __func__, "DELETE FROM parties WHERE block_number > ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			Cursor = EmplaceQuery(*Aliasdata, Label, __func__, "DELETE FROM aliases WHERE block_number > ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			Map.clear();
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(BlockNumber));

			Cursor = EmplaceQuery(*Uniformdata, Label, __func__,
				"DELETE FROM uniformtries WHERE block_number > ?;"
				"INSERT OR REPLACE INTO uniforms (index_number, block_number) SELECT index_number, MAX(block_number) FROM uniformtries WHERE block_number <= ? GROUP BY index_number;"
				"DELETE FROM indices WHERE block_number > ?;", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			Map.clear();
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(BlockNumber));

			Cursor = EmplaceQuery(*Multiformdata, Label, __func__,
				"DELETE FROM multiformtries WHERE block_number > ?;"
				"INSERT OR REPLACE INTO multiforms (column_number, row_number, factor, block_number) SELECT column_number, row_number, factor, MAX(block_number) FROM multiformtries WHERE block_number <= ? GROUP BY column_number, row_number;"
				"DELETE FROM columns WHERE block_number > ?;"
				"DELETE FROM rows WHERE block_number > ?;", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			AccountCache::Get()->ClearLocations();
			UniformCache::Get()->ClearLocations();
			MultiformCache::Get()->ClearLocations();

			auto CheckpointNumber = GetCheckpointBlockNumber();
			if (CheckpointNumber && *CheckpointNumber > BlockNumber)
				return Reorganize(Blocktrie, Transactiontrie, Statetrie);

			return Expectation::Met;
		}
		ExpectsLR<void> Chainstate::Dispatch(const Vector<uint256_t>& FinalizedTransactionHashes, const Vector<uint256_t>& RepeatedTransactionHashes)
		{
			UnorderedSet<uint256_t> Exclusion;
			Exclusion.reserve(RepeatedTransactionHashes.size());
			for (auto& Hash : RepeatedTransactionHashes)
				Exclusion.insert(Hash);

			if (!FinalizedTransactionHashes.empty())
			{
				UPtr<Schema> Hashes = Var::Set::Array();
				for (auto& Item : FinalizedTransactionHashes)
				{
					if (Exclusion.find(Item) != Exclusion.end())
						continue;

					uint8_t Hash[32];
					Algorithm::Encoding::DecodeUint256(Item, Hash);
					Hashes->Push(Var::Binary(Hash, sizeof(Hash)));
				}

				if (!Hashes->Empty())
				{
					SchemaList Map;
					Map.push_back(Var::Set::String(*LDB::Utils::InlineArray(std::move(Hashes))));

					auto Cursor = EmplaceQuery(*Txdata, Label, __func__, "UPDATE transactions SET dispatch_queue = NULL WHERE transaction_hash IN ($?)", &Map);
					if (!Cursor || Cursor->Error())
						return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));
				}
			}

			if (!RepeatedTransactionHashes.empty())
			{
				UPtr<Schema> Hashes = Var::Set::Array();
				for (auto& Item : RepeatedTransactionHashes)
				{
					uint8_t Hash[32];
					Algorithm::Encoding::DecodeUint256(Item, Hash);
					Hashes->Push(Var::Binary(Hash, sizeof(Hash)));
				}

				SchemaList Map;
				Map.push_back(Var::Set::Integer(std::max<uint64_t>(1, (1000 * Protocol::Now().User.Storage.TransactionDispatchRepeatInterval / Protocol::Now().Policy.ConsensusProofTime))));
				Map.push_back(Var::Set::String(*LDB::Utils::InlineArray(std::move(Hashes))));

				auto Cursor = EmplaceQuery(*Txdata, Label, __func__, "UPDATE transactions SET dispatch_queue = dispatch_queue + ? WHERE transaction_hash IN ($?)", &Map);
				if (!Cursor || Cursor->Error())
					return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));
			}

			return Expectation::Met;
		}
		ExpectsLR<void> Chainstate::Prune(uint32_t Types, uint64_t BlockNumber)
		{
			size_t Blocktrie = 0;
			if (Types & (uint32_t)Pruning::Blocktrie)
			{
				size_t Offset = 0, Count = 1024;
				SchemaList Map;
				Map.push_back(Var::Set::Integer(BlockNumber));
				Map.push_back(Var::Set::Integer(Count));
				Map.push_back(Var::Set::Integer(Offset = 0));

				while (true)
				{
					Map.back()->Value = Var::Integer(Offset);

					auto Cursor = EmplaceQuery(*Blockdata, Label, __func__, "SELECT block_hash FROM blocks WHERE block_number < ? LIMIT ? OFFSET ?", &Map);
					if (!Cursor || Cursor->Error())
						return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

					auto Response = Cursor->First();
					Parallel::WailAll(ParallelForEachNode(Response.begin(), Response.end(), Response.Size(), [&](LDB::Row Row)
					{
						auto BlockHash = Row["block_hash"].Get();
						Store(Label, __func__, GetBlockLabel(BlockHash.GetBinary()), std::string_view());
					}));

					size_t Results = Cursor->First().Size();
					Offset += Results;
					Blocktrie += Results;
					if (Results < Count)
						break;
				}

				auto Cursor = EmplaceQuery(*Blockdata, Label, __func__, "DELETE FROM blocks WHERE block_number < ?", &Map);
				if (!Cursor || Cursor->Error())
					return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));
			}

			size_t Transactiontrie = 0;
			if (Types & (uint32_t)Pruning::Transactiontrie)
			{
				size_t Offset = 0, Count = 1024;
				SchemaList Map;
				Map.push_back(Var::Set::Integer(BlockNumber));
				Map.push_back(Var::Set::Integer(Count));
				Map.push_back(Var::Set::Integer(Offset));

				while (true)
				{
					Map.back()->Value = Var::Integer(Offset);

					auto Cursor = EmplaceQuery(*Txdata, Label, __func__, "SELECT transaction_hash FROM transactions WHERE block_number < ? LIMIT ? OFFSET ?", &Map);
					if (!Cursor || Cursor->Error())
						return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

					auto Response = Cursor->First();
					Parallel::WailAll(ParallelForEachNode(Response.begin(), Response.end(), Response.Size(), [&](LDB::Row Row)
					{
						auto TransactionHash = Row["transaction_hash"].Get();
						Store(Label, __func__, GetTransactionLabel(TransactionHash.GetBinary()), std::string_view());
						Store(Label, __func__, GetReceiptLabel(TransactionHash.GetBinary()), std::string_view());
					}));

					size_t Results = Cursor->First().Size();
					Offset += Results;
					Transactiontrie += Results;
					if (Results < Count)
						break;
				}

				auto Cursor = EmplaceQuery(*Txdata, Label, __func__, "DELETE FROM transactions WHERE block_number < ?", &Map);
				if (!Cursor || Cursor->Error())
					return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));
			}

			size_t Statetrie = 0;
			if (Types & (uint32_t)Pruning::Statetrie)
			{
				size_t Offset = 0, Count = 1024;
				SchemaList Map;
				Map.push_back(Var::Set::Integer(BlockNumber));
				Map.push_back(Var::Set::Integer(Count));
				Map.push_back(Var::Set::Integer(Offset));

				while (true)
				{
					Map.back()->Value = Var::Integer(Offset);

					auto Cursor = EmplaceQuery(*Uniformdata, Label, __func__,
						"SELECT"
						" (COALESCE((SELECT TRUE FROM uniforms WHERE uniforms.index_number = uniformtries.index_number AND uniforms.block_number = uniformtries.block_number), FALSE)) AS latest,"
						" (SELECT index_hash FROM indices WHERE indices.index_number = uniformtries.index_number) AS index_hash,"
						" block_number "
						"FROM uniformtries WHERE block_number < ? LIMIT ? OFFSET ?", &Map);
					if (!Cursor || Cursor->Error())
						return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

					std::atomic<size_t> Skips = 0;
					auto Response = Cursor->First();
					Parallel::WailAll(ParallelForEachNode(Response.begin(), Response.end(), Response.Size(), [&](LDB::Row Row)
					{
						bool Latest = Row["latest"].Get().GetBoolean();
						if (Latest)
						{
							++Skips;
							return;
						}

						String Index = Row["index_hash"].Get().GetBlob();
						uint64_t Number = Row["block_number"].Get().GetInteger();
						Store(Label, __func__, GetUniformLabel(Index, Number), std::string_view());
					}));

					size_t Results = Cursor->First().Size();
					Offset += Results;
					Statetrie += Results - Skips;
					if (Results < Count)
						break;
				}

				auto Cursor = EmplaceQuery(*Uniformdata, Label, __func__, "DELETE FROM uniformtries WHERE block_number < ?", &Map);
				if (!Cursor || Cursor->Error())
					return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

				Map.back()->Value = Var::Integer(Offset = 0);
				while (true)
				{
					Map.back()->Value = Var::Integer(Offset);

					auto Cursor = EmplaceQuery(*Multiformdata, Label, __func__,
						"SELECT"
						" (COALESCE((SELECT TRUE FROM multiforms WHERE multiforms.column_number = multiformtries.column_number AND multiforms.row_number = multiformtries.row_number AND multiforms.block_number = multiformtries.block_number), FALSE)) AS latest,"
						" (SELECT column_hash FROM columns WHERE columns.column_number = multiformtries.column_number) AS column_hash,"
						" (SELECT row_hash FROM rows WHERE rows.row_number = multiformtries.row_number) AS row_hash,"
						" block_number "
						"FROM multiformtries WHERE block_number < ? LIMIT ? OFFSET ?", &Map);
					if (!Cursor || Cursor->Error())
						return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

					std::atomic<size_t> Skips = 0;
					auto Response = Cursor->First();
					Parallel::WailAll(ParallelForEachNode(Response.begin(), Response.end(), Response.Size(), [&](LDB::Row Next)
					{
						bool Latest = Next["latest"].Get().GetBoolean();
						if (Latest)
						{
							++Skips;
							return;
						}

						String Column = Next["column_hash"].Get().GetBlob();
						String Row = Next["row_hash"].Get().GetBlob();
						uint64_t Number = Next["block_number"].Get().GetInteger();
						Store(Label, __func__, GetMultiformLabel(Column, Row, Number), std::string_view());
					}));

					size_t Results = Cursor->First().Size();
					Offset += Results;
					Statetrie += Results - Skips;
					if (Results < Count)
						break;
				}

				Cursor = EmplaceQuery(*Multiformdata, Label, __func__, "DELETE FROM multiformtries WHERE block_number < ?", &Map);
				if (!Cursor || Cursor->Error())
					return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));
			}

			SchemaList Map;
			Map.push_back(Var::Set::Integer(BlockNumber));

			auto Cursor = EmplaceQuery(*Blockdata, Label, __func__, "INSERT OR IGNORE INTO checkpoints (block_number) VALUES (?)", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			if (Protocol::Now().User.Storage.Logging)
				VI_INFO("[chainstate] pruning checkpoint at block number %" PRIu64 " (blocktrie: -%" PRIu64 ", transactiontrie: -%" PRIu64 ", statetrie: -%" PRIu64 ")", BlockNumber, (uint64_t)Blocktrie, (uint64_t)Transactiontrie, (uint64_t)Statetrie);

			return Expectation::Met;
		}
		ExpectsLR<void> Chainstate::Checkpoint(const Ledger::Block& Value, bool Reorganization)
		{
			if (!Reorganization)
			{
				Format::Stream BlockHeaderMessage;
				if (!Value.AsHeader().Store(&BlockHeaderMessage))
					return ExpectsLR<void>(LayerException("block header serialization error"));

				uint8_t Hash[32];
				Algorithm::Encoding::DecodeUint256(Value.AsHash(), Hash);

				auto Status = Store(Label, __func__, GetBlockLabel(Hash), BlockHeaderMessage.Data);
				if (!Status)
					return ExpectsLR<void>(LayerException(ErrorOf(Status)));

				SchemaList Map;
				Map.push_back(Var::Set::Integer(Value.Number));
				Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));

				auto Cursor = EmplaceQuery(*Blockdata, Label, __func__, "INSERT INTO blocks (block_number, block_hash) VALUES (?, ?)", &Map);
				if (!Cursor || Cursor->Error())
					return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));
			}

			auto CommitTransactionData = Reorganization ? LDB::ExpectsDB<LDB::TStatement*>(nullptr) : Txdata->PrepareStatement("INSERT INTO transactions (transaction_number, transaction_hash, dispatch_queue, block_number, block_nonce) VALUES (?, ?, ?, ?, ?)", nullptr);
			if (!CommitTransactionData)
				return ExpectsLR<void>(LayerException(std::move(CommitTransactionData.Error().message())));

			auto CommitAccountData = Reorganization ? LDB::ExpectsDB<LDB::TStatement*>(nullptr) : Accountdata->PrepareStatement("INSERT OR IGNORE INTO accounts (account_number, account_hash, block_number) SELECT (SELECT COALESCE(MAX(account_number), 0) + 1 FROM accounts), ?, ? ON CONFLICT DO UPDATE SET block_number = block_number RETURNING account_number", nullptr);
			if (!CommitAccountData)
				return ExpectsLR<void>(LayerException(std::move(CommitAccountData.Error().message())));

			auto CommitPartyData = Reorganization ? LDB::ExpectsDB<LDB::TStatement*>(nullptr) : Partydata->PrepareStatement("INSERT OR IGNORE INTO parties (transaction_number, transaction_account_number, block_number) VALUES (?, ?, ?)", nullptr);
			if (!CommitPartyData)
				return ExpectsLR<void>(LayerException(std::move(CommitPartyData.Error().message())));

			auto CommitAliasData = Reorganization ? LDB::ExpectsDB<LDB::TStatement*>(nullptr) : Aliasdata->PrepareStatement("INSERT INTO aliases (transaction_number, transaction_hash, block_number) VALUES (?, ?, ?)", nullptr);
			if (!CommitAliasData)
				return ExpectsLR<void>(LayerException(std::move(CommitAliasData.Error().message())));

			auto CommitUniformIndexData = Uniformdata->PrepareStatement("INSERT OR IGNORE INTO indices (index_number, index_hash, block_number) SELECT (SELECT COALESCE(MAX(index_number), 0) + 1 FROM indices), ?, ? ON CONFLICT DO UPDATE SET block_number = block_number RETURNING index_number", nullptr);
			if (!CommitUniformIndexData)
				return ExpectsLR<void>(LayerException(std::move(CommitUniformIndexData.Error().message())));

			auto CommitUniformData = Uniformdata->PrepareStatement("INSERT OR REPLACE INTO uniforms (index_number, block_number) VALUES (?, ?)", nullptr);
			if (!CommitUniformData)
				return ExpectsLR<void>(LayerException(std::move(CommitUniformData.Error().message())));

			auto CommitUniformtrieData = Uniformdata->PrepareStatement("INSERT OR REPLACE INTO uniformtries (index_number, block_number) VALUES (?, ?)", nullptr);
			if (!CommitUniformtrieData)
				return ExpectsLR<void>(LayerException(std::move(CommitUniformtrieData.Error().message())));

			auto CommitMultiformColumnData = Multiformdata->PrepareStatement("INSERT OR IGNORE INTO columns (column_number, column_hash, block_number) SELECT (SELECT COALESCE(MAX(column_number), 0) + 1 FROM columns), ?, ? ON CONFLICT DO UPDATE SET block_number = block_number RETURNING column_number", nullptr);
			if (!CommitMultiformColumnData)
				return ExpectsLR<void>(LayerException(std::move(CommitMultiformColumnData.Error().message())));

			auto CommitMultiformRowData = Multiformdata->PrepareStatement("INSERT OR IGNORE INTO rows (row_number, row_hash, block_number) SELECT (SELECT COALESCE(MAX(row_number), 0) + 1 FROM rows), ?, ? ON CONFLICT DO UPDATE SET block_number = block_number RETURNING row_number", nullptr);
			if (!CommitMultiformRowData)
				return ExpectsLR<void>(LayerException(std::move(CommitMultiformRowData.Error().message())));

			auto CommitMultiformData = Multiformdata->PrepareStatement("INSERT OR REPLACE INTO multiforms (column_number, row_number, block_number, factor) VALUES (?, ?, ?, ?)", nullptr);
			if (!CommitMultiformData)
				return ExpectsLR<void>(LayerException(std::move(CommitMultiformData.Error().message())));

			auto CommitMultiformtrieData = Multiformdata->PrepareStatement("INSERT OR REPLACE INTO multiformtries (column_number, row_number, block_number, factor) VALUES (?, ?, ?, ?)", nullptr);
			if (!CommitMultiformtrieData)
				return ExpectsLR<void>(LayerException(std::move(CommitMultiformtrieData.Error().message())));

			auto& States = Value.States.At(Ledger::WorkCommitment::Finalized);
			auto State = States.begin();
			Vector<UniformBlob> Uniforms;
			Vector<MultiformBlob> Multiforms;
			Uniforms.reserve(States.size());
			Multiforms.reserve(States.size());
			for (size_t i = 0; i < States.size(); i++, State++)
			{
				switch (State->second->AsLevel())
				{
					case Ledger::StateLevel::Uniform:
					{
						UniformBlob Blob;
						Blob.Context = (Ledger::Uniform*)*State->second;
						Uniforms.emplace_back(std::move(Blob));
						break;
					}
					case Ledger::StateLevel::Multiform:
					{
						MultiformBlob Blob;
						Blob.Context = (Ledger::Multiform*)*State->second;
						Multiforms.emplace_back(std::move(Blob));
						break;
					}
					default:
						return ExpectsLR<void>(LayerException("state level is not valid"));
				}
			}

			Vector<Promise<void>> Queue1;
			Vector<TransactionBlob> Transactions;
			bool TransactionToAccountIndex = Protocol::Now().User.Storage.TransactionToAccountIndex;
			bool TransactionToRollupIndex = Protocol::Now().User.Storage.TransactionToRollupIndex;
			if (!Reorganization)
			{
				auto Cursor = Query(*Txdata, Label, __func__, "SELECT MAX(transaction_number) AS counter FROM transactions");
				if (!Cursor || Cursor->ErrorOrEmpty())
					return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

				uint64_t TransactionNonce = (*Cursor)["counter"].Get().GetInteger();
				Transactions.resize(Value.Transactions.size());
				for (size_t i = 0; i < Transactions.size(); i++)
				{
					TransactionBlob& Blob = Transactions[i];
					Blob.TransactionNumber = ++TransactionNonce;
					Blob.BlockNonce = (uint64_t)i;
					Blob.Context = &Value.Transactions[i];
				}
				Queue1 = ParallelForEach(Transactions.begin(), Transactions.end(), [&](TransactionBlob& Item)
				{
					Item.ReceiptMessage.Data.reserve(1024);
					Item.Context->Transaction->Store(&Item.TransactionMessage);
					Item.Context->Receipt.Store(&Item.ReceiptMessage);
					Item.DispatchNumber = Item.Context->Transaction->GetDispatchOffset();
					Algorithm::Encoding::DecodeUint256(Item.Context->Receipt.TransactionHash, Item.TransactionHash);
					if (TransactionToAccountIndex)
					{
						OrderedSet<String> Output;
						Item.Context->Transaction->RecoverMany(Item.Context->Receipt, Output);
						Item.Parties.reserve(Item.Parties.size() + Output.size() + 1);

						TransactionPartyBlob Party;
						memcpy(Party.Owner, Item.Context->Receipt.From, sizeof(Party.Owner));
						Item.Parties.push_back(Party);

						for (auto& Owner : Output)
						{
							memcpy(Party.Owner, Owner.data(), std::min(Owner.size(), sizeof(Algorithm::Pubkeyhash)));
							Item.Parties.push_back(Party);
						}
					}
					if (TransactionToRollupIndex)
					{
						OrderedSet<uint256_t> Aliases;
						Item.Context->Transaction->RecoverAliases(Item.Context->Receipt, Aliases);
						Item.Aliases.reserve(Aliases.size());

						TransactionAliasBlob Alias;
						for (auto& Hash : Aliases)
						{
							Algorithm::Encoding::DecodeUint256(Hash, Alias.TransactionHash);
							Item.Aliases.push_back(Alias);
						}
					}
				});
			}

			auto Queue2 = ParallelForEach(Uniforms.begin(), Uniforms.end(), [&](UniformBlob& Item)
			{
				Item.Index = Item.Context->AsIndex();
				Item.Context->Store(&Item.Message);
			});
			auto Queue3 = ParallelForEach(Multiforms.begin(), Multiforms.end(), [&](MultiformBlob& Item)
			{
				Item.Column = Item.Context->AsColumn();
				Item.Row = Item.Context->AsRow();
				Item.Factor = Item.Context->AsFactor();
				Item.Context->Store(&Item.Message);
			});
			Parallel::WailAll(std::move(Queue1));
			Parallel::WailAll(std::move(Queue2));
			Parallel::WailAll(std::move(Queue3));

			if (!Reorganization)
			{
				auto* CacheA = AccountCache::Get();
				for (auto& Data : Transactions)
				{
					for (auto& Party : Data.Parties)
						CacheA->ClearAccountLocation(Party.Owner);
				}
			}

			auto* CacheU = UniformCache::Get();
			for (auto& Item : Uniforms)
				CacheU->ClearBlockLocation(Item.Index);

			for (auto& Item : Uniforms)
				CacheU->ClearUniformLocation(Item.Index);

			auto* CacheM = MultiformCache::Get();
			for (auto& Item : Multiforms)
				CacheM->ClearBlockLocation(Item.Column, Item.Row);

			for (auto& Item : Multiforms)
				CacheM->ClearMultiformLocation(Item.Column, Item.Row);

			Vector<Promise<ExpectsLR<void>>> Queue4;
			Queue4.emplace_back(Cotask<ExpectsLR<void>>([&]() -> ExpectsLR<void>
			{
				LDB::ExpectsDB<LDB::Cursor> Cursor = LDB::DatabaseException(String());
				for (auto& Item : Uniforms)
				{
					auto* Statement = *CommitUniformIndexData;
					Uniformdata->BindBlob(Statement, 0, Item.Index);
					Uniformdata->BindInt64(Statement, 1, Value.Number);

					Cursor = PreparedQuery(*Uniformdata, Label, __func__, Statement);
					if (!Cursor || Cursor->ErrorOrEmpty())
						return LayerException(Cursor->Empty() ? "uniform index not linked" : ErrorOf(Cursor));

					uint64_t IndexNumber = Cursor->First().Front().GetColumn(0).Get().GetInteger();
					Statement = *CommitUniformData;
					Uniformdata->BindInt64(Statement, 0, IndexNumber);
					Uniformdata->BindInt64(Statement, 1, Value.Number);

					Cursor = PreparedQuery(*Uniformdata, Label, __func__, Statement);
					if (!Cursor || Cursor->Error())
						return LayerException(ErrorOf(Cursor));

					Statement = *CommitUniformtrieData;
					Uniformdata->BindInt64(Statement, 0, IndexNumber);
					Uniformdata->BindInt64(Statement, 1, Value.Number);

					Cursor = PreparedQuery(*Uniformdata, Label, __func__, Statement);
					if (!Cursor || Cursor->Error())
						return LayerException(ErrorOf(Cursor));
				}
				return Expectation::Met;
			}, false));
			Queue4.emplace_back(Cotask<ExpectsLR<void>>([&]() -> ExpectsLR<void>
			{
				LDB::ExpectsDB<LDB::Cursor> Cursor = LDB::DatabaseException(String());
				for (auto& Item : Multiforms)
				{
					auto* Multiformment = *CommitMultiformColumnData;
					Multiformdata->BindBlob(Multiformment, 0, Item.Column);
					Multiformdata->BindInt64(Multiformment, 1, Value.Number);

					Cursor = PreparedQuery(*Multiformdata, Label, __func__, Multiformment);
					if (!Cursor || Cursor->ErrorOrEmpty())
						return LayerException(Cursor->Empty() ? "multiform column not linked" : ErrorOf(Cursor));

					Multiformment = *CommitMultiformRowData;
					Multiformdata->BindBlob(Multiformment, 0, Item.Row);
					Multiformdata->BindInt64(Multiformment, 1, Value.Number);

					uint64_t ColumnNumber = Cursor->First().Front().GetColumn(0).Get().GetInteger();
					Cursor = PreparedQuery(*Multiformdata, Label, __func__, Multiformment);
					if (!Cursor || Cursor->ErrorOrEmpty())
						return LayerException(Cursor->Empty() ? "multiform row not linked" : ErrorOf(Cursor));

					uint64_t RowNumber = Cursor->First().Front().GetColumn(0).Get().GetInteger();
					Multiformment = *CommitMultiformData;
					Multiformdata->BindInt64(Multiformment, 0, ColumnNumber);
					Multiformdata->BindInt64(Multiformment, 1, RowNumber);
					Multiformdata->BindInt64(Multiformment, 2, Value.Number);
					Multiformdata->BindInt64(Multiformment, 3, Item.Factor);

					Cursor = PreparedQuery(*Multiformdata, Label, __func__, Multiformment);
					if (!Cursor || Cursor->Error())
						return LayerException(ErrorOf(Cursor));

					Multiformment = *CommitMultiformtrieData;
					Multiformdata->BindInt64(Multiformment, 0, ColumnNumber);
					Multiformdata->BindInt64(Multiformment, 1, RowNumber);
					Multiformdata->BindInt64(Multiformment, 2, Value.Number);
					Multiformdata->BindInt64(Multiformment, 3, Item.Factor);

					Cursor = PreparedQuery(*Multiformdata, Label, __func__, Multiformment);
					if (!Cursor || Cursor->Error())
						return LayerException(ErrorOf(Cursor));
				}
				return Expectation::Met;
			}, false));
			Queue4.emplace_back(Cotask<ExpectsLR<void>>([&]() -> ExpectsLR<void>
			{
				LDB::ExpectsDB<void> Status = Expectation::Met;
				for (auto& Item : Uniforms)
				{
					Status = Store(Label, __func__, GetUniformLabel(Item.Index, Value.Number), Item.Message.Data);
					if (!Status)
						return LayerException(ErrorOf(Status));
				}
				return Expectation::Met;
			}, false));
			Queue4.emplace_back(Cotask<ExpectsLR<void>>([&]() -> ExpectsLR<void>
			{
				LDB::ExpectsDB<void> Status = Expectation::Met;
				for (auto& Item : Multiforms)
				{
					Status = Store(Label, __func__, GetMultiformLabel(Item.Column, Item.Row, Value.Number), Item.Message.Data);
					if (!Status)
						return LayerException(ErrorOf(Status));
				}
				return Expectation::Met;
			}, false));
			if (!Reorganization)
			{
				Queue4.emplace_back(Cotask<ExpectsLR<void>>([&]() -> ExpectsLR<void>
				{
					auto* Statement = *CommitTransactionData;
					LDB::ExpectsDB<LDB::Cursor> Cursor = LDB::DatabaseException(String());
					for (auto& Data : Transactions)
					{
						Txdata->BindInt64(Statement, 0, Data.TransactionNumber);
						Txdata->BindBlob(Statement, 1, std::string_view((char*)Data.TransactionHash, sizeof(Data.TransactionHash)));
						if (Data.DispatchNumber > 0)
							Txdata->BindInt64(Statement, 2, Value.Number + (Data.DispatchNumber - 1));
						else
							Txdata->BindNull(Statement, 2);
						Txdata->BindInt64(Statement, 3, Value.Number);
						Txdata->BindInt64(Statement, 4, Data.BlockNonce);

						Cursor = PreparedQuery(*Txdata, Label, __func__, Statement);
						if (!Cursor || Cursor->Error())
							return LayerException(ErrorOf(Cursor));
					}
					return Expectation::Met;
				}, false));
				Queue4.emplace_back(Cotask<ExpectsLR<void>>([&]() -> ExpectsLR<void>
				{
					LDB::ExpectsDB<void> Status = Expectation::Met;
					for (auto& Data : Transactions)
					{
						Status = Store(Label, __func__, GetTransactionLabel(Data.TransactionHash), Data.TransactionMessage.Data);
						if (!Status)
							return LayerException(ErrorOf(Status));

						Status = Store(Label, __func__, GetReceiptLabel(Data.TransactionHash), Data.ReceiptMessage.Data);
						if (!Status)
							return LayerException(ErrorOf(Status));
					}
					return Expectation::Met;
				}, false));
				if (TransactionToAccountIndex)
				{
					Queue4.emplace_back(Cotask<ExpectsLR<void>>([&]() -> ExpectsLR<void>
					{
						LDB::ExpectsDB<LDB::Cursor> Cursor = LDB::DatabaseException(String());
						for (auto& Data : Transactions)
						{
							for (auto& Party : Data.Parties)
							{
								auto* Statement = *CommitAccountData;
								Accountdata->BindBlob(Statement, 0, std::string_view((char*)Party.Owner, sizeof(Party.Owner)));
								Accountdata->BindInt64(Statement, 1, Value.Number);

								Cursor = PreparedQuery(*Accountdata, Label, __func__, Statement);
								if (!Cursor || Cursor->ErrorOrEmpty())
									return LayerException(Cursor->Empty() ? "account not linked" : ErrorOf(Cursor));

								uint64_t AccountNumber = Cursor->First().Front().GetColumn(0).Get().GetInteger();
								Statement = *CommitPartyData;
								Partydata->BindInt64(Statement, 0, Data.TransactionNumber);
								Partydata->BindInt64(Statement, 1, AccountNumber);
								Partydata->BindInt64(Statement, 2, Value.Number);

								Cursor = PreparedQuery(*Partydata, Label, __func__, Statement);
								if (!Cursor || Cursor->Error())
									return LayerException(ErrorOf(Cursor));
							}
						}
						return Expectation::Met;
					}, false));
				}
				if (TransactionToRollupIndex)
				{
					Queue4.emplace_back(Cotask<ExpectsLR<void>>([&]() -> ExpectsLR<void>
					{
						auto* Statement = *CommitAliasData;
						LDB::ExpectsDB<LDB::Cursor> Cursor = LDB::DatabaseException(String());
						for (auto& Data : Transactions)
						{
							for (auto& Alias : Data.Aliases)
							{
								Aliasdata->BindInt64(Statement, 0, Data.TransactionNumber);
								Aliasdata->BindBlob(Statement, 1, std::string_view((char*)Alias.TransactionHash, sizeof(Alias.TransactionHash)));
								Aliasdata->BindInt64(Statement, 2, Value.Number);

								Cursor = PreparedQuery(*Aliasdata, Label, __func__, Statement);
								if (!Cursor || Cursor->Error())
									return LayerException(ErrorOf(Cursor));
							}
						}
						return Expectation::Met;
					}, false));
				}
			}

			for (auto& Status : Parallel::InlineWaitAll(std::move(Queue4)))
			{
				if (!Status)
					return Status;
			}

			auto CheckpointSize = Protocol::Now().User.Storage.CheckpointSize;
			if (!CheckpointSize || Value.Priority > 0)
				return Expectation::Met;

			auto CheckpointNumber = Value.Number - Value.Number % CheckpointSize;
			if (CheckpointNumber < Value.Number)
				return Expectation::Met;

			auto LatestCheckpoint = GetCheckpointBlockNumber().Or(0);
			if (Value.Number <= LatestCheckpoint)
				return Expectation::Met;

			return Prune(Protocol::Now().User.Storage.PruneAggressively ? (uint32_t)Pruning::Blocktrie | (uint32_t)Pruning::Transactiontrie | (uint32_t)Pruning::Statetrie : (uint32_t)Pruning::Statetrie, Value.Number);
		}
		ExpectsLR<size_t> Chainstate::ResolveBlockTransactions(Ledger::Block& Value, bool Fully, size_t Offset, size_t Count)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Integer(Value.Number));
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(*Txdata, Label, __func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<size_t>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Value.Transactions.reserve(Value.Transactions.size() + Size);
			for (size_t i = 0; i < Size; i++)
			{
				auto Row = Response[i];
				auto TransactionHash = Row["transaction_hash"].Get();
				Format::Stream TransactionMessage = Format::Stream(Load(Label, __func__, GetTransactionLabel(TransactionHash.GetBinary())).Or(String()));
				UPtr<Ledger::Transaction> NextTransaction = Transactions::Resolver::New(Messages::Authentic::ResolveType(TransactionMessage).Or(0));
				if (NextTransaction && NextTransaction->Load(TransactionMessage))
				{
					Ledger::Receipt NextReceipt;
					if (Fully)
					{
						Format::Stream ReceiptMessage = Format::Stream(Load(Label, __func__, GetReceiptLabel(TransactionHash.GetBinary())).Or(String()));
						if (NextReceipt.Load(ReceiptMessage))
						{
							FinalizeChecksum(**NextTransaction, TransactionHash);
							Value.Transactions.emplace_back(std::move(NextTransaction), std::move(NextReceipt));
						}
					}
					else
					{
						FinalizeChecksum(**NextTransaction, TransactionHash);
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

			auto Cursor1 = EmplaceQuery(*Uniformdata, Label, __func__, "SELECT (SELECT index_hash FROM indices WHERE indices.index_number = uniformtries.index_number) AS index_hash FROM uniformtries WHERE block_number = ? LIMIT ? OFFSET ?", &Map);
			if (!Cursor1 || Cursor1->Error())
				return ExpectsLR<size_t>(LayerException(ErrorOf(Cursor1)));

			auto Cursor2 = EmplaceQuery(*Multiformdata, Label, __func__, "SELECT (SELECT column_hash FROM columns WHERE columns.column_number = multiformtries.column_number) AS column_hash, (SELECT row_hash FROM rows WHERE rows.row_number = multiformtries.row_number) AS row_hash FROM multiformtries WHERE block_number = ? LIMIT ? OFFSET ?", &Map);
			if (!Cursor2 || Cursor2->Error())
				return ExpectsLR<size_t>(LayerException(ErrorOf(Cursor2)));

			size_t Size1 = 0;
			if (!Cursor1->Empty())
			{
				auto& Response = Cursor1->First();
				Size1 = Response.Size();
				for (size_t i = 0; i < Size1; i++)
				{
					auto Row = Response[i];
					Format::Stream Message = Format::Stream(Load(Label, __func__, GetUniformLabel(Row["index_hash"].Get().GetBlob(), Value.Number)).Or(String()));
					UPtr<Ledger::State> NextState = States::Resolver::New(Messages::Generic::ResolveType(Message).Or(0));
					if (NextState && NextState->Load(Message))
						Value.States.MoveAny(std::move(NextState));
				}
			}

			size_t Size2 = 0;
			if (!Cursor2->Empty())
			{
				auto& Response = Cursor2->First();
				Size2 = Response.Size();
				for (size_t i = 0; i < Size2; i++)
				{
					auto Row = Response[i];
					Format::Stream Message = Format::Stream(Load(Label, __func__, GetMultiformLabel(Row["column_hash"].Get().GetBlob(), Row["row_hash"].Get().GetBlob(), Value.Number)).Or(String()));
					UPtr<Ledger::State> NextState = States::Resolver::New(Messages::Generic::ResolveType(Message).Or(0));
					if (NextState && NextState->Load(Message))
						Value.States.MoveAny(std::move(NextState));
				}
			}

			Value.States.Commit();
			return Size1 + Size2;
		}
		ExpectsLR<Chainstate::UniformLocation> Chainstate::ResolveUniformLocation(const std::string_view& Index, bool Latest)
		{
			auto Cache = UniformCache::Get();
			auto IndexLocation = Cache->GetIndexLocation(Index);
			auto BlockLocation = Latest && IndexLocation ? Cache->GetBlockLocation(*IndexLocation) : Option<uint64_t>(Optional::None);
			if (!IndexLocation)
			{
				auto FindIndex = Uniformdata->PrepareStatement("SELECT index_number FROM indices WHERE index_hash = ?", nullptr);
				if (!FindIndex)
					return ExpectsLR<UniformLocation>(LayerException(std::move(FindIndex.Error().message())));

				Uniformdata->BindBlob(*FindIndex, 0, Index);
				auto Cursor = PreparedQuery(*Uniformdata, Label, __func__, *FindIndex);
				if (!Cursor || Cursor->Error())
					return ExpectsLR<UniformLocation>(LayerException(ErrorOf(Cursor)));

				IndexLocation = (*Cursor)["index_number"].Get().GetInteger();
				Cache->SetIndexLocation(Index, *IndexLocation);
			}

			UniformLocation Location;
			Location.Index = IndexLocation && *IndexLocation > 0 ? std::move(IndexLocation) : Option<uint64_t>(Optional::None);
			Location.Block = BlockLocation && *BlockLocation > 0 ? std::move(BlockLocation) : Option<uint64_t>(Optional::None);
			return Location;
		}
		ExpectsLR<Chainstate::MultiformLocation> Chainstate::ResolveMultiformLocation(const Option<std::string_view>& Column, const Option<std::string_view>& Row, bool Latest)
		{
			VI_ASSERT(Column || Row, "column or row should be set");
			auto Cache = MultiformCache::Get();
			bool UpdateColumn = false, UpdateRow = false;
			auto ColumnLocation = Column ? Cache->GetColumnLocation(*Column) : Option<uint64_t>(Optional::None);
			auto RowLocation = Row ? Cache->GetRowLocation(*Row) : Option<uint64_t>(Optional::None);
			auto BlockLocation = Latest && ColumnLocation && RowLocation ? Cache->GetBlockLocation(*ColumnLocation, *RowLocation) : Option<uint64_t>(Optional::None);
			if (Column && !ColumnLocation)
			{
				auto FindColumn = Multiformdata->PrepareStatement("SELECT column_number FROM columns WHERE column_hash = ?", nullptr);
				if (!FindColumn)
					return ExpectsLR<MultiformLocation>(LayerException(std::move(FindColumn.Error().message())));

				Multiformdata->BindBlob(*FindColumn, 0, *Column);
				auto Cursor = PreparedQuery(*Multiformdata, Label, __func__, *FindColumn);
				if (!Cursor || Cursor->Error())
					return ExpectsLR<MultiformLocation>(LayerException(ErrorOf(Cursor)));

				ColumnLocation = (*Cursor)["column_number"].Get().GetInteger();
				UpdateColumn = true;
			}

			if (Row && !RowLocation)
			{
				auto FindRow = Multiformdata->PrepareStatement("SELECT row_number FROM rows WHERE row_hash = ?", nullptr);
				if (!FindRow)
					return ExpectsLR<MultiformLocation>(LayerException(std::move(FindRow.Error().message())));

				Multiformdata->BindBlob(*FindRow, 0, *Row);
				auto Cursor = PreparedQuery(*Multiformdata, Label, __func__, *FindRow);
				if (!Cursor || Cursor->Error())
					return ExpectsLR<MultiformLocation>(LayerException(ErrorOf(Cursor)));

				RowLocation = (*Cursor)["row_number"].Get().GetInteger();
				UpdateRow = true;
			}

			if (Column && Row)
			{
				if (!ColumnLocation.Or(0) || !RowLocation.Or(0))
					return LayerException("multiform location not found");
				else if (UpdateColumn || UpdateRow)
					Cache->SetMultiformLocation(*Column, *Row, *ColumnLocation, *RowLocation);
			}
			else if (Column)
			{
				if (!ColumnLocation.Or(0))
					return LayerException("multiform column not found");
				else if (UpdateColumn)
					Cache->SetColumnLocation(*Column, *ColumnLocation);
			}
			else if (Row)
			{
				if (!RowLocation.Or(0))
					return LayerException("multiform row not found");
				else if (UpdateRow)
					Cache->SetRowLocation(*Row, *RowLocation);
			}

			MultiformLocation Location;
			Location.Column = ColumnLocation && *ColumnLocation > 0 ? std::move(ColumnLocation) : Option<uint64_t>(Optional::None);
			Location.Row = RowLocation && *RowLocation > 0 ? std::move(RowLocation) : Option<uint64_t>(Optional::None);
			Location.Block = BlockLocation && *BlockLocation > 0 ? std::move(BlockLocation) : Option<uint64_t>(Optional::None);
			return Location;
		}
		ExpectsLR<uint64_t> Chainstate::ResolveAccountLocation(const Algorithm::Pubkeyhash Account)
		{
			VI_ASSERT(Account, "account should be set");
			auto Cache = AccountCache::Get();
			auto AccountNumberCache = Cache->GetAccountLocation(std::string_view((char*)Account, sizeof(Algorithm::Pubkeyhash)));
			if (AccountNumberCache)
			{
				if (!*AccountNumberCache)
					return LayerException("account not found");

				return AccountNumberCache.Or(0);
			}

			auto FindAccount = Accountdata->PrepareStatement("SELECT account_number FROM accounts WHERE account_hash = ?", nullptr);
			if (!FindAccount)
				return ExpectsLR<uint64_t>(LayerException(std::move(FindAccount.Error().message())));

			Accountdata->BindBlob(*FindAccount, 0, std::string_view((char*)Account, sizeof(Algorithm::Pubkeyhash)));
			auto Cursor = PreparedQuery(*Accountdata, Label, __func__, *FindAccount);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<uint64_t>(LayerException(ErrorOf(Cursor)));

			uint64_t AccountNumber = (*Cursor)["account_number"].Get().GetInteger();
			Cache->SetAccountLocation(Account, AccountNumber);
			if (!AccountNumber)
				return LayerException("account not found");

			return AccountNumber;
		}
		ExpectsLR<uint64_t> Chainstate::GetCheckpointBlockNumber()
		{
			auto Cursor = Query(*Blockdata, Label, __func__, "SELECT MAX(block_number) AS block_number FROM checkpoints");
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<uint64_t>(LayerException(ErrorOf(Cursor)));

			return (uint64_t)(*Cursor)["block_number"].Get().GetInteger();
		}
		ExpectsLR<uint64_t> Chainstate::GetLatestBlockNumber()
		{
			auto Cursor = Query(*Blockdata, Label, __func__, "SELECT block_number FROM blocks ORDER BY block_number DESC LIMIT 1");
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

			auto Cursor = EmplaceQuery(*Blockdata, Label, __func__, "SELECT block_number FROM blocks WHERE block_hash = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<uint64_t>(LayerException(ErrorOf(Cursor)));

			return (uint64_t)(*Cursor)["block_number"].Get().GetInteger();
		}
		ExpectsLR<uint256_t> Chainstate::GetBlockHashByNumber(uint64_t BlockNumber)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Integer(BlockNumber));

			auto Cursor = EmplaceQuery(*Blockdata, Label, __func__, "SELECT block_hash FROM blocks WHERE block_number = ?", &Map);
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
			size_t Count = LOAD_RATE;
			while (true)
			{
				SchemaList Map;
				Map.push_back(Var::Set::Integer(BlockNumber));
				Map.push_back(Var::Set::Integer(Count));
				Map.push_back(Var::Set::Integer(Offset));

				auto Cursor = EmplaceQuery(*Txdata, Label, __func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce LIMIT ? OFFSET ?", &Map);
				if (!Cursor || Cursor->Error())
					return ExpectsLR<Decimal>(LayerException(ErrorOf(Cursor)));

				auto& Response = Cursor->First();
				size_t Size = Response.Size();
				for (size_t i = 0; i < Size; i++)
				{
					auto Row = Response[i];
					auto TransactionHash = Row["transaction_hash"].Get();
					Format::Stream Message = Format::Stream(Load(Label, __func__, GetTransactionLabel(TransactionHash.GetBinary())).Or(String()));
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
		ExpectsLR<Ledger::Block> Chainstate::GetBlockByNumber(uint64_t BlockNumber, size_t Chunk, uint32_t Details)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Integer(BlockNumber));

			auto Cursor = EmplaceQuery(*Blockdata, Label, __func__, "SELECT block_hash FROM blocks WHERE block_number = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Ledger::Block>(LayerException(ErrorOf(Cursor)));

			Ledger::BlockHeader Header;
			auto BlockHash = (*Cursor)["block_hash"].Get();
			Format::Stream Message = Format::Stream(Load(Label, __func__, GetBlockLabel(BlockHash.GetBinary())).Or(String()));
			if (!Header.Load(Message))
				return ExpectsLR<Ledger::Block>(LayerException("block header deserialization error"));

			Ledger::Block Result = Ledger::Block(Header);
			size_t Offset = 0;
			while ((Details & (uint32_t)BlockDetails::Transactions || Details & (uint32_t)BlockDetails::BlockTransactions) && Chunk > 0)
			{
				auto Size = ResolveBlockTransactions(Result, Details & (uint32_t)BlockDetails::BlockTransactions, Offset, Chunk);
				if (!Size)
					return Size.Error();

				Offset += *Size;
				if (*Size < Chunk)
					break;
			}

			Offset = 0;
			while (Details & (uint32_t)BlockDetails::States && Chunk > 0)
			{
				auto Size = ResolveBlockStatetrie(Result, Offset, Chunk);
				if (!Size)
					return Size.Error();

				Offset += *Size;
				if (*Size < Chunk)
					break;
			}

			FinalizeChecksum(Header, BlockHash);
			return Result;
		}
		ExpectsLR<Ledger::Block> Chainstate::GetBlockByHash(const uint256_t& BlockHash, size_t Chunk, uint32_t Details)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(BlockHash, Hash);

			Ledger::BlockHeader Header;
			Format::Stream Message = Format::Stream(Load(Label, __func__, GetBlockLabel(Hash)).Or(String()));
			if (!Header.Load(Message))
				return ExpectsLR<Ledger::Block>(LayerException("block header deserialization error"));

			Ledger::Block Result = Ledger::Block(Header);
			size_t Offset = 0;
			while ((Details & (uint32_t)BlockDetails::Transactions || Details & (uint32_t)BlockDetails::BlockTransactions) && Chunk > 0)
			{
				auto Size = ResolveBlockTransactions(Result, Details & (uint32_t)BlockDetails::BlockTransactions, Offset, Chunk);
				if (!Size)
					return Size.Error();

				Offset += *Size;
				if (*Size < Chunk)
					break;
			}

			Offset = 0;
			while (Details & (uint32_t)BlockDetails::States && Chunk > 0)
			{
				auto Size = ResolveBlockStatetrie(Result, Offset, Chunk);
				if (!Size)
					return Size.Error();

				Offset += *Size;
				if (*Size < Chunk)
					break;
			}

			FinalizeChecksum(Header, Var::Binary(Hash, sizeof(Hash)));
			return Result;
		}
		ExpectsLR<Ledger::Block> Chainstate::GetLatestBlock(size_t Chunk, uint32_t Details)
		{
			auto Cursor = Query(*Blockdata, Label, __func__, "SELECT block_hash FROM blocks ORDER BY block_number DESC LIMIT 1");
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Ledger::Block>(LayerException(ErrorOf(Cursor)));

			Ledger::BlockHeader Header;
			auto BlockHash = (*Cursor)["block_hash"].Get();
			Format::Stream Message = Format::Stream(Load(Label, __func__, GetBlockLabel(BlockHash.GetBinary())).Or(String()));
			if (!Header.Load(Message))
				return ExpectsLR<Ledger::Block>(LayerException("block header deserialization error"));

			Ledger::Block Result = Ledger::Block(Header);
			size_t Offset = 0;
			while ((Details & (uint32_t)BlockDetails::Transactions || Details & (uint32_t)BlockDetails::BlockTransactions) && Chunk > 0)
			{
				auto Size = ResolveBlockTransactions(Result, Details & (uint32_t)BlockDetails::BlockTransactions, Offset, Chunk);
				if (!Size)
					return Size.Error();

				Offset += *Size;
				if (*Size < Chunk)
					break;
			}

			Offset = 0;
			while (Details & (uint32_t)BlockDetails::States && Chunk > 0)
			{
				auto Size = ResolveBlockStatetrie(Result, Offset, Chunk);
				if (!Size)
					return Size.Error();

				Offset += *Size;
				if (*Size < Chunk)
					break;
			}

			FinalizeChecksum(Header, BlockHash);
			return Result;
		}
		ExpectsLR<Ledger::BlockHeader> Chainstate::GetBlockHeaderByNumber(uint64_t BlockNumber)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Integer(BlockNumber));

			auto Cursor = EmplaceQuery(*Blockdata, Label, __func__, "SELECT block_hash FROM blocks WHERE block_number = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Ledger::BlockHeader>(LayerException(ErrorOf(Cursor)));

			Ledger::BlockHeader Header;
			auto BlockHash = (*Cursor)["block_hash"].Get();
			Format::Stream Message = Format::Stream(Load(Label, __func__, GetBlockLabel(BlockHash.GetBinary())).Or(String()));
			if (!Header.Load(Message))
				return ExpectsLR<Ledger::BlockHeader>(LayerException("block header deserialization error"));

			FinalizeChecksum(Header, BlockHash);
			return Header;
		}
		ExpectsLR<Ledger::BlockHeader> Chainstate::GetBlockHeaderByHash(const uint256_t& BlockHash)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(BlockHash, Hash);

			Ledger::BlockHeader Header;
			Format::Stream Message = Format::Stream(Load(Label, __func__, GetBlockLabel(Hash)).Or(String()));
			if (!Header.Load(Message))
				return ExpectsLR<Ledger::BlockHeader>(LayerException("block header deserialization error"));

			FinalizeChecksum(Header, Var::Binary(Hash, sizeof(Hash)));
			return Header;
		}
		ExpectsLR<Ledger::BlockHeader> Chainstate::GetLatestBlockHeader()
		{
			auto Cursor = Query(*Blockdata, Label, __func__, "SELECT block_hash FROM blocks ORDER BY block_number DESC LIMIT 1");
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Ledger::BlockHeader>(LayerException(ErrorOf(Cursor)));

			Ledger::BlockHeader Header;
			auto BlockHash = (*Cursor)["block_hash"].Get();
			Format::Stream Message = Format::Stream(Load(Label, __func__, GetBlockLabel(BlockHash.GetBinary())).Or(String()));
			if (!Header.Load(Message))
				return ExpectsLR<Ledger::BlockHeader>(LayerException("block header deserialization error"));

			FinalizeChecksum(Header, BlockHash);
			return Header;
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

			auto Cursor = EmplaceQuery(*Txdata, Label, __func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce;", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Ledger::BlockProof>(LayerException(ErrorOf(Cursor)));

			size_t Size = Cursor->First().Size();
			Value.Transactions.reserve(Size);
			Value.Receipts.reserve(Size);
			for (auto Row : Cursor->First())
			{
				auto TransactionHash = Row["transaction_hash"].Get().GetBlob();
				if (TransactionHash.size() != sizeof(uint256_t))
					continue;

				uint256_t Hash;
				Algorithm::Encoding::EncodeUint256((uint8_t*)TransactionHash.data(), Hash);
				Value.Transactions.push_back(Hash);

				Format::Stream ReceiptMessage = Format::Stream(Load(Label, __func__, GetReceiptLabel((uint8_t*)TransactionHash.data())).Or(String()));
				Value.Receipts.push_back(ReceiptMessage.Hash());
			}

			auto Cursor1 = EmplaceQuery(*Uniformdata, Label, __func__, "SELECT (SELECT index_hash FROM indices WHERE indices.index_number = uniformtries.index_number) AS index_hash FROM uniformtries WHERE block_number = ?", &Map);
			if (!Cursor1 || Cursor1->Error())
				return ExpectsLR<Ledger::BlockProof>(LayerException(ErrorOf(Cursor1)));

			auto Cursor2 = EmplaceQuery(*Multiformdata, Label, __func__, "SELECT (SELECT column_hash FROM columns WHERE columns.column_number = multiformtries.column_number) AS column_hash, (SELECT row_hash FROM rows WHERE rows.row_number = multiformtries.row_number) AS row_hash FROM multiformtries WHERE block_number = ?", &Map);
			if (!Cursor2 || Cursor2->Error())
				return ExpectsLR<Ledger::BlockProof>(LayerException(ErrorOf(Cursor2)));

			Value.States.reserve(Cursor1->First().Size() + Cursor2->First().Size());
			for (auto Row : Cursor1->First())
			{
				auto Message = Format::Stream(Load(Label, __func__, GetUniformLabel(Row["index_hash"].Get().GetBlob(), BlockNumber)).Or(String()));
				Value.States.push_back(Message.Hash());
			}
			for (auto Row : Cursor2->First())
			{
				auto Message = Format::Stream(Load(Label, __func__, GetMultiformLabel(Row["column_hash"].Get().GetBlob(), Row["row_hash"].Get().GetBlob(), BlockNumber)).Or(String()));
				Value.States.push_back(Message.Hash());
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

			auto Cursor = EmplaceQuery(*Txdata, Label, __func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce", &Map);
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

			auto Cursor1 = EmplaceQuery(*Uniformdata, Label, __func__, "SELECT (SELECT index_hash FROM indices WHERE indices.index_number = uniformtries.index_number) AS index_hash FROM uniformtries WHERE block_number = ?", &Map);
			if (!Cursor1 || Cursor1->Error())
				return ExpectsLR<Vector<uint256_t>>(LayerException(ErrorOf(Cursor1)));

			auto Cursor2 = EmplaceQuery(*Multiformdata, Label, __func__, "SELECT (SELECT column_hash FROM columns WHERE columns.column_number = multiformtries.column_number) AS column_hash, (SELECT row_hash FROM rows WHERE rows.row_number = multiformtries.row_number) AS row_hash FROM multiformtries WHERE block_number = ?", &Map);
			if (!Cursor2 || Cursor2->Error())
				return ExpectsLR<Vector<uint256_t>>(LayerException(ErrorOf(Cursor2)));

			Vector<uint256_t> Result;
			for (auto& Response : *Cursor1)
			{
				size_t Size = Response.Size();
				Result.reserve(Result.size() + Size);
				for (size_t i = 0; i < Size; i++)
				{
					auto Row = Response[i];
					auto Message = Format::Stream(Load(Label, __func__, GetUniformLabel(Row["index_hash"].Get().GetBlob(), BlockNumber)).Or(String()));
					Result.push_back(Message.Hash());
				}
			}
			for (auto& Response : *Cursor2)
			{
				size_t Size = Response.Size();
				Result.reserve(Result.size() + Size);
				for (size_t i = 0; i < Size; i++)
				{
					auto Row = Response[i];
					auto Message = Format::Stream(Load(Label, __func__, GetMultiformLabel(Row["column_hash"].Get().GetBlob(), Row["row_hash"].Get().GetBlob(), BlockNumber)).Or(String()));
					Result.push_back(Message.Hash());
				}
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

			auto Cursor = EmplaceQuery(*Blockdata, Label, __func__, "SELECT block_hash FROM blocks WHERE block_number BETWEEN ? AND ? ORDER BY block_number DESC", &Map);
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

			auto Cursor = EmplaceQuery(*Blockdata, Label, __func__, "SELECT block_hash FROM blocks WHERE block_number BETWEEN ? AND ? ORDER BY block_number DESC", &Map);
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
					auto BlockHash = Response[i]["block_hash"].Get();
					Format::Stream Message = Format::Stream(Load(Label, __func__, GetBlockLabel(BlockHash.GetBinary())).Or(String()));
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

			auto Cursor1 = EmplaceQuery(*Uniformdata, Label, __func__, "SELECT (SELECT index_hash FROM indices WHERE indices.index_number = uniformtries.index_number) AS index_hash FROM uniformtries WHERE block_number = ? LIMIT ? OFFSET ?", &Map);
			if (!Cursor1 || Cursor1->Error())
				return ExpectsLR<Ledger::StateWork>(LayerException(ErrorOf(Cursor1)));

			auto Cursor2 = EmplaceQuery(*Multiformdata, Label, __func__, "SELECT (SELECT column_hash FROM columns WHERE columns.column_number = multiformtries.column_number) AS column_hash, (SELECT row_hash FROM rows WHERE rows.row_number = multiformtries.row_number) AS row_hash FROM multiformtries WHERE block_number = ? LIMIT ? OFFSET ?", &Map);
			if (!Cursor2 || Cursor2->Error())
				return ExpectsLR<Ledger::StateWork>(LayerException(ErrorOf(Cursor2)));

			auto Result = ExpectsLR<Ledger::StateWork>(Ledger::StateWork());
			if (!Cursor1->Empty())
			{
				auto& Response = Cursor1->First();
				size_t Size = Response.Size();
				for (size_t i = 0; i < Size; i++)
				{
					auto Row = Response[i];
					auto Message = Format::Stream(Load(Label, __func__, GetUniformLabel(Row["index_hash"].Get().GetBlob(), BlockNumber)).Or(String()));
					UPtr<Ledger::State> NextState = States::Resolver::New(Messages::Generic::ResolveType(Message).Or(0));
					if (NextState && NextState->Load(Message))
						(*Result)[NextState->AsComposite()] = std::move(NextState);
				}
			}
			if (!Cursor2->Empty())
			{
				auto& Response = Cursor2->First();
				size_t Size = Response.Size();
				for (size_t i = 0; i < Size; i++)
				{
					auto Row = Response[i];
					auto Message = Format::Stream(Load(Label, __func__, GetMultiformLabel(Row["column_hash"].Get().GetBlob(), Row["row_hash"].Get().GetBlob(), BlockNumber)).Or(String()));
					UPtr<Ledger::State> NextState = States::Resolver::New(Messages::Generic::ResolveType(Message).Or(0));
					if (NextState && NextState->Load(Message))
						(*Result)[NextState->AsComposite()] = std::move(NextState);
				}
			}
			return Result;
		}
		ExpectsLR<Vector<UPtr<Ledger::Transaction>>> Chainstate::GetTransactionsByNumber(uint64_t BlockNumber, size_t Offset, size_t Count)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(*Txdata, Label, __func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<UPtr<Ledger::Transaction>>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Vector<UPtr<Ledger::Transaction>> Values;
			Values.reserve(Size);

			for (size_t i = 0; i < Size; i++)
			{
				auto Row = Response[i];
				auto TransactionHash = Row["transaction_hash"].Get();
				Format::Stream Message = Format::Stream(Load(Label, __func__, GetTransactionLabel(TransactionHash.GetBinary())).Or(String()));
				UPtr<Ledger::Transaction> Value = Transactions::Resolver::New(Messages::Authentic::ResolveType(Message).Or(0));
				if (Value && Value->Load(Message))
				{
					FinalizeChecksum(**Value, TransactionHash);
					Values.emplace_back(std::move(Value));
				}
			}

			return Values;
		}
		ExpectsLR<Vector<UPtr<Ledger::Transaction>>> Chainstate::GetTransactionsByOwner(uint64_t BlockNumber, const Algorithm::Pubkeyhash Owner, int8_t Direction, size_t Offset, size_t Count)
		{
			auto Location = ResolveAccountLocation(Owner);
			if (!Location)
				return ExpectsLR<Vector<UPtr<Ledger::Transaction>>>(Vector<UPtr<Ledger::Transaction>>());

			SchemaList Map;
			Map.push_back(Var::Set::Integer(*Location));
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::String(Direction < 0 ? "DESC" : "ASC"));
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(*Partydata, Label, __func__, "SELECT transaction_number FROM parties WHERE transaction_account_number = ? AND block_number <= ? ORDER BY transaction_number $? LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<UPtr<Ledger::Transaction>>>(LayerException(ErrorOf(Cursor)));
			else if (Cursor->Empty())
				return ExpectsLR<Vector<UPtr<Ledger::Transaction>>>(Vector<UPtr<Ledger::Transaction>>());

			String DynamicQuery = "SELECT transaction_hash FROM transactions WHERE transaction_number IN (";
			for (auto Row : Cursor->First())
				DynamicQuery.append(Row.GetColumn(0).Get().GetBlob()).push_back(',');
			DynamicQuery.pop_back();
			DynamicQuery.append(") ORDER BY transaction_number ");
			DynamicQuery.append(Direction < 0 ? "DESC" : "ASC");

			Cursor = Query(*Txdata, Label, __func__, DynamicQuery);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<UPtr<Ledger::Transaction>>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Vector<UPtr<Ledger::Transaction>> Values;
			Values.reserve(Size);

			for (size_t i = 0; i < Size; i++)
			{
				auto Row = Response[i];
				auto TransactionHash = Row["transaction_hash"].Get();
				Format::Stream Message = Format::Stream(Load(Label, __func__, GetTransactionLabel(TransactionHash.GetBinary())).Or(String()));
				UPtr<Ledger::Transaction> Value = Transactions::Resolver::New(Messages::Authentic::ResolveType(Message).Or(0));
				if (Value && Value->Load(Message))
				{
					FinalizeChecksum(**Value, TransactionHash);
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

			auto Cursor = EmplaceQuery(*Txdata, Label, __func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<Ledger::BlockTransaction>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Vector<Ledger::BlockTransaction> Values;
			Values.reserve(Size);

			for (size_t i = 0; i < Size; i++)
			{
				auto Row = Response[i];
				auto TransactionHash = Row["transaction_hash"].Get();
				Format::Stream TransactionMessage = Format::Stream(Load(Label, __func__, GetTransactionLabel(TransactionHash.GetBinary())).Or(String()));
				Format::Stream ReceiptMessage = Format::Stream(Load(Label, __func__, GetReceiptLabel(TransactionHash.GetBinary())).Or(String()));
				Ledger::BlockTransaction Value;
				Value.Transaction = Transactions::Resolver::New(Messages::Authentic::ResolveType(TransactionMessage).Or(0));
				if (Value.Transaction && Value.Transaction->Load(TransactionMessage) && Value.Receipt.Load(ReceiptMessage))
				{
					FinalizeChecksum(**Value.Transaction, TransactionHash);
					Values.emplace_back(std::move(Value));
				}
			}

			return Values;
		}
		ExpectsLR<Vector<Ledger::BlockTransaction>> Chainstate::GetBlockTransactionsByOwner(uint64_t BlockNumber, const Algorithm::Pubkeyhash Owner, int8_t Direction, size_t Offset, size_t Count)
		{
			auto Location = ResolveAccountLocation(Owner);
			if (!Location)
				return ExpectsLR<Vector<Ledger::BlockTransaction>>(Vector<Ledger::BlockTransaction>());

			SchemaList Map;
			Map.push_back(Var::Set::Integer(*Location));
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::String(Direction < 0 ? "DESC" : "ASC"));
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(*Partydata, Label, __func__, "SELECT transaction_number FROM parties WHERE transaction_account_number = ? AND block_number <= ? ORDER BY transaction_number $? LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<Ledger::BlockTransaction>>(LayerException(ErrorOf(Cursor)));
			else if (Cursor->Empty())
				return ExpectsLR<Vector<Ledger::BlockTransaction>>(Vector<Ledger::BlockTransaction>());

			String DynamicQuery = "SELECT transaction_hash FROM transactions WHERE transaction_number IN (";
			for (auto Row : Cursor->First())
				DynamicQuery.append(Row.GetColumn(0).Get().GetBlob()).push_back(',');
			DynamicQuery.pop_back();
			DynamicQuery.append(") ORDER BY transaction_number ");
			DynamicQuery.append(Direction < 0 ? "DESC" : "ASC");

			Cursor = Query(*Txdata, Label, __func__, DynamicQuery);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<Ledger::BlockTransaction>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Vector<Ledger::BlockTransaction> Values;
			Values.reserve(Size);

			for (size_t i = 0; i < Size; i++)
			{
				auto Row = Response[i];
				auto TransactionHash = Row["transaction_hash"].Get();
				Format::Stream TransactionMessage = Format::Stream(Load(Label, __func__, GetTransactionLabel(TransactionHash.GetBinary())).Or(String()));
				Format::Stream ReceiptMessage = Format::Stream(Load(Label, __func__, GetReceiptLabel(TransactionHash.GetBinary())).Or(String()));
				Ledger::BlockTransaction Value;
				Value.Transaction = Transactions::Resolver::New(Messages::Authentic::ResolveType(TransactionMessage).Or(0));
				if (Value.Transaction && Value.Transaction->Load(TransactionMessage) && Value.Receipt.Load(ReceiptMessage))
				{
					FinalizeChecksum(**Value.Transaction, TransactionHash);
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

			auto Cursor = EmplaceQuery(*Txdata, Label, __func__, "SELECT transaction_hash FROM transactions WHERE block_number = ? ORDER BY block_nonce LIMIT ? OFFSET ?", &Map);
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
				auto TransactionHash = Row["transaction_hash"].Get();
				Format::Stream Message = Format::Stream(Load(Label, __func__, GetReceiptLabel(TransactionHash.GetBinary())).Or(String()));
				if (Value.Load(Message))
					Values.emplace_back(std::move(Value));
			}

			return Values;
		}
		ExpectsLR<Vector<Ledger::BlockTransaction>> Chainstate::GetPendingBlockTransactions(uint64_t BlockNumber, size_t Offset, size_t Count)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(*Txdata, Label, __func__, "SELECT transaction_hash FROM transactions WHERE dispatch_queue IS NOT NULL AND dispatch_queue <= ? ORDER BY block_nonce LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<Ledger::BlockTransaction>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Vector<Ledger::BlockTransaction> Values;
			Values.reserve(Size);

			for (size_t i = 0; i < Size; i++)
			{
				auto Row = Response[i];
				auto TransactionHash = Row["transaction_hash"].Get();
				Format::Stream TransactionMessage = Format::Stream(Load(Label, __func__, GetTransactionLabel(TransactionHash.GetBinary())).Or(String()));
				Format::Stream ReceiptMessage = Format::Stream(Load(Label, __func__, GetReceiptLabel(TransactionHash.GetBinary())).Or(String()));
				Ledger::BlockTransaction Value;
				Value.Transaction = Transactions::Resolver::New(Messages::Authentic::ResolveType(TransactionMessage).Or(0));
				if (Value.Transaction && Value.Transaction->Load(TransactionMessage) && Value.Receipt.Load(ReceiptMessage))
				{
					FinalizeChecksum(**Value.Transaction, TransactionHash);
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

			auto Cursor = EmplaceQuery(*Aliasdata, Label, __func__, "SELECT transaction_number FROM aliases WHERE transaction_hash = ?", &Map);
			String DynamicQuery = "SELECT transaction_hash FROM transactions WHERE transaction_hash = ?";
			if (Cursor && !Cursor->ErrorOrEmpty())
			{
				DynamicQuery.append("OR transaction_number IN (");
				for (auto Row : Cursor->First())
					DynamicQuery.append(Row.GetColumn(0).Get().GetBlob()).push_back(',');
				DynamicQuery.pop_back();
				DynamicQuery.push_back(')');
			}

			Cursor = EmplaceQuery(*Txdata, Label, __func__, DynamicQuery, &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<UPtr<Ledger::Transaction>>(LayerException(ErrorOf(Cursor)));

			auto ParentTransactionHash = (*Cursor)["transaction_hash"].Get();
			Format::Stream Message = Format::Stream(Load(Label, __func__, GetTransactionLabel(ParentTransactionHash.GetBinary())).Or(String()));
			UPtr<Ledger::Transaction> Value = Transactions::Resolver::New(Messages::Authentic::ResolveType(Message).Or(0));
			if (!Value || !Value->Load(Message))
				return ExpectsLR<UPtr<Ledger::Transaction>>(LayerException("transaction deserialization error"));

			FinalizeChecksum(**Value, ParentTransactionHash);
			return Value;
		}
		ExpectsLR<Ledger::BlockTransaction> Chainstate::GetBlockTransactionByHash(const uint256_t& TransactionHash)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(TransactionHash, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));

			auto Cursor = EmplaceQuery(*Aliasdata, Label, __func__, "SELECT transaction_number FROM aliases WHERE transaction_hash = ?", &Map);
			String DynamicQuery = "SELECT transaction_hash FROM transactions WHERE transaction_hash = ?";
			if (Cursor && !Cursor->ErrorOrEmpty())
			{
				DynamicQuery.append("OR transaction_number IN (");
				for (auto Row : Cursor->First())
					DynamicQuery.append(Row.GetColumn(0).Get().GetBlob()).push_back(',');
				DynamicQuery.pop_back();
				DynamicQuery.push_back(')');
			}

			Cursor = EmplaceQuery(*Txdata, Label, __func__, DynamicQuery, &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Ledger::BlockTransaction>(LayerException(ErrorOf(Cursor)));

			auto ParentTransactionHash = (*Cursor)["transaction_hash"].Get();
			Format::Stream TransactionMessage = Format::Stream(Load(Label, __func__, GetTransactionLabel(ParentTransactionHash.GetBinary())).Or(String()));
			Format::Stream ReceiptMessage = Format::Stream(Load(Label, __func__, GetReceiptLabel(ParentTransactionHash.GetBinary())).Or(String()));
			Ledger::BlockTransaction Value;
			Value.Transaction = Transactions::Resolver::New(Messages::Authentic::ResolveType(TransactionMessage).Or(0));
			if (!Value.Transaction || !Value.Transaction->Load(TransactionMessage) || !Value.Receipt.Load(ReceiptMessage))
				return ExpectsLR<Ledger::BlockTransaction>(LayerException("block transaction deserialization error"));

			FinalizeChecksum(**Value.Transaction, ParentTransactionHash);
			return Value;
		}
		ExpectsLR<Ledger::Receipt> Chainstate::GetReceiptByTransactionHash(const uint256_t& TransactionHash)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(TransactionHash, Hash);

			Ledger::Receipt Value;
			Format::Stream Message = Format::Stream(Load(Label, __func__, GetReceiptLabel(Hash)).Or(String()));
			if (!Value.Load(Message))
				return ExpectsLR<Ledger::Receipt>(LayerException("receipt deserialization error"));

			return Value;
		}
		ExpectsLR<UPtr<Ledger::State>> Chainstate::GetUniformByIndex(const Ledger::BlockMutation* Delta, const std::string_view& Index, uint64_t BlockNumber)
		{
			if (Delta != nullptr)
			{
				if (Delta->Outgoing != nullptr)
				{
					auto Candidate = Delta->Outgoing->FindUniform(Index);
					if (Candidate)
						return std::move(*Candidate);
				}

				if (Delta->Incoming != nullptr)
				{
					auto Candidate = Delta->Incoming->FindUniform(Index);
					if (Candidate)
						return std::move(*Candidate);
				}
			}

			auto Location = ResolveUniformLocation(Index, !BlockNumber);
			if (!Location)
				return Location.Error();

			if (!Location->Block)
			{
				auto FindState = Uniformdata->PrepareStatement(!BlockNumber ?
					"SELECT block_number FROM uniforms WHERE index_number = ?" :
					"SELECT block_number FROM uniformtries WHERE index_number = ? AND block_number < ? ORDER BY block_number DESC LIMIT 1", nullptr);
				if (!FindState)
					return ExpectsLR<UPtr<Ledger::State>>(LayerException(std::move(FindState.Error().message())));

				Uniformdata->BindInt64(*FindState, 0, Location->Index.Or(0));
				if (BlockNumber > 0)
					Uniformdata->BindInt64(*FindState, 1, BlockNumber);

				auto Cursor = PreparedQuery(*Uniformdata, Label, __func__, *FindState);
				if (!Cursor || Cursor->Empty())
				{
					if (Delta != nullptr && Delta->Incoming != nullptr)
						((Ledger::BlockMutation*)Delta)->Incoming->ClearUniform(Index);
					return ExpectsLR<UPtr<Ledger::State>>(LayerException(ErrorOf(Cursor)));
				}
				else if (Cursor->Empty())
				{
					if (Delta != nullptr && Delta->Incoming != nullptr)
						((Ledger::BlockMutation*)Delta)->Incoming->ClearUniform(Index);
					return ExpectsLR<UPtr<Ledger::State>>(LayerException("uniform not found"));
				}

				auto Cache = UniformCache::Get();
				Location->Block = (*Cursor)["block_number"].Get().GetInteger();
				Cache->SetBlockLocation(Location->Index.Or(0), Location->Block.Or(0));
			}

			Format::Stream Message = Format::Stream(Load(Label, __func__, GetUniformLabel(Index, Location->Block.Or(0))).Or(String()));
			UPtr<Ledger::State> Value = States::Resolver::New(Messages::Generic::ResolveType(Message).Or(0));
			if (!Value || !Value->Load(Message))
			{
				if (Delta != nullptr && Delta->Incoming != nullptr)
					((Ledger::BlockMutation*)Delta)->Incoming->ClearUniform(Index);
				return ExpectsLR<UPtr<Ledger::State>>(LayerException("uniform deserialization error"));
			}

			if (Delta != nullptr && Delta->Incoming != nullptr)
				((Ledger::BlockMutation*)Delta)->Incoming->CopyAny(*Value);
			return Value;
		}
		ExpectsLR<UPtr<Ledger::State>> Chainstate::GetMultiformByComposition(const Ledger::BlockMutation* Delta, const std::string_view& Column, const std::string_view& Row, uint64_t BlockNumber)
		{
			if (Delta != nullptr)
			{
				if (Delta->Outgoing != nullptr)
				{
					auto Candidate = Delta->Outgoing->FindMultiform(Column, Row);
					if (Candidate)
						return std::move(*Candidate);
				}

				if (Delta->Incoming != nullptr)
				{
					auto Candidate = Delta->Incoming->FindMultiform(Column, Row);
					if (Candidate)
						return std::move(*Candidate);
				}
			}

			auto Location = ResolveMultiformLocation(Column, Row, !BlockNumber);
			if (!Location)
				return Location.Error();

			if (!Location->Block)
			{
				auto FindState = Multiformdata->PrepareStatement(!BlockNumber ?
					"SELECT block_number FROM multiforms WHERE column_number = ? AND row_number = ?" :
					"SELECT block_number FROM multiformtries WHERE column_number = ? AND row_number = ? AND block_number < ? ORDER BY block_number DESC LIMIT 1", nullptr);
				if (!FindState)
					return ExpectsLR<UPtr<Ledger::State>>(LayerException(std::move(FindState.Error().message())));

				Multiformdata->BindInt64(*FindState, 0, Location->Column.Or(0));
				Multiformdata->BindInt64(*FindState, 1, Location->Row.Or(0));
				if (BlockNumber > 0)
					Multiformdata->BindInt64(*FindState, 2, BlockNumber);

				auto Cursor = PreparedQuery(*Multiformdata, Label, __func__, *FindState);
				if (!Cursor || Cursor->Empty())
				{
					if (Delta != nullptr && Delta->Incoming != nullptr)
						((Ledger::BlockMutation*)Delta)->Incoming->ClearMultiform(Column, Row);
					return ExpectsLR<UPtr<Ledger::State>>(LayerException(ErrorOf(Cursor)));
				}
				else if (Cursor->Empty())
				{
					if (Delta != nullptr && Delta->Incoming != nullptr)
						((Ledger::BlockMutation*)Delta)->Incoming->ClearMultiform(Column, Row);
					return ExpectsLR<UPtr<Ledger::State>>(LayerException("multiform not found"));
				}

				auto Cache = MultiformCache::Get();
				Location->Block = (*Cursor)["block_number"].Get().GetInteger();
				Cache->SetBlockLocation(Location->Column.Or(0), Location->Row.Or(0), Location->Block.Or(0));
			}

			Format::Stream Message = Format::Stream(Load(Label, __func__, GetMultiformLabel(Column, Row, Location->Block.Or(0))).Or(String()));
			UPtr<Ledger::State> Value = States::Resolver::New(Messages::Generic::ResolveType(Message).Or(0));
			if (!Value || !Value->Load(Message))
			{
				if (Delta != nullptr && Delta->Incoming != nullptr)
					((Ledger::BlockMutation*)Delta)->Incoming->ClearMultiform(Column, Row);
				return ExpectsLR<UPtr<Ledger::State>>(LayerException("multiform deserialization error"));
			}

			if (Delta != nullptr && Delta->Incoming != nullptr)
				((Ledger::BlockMutation*)Delta)->Incoming->CopyAny(*Value);
			return Value;
		}
		ExpectsLR<UPtr<Ledger::State>> Chainstate::GetMultiformByColumn(const Ledger::BlockMutation* Delta, const std::string_view& Column, uint64_t BlockNumber, size_t Offset)
		{
			auto Location = ResolveMultiformLocation(Column, Optional::None, false);
			if (!Location)
				return Location.Error();

			SchemaList Map;
			Map.push_back(Var::Set::Integer(Location->Column.Or(0)));
			if (BlockNumber > 0)
				Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(*Multiformdata, Label, __func__, !BlockNumber ?
				"SELECT (SELECT row_hash FROM rows WHERE rows.row_number = multiforms.row_number) AS row_hash, block_number FROM multiforms WHERE column_number = ? ORDER BY row_number LIMIT 1 OFFSET ?" :
				"SELECT (SELECT row_hash FROM rows WHERE rows.row_number = multiformtries.row_number) AS row_hash, MAX(block_number) AS block_number FROM multiformtries WHERE column_number = ? AND block_number < ? GROUP BY row_number ORDER BY row_number LIMIT 1 OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<UPtr<Ledger::State>>(LayerException(ErrorOf(Cursor)));
			else if (Cursor->Empty())
				return ExpectsLR<UPtr<Ledger::State>>(LayerException("multiform not found"));

			Format::Stream Message = Format::Stream(Load(Label, __func__, GetMultiformLabel(Column, (*Cursor)["row_hash"].Get().GetBlob(), (*Cursor)["block_number"].Get().GetInteger())).Or(String()));
			UPtr<Ledger::State> Value = States::Resolver::New(Messages::Generic::ResolveType(Message).Or(0));
			if (!Value || !Value->Load(Message))
			{
				if (Value && Delta != nullptr && Delta->Incoming != nullptr)
					((Ledger::BlockMutation*)Delta)->Incoming->ClearMultiform(Column, ((Ledger::Multiform*)*Value)->AsRow());
				return ExpectsLR<UPtr<Ledger::State>>(LayerException("multiform deserialization error"));
			}

			if (Delta != nullptr && Delta->Incoming != nullptr)
				((Ledger::BlockMutation*)Delta)->Incoming->CopyAny(*Value);
			return Value;
		}
		ExpectsLR<UPtr<Ledger::State>> Chainstate::GetMultiformByRow(const Ledger::BlockMutation* Delta, const std::string_view& Row, uint64_t BlockNumber, size_t Offset)
		{
			auto Location = ResolveMultiformLocation(Optional::None, Row, false);
			if (!Location)
				return Location.Error();

			SchemaList Map;
			Map.push_back(Var::Set::Integer(Location->Row.Or(0)));
			if (BlockNumber > 0)
				Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(*Multiformdata, Label, __func__, !BlockNumber ?
				"SELECT (SELECT column_hash FROM columns WHERE columns.column_number = multiforms.column_number) AS column_hash, block_number FROM multiforms WHERE row_number = ? ORDER BY column_number LIMIT 1 OFFSET ?" :
				"SELECT (SELECT column_hash FROM columns WHERE columns.column_number = multiformtries.column_number) AS column_hash, MAX(block_number) AS block_number FROM multiformtries WHERE row_number = ? AND block_number < ? GROUP BY column_number ORDER BY column_number LIMIT 1 OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<UPtr<Ledger::State>>(LayerException(ErrorOf(Cursor)));
			else if (Cursor->Empty())
				return ExpectsLR<UPtr<Ledger::State>>(LayerException("multiform not found"));

			Format::Stream Message = Format::Stream(Load(Label, __func__, GetMultiformLabel((*Cursor)["column_hash"].Get().GetBlob(), Row, (*Cursor)["block_number"].Get().GetInteger())).Or(String()));
			UPtr<Ledger::State> Value = States::Resolver::New(Messages::Generic::ResolveType(Message).Or(0));
			if (!Value || !Value->Load(Message))
			{
				if (Value && Delta != nullptr && Delta->Incoming != nullptr)
					((Ledger::BlockMutation*)Delta)->Incoming->ClearMultiform(((Ledger::Multiform*)*Value)->AsColumn(), Row);
				return ExpectsLR<UPtr<Ledger::State>>(LayerException("multiform deserialization error"));
			}

			if (Delta != nullptr && Delta->Incoming != nullptr)
				((Ledger::BlockMutation*)Delta)->Incoming->CopyAny(*Value);
			return Value;
		}
		ExpectsLR<Vector<UPtr<Ledger::State>>> Chainstate::GetMultiformsByColumn(const Ledger::BlockMutation* Delta, const std::string_view& Column, uint64_t BlockNumber, size_t Offset, size_t Count)
		{
			auto Location = ResolveMultiformLocation(Column, Optional::None, false);
			if (!Location)
				return ExpectsLR<Vector<UPtr<Ledger::State>>>(Vector<UPtr<Ledger::State>>());

			SchemaList Map;
			Map.push_back(Var::Set::Integer(Location->Column.Or(0)));
			if (BlockNumber > 0)
				Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(*Multiformdata, Label, __func__, !BlockNumber ?
				"SELECT (SELECT row_hash FROM rows WHERE rows.row_number = multiforms.row_number) AS row_hash, block_number FROM multiforms WHERE column_number = ? ORDER BY row_number LIMIT ? OFFSET ?" :
				"SELECT (SELECT row_hash FROM rows WHERE rows.row_number = multiformtries.row_number) AS row_hash, MAX(block_number) AS block_number FROM multiformtries WHERE column_number = ? AND block_number < ? GROUP BY row_number ORDER BY row_number LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<UPtr<Ledger::State>>>(LayerException(ErrorOf(Cursor)));

			Vector<UPtr<Ledger::State>> Values;
			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			for (size_t i = 0; i < Size; i++)
			{
				auto Next = Response[i];
				Format::Stream Message = Format::Stream(Load(Label, __func__, GetMultiformLabel(Column, Next["row_hash"].Get().GetBlob(), Next["block_number"].Get().GetInteger())).Or(String()));
				UPtr<Ledger::State> NextState = States::Resolver::New(Messages::Generic::ResolveType(Message).Or(0));
				if (!NextState || !NextState->Load(Message))
				{
					if (NextState && Delta != nullptr && Delta->Incoming != nullptr)
						((Ledger::BlockMutation*)Delta)->Incoming->ClearMultiform(Column, ((Ledger::Multiform*)*NextState)->AsRow());
					continue;
				}
				else if (Delta != nullptr && Delta->Incoming != nullptr)
					((Ledger::BlockMutation*)Delta)->Incoming->CopyAny(*NextState);
				Values.push_back(std::move(NextState));
			}

			return Values;
		}
		ExpectsLR<Vector<UPtr<Ledger::State>>> Chainstate::GetMultiformsByColumnFilter(const Ledger::BlockMutation* Delta, const std::string_view& Column, const FactorFilter& Filter, uint64_t BlockNumber, const FactorWindow& Window)
		{
			auto Location = ResolveMultiformLocation(Column, Optional::None, false);
			if (!Location)
				return ExpectsLR<Vector<UPtr<Ledger::State>>>(Vector<UPtr<Ledger::State>>());

			SchemaList Map; String Template;
			if (Window.Type() == FactorRangeWindow::InstanceType())
			{
				auto& Range = *(FactorRangeWindow*)&Window;
				Map.push_back(Var::Set::Integer(Location->Column.Or(0)));
				if (BlockNumber > 0)
					Map.push_back(Var::Set::Integer(BlockNumber));
				Map.push_back(Var::Set::String(Filter.AsCondition()));
				Map.push_back(Var::Set::Integer(Filter.Value));
				Map.push_back(Var::Set::String(Filter.AsOrder()));
				Map.push_back(Var::Set::Integer(Range.Count));
				Map.push_back(Var::Set::Integer(Range.Offset));

				Template = !BlockNumber ?
					"SELECT (SELECT row_hash FROM rows WHERE rows.row_number = multiforms.row_number) AS row_hash, block_number FROM multiforms WHERE column_number = ? AND factor $? ? ORDER BY factor $?, row_number ASC LIMIT ? OFFSET ?" :
					"SELECT (SELECT row_hash FROM rows WHERE rows.row_number = queryforms.row_number) AS row_hash, block_number FROM (SELECT column_number, row_number, factor, MAX(block_number) AS block_number FROM multiformtries WHERE column_number = ? AND block_number < ? GROUP BY row_number) AS queryforms WHERE factor $? ? ORDER BY factor $?, row_number ASC LIMIT ? OFFSET ?";
			}
			else if (Window.Type() == FactorIndexWindow::InstanceType())
			{
				String Indices;
				for (auto& Item : ((FactorIndexWindow*)&Window)->Indices)
					Indices += ToString(Item + 1) + ",";

				Map.push_back(Var::Set::String(Filter.AsOrder()));
				Map.push_back(Var::Set::Integer(Location->Column.Or(0)));
				if (BlockNumber > 0)
					Map.push_back(Var::Set::Integer(BlockNumber));
				Map.push_back(Var::Set::String(Filter.AsCondition()));
				Map.push_back(Var::Set::Integer(Filter.Value));
				Map.push_back(Var::Set::String(Indices.substr(0, Indices.size() - 1)));

				Template = !BlockNumber ?
					"SELECT (SELECT row_hash FROM rows WHERE rows.row_number = sq.row_number) AS row_hash, block_number FROM (SELECT ROW_NUMBER() OVER (ORDER BY factor $?, row_number ASC) AS id, row_number, block_number FROM multiforms WHERE column_number = ? AND factor $? ?) AS sq WHERE sq.id IN ($?)" :
					"SELECT (SELECT row_hash FROM rows WHERE rows.row_number = sq.row_number) AS row_hash, block_number FROM (SELECT ROW_NUMBER() OVER (ORDER BY factor $?, row_number ASC) AS id, row_number, block_number FROM (SELECT column_number, row_number, factor, MAX(block_number) AS block_number FROM multiformtries WHERE column_number = ? AND block_number < ? GROUP BY row_number) AS queryforms WHERE factor $? ?) AS sq WHERE sq.id IN ($?)";
			}

			auto Cursor = EmplaceQuery(*Multiformdata, Label, __func__, Template, &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<UPtr<Ledger::State>>>(LayerException(ErrorOf(Cursor)));

			Vector<UPtr<Ledger::State>> Values;
			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			for (size_t i = 0; i < Size; i++)
			{
				auto Next = Response[i];
				Format::Stream Message = Format::Stream(Load(Label, __func__, GetMultiformLabel(Column, Next["row_hash"].Get().GetBlob(), Next["block_number"].Get().GetInteger())).Or(String()));
				UPtr<Ledger::State> NextState = States::Resolver::New(Messages::Generic::ResolveType(Message).Or(0));
				if (!NextState || !NextState->Load(Message))
				{
					if (NextState && Delta != nullptr && Delta->Incoming != nullptr)
						((Ledger::BlockMutation*)Delta)->Incoming->ClearMultiform(Column, ((Ledger::Multiform*)*NextState)->AsRow());
					continue;
				}
				else if (Delta != nullptr && Delta->Incoming != nullptr)
					((Ledger::BlockMutation*)Delta)->Incoming->CopyAny(*NextState);
				Values.push_back(std::move(NextState));
			}

			return Values;
		}
		ExpectsLR<Vector<UPtr<Ledger::State>>> Chainstate::GetMultiformsByRow(const Ledger::BlockMutation* Delta, const std::string_view& Row, uint64_t BlockNumber, size_t Offset, size_t Count)
		{
			auto Location = ResolveMultiformLocation(Optional::None, Row, false);
			if (!Location)
				return ExpectsLR<Vector<UPtr<Ledger::State>>>(Vector<UPtr<Ledger::State>>());

			SchemaList Map;
			Map.push_back(Var::Set::Integer(Location->Column.Or(0)));
			if (BlockNumber > 0)
				Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(*Multiformdata, Label, __func__, !BlockNumber ?
				"SELECT (SELECT column_hash FROM columns WHERE columns.column_number = multiforms.column_number) AS column_hash, block_number FROM multiforms WHERE row_number = ? ORDER BY column_number LIMIT ? OFFSET ?" :
				"SELECT (SELECT column_hash FROM columns WHERE columns.column_number = multiformtries.column_number) AS column_hash, MAX(block_number) AS block_number FROM multiformtries WHERE row_number = ? AND block_number < ? GROUP BY column_number ORDER BY column_number LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<UPtr<Ledger::State>>>(LayerException(ErrorOf(Cursor)));

			Vector<UPtr<Ledger::State>> Values;
			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			for (size_t i = 0; i < Size; i++)
			{
				auto Next = Response[i];
				Format::Stream Message = Format::Stream(Load(Label, __func__, GetMultiformLabel(Next["column_hash"].Get().GetBlob(), Row, Next["block_number"].Get().GetInteger())).Or(String()));
				UPtr<Ledger::State> NextState = States::Resolver::New(Messages::Generic::ResolveType(Message).Or(0));
				if (!NextState || !NextState->Load(Message))
				{
					if (NextState && Delta != nullptr && Delta->Incoming != nullptr)
						((Ledger::BlockMutation*)Delta)->Incoming->ClearMultiform(((Ledger::Multiform*)*NextState)->AsColumn(), Row);
					continue;
				}
				else if (Delta != nullptr && Delta->Incoming != nullptr)
					((Ledger::BlockMutation*)Delta)->Incoming->CopyAny(*NextState);
				Values.push_back(std::move(NextState));
			}

			return Values;
		}
		ExpectsLR<Vector<UPtr<Ledger::State>>> Chainstate::GetMultiformsByRowFilter(const Ledger::BlockMutation* Delta, const std::string_view& Row, const FactorFilter& Filter, uint64_t BlockNumber, const FactorWindow& Window)
		{
			auto Location = ResolveMultiformLocation(Optional::None, Row, false);
			if (!Location)
				return ExpectsLR<Vector<UPtr<Ledger::State>>>(Vector<UPtr<Ledger::State>>());

			SchemaList Map; String Template;
			if (Window.Type() == FactorRangeWindow::InstanceType())
			{
				auto& Range = *(FactorRangeWindow*)&Window;
				Map.push_back(Var::Set::Integer(Location->Row.Or(0)));
				if (BlockNumber > 0)
					Map.push_back(Var::Set::Integer(BlockNumber));
				Map.push_back(Var::Set::String(Filter.AsCondition()));
				Map.push_back(Var::Set::Integer(Filter.Value));
				Map.push_back(Var::Set::String(Filter.AsOrder()));
				Map.push_back(Var::Set::Integer(Range.Count));
				Map.push_back(Var::Set::Integer(Range.Offset));

				Template = !BlockNumber ?
					"SELECT (SELECT column_hash FROM columns WHERE columns.column_number = multiforms.column_number) AS column_hash, block_number FROM multiforms WHERE row_number = ? AND factor $? ? ORDER BY factor $?, column_number ASC LIMIT ? OFFSET ?" :
					"SELECT (SELECT column_hash FROM columns WHERE columns.column_number = queryforms.column_number) AS column_hash, block_number FROM (SELECT column_number, row_number, factor, MAX(block_number) AS block_number FROM multiformtries WHERE row_number = ? AND block_number < ? GROUP BY column_number) AS queryforms WHERE factor $? ? ORDER BY factor $?, column_number ASC LIMIT ? OFFSET ?";
			}
			else if (Window.Type() == FactorIndexWindow::InstanceType())
			{
				String Indices;
				for (auto& Item : ((FactorIndexWindow*)&Window)->Indices)
					Indices += ToString(Item + 1) + ",";

				Map.push_back(Var::Set::String(Filter.AsOrder()));
				Map.push_back(Var::Set::Integer(Location->Row.Or(0)));
				if (BlockNumber > 0)
					Map.push_back(Var::Set::Integer(BlockNumber));
				Map.push_back(Var::Set::String(Filter.AsCondition()));
				Map.push_back(Var::Set::Integer(Filter.Value));
				Map.push_back(Var::Set::String(Indices.substr(0, Indices.size() - 1)));

				Template = !BlockNumber ?
					"SELECT (SELECT column_hash FROM columns WHERE columns.column_number = sq.column_number) AS column_hash, block_number FROM (SELECT ROW_NUMBER() OVER (ORDER BY factor $?, column_number ASC) AS id, column_number, block_number FROM multiforms WHERE row_number = ? AND factor $? ?) AS sq WHERE sq.id IN ($?) ORDER BY sq.id ASC" :
					"SELECT (SELECT column_hash FROM columns WHERE columns.column_number = sq.column_number) AS column_hash, block_number FROM (SELECT ROW_NUMBER() OVER (ORDER BY factor $?, column_number ASC) AS id, column_number, block_number FROM (SELECT column_number, row_number, factor, MAX(block_number) AS block_number FROM multiformtries WHERE row_number = ? AND block_number < ? GROUP BY column_number) AS queryforms WHERE factor $? ?) AS sq WHERE sq.id IN ($?) ORDER BY sq.id ASC";
			}

			auto Cursor = EmplaceQuery(*Multiformdata, Label, __func__, Template, &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<UPtr<Ledger::State>>>(LayerException(ErrorOf(Cursor)));

			Vector<UPtr<Ledger::State>> Values;
			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			for (size_t i = 0; i < Size; i++)
			{
				auto Next = Response[i];
				Format::Stream Message = Format::Stream(Load(Label, __func__, GetMultiformLabel(Next["column_hash"].Get().GetBlob(), Row, Next["block_number"].Get().GetInteger())).Or(String()));
				UPtr<Ledger::State> NextState = States::Resolver::New(Messages::Generic::ResolveType(Message).Or(0));
				if (!NextState || !NextState->Load(Message))
				{
					if (NextState && Delta != nullptr && Delta->Incoming != nullptr)
						((Ledger::BlockMutation*)Delta)->Incoming->ClearMultiform(((Ledger::Multiform*)*NextState)->AsColumn(), Row);
					continue;
				}
				else if (Delta != nullptr && Delta->Incoming != nullptr)
					((Ledger::BlockMutation*)Delta)->Incoming->CopyAny(*NextState);
				Values.push_back(std::move(NextState));
			}

			return Values;
		}
		ExpectsLR<size_t> Chainstate::GetMultiformsCountByColumn(const std::string_view& Column, uint64_t BlockNumber)
		{
			auto Location = ResolveMultiformLocation(Column, Optional::None, false);
			if (!Location)
				return Location.Error();

			SchemaList Map;
			Map.push_back(Var::Set::Integer(Location->Column.Or(0)));
			if (BlockNumber > 0)
				Map.push_back(Var::Set::Integer(BlockNumber));

			auto Cursor = EmplaceQuery(*Multiformdata, Label, __func__, !BlockNumber ? "SELECT COUNT(1) AS multiform_count FROM multiforms WHERE column_number = ?" : "SELECT COUNT(1) AS multiform_count FROM (SELECT MAX(block_number) FROM multiformtries WHERE column_number = ? AND block_number < ? GROUP BY row_number)", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<size_t>(LayerException(ErrorOf(Cursor)));

			size_t Count = (*Cursor)["multiform_count"].Get().GetInteger();
			return ExpectsLR<size_t>(Count);
		}
		ExpectsLR<size_t> Chainstate::GetMultiformsCountByColumnFilter(const std::string_view& Column, const FactorFilter& Filter, uint64_t BlockNumber)
		{
			auto Location = ResolveMultiformLocation(Column, Optional::None, false);
			if (!Location)
				return Location.Error();

			SchemaList Map;
			Map.push_back(Var::Set::Integer(Location->Column.Or(0)));
			if (BlockNumber > 0)
				Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::String(Filter.AsCondition()));
			Map.push_back(Var::Set::Integer(Filter.Value));

			auto Cursor = EmplaceQuery(*Multiformdata, Label, __func__, !BlockNumber ? "SELECT COUNT(1) AS multiform_count FROM multiforms WHERE column_number = ? AND factor $? ?" : "SELECT COUNT(1) AS multiform_count FROM (SELECT factor, MAX(block_number) FROM multiformtries WHERE column_number = ? AND block_number < ? GROUP BY row_number) WHERE factor $? ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<size_t>(LayerException(ErrorOf(Cursor)));

			size_t Count = (*Cursor)["multiform_count"].Get().GetInteger();
			return ExpectsLR<size_t>(Count);
		}
		ExpectsLR<size_t> Chainstate::GetMultiformsCountByRow(const std::string_view& Row, uint64_t BlockNumber)
		{
			auto Location = ResolveMultiformLocation(Optional::None, Row, false);
			if (!Location)
				return Location.Error();

			SchemaList Map;
			Map.push_back(Var::Set::Integer(Location->Row.Or(0)));
			if (BlockNumber > 0)
				Map.push_back(Var::Set::Integer(BlockNumber));

			auto Cursor = EmplaceQuery(*Multiformdata, Label, __func__, !BlockNumber ? "SELECT COUNT(1) AS multiform_count FROM multiforms WHERE row_number = ?" : "SELECT COUNT(1) AS multiform_count FROM (SELECT MAX(block_number) FROM multiformtries WHERE row_number = ? AND block_number < ? GROUP BY column_number)", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<size_t>(LayerException(ErrorOf(Cursor)));

			size_t Count = (*Cursor)["multiform_count"].Get().GetInteger();
			return ExpectsLR<size_t>(Count);
		}
		ExpectsLR<size_t> Chainstate::GetMultiformsCountByRowFilter(const std::string_view& Row, const FactorFilter& Filter, uint64_t BlockNumber)
		{
			auto Location = ResolveMultiformLocation(Optional::None, Row, false);
			if (!Location)
				return Location.Error();

			SchemaList Map;
			Map.push_back(Var::Set::Integer(Location->Row.Or(0)));
			if (BlockNumber > 0)
				Map.push_back(Var::Set::Integer(BlockNumber));
			Map.push_back(Var::Set::String(Filter.AsCondition()));
			Map.push_back(Var::Set::Integer(Filter.Value));

			auto Cursor = EmplaceQuery(*Multiformdata, Label, __func__, !BlockNumber ? "SELECT COUNT(1) AS multiform_count FROM multiforms WHERE row_number = ? AND factor $? ?" : "SELECT COUNT(1) AS multiform_count FROM (SELECT factor, MAX(block_number) FROM multiformtries WHERE row_number = ? AND block_number < ? GROUP BY column_number) WHERE factor $? ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<size_t>(LayerException(ErrorOf(Cursor)));

			size_t Count = (*Cursor)["multiform_count"].Get().GetInteger();
			return ExpectsLR<size_t>(Count);
		}
		void Chainstate::ClearIndexerCache()
		{
			AccountCache::CleanupInstance();
			UniformCache::CleanupInstance();
			MultiformCache::CleanupInstance();
		}
		Vector<LDB::Connection*> Chainstate::GetIndexStorages()
		{
			Vector<LDB::Connection*> Index;
			Index.push_back(*Blockdata);
			Index.push_back(*Accountdata);
			Index.push_back(*Txdata);
			Index.push_back(*Partydata);
			Index.push_back(*Aliasdata);
			Index.push_back(*Uniformdata);
			Index.push_back(*Multiformdata);
			return Index;
		}
		bool Chainstate::ReconstructIndexStorage(LDB::Connection* Storage, const std::string_view& Name)
		{
			String Command;
			if (Name == "blockdata")
			{
				Command = VI_STRINGIFY((
					CREATE TABLE IF NOT EXISTS blocks
					(
					block_number BIGINT NOT NULL,
					block_hash BINARY(32) NOT NULL,
					PRIMARY KEY (block_hash)
				) WITHOUT ROWID;
				CREATE UNIQUE INDEX IF NOT EXISTS blocks_block_number ON blocks (block_number);
				CREATE TABLE IF NOT EXISTS checkpoints
				(
					block_number BIGINT NOT NULL,
					PRIMARY KEY (block_number)
				) WITHOUT ROWID;));
			}
			else if (Name == "accountdata")
			{
				Command = VI_STRINGIFY((
					CREATE TABLE IF NOT EXISTS accounts
					(
						account_number BIGINT NOT NULL,
						account_hash BINARY(20) NOT NULL,
						block_number BIGINT NOT NULL,
						PRIMARY KEY (account_number)
					) WITHOUT ROWID;
					CREATE UNIQUE INDEX IF NOT EXISTS accounts_account_hash ON accounts (account_hash);
					CREATE INDEX IF NOT EXISTS accounts_block_number ON accounts (block_number);));
			}
			else if (Name == "txdata")
			{
				Command = VI_STRINGIFY((
					CREATE TABLE IF NOT EXISTS transactions
					(
						transaction_number BIGINT NOT NULL,
						transaction_hash BINARY(32) NOT NULL,
						dispatch_queue BIGINT DEFAULT NULL,
						block_number BIGINT NOT NULL,
						block_nonce BIGINT NOT NULL,
						PRIMARY KEY (transaction_hash)
					) WITHOUT ROWID;
					CREATE UNIQUE INDEX IF NOT EXISTS transactions_transaction_number ON transactions (transaction_number);
					CREATE INDEX IF NOT EXISTS transactions_dispatch_queue_block_nonce ON transactions (dispatch_queue, block_nonce) WHERE dispatch_queue IS NOT NULL;
					CREATE INDEX IF NOT EXISTS transactions_block_number_block_nonce ON transactions (block_number, block_nonce);));
			}
			else if (Name == "partydata")
			{
				Command = VI_STRINGIFY((
					CREATE TABLE IF NOT EXISTS parties
					(
						transaction_number BIGINT NOT NULL,
						transaction_account_number BIGINT NOT NULL,
						block_number BIGINT NOT NULL,
						PRIMARY KEY (transaction_account_number, block_number, transaction_number)
					) WITHOUT ROWID;
					CREATE INDEX IF NOT EXISTS parties_block_number ON parties (block_number);));
			}
			else if (Name == "aliasdata")
			{
				Command = VI_STRINGIFY((
					CREATE TABLE IF NOT EXISTS aliases
					(
						transaction_number BIGINT NOT NULL,
						transaction_hash BINARY(32) NOT NULL,
						block_number BIGINT NOT NULL,
						PRIMARY KEY (transaction_hash, transaction_number)
					) WITHOUT ROWID;
					CREATE INDEX IF NOT EXISTS aliases_block_number ON aliases (block_number);));
			}
			else if (Name == "uniformdata")
			{
				Command = VI_STRINGIFY((
					CREATE TABLE IF NOT EXISTS indices
					(
						index_number BIGINT NOT NULL,
						index_hash BINARY NOT NULL,
						block_number BIGINT NOT NULL,
						PRIMARY KEY (index_number)
					) WITHOUT ROWID;
					CREATE UNIQUE INDEX IF NOT EXISTS indices_index_hash ON indices (index_hash);
					CREATE INDEX IF NOT EXISTS indices_block_number ON indices (block_number);
					CREATE TABLE IF NOT EXISTS uniforms
					(
						index_number BIGINT NOT NULL,
						block_number BIGINT NOT NULL,
						PRIMARY KEY (index_number)
					) WITHOUT ROWID;
					CREATE INDEX IF NOT EXISTS uniforms_block_number ON uniforms (block_number);
					CREATE TABLE IF NOT EXISTS uniformtries
					(
						index_number BIGINT NOT NULL,
						block_number BIGINT NOT NULL,
						PRIMARY KEY (index_number, block_number)
					) WITHOUT ROWID;
					CREATE INDEX IF NOT EXISTS uniformtries_block_number ON uniformtries (block_number);));
			}
			else if (Name == "multiformdata")
			{
				Command = VI_STRINGIFY((
					CREATE TABLE IF NOT EXISTS columns
					(
						column_number BIGINT NOT NULL,
						column_hash BINARY NOT NULL,
						block_number BIGINT NOT NULL,
						PRIMARY KEY (column_number)
					) WITHOUT ROWID;
					CREATE UNIQUE INDEX IF NOT EXISTS columns_column_hash ON columns (column_hash);
					CREATE INDEX IF NOT EXISTS columns_block_number ON columns (block_number);
					CREATE TABLE IF NOT EXISTS rows
					(
						row_number BIGINT NOT NULL,
						row_hash BINARY NOT NULL,
						block_number BIGINT NOT NULL,
						PRIMARY KEY (row_number)
					) WITHOUT ROWID;
					CREATE UNIQUE INDEX IF NOT EXISTS rows_row_hash ON rows (row_hash);
					CREATE INDEX IF NOT EXISTS rows_block_number ON rows (block_number);
					CREATE TABLE IF NOT EXISTS multiforms
					(
						column_number BIGINT NOT NULL,
						row_number BIGINT NOT NULL,
						factor BIGINT NOT NULL,
						block_number BIGINT NOT NULL,
						PRIMARY KEY (column_number, row_number)
					) WITHOUT ROWID;
					CREATE INDEX IF NOT EXISTS multiforms_row_number_column_number ON multiforms (row_number, column_number);
					CREATE INDEX IF NOT EXISTS multiforms_row_number_factor ON multiforms (row_number, factor);
					CREATE INDEX IF NOT EXISTS multiforms_block_number ON multiforms (block_number);
					CREATE TABLE IF NOT EXISTS multiformtries
					(
						column_number BIGINT NOT NULL,
						row_number BIGINT NOT NULL,
						factor BIGINT NOT NULL,
						block_number BIGINT NOT NULL,
						PRIMARY KEY (column_number, row_number, block_number)
					) WITHOUT ROWID;
					CREATE INDEX IF NOT EXISTS multiformtries_row_number_block_number ON multiformtries (row_number, block_number);
					CREATE INDEX IF NOT EXISTS multiformtries_column_number_block_number ON multiformtries (column_number, block_number);
					CREATE INDEX IF NOT EXISTS multiformtries_block_number ON multiformtries (block_number);));
			}

			Command.front() = ' ';
			Command.back() = ' ';
			Stringify::Trim(Command);
			auto Cursor = Query(Storage, Label, __func__, Command);
			return (Cursor && !Cursor->Error());
		}
	}
}