#ifndef TAN_STORAGE_CHAINSTATE_H
#define TAN_STORAGE_CHAINSTATE_H
#include "engine.h"
#include "../kernel/block.h"

namespace Tangent
{
	namespace Storages
	{
		enum
		{
			LOAD_RATE = 512
		};

		enum class PositionCondition
		{
			Greater,
			GreaterEqual,
			Equal,
			NotEqual,
			Less,
			LessEqual
		};

		enum class BlockDetails
		{
			Transactions = 1 << 0,
			BlockTransactions = 1 << 1,
			States = 1 << 2
		};

		enum class Pruning
		{
			Blocktrie = 1 << 0,
			Transactiontrie = 1 << 1,
			Statetrie = 1 << 2
		};

		class AccountCache : public Singleton<AccountCache>
		{
		private:
			UnorderedMap<String, uint64_t> Accounts;
			std::mutex Mutex;

		public:
			AccountCache() = default;
			virtual ~AccountCache() = default;
			void ClearLocations();
			void ClearAccountLocation(const Algorithm::Pubkeyhash Account);
			void SetAccountLocation(const Algorithm::Pubkeyhash Account, uint64_t Location);
			Option<uint64_t> GetAccountLocation(const std::string_view& Account);
		};

		class UniformCache : public Singleton<UniformCache>
		{
		private:
			UnorderedMap<String, uint64_t> Indices;
			UnorderedMap<uint64_t, uint64_t> Blocks;
			std::mutex Mutex;

		public:
			UniformCache() = default;
			virtual ~UniformCache() = default;
			void ClearLocations();
			void ClearUniformLocation(const std::string_view& Index);
			void ClearBlockLocation(const std::string_view& Index);
			void SetIndexLocation(const std::string_view& Index, uint64_t Location);
			void SetBlockLocation(uint64_t Location, uint64_t BlockNumber);
			Option<uint64_t> GetIndexLocation(const std::string_view& Index);
			Option<uint64_t> GetBlockLocation(uint64_t Location);
		};

		class MultiformCache : public Singleton<MultiformCache>
		{
		private:
			UnorderedMap<String, uint64_t> Columns;
			UnorderedMap<String, uint64_t> Rows;
			UnorderedMap<uint128_t, uint64_t> Blocks;
			std::mutex Mutex;

		public:
			MultiformCache() = default;
			virtual ~MultiformCache() = default;
			void ClearLocations();
			void ClearMultiformLocation(const std::string_view& Column, const std::string_view& Row);
			void ClearBlockLocation(const std::string_view& Column, const std::string_view& Row);
			void SetMultiformLocation(const std::string_view& Column, const std::string_view& Row, uint64_t ColumnLocation, uint64_t RowLocation);
			void SetColumnLocation(const std::string_view& Column, uint64_t Location);
			void SetRowLocation(const std::string_view& Row, uint64_t Location);
			void SetBlockLocation(uint64_t ColumnLocation, uint64_t RowLocation, uint64_t BlockNumber);
			Option<uint64_t> GetColumnLocation(const std::string_view& Column);
			Option<uint64_t> GetRowLocation(const std::string_view& Row);
			Option<uint64_t> GetBlockLocation(uint64_t ColumnLocation, uint64_t RowLocation);
		};

		struct FactorFilter
		{
			PositionCondition Condition = PositionCondition::Equal;
			int64_t Value = 0;
			int8_t Order = 0;

			std::string_view AsCondition() const;
			std::string_view AsOrder() const;
			static FactorFilter From(const std::string_view& Query, int64_t Value, int8_t Order);
			static FactorFilter Greater(int64_t Value, int8_t Order) { return { PositionCondition::Greater, Value, Order }; }
			static FactorFilter GreaterEqual(int64_t Value, int8_t Order) { return { PositionCondition::GreaterEqual, Value, Order }; }
			static FactorFilter Equal(int64_t Value, int8_t Order) { return { PositionCondition::Equal, Value, Order }; }
			static FactorFilter NotEqual(int64_t Value, int8_t Order) { return { PositionCondition::NotEqual, Value, Order }; }
			static FactorFilter Less(int64_t Value, int8_t Order) { return { PositionCondition::Less, Value, Order }; }
			static FactorFilter LessEqual(int64_t Value, int8_t Order) { return { PositionCondition::LessEqual, Value, Order }; }
		};

		struct Chainstate : Ledger::PermanentStorage
		{
		private:
			struct UniformLocation
			{
				Option<uint64_t> Index = Optional::None;
				Option<uint64_t> Block = Optional::None;
			};

			struct MultiformLocation
			{
				Option<uint64_t> Column = Optional::None;
				Option<uint64_t> Row = Optional::None;
				Option<uint64_t> Block = Optional::None;
			};

		private:
			UPtr<LDB::Connection> Blockdata;
			UPtr<LDB::Connection> Accountdata;
			UPtr<LDB::Connection> Txdata;
			UPtr<LDB::Connection> Partydata;
			UPtr<LDB::Connection> Aliasdata;
			UPtr<LDB::Connection> Uniformdata;
			UPtr<LDB::Connection> Multiformdata;
			std::string_view Label;
			bool Borrows;

		public:
			Chainstate(const std::string_view& NewLabel) noexcept;
			virtual ~Chainstate() noexcept override;
			ExpectsLR<void> Reorganize(int64_t* Blocktrie = nullptr, int64_t* Transactiontrie = nullptr, int64_t* Statetrie = nullptr);
			ExpectsLR<void> Revert(uint64_t BlockNumber, int64_t* Blocktrie = nullptr, int64_t* Transactiontrie = nullptr, int64_t* Statetrie = nullptr);
			ExpectsLR<void> Dispatch(const Vector<uint256_t>& TransactionHashes);
			ExpectsLR<void> Prune(uint32_t Types, uint64_t BlockNumber);
			ExpectsLR<void> Checkpoint(const Ledger::Block& Value, bool Reorganization = false);
			ExpectsLR<uint64_t> GetCheckpointBlockNumber();
			ExpectsLR<uint64_t> GetLatestBlockNumber();
			ExpectsLR<uint64_t> GetBlockNumberByHash(const uint256_t& BlockHash);
			ExpectsLR<uint256_t> GetBlockHashByNumber(uint64_t BlockNumber);
			ExpectsLR<Decimal> GetBlockGasPrice(uint64_t BlockNumber, const Algorithm::AssetId& Asset, double Percentile);
			ExpectsLR<Decimal> GetBlockAssetPrice(uint64_t BlockNumber, const Algorithm::AssetId& PriceOf, const Algorithm::AssetId& RelativeTo, double Percentile);
			ExpectsLR<Ledger::Block> GetBlockByNumber(uint64_t BlockNumber, size_t Chunk = LOAD_RATE, uint32_t Details = (uint32_t)BlockDetails::Transactions | (uint32_t)BlockDetails::BlockTransactions | (uint32_t)BlockDetails::States);
			ExpectsLR<Ledger::Block> GetBlockByHash(const uint256_t& BlockHash, size_t Chunk = LOAD_RATE, uint32_t Details = (uint32_t)BlockDetails::Transactions | (uint32_t)BlockDetails::BlockTransactions | (uint32_t)BlockDetails::States);
			ExpectsLR<Ledger::Block> GetLatestBlock(size_t Chunk = LOAD_RATE, uint32_t Details = (uint32_t)BlockDetails::Transactions | (uint32_t)BlockDetails::BlockTransactions | (uint32_t)BlockDetails::States);
			ExpectsLR<Ledger::BlockHeader> GetBlockHeaderByNumber(uint64_t BlockNumber);
			ExpectsLR<Ledger::BlockHeader> GetBlockHeaderByHash(const uint256_t& BlockHash);
			ExpectsLR<Ledger::BlockHeader> GetLatestBlockHeader();
			ExpectsLR<Ledger::BlockProof> GetBlockProofByNumber(uint64_t BlockNumber);
			ExpectsLR<Ledger::BlockProof> GetBlockProofByHash(const uint256_t& BlockHash);
			ExpectsLR<Vector<uint256_t>> GetBlockTransactionHashset(uint64_t BlockNumber);
			ExpectsLR<Vector<uint256_t>> GetBlockStatetrieHashset(uint64_t BlockNumber);
			ExpectsLR<Vector<uint256_t>> GetBlockHashset(uint64_t BlockNumber, size_t Count);
			ExpectsLR<Vector<Ledger::BlockHeader>> GetBlockHeaders(uint64_t BlockNumber, size_t Count);
			ExpectsLR<Ledger::StateWork> GetBlockStatetrieByNumber(uint64_t BlockNumber, size_t Offset, size_t Count);
			ExpectsLR<Vector<UPtr<Ledger::Transaction>>> GetTransactionsByNumber(uint64_t BlockNumber, size_t Offset, size_t Count);
			ExpectsLR<Vector<UPtr<Ledger::Transaction>>> GetTransactionsByOwner(uint64_t BlockNumber, const Algorithm::Pubkeyhash Owner, int8_t Direction, size_t Offset, size_t Count);
			ExpectsLR<Vector<Ledger::BlockTransaction>> GetBlockTransactionsByNumber(uint64_t BlockNumber, size_t Offset, size_t Count);
			ExpectsLR<Vector<Ledger::BlockTransaction>> GetBlockTransactionsByOwner(uint64_t BlockNumber, const Algorithm::Pubkeyhash Owner, int8_t Direction, size_t Offset, size_t Count);
			ExpectsLR<Vector<Ledger::Receipt>> GetBlockReceiptsByNumber(uint64_t BlockNumber, size_t Offset, size_t Count);
			ExpectsLR<Vector<Ledger::BlockTransaction>> GetPendingBlockTransactions(uint64_t BlockNumber, size_t Offset, size_t Count);
			ExpectsLR<UPtr<Ledger::Transaction>> GetTransactionByHash(const uint256_t& TransactionHash);
			ExpectsLR<Ledger::BlockTransaction> GetBlockTransactionByHash(const uint256_t& TransactionHash);
			ExpectsLR<Ledger::Receipt> GetReceiptByTransactionHash(const uint256_t& TransactionHash);
			ExpectsLR<UPtr<Ledger::State>> GetUniformByIndex(const Ledger::BlockMutation* Delta, const std::string_view& Index, uint64_t BlockNumber);
			ExpectsLR<UPtr<Ledger::State>> GetMultiformByComposition(const Ledger::BlockMutation* Delta, const std::string_view& Column, const std::string_view& Row, uint64_t BlockNumber);
			ExpectsLR<UPtr<Ledger::State>> GetMultiformByColumn(const Ledger::BlockMutation* Delta, const std::string_view& Column, uint64_t BlockNumber, size_t Offset);
			ExpectsLR<UPtr<Ledger::State>> GetMultiformByRow(const Ledger::BlockMutation* Delta, const std::string_view& Row, uint64_t BlockNumber, size_t Offset);
			ExpectsLR<Vector<UPtr<Ledger::State>>> GetMultiformsByColumn(const Ledger::BlockMutation* Delta, const std::string_view& Column, uint64_t BlockNumber, size_t Offset, size_t Count);
			ExpectsLR<Vector<UPtr<Ledger::State>>> GetMultiformsByColumnFilter(const Ledger::BlockMutation* Delta, const std::string_view& Column, const FactorFilter& Filter, uint64_t BlockNumber, size_t Offset, size_t Count);
			ExpectsLR<Vector<UPtr<Ledger::State>>> GetMultiformsByRow(const Ledger::BlockMutation* Delta, const std::string_view& Row, uint64_t BlockNumber, size_t Offset, size_t Count);
			ExpectsLR<Vector<UPtr<Ledger::State>>> GetMultiformsByRowFilter(const Ledger::BlockMutation* Delta, const std::string_view& Row, const FactorFilter& Filter, uint64_t BlockNumber, size_t Offset, size_t Count);
			ExpectsLR<size_t> GetMultiformsCountByColumn(const std::string_view& Row, uint64_t BlockNumber);
			ExpectsLR<size_t> GetMultiformsCountByColumnFilter(const std::string_view& Row, const FactorFilter& Filter, uint64_t BlockNumber);
			ExpectsLR<size_t> GetMultiformsCountByRow(const std::string_view& Row, uint64_t BlockNumber);
			ExpectsLR<size_t> GetMultiformsCountByRowFilter(const std::string_view& Row, const FactorFilter& Filter, uint64_t BlockNumber);

		private:
			ExpectsLR<size_t> ResolveBlockTransactions(Ledger::Block& Value, bool Fully, size_t Offset, size_t Count);
			ExpectsLR<size_t> ResolveBlockStatetrie(Ledger::Block& Value, size_t Offset, size_t Count);
			ExpectsLR<UniformLocation> ResolveUniformLocation(const std::string_view& Index, bool Latest);
			ExpectsLR<MultiformLocation> ResolveMultiformLocation(const Option<std::string_view>& Column, const Option<std::string_view>& Row, bool Latest);
			ExpectsLR<uint64_t> ResolveAccountLocation(const Algorithm::Pubkeyhash Account);

		protected:
			Vector<LDB::Connection*> GetIndexStorages() override;
			bool ReconstructIndexStorage(LDB::Connection* Storage, const std::string_view& Name) override;
		};
	}
}
#endif