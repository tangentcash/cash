#ifndef TAN_POLICY_STORAGE_H
#define TAN_POLICY_STORAGE_H
#include "../kernel/oracle.h"
#include "../kernel/storage.h"
#include "../kernel/block.h"

namespace Tangent
{
	namespace Storages
	{
		enum class FeePriority
		{
			Fastest,
			Fast,
			Medium,
			Slow
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

		enum class Pruning
		{
			Blocktrie = 1 << 0,
			Transactiontrie = 1 << 1,
			Statetrie = 1 << 2
		};

		class LocationCache : public Singleton<LocationCache>
		{
		private:
			UnorderedMap<String, uint64_t> Addresses;
			UnorderedMap<String, uint64_t> Strides;
			UnorderedMap<String, uint64_t> Owners;
			std::mutex Mutex;

		public:
			LocationCache() = default;
			virtual ~LocationCache() = default;
			void ClearLocations();
			void ClearLocation(const Option<String>& Address, const Option<String>& Stride, const Option<String>& Owner);
			void SetStateLocation(const std::string_view& Address, const std::string_view& Stride, uint64_t AddressLocation, uint64_t StrideLocation);
			void SetAddressLocation(const std::string_view& Hash, uint64_t Location);
			void SetStrideLocation(const std::string_view& Hash, uint64_t Location);
			void SetOwnerLocation(const std::string_view& Hash, uint64_t Location);
			Option<uint64_t> GetAddressLocation(const std::string_view& Hash);
			Option<uint64_t> GetStrideLocation(const std::string_view& Hash);
			Option<uint64_t> GetOwnerLocation(const std::string_view& Hash);
		};

		struct WeightQuery
		{
			PositionCondition Condition = PositionCondition::Equal;
			int64_t Value = 0;
			int8_t Order = 0;

			std::string_view AsCondition() const;
			std::string_view AsOrder() const;
			static WeightQuery From(const std::string_view& Query, int64_t Value, int8_t Order);
			static WeightQuery Greater(int64_t Value, int8_t Order) { return { PositionCondition::Greater, Value, Order }; }
			static WeightQuery GreaterEqual(int64_t Value, int8_t Order) { return { PositionCondition::GreaterEqual, Value, Order }; }
			static WeightQuery Equal(int64_t Value, int8_t Order) { return { PositionCondition::Equal, Value, Order }; }
			static WeightQuery NotEqual(int64_t Value, int8_t Order) { return { PositionCondition::NotEqual, Value, Order }; }
			static WeightQuery Less(int64_t Value, int8_t Order) { return { PositionCondition::Less, Value, Order }; }
			static WeightQuery LessEqual(int64_t Value, int8_t Order) { return { PositionCondition::LessEqual, Value, Order }; }
		};

		struct Chainstate : Ledger::PermanentStorage
		{
		private:
			LDB::Connection* Blockdata;
			LDB::Connection* Txdata;
			LDB::Connection* Statedata;
			std::string_view Label;
			bool Borrows;

		public:
			Chainstate(const std::string_view& NewLabel) noexcept;
			virtual ~Chainstate() noexcept override;
			ExpectsLR<void> Revert(uint64_t BlockNumber);
			ExpectsLR<void> Dispatch(const Vector<uint256_t>& TransactionHashes);
			ExpectsLR<void> Prune(uint32_t Types, uint64_t BlockNumber);
			ExpectsLR<void> Checkpoint(const Ledger::Block& Value);
			ExpectsLR<uint64_t> GetCheckpointBlockNumber();
			ExpectsLR<uint64_t> GetLatestBlockNumber();
			ExpectsLR<uint64_t> GetBlockNumberByHash(const uint256_t& BlockHash);
			ExpectsLR<uint256_t> GetBlockHashByNumber(uint64_t BlockNumber);
			ExpectsLR<Decimal> GetBlockGasPrice(uint64_t BlockNumber, const Algorithm::AssetId& Asset, double Percentile);
			ExpectsLR<Decimal> GetBlockAssetPrice(uint64_t BlockNumber, const Algorithm::AssetId& PriceOf, const Algorithm::AssetId& RelativeTo, double Percentile);
			ExpectsLR<Ledger::Block> GetBlockByNumber(uint64_t BlockNumber, size_t LoadRate = 512);
			ExpectsLR<Ledger::Block> GetBlockByHash(const uint256_t& BlockHash, size_t LoadRate = 512);
			ExpectsLR<Ledger::Block> GetLatestBlock(size_t LoadRate = 512);
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
			ExpectsLR<Vector<UPtr<Ledger::Transaction>>> GetTransactionsByOwner(uint64_t BlockNumber, const Algorithm::Pubkeyhash Owner, size_t Offset, size_t Count);
			ExpectsLR<Vector<Ledger::BlockTransaction>> GetBlockTransactionsByNumber(uint64_t BlockNumber, size_t Offset, size_t Count);
			ExpectsLR<Vector<Ledger::BlockTransaction>> GetBlockTransactionsByOwner(uint64_t BlockNumber, const Algorithm::Pubkeyhash Owner, size_t Offset, size_t Count);
			ExpectsLR<Vector<Ledger::Receipt>> GetBlockReceiptsByNumber(uint64_t BlockNumber, size_t Offset, size_t Count);
			ExpectsLR<Vector<Ledger::BlockTransaction>> GetPendingBlockTransactions(uint64_t BlockNumber, size_t Offset, size_t Count);
			ExpectsLR<UPtr<Ledger::Transaction>> GetTransactionByHash(const uint256_t& TransactionHash);
			ExpectsLR<UPtr<Ledger::Transaction>> GetTransactionByReceiptHash(const uint256_t& ReceiptHash);
			ExpectsLR<Ledger::BlockTransaction> GetBlockTransactionByHash(const uint256_t& TransactionHash);
			ExpectsLR<Ledger::BlockTransaction> GetBlockTransactionByReceiptHash(const uint256_t& ReceiptHash);
			ExpectsLR<Ledger::Receipt> GetReceiptByHash(const uint256_t& ReceiptHash);
			ExpectsLR<Ledger::Receipt> GetReceiptByTransactionHash(const uint256_t& TransactionHash);
			ExpectsLR<UPtr<Ledger::State>> GetStateByComposition(const Ledger::BlockMutation* Delta, const std::string_view& Address, const std::string_view& Stride, uint64_t BlockNumber);
			ExpectsLR<UPtr<Ledger::State>> GetStateByAddress(const Ledger::BlockMutation* Delta, const std::string_view& Address, uint64_t BlockNumber, size_t Offset);
			ExpectsLR<UPtr<Ledger::State>> GetStateByStride(const Ledger::BlockMutation* Delta, const std::string_view& Stride, uint64_t BlockNumber, size_t Offset);
			ExpectsLR<Vector<UPtr<Ledger::State>>> GetStatesByAddress(const Ledger::BlockMutation* Delta, const std::string_view& Address, uint64_t BlockNumber, size_t Offset, size_t Count);
			ExpectsLR<Vector<UPtr<Ledger::State>>> GetStatesByStride(const Ledger::BlockMutation* Delta, const std::string_view& Stride, const WeightQuery& Weight, uint64_t BlockNumber, size_t Offset, size_t Count);
			ExpectsLR<size_t> GetStatesCountByStride(const std::string_view& Stride, const WeightQuery& Weight, uint64_t BlockNumber);

		private:
			ExpectsLR<size_t> ResolveBlockTransactions(Ledger::Block& Value, size_t Offset, size_t Count);
			ExpectsLR<size_t> ResolveBlockStatetrie(Ledger::Block& Value, size_t Offset, size_t Count);
			ExpectsLR<std::pair<uint64_t, uint64_t>> ResolveStateLocation(const Option<std::string_view>& Address, const Option<std::string_view>& Stride);
			ExpectsLR<uint64_t> ResolveOwnerLocation(const Algorithm::Pubkeyhash Owner);

		protected:
			bool Verify(LDB::Connection* Storage, const std::string_view& Name) override;
		};

		struct Mempoolstate : Ledger::MutableStorage
		{
		private:
			std::string_view Label;
			bool Borrows;

		public:
			Mempoolstate(const std::string_view& NewLabel) noexcept;
			virtual ~Mempoolstate() noexcept override;
			ExpectsLR<void> SetSeed(const std::string_view& Address);
			ExpectsLR<void> SetValidator(const Ledger::Edge& Node, Option<Ledger::Wallet>&& Wallet);
			ExpectsLR<void> ClearValidator(const std::string_view& ValidatorAddress);
			ExpectsLR<std::pair<Ledger::Edge, Ledger::Wallet>> GetValidatorByOwnership(size_t Offset);
			ExpectsLR<Ledger::Edge> GetValidatorByAddress(const std::string_view& ValidatorAddress);
			ExpectsLR<Ledger::Edge> GetValidatorByPreference(size_t Offset);
			ExpectsLR<Vector<String>> GetSeeds(size_t Count);
			ExpectsLR<String> PopSeed();
			ExpectsLR<size_t> GetValidatorsCount();
			ExpectsLR<Decimal> GetGasPrice(const Algorithm::AssetId& Asset, double PriorityPercentile);
			ExpectsLR<Decimal> GetAssetPrice(const Algorithm::AssetId& PriceOf, const Algorithm::AssetId& RelativeTo, double PriorityPercentile = 0.5);
			ExpectsLR<void> AddTransaction(Ledger::Transaction& Value);
			ExpectsLR<void> RemoveTransactions(const Vector<uint256_t>& TransactionHashes);
			ExpectsLR<void> RemoveTransactions(const UnorderedSet<uint256_t>& TransactionHashes);
			ExpectsLR<bool> HasTransaction(const uint256_t& TransactionHash);
			ExpectsLR<uint64_t> GetLowestTransactionSequence(const Algorithm::Pubkeyhash Owner);
			ExpectsLR<uint64_t> GetHighestTransactionSequence(const Algorithm::Pubkeyhash Owner);
			ExpectsLR<UPtr<Ledger::Transaction>> GetTransactionByHash(const uint256_t& TransactionHash);
			ExpectsLR<Vector<UPtr<Ledger::Transaction>>> GetTransactions(size_t Offset, size_t Count);
			ExpectsLR<Vector<UPtr<Ledger::Transaction>>> GetCumulativeEventTransactions(const uint256_t& CumulativeHash, size_t Offset, size_t Count);
			ExpectsLR<Vector<uint256_t>> GetTransactionHashset(size_t Offset, size_t Count);

		public:
			static double FeePercentile(FeePriority Priority);

		protected:
			bool Verify() override;
		};

		struct Sidechainstate : Ledger::MutableStorage
		{
		private:
			Algorithm::AssetId Asset;
			std::string_view Label;

		public:
			Sidechainstate(const std::string_view& NewLabel, const Algorithm::AssetId& NewAsset) noexcept;
			virtual ~Sidechainstate() noexcept = default;
			ExpectsLR<void> AddMasterWallet(const Oracle::MasterWallet& Value);
			ExpectsLR<Oracle::MasterWallet> GetMasterWallet();
			ExpectsLR<Oracle::MasterWallet> GetMasterWalletByHash(const uint256_t& MasterWalletHash);
			ExpectsLR<void> AddDerivedWallet(const Oracle::MasterWallet& Parent, const Oracle::DerivedSigningWallet& Value);
			ExpectsLR<Oracle::DerivedSigningWallet> GetDerivedWallet(const uint256_t& MasterWalletHash, uint64_t AddressIndex);
			ExpectsLR<void> AddUTXO(const Oracle::IndexUTXO& Value);
			ExpectsLR<void> RemoveUTXO(const std::string_view& TransactionId, uint32_t Index);
			ExpectsLR<Oracle::IndexUTXO> GetSTXO(const std::string_view& TransactionId, uint32_t Index);
			ExpectsLR<Oracle::IndexUTXO> GetUTXO(const std::string_view& TransactionId, uint32_t Index);
			ExpectsLR<Vector<Oracle::IndexUTXO>> GetUTXOs(const std::string_view& Binding, size_t Offset, size_t Count);
			ExpectsLR<void> AddIncomingTransaction(const Oracle::IncomingTransaction& Value, uint64_t BlockId);
			ExpectsLR<void> AddOutgoingTransaction(const Oracle::IncomingTransaction& Value, const uint256_t ExternalId);
			ExpectsLR<Oracle::IncomingTransaction> GetTransaction(const std::string_view& TransactionId, const uint256_t& ExternalId);
			ExpectsLR<Vector<Oracle::IncomingTransaction>> ApproveTransactions(uint64_t BlockHeight, uint64_t BlockLatency);
			ExpectsLR<void> SetProperty(const std::string_view& Key, UPtr<Schema>&& Value);
			ExpectsLR<Schema*> GetProperty(const std::string_view& Key);
			ExpectsLR<void> SetCache(Oracle::CachePolicy Policy, const std::string_view& Key, UPtr<Schema>&& Value);
			ExpectsLR<Schema*> GetCache(Oracle::CachePolicy Policy, const std::string_view& Key);
			ExpectsLR<void> SetAddressIndex(const std::string_view& Address, const Oracle::IndexAddress& Value);
			ExpectsLR<Oracle::IndexAddress> GetAddressIndex(const std::string_view& Address);
			ExpectsLR<UnorderedMap<String, Oracle::IndexAddress>> GetAddressIndices(const UnorderedSet<String>& Addresses);
			ExpectsLR<Vector<String>> GetAddressIndices();

		protected:
			String GetAddressLocation(const std::string_view& Address);
			String GetTransactionLocation(const std::string_view& TransactionId);
			String GetCoinLocation(const std::string_view& TransactionId, uint32_t Index);
			bool Verify() override;

		private:
			static std::string_view GetCacheLocation(Oracle::CachePolicy Policy);
		};
	}
}
#endif