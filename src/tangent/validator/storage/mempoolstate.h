#ifndef TAN_STORAGE_MEMPOOLSTATE_H
#define TAN_STORAGE_MEMPOOLSTATE_H
#include "engine.h"
#include "../../kernel/block.h"

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

		enum class NodeServices
		{
			Consensus = (1 << 0),
			Discovery = (1 << 1),
			Synchronization = (1 << 2),
			Interface = (1 << 3),
			Proposer = (1 << 4),
			Public = (1 << 5),
			Streaming = (1 << 6)
		};

		struct TAN_OUT AccountBandwidth
		{
			uint64_t Sequence = 0;
			size_t Count = 0;
			bool Congested = false;
		};

		struct TAN_OUT Mempoolstate : Ledger::MutableStorage
		{
		private:
			std::string_view Label;
			bool Borrows;

		public:
			Mempoolstate(const std::string_view& NewLabel) noexcept;
			virtual ~Mempoolstate() noexcept override;
			ExpectsLR<void> ApplyTrialAddress(const SocketAddress& Address);
			ExpectsLR<void> ApplyValidator(const Ledger::Validator& Node, Option<Ledger::Wallet>&& Wallet);
			ExpectsLR<void> ClearValidator(const SocketAddress& ValidatorAddress);
			ExpectsLR<std::pair<Ledger::Validator, Ledger::Wallet>> GetValidatorByOwnership(size_t Offset);
			ExpectsLR<Ledger::Validator> GetValidatorByAddress(const SocketAddress& ValidatorAddress);
			ExpectsLR<Ledger::Validator> GetValidatorByPreference(size_t Offset);
			ExpectsLR<Vector<SocketAddress>> GetValidatorAddresses(size_t Offset, size_t Count, uint32_t Services = 0);
			ExpectsLR<Vector<SocketAddress>> GetRandomizedValidatorAddresses(size_t Count, uint32_t Services = 0);
			ExpectsLR<SocketAddress> NextTrialAddress();
			ExpectsLR<size_t> GetValidatorsCount();
			ExpectsLR<Decimal> GetGasPrice(const Algorithm::AssetId& Asset, double PriorityPercentile);
			ExpectsLR<Decimal> GetAssetPrice(const Algorithm::AssetId& PriceOf, const Algorithm::AssetId& RelativeTo, double PriorityPercentile = 0.5);
			ExpectsLR<void> AddTransaction(Ledger::Transaction& Value, bool BypassCongestion = false);
			ExpectsLR<void> RemoveTransactions(const Vector<uint256_t>& TransactionHashes);
			ExpectsLR<void> RemoveTransactions(const UnorderedSet<uint256_t>& TransactionHashes);
			ExpectsLR<void> ExpireTransactions();
			ExpectsLR<AccountBandwidth> GetBandwidthByOwner(const Algorithm::Pubkeyhash Owner, Ledger::TransactionLevel Type);
			ExpectsLR<bool> HasTransaction(const uint256_t& TransactionHash);
			ExpectsLR<uint64_t> GetLowestTransactionSequence(const Algorithm::Pubkeyhash Owner);
			ExpectsLR<uint64_t> GetHighestTransactionSequence(const Algorithm::Pubkeyhash Owner);
			ExpectsLR<UPtr<Ledger::Transaction>> GetTransactionByHash(const uint256_t& TransactionHash);
			ExpectsLR<Vector<UPtr<Ledger::Transaction>>> GetTransactions(size_t Offset, size_t Count);
			ExpectsLR<Vector<UPtr<Ledger::Transaction>>> GetTransactionsByOwner(const Algorithm::Pubkeyhash Owner, int8_t Direction, size_t Offset, size_t Count);
			ExpectsLR<Vector<UPtr<Ledger::Transaction>>> GetCumulativeEventTransactions(const uint256_t& CumulativeHash, size_t Offset, size_t Count);
			ExpectsLR<Vector<uint256_t>> GetTransactionHashset(size_t Offset, size_t Count);

		public:
			static double FeePercentile(FeePriority Priority);

		protected:
			bool ReconstructStorage() override;
		};
	}
}
#endif