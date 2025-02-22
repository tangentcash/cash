#ifndef TAN_STORAGE_MEDIATORSTATE_H
#define TAN_STORAGE_MEDIATORSTATE_H
#include "engine.h"
#include "../../kernel/mediator.h"

namespace Tangent
{
	namespace Storages
	{
		struct TAN_OUT Mediatorstate : Ledger::MutableStorage
		{
		private:
			Algorithm::AssetId Asset;
			std::string_view Label;

		public:
			Mediatorstate(const std::string_view& NewLabel, const Algorithm::AssetId& NewAsset) noexcept;
			virtual ~Mediatorstate() noexcept = default;
			ExpectsLR<void> AddMasterWallet(const Mediator::MasterWallet& Value);
			ExpectsLR<Mediator::MasterWallet> GetMasterWallet();
			ExpectsLR<Mediator::MasterWallet> GetMasterWalletByHash(const uint256_t& MasterWalletHash);
			ExpectsLR<void> AddDerivedWallet(const Mediator::MasterWallet& Parent, const Mediator::DerivedSigningWallet& Value);
			ExpectsLR<Mediator::DerivedSigningWallet> GetDerivedWallet(const uint256_t& MasterWalletHash, uint64_t AddressIndex);
			ExpectsLR<void> AddUTXO(const Mediator::IndexUTXO& Value);
			ExpectsLR<void> RemoveUTXO(const std::string_view& TransactionId, uint32_t Index);
			ExpectsLR<Mediator::IndexUTXO> GetSTXO(const std::string_view& TransactionId, uint32_t Index);
			ExpectsLR<Mediator::IndexUTXO> GetUTXO(const std::string_view& TransactionId, uint32_t Index);
			ExpectsLR<Vector<Mediator::IndexUTXO>> GetUTXOs(const std::string_view& Binding, size_t Offset, size_t Count);
			ExpectsLR<void> AddIncomingTransaction(const Mediator::IncomingTransaction& Value, uint64_t BlockId);
			ExpectsLR<void> AddOutgoingTransaction(const Mediator::IncomingTransaction& Value, const uint256_t ExternalId);
			ExpectsLR<Mediator::IncomingTransaction> GetTransaction(const std::string_view& TransactionId, const uint256_t& ExternalId);
			ExpectsLR<Vector<Mediator::IncomingTransaction>> ApproveTransactions(uint64_t BlockHeight, uint64_t BlockLatency);
			ExpectsLR<void> SetProperty(const std::string_view& Key, UPtr<Schema>&& Value);
			ExpectsLR<Schema*> GetProperty(const std::string_view& Key);
			ExpectsLR<void> SetCache(Mediator::CachePolicy Policy, const std::string_view& Key, UPtr<Schema>&& Value);
			ExpectsLR<Schema*> GetCache(Mediator::CachePolicy Policy, const std::string_view& Key);
			ExpectsLR<void> SetAddressIndex(const std::string_view& Address, const Mediator::IndexAddress& Value);
			ExpectsLR<void> ClearAddressIndex(const std::string_view& Address);
			ExpectsLR<Mediator::IndexAddress> GetAddressIndex(const std::string_view& Address);
			ExpectsLR<UnorderedMap<String, Mediator::IndexAddress>> GetAddressIndices(const UnorderedSet<String>& Addresses);
			ExpectsLR<Vector<String>> GetAddressIndices();

		protected:
			String GetAddressLocation(const std::string_view& Address);
			String GetTransactionLocation(const std::string_view& TransactionId);
			String GetCoinLocation(const std::string_view& TransactionId, uint32_t Index);
			bool ReconstructStorage() override;

		private:
			static std::string_view GetCacheLocation(Mediator::CachePolicy Policy);
		};
	}
}
#endif