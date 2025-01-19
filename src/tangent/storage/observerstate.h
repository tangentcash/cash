#ifndef TAN_STORAGE_OBSERVERSTATE_H
#define TAN_STORAGE_OBSERVERSTATE_H
#include "engine.h"
#include "../kernel/observer.h"

namespace Tangent
{
	namespace Storages
	{
		struct Observerstate : Ledger::MutableStorage
		{
		private:
			Algorithm::AssetId Asset;
			std::string_view Label;

		public:
			Observerstate(const std::string_view& NewLabel, const Algorithm::AssetId& NewAsset) noexcept;
			virtual ~Observerstate() noexcept = default;
			ExpectsLR<void> AddMasterWallet(const Observer::MasterWallet& Value);
			ExpectsLR<Observer::MasterWallet> GetMasterWallet();
			ExpectsLR<Observer::MasterWallet> GetMasterWalletByHash(const uint256_t& MasterWalletHash);
			ExpectsLR<void> AddDerivedWallet(const Observer::MasterWallet& Parent, const Observer::DerivedSigningWallet& Value);
			ExpectsLR<Observer::DerivedSigningWallet> GetDerivedWallet(const uint256_t& MasterWalletHash, uint64_t AddressIndex);
			ExpectsLR<void> AddUTXO(const Observer::IndexUTXO& Value);
			ExpectsLR<void> RemoveUTXO(const std::string_view& TransactionId, uint32_t Index);
			ExpectsLR<Observer::IndexUTXO> GetSTXO(const std::string_view& TransactionId, uint32_t Index);
			ExpectsLR<Observer::IndexUTXO> GetUTXO(const std::string_view& TransactionId, uint32_t Index);
			ExpectsLR<Vector<Observer::IndexUTXO>> GetUTXOs(const std::string_view& Binding, size_t Offset, size_t Count);
			ExpectsLR<void> AddIncomingTransaction(const Observer::IncomingTransaction& Value, uint64_t BlockId);
			ExpectsLR<void> AddOutgoingTransaction(const Observer::IncomingTransaction& Value, const uint256_t ExternalId);
			ExpectsLR<Observer::IncomingTransaction> GetTransaction(const std::string_view& TransactionId, const uint256_t& ExternalId);
			ExpectsLR<Vector<Observer::IncomingTransaction>> ApproveTransactions(uint64_t BlockHeight, uint64_t BlockLatency);
			ExpectsLR<void> SetProperty(const std::string_view& Key, UPtr<Schema>&& Value);
			ExpectsLR<Schema*> GetProperty(const std::string_view& Key);
			ExpectsLR<void> SetCache(Observer::CachePolicy Policy, const std::string_view& Key, UPtr<Schema>&& Value);
			ExpectsLR<Schema*> GetCache(Observer::CachePolicy Policy, const std::string_view& Key);
			ExpectsLR<void> SetAddressIndex(const std::string_view& Address, const Observer::IndexAddress& Value);
			ExpectsLR<Observer::IndexAddress> GetAddressIndex(const std::string_view& Address);
			ExpectsLR<UnorderedMap<String, Observer::IndexAddress>> GetAddressIndices(const UnorderedSet<String>& Addresses);
			ExpectsLR<Vector<String>> GetAddressIndices();

		protected:
			String GetAddressLocation(const std::string_view& Address);
			String GetTransactionLocation(const std::string_view& TransactionId);
			String GetCoinLocation(const std::string_view& TransactionId, uint32_t Index);
			bool ReconstructStorage() override;

		private:
			static std::string_view GetCacheLocation(Observer::CachePolicy Policy);
		};
	}
}
#endif