#ifndef TAN_STORAGE_SIDECHAINSTATE_H
#define TAN_STORAGE_SIDECHAINSTATE_H
#include "engine.h"
#include "../kernel/oracle.h"

namespace Tangent
{
	namespace Storages
	{
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