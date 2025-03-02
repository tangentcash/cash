#ifndef TAN_MEDIATOR_MONERO_H
#define TAN_MEDIATOR_MONERO_H
#include "../../kernel/mediator.h"

struct btc_chainparams_;

namespace Tangent
{
	namespace Mediator
	{
		namespace Backends
		{
			class Monero : public RelayBackendUTXO
			{
			public:
				class NdCall
				{
				public:
					static const char* JsonRpc();
					static const char* SendRawTransaction();
					static const char* GetTransactions();
					static const char* GetHeight();
				};

				class NdCallRestricted
				{
				public:
					static const char* GetBlock();
					static const char* GetFeeEstimate();
				};

			protected:
				Chainparams Netdata;

			public:
				Monero() noexcept;
				virtual ~Monero() noexcept = default;
				virtual ExpectsPromiseRT<void> BroadcastTransaction(const Algorithm::AssetId& Asset, const OutgoingTransaction& TxData) override;
				virtual ExpectsPromiseRT<uint64_t> GetLatestBlockHeight(const Algorithm::AssetId& Asset) override;
				virtual ExpectsPromiseRT<Schema*> GetBlockTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, String* BlockHash) override;
				virtual ExpectsPromiseRT<Schema*> GetBlockTransaction(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, const std::string_view& TransactionId) override;
				virtual ExpectsPromiseRT<Vector<IncomingTransaction>> GetAuthenticTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, Schema* TransactionData) override;
				virtual ExpectsPromiseRT<BaseFee> EstimateFee(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const FeeSupervisorOptions& Options) override;
				virtual ExpectsPromiseRT<CoinUTXO> GetTransactionOutput(const Algorithm::AssetId& Asset, const std::string_view& TxId, uint32_t Index) override;
				virtual ExpectsPromiseRT<OutgoingTransaction> NewTransaction(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const BaseFee& Fee) override;
				virtual ExpectsLR<MasterWallet> NewMasterWallet(const std::string_view& Seed) override;
				virtual ExpectsLR<DerivedSigningWallet> NewSigningWallet(const Algorithm::AssetId& Asset, const MasterWallet& Wallet, uint64_t AddressIndex) override;
				virtual ExpectsLR<DerivedSigningWallet> NewSigningWallet(const Algorithm::AssetId& Asset, const PrivateKey& SigningKey) override;
				virtual ExpectsLR<DerivedVerifyingWallet> NewVerifyingWallet(const Algorithm::AssetId& Asset, const std::string_view& VerifyingKey) override;
				virtual ExpectsLR<String> NewPublicKeyHash(const std::string_view& Address) override;
				virtual ExpectsLR<String> SignMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const PrivateKey& SigningKey) override;
				virtual ExpectsLR<void> VerifyMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const std::string_view& VerifyingKey, const std::string_view& Signature) override;
				virtual String GetDerivation(uint64_t AddressIndex) const override;
				virtual const btc_chainparams_* GetChain();
				virtual const Chainparams& GetChainparams() const override;
				virtual uint64_t GetRetirementBlockNumber() const override;

			public:
				virtual bool MessageHash(uint8_t Hash[32], const uint8_t* Message, size_t MessageSize, const uint8_t PublicSpendKey[32], const uint8_t PublicViewKey[32], const uint8_t Mode);
				virtual void DeriveKnownPrivateViewKey(const uint8_t PublicSpendKey[32], uint8_t PrivateViewKey[32]);
				virtual void DeriveKnownPublicViewKey(const uint8_t PublicSpendKey[32], uint8_t PublicViewKey[32]);
				virtual uint64_t GetNetworkType() const;
			};
		}
	}
}
#endif
