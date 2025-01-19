#ifndef TAN_OBSERVER_CARDANO_H
#define TAN_OBSERVER_CARDANO_H
#include "../kernel/observer.h"

namespace Tangent
{
	namespace Observer
	{
		namespace Chains
		{
			class Cardano : public ChainmasterUTXO
			{
			public:
				class NdCall
				{
				public:
					static const char* NetworkStatus();
					static const char* BlockData();
					static const char* TransactionData();
					static const char* SubmitTransaction();
				};

			private:
				struct
				{
					uint64_t BlockHeight = 0;
					size_t Transactions = 0;
					size_t TotalSize = 0;
				} TxAnalytics;

			protected:
				Chainparams Netdata;

			public:
				Cardano() noexcept;
				virtual ~Cardano() noexcept = default;
				virtual Promise<ExpectsLR<void>> BroadcastTransaction(const Algorithm::AssetId& Asset, const OutgoingTransaction& TxData) override;
				virtual Promise<ExpectsLR<uint64_t>> GetLatestBlockHeight(const Algorithm::AssetId& Asset) override;
				virtual Promise<ExpectsLR<Schema*>> GetBlockTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, String* BlockHash) override;
				virtual Promise<ExpectsLR<Schema*>> GetBlockTransaction(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, const std::string_view& TransactionId) override;
				virtual Promise<ExpectsLR<Vector<IncomingTransaction>>> GetAuthenticTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, Schema* TransactionData) override;
				virtual Promise<ExpectsLR<BaseFee>> EstimateFee(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const FeeSupervisorOptions& Options) override;
				virtual Promise<ExpectsLR<CoinUTXO>> GetTransactionOutput(const Algorithm::AssetId& Asset, const std::string_view& TxId, uint32_t Index) override;
				virtual Promise<ExpectsLR<uint64_t>> GetLatestBlockSlot(const Algorithm::AssetId& Asset);
				virtual Promise<ExpectsLR<OutgoingTransaction>> NewTransaction(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const BaseFee& Fee) override;
				virtual ExpectsLR<MasterWallet> NewMasterWallet(const std::string_view& Seed) override;
				virtual ExpectsLR<DerivedSigningWallet> NewSigningWallet(const Algorithm::AssetId& Asset, const MasterWallet& Wallet, uint64_t AddressIndex) override;
				virtual ExpectsLR<DerivedSigningWallet> NewSigningWallet(const Algorithm::AssetId& Asset, const std::string_view& SigningKey) override;
				virtual ExpectsLR<DerivedVerifyingWallet> NewVerifyingWallet(const Algorithm::AssetId& Asset, const std::string_view& VerifyingKey) override;
				virtual ExpectsLR<String> NewPublicKeyHash(const std::string_view& Address) override;
				virtual ExpectsLR<String> SignMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const PrivateKey& SigningKey) override;
				virtual ExpectsLR<void> VerifyMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const std::string_view& VerifyingKey, const std::string_view& Signature) override;
				virtual ExpectsLR<void> VerifyNodeCompatibility(Nodemaster* Node) override;
				virtual String GetDerivation(uint64_t AddressIndex) const override;
				virtual const Chainparams& GetChainparams() const override;

			public:
				virtual bool DecodePrivateKey(const std::string_view& Data, uint8_t PrivateKey[96], size_t* PrivateKeySize);
				virtual bool DecodePublicKey(const std::string_view& Data, uint8_t PublicKey[64], size_t* PublicKeySize);
				virtual Decimal GetMinValuePerOutput();
				virtual uint256_t ToLovelace(const Decimal& Value);
				virtual uint64_t GetMinProtocolFeeA();
				virtual uint64_t GetMinProtocolFeeB();
				virtual size_t GetBlockSlotOffset();
				virtual String GetBlockchain();
				virtual String GetNetwork();
				virtual size_t GetTxFeeBlocks();
				virtual size_t GetTxFeeBlockDelta();
				virtual size_t GetTxFeeBaseSize();
			};
		}
	}
}
#endif
