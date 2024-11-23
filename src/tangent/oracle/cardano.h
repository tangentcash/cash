#ifndef TAN_ORACLE_CARDANO_H
#define TAN_ORACLE_CARDANO_H
#include "../kernel/oracle.h"

namespace Tangent
{
	namespace Oracle
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

			public:
				Cardano() noexcept = default;
				virtual ~Cardano() noexcept = default;
				virtual Promise<ExpectsLR<void>> BroadcastTransaction(const Algorithm::AssetId& Asset, const OutgoingTransaction& TxData) override;
				virtual Promise<ExpectsLR<uint64_t>> GetLatestBlockHeight(const Algorithm::AssetId& Asset) override;
				virtual Promise<ExpectsLR<Schema*>> GetBlockTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, String* BlockHash) override;
				virtual Promise<ExpectsLR<Schema*>> GetBlockTransaction(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, const std::string_view& TransactionId) override;
				virtual Promise<ExpectsLR<Vector<IncomingTransaction>>> GetAuthenticTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, Schema* TransactionData) override;
				virtual Promise<ExpectsLR<BaseFee>> EstimateFee(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const FeeSupervisorOptions& Options) override;
				virtual Promise<ExpectsLR<CoinUTXO>> GetTransactionOutput(const Algorithm::AssetId& Asset, const std::string_view& TxId, uint32_t Index) override;
				virtual Promise<ExpectsLR<size_t>> GetLatestBlockSlot(const Algorithm::AssetId& Asset);
				virtual Promise<ExpectsLR<OutgoingTransaction>> NewTransaction(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const BaseFee& Fee) override;
				virtual ExpectsLR<MasterWallet> NewMasterWallet(const std::string_view& Seed) override;
				virtual ExpectsLR<DerivedSigningWallet> NewSigningWallet(const Algorithm::AssetId& Asset, const MasterWallet& Wallet, uint64_t AddressIndex) override;
				virtual ExpectsLR<DerivedSigningWallet> NewSigningWallet(const Algorithm::AssetId& Asset, const std::string_view& RawPrivateKey) override;
				virtual ExpectsLR<DerivedVerifyingWallet> NewVerifyingWallet(const Algorithm::AssetId& Asset, const std::string_view& RawPublicKey) override;
				virtual ExpectsLR<String> NewPublicKeyHash(const std::string_view& Address) override;
				virtual ExpectsLR<String> SignMessage(const Messages::Generic& Message, const DerivedSigningWallet& Wallet) override;
				virtual ExpectsLR<bool> VerifyMessage(const Messages::Generic& Message, const std::string_view& Address, const std::string_view& PublicKey, const std::string_view& Signature) override;
				virtual ExpectsLR<void> VerifyNodeCompatibility(Nodemaster* Node) override;
				virtual String GetDerivation(uint64_t AddressIndex) const override;
				virtual Decimal GetDivisibility() const override;
				virtual Algorithm::Composition::Type GetCompositionPolicy() const override;
				virtual RoutingPolicy GetRoutingPolicy() const override;
				virtual uint64_t GetBlockLatency() const override;
				virtual bool HasBulkTransactions() const override;

			public:
				virtual bool DecodePrivateKey(const std::string_view& Data, uint8_t PrivateKey[96]);
				virtual bool DecodePublicKey(const std::string_view& Data, uint8_t PublicKey[64]);
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