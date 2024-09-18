#ifndef TAN_ORACLE_SOLANA_H
#define TAN_ORACLE_SOLANA_H
#include "../kernel/oracle.h"

struct btc_chainparams_;

namespace Tangent
{
	namespace Oracle
	{
		namespace Chains
		{
			class Solana : public Chainmaster
			{
			public:
				struct TokenAccount
				{
					String ProgramId;
					String Account;
					Decimal Balance;
					Decimal Divisibility;
				};

			public:
				class NdCall
				{
				public:
					static String GetTokenMetadata(const std::string_view& Mint);
					static const char* GetTokenBalance();
					static const char* GetBalance();
					static const char* GetBlockHash();
					static const char* GetBlockNumber();
					static const char* GetBlock();
					static const char* GetTransaction();
					static const char* SendTransaction();
				};

			public:
				Solana() noexcept = default;
				virtual ~Solana() override = default;
				virtual Promise<ExpectsLR<void>> BroadcastTransaction(const Algorithm::AssetId& Asset, const OutgoingTransaction& TxData) override;
				virtual Promise<ExpectsLR<uint64_t>> GetLatestBlockHeight(const Algorithm::AssetId& Asset) override;
				virtual Promise<ExpectsLR<Schema*>> GetBlockTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, String* BlockHash) override;
				virtual Promise<ExpectsLR<Schema*>> GetBlockTransaction(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, const std::string_view& TransactionId) override;
				virtual Promise<ExpectsLR<Vector<IncomingTransaction>>> GetAuthenticTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, Schema* TransactionData) override;
				virtual Promise<ExpectsLR<BaseFee>> EstimateFee(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const FeeSupervisorOptions& Options) override;
				virtual Promise<ExpectsLR<Decimal>> CalculateBalance(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, Option<String>&& Address) override;
				virtual Promise<ExpectsLR<OutgoingTransaction>> NewTransaction(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const BaseFee& Fee) override;
				virtual ExpectsLR<MasterWallet> NewMasterWallet(const std::string_view& Seed) override;
				virtual ExpectsLR<DerivedSigningWallet> NewSigningWallet(const Algorithm::AssetId& Asset, const MasterWallet& Wallet, uint64_t AddressIndex) override;
				virtual ExpectsLR<DerivedSigningWallet> NewSigningWallet(const Algorithm::AssetId& Asset, const std::string_view& RawPrivateKey) override;
				virtual ExpectsLR<DerivedVerifyingWallet> NewVerifyingWallet(const Algorithm::AssetId& Asset, const std::string_view& RawPublicKey) override;
				virtual ExpectsLR<String> NewPublicKeyHash(const std::string_view& Address) override;
				virtual ExpectsLR<String> SignMessage(const Messages::Generic& Message, const DerivedSigningWallet& Wallet) override;
				virtual ExpectsLR<bool> VerifyMessage(const Messages::Generic& Message, const std::string_view& Address, const std::string_view& PublicKey, const std::string_view& Signature) override;
				virtual String GetDerivation(uint64_t AddressIndex) const override;
				virtual Decimal GetDivisibility() const override;
				virtual Algorithm::Composition::Type GetCompositionPolicy() const override;
				virtual RoutingPolicy GetRoutingPolicy() const override;
				virtual uint64_t GetBlockLatency() const override;
				virtual bool HasBulkTransactions() const override;

			public:
				virtual Promise<ExpectsLR<String>> GetTokenSymbol(const std::string_view& Mint);
				virtual Promise<ExpectsLR<TokenAccount>> GetTokenBalance(const Algorithm::AssetId& Asset, const std::string_view& Mint, const std::string_view& Owner);
				virtual Promise<ExpectsLR<Decimal>> GetBalance(const Algorithm::AssetId& Asset, const std::string_view& Owner);
				virtual Promise<ExpectsLR<String>> GetRecentBlockHash(const Algorithm::AssetId& Asset);
				virtual bool DecodePrivateKey(const std::string_view& Data, uint8_t PrivateKey[64]);
				virtual const btc_chainparams_* GetChain();
			};
		}
	}
}
#endif