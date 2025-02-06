#ifndef TAN_MEDIATOR_SOLANA_H
#define TAN_MEDIATOR_SOLANA_H
#include "../../kernel/mediator.h"

struct btc_chainparams_;

namespace Tangent
{
	namespace Mediator
	{
		namespace Backends
		{
			class Solana : public RelayBackend
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

			protected:
				Chainparams Netdata;

			public:
				Solana() noexcept;
				virtual ~Solana() override = default;
				virtual ExpectsPromiseRT<void> BroadcastTransaction(const Algorithm::AssetId& Asset, const OutgoingTransaction& TxData) override;
				virtual ExpectsPromiseRT<uint64_t> GetLatestBlockHeight(const Algorithm::AssetId& Asset) override;
				virtual ExpectsPromiseRT<Schema*> GetBlockTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, String* BlockHash) override;
				virtual ExpectsPromiseRT<Schema*> GetBlockTransaction(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, const std::string_view& TransactionId) override;
				virtual ExpectsPromiseRT<Vector<IncomingTransaction>> GetAuthenticTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, Schema* TransactionData) override;
				virtual ExpectsPromiseRT<BaseFee> EstimateFee(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const FeeSupervisorOptions& Options) override;
				virtual ExpectsPromiseRT<Decimal> CalculateBalance(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, Option<String>&& Address) override;
				virtual ExpectsPromiseRT<OutgoingTransaction> NewTransaction(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const BaseFee& Fee) override;
				virtual ExpectsLR<MasterWallet> NewMasterWallet(const std::string_view& Seed) override;
				virtual ExpectsLR<DerivedSigningWallet> NewSigningWallet(const Algorithm::AssetId& Asset, const MasterWallet& Wallet, uint64_t AddressIndex) override;
				virtual ExpectsLR<DerivedSigningWallet> NewSigningWallet(const Algorithm::AssetId& Asset, const std::string_view& SigningKey) override;
				virtual ExpectsLR<DerivedVerifyingWallet> NewVerifyingWallet(const Algorithm::AssetId& Asset, const std::string_view& VerifyingKey) override;
				virtual ExpectsLR<String> NewPublicKeyHash(const std::string_view& Address) override;
				virtual ExpectsLR<String> SignMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const PrivateKey& SigningKey) override;
				virtual ExpectsLR<void> VerifyMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const std::string_view& VerifyingKey, const std::string_view& Signature) override;
				virtual String GetDerivation(uint64_t AddressIndex) const override;
				virtual const Chainparams& GetChainparams() const override;

			public:
				virtual ExpectsPromiseRT<String> GetTokenSymbol(const std::string_view& Mint);
				virtual ExpectsPromiseRT<TokenAccount> GetTokenBalance(const Algorithm::AssetId& Asset, const std::string_view& Mint, const std::string_view& Owner);
				virtual ExpectsPromiseRT<Decimal> GetBalance(const Algorithm::AssetId& Asset, const std::string_view& Owner);
				virtual ExpectsPromiseRT<String> GetRecentBlockHash(const Algorithm::AssetId& Asset);
				virtual bool DecodePrivateKey(const std::string_view& Data, uint8_t PrivateKey[64]);
				virtual bool DecodeSecretOrPublicKey(const std::string_view& Data, uint8_t SecretKey[32]);
				virtual const btc_chainparams_* GetChain();
			};
		}
	}
}
#endif