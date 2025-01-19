#ifndef TAN_OBSERVER_STELLAR_H
#define TAN_OBSERVER_STELLAR_H
#include "../kernel/observer.h"

struct btc_chainparams_;

namespace Tangent
{
	namespace Observer
	{
		namespace Chains
		{
			class Stellar : public Chainmaster
			{
			public:
				enum class AssetType : uint32_t
				{
					ASSET_TYPE_NATIVE = 0,
					ASSET_TYPE_CREDIT_ALPHANUM4 = 1,
					ASSET_TYPE_CREDIT_ALPHANUM12 = 2
				};

			public:
				struct ChainInfo
				{
					uint8_t Ed25519PublicKey = 6 << 3;
					uint8_t Ed25519SecretSeed = 18 << 3;
					uint8_t Med25519PublicKey = 12 << 3;
					uint8_t PreAuthTx = 19 << 3;
					uint8_t Sha256Hash = 23 << 3;
				};

				struct ChainConfig
				{
					ChainInfo Mainnet;
					ChainInfo Testnet;
					ChainInfo Regtest;
				};

				struct AssetInfo
				{
					String Type;
					String Code;
					String Issuer;
				};

				struct AssetBalance
				{
					AssetInfo Info;
					Decimal Balance;
				};

				struct AccountInfo
				{
					UnorderedMap<String, AssetBalance> Balances;
					uint64_t Sequence = 0;
				};


			public:
				class NdCall
				{
				public:
					static String GetLedger(uint64_t BlockHeight);
					static String GetLedgerOperations(uint64_t BlockHeight);
					static String GetOperations(const std::string_view& TxId);
					static String GetTransactions(const std::string_view& TxId);
					static String GetAccounts(const std::string_view& Address);
					static String GetAssets(const std::string_view& Issuer, const std::string_view& Code);
					static const char* GetLastLedger();
					static const char* SubmitTransaction();
				};

			protected:
				ChainConfig Config;
				Chainparams Netdata;

			public:
				Stellar(ChainConfig* Config = nullptr) noexcept;
				virtual ~Stellar() override = default;
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
				virtual ExpectsLR<DerivedSigningWallet> NewSigningWallet(const Algorithm::AssetId& Asset, const std::string_view& SigningKey) override;
				virtual ExpectsLR<DerivedVerifyingWallet> NewVerifyingWallet(const Algorithm::AssetId& Asset, const std::string_view& VerifyingKey) override;
				virtual ExpectsLR<String> NewPublicKeyHash(const std::string_view& Address) override;
				virtual ExpectsLR<String> SignMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const PrivateKey& SigningKey) override;
				virtual ExpectsLR<void> VerifyMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const std::string_view& VerifyingKey, const std::string_view& Signature) override;
				virtual String GetDerivation(uint64_t AddressIndex) const override;
				virtual const Chainparams& GetChainparams() const override;

			public:
				virtual Promise<ExpectsLR<AssetInfo>> GetAssetInfo(const Algorithm::AssetId& Asset, const std::string_view& Address, const std::string_view& Code);
				virtual Promise<ExpectsLR<AccountInfo>> GetAccountInfo(const Algorithm::AssetId& Asset, const std::string_view& Address);
				virtual Promise<ExpectsLR<String>> GetTransactionMemo(const Algorithm::AssetId& Asset, const std::string_view& TxId);
				virtual Promise<bool> IsAccountExists(const Algorithm::AssetId& Asset, const std::string_view& Address);
				virtual String GetNetworkPassphrase();
				virtual Decimal FromStroop(const uint256_t& Value);
				virtual uint256_t ToStroop(const Decimal& Value);
				virtual uint64_t GetBaseStroopFee();
				virtual uint16_t CalculateChecksum(const uint8_t* Value, size_t Size);
				virtual bool DecodePrivateKey(const std::string_view& Data, uint8_t PrivateKey[64]);
				virtual bool DecodeKey(uint8_t Version, const std::string_view& Data, uint8_t* OutValue, size_t* OutSize);
				virtual bool DecodeBase32(const std::string_view& Data, uint8_t* OutValue, size_t* OutSize);
				virtual String EncodePrivateKey(uint8_t* PrivateKey, size_t PrivateKeySize);
				virtual String EncodeKey(uint8_t Version, const uint8_t* Value, size_t Size);
				virtual String EncodeBase32(const uint8_t* Value, size_t Size);
				virtual const btc_chainparams_* GetChain();
				virtual ChainInfo& GetParams();
			};
		}
	}
}
#endif