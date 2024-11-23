#ifndef TAN_ORACLE_RIPPLE_H
#define TAN_ORACLE_RIPPLE_H
#include "../kernel/oracle.h"

struct btc_chainparams_;

namespace Tangent
{
	namespace Oracle
	{
		namespace Chains
		{
			class Ripple : public Chainmaster
			{
			public:
				struct TransactionBuffer
				{
					uint16_t TransactionType = 0;
					uint32_t Flags = 0;
					uint32_t Sequence = 0;
					uint32_t DestinationTag = 0;
					uint32_t LastLedgerSequence = 0;
					struct
					{
						uint64_t BaseValue = 0;
						Decimal TokenValue = Decimal::NaN();
						String Asset;
						String Issuer;
					} Amount;
					uint64_t Fee = 0;
					String SigningPubKey;
					String TxnSignature;
					String Account;
					String Destination;
				};

				struct AccountInfo
				{
					Decimal Balance;
					uint64_t Sequence = 0;
				};

				struct AccountTokenInfo
				{
					Decimal Balance;
				};

				struct LedgerSequenceInfo
				{
					uint64_t Index = 0;
					uint64_t Sequence = 0;
				};

			public:
				class NdCall
				{
				public:
					static const char* Ledger();
					static const char* Transaction();
					static const char* AccountInfo();
					static const char* AccountObjects();
					static const char* ServerInfo();
					static const char* SubmitTransaction();
				};

			public:
				Ripple() noexcept = default;
				virtual ~Ripple() override = default;
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
				virtual Promise<ExpectsLR<AccountInfo>> GetAccountInfo(const Algorithm::AssetId& Asset, const std::string_view& Address);
				virtual Promise<ExpectsLR<AccountTokenInfo>> GetAccountTokenInfo(const Algorithm::AssetId& Asset, const std::string_view& Address);
				virtual Promise<ExpectsLR<LedgerSequenceInfo>> GetLedgerSequenceInfo(const Algorithm::AssetId& Asset);
				virtual bool TxSignAndVerify(TransactionBuffer* TxData, const PrivateKey& Public, const PrivateKey& Private);
				virtual Vector<uint8_t> TxSerialize(TransactionBuffer* TxData, bool SigningData);
				virtual String TxHash(const Vector<uint8_t>& TxBlob);
				virtual Decimal GetBaseFeeXRP();
				virtual Decimal FromDrop(const uint256_t& Value);
				virtual uint256_t ToDrop(const Decimal& Value);
				virtual String EncodeSecretKey(uint8_t* SecretKey, size_t SecretKeySize);
				virtual String EncodePublicKey(uint8_t* PublicKey, size_t PublicKeySize);
				virtual String EncodePrivateKey(uint8_t* PrivateKey, size_t PrivateKeySize);
				virtual String EncodeAndHashPublicKey(uint8_t* PublicKey, size_t PublicKeySize);
				virtual bool DecodeSecretKey(const std::string_view& Data, uint8_t SecretKey[16]);
				virtual bool DecodePrivateKey(const std::string_view& Data, uint8_t PrivateKey[65]);
				virtual bool DecodePublicKey(const std::string_view& Data, uint8_t PublicKey[33]);
				virtual bool DecodePublicKeyHash(const std::string_view& Data, uint8_t PublicKeyHash[20]);
				virtual const btc_chainparams_* GetChain();
			};
		}
	}
}
#endif