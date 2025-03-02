#ifndef TAN_MEDIATOR_RIPPLE_H
#define TAN_MEDIATOR_RIPPLE_H
#include "../../kernel/mediator.h"

struct btc_chainparams_;

namespace Tangent
{
	namespace Mediator
	{
		namespace Backends
		{
			class Ripple : public RelayBackend
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

			protected:
				Chainparams Netdata;

			public:
				Ripple() noexcept;
				virtual ~Ripple() override = default;
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
				virtual ExpectsLR<DerivedSigningWallet> NewSigningWallet(const Algorithm::AssetId& Asset, const PrivateKey& SigningKey) override;
				virtual ExpectsLR<DerivedVerifyingWallet> NewVerifyingWallet(const Algorithm::AssetId& Asset, const std::string_view& VerifyingKey) override;
				virtual ExpectsLR<String> NewPublicKeyHash(const std::string_view& Address) override;
				virtual ExpectsLR<String> SignMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const PrivateKey& SigningKey) override;
				virtual ExpectsLR<void> VerifyMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const std::string_view& VerifyingKey, const std::string_view& Signature) override;
				virtual String GetDerivation(uint64_t AddressIndex) const override;
				virtual const Chainparams& GetChainparams() const override;

			public:
				virtual ExpectsPromiseRT<AccountInfo> GetAccountInfo(const Algorithm::AssetId& Asset, const std::string_view& Address);
				virtual ExpectsPromiseRT<AccountTokenInfo> GetAccountTokenInfo(const Algorithm::AssetId& Asset, const std::string_view& Address);
				virtual ExpectsPromiseRT<LedgerSequenceInfo> GetLedgerSequenceInfo(const Algorithm::AssetId& Asset);
				virtual bool TxSignAndVerify(TransactionBuffer* TxData, const std::string_view& Public, const PrivateKey& Private);
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