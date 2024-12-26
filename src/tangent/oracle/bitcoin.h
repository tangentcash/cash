#ifndef TAN_ORACLE_BITCOIN_H
#define TAN_ORACLE_BITCOIN_H
#include "../kernel/oracle.h"

struct btc_tx_;
struct btc_chainparams_;
struct cstring;

namespace Tangent
{
	namespace Oracle
	{
		namespace Chains
		{
			class Bitcoin : public ChainmasterUTXO
			{
			public:
				enum class AddressFormat
				{
					Unknown = 0,
					Pay2PublicKey = (1 << 0),
					Pay2ScriptHash = (1 << 1),
					Pay2PublicKeyHash = (1 << 2),
					Pay2WitnessScriptHash = (1 << 3),
					Pay2WitnessPublicKeyHash = (1 << 4),
					Pay2Tapscript = (1 << 5),
					Pay2Taproot = (1 << 6),
					Pay2CashaddrScriptHash = (1 << 7),
					Pay2CashaddrPublicKeyHash = (1 << 8),
					All = (Pay2PublicKey | Pay2PublicKeyHash | Pay2ScriptHash | Pay2WitnessPublicKeyHash | Pay2WitnessPublicKeyHash | Pay2WitnessScriptHash | Pay2Taproot | Pay2Tapscript | Pay2CashaddrPublicKeyHash | Pay2CashaddrScriptHash)
				};

				struct SighashContext
				{
					struct
					{
						Vector<cstring*> Locking;
						Vector<Vector<cstring*>> Unlocking;
					} Scripts;
					Vector<String> Keys;
					Vector<uint64_t> Values;
					Vector<uint8_t> Types;

					~SighashContext();
				};

			public:
				class NdCall
				{
				public:
					static const char* GetBlockCount();
					static const char* GetBlockHash();
					static const char* GetBlockStats();
					static const char* GetBlock();
					static const char* GetRawTransaction();
					static const char* SendRawTransaction();
				};

			private:
				struct
				{
					uint8_t GetRawTransaction = 0;
					uint8_t GetBlock = 0;
				} Legacy;

			protected:
				Chainparams Netdata;

			public:
				Bitcoin() noexcept;
				virtual ~Bitcoin() override;
				virtual Promise<ExpectsLR<void>> BroadcastTransaction(const Algorithm::AssetId& Asset, const OutgoingTransaction& TxData) override;
				virtual Promise<ExpectsLR<uint64_t>> GetLatestBlockHeight(const Algorithm::AssetId& Asset) override;
				virtual Promise<ExpectsLR<Schema*>> GetBlockTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, String* BlockHash) override;
				virtual Promise<ExpectsLR<Schema*>> GetBlockTransaction(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, const std::string_view& TransactionId) override;
				virtual Promise<ExpectsLR<Vector<IncomingTransaction>>> GetAuthenticTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, Schema* TransactionData) override;
				virtual Promise<ExpectsLR<BaseFee>> EstimateFee(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const FeeSupervisorOptions& Options) override;
				virtual Promise<ExpectsLR<CoinUTXO>> GetTransactionOutput(const Algorithm::AssetId& Asset, const std::string_view& TxId, uint32_t Index) override;
				virtual UnorderedSet<String> GetOutputAddresses(Schema* TxOutput, bool* IsAllowed);
				virtual Promise<ExpectsLR<OutgoingTransaction>> NewTransaction(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const BaseFee& Fee) override;
				virtual ExpectsLR<MasterWallet> NewMasterWallet(const std::string_view& Wallet) override;
				virtual ExpectsLR<DerivedSigningWallet> NewSigningWallet(const Algorithm::AssetId& Asset, const MasterWallet& Wallet, uint64_t AddressIndex) override;
				virtual ExpectsLR<DerivedSigningWallet> NewSigningWallet(const Algorithm::AssetId& Asset, const std::string_view& SigningKey) override;
				virtual ExpectsLR<DerivedVerifyingWallet> NewVerifyingWallet(const Algorithm::AssetId& Asset, const std::string_view& VerifyingKey) override;
				virtual ExpectsLR<String> NewPublicKeyHash(const std::string_view& Address) override;
				virtual ExpectsLR<String> SignMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const PrivateKey& SigningKey) override;
				virtual ExpectsLR<void> VerifyMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const std::string_view& VerifyingKey, const std::string_view& Signature) override;
				virtual String GetDerivation(uint64_t AddressIndex) const override;
				virtual const Chainparams& GetChainparams() const override;
				virtual Promise<ExpectsLR<BaseFee>> CalculateTransactionFeeFromFeeEstimate(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const BaseFee& Estimate, const std::string_view& ChangeAddress);
				virtual Option<LayerException> SignTransactionInput(btc_tx_* Transaction, const CoinUTXO& Output, const SighashContext& Context, size_t Index);
				virtual Option<LayerException> AddTransactionInput(btc_tx_* Transaction, const CoinUTXO& Output, SighashContext& Context, const char* PrivateKey);
				virtual Option<LayerException> AddTransactionOutput(btc_tx_* Transaction, const std::string_view& Address, const Decimal& Value);
				virtual String SerializeTransactionData(btc_tx_* Transaction);
				virtual String SerializeTransactionId(btc_tx_* Transaction);
				virtual AddressFormat ParseAddress(const std::string_view& Address, uint8_t* DataOut = nullptr, size_t* DataSizeOut = nullptr);
				virtual String GetMessageMagic();
				virtual void GenerateMessageHash(const std::string_view& Input, uint8_t Output[32]);
				virtual const btc_chainparams_* GetChain();
				virtual AddressFormat GetAddressType();
				virtual uint32_t GetSigHashType();
			};
		}
	}
}
#endif