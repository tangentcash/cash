#ifndef TAN_ORACLE_ETHEREUM_H
#define TAN_ORACLE_ETHEREUM_H
#include "../kernel/oracle.h"

struct btc_chainparams_;

namespace Tangent
{
	namespace Oracle
	{
		namespace Chains
		{
			class Ethereum : public Chainmaster
			{
			public:
				typedef uint256_t wei256_t;
				typedef uint256_t gwei256_t;
				typedef String address336_t;
				typedef String evm_abi_t;
				typedef String binary_data_t;

			public:
				struct EvmSignature
				{
					binary_data_t R;
					binary_data_t S;
					uint32_t V = 0;
				};

				struct EvmSignedTransaction
				{
					EvmSignature Signature;
					binary_data_t Data;
					binary_data_t Id;
				};

				struct EvmTransaction
				{
					uint256_t Nonce = 0;
					uint256_t ChainId = 0;
					gwei256_t GasPrice = 0;
					gwei256_t GasLimit = 0;
					wei256_t Value = 0;
					address336_t Address;
					binary_data_t AbiData;

					EvmSignature Sign(const binary_data_t& Hash, const uint8_t PrivateKey[32]);
					EvmSignedTransaction SerializeAndSign(const uint8_t PrivateKey[32]);
					binary_data_t Hash(const binary_data_t& SerializedData);
					binary_data_t Serialize(EvmSignature* Signature = nullptr);
				};

			public:
				class ScFunction
				{
				public:
					static const char* Symbol();
					static const char* Decimals();
					static const char* BalanceOf();
					static const char* Transfer();
					static const char* TransferFrom();
				};

				class ScCall
				{
				public:
					static binary_data_t Symbol();
					static binary_data_t Decimals();
					static binary_data_t BalanceOf(const String& Address);
					static binary_data_t Transfer(const String& Address, const uint256_t& Value);
				};

				class NdCall
				{
				public:
					static const char* GetBlockByNumber();
					static const char* GetTransactionReceipt();
					static const char* GetTransactionByHash();
					static const char* GetTransactionCount();
					static const char* GetBalance();
					static const char* GetChainId();
					static const char* BlockNumber();
					static const char* EstimateGas();
					static const char* GasPrice();
					static const char* Call();
					static const char* SendRawTransaction();
				};

			private:
				struct
				{
					uint8_t GetLogs = 0;
				} Legacy;

			protected:
				Chainparams Netdata;

			public:
				Ethereum() noexcept;
				virtual ~Ethereum() override = default;
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
				virtual String GetChecksumHash(const std::string_view& Value) const override;
				virtual String GetDerivation(uint64_t AddressIndex) const override;
				virtual const Chainparams& GetChainparams() const override;

			public:
				virtual Promise<ExpectsLR<Schema*>> GetTransactionReceipt(const Algorithm::AssetId& Asset, const std::string_view& TxId);
				virtual Promise<ExpectsLR<uint256_t>> GetTransactionsCount(const Algorithm::AssetId& Asset, const std::string_view& Address);
				virtual Promise<ExpectsLR<uint256_t>> GetChainId(const Algorithm::AssetId& Asset);
				virtual Promise<ExpectsLR<String>> GetContractSymbol(const Algorithm::AssetId& Asset, Chains::Ethereum* Implementation, const std::string_view& ContractAddress);
				virtual Promise<ExpectsLR<Decimal>> GetContractDivisibility(const Algorithm::AssetId& Asset, Chains::Ethereum* Implementation, const std::string_view& ContractAddress);
				virtual const char* GetTokenTransferSignature();
				virtual bool IsTokenTransfer(const std::string_view& FunctionSignature);
				virtual void GeneratePublicKeyHashFromPublicKey(const uint8_t PublicKey[64], char OutPublicKeyHash[20]);
				virtual void GeneratePrivateKeyDataFromPrivateKey(const char* PrivateKey, size_t PrivateKeySize, uint8_t OutPrivateKeyHash[20]);
				virtual void GenerateMessageHash(const std::string_view& Input, uint8_t Output[32]);
				virtual String GetMessageMagic();
				virtual String GeneratePkhAddress(const char* PublicKeyHash20);
				virtual String GenerateUncheckedAddress(const std::string_view& Data);
				virtual String GenerateChecksumAddress(const std::string_view& Address);
				virtual String EncodeEthAddress(const std::string_view& EthAddress);
				virtual String DecodeNonEthAddress(const std::string_view& NonEthAddress);
				virtual String NormalizeTopicAddress(const std::string_view& Address);
				virtual String Uint256ToHex(const uint256_t& Data);
				virtual String GetRawGasLimit(Schema* TxData);
				virtual uint256_t HexToUint256(const std::string_view& Data);
				virtual uint256_t FromEth(const Decimal& Value, const Decimal& Divisibility = 1);
				virtual Decimal ToEth(const uint256_t& Value, const Decimal& Divisibility = 1);
				virtual Decimal GetDivisibilityGwei();
				virtual uint256_t GetEthTransferGasLimitGwei();
				virtual uint256_t GetErc20TransferGasLimitGwei();
				virtual const btc_chainparams_* GetChain();
			};
		}
	}
}
#endif