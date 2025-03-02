#ifndef TAN_MEDIATOR_H
#define TAN_MEDIATOR_H
#include "../policy/messages.h"
#include "../layer/control.h"

namespace Tangent
{
	namespace Mediator
	{
		enum
		{
			KEY_LIMIT = 1024
		};

		enum class RoutingPolicy
		{
			Account,
			Memo,
			UTXO
		};

		enum class CachePolicy
		{
			Greedy,
			Lazy,
			Shortened,
			Extended,
			Persistent
		};

		class ServerRelay;

		class RelayBackend;

		struct TokenUTXO
		{
			String ContractAddress;
			String Symbol;
			Decimal Value;
			uint8_t Decimals;

			TokenUTXO();
			TokenUTXO(const std::string_view& NewContractAddress, const Decimal& NewValue);
			TokenUTXO(const std::string_view& NewContractAddress, const std::string_view& NewSymbol, const Decimal& NewValue, uint8_t NewDecimals);
			Decimal GetDivisibility();
			bool IsCoinValid() const;
		};

		struct CoinUTXO
		{
			Vector<TokenUTXO> Tokens;
			Option<uint64_t> AddressIndex = Optional::None;
			String TransactionId;
			String Address;
			Decimal Value;
			uint32_t Index = 0;

			CoinUTXO() = default;
			CoinUTXO(const std::string_view& NewTransactionId, const std::string_view& NewAddress, Option<uint64_t>&& AddressIndex, Decimal&& NewValue, uint32_t NewIndex);
			void ApplyTokenValue(const std::string_view& ContractAddress, const std::string_view& Symbol, const Decimal& Value, uint8_t Decimals);
			Option<Decimal> GetTokenValue(const std::string_view& ContractAddress);
			bool IsValid() const;
		};

		struct Transferer
		{
			Option<uint64_t> AddressIndex = Optional::None;
			String Address;
			Decimal Value;

			Transferer();
			Transferer(const std::string_view& NewAddress, Option<uint64_t>&& AddressIndex, Decimal&& NewValue);
			bool IsValid() const;
		};

		struct MasterWallet : Messages::Generic
		{
			PrivateKey SeedingKey;
			PrivateKey SigningKey;
			String VerifyingKey;
			uint64_t MaxAddressIndex = 0;

			MasterWallet() = default;
			MasterWallet(PrivateKey&& NewSeedingKey, PrivateKey&& NewSigningKey, String&& NewVerifyingKey);
			MasterWallet(const MasterWallet&) = default;
			MasterWallet(MasterWallet&&) = default;
			MasterWallet& operator=(const MasterWallet&) = default;
			MasterWallet& operator=(MasterWallet&&) = default;
			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			bool IsValid() const;
			UPtr<Schema> AsSchema() const override;
			uint256_t AsHash(bool Renew = false) const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct DerivedVerifyingWallet : Messages::Generic
		{
			AddressMap Addresses;
			Option<uint64_t> AddressIndex = Optional::None;
			String VerifyingKey;

			DerivedVerifyingWallet() = default;
			DerivedVerifyingWallet(AddressMap&& NewAddresses, Option<uint64_t>&& NewAddressIndex, String&& NewVerifyingKey);
			DerivedVerifyingWallet(const DerivedVerifyingWallet&) = default;
			DerivedVerifyingWallet(DerivedVerifyingWallet&&) = default;
			DerivedVerifyingWallet& operator=(const DerivedVerifyingWallet&) = default;
			DerivedVerifyingWallet& operator=(DerivedVerifyingWallet&&) = default;
			virtual bool StorePayload(Format::Stream* Stream) const override;
			virtual bool LoadPayload(Format::Stream& Stream) override;
			virtual bool IsValid() const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct DerivedSigningWallet : DerivedVerifyingWallet
		{
			PrivateKey SigningKey;

			DerivedSigningWallet() = default;
			DerivedSigningWallet(DerivedVerifyingWallet&& NewWallet, PrivateKey&& NewSigningKey);
			DerivedSigningWallet(const DerivedSigningWallet&) = default;
			DerivedSigningWallet(DerivedSigningWallet&&) = default;
			DerivedSigningWallet& operator=(const DerivedSigningWallet&) = default;
			DerivedSigningWallet& operator=(DerivedSigningWallet&&) = default;
			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			bool IsValid() const override;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct DynamicWallet
		{
			Option<MasterWallet> Parent;
			Option<DerivedVerifyingWallet> VerifyingChild;
			Option<DerivedSigningWallet> SigningChild;

			DynamicWallet();
			DynamicWallet(const MasterWallet& Value);
			DynamicWallet(const DerivedVerifyingWallet& Value);
			DynamicWallet(const DerivedSigningWallet& Value);
			DynamicWallet(const DynamicWallet&) = default;
			DynamicWallet(DynamicWallet&&) = default;
			DynamicWallet& operator=(const DynamicWallet&) = default;
			DynamicWallet& operator=(DynamicWallet&&) = default;
			Option<String> GetBinding() const;
			bool IsValid() const;
		};

		struct IncomingTransaction : Messages::Generic
		{
			Vector<Transferer> To;
			Vector<Transferer> From;
			Algorithm::AssetId Asset;
			String TransactionId;
			uint64_t BlockId = 0;
			Decimal Fee;

			IncomingTransaction();
			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			bool IsValid() const;
			void SetTransaction(const Algorithm::AssetId& NewAsset, uint64_t NewBlockId, const std::string_view& NewTransactionId, Decimal&& NewFee);
			void SetOperations(Vector<Transferer>&& NewFrom, Vector<Transferer>&& NewTo);
			bool IsLatencyApproved() const;
			bool IsApproved() const;
			Decimal GetInputValue() const;
			Decimal GetOutputValue() const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct OutgoingTransaction : Messages::Generic
		{
			Option<Vector<CoinUTXO>> Inputs;
			Option<Vector<CoinUTXO>> Outputs;
			IncomingTransaction Transaction;
			String Data;

			OutgoingTransaction();
			OutgoingTransaction(IncomingTransaction&& NewTransaction, const std::string_view& NewData, Option<Vector<CoinUTXO>>&& NewInputs = Optional::None, Option<Vector<CoinUTXO>>&& NewOutputs = Optional::None);
			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			bool IsValid() const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct TransactionLogs
		{
			Vector<IncomingTransaction> Transactions;
			uint64_t BlockHeight = (uint64_t)-1;
			String BlockHash;
		};

		struct IndexAddress : Messages::Generic
		{
			Option<uint64_t> AddressIndex = Optional::None;
			String Address;
			String Binding;

			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct IndexUTXO : Messages::Generic
		{
			CoinUTXO UTXO;
			String Binding;

			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct BaseFee
		{
			Decimal Price;
			Decimal Limit;

			BaseFee();
			BaseFee(const Decimal& NewPrice, const Decimal& NewLimit);
			Decimal GetFee() const;
			bool IsValid() const;
		};

		struct SupervisorOptions
		{
			uint64_t PollingFrequencyMs = 70000;
			uint64_t MinBlockConfirmations = 0;
		};

		struct ChainSupervisorOptions : SupervisorOptions
		{
			struct
			{
				UnorderedSet<ServerRelay*> Interactions;
				uint64_t CurrentBlockHeight = 0;
				uint64_t LatestBlockHeight = 0;
				uint64_t StartingBlockHeight = 0;
				uint64_t LatestTimeAwaited = 0;
			} State;

			void SetCheckpointFromBlock(uint64_t BlockHeight);
			void SetCheckpointToBlock(uint64_t BlockHeight);
			uint64_t GetNextBlockHeight();
			uint64_t GetTimeAwaited() const;
			bool HasNextBlockHeight() const;
			bool HasCurrentBlockHeight() const;
			bool HasLatestBlockHeight() const;
			bool WillWaitForTransactions() const;
			double GetCheckpointPercentage() const;
			const UnorderedSet<ServerRelay*>& GetInteractedNodes() const;
			bool IsCancelled(const Algorithm::AssetId& Asset);
		};

		struct MultichainSupervisorOptions : SupervisorOptions
		{
			UnorderedMap<String, ChainSupervisorOptions> Specifics;
			uint64_t RetryWaitingTimeMs = 30000;

			ChainSupervisorOptions& AddSpecificOptions(const std::string_view& Blockchain);
		};

		struct FeeSupervisorOptions
		{
			uint64_t BlockHeightOffset = 1;
			uint64_t MaxBlocks = 10;
			uint64_t MaxTransactions = 32;
		};

		class ServerRelay : public Reference<ServerRelay>
		{
		public:
			enum class TransmitType
			{
				Any,
				JSONRPC,
				REST,
				HTTP
			};

			struct ErrorReporter
			{
				TransmitType Type = TransmitType::Any;
				String Method;
			};

		private:
			struct
			{
				String JsonRpcPath;
				bool JsonRpcDistinct = false;
				String RestPath;
				bool RestDistinct = false;
				String HttpPath;
				bool HttpDistinct = false;
			} Paths;

		private:
			Vector<std::pair<Promise<bool>, TaskId>> Tasks;
			std::recursive_mutex Mutex;
			double Throttling;
			int64_t Latest;
			bool Allowed;

		public:
			void* UserData;

		public:
			ServerRelay(const std::string_view& NodeURL, double NodeThrottling) noexcept;
			~ServerRelay() noexcept;
			ExpectsPromiseRT<Schema*> ExecuteRPC(const Algorithm::AssetId& Asset, ErrorReporter& Reporter, const std::string_view& Method, const SchemaList& Args, CachePolicy Cache, const std::string_view& Path);
			ExpectsPromiseRT<Schema*> ExecuteRPC3(const Algorithm::AssetId& Asset, ErrorReporter& Reporter, const std::string_view& Method, const SchemaArgs& Args, CachePolicy Cache, const std::string_view& Path);
			ExpectsPromiseRT<Schema*> ExecuteREST(const Algorithm::AssetId& Asset, ErrorReporter& Reporter, const std::string_view& Method, const std::string_view& Path, Schema* Args, CachePolicy Cache);
			ExpectsPromiseRT<Schema*> ExecuteHTTP(const Algorithm::AssetId& Asset, ErrorReporter& Reporter, const std::string_view& Method, const std::string_view& Path, const std::string_view& Type, const std::string_view& Body, CachePolicy Cache);
			Promise<bool> YieldForCooldown(uint64_t& RetryTimeout, uint64_t TotalTimeoutMs);
			Promise<bool> YieldForDiscovery(ChainSupervisorOptions* Options);
			ExpectsLR<void> VerifyCompatibility(const Algorithm::AssetId& Asset);
			TaskId EnqueueActivity(const Promise<bool>& Future, TaskId TimerId);
			void DequeueActivity(TaskId TimerId);
			void AllowActivities();
			void CancelActivities();
			bool HasDistinctURL(TransmitType Type) const;
			bool IsActivityAllowed() const;
			const String& GetNodeURL(TransmitType Type) const;
			String GetNodeURL(TransmitType Type, const std::string_view& Path) const;

		public:
			static std::string_view GetCacheType(CachePolicy Cache);

		private:
			static String GenerateErrorMessage(const ExpectsSystem<HTTP::ResponseFrame>& Response, const ErrorReporter& Reporter, const std::string_view& ErrorCode, const std::string_view& ErrorMessage);
		};

		class RelayBackend : public Reference<RelayBackend>
		{
			friend class Datamaster;

		public:
			typedef std::function<void(ServerRelay*)> InteractionCallback;

		public:
			struct Chainparams
			{
				Algorithm::Composition::Type Composition;
				RoutingPolicy Routing;
				uint64_t SyncLatency;
				Decimal Divisibility;
				String SupportsTokenTransfer;
				bool SupportsBulkTransfer;
			};

		public:
			InteractionCallback Interact;

		public:
			RelayBackend() noexcept;
			virtual ~RelayBackend() noexcept;
			virtual ExpectsPromiseRT<void> BroadcastTransaction(const Algorithm::AssetId& Asset, const OutgoingTransaction& TxData) = 0;
			virtual ExpectsPromiseRT<uint64_t> GetLatestBlockHeight(const Algorithm::AssetId& Asset) = 0;
			virtual ExpectsPromiseRT<Schema*> GetBlockTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, String* BlockHash) = 0;
			virtual ExpectsPromiseRT<Schema*> GetBlockTransaction(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, const std::string_view& TransactionId) = 0;
			virtual ExpectsPromiseRT<Vector<IncomingTransaction>> GetAuthenticTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, Schema* TransactionData) = 0;
			virtual ExpectsPromiseRT<BaseFee> EstimateFee(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const FeeSupervisorOptions& Options) = 0;
			virtual ExpectsPromiseRT<Decimal> CalculateBalance(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, Option<String>&& Address) = 0;
			virtual ExpectsPromiseRT<Schema*> ExecuteRPC(const Algorithm::AssetId& Asset, const std::string_view& Method, SchemaList&& Args, CachePolicy Cache, const std::string_view& Path = std::string_view());
			virtual ExpectsPromiseRT<Schema*> ExecuteRPC3(const Algorithm::AssetId& Asset, const std::string_view& Method, SchemaArgs&& Args, CachePolicy Cache, const std::string_view& Path = std::string_view());
			virtual ExpectsPromiseRT<Schema*> ExecuteREST(const Algorithm::AssetId& Asset, const std::string_view& Method, const std::string_view& Path, Schema* Args, CachePolicy Cache);
			virtual ExpectsPromiseRT<Schema*> ExecuteHTTP(const Algorithm::AssetId& Asset, const std::string_view& Method, const std::string_view& Path, const std::string_view& Type, const std::string_view& Body, CachePolicy Cache);
			virtual ExpectsPromiseRT<OutgoingTransaction> NewTransaction(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const BaseFee& Fee) = 0;
			virtual ExpectsLR<MasterWallet> NewMasterWallet(const std::string_view& Seed) = 0;
			virtual ExpectsLR<DerivedSigningWallet> NewSigningWallet(const Algorithm::AssetId& Asset, const MasterWallet& Wallet, uint64_t AddressIndex) = 0;
			virtual ExpectsLR<DerivedSigningWallet> NewSigningWallet(const Algorithm::AssetId& Asset, const PrivateKey& SigningKey) = 0;
			virtual ExpectsLR<DerivedVerifyingWallet> NewVerifyingWallet(const Algorithm::AssetId& Asset, const std::string_view& VerifyingKey) = 0;
			virtual ExpectsLR<String> NewPublicKeyHash(const std::string_view& Address) = 0;
			virtual ExpectsLR<String> SignMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const PrivateKey& SigningKey) = 0;
			virtual ExpectsLR<void> VerifyMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const std::string_view& VerifyingKey, const std::string_view& Signature) = 0;
			virtual ExpectsLR<OrderedMap<String, uint64_t>> FindCheckpointAddresses(const Algorithm::AssetId& Asset, const UnorderedSet<String>& Addresses);
			virtual ExpectsLR<Vector<String>> GetCheckpointAddresses(const Algorithm::AssetId& Asset);
			virtual ExpectsLR<void> VerifyNodeCompatibility(ServerRelay* Node);
			virtual String GetDerivation(uint64_t AddressIndex) const = 0;
			virtual String GetChecksumHash(const std::string_view& Value) const;
			virtual uint256_t ToBaselineValue(const Decimal& Value) const;
			virtual uint64_t GetRetirementBlockNumber() const;
			virtual const Chainparams& GetChainparams() const = 0;
		};

		class RelayBackendUTXO : public RelayBackend
		{
		public:
			RelayBackendUTXO() noexcept;
			virtual ~RelayBackendUTXO() = default;
			virtual ExpectsPromiseRT<CoinUTXO> GetTransactionOutput(const Algorithm::AssetId& Asset, const std::string_view& TransactionId, uint32_t Index) = 0;
			virtual ExpectsPromiseRT<Decimal> CalculateBalance(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, Option<String>&& Address) override;
			virtual ExpectsLR<Vector<CoinUTXO>> CalculateCoins(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, Option<Decimal>&& MinNativeValue, Option<TokenUTXO>&& MinTokenValue);
			virtual ExpectsLR<CoinUTXO> GetCoins(const Algorithm::AssetId& Asset, const std::string_view& TransactionId, uint32_t Index);
			virtual ExpectsLR<void> UpdateCoins(const Algorithm::AssetId& Asset, const OutgoingTransaction& TxData);
			virtual ExpectsLR<void> AddCoins(const Algorithm::AssetId& Asset, const CoinUTXO& Output);
			virtual ExpectsLR<void> RemoveCoins(const Algorithm::AssetId& Asset, const std::string_view& TransactionId, uint32_t Index);
			virtual Decimal GetCoinsValue(const Vector<CoinUTXO>& Values, Option<String>&& ContractAddress);
		};
	}
}
#endif