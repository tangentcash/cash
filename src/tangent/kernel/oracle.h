#ifndef TAN_ORACLE_H
#define TAN_ORACLE_H
#include "../policy/messages.h"
#include "../layer/control.h"

namespace Tangent
{
	namespace Oracle
	{
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

		class Nodemaster;
		class Chainmaster;

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
			PrivateKey VerifyingKey;
			uint64_t MaxAddressIndex = 0;

			MasterWallet() = default;
			MasterWallet(PrivateKey&& NewSeedingKey, PrivateKey&& NewVerifyingKey, PrivateKey&& NewSigningKey);
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
			PrivateKey VerifyingKey;

			DerivedVerifyingWallet() = default;
			DerivedVerifyingWallet(AddressMap&& NewAddresses, Option<uint64_t>&& NewAddressIndex, PrivateKey&& NewVerifyingKey);
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
				UnorderedSet<Nodemaster*> Interactions;
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
			const UnorderedSet<Nodemaster*>& GetInteractedNodes() const;
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

		class Nodemaster : public Reference<Nodemaster>
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
			Nodemaster(const std::string_view& NodeURL, double NodeThrottling) noexcept;
			~Nodemaster() noexcept;
			Promise<ExpectsLR<Schema*>> ExecuteRPC(const Algorithm::AssetId& Asset, ErrorReporter& Reporter, const std::string_view& Method, const SchemaList& Args, CachePolicy Cache);
			Promise<ExpectsLR<Schema*>> ExecuteRPC3(const Algorithm::AssetId& Asset, ErrorReporter& Reporter, const std::string_view& Method, const SchemaArgs& Args, CachePolicy Cache);
			Promise<ExpectsLR<Schema*>> ExecuteREST(const Algorithm::AssetId& Asset, ErrorReporter& Reporter, const std::string_view& Method, const std::string_view& Path, Schema* Args, CachePolicy Cache);
			Promise<ExpectsLR<Schema*>> ExecuteHTTP(const Algorithm::AssetId& Asset, ErrorReporter& Reporter, const std::string_view& Method, const std::string_view& Path, const std::string_view& Type, const std::string_view& Body, CachePolicy Cache);
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

		class Chainmaster : public Reference<Chainmaster>
		{
			friend class Datamaster;

		public:
			typedef std::function<void(Nodemaster*)> InteractionCallback;

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
			Chainmaster() noexcept;
			virtual ~Chainmaster() noexcept;
			virtual Promise<ExpectsLR<void>> BroadcastTransaction(const Algorithm::AssetId& Asset, const OutgoingTransaction& TxData) = 0;
			virtual Promise<ExpectsLR<uint64_t>> GetLatestBlockHeight(const Algorithm::AssetId& Asset) = 0;
			virtual Promise<ExpectsLR<Schema*>> GetBlockTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, String* BlockHash) = 0;
			virtual Promise<ExpectsLR<Schema*>> GetBlockTransaction(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, const std::string_view& TransactionId) = 0;
			virtual Promise<ExpectsLR<Vector<IncomingTransaction>>> GetAuthenticTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, Schema* TransactionData) = 0;
			virtual Promise<ExpectsLR<BaseFee>> EstimateFee(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const FeeSupervisorOptions& Options) = 0;
			virtual Promise<ExpectsLR<Decimal>> CalculateBalance(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, Option<String>&& Address) = 0;
			virtual Promise<ExpectsLR<Schema*>> ExecuteRPC(const Algorithm::AssetId& Asset, const std::string_view& Method, SchemaList&& Args, CachePolicy Cache);
			virtual Promise<ExpectsLR<Schema*>> ExecuteRPC3(const Algorithm::AssetId& Asset, const std::string_view& Method, SchemaArgs&& Args, CachePolicy Cache);
			virtual Promise<ExpectsLR<Schema*>> ExecuteREST(const Algorithm::AssetId& Asset, const std::string_view& Method, const std::string_view& Path, Schema* Args, CachePolicy Cache);
			virtual Promise<ExpectsLR<Schema*>> ExecuteHTTP(const Algorithm::AssetId& Asset, const std::string_view& Method, const std::string_view& Path, const std::string_view& Type, const std::string_view& Body, CachePolicy Cache);
			virtual Promise<ExpectsLR<OutgoingTransaction>> NewTransaction(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const BaseFee& Fee) = 0;
			virtual ExpectsLR<MasterWallet> NewMasterWallet(const std::string_view& Seed) = 0;
			virtual ExpectsLR<DerivedSigningWallet> NewSigningWallet(const Algorithm::AssetId& Asset, const MasterWallet& Wallet, uint64_t AddressIndex) = 0;
			virtual ExpectsLR<DerivedSigningWallet> NewSigningWallet(const Algorithm::AssetId& Asset, const std::string_view& SigningKey) { return LayerException(); };
			virtual ExpectsLR<DerivedVerifyingWallet> NewVerifyingWallet(const Algorithm::AssetId& Asset, const std::string_view& VerifyingKey) { return LayerException(); };
			virtual ExpectsLR<String> NewAddress(const Algorithm::AssetId& Asset, const std::string_view& VerifyingKey) { return LayerException(); };
			virtual ExpectsLR<String> NewPublicKeyHash(const std::string_view& Address) { return LayerException(); };
			virtual ExpectsLR<String> SignMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const PrivateKey& SigningKey) = 0;
			virtual ExpectsLR<void> VerifyMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const std::string_view& VerifyingKey, const std::string_view& Signature) = 0;
			virtual ExpectsLR<OrderedMap<String, uint64_t>> FindCheckpointAddresses(const Algorithm::AssetId& Asset, const UnorderedSet<String>& Addresses);
			virtual ExpectsLR<Vector<String>> GetCheckpointAddresses(const Algorithm::AssetId& Asset);
			virtual ExpectsLR<void> VerifyNodeCompatibility(Nodemaster* Node);
			virtual String GetDerivation(uint64_t AddressIndex) const = 0;
			virtual String GetChecksumHash(const std::string_view& Value) const;
			virtual uint256_t ToBaselineValue(const Decimal& Value) const;
			virtual const Chainparams& GetChainparams() const = 0;
		};

		class ChainmasterUTXO : public Chainmaster
		{
		public:
			ChainmasterUTXO() noexcept;
			virtual ~ChainmasterUTXO() = default;
			virtual Promise<ExpectsLR<CoinUTXO>> GetTransactionOutput(const Algorithm::AssetId& Asset, const std::string_view& TransactionId, uint32_t Index) = 0;
			virtual Promise<ExpectsLR<Decimal>> CalculateBalance(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, Option<String>&& Address) override;
			virtual ExpectsLR<Vector<CoinUTXO>> CalculateCoins(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, Option<Decimal>&& MinNativeValue, Option<TokenUTXO>&& MinTokenValue);
			virtual ExpectsLR<CoinUTXO> GetCoins(const Algorithm::AssetId& Asset, const std::string_view& TransactionId, uint32_t Index);
			virtual ExpectsLR<void> UpdateCoins(const Algorithm::AssetId& Asset, const OutgoingTransaction& TxData);
			virtual ExpectsLR<void> AddCoins(const Algorithm::AssetId& Asset, const CoinUTXO& Output);
			virtual ExpectsLR<void> RemoveCoins(const Algorithm::AssetId& Asset, const std::string_view& TransactionId, uint32_t Index);
			virtual Decimal GetCoinsValue(const Vector<CoinUTXO>& Values, Option<String>&& ContractAddress);
		};

		class Paymaster : Singletonish
		{
		public:
			typedef std::function<Promise<void>(const ChainSupervisorOptions&, TransactionLogs&&)> TransactionCallback;

		private:
			struct TransactionListener
			{
				Algorithm::AssetId Asset = 0;
				ChainSupervisorOptions Options;
				TaskId CooldownId = INVALID_TASK_ID;
				bool IsDryRun = true;
				bool IsDead = false;
			};

			struct TransactionParams
			{
				Vector<Transferer> To;
				Option<BaseFee> Fee = Optional::None;
				uint256_t ExternalId = 0;
				Algorithm::AssetId Asset = 0;
				DynamicWallet Wallet = DynamicWallet();
				Promise<ExpectsLR<OutgoingTransaction>> Future;
			};

			struct TransactionQueueState
			{
				SingleQueue<TransactionParams*> Queue;
				String Blockchain;
				size_t Transactions = 0;
				bool IsBusy = false;
			};

		private:
			static UnorderedSet<String>* Connections;
			static UnorderedMap<String, UPtr<TransactionQueueState>>* States;
			static UnorderedMap<String, TransactionCallback>* Callbacks;
			static Vector<UPtr<TransactionListener>>* Listeners;
			static MultichainSupervisorOptions* Settings;
			static SystemControl ControlSys;

		public:
			static Promise<ExpectsLR<OutgoingTransaction>> SubmitTransaction(const uint256_t& ExternalId, const Algorithm::AssetId& Asset, DynamicWallet&& Wallet, Vector<Transferer>&& To, Option<BaseFee>&& Fee = Optional::None);
			static Promise<bool> Startup(const MultichainSupervisorOptions& Options);
			static Promise<bool> Shutdown();
			static void SubmitCallback(const std::string_view& Name, TransactionCallback&& Callback);
			static bool HasSupport(const Algorithm::AssetId& Asset);
			static MultichainSupervisorOptions& GetOptions();
			static SystemControl& GetControl();

		private:
			static bool CallTransactionListener(TransactionListener* Listener);
			static void DispatchTransactionQueue(TransactionQueueState* State, TransactionParams* FromParams);
			static void FinalizeTransaction(TransactionQueueState* State, UPtr<TransactionParams>&& Params, ExpectsLR<OutgoingTransaction>&& Transaction);
		};

		class Datamaster : Singletonish
		{
			friend Paymaster;

		private:
			static UnorderedMap<String, std::pair<BaseFee, int64_t>>* Fees;
			static UnorderedMap<String, Vector<UPtr<Nodemaster>>>* Nodes;
			static UnorderedMap<String, UPtr<Chainmaster>>* Chains;
			static UnorderedMap<String, UPtr<Schema>>* Options;
			static std::recursive_mutex Mutex;

		public:
			static Promise<ExpectsLR<void>> BroadcastTransaction(const Algorithm::AssetId& Asset, const uint256_t& ExternalId, const OutgoingTransaction& TxData);
			static Promise<ExpectsLR<void>> ValidateTransaction(const IncomingTransaction& Value);
			static Promise<ExpectsLR<uint64_t>> GetLatestBlockHeight(const Algorithm::AssetId& Asset);
			static Promise<ExpectsLR<Schema*>> GetBlockTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, String* BlockHash);
			static Promise<ExpectsLR<Schema*>> GetBlockTransaction(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, const std::string_view& TransactionId);
			static Promise<ExpectsLR<Vector<IncomingTransaction>>> GetAuthenticTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, Schema* TransactionData);
			static Promise<ExpectsLR<Schema*>> ExecuteRPC(const Algorithm::AssetId& Asset, const std::string_view& Method, SchemaList&& Args, CachePolicy Cache);
			static Promise<ExpectsLR<OutgoingTransaction>> NewTransaction(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, Option<BaseFee>&& Fee = Optional::None);
			static Promise<ExpectsLR<TransactionLogs>> GetTransactionLogs(const Algorithm::AssetId& Asset, ChainSupervisorOptions* Options);
			static Promise<ExpectsLR<BaseFee>> EstimateFee(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const FeeSupervisorOptions& Options = FeeSupervisorOptions());
			static Promise<ExpectsLR<Decimal>> CalculateBalance(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, Option<String>&& Address = Optional::None);
			static ExpectsLR<MasterWallet> NewMasterWallet(const Algorithm::AssetId& Asset, const std::string_view& Seed);
			static ExpectsLR<MasterWallet> NewMasterWallet(const Algorithm::AssetId& Asset, const Algorithm::Seckey PrivateKey);
			static ExpectsLR<DerivedSigningWallet> NewSigningWallet(const Algorithm::AssetId& Asset, const MasterWallet& Wallet, Option<uint64_t>&& AddressIndex = Optional::None);
			static ExpectsLR<DerivedSigningWallet> NewSigningWallet(const Algorithm::AssetId& Asset, const std::string_view& SigningKey);
			static ExpectsLR<DerivedVerifyingWallet> NewVerifyingWallet(const Algorithm::AssetId& Asset, const std::string_view& VerifyingKey);
			static ExpectsLR<String> NewPublicKeyHash(const Algorithm::AssetId& Asset, const std::string_view& Address);
			static ExpectsLR<String> SignMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const PrivateKey& SigningKey);
			static ExpectsLR<void> VerifyMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const std::string_view& VerifyingKey, const std::string_view& Signature);
			static ExpectsLR<void> EnableCheckpointHeight(const Algorithm::AssetId& Asset, uint64_t BlockHeight);
			static ExpectsLR<void> EnableWalletAddress(const Algorithm::AssetId& Asset, const std::string_view& Binding, const std::string_view& Address, uint64_t AddressIndex);
			static ExpectsLR<void> EnableContractAddress(const Algorithm::AssetId& Asset, const std::string_view& ContractAddress);
			static ExpectsLR<uint64_t> GetLatestKnownBlockHeight(const Algorithm::AssetId& Asset);
			static Option<String> GetContractAddress(const Algorithm::AssetId& Asset);
			static UnorderedMap<Algorithm::AssetId, Chainmaster::Chainparams> GetChains();
			static Vector<Algorithm::AssetId> GetAssets(bool ObservingOnly = false);
			static Vector<UPtr<Nodemaster>>* GetNodes(const Algorithm::AssetId& Asset);
			static Nodemaster* GetNode(const Algorithm::AssetId& Asset);
			static Chainmaster* GetChain(const Algorithm::AssetId& Asset);
			static const Chainmaster::Chainparams* GetChainparams(const Algorithm::AssetId& Asset);
			static Schema* GetOptions(const Algorithm::AssetId& Asset);
			static Schema* AddOptions(const Algorithm::AssetId& Asset, UPtr<Schema>&& Value);
			static Nodemaster* AddNode(const Algorithm::AssetId& Asset, const std::string_view& URL, double Throttling);
			static bool HasChain(const Algorithm::AssetId& Asset);
			static bool HasNode(const Algorithm::AssetId& Asset);
			static bool HasOracle(const Algorithm::AssetId& Asset);
			static bool IsInitialized();
			static void Initialize();
			static void Cleanup();

		public:
			template <typename T, typename... Args>
			static T* AddChain(const Algorithm::AssetId& Asset, Args&&... Values)
			{
				T* Instance = new T(Values...);
				AddChainInstance(Asset, Instance);
				return Instance;
			}

		private:
			static void AddNodeInstance(const Algorithm::AssetId& Asset, Nodemaster* Instance);
			static void AddChainInstance(const Algorithm::AssetId& Asset, Chainmaster* Instance);
		};

		class Bridge
		{
		public:
			typedef std::function<bool(const std::string_view&)> InvocationCallback;

		public:
			static void Open(Schema* Config, bool Observe);
			static void Close();
			static UnorderedMap<String, Oracle::MasterWallet> GetWallets(const Algorithm::Seckey PrivateKey);
			static UnorderedMap<String, InvocationCallback> GetRegistrations();
		};
	}
}
#endif