#ifndef TAN_LAYER_NSS_H
#define TAN_LAYER_NSS_H
#include "../../kernel/mediator.h"

namespace Tangent
{
	namespace NSS
	{
		typedef std::function<bool(const std::string_view&)> InvocationCallback;
		typedef std::function<Promise<void>(const Mediator::ChainSupervisorOptions&, Mediator::TransactionLogs&&)> TransactionCallback;

		struct TransactionListener
		{
			Algorithm::AssetId Asset = 0;
			Mediator::ChainSupervisorOptions Options;
			TaskId CooldownId = INVALID_TASK_ID;
			bool IsDryRun = true;
			bool IsDead = false;
		};

		struct TransactionParams
		{
			Vector<Mediator::Transferer> To;
			Option<Mediator::BaseFee> Fee = Optional::None;
			uint256_t ExternalId = 0;
			Algorithm::AssetId Asset = 0;
			Mediator::DynamicWallet Wallet = Mediator::DynamicWallet();
			ExpectsPromiseRT<Mediator::OutgoingTransaction> Future;
		};

		struct TransactionQueueState
		{
			SingleQueue<TransactionParams*> Queue;
			String Blockchain;
			size_t Transactions = 0;
			bool IsBusy = false;
		};

		class ServerNode : public Singleton<ServerNode>
		{
		protected:
			UnorderedSet<String> Connections;
			UnorderedMap<String, InvocationCallback> Registrations;
			UnorderedMap<String, UPtr<TransactionQueueState>> States;
			UnorderedMap<String, TransactionCallback> Callbacks;
			UnorderedMap<String, std::pair<Mediator::BaseFee, int64_t>> Fees;
			UnorderedMap<String, Vector<UPtr<Mediator::ServerRelay>>> Nodes;
			UnorderedMap<String, UPtr<Mediator::RelayBackend>> Chains;
			UnorderedMap<String, UPtr<Schema>> Specifications;
			Vector<UPtr<TransactionListener>> Listeners;
			Mediator::MultichainSupervisorOptions Options;
			SystemControl ControlSys;

		public:
			ServerNode() noexcept;
			~ServerNode() noexcept;
			ExpectsPromiseSystem<HTTP::ResponseFrame> InternalCall(const std::string_view& Location, const std::string_view& Method, const HTTP::FetchFrame& Options);
			ExpectsPromiseRT<Mediator::OutgoingTransaction> SubmitTransaction(const uint256_t& ExternalId, const Algorithm::AssetId& Asset, Mediator::DynamicWallet&& Wallet, Vector<Mediator::Transferer>&& To, Option<Mediator::BaseFee>&& Fee = Optional::None);
			ExpectsPromiseRT<void> BroadcastTransaction(const Algorithm::AssetId& Asset, const uint256_t& ExternalId, const Mediator::OutgoingTransaction& TxData);
			ExpectsPromiseRT<void> ValidateTransaction(const Mediator::IncomingTransaction& Value);
			ExpectsPromiseRT<uint64_t> GetLatestBlockHeight(const Algorithm::AssetId& Asset);
			ExpectsPromiseRT<Schema*> GetBlockTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, String* BlockHash);
			ExpectsPromiseRT<Schema*> GetBlockTransaction(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, const std::string_view& TransactionId);
			ExpectsPromiseRT<Vector<Mediator::IncomingTransaction>> GetAuthenticTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, Schema* TransactionData);
			ExpectsPromiseRT<Schema*> ExecuteRPC(const Algorithm::AssetId& Asset, const std::string_view& Method, SchemaList&& Args, Mediator::CachePolicy Cache);
			ExpectsPromiseRT<Mediator::OutgoingTransaction> NewTransaction(const Algorithm::AssetId& Asset, const Mediator::DynamicWallet& Wallet, const Vector<Mediator::Transferer>& To, Option<Mediator::BaseFee>&& Fee = Optional::None);
			ExpectsPromiseRT<Mediator::TransactionLogs> GetTransactionLogs(const Algorithm::AssetId& Asset, Mediator::ChainSupervisorOptions* Options);
			ExpectsPromiseRT<Mediator::BaseFee> EstimateFee(const Algorithm::AssetId& Asset, const Mediator::DynamicWallet& Wallet, const Vector<Mediator::Transferer>& To, const Mediator::FeeSupervisorOptions& Options = Mediator::FeeSupervisorOptions());
			ExpectsPromiseRT<Decimal> CalculateBalance(const Algorithm::AssetId& Asset, const Mediator::DynamicWallet& Wallet, Option<String>&& Address = Optional::None);
			ExpectsLR<Mediator::MasterWallet> NewMasterWallet(const Algorithm::AssetId& Asset, const std::string_view& Seed);
			ExpectsLR<Mediator::MasterWallet> NewMasterWallet(const Algorithm::AssetId& Asset, const Algorithm::Seckey PrivateKey);
			ExpectsLR<Mediator::DerivedSigningWallet> NewSigningWallet(const Algorithm::AssetId& Asset, const Mediator::MasterWallet& Wallet, Option<uint64_t>&& AddressIndex = Optional::None);
			ExpectsLR<Mediator::DerivedSigningWallet> NewSigningWallet(const Algorithm::AssetId& Asset, const PrivateKey& SigningKey);
			ExpectsLR<Mediator::DerivedVerifyingWallet> NewVerifyingWallet(const Algorithm::AssetId& Asset, const std::string_view& VerifyingKey);
			ExpectsLR<String> NewPublicKeyHash(const Algorithm::AssetId& Asset, const std::string_view& Address);
			ExpectsLR<String> SignMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const PrivateKey& SigningKey);
			ExpectsLR<void> VerifyMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const std::string_view& VerifyingKey, const std::string_view& Signature);
			ExpectsLR<void> EnableSigningWallet(const Algorithm::AssetId& Asset, const Mediator::MasterWallet& Wallet, const Mediator::DerivedSigningWallet& SigningWallet);
			ExpectsLR<void> EnableCheckpointHeight(const Algorithm::AssetId& Asset, uint64_t BlockHeight);
			ExpectsLR<void> EnableContractAddress(const Algorithm::AssetId& Asset, const std::string_view& ContractAddress);
			ExpectsLR<void> EnableWalletAddress(const Algorithm::AssetId& Asset, const std::string_view& Binding, const std::string_view& Address, uint64_t AddressIndex);
			ExpectsLR<void> DisableWalletAddress(const Algorithm::AssetId& Asset, const std::string_view& Address);
			ExpectsLR<uint64_t> GetLatestKnownBlockHeight(const Algorithm::AssetId& Asset);
			ExpectsLR<Mediator::IndexAddress> GetAddressIndex(const Algorithm::AssetId& Asset, const std::string_view& Address);
			ExpectsLR<UnorderedMap<String, Mediator::IndexAddress>> GetAddressIndices(const Algorithm::AssetId& Asset, const UnorderedSet<String>& Addresses);
			ExpectsLR<Vector<String>> GetAddressIndices(const Algorithm::AssetId& Asset);
			ExpectsLR<void> AddUTXO(const Algorithm::AssetId& Asset, const Mediator::IndexUTXO& Value);
			ExpectsLR<void> RemoveUTXO(const Algorithm::AssetId& Asset, const std::string_view& TransactionId, uint32_t Index);
			ExpectsLR<Mediator::IndexUTXO> GetUTXO(const Algorithm::AssetId& Asset, const std::string_view& TransactionId, uint32_t Index);
			ExpectsLR<Vector<Mediator::IndexUTXO>> GetUTXOs(const Algorithm::AssetId& Asset, const std::string_view& Binding, size_t Offset, size_t Count);
			ExpectsLR<Schema*> LoadCache(const Algorithm::AssetId& Asset, Mediator::CachePolicy Policy, const std::string_view& Key);
			ExpectsLR<void> StoreCache(const Algorithm::AssetId& Asset, Mediator::CachePolicy Policy, const std::string_view& Key, UPtr<Schema>&& Value);
			Option<String> GetContractAddress(const Algorithm::AssetId& Asset);
			UnorderedMap<Algorithm::AssetId, Mediator::RelayBackend::Chainparams> GetChains();
			UnorderedMap<String, Mediator::MasterWallet> GetWallets(const Algorithm::Seckey PrivateKey);
			UnorderedMap<String, InvocationCallback>& GetRegistrations();
			Vector<Algorithm::AssetId> GetAssets(bool ObservingOnly = false);
			Vector<UPtr<Mediator::ServerRelay>>* GetNodes(const Algorithm::AssetId& Asset);
			const Mediator::RelayBackend::Chainparams* GetChainparams(const Algorithm::AssetId& Asset);
			Mediator::ServerRelay* AddNode(const Algorithm::AssetId& Asset, const std::string_view& URL, double Throttling);
			Mediator::ServerRelay* GetNode(const Algorithm::AssetId& Asset);
			Mediator::RelayBackend* GetChain(const Algorithm::AssetId& Asset);
			Schema* GetSpecifications(const Algorithm::AssetId& Asset);
			Schema* AddSpecifications(const Algorithm::AssetId& Asset, UPtr<Schema>&& Value);
			ServiceControl::ServiceNode GetEntrypoint();
			Mediator::MultichainSupervisorOptions& GetOptions();
			SystemControl& GetControl();
			void AddTransactionCallback(const std::string_view& Name, TransactionCallback&& Callback);
			void Startup();
			void Shutdown();
			bool HasChain(const Algorithm::AssetId& Asset);
			bool HasNode(const Algorithm::AssetId& Asset);
			bool HasObserver(const Algorithm::AssetId& Asset);
			bool HasSupport(const Algorithm::AssetId& Asset);
			bool IsActive();

		public:
			template <typename T, typename... Args>
			T* AddChain(const Algorithm::AssetId& Asset, Args&&... Values)
			{
				T* Instance = new T(Values...);
				AddChainInstance(Asset, Instance);
				return Instance;
			}

		private:
			void AddNodeInstance(const Algorithm::AssetId& Asset, Mediator::ServerRelay* Instance);
			void AddChainInstance(const Algorithm::AssetId& Asset, Mediator::RelayBackend* Instance);
			void DispatchTransactionQueue(TransactionQueueState* State, TransactionParams* FromParams);
			void FinalizeTransaction(TransactionQueueState* State, UPtr<TransactionParams>&& Params, ExpectsRT<Mediator::OutgoingTransaction>&& Transaction);
			bool CallTransactionListener(TransactionListener* Listener);
		};
	}
}
#endif