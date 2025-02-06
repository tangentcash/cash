#ifndef TAN_LAYER_P2P_H
#define TAN_LAYER_P2P_H
#include "../../kernel/block.h"
#include "../../kernel/wallet.h"
#include "../../kernel/mediator.h"

namespace Tangent
{
	namespace Storages
	{
		struct Mempoolstate;
	};

	namespace P2P
	{
		struct Procedure;

		class Relay;

		class OutboundNode;

		class ServerNode;

		typedef std::function<void(Relay*)> AbortCallback;
		typedef SocketConnection InboundNode;

		enum class NodeType
		{
			Inbound,
			Outbound
		};

		struct Procedure
		{
			Format::Variables Args;
			uint32_t Magic = 0;
			uint32_t Method = 0;
			uint32_t Size = 0;
			uint32_t Checksum = 0;

			bool SerializeInto(String* Buffer);
			bool DeserializeFrom(String& Message);
			bool DeserializeFromStream(String& Message, const uint8_t* Buffer, size_t Size);
		};

		class RelayProcedure : public Reference<RelayProcedure>
		{
		public:
			Procedure Data;

		public:
			RelayProcedure(Procedure&& NewData);
			~RelayProcedure() = default;
		};

		class Relay : public Reference<Relay>
		{
		private:
			struct
			{
				void(*Destructor)(void*) = nullptr;
				void* Pointer = nullptr;
			} UserData;
			std::mutex Mutex;
			SingleQueue<URef<RelayProcedure>> PriorityMessages;
			SingleQueue<Procedure> IncomingMessages;
			SingleQueue<Procedure> OutgoingMessages;
			String IncomingData;
			String OutgoingData;
			String Address;
			String Service;
			void* Instance;
			NodeType Type;

		public:
			Relay(NodeType NewType, void* NewInstance);
			~Relay();
			bool IncomingMessageInto(Procedure* Message);
			bool PullIncomingMessage(const uint8_t* Buffer, size_t Size);
			bool BeginOutgoingMessage();
			void EndOutgoingMessage();
			void PushMessage(Procedure&& Message);
			void RelayMessage(URef<RelayProcedure>&& Message);
			void Invalidate();
			const String& PeerAddress();
			const String& PeerService();
			const SingleQueue<URef<RelayProcedure>>& GetPriorityMessages() const;
			const SingleQueue<Procedure>& GetIncomingMessages() const;
			const SingleQueue<Procedure>& GetOutgoingMessages() const;
			const uint8_t* OutgoingBuffer();
			NodeType TypeOf();
			size_t IncomingSize();
			size_t OutgoingSize();
			InboundNode* AsInboundNode();
			OutboundNode* AsOutboundNode();
			Socket* AsSocket();
			void* AsInstance();
			UPtr<Schema> AsSchema() const;
			template <typename T>
			void Use(T* Pointer, void(*Destructor)(T*) = nullptr)
			{
				if (UserData.Pointer && UserData.Destructor)
					UserData.Destructor(UserData.Pointer);
				UserData.Pointer = (void*)Pointer;
				UserData.Destructor = (void(*)(void*))Destructor;
			}
			template <typename T>
			T* AsUser() const
			{
				return (T*)UserData.Pointer;
			}
		};

		class OutboundNode final : public SocketClient
		{
			friend ServerNode;

		public:
			OutboundNode() noexcept;
			~OutboundNode() override = default;

		protected:
			void ConfigureStream() override;
		};

		class ServerNode final : public SocketServer
		{
		public:
			using ReceiveFunction = Promise<void>(*)(ServerNode*, UPtr<Relay>&&, Format::Variables&&);

		public:
			struct
			{
				Option<Ledger::Block> Block = Optional::None;
				uint256_t Hash = 0;
				TaskId Timeout = INVALID_TASK_ID;
			} PendingTip;

			struct
			{
				Ledger::Wallet Wallet;
				Ledger::Validator Node;
			} Validator;

			struct
			{
				std::recursive_mutex Account;
				std::recursive_mutex Block;
				std::mutex Inventory;
			} Sync;

			struct
			{
				size_t Count = 0;
				size_t Offset = 0;
			} Discovery;

			struct
			{
				std::function<void(const uint256_t&, const Ledger::Block&, const Ledger::BlockCheckpoint&)> AcceptBlock;
				std::function<void(const uint256_t&, const Ledger::Transaction*, const Algorithm::Pubkeyhash)> AcceptTransaction;
				std::function<void(const std::string_view&, int8_t)> AcceptMessage;
			} Events;

		private:
			struct
			{
				Option<uint64_t> ActivationBlock = Optional::None;
				bool Dirty = false;
			} Mempool;

		private:
			UnorderedMap<uint256_t, int64_t> Inventory;
			UnorderedMap<uint32_t, std::pair<void*, bool>> InMethods;
			UnorderedMap<void*, uint32_t> OutMethods;
			UnorderedMap<void*, Relay*> Nodes;
			UnorderedSet<OutboundNode*> CandidateNodes;
			SingleQueue<URef<RelayProcedure>> Messages;
			uint32_t MethodAddress;
			SystemControl ControlSys;

		public:
			Ledger::EvaluationContext Environment;
			UnorderedMap<uint256_t, Ledger::BlockHeader> Forks;

		public:
			ServerNode() noexcept;
			virtual ~ServerNode() noexcept override;
			void Startup();
			void Shutdown();
			void Reject(Relay* State);
			void ClearPendingTip();
			void AcceptForkTip(const uint256_t& ForkTip, const uint256_t& CandidateHash, Ledger::BlockHeader&& ForkTipBlock);
			void AcceptPendingTip();
			bool ClearMempool(bool Wait);
			bool AcceptMempool();
			bool AcceptDispatchpool(const Ledger::BlockHeader& Tip);
			bool AcceptBlock(Relay* From, Ledger::Block&& CandidateBlock, const uint256_t& ForkTip);
			bool AcceptMessage(const Algorithm::Pubkey SealingKey, const std::string_view& Plaintext);
			bool Accept(Option<SocketAddress>&& Address = Optional::None);
			ExpectsLR<void> ProposeTransaction(Relay* From, UPtr<Ledger::Transaction>&& CandidateTx, uint64_t AccountSequence, const std::string_view& Purpose, uint256_t* OutputHash = nullptr);
			ExpectsLR<void> AcceptTransaction(Relay* From, UPtr<Ledger::Transaction>&& CandidateTx, bool DeepValidation = false);
			ExpectsLR<void> BroacastTransaction(Relay* From, UPtr<Ledger::Transaction>&& CandidateTx, const Algorithm::Pubkeyhash Owner);
			Relay* Find(const SocketAddress& Address);
			size_t SizeOf(NodeType Type);
			size_t GetConnections();
			bool IsActive();
			bool IsSyncing();
			double GetSyncProgress(const uint256_t& ForkTip, uint64_t CurrentNumber);
			ServiceControl::ServiceNode GetEntrypoint();
			std::recursive_mutex& GetMutex();
			const UnorderedMap<void*, Relay*>& GetNodes() const;
			const UnorderedSet<OutboundNode*>& GetCandidateNodes() const;
			const SingleQueue<URef<RelayProcedure>>& GetMessages() const;

		public:
			void BindCallable(ReceiveFunction Function)
			{
				BindFunction((ReceiveFunction)Function, false);
			}
			void BindMulticallable(ReceiveFunction Function)
			{
				BindFunction((ReceiveFunction)Function, true);
			}
			void Call(Relay* State, ReceiveFunction Function, Format::Variable&& Argument)
			{
				CallFunction(State, (ReceiveFunction)Function, { std::move(Argument) });
			}
			void Multicall(Relay* State, ReceiveFunction Function, Format::Variable&& Argument)
			{
				MulticallFunction(State, (ReceiveFunction)Function, { std::move(Argument) });
			}
			void Call(Relay* State, ReceiveFunction Function, Format::Variables&& Args)
			{
				CallFunction(State, (ReceiveFunction)Function, std::move(Args));
			}
			void Multicall(Relay* State, ReceiveFunction Function, Format::Variables&& Args)
			{
				MulticallFunction(State, (ReceiveFunction)Function, std::move(Args));
			}

		private:
			ExpectsSystem<void> OnUnlisten() override;
			ExpectsLR<void> ApplyValidator(Storages::Mempoolstate& Mempool, Ledger::Validator& Node, Option<Ledger::Wallet>&& Wallet);
			Relay* FindNodeByInstance(void* Instance);
			int32_t ConnectOutboundNode(const SocketAddress& Address);
			bool AcceptBlockCandidate(const Ledger::Block& CandidateBlock, const uint256_t& CandidateHash, const uint256_t& ForkTip);
			bool AcceptProposalTransaction(const Ledger::Block& CheckpointBlock, const Ledger::BlockTransaction& Transaction);
			bool ReceiveOutboundNode(Option<SocketAddress>&& ErrorAddress);
			bool PushNextProcedure(Relay* State);
			void BindFunction(ReceiveFunction Function, bool Multicallable);
			void CallFunction(Relay* State, ReceiveFunction Function, Format::Variables&& Args);
			void MulticallFunction(Relay* State, ReceiveFunction Function, Format::Variables&& Args);
			void AcceptOutboundNode(OutboundNode* Candidate, ExpectsSystem<void>&& Status);
			void PullProcedure(Relay* State, const AbortCallback& AbortCallback);
			void PushProcedure(Relay* State, const AbortCallback& AbortCallback);
			void AbortInboundNode(InboundNode* Node);
			void AbortOutboundNode(OutboundNode* Node);
			void AppendNode(Relay* State, TaskCallback&& Callback);
			void EraseNode(Relay* State, TaskCallback&& Callback);
			void EraseNodeByInstance(void* Instance, TaskCallback&& Callback);
			void OnRequestOpen(InboundNode* Base) override;

		private:
			Promise<Option<SocketAddress>> Discover(Option<SocketAddress>&& ErrorAddress, bool TryRediscovering);
			Promise<Option<SocketAddress>> Rediscover();
			Promise<void> Connect(UPtr<Relay>&& From);
			Promise<void> Disconnect(UPtr<Relay>&& From);
			Promise<void> ProposeTransactionLogs(const Mediator::ChainSupervisorOptions& Options, Mediator::TransactionLogs&& Logs);

		private:
			static Promise<void> ProposeHandshake(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args);
			static Promise<void> ApproveHandshake(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args);
			static Promise<void> ProposeSeeds(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args);
			static Promise<void> FindForkCollision(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args);
			static Promise<void> VerifyForkCollision(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args);
			static Promise<void> RequestForkBlock(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args);
			static Promise<void> ProposeForkBlock(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args);
			static Promise<void> RequestBlock(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args);
			static Promise<void> ProposeBlock(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args);
			static Promise<void> ProposeBlockHash(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args);
			static Promise<void> RequestTransaction(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args);
			static Promise<void> ProposeTransaction(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args);
			static Promise<void> ProposeTransactionHash(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args);
			static Promise<void> RequestMempool(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args);
			static Promise<void> ProposeMempool(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args);
			static Promise<void> ProposeMessage(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args);

		private:
			static Promise<void> ReturnAbort(ServerNode* Relayer, Relay* From, const char* Function, const std::string_view& Message);
			static Promise<void> ReturnError(ServerNode* Relayer, Relay* From, const char* Function, const std::string_view& Message);
			static Promise<void> ReturnOK(Relay* From, const char* Function, const std::string_view& Message);
			static std::string_view NodeTypeOf(Relay* From);

		};

		class Routing
		{
		public:
			static bool IsAddressReserved(const SocketAddress& Address);
		};

		class Reasons
		{
		public:
			static std::string_view Claim();
			static std::string_view Commitment();
			static std::string_view Allocation();
			static std::string_view Adjustment();
			static std::string_view Migration();
			static std::string_view Deallocation();
			static std::string_view Dispatch();
			static std::string_view Other();
		};
	}
}
#endif