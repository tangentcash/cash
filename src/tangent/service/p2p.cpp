#include "p2p.h"
#include "../storage/mempoolstate.h"
#include "../storage/chainstate.h"
#include "../policy/transactions.h"
#include <array>
#define PURPOSE_CLAIM "observer claim"
#define PURPOSE_COMMITMENT "validator registration"
#define PURPOSE_DISPATCH "deferred event"
#define PURPOSE_OTHER "response"

namespace Tangent
{
	namespace P2P
	{
		bool Procedure::SerializeInto(String* Result)
		{
			VI_ASSERT(Result != nullptr, "result should be set");
			Format::Stream Stream;
			if (!Format::VariablesUtil::SerializeFlatInto(Args, &Stream))
				return false;

			uint32_t BodyChecksum = Algorithm::Hashing::Hash32d((uint8_t*)Stream.Data.data(), Stream.Data.size());
			uint32_t NetMagic = OS::CPU::ToEndianness(OS::CPU::Endian::Little, Magic = Protocol::Now().Message.PacketMagic);
			uint32_t NetMethod = OS::CPU::ToEndianness(OS::CPU::Endian::Little, Method);
			uint32_t NetSize = OS::CPU::ToEndianness(OS::CPU::Endian::Little, Size = (uint32_t)Stream.Data.size());
			uint32_t NetChecksum = OS::CPU::ToEndianness(OS::CPU::Endian::Little, Checksum = BodyChecksum);

			size_t Offset = Result->size();
			Result->resize(Offset + sizeof(uint32_t) * 4 + Stream.Data.size());
			memcpy(Result->data() + Offset + sizeof(uint32_t) * 0, &NetMagic, sizeof(uint32_t));
			memcpy(Result->data() + Offset + sizeof(uint32_t) * 1, &NetMethod, sizeof(uint32_t));
			memcpy(Result->data() + Offset + sizeof(uint32_t) * 2, &NetSize, sizeof(uint32_t));
			memcpy(Result->data() + Offset + sizeof(uint32_t) * 3, &NetChecksum, sizeof(uint32_t));
			memcpy(Result->data() + Offset + sizeof(uint32_t) * 4, Stream.Data.data(), Stream.Data.size());
			return true;
		}
		bool Procedure::DeserializeFrom(String& Message)
		{
			while (Message.size() >= sizeof(uint32_t))
			{
				memcpy(&Magic, Message.data() + sizeof(uint32_t) * 0, sizeof(uint32_t));
				Magic = OS::CPU::ToEndianness(OS::CPU::Endian::Little, Magic);
				if (Magic == Protocol::Now().Message.PacketMagic)
					break;

				Message.erase(Message.begin(), Message.begin() + sizeof(uint32_t));
			}

			const size_t HeaderSize = sizeof(uint32_t) * 4;
			if (Message.size() < HeaderSize)
				return false;

			memcpy(&Method, Message.data() + sizeof(uint32_t) * 1, sizeof(uint32_t));
			memcpy(&Size, Message.data() + sizeof(uint32_t) * 2, sizeof(uint32_t));
			memcpy(&Checksum, Message.data() + sizeof(uint32_t) * 3, sizeof(uint32_t));
			Method = OS::CPU::ToEndianness(OS::CPU::Endian::Little, Method);
			Size = OS::CPU::ToEndianness(OS::CPU::Endian::Little, Size);
			Checksum = OS::CPU::ToEndianness(OS::CPU::Endian::Little, Checksum);

			if (!Size)
			{
				Message.erase(Message.begin(), Message.begin() + HeaderSize);
				Args.clear();
				return Checksum == 0;
			}
			else if (Message.size() < HeaderSize + Size)
				return false;

			if (Size > Protocol::Now().Message.MaxBodySize)
			{
				uint32_t Delta = std::min<uint32_t>(Size - Protocol::Now().Message.MaxBodySize, (uint32_t)(Message.size() - HeaderSize));
				Size = (Size > Delta ? Size - Delta : 0);
				Message.erase(Message.end() - Delta, Message.end());
				if (Size > Protocol::Now().Message.MaxBodySize || Message.size() < HeaderSize + Size)
					return false;
			}

			String Body;
			Body.resize(Size);
			memcpy(Body.data(), Message.data() + HeaderSize, Size);
			Message.erase(Message.begin(), Message.begin() + HeaderSize + Size);
			Args.clear();

			uint32_t BodyChecksum = Algorithm::Hashing::Hash32d((uint8_t*)Body.data(), Body.size());
			if (OS::CPU::ToEndianness(OS::CPU::Endian::Little, BodyChecksum) != Checksum)
				return false;

			Format::Stream Stream = Format::Stream(std::move(Body));
			return Format::VariablesUtil::DeserializeFlatFrom(Stream, &Args);
		}
		bool Procedure::DeserializeFromStream(String& Message, const uint8_t* Buffer, size_t Size)
		{
			if (!Buffer || !Size)
				return DeserializeFrom(Message);

			size_t Offset = Message.size();
			Message.resize(Offset + Size);
			memcpy(Message.data() + Offset, Buffer, Size);
			return DeserializeFrom(Message);
		}

		RelayProcedure::RelayProcedure(Procedure&& NewData) : Data(std::move(NewData))
		{
		}

		Relay::Relay(NodeType NewType, void* NewInstance) : Type(NewType), Instance(NewInstance)
		{
			VI_ASSERT(Instance != nullptr, "instance should be set");
			switch (Type)
			{
				case NodeType::Inbound:
					AsInboundNode()->AddRef();
					break;
				case NodeType::Outbound:
					AsOutboundNode()->AddRef();
					break;
				default:
					VI_ASSERT(false, "invalid node state");
					break;
			}
		}
		Relay::~Relay()
		{
			Invalidate();
		}
		bool Relay::IncomingMessageInto(Procedure* Message)
		{
			VI_ASSERT(Message != nullptr, "incoming message should be set");
			UMutex<std::mutex> Unique(Mutex);
			if (IncomingMessages.empty())
				return false;

			*Message = std::move(IncomingMessages.front());
			IncomingMessages.pop();
			return true;
		}
		bool Relay::PullIncomingMessage(const uint8_t* Buffer, size_t Size)
		{
			Procedure Message;
			UMutex<std::mutex> Unique(Mutex);
			if (!Message.DeserializeFromStream(IncomingData, Buffer, Size))
				return !IncomingMessages.empty();

			IncomingMessages.emplace(std::move(Message));
			return true;
		}
		bool Relay::BeginOutgoingMessage()
		{
			UMutex<std::mutex> Unique(Mutex);
			if (!OutgoingData.empty())
				return false;
		Retry:
			if (!PriorityMessages.empty())
			{
				auto& Message = PriorityMessages.front();
				bool Relayable = Message->Data.SerializeInto(&OutgoingData) && !OutgoingData.empty();
				PriorityMessages.pop();
				if (Relayable)
					return true;
			}
			else
			{
				if (OutgoingMessages.empty())
					return false;

				auto& Message = OutgoingMessages.front();
				bool Relayable = Message.SerializeInto(&OutgoingData) && !OutgoingData.empty();
				OutgoingMessages.pop();
				if (Relayable)
					return true;
			}

			OutgoingData.clear();
			goto Retry;
		}
		void Relay::EndOutgoingMessage()
		{
			UMutex<std::mutex> Unique(Mutex);
			OutgoingData.clear();
		}
		void Relay::PushMessage(Procedure&& Message)
		{
			UMutex<std::mutex> Unique(Mutex);
			OutgoingMessages.push(std::move(Message));
		}
		void Relay::RelayMessage(URef<RelayProcedure>&& Message)
		{
			UMutex<std::mutex> Unique(Mutex);
			PriorityMessages.push(std::move(Message));
		}
		void Relay::Invalidate()
		{
			if (UserData.Pointer)
			{
				if (UserData.Destructor)
					UserData.Destructor(UserData.Pointer);
				UserData.Pointer = nullptr;
			}

			if (!Instance)
				return;

			switch (Type)
			{
				case NodeType::Inbound:
					AsInboundNode()->Release();
					break;
				case NodeType::Outbound:
					AsOutboundNode()->Release();
					break;
				default:
					VI_ASSERT(false, "invalid node state");
					break;
			}
			Instance = nullptr;
		}
		const String& Relay::PeerAddress()
		{
			if (!Address.empty())
				return Address;

			UMutex<std::mutex> Unique(Mutex);
			auto* Stream = AsSocket();
			if (!Stream)
			{
			NoAddress:
				Address = "[bad_address]";
				return Address;
			}

			auto Target = Stream->GetPeerAddress();
			if (!Target)
				goto NoAddress;

			auto Result = Target->GetIpAddress();
			if (!Result)
				goto NoAddress;

			Address = std::move(*Result);
			return Address;
		}
		const String& Relay::PeerService()
		{
			if (!Service.empty())
				return Service;

			UMutex<std::mutex> Unique(Mutex);
			auto* Stream = AsSocket();
			if (!Stream)
			{
			NoService:
				Service = ToString(Protocol::Now().User.P2P.Port);
				return Service;
			}

			auto Target = Stream->GetPeerAddress();
			if (!Target)
				goto NoService;

			auto Result = Target->GetIpPort();
			if (!Result)
				goto NoService;

			Service = ToString(*Result);
			return Service;
		}
		const SingleQueue<URef<RelayProcedure>>& Relay::GetPriorityMessages() const
		{
			return PriorityMessages;
		}
		const SingleQueue<Procedure>& Relay::GetIncomingMessages() const
		{
			return IncomingMessages;
		}
		const SingleQueue<Procedure>& Relay::GetOutgoingMessages() const
		{
			return OutgoingMessages;
		}
		const uint8_t* Relay::OutgoingBuffer()
		{
			return (const uint8_t*)OutgoingData.data();
		}
		size_t Relay::IncomingSize()
		{
			return IncomingData.size();
		}
		size_t Relay::OutgoingSize()
		{
			return OutgoingData.size();
		}
		NodeType Relay::TypeOf()
		{
			return Type;
		}
		InboundNode* Relay::AsInboundNode()
		{
			return Type == NodeType::Inbound ? (InboundNode*)Instance : nullptr;
		}
		OutboundNode* Relay::AsOutboundNode()
		{
			return Type == NodeType::Outbound ? (OutboundNode*)Instance : nullptr;
		}
		Socket* Relay::AsSocket()
		{
			switch (Type)
			{
				case NodeType::Inbound:
				{
					auto* Node = AsInboundNode();
					return Node ? Node->Stream : nullptr;
				}
				case NodeType::Outbound:
				{
					auto* Node = AsOutboundNode();
					return Node ? Node->GetStream() : nullptr;
				}
				default:
					return nullptr;
			}
		}
		void* Relay::AsInstance()
		{
			return Instance;
		}
		UPtr<Schema> Relay::AsSchema() const
		{
			Schema* Data = Var::Set::Object();
			switch (Type)
			{
				case NodeType::Inbound:
					Data->Set("type", Var::String("inbound"));
					break;
				case NodeType::Outbound:
					Data->Set("type", Var::String("outbound"));
					break;
				default:
					Data->Set("type", Var::String("unknown"));
					break;
			}
			Data->Set("priority_queue", Algorithm::Encoding::SerializeUint256(PriorityMessages.size()));
			auto* Incoming = Data->Set("incoming", Var::Object());
			Incoming->Set("queue", Algorithm::Encoding::SerializeUint256(IncomingMessages.size()));
			Incoming->Set("bytes", Algorithm::Encoding::SerializeUint256(IncomingData.size()));
			auto* Outgoing = Data->Set("outgoing", Var::Object());
			Outgoing->Set("queue", Algorithm::Encoding::SerializeUint256(OutgoingMessages.size()));
			Outgoing->Set("bytes", Algorithm::Encoding::SerializeUint256(OutgoingData.size()));
			return Data;
		}

		OutboundNode::OutboundNode() noexcept : SocketClient(Protocol::Now().User.TCP.Timeout)
		{
		}
		void OutboundNode::ConfigureStream()
		{
			SocketClient::ConfigureStream();
			if (Protocol::Now().Is(NetworkType::Regtest))
				Net.Stream->Bind(SocketAddress(Protocol::Now().User.P2P.Address, 0));
		}

		ServerNode::ServerNode() noexcept : SocketServer(), ControlSys("p2p-node")
		{
		}
		ServerNode::~ServerNode() noexcept
		{
			auto NodeId = Codec::HexEncode(std::string_view((char*)this, sizeof(this)));
			Oracle::Paymaster::SubmitCallback(NodeId, nullptr);
			ClearPendingTip();
		}
		Promise<Option<SocketAddress>> ServerNode::Discover(Option<SocketAddress>&& ErrorAddress, bool TryRediscovering)
		{
			auto Mempool = Storages::Mempoolstate(__func__);
			if (ErrorAddress)
			{
				auto ErrorValidator = Mempool.GetValidatorByAddress(*ErrorAddress);
				if (ErrorValidator)
				{
					++ErrorValidator->Availability.Calls;
					++ErrorValidator->Availability.Errors;
					ApplyValidator(Mempool, *ErrorValidator, Optional::None);
				}

				if (Protocol::Now().User.P2P.Logging)
					VI_WARN("[p2p] on peer %s:%i channel skip: host not reachable", ErrorAddress->GetIpAddress().Or("[bad_address]").c_str(), (int)ErrorAddress->GetIpPort().Or(0));
			}
		RetryValidator:
			auto NextValidator = Mempool.GetValidatorByPreference(Discovery.Offset);
			if (!NextValidator)
			{
			RetryTrialAddress:
				auto NextTrialAddress = Mempool.NextTrialAddress();
				if (!NextTrialAddress)
					goto NoCandidate;

				if (Find(*NextTrialAddress) || Routing::IsAddressReserved(*NextTrialAddress))
					goto RetryTrialAddress;

				if (Protocol::Now().User.P2P.Logging)
					VI_INFO("[p2p] on peer %s:%i channel try: mempool address", NextTrialAddress->GetIpAddress().Or(String("[bad_address]")).c_str(), (int)NextTrialAddress->GetIpPort().Or(0));
				
				return Promise<Option<SocketAddress>>(std::move(*NextTrialAddress));
			}

			++Discovery.Offset;
			if (Find(NextValidator->Address) || Routing::IsAddressReserved(NextValidator->Address))
			{
				if (Discovery.Offset < Discovery.Count)
					goto RetryValidator;

			NoCandidate:
				if (TryRediscovering)
					return Rediscover();

				return Promise<Option<SocketAddress>>(Optional::None);
			}

			if (Protocol::Now().User.P2P.Logging)
				VI_INFO("[p2p] on peer %s:%i channel try: discovery address", NextValidator->Address.GetIpAddress().Or(String("[bad_address]")).c_str(), (int)NextValidator->Address.GetIpPort().Or(0));

			return Promise<Option<SocketAddress>>(std::move(NextValidator->Address));
		}
		Promise<Option<SocketAddress>> ServerNode::Rediscover()
		{
			if (Protocol::Now().User.Seeders.empty())
				return Promise<Option<SocketAddress>>(Optional::None);

			return Coasync<Option<SocketAddress>>([this]() -> Promise<Option<SocketAddress>>
			{
				UMutex<std::recursive_mutex> Unique(Exclusive);
				auto Mempool = Storages::Mempoolstate(__func__);
				auto Random = std::default_random_engine();
				auto Lists = Vector<String>(Protocol::Now().User.Seeders.begin(), Protocol::Now().User.Seeders.end());
				std::shuffle(std::begin(Lists), std::end(Lists), Random);
				Unique.Unlock();

				for (auto& Seeder : Lists)
				{
					size_t Results = std::numeric_limits<size_t>::max();
					auto Response = Coawait(HTTP::Fetch(Seeder));
					if (Response)
					{
						auto Addresses = UPtr<Schema>(Response->Content.GetJSON());
						if (Addresses)
						{
							Results = 0;
							for (auto* Address : Addresses->GetChilds())
							{
								auto Endpoint = Algorithm::Endpoint(Address->Value.GetBlob());
								if (Endpoint.IsValid() && !Routing::IsAddressReserved(Endpoint.Address) && Mempool.ApplyTrialAddress(Endpoint.Address))
									++Results;
							}
						}
					}

					if (Protocol::Now().User.P2P.Logging)
					{
						if (Results != std::numeric_limits<size_t>::max())
							VI_INFO("[p2p] on seeder %s %sresults found (addresses: %" PRIu64 ")", Seeder.c_str(), Results > 0 ? "" : "no ", (uint64_t)Results);
						else
							VI_WARN("[p2p] on seeder %s no results found: bad seeder", Seeder.c_str());
					}
				}

				Coreturn Discover(Optional::None, false);
			});
		}
		Promise<void> ServerNode::Connect(UPtr<Relay>&& From)
		{
			Call(*From, &ServerNode::ProposeHandshake, { Format::Variable(Validator.Node.AsMessage().Data), Format::Variable(Protocol::Now().Time.NowCPU()) });
			return ReturnOK(*From, __func__, "initiate handshake");
		}
		Promise<void> ServerNode::Disconnect(UPtr<Relay>&& From)
		{
			auto* PeerValidator = From->AsUser<Ledger::Validator>();
			if (PeerValidator != nullptr)
			{
				auto Mempool = Storages::Mempoolstate(__func__);
				PeerValidator->Availability.Timestamp = Protocol::Now().Time.Now();
				ApplyValidator(Mempool, *PeerValidator, Optional::None).Report("mempool validator save failed");
			}

			if (Discovery.Offset >= Discovery.Count)
				Discovery.Offset = 0;

			if (Protocol::Now().User.P2P.Logging)
				VI_INFO("[p2p] on validator %s channel shutdown (%s %s)", From->PeerAddress().c_str(), NodeTypeOf(*From).data(), From->PeerService().c_str());

			return ReturnOK(*From, __func__, "approve shutdown");
		}
		Promise<void> ServerNode::ProposeTransactionLogs(const Oracle::ChainSupervisorOptions& Options, Oracle::TransactionLogs&& Logs)
		{
			UMutex<std::recursive_mutex> Unique(Sync.Account);
			auto AccountSequence = Validator.Wallet.GetLatestSequence().Or(1);
			Unique.Unlock();

			for (auto& Receipt : Logs.Transactions)
			{
				if (!Receipt.IsApproved())
				{
					if (Protocol::Now().User.P2P.Logging)
						VI_INFO("[p2p] on claim %s transaction %s queued", Algorithm::Asset::HandleOf(Receipt.Asset).c_str(), Receipt.TransactionId.c_str());

					continue;
				}

				auto Collision = Ledger::TransactionContext().GetWitnessTransaction(Receipt.TransactionId);
				if (Collision)
				{
					if (Protocol::Now().User.P2P.Logging)
						VI_INFO("[p2p] on claim %s transaction %s approved", Algorithm::Asset::HandleOf(Receipt.Asset).c_str(), Receipt.TransactionId.c_str());

					continue;
				}

				UPtr<Transactions::Claim> Transaction = Memory::New<Transactions::Claim>();
				Transaction->SetWitness(Receipt);

				if (ProposeTransaction(nullptr, std::move(*Transaction), AccountSequence, PURPOSE_CLAIM))
					++AccountSequence;
			}
			return Promise<void>::Null();
		}
		Promise<void> ServerNode::ProposeHandshake(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args)
		{
			if (Args.size() != 2)
				return ReturnAbort(Relayer, *From, __func__, "invalid arguments");

			UPtr<Ledger::Validator> PeerValidator = Memory::New<Ledger::Validator>();
			Format::Stream ValidatorMessage = Format::Stream(Args.front().AsBlob());
			uint64_t PeerTime = Args.back().AsUint64();
			uint64_t ServerTime = Protocol::Now().Time.NowCPU();
			uint64_t LatencyTime = PeerTime > ServerTime ? PeerTime - ServerTime : ServerTime - PeerTime;
			if (!PeerValidator->Load(ValidatorMessage))
				return ReturnAbort(Relayer, *From, __func__, "invalid message");

			auto& Peer = Protocol::Now().User.P2P;
			PeerValidator->Availability.Latency = LatencyTime;
			PeerValidator->Address = SocketAddress(From->PeerAddress(), PeerValidator->Address.GetIpPort().Or(Protocol::Now().User.P2P.Port));
			if (!PeerValidator->IsValid())
				return ReturnAbort(Relayer, *From, __func__, "invalid validator");

			auto Mempool = Storages::Mempoolstate(__func__);
			Relayer->ApplyValidator(Mempool, **PeerValidator, Optional::None).Report("mempool peer validator save failed");

			auto Chain = Storages::Chainstate(__func__);
			auto Tip = Chain.GetLatestBlockHeader();
			Relayer->Call(*From, &ServerNode::ApproveHandshake, { Format::Variable(ValidatorMessage.Data), Format::Variable(Protocol::Now().Time.NowCPU()), Format::Variable(Tip ? Tip->Number : 0), Format::Variable(Tip ? Tip->AsHash() : uint256_t(0)) });
			From->Use<Ledger::Validator>(PeerValidator.Reset(), [](Ledger::Validator* Value) { Memory::Delete(Value); });
			return ReturnOK(*From, __func__, "approve handshake");
		}
		Promise<void> ServerNode::ApproveHandshake(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args)
		{
			if (Args.size() != 4)
				return ReturnAbort(Relayer, *From, __func__, "invalid arguments");

			Ledger::Validator SelfValidator;
			Format::Stream ValidatorMessage = Format::Stream(Args[0].AsBlob());
			if (!SelfValidator.Load(ValidatorMessage))
				return ReturnAbort(Relayer, *From, __func__, "invalid message");
			else if (!SelfValidator.IsValid())
				return ReturnAbort(Relayer, *From, __func__, "invalid validator");
			else if (SelfValidator.Availability.Calls != Relayer->Validator.Node.Availability.Calls || SelfValidator.Availability.Errors != Relayer->Validator.Node.Availability.Errors || SelfValidator.Availability.Timestamp != Relayer->Validator.Node.Availability.Timestamp)
				return ReturnAbort(Relayer, *From, __func__, "invalid validator adjustment");

			auto* PeerValidator = From->AsUser<Ledger::Validator>();
			if (!PeerValidator)
				return ReturnAbort(Relayer, *From, __func__, "validator not found");

			if (SelfValidator.Address.GetIpAddress().Or(String()) != Relayer->Validator.Node.Address.GetIpAddress().Or(String()) || SelfValidator.Availability.Latency != Relayer->Validator.Node.Availability.Latency)
			{
				auto Mempool = Storages::Mempoolstate(__func__);
				Relayer->Validator.Node = std::move(SelfValidator);
				Relayer->ApplyValidator(Mempool, Relayer->Validator.Node, Relayer->Validator.Wallet).Report("mempool self validator save failed");
			}

			auto& Protocol = Protocol::Change();
			uint64_t PeerTime = Args[1].AsUint64();
			uint64_t ServerTime = Protocol::Now().Time.NowCPU();
			uint64_t LatencyTime = PeerTime > ServerTime ? PeerTime - ServerTime : ServerTime - PeerTime;
			uint64_t VaryingPeerTime = PeerTime + (PeerValidator->Availability.Latency + LatencyTime) / 2;
			Protocol.Time.Adjust(PeerValidator->Address, (int64_t)ServerTime - (int64_t)VaryingPeerTime);
			if (Protocol::Now().User.P2P.Logging)
				VI_INFO("[p2p] on validator %s channel accept (%s %s)", From->PeerAddress().c_str(), NodeTypeOf(*From).data(), From->PeerService().c_str());

			auto Mempool = Storages::Mempoolstate(__func__);
			auto Seeds = Mempool.GetValidatorAddresses(0, Protocol::Now().User.P2P.CursorSize);
			if (Seeds && !Seeds->empty())
			{
				Format::Variables Args;
				Args.reserve(Seeds->size() * 2);
				for (auto& Item : *Seeds)
				{
					auto IpAddress = Item.GetIpAddress();
					auto IpPort = Item.GetIpPort();
					if (IpAddress && IpPort)
					{
						Args.push_back(Format::Variable(*IpAddress));
						Args.push_back(Format::Variable(*IpPort));
					}
				}
				Relayer->Call(*From, &ServerNode::ProposeSeeds, std::move(Args));
			}

			auto Chain = Storages::Chainstate(__func__);
			auto Tip = Chain.GetLatestBlockHeader();
			uint64_t PeerTipNumber = Args[2].AsUint64();
			uint256_t PeerTipHash = Args[3].AsUint256();
			if (!Tip || PeerTipNumber > Tip->Number)
				return ReturnOK(*From, __func__, "tip required");
			else if (PeerTipNumber == Tip->Number && Tip->AsHash() == PeerTipHash)
				return ReturnOK(*From, __func__, "tip synced");

			auto Block = Chain.GetBlockByNumber(Tip->Number);
			if (!Block)
				return ReturnOK(*From, __func__, "no tip found");

			Format::Stream Message = Block->AsMessage();
			Relayer->Call(*From, &ServerNode::ProposeBlock, { Format::Variable(Message.Data) });
			return ReturnOK(*From, __func__, "new tip proposed");
		}
		Promise<void> ServerNode::ProposeSeeds(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args)
		{
			if (Args.empty() || Args.size() % 2 != 0)
				return ReturnAbort(Relayer, *From, __func__, "invalid arguments");

			size_t Candidates = 0;
			auto Mempool = Storages::Mempoolstate(__func__);
			for (size_t i = 0; i < Args.size(); i += 2)
			{
				auto IpAddress = Args[i + 0].AsString();
				auto IpPort = Args[i + 1].AsUint16();
				auto Target = SocketAddress(IpAddress, IpPort);
				Candidates += Target.IsValid() && !Routing::IsAddressReserved(Target) && Mempool.ApplyTrialAddress(Target) ? 1 : 0;
			}

			if (Candidates > 0)
				Relayer->Accept();

			return ReturnOK(*From, __func__, "accept seeds");
		}
		Promise<void> ServerNode::FindForkCollision(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args)
		{
			if (Args.size() != 2)
				return ReturnAbort(Relayer, *From, __func__, "invalid arguments");

			uint256_t ForkHash = Args[0].AsUint256();
			if (!ForkHash)
				return ReturnAbort(Relayer, *From, __func__, "invalid fork");

			uint64_t BranchNumber = Args[1].AsUint64();
			if (!BranchNumber)
				return ReturnAbort(Relayer, *From, __func__, "invalid branch");

			const uint64_t BlocksCount = Protocol::Now().User.P2P.CursorSize;
			const uint64_t ForkNumber = BranchNumber > BlocksCount ? BranchNumber - BlocksCount : 1;
			auto Chain = Storages::Chainstate(__func__);
			auto Headers = Chain.GetBlockHeaders(ForkNumber, BlocksCount);
			if (!Headers || Headers->empty())
				return ReturnError(Relayer, *From, __func__, "fork collision not found");

			Format::Variables HeaderArgs;
			HeaderArgs.reserve(Headers->size() + 2);
			HeaderArgs.push_back(Format::Variable(ForkHash));
			HeaderArgs.push_back(Format::Variable(ForkNumber + Headers->size() - 1));
			for (auto& Item : *Headers)
				HeaderArgs.push_back(Format::Variable(Item.AsMessage().Data));

			Relayer->Call(*From, &ServerNode::VerifyForkCollision, std::move(HeaderArgs));
			return ReturnOK(*From, __func__, "fork collisions proposed");
		}
		Promise<void> ServerNode::VerifyForkCollision(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args)
		{
			if (Args.size() < 2)
				return ReturnAbort(Relayer, *From, __func__, "invalid arguments");

			uint256_t ForkHash = Args[0].AsUint256();
			if (!ForkHash)
				return ReturnAbort(Relayer, *From, __func__, "invalid fork");

			uint64_t BranchNumber = Args[1].AsUint64();
			if (!BranchNumber)
				return ReturnAbort(Relayer, *From, __func__, "invalid branch");

			if (Args.size() < 3)
				return ReturnError(Relayer, *From, __func__, "fork collision not found");

			Format::Stream Message;
			Ledger::BlockHeader ChildHeader;
			Message.Data = Args[2].AsString();
			if (!ChildHeader.Load(Message))
				return ReturnAbort(Relayer, *From, __func__, "invalid fork block header");

			Ledger::BlockHeader ParentHeader;
			auto Chain = Storages::Chainstate(__func__);
			for (size_t i = 3; i < Args.size() + 1; i++)
			{
				uint256_t BranchHash = ChildHeader.AsHash(true);
				auto Collision = Chain.GetBlockHeaderByHash(BranchHash);
				if (Collision || --BranchNumber < 1)
				{
					Relayer->Call(*From, &ServerNode::RequestForkBlock, { Format::Variable(ForkHash), Format::Variable(BranchHash), Format::Variable((uint64_t)0) });
					return ReturnOK(*From, __func__, "fork collision found");
				}
				else if (i < Args.size())
				{
					Message.Clear();
					Message.Data = Args[i].AsString();
					if (!ParentHeader.Load(Message))
						return ReturnAbort(Relayer, *From, __func__, "invalid fork block header");
				}

				auto Verification = ChildHeader.Verify(ParentHeader.Number > 0 ? &ParentHeader : nullptr);
				if (!Verification)
					return ReturnAbort(Relayer, *From, __func__, "invalid fork block header: " + Verification.Error().Info);

				ChildHeader = ParentHeader;
			}

			Relayer->Call(*From, &ServerNode::FindForkCollision, { Format::Variable(ForkHash), Format::Variable(BranchNumber) });
			return ReturnOK(*From, __func__, "fork collision not found");
		}
		Promise<void> ServerNode::RequestForkBlock(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args)
		{
			if (Args.size() != 3)
				return ReturnAbort(Relayer, *From, __func__, "invalid arguments");

			uint256_t ForkHash = Args[0].AsUint256();
			if (!ForkHash)
				return ReturnAbort(Relayer, *From, __func__, "invalid fork");

			uint256_t BlockHash = Args[1].AsUint256();
			if (BlockHash > 0)
			{
				auto Chain = Storages::Chainstate(__func__);
				auto Block = Chain.GetBlockByHash(BlockHash);
				if (Block)
				{
					Format::Stream Message = Block->AsMessage();
					Relayer->Call(*From, &ServerNode::ProposeForkBlock, { Format::Variable(ForkHash), Format::Variable(Message.Data) });
					return ReturnOK(*From, __func__, "new fork block proposed");
				}
			}

			uint256_t BlockNumber = Args[2].AsUint64();
			if (BlockNumber > 0)
			{
				auto Chain = Storages::Chainstate(__func__);
				auto Block = Chain.GetBlockByNumber(BlockNumber);
				if (Block)
				{
					Format::Stream Message = Block->AsMessage();
					Relayer->Call(*From, &ServerNode::ProposeForkBlock, { Format::Variable(ForkHash), Format::Variable(Message.Data) });
					return ReturnOK(*From, __func__, "new fork block proposed");
				}
			}

			return ReturnOK(*From, __func__, "fork block not found");
		}
		Promise<void> ServerNode::ProposeForkBlock(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args)
		{
			if (Args.size() != 2)
				return ReturnAbort(Relayer, *From, __func__, "invalid arguments");

			uint256_t ForkHash = Args.front().AsUint256();
			if (!ForkHash)
				return ReturnAbort(Relayer, *From, __func__, "invalid fork");

			Ledger::Block Tip;
			Format::Stream Message = Format::Stream(Args.back().AsBlob());
			if (!Tip.Load(Message) || !Relayer->AcceptBlock(*From, std::move(Tip), ForkHash))
				return ReturnError(Relayer, *From, __func__, "block rejected");

			Relayer->Call(*From, &ServerNode::RequestForkBlock, { Format::Variable(ForkHash), Format::Variable(uint256_t(0)), Format::Variable(Tip.Number + 1) });
			return ReturnOK(*From, __func__, "new fork block accepted");
		}
		Promise<void> ServerNode::RequestBlock(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args)
		{
			if (Args.size() != 1)
				return ReturnAbort(Relayer, *From, __func__, "invalid arguments");

			uint256_t BlockHash = Args.front().AsUint256();
			if (!BlockHash)
				return ReturnAbort(Relayer, *From, __func__, "invalid hash");

			auto Chain = Storages::Chainstate(__func__);
			auto Block = Chain.GetBlockByHash(BlockHash);
			if (!Block)
				return ReturnOK(*From, __func__, "block not found");

			Format::Stream Message = Block->AsMessage();
			Relayer->Call(*From, &ServerNode::ProposeBlock, { Format::Variable(Message.Data) });
			return ReturnOK(*From, __func__, "block proposed");
		}
		Promise<void> ServerNode::ProposeBlock(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args)
		{
			if (Args.size() != 1)
				return ReturnAbort(Relayer, *From, __func__, "invalid arguments");

			Ledger::Block Candidate;
			Format::Stream Message = Format::Stream(Args.front().AsBlob());
			if (!Candidate.Load(Message) || !Relayer->AcceptBlock(*From, std::move(Candidate), 0))
				return ReturnError(Relayer, *From, __func__, "block rejected");

			return ReturnOK(*From, __func__, "block accepted");
		}
		Promise<void> ServerNode::ProposeBlockHash(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args)
		{
			if (Args.size() != 1)
				return ReturnAbort(Relayer, *From, __func__, "invalid arguments");

			uint256_t BlockHash = Args.front().AsUint256();
			if (!BlockHash)
				return ReturnAbort(Relayer, *From, __func__, "invalid hash");

			auto Chain = Storages::Chainstate(__func__);
			if (Chain.GetBlockHeaderByHash(BlockHash))
				return ReturnOK(*From, __func__, "block found");

			Relayer->Call(*From, &ServerNode::RequestBlock, { Format::Variable(BlockHash) });
			return ReturnOK(*From, __func__, "block requested");
		}
		Promise<void> ServerNode::RequestTransaction(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args)
		{
			if (Args.size() != 1)
				return ReturnAbort(Relayer, *From, __func__, "invalid arguments");

			uint256_t TransactionHash = Args.front().AsUint256();
			if (!TransactionHash)
				return ReturnAbort(Relayer, *From, __func__, "invalid hash");

			auto Chain = Storages::Chainstate(__func__);
			auto Transaction = Chain.GetTransactionByHash(TransactionHash);
			if (!Transaction)
			{
				auto Mempool = Storages::Mempoolstate(__func__);
				Transaction = Mempool.GetTransactionByHash(TransactionHash);
				if (!Transaction)
					return ReturnOK(*From, __func__, "transaction not found");
			}

			Format::Stream Message = (*Transaction)->AsMessage();
			Relayer->Call(*From, &ServerNode::ProposeTransaction, { Format::Variable(Message.Data) });
			return ReturnOK(*From, __func__, "transaction proposed");
		}
		Promise<void> ServerNode::ProposeTransaction(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args)
		{
			if (Args.size() != 1)
				return ReturnAbort(Relayer, *From, __func__, "invalid arguments");

			Format::Stream Message = Format::Stream(Args.front().AsBlob());
			UPtr<Ledger::Transaction> Candidate = Tangent::Transactions::Resolver::New(Messages::Authentic::ResolveType(Message).Or(0));
			if (!Candidate)
				return ReturnError(Relayer, *From, __func__, "invalid transaction");

			if (!Candidate->Load(Message) || !Relayer->AcceptTransaction(*From, std::move(Candidate)))
				return ReturnError(Relayer, *From, __func__, "transaction rejected");

			return ReturnOK(*From, __func__, "transaction accepted");
		}
		Promise<void> ServerNode::ProposeTransactionHash(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args)
		{
			if (Args.size() != 1)
				return ReturnAbort(Relayer, *From, __func__, "invalid arguments");

			uint256_t TransactionHash = Args.front().AsUint256();
			if (!TransactionHash)
				return ReturnAbort(Relayer, *From, __func__, "invalid hash");

			auto Chain = Storages::Chainstate(__func__);
			if (Chain.GetTransactionByHash(TransactionHash))
				return ReturnOK(*From, __func__, "finalized transaction found");

			auto Mempool = Storages::Mempoolstate(__func__);
			if (Mempool.GetTransactionByHash(TransactionHash))
				return ReturnOK(*From, __func__, "pending transaction found");

			Relayer->Call(*From, &ServerNode::RequestTransaction, { Format::Variable(TransactionHash) });
			return ReturnOK(*From, __func__, "transaction requested");
		}
		Promise<void> ServerNode::RequestMempool(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args)
		{
			if (Args.size() != 1)
				return ReturnAbort(Relayer, *From, __func__, "invalid arguments");

			uint64_t Cursor = Args.front().AsUint64();
			const uint64_t TransactionsCount = Protocol::Now().User.P2P.CursorSize;
			auto Mempool = Storages::Mempoolstate(__func__);
			auto Hashes = Mempool.GetTransactionHashset(Cursor, TransactionsCount);
			if (!Hashes || Hashes->empty())
				return ReturnOK(*From, __func__, "mempool is empty");

			Format::Variables HashArgs;
			HashArgs.reserve(Hashes->size());
			HashArgs.push_back(Format::Variable(Cursor + Hashes->size()));
			for (auto& Item : *Hashes)
				HashArgs.push_back(Format::Variable(Item));

			Relayer->Call(*From, &ServerNode::ProposeMempool, std::move(HashArgs));
			return ReturnOK(*From, __func__, "mempool proposed");
		}
		Promise<void> ServerNode::ProposeMempool(ServerNode* Relayer, UPtr<Relay>&& From, Format::Variables&& Args)
		{
			if (Args.size() < 2)
				return ReturnAbort(Relayer, *From, __func__, "invalid arguments");

			uint64_t Cursor = Args.front().AsUint64();
			auto Mempool = Storages::Mempoolstate(__func__);
			for (size_t i = 1; i < Args.size(); i++)
			{
				auto TransactionHash = Args[i].AsUint256();
				if (!Mempool.HasTransaction(TransactionHash))
					Relayer->Call(*From, &ServerNode::RequestTransaction, { Format::Variable(TransactionHash) });
			}

			const uint64_t TransactionsCount = Protocol::Now().User.P2P.CursorSize;
			if (Args.size() > TransactionsCount)
				Relayer->Call(*From, &ServerNode::RequestMempool, { Format::Variable(Cursor) });

			return ReturnOK(*From, __func__, "mempool accepted");
		}
		Promise<void> ServerNode::ReturnAbort(ServerNode* Relayer, Relay* From, const char* Function, const std::string_view& Message)
		{
			auto* PeerValidator = From->AsUser<Ledger::Validator>();
			if (PeerValidator != nullptr)
			{
				++PeerValidator->Availability.Calls;
				++PeerValidator->Availability.Errors;
			}

			Relayer->Reject(From);
			if (Protocol::Now().User.P2P.Logging)
				VI_DEBUG("[p2p] on validator %s call \"%s\" abort: %.*s (%s %s)", From->PeerAddress().c_str(), Function, (int)Message.size(), Message.data(), NodeTypeOf(From).data(), From->PeerService().c_str());
			
			return Promise<void>::Null();
		}
		Promise<void> ServerNode::ReturnError(ServerNode* Relayer, Relay* From, const char* Function, const std::string_view& Message)
		{
			auto* PeerValidator = From->AsUser<Ledger::Validator>();
			if (PeerValidator != nullptr)
			{
				++PeerValidator->Availability.Calls;
				++PeerValidator->Availability.Errors;
			}

			if (Protocol::Now().User.P2P.Logging)
				VI_DEBUG("[p2p] on validator %s call \"%s\" error: %.*s (%s %s)", From->PeerAddress().c_str(), Function, (int)Message.size(), Message.data(), NodeTypeOf(From).data(), From->PeerService().c_str());
			
			return Promise<void>::Null();
		}
		Promise<void> ServerNode::ReturnOK(Relay* From, const char* Function, const std::string_view& Message)
		{
			auto* PeerValidator = From->AsUser<Ledger::Validator>();
			if (PeerValidator != nullptr)
				++PeerValidator->Availability.Calls;

			if (Protocol::Now().User.P2P.Logging)
				VI_DEBUG("[p2p] on validator %s call \"%s\" OK: %.*s (%s %s)", From->PeerAddress().c_str(), Function, (int)Message.size(), Message.data(), NodeTypeOf(From).data(), From->PeerService().c_str());
			
			return Promise<void>::Null();
		}
		ExpectsSystem<void> ServerNode::OnUnlisten()
		{
			UMutex<std::recursive_mutex> Unique(Exclusive);
			for (auto& Instance : CandidateNodes)
			{
				if (Instance->Net.Stream != nullptr)
					Instance->Net.Stream->Shutdown(true);
				Instance->Release();
			}
			CandidateNodes.clear();

		Retry:
			UnorderedMap<void*, Relay*> CurrentNodes;
			CurrentNodes.swap(Nodes);
			Unique.Unlock();

			for (auto& Node : CurrentNodes)
			{
				auto* OutboundInstance = Node.second->AsOutboundNode();
				if (OutboundInstance != nullptr)
					OutboundInstance->Release();

				Relay* State = Node.second;
				State->AddRef();
				Disconnect(State).When([State]()
				{
					State->Invalidate();
					State->Release();
				});
			}

			Unique.Lock();
			if (!Nodes.empty())
				goto Retry;

			if (ControlSys.Deactivate())
				ControlSys.Shutdown().Wait();

			ControlSys.Deactivate();
			return Expectation::Met;
		}
		ExpectsLR<void> ServerNode::ApplyValidator(Storages::Mempoolstate& Mempool, Ledger::Validator& Node, Option<Ledger::Wallet>&& Wallet)
		{
			bool HasWallet = !!Wallet;
			auto IpAddress = Node.Address.GetIpAddress();
			auto IpPort = Node.Address.GetIpPort();
			if (!Node.Address.IsValid() || !IpAddress || !IpPort)
				return LayerException("bad node address");

			bool IsLocal = *IpAddress == "127.0.0.1";
			if (*IpAddress == "0.0.0.0")
			{
				Node.Address = SocketAddress("127.0.0.1", *IpPort);
				IsLocal = true;
			}

			if (IsLocal && !HasWallet)
				return Expectation::Met;

			auto Status = Mempool.ApplyValidator(Node, std::move(Wallet));
			if (Status && !HasWallet)
				Discovery.Count = Mempool.GetValidatorsCount().Or(0);
			return Status;
		}
		void ServerNode::BindFunction(ReceiveFunction Function)
		{
			uint32_t MethodIndex = MethodAddress + (uint32_t)InMethods.size();
			void* FunctionIndex = (void*)Function;
			InMethods[MethodIndex] = FunctionIndex;
			OutMethods[FunctionIndex] = MethodIndex;
		}
		void ServerNode::CallFunction(Relay* State, ReceiveFunction Function, Format::Variables&& Args)
		{
			VI_ASSERT(State != nullptr, "state should be set");
			auto It = OutMethods.find((void*)Function);
			if (It == OutMethods.end())
				return;

			Procedure Next;
			Next.Method = It->second;
			Next.Args = std::move(Args);
			State->PushMessage(std::move(Next));
			PushNextProcedure(State);
		}
		void ServerNode::MulticallFunction(Relay* State, ReceiveFunction Function, Format::Variables&& Args)
		{
			auto It = OutMethods.find((void*)Function);
			if (It == OutMethods.end())
				return;

			Procedure Next;
			Next.Method = It->second;
			Next.Args = std::move(Args);

			URef<RelayProcedure> RelayMessage = new RelayProcedure(std::move(Next));
			UMutex<std::recursive_mutex> Unique(Exclusive);
			for (auto& Node : Nodes)
			{
				if (State != Node.second)
					Node.second->RelayMessage(URef<RelayProcedure>(RelayMessage));
			}

			for (auto& Node : Nodes)
			{
				if (State != Node.second)
					PushNextProcedure(Node.second);
			}
		}
		void ServerNode::AcceptOutboundNode(OutboundNode* Candidate, ExpectsSystem<void>&& Status)
		{
			UPtr<OutboundNode> Copy = Candidate;
			UMutex<std::recursive_mutex> Unique(Exclusive);
			CandidateNodes.erase(Candidate);
			Candidate->Release();
			if (!IsActive())
			{
				Copy.Reset();
				return;
			}

			auto* Duplicate = Find(Candidate->GetPeerAddress());
			if (Status && !Duplicate)
			{
				Relay* State = new Relay(NodeType::Outbound, Candidate);
				AppendNode(State, [State, Candidate, this]()
				{
					PullProcedure(State, std::bind(&ServerNode::AbortOutboundNode, this, Candidate));
					ReceiveOutboundNode(Optional::None);
				});
			}
			else if (!Duplicate)
			{
				auto Address = std::move(Candidate->State.Address);
				Unique.Unlock();
				ReceiveOutboundNode(std::move(Address));
			}
			else
			{
				Unique.Unlock();
				ReceiveOutboundNode(Optional::None);
			}
		}
		void ServerNode::PullProcedure(Relay* State, const AbortCallback& AbortCallback)
		{
			VI_ASSERT(State && AbortCallback, "state and abort callback should be set");
			auto* Stream = State->AsSocket();
			if (!Stream)
				return;

			if (State->PullIncomingMessage(nullptr, 0))
			{
				Procedure Message;
				State->IncomingMessageInto(&Message);
				if (InMethods.empty() || Message.Method < MethodAddress || Message.Method > MethodAddress + InMethods.size() - 1)
					return AbortCallback(State);

				auto It = InMethods.find(Message.Method);
				if (It == InMethods.end())
					return AbortCallback(State);
				else if (!ControlSys.Enqueue())
					return;

				auto Function = (ReceiveFunction)It->second;
				State->AddRef();
				return Cospawn([this, State, AbortCallback, Function, Message = std::move(Message)]() mutable
				{
					(*Function)(this, State, std::move(Message.Args)).When([this, State, AbortCallback]()
					{
						if (ControlSys.Dequeue())
							PullProcedure(State, AbortCallback);
					});
				});
			}
			else
			{
				Stream->ReadQueued(BLOB_SIZE, [this, State, AbortCallback](SocketPoll Event, const uint8_t* Buffer, size_t Size)
				{
					if (Packet::IsData(Event))
						return !State->PullIncomingMessage(Buffer, Size);
					else if (Packet::IsDone(Event))
						PullProcedure(State, AbortCallback);
					else if (Packet::IsError(Event))
						AbortCallback(State);
					return true;
				});
			}
		}
		void ServerNode::PushProcedure(Relay* State, const AbortCallback& AbortCallback)
		{
			VI_ASSERT(State && AbortCallback, "state and abort callback should be set");
			auto* Stream = State->AsSocket();
			if (!Stream)
				return;

			if (!State->BeginOutgoingMessage())
				return;

			Stream->WriteQueued(State->OutgoingBuffer(), State->OutgoingSize(), [this, Stream, State, AbortCallback](SocketPoll Event)
			{
				State->EndOutgoingMessage();
				if (Packet::IsDone(Event))
					PushProcedure(State, AbortCallback);
				else if (Packet::IsError(Event))
					AbortCallback(State);
			}, false);
		}
		void ServerNode::AbortInboundNode(InboundNode* Node)
		{
			VI_ASSERT(Node != nullptr, "node should be set");
			EraseNodeByInstance(Node, [this, Node]()
			{
				Node->Abort();
				Finalize(Node);
			});
		}
		void ServerNode::AbortOutboundNode(OutboundNode* Node)
		{
			VI_ASSERT(Node != nullptr, "node should be set");
			EraseNodeByInstance(Node, [this, Node]()
			{
				ReceiveOutboundNode(Optional::None);
				Node->Release();
			});
		}
		void ServerNode::AppendNode(Relay* State, TaskCallback&& Callback)
		{
			VI_ASSERT(State != nullptr && Callback, "node and callback should be set");
			UMutex<std::recursive_mutex> Unique(Exclusive);
			if (!IsActive())
				return;

			auto It = Nodes.find(State->AsInstance());
			if (It == Nodes.end() || It->second != State)
			{
				auto* Socket = State->AsSocket();
				if (Socket != nullptr)
					Socket->SetIoTimeout(0);

				auto& Node = Nodes[State->AsInstance()];
				Memory::Release(Node);
				Node = State;
				Node->AddRef();
				Unique.Unlock();
				if (!ControlSys.Enqueue())
				{
					Callback();
					return;
				}

				Cospawn([this, State, Callback = std::move(Callback)]() mutable
				{
					Connect(State).When([this, State, Callback = std::move(Callback)]() mutable
					{
						Callback();
						ControlSys.Dequeue();
					});
				});
			}
			else
			{
				Unique.Unlock();
				Callback();
			}
		}
		void ServerNode::EraseNode(Relay* State, TaskCallback&& Callback)
		{
			VI_ASSERT(State != nullptr && Callback, "node and callback should be set");
			EraseNodeByInstance(State->AsInstance(), std::move(Callback));
		}
		void ServerNode::EraseNodeByInstance(void* Instance, TaskCallback&& Callback)
		{
			VI_ASSERT(Instance != nullptr && Callback, "instance and callback should be set");
			UMutex<std::recursive_mutex> Unique(Exclusive);
			auto It = Nodes.find(Instance);
			if (It == Nodes.end())
				return;

			UPtr<Relay> State = It->second;
			Nodes.erase(It);
			Unique.Unlock();
			if (!ControlSys.Enqueue())
			{
				State->Invalidate();
				Callback();
				return;
			}

			auto* Copy = *State;
			Copy->AddRef();
			Cospawn([this, Copy, Callback = std::move(Callback)]() mutable
			{
				Copy->AddRef();
				Disconnect(Copy).When([this, Copy, Callback = std::move(Callback)]() mutable
				{
					Copy->Invalidate();
					Copy->Release();
					Callback();
					ControlSys.Dequeue();
				});
			});
		}
		void ServerNode::OnRequestOpen(InboundNode* Node)
		{
			VI_ASSERT(Node != nullptr, "node should be set");
			Relay* State = FindNodeByInstance(Node);
			if (!State)
			{
				UMutex<std::recursive_mutex> Unique(Exclusive);
				auto* Duplicate = Find(Node->Address);
				if (!Duplicate)
				{
					State = new Relay(NodeType::Inbound, Node);
					AppendNode(State, [this, State, Node]()
					{
						PullProcedure(State, std::bind(&ServerNode::AbortInboundNode, this, Node));
					});
				}
				else
				{
					Node->Abort();
					Finalize(Node);
				}
			}
			else
				PullProcedure(State, std::bind(&ServerNode::AbortInboundNode, this, Node));
		}
		void ServerNode::Startup()
		{
			if (!Protocol::Now().User.P2P.Server && !Protocol::Now().User.P2P.MaxOutboundConnections)
				return;

			SocketRouter* Config = new SocketRouter();
			Config->MaxConnections = (size_t)Protocol::Now().User.P2P.MaxInboundConnections;
			Config->SocketTimeout = (size_t)Protocol::Now().User.TCP.Timeout;
			ControlSys.ActivateAndEnqueue();
			ControlSys.Dequeue();

			uint32_t MethodMagic = OS::CPU::ToEndianness(OS::CPU::Endian::Little, Protocol::Now().Message.PacketMagic);
			uint32_t MethodRange = (uint32_t)std::numeric_limits<int32_t>::max();
			MethodAddress = (Algorithm::Hashing::Hash32d((uint8_t*)&MethodMagic, sizeof(MethodMagic))) % MethodRange;
			if (Protocol::Now().User.P2P.Server)
			{
				auto ListenerStatus = Config->Listen(Protocol::Now().User.P2P.Address, ToString(Protocol::Now().User.P2P.Port));
				VI_PANIC(ListenerStatus, "server listener error: %s", ListenerStatus.Error().what());

				auto ConfigureStatus = Configure(Config);
				VI_PANIC(ConfigureStatus, "server configuration error: %s", ConfigureStatus.Error().what());

				auto BindingStatus = Listen();
				VI_PANIC(BindingStatus, "server binding error: %s", BindingStatus.Error().what());

				if (Protocol::Now().User.P2P.Logging)
					VI_INFO("[p2p] p2p node listen (location: %s:%i, type: %s)", Protocol::Now().User.P2P.Address.c_str(), (int)Protocol::Now().User.P2P.Port, Protocol::Now().User.P2P.MaxOutboundConnections > 0 ? "in-out" : "in");
			}
			else if (Protocol::Now().User.P2P.MaxOutboundConnections > 0 && Protocol::Now().User.P2P.Logging)
				VI_INFO("[p2p] p2p node listen (type: out)");

			auto Mempool = Storages::Mempoolstate(__func__);
			Discovery.Count = Mempool.GetValidatorsCount().Or(0);

			auto MainValidator = Mempool.GetValidatorByOwnership(0);
			if (!MainValidator)
			{
				Validator.Wallet = Ledger::Wallet::FromSeed(*Crypto::RandomBytes(512));
				Validator.Node.Address = SocketAddress(Protocol::Now().User.P2P.Address, Protocol::Now().User.P2P.Port);
			}
			else
			{
				Validator.Wallet = std::move(MainValidator->second);
				Validator.Node = std::move(MainValidator->first);
			}

			Validator.Node.Ports.P2P = Protocol::Now().User.P2P.Port;
			Validator.Node.Ports.NDS = Protocol::Now().User.NDS.Port;
			Validator.Node.Ports.RPC = Protocol::Now().User.RPC.Port;
			Validator.Node.Services.Consensus = Protocol::Now().User.P2P.Server;
			Validator.Node.Services.Discovery = Protocol::Now().User.NDS.Server;
			Validator.Node.Services.Interface = Protocol::Now().User.RPC.Server;
			Validator.Node.Services.Proposer = Protocol::Now().User.P2P.Proposer;
			Validator.Node.Services.Public = Protocol::Now().User.RPC.UserUsername.empty();
			ApplyValidator(Mempool, Validator.Node, Validator.Wallet).Expect("failed to save trusted validator");

			auto NodeId = Codec::HexEncode(std::string_view((char*)this, sizeof(this)));
			Oracle::Paymaster::SubmitCallback(NodeId, std::bind(&ServerNode::ProposeTransactionLogs, this, std::placeholders::_1, std::placeholders::_2));

			auto Chain = Storages::Chainstate(__func__);
			auto Tip = Chain.GetLatestBlockHeader();
			if (Tip)
				AcceptDispatchpool(*Tip);
			else
				AcceptMempool();

			for (auto& Seed : Protocol::Now().User.Seeds)
			{
				auto Endpoint = Algorithm::Endpoint(Seed);
				if (!Endpoint.IsValid() || Routing::IsAddressReserved(Endpoint.Address))
				{
					if (Protocol::Now().User.P2P.Logging)
						VI_ERR("[p2p] seed resolver failed on \"%s\" seed: url not valid", Seed.c_str());
					continue;
				}
				
				Mempool.ApplyTrialAddress(Endpoint.Address);
			}

			Bind(&ServerNode::ProposeHandshake);
			Bind(&ServerNode::ApproveHandshake);
			Bind(&ServerNode::ProposeSeeds);
			Bind(&ServerNode::FindForkCollision);
			Bind(&ServerNode::VerifyForkCollision);
			Bind(&ServerNode::RequestForkBlock);
			Bind(&ServerNode::ProposeForkBlock);
			Bind(&ServerNode::RequestBlock);
			Bind(&ServerNode::ProposeBlock);
			Bind(&ServerNode::ProposeBlockHash);
			Bind(&ServerNode::RequestTransaction);
			Bind(&ServerNode::ProposeTransaction);
			Bind(&ServerNode::ProposeTransactionHash);
			Bind(&ServerNode::RequestMempool);
			Bind(&ServerNode::ProposeMempool);
			ClearMempool(false);
			Accept();
		}
		void ServerNode::Shutdown()
		{
			if (IsActive() || Protocol::Now().User.P2P.Server || Protocol::Now().User.P2P.MaxOutboundConnections)
			{
				if (Protocol::Now().User.P2P.Logging)
					VI_INFO("[p2p] p2p node shutdown requested");
			}

			if (IsActive())
				Unlisten(false);
		}
		void ServerNode::Reject(Relay* State)
		{
			auto* Socket = State->AsSocket();
			if (Socket != nullptr)
				Socket->Shutdown(true);
		}
		void ServerNode::ClearPendingTip()
		{
			PendingTip.Hash = 0;
			PendingTip.Block = Optional::None;
			if (PendingTip.Timeout != INVALID_TASK_ID)
			{
				Schedule::Get()->ClearTimeout(PendingTip.Timeout);
				PendingTip.Timeout = INVALID_TASK_ID;
			}
		}
		void ServerNode::AcceptForkTip(const uint256_t& ForkTip, const uint256_t& CandidateHash, Ledger::BlockHeader&& ForkTipBlock)
		{
			if (!ForkTip)
				return;

			Forks.clear();
			if (ForkTip != CandidateHash)
			{
				Forks[ForkTip] = std::move(ForkTipBlock);
				Mempool.Dirty = true;
			}
		}
		void ServerNode::AcceptPendingTip()
		{
			UMutex<std::recursive_mutex> Unique(Sync.Block);
			if (PendingTip.Block)
			{
				auto Chain = Storages::Chainstate(__func__);
				auto TipBlock = Chain.GetLatestBlockHeader();
				if (!TipBlock || *TipBlock < *PendingTip.Block)
				{
					if (AcceptBlockCandidate(*PendingTip.Block, PendingTip.Hash, 0))
						AcceptDispatchpool(*PendingTip.Block);
				}
			}
			ClearPendingTip();
		}
		bool ServerNode::ClearMempool(bool Wait)
		{
			if (!Protocol::Now().User.P2P.Proposer || IsSyncing())
				return false;

			return ControlSys.TimeoutIfNone("clear_mempool", Wait ? (Protocol::Now().User.Storage.TransactionTimeout * 1000) : 0, [this]()
			{
				auto Mempool = Storages::Mempoolstate(__func__);
				Mempool.ExpireTransactions().Report("mempool cleanup failed");
				ControlSys.ClearTimeout("clear_mempool");
				ClearMempool(true);
			});
		}
		bool ServerNode::AcceptMempool()
		{
			if (!Protocol::Now().User.P2P.Proposer || IsSyncing())
				return false;

			return ControlSys.TimeoutIfNone("accept_mempool", 0, [this]()
			{
			Retry:
				if (Mempool.BlockNumber && !*Mempool.BlockNumber)
				{
					auto Priority = Environment.Priority(Validator.Wallet.PublicKeyHash, Validator.Wallet.PrivateKey);
					if (!Priority)
					{
						auto Chain = Storages::Chainstate(__func__);
						auto Tip = Chain.GetLatestBlockHeader();
						if (Tip)
						{
							int64_t Delta = (int64_t)Protocol::Now().Time.Now() - Tip->Time;
							if (Delta < 0 || (uint64_t)Delta < Protocol::Now().Policy.ConsensusProofTime * Protocol::Now().Policy.ConsensusRecoveryProofs)
							{
								ControlSys.ClearTimeout("accept_mempool");
								return;
							}
						}
					}

					size_t Offset = 0, Count = 512;
					auto Mempool = Storages::Mempoolstate(__func__);
					while (IsActive())
					{
						auto Candidates = Mempool.GetTransactions(Offset, Count);
						Offset += Candidates ? Environment.Apply(std::move(*Candidates)) : 0;
						if (Count != (Candidates ? Candidates->size() : 0))
							break;
					}

					if (IsActive() && !Environment.Incoming.empty())
					{
						if (Protocol::Now().User.P2P.Logging)
						{
							if (Priority)
								VI_INFO("[p2p] on mempool chain extension evaluation (txns: %" PRIu64 ", priority: %" PRIu64 ")", (uint64_t)Environment.Incoming.size(), *Priority);
							else
								VI_INFO("[p2p] on mempool chain extension evaluation (txns: %" PRIu64 ", priority: recovery)", (uint64_t)Environment.Incoming.size());
						}

						String Errors;
						auto Evaluation = Environment.Evaluate(&Errors);
						Evaluation.Report("mempool proposal evaluation failed");
						if (Evaluation)
						{
							auto Solution = Environment.Solve(*Evaluation);
							Solution.Report("mempool proposal solution failed");
							if (Solution)
								AcceptBlock(nullptr, std::move(*Evaluation), 0);
						}

						if (!Errors.empty())
						{
							if (Evaluation)
								VI_WARN("[p2p] on mempool block %s acceptable evaluation error: %s", Algorithm::Encoding::Encode0xHex256(Evaluation->AsHash()).c_str(), Errors.c_str());
							else
								VI_ERR("[p2p] on mempool block evaluation error: %s", Errors.c_str());
						}
					}
					else if (IsActive())
						Environment.Cleanup().Report("mempool cleanup failed");
				}
				else if (Mempool.BlockNumber && *Mempool.BlockNumber != std::numeric_limits<uint64_t>::max())
				{
					auto Chain = Storages::Chainstate(__func__);
					if (*Mempool.BlockNumber <= Chain.GetLatestBlockNumber().Or(0) && Oracle::Datamaster::IsInitialized())
						goto Register;
				}
				else if (!Mempool.BlockNumber && Oracle::Datamaster::IsInitialized())
				{
				Register:
					auto Context = Ledger::TransactionContext();
					auto Transaction = UPtr<Transactions::Commitment>(Memory::New<Transactions::Commitment>());
					for (auto& Asset : Oracle::Datamaster::GetAssets(true))
						Transaction->SetOnline(Asset);

					auto Work = Context.GetAccountWork(Validator.Wallet.PublicKeyHash);
					if (!Work || !Work->IsOnline())
						Transaction->SetOnline();

					for (auto& Observer : Context.GetAccountObservers(Validator.Wallet.PublicKeyHash, 0, 1024).Or(Vector<States::AccountObserver>()))
					{
						if (!Observer.IsOnline() && Transaction->Observers.find(Observer.Asset) != Transaction->Observers.end())
							Transaction->SetOffline(Observer.Asset);
					}

					size_t Updates = Transaction->Worker != Ledger::WorkStatus::Standby ? 1 : 0;
					for (auto& Observer : Transaction->Observers)
						Updates += Observer.second != Ledger::WorkStatus::Standby ? 1 : 0;

					Mempool.BlockNumber = Updates > 0 ? std::numeric_limits<uint64_t>::max() : 0;
					if (!Updates)
					{
						if (Work && Work->Penalty > 0)
							Mempool.BlockNumber = Work->GetClosestProposalBlockNumber();		
						goto Retry;
					}

					UMutex<std::recursive_mutex> Unique(Sync.Account);
					auto AccountSequence = Validator.Wallet.GetLatestSequence().Or(1);
					Unique.Unlock();

					auto Chain = Storages::Chainstate(__func__);
					auto Balances = Chain.GetMultiformsByColumn(nullptr, States::AccountBalance::AsInstanceColumn(Validator.Wallet.PublicKeyHash), 0, 0, 64);
					if (Balances && !Balances->empty())
					{
						for (auto& State : *Balances)
						{
							auto& Balance = *(States::AccountBalance*)*State;
							if (Balance.GetBalance().IsPositive())
							{
								Transaction->Asset = Balance.Asset;
								break;
							}
							else if (!Transaction->Asset)
								Transaction->Asset = Balance.Asset;
						}
					}
					else
					{
						auto Assets = Oracle::Datamaster::GetAssets();
						Transaction->Asset = Assets[Math<size_t>::Random(0, Assets.size())];
					}

					if (!ProposeTransaction(nullptr, Transaction.Reset(), AccountSequence, PURPOSE_COMMITMENT))
					{
						if (Protocol::Now().User.P2P.Logging)
							VI_ERR("[p2p] on mempool commitment error: failed to register this validator");
					}
				}
				ControlSys.ClearTimeout("accept_mempool");
			});
		}
		bool ServerNode::AcceptDispatchpool(const Ledger::BlockHeader& Tip)
		{
			if (IsSyncing())
				return false;

			return ControlSys.TimeoutIfNone("accept_dispatchpool", 0, [this, Tip]()
			{
				Tip.DispatchAsync(Validator.Wallet).When([this](ExpectsLR<Ledger::BlockDispatch>&& Dispatch)
				{
					Dispatch.Report("dispatchpool execution failed");
					if (Dispatch)
					{
						Dispatch->Checkpoint().Report("dispatchpool checkpoint failed");
						if (!Dispatch->Outputs.empty())
						{
							UMutex<std::recursive_mutex> Unique(Sync.Account);
							auto AccountSequence = Validator.Wallet.GetLatestSequence().Or(1);
							Unique.Unlock();

							ControlSys.LockTimeout("accept_mempool");
							for (auto& Transaction : Dispatch->Outputs)
							{
								if (ProposeTransaction(nullptr, std::move(Transaction), AccountSequence, PURPOSE_DISPATCH))
									++AccountSequence;
							}
							if (ControlSys.UnlockTimeout("accept_mempool"))
								AcceptMempool();
						}
						else
							AcceptMempool();
					}
					else
						AcceptMempool();
					ControlSys.ClearTimeout("accept_dispatchpool");
				});
			});
		}
		bool ServerNode::AcceptBlock(Relay* From, Ledger::Block&& CandidateBlock, const uint256_t& ForkTip)
		{
			uint256_t CandidateHash = CandidateBlock.AsHash();
			auto Verification = From ? CandidateBlock.Verify(nullptr) : Environment.Verify(CandidateBlock);
			if (!Verification)
			{
				if (Protocol::Now().User.P2P.Logging)
					VI_WARN("[p2p] on block %s branch averted: %s", Algorithm::Encoding::Encode0xHex256(CandidateHash).c_str(), Verification.Error().what());
				return false;
			}

			auto Chain = Storages::Chainstate(__func__);
			if (Chain.GetBlockHeaderByHash(CandidateHash))
			{
				if (Protocol::Now().User.P2P.Logging)
					VI_INFO("[p2p] on block %s branch confirmed", Algorithm::Encoding::Encode0xHex256(CandidateHash).c_str());
				return true;
			}

			auto ForkTipBlock = Ledger::BlockHeader();
			if (ForkTip > 0)
			{
				UMutex<std::recursive_mutex> Unique(Sync.Block);
				auto It = Forks.find(ForkTip);
				if (It == Forks.end())
				{
					if (Protocol::Now().User.P2P.Logging)
						VI_WARN("[p2p] on block %s branch averted: fork reverted", Algorithm::Encoding::Encode0xHex256(CandidateHash).c_str());
					return false;
				}
				ForkTipBlock = It->second;
			}

			auto TipBlock = ForkTip > 0 ? ExpectsLR<Ledger::BlockHeader>(ForkTipBlock) : Chain.GetLatestBlockHeader();
			auto TipHash = TipBlock ? TipBlock->AsHash() : (uint256_t)0;
			auto BestTipWork = TipBlock ? TipBlock->AbsoluteWork : (uint256_t)0;
			auto ParentBlock = TipHash == CandidateBlock.ParentHash ? TipBlock : Chain.GetBlockHeaderByHash(CandidateBlock.ParentHash);
			auto ParentHash = ParentBlock ? ParentBlock->AsHash() : (uint256_t)0;
			int64_t BranchLength = (int64_t)CandidateBlock.Number - (int64_t)(TipBlock ? TipBlock->Number : 0);
			BranchLength = ForkTip > 0 ? abs(BranchLength) : BranchLength;
			if (BranchLength < 0 || (!ForkTip && CandidateBlock.AbsoluteWork < BestTipWork))
			{
				/*
													  <+> - <+> - <+> = ignore (weaker branch)
													 /
					<+> - <+> - <+> - <+> - <+> - <+> - <+>
											   \
												<+> = ignore (smaller branch)
				*/
				if (Protocol::Now().User.P2P.Logging)
					VI_WARN("[p2p] on block %s branch averted: not preferred %s (length: %" PRIi64 ")", Algorithm::Encoding::Encode0xHex256(CandidateHash).c_str(), BranchLength < 0 ? "branch" : "difficulty", BranchLength);
				return false;
			}
			else if (BranchLength == 0 && TipBlock && TipHash != CandidateHash && CandidateBlock < *TipBlock)
			{
				/*
													  <+> = ignore (weaker branch)
													 /
					<+> - <+> - <+> - <+> - <+> - <+> - <+>
				*/
				if (Protocol::Now().User.P2P.Logging)
					VI_WARN("[p2p] on block %s branch averted: not preferred difficulty", Algorithm::Encoding::Encode0xHex256(CandidateHash).c_str());
				return false;
			}
			else if (!ParentBlock && CandidateBlock.Number > 1)
			{
				if (!From)
				{
					if (Protocol::Now().User.P2P.Logging)
						VI_WARN("[p2p] on block %s branch averted: not preferred candidate", Algorithm::Encoding::Encode0xHex256(CandidateHash).c_str());
					return false;
				}

				UMutex<std::recursive_mutex> Unique(Sync.Block);
				bool HasBetterTip = Forks.empty();
				for (auto& ForkCandidateTip : Forks)
				{
					if (ForkCandidateTip.second < CandidateBlock)
					{
						HasBetterTip = true;
						break;
					}
				}

				if (!HasBetterTip)
				{
					/*
																   <+> = better orphan
																  /
						<+> - <+> - <+> - <+> - <+> - <+> ------------
															  \
															   <+> = weaker orphan
					*/
					if (Protocol::Now().User.P2P.Logging)
					{
						if (Forks.find(CandidateHash) != Forks.end())
							VI_INFO("[p2p] on block %s new best branch confirmed", Algorithm::Encoding::Encode0xHex256(CandidateHash).c_str());
						else
							VI_WARN("[p2p] on block %s branch averted: not preferred orpan branch", Algorithm::Encoding::Encode0xHex256(CandidateHash).c_str());
					}
					return false;
				}
				else if (Forks.find(CandidateHash) != Forks.end())
					return true;

				/*
					<+> - <+> - <+> - <+> - <+> - <+> ----
														  \
														   <+> = possibly orphan
				*/
				Forks[CandidateHash] = CandidateBlock;
				Mempool.Dirty = true;
				Unique.Unlock();
				if (!TipBlock)
					Call(From, &ServerNode::RequestForkBlock, { Format::Variable(CandidateHash), Format::Variable(uint256_t(0)), Format::Variable((uint64_t)1) });
				else
					Call(From, &ServerNode::FindForkCollision, { Format::Variable(CandidateHash), Format::Variable(TipBlock->Number) });
				
				if (Protocol::Now().User.P2P.Logging)
					VI_INFO("[p2p] on block %s new best branch found (height: %" PRIu64 ", distance: %" PRIu64 ")", Algorithm::Encoding::Encode0xHex256(CandidateHash).c_str(), CandidateBlock.Number, std::abs((int64_t)(TipBlock ? TipBlock->Number : 0) - (int64_t)CandidateBlock.Number));
				return true;
			}

			if (From != nullptr)
			{
				auto Validation = CandidateBlock.Validate(ParentBlock.Address());
				if (!Validation)
				{
					if (Protocol::Now().User.P2P.Logging)
						VI_WARN("[p2p] on block %s branch averted: %s", Algorithm::Encoding::Encode0xHex256(CandidateHash).c_str(), Validation.Error().what());
					return false;
				}
			}

			UMutex<std::recursive_mutex> Unique(Sync.Block);
			if (!ForkTip && CandidateBlock.Priority != 0 && (BranchLength == 0 || BranchLength == 1))
			{
				/*
					<+> - <+> - <+> - <+> - <+> - <+> = extension (non-zero priority, possible fork)
				*/
				if (PendingTip.Block)
				{
					if (PendingTip.Hash == CandidateHash)
					{
						if (Protocol::Now().User.P2P.Logging)
							VI_INFO("[p2p] on block %s branch confirmed", Algorithm::Encoding::Encode0xHex256(CandidateHash).c_str());
						return true;
					}
					else if (CandidateBlock < *PendingTip.Block)
					{
						if (Protocol::Now().User.P2P.Logging)
							VI_WARN("[p2p] on block %s branch averted: not preferred priority", Algorithm::Encoding::Encode0xHex256(CandidateHash).c_str());
						return false;
					}
				}

				PendingTip.Block = std::move(CandidateBlock);
				PendingTip.Hash = CandidateHash;
				PendingTip.Timeout = Schedule::Get()->SetTimeout(Protocol::Now().Policy.ConsensusProofTime, std::bind(&ServerNode::AcceptPendingTip, this));
				if (From != nullptr)
					Multicall(From, &ServerNode::ProposeBlockHash, { Format::Variable(PendingTip.Hash) });
				else
					Multicall(From, &ServerNode::ProposeBlock, { Format::Variable(PendingTip.Block->AsMessage().Data) });
				AcceptForkTip(ForkTip, CandidateHash, std::move(ForkTipBlock));
			}
			else
			{
				/*
					<+> - <+> - <+> - <+> - <+> - <+> = possible extension
											   \
												<+> - <+> = possible reorganization
				*/
				if (!AcceptBlockCandidate(CandidateBlock, CandidateHash, ForkTip))
					return false;

				if (From != nullptr)
					Multicall(From, &ServerNode::ProposeBlockHash, { Format::Variable(CandidateHash) });
				else
					Multicall(From, &ServerNode::ProposeBlock, { Format::Variable(CandidateBlock.AsMessage().Data) });

				AcceptForkTip(ForkTip, CandidateHash, std::move(ForkTipBlock));
				AcceptDispatchpool(CandidateBlock);
				ClearPendingTip();
				if (From != nullptr && Mempool.Dirty && !IsSyncing())
				{
					Call(From, &ServerNode::RequestMempool, { Format::Variable((uint64_t)0) });
					Mempool.Dirty = false;
				}
			}

			return true;
		}
		bool ServerNode::AcceptBlockCandidate(const Ledger::Block& CandidateBlock, const uint256_t& CandidateHash, const uint256_t& ForkTip)
		{
			auto Mutation = CandidateBlock.Checkpoint();
			if (!Mutation)
			{
				if (Protocol::Now().User.P2P.Logging)
					VI_WARN("[p2p] on block %s checkpoint failed: %s", Algorithm::Encoding::Encode0xHex256(CandidateHash).c_str(), Mutation.Error().what());
				return false;
			}

			if (Protocol::Now().User.P2P.Logging)
			{
				if (Mutation->IsFork)
					VI_INFO("[p2p] on block %s chain rollback (deleted: %" PRIu64 " blocks, resurrected: %" PRIu64 " txns)", Algorithm::Encoding::Encode0xHex256(CandidateHash).c_str(), Math64::Abs((int64_t)Mutation->OldTipBlockNumber - (int64_t)Mutation->NewTipBlockNumber), Mutation->Resurrections);
				VI_INFO("[p2p] on block %s chain %s (height: %" PRIu64 ", sync: %.2f%%, priority: %" PRIu64 ")", Algorithm::Encoding::Encode0xHex256(CandidateHash).c_str(), Mutation->IsFork ? "shortened" : "extended", CandidateBlock.Number, 100.0 * GetSyncProgress(ForkTip, CandidateBlock.Number), CandidateBlock.Priority);
			}
				
			if (Events.AcceptBlock)
				Events.AcceptBlock(CandidateHash, CandidateBlock, *Mutation);

			for (auto& Transaction : CandidateBlock.Transactions)
			{
				if (!memcmp(Transaction.Receipt.From, Validator.Wallet.PublicKeyHash, sizeof(Algorithm::Pubkeyhash)))
					AcceptProposalTransaction(CandidateBlock, Transaction);
			}

			return true;
		}
		bool ServerNode::AcceptProposalTransaction(const Ledger::Block& CheckpointBlock, const Ledger::BlockTransaction& Transaction)
		{
			if (Transaction.Transaction->AsType() == Transactions::Commitment::AsInstanceType())
			{
				std::string_view Purpose = PURPOSE_COMMITMENT;
				if (Transaction.Receipt.Successful)
				{
					auto Context = Ledger::TransactionContext();
					auto Work = Context.GetAccountWork(Validator.Wallet.PublicKeyHash);
					if (Work && Work->Status == Ledger::WorkStatus::Online)
					{
						Mempool.BlockNumber = Work->GetClosestProposalBlockNumber();
						if (*Mempool.BlockNumber <= CheckpointBlock.Number)
							AcceptMempool();
						else
							Mempool.BlockNumber = Optional::None;
					}
					else
						Mempool.BlockNumber = Optional::None;

					if (Protocol::Now().User.P2P.Logging)
						VI_INFO("[p2p] on transaction %s %.*s finalized (%s)", Algorithm::Encoding::Encode0xHex256(Transaction.Transaction->AsHash()).c_str(), (int)Purpose.size(), Purpose.data(), Mempool.BlockNumber ? "ready to propose blocks" : "cannot propose blocks yet");
				}
				else
				{
					Mempool.BlockNumber = Optional::None;
					if (Protocol::Now().User.P2P.Logging)
						VI_ERR("[p2p] on transaction %s %.*s error: %s", Algorithm::Encoding::Encode0xHex256(Transaction.Transaction->AsHash()).c_str(), (int)Purpose.size(), Purpose.data(), Transaction.Receipt.GetErrorMessages().Or(String("execution error")).c_str());
				}
			}
			else if (Protocol::Now().User.P2P.Logging)
			{
				std::string_view Purpose = Transaction.Transaction->AsType() == Transactions::Claim::AsInstanceType() ? PURPOSE_CLAIM : PURPOSE_OTHER;
				if (Transaction.Receipt.Successful)
					VI_INFO("[p2p] on transaction %s %.*s finalized", Algorithm::Encoding::Encode0xHex256(Transaction.Transaction->AsHash()).c_str(), (int)Purpose.size(), Purpose.data());
				else
					VI_ERR("[p2p] on transaction %s %.*s error: %s", Algorithm::Encoding::Encode0xHex256(Transaction.Transaction->AsHash()).c_str(), (int)Purpose.size(), Purpose.data(), Transaction.Receipt.GetErrorMessages().Or(String("execution error")).c_str());
			}
			return true;
		}
		bool ServerNode::Accept(Option<SocketAddress>&& Address)
		{
			if (Address && Routing::IsAddressReserved(*Address))
				return false;

			return Address ? ConnectOutboundNode(*Address) : ReceiveOutboundNode(Optional::None);
		}
		ExpectsLR<void> ServerNode::ProposeTransaction(Relay* From, UPtr<Ledger::Transaction>&& CandidateTx, uint64_t AccountSequence, const std::string_view& Purpose)
		{
			auto Mempool = Storages::Mempoolstate(__func__);
			auto Bandwidth = Mempool.GetBandwidthByOwner(Validator.Wallet.PublicKeyHash, CandidateTx->GetType());
			if (Bandwidth->Congested)
			{
				auto Price = Mempool.GetGasPrice(CandidateTx->Asset, 0.10);
				CandidateTx->SetOptimalGas(Price.Or(Decimal::Zero()));
			}
			else
				CandidateTx->SetOptimalGas(Decimal::Zero());

			if (CandidateTx->Sign(Validator.Wallet.PrivateKey, AccountSequence, Decimal::Zero()))
			{
				auto Status = AcceptTransaction(From, std::move(CandidateTx), AccountSequence);
				if (Protocol::Now().User.P2P.Logging && !Status)
					VI_ERR("[p2p] on transaction %s %.*s error: %s", Algorithm::Encoding::Encode0xHex256(CandidateTx->AsHash()).c_str(), (int)Purpose.size(), Purpose.data(), Status.Error().what());
				else if (Protocol::Now().User.P2P.Logging)
					VI_INFO("[p2p] on transaction %s %.*s accepted", Algorithm::Encoding::Encode0xHex256(CandidateTx->AsHash()).c_str(), (int)Purpose.size(), Purpose.data());
				return Status;
			}
			else
			{
				auto Status = LayerException("transaction sign failed");
				if (Protocol::Now().User.P2P.Logging)
					VI_ERR("[p2p] on transaction %s %.*s error: %s", Algorithm::Encoding::Encode0xHex256(CandidateTx->AsHash()).c_str(), (int)Purpose.size(), Purpose.data(), Status.what());
				return Status;
			}
		}
		ExpectsLR<void> ServerNode::AcceptTransaction(Relay* From, UPtr<Ledger::Transaction>&& CandidateTx, bool DeepValidation)
		{
			auto CandidateHash = CandidateTx->AsHash();
			auto Chain = Storages::Chainstate(__func__);
			if (Chain.GetTransactionByHash(CandidateHash))
			{
				if (Protocol::Now().User.P2P.Logging)
					VI_INFO("[p2p] on transaction %s confirmed", Algorithm::Encoding::Encode0xHex256(CandidateHash).c_str());
				return Expectation::Met;
			}

			Algorithm::Pubkeyhash Owner;
			if (!CandidateTx->Recover(Owner))
			{
				if (Protocol::Now().User.P2P.Logging)
					VI_WARN("[p2p] on transaction %s prevalidation failed: invalid signature", Algorithm::Encoding::Encode0xHex256(CandidateHash).c_str());
				return LayerException("signature key recovery failed");
			}

			Algorithm::Pubkeyhash PrevalidationOwner;
			auto Prevalidation = Ledger::TransactionContext::PrevalidateTx(*CandidateTx, CandidateHash, PrevalidationOwner);
			if (!Prevalidation)
			{
				if (Protocol::Now().User.P2P.Logging)
					VI_WARN("[p2p] on transaction %s prevalidation failed: %s", Algorithm::Encoding::Encode0xHex256(CandidateHash).c_str(), Prevalidation.Error().what());
				return Prevalidation.Error();
			}

			bool Event = CandidateTx->IsConsensus() && !memcmp(Validator.Wallet.PublicKeyHash, Owner, sizeof(Owner));
			if (Event || DeepValidation)
			{
				Ledger::Block TempBlock;
				TempBlock.Number = std::numeric_limits<int64_t>::max() - 1;

				Ledger::EvaluationContext TempEnvironment;
				memcpy(TempEnvironment.Proposer.PublicKeyHash, Validator.Wallet.PublicKeyHash, sizeof(Algorithm::Pubkeyhash));

				Ledger::BlockWork Cache;
				auto Validation = Ledger::TransactionContext::ValidateTx(&TempBlock, &TempEnvironment, *CandidateTx, CandidateHash, Cache);
				if (!Validation)
				{
					if (Protocol::Now().User.P2P.Logging)
						VI_WARN("[p2p] on transaction %s event skip: %s", Algorithm::Encoding::Encode0xHex256(CandidateHash).c_str(), Validation.Error().what());
					return Validation.Error();
				}
			}

			return BroacastTransaction(From, std::move(CandidateTx), Owner);
		}
		ExpectsLR<void> ServerNode::BroacastTransaction(Relay* From, UPtr<Ledger::Transaction>&& CandidateTx, const Algorithm::Pubkeyhash Owner)
		{
			auto CandidateHash = CandidateTx->AsHash();
			auto Mempool = Storages::Mempoolstate(__func__);
			auto Status = Mempool.AddTransaction(**CandidateTx);
			if (!Status)
			{
				if (Protocol::Now().User.P2P.Logging)
					VI_WARN("[p2p] on transaction %s mempool rejection: %s", Algorithm::Encoding::Encode0xHex256(CandidateHash).c_str(), Status.Error().what());
				return Status.Error();
			}

			if (Protocol::Now().User.P2P.Logging)
				VI_INFO("[p2p] on transaction %s accepted", Algorithm::Encoding::Encode0xHex256(CandidateHash).c_str());

			if (Events.AcceptTransaction)
				Events.AcceptTransaction(CandidateHash, *CandidateTx, Owner);

			if (From != nullptr)
				Multicall(From, &ServerNode::ProposeTransactionHash, { Format::Variable(CandidateTx->AsHash()) });
			else
				Multicall(From, &ServerNode::ProposeTransaction, { Format::Variable(CandidateTx->AsMessage().Data) });

			AcceptMempool();
			return Expectation::Met;
		}
		bool ServerNode::ReceiveOutboundNode(Option<SocketAddress>&& ErrorAddress)
		{
			auto& Peer = Protocol::Now().User.P2P;
			UMutex<std::recursive_mutex> Unique(Exclusive);
			size_t CurrentOutboundNodes = SizeOf(NodeType::Outbound) + CandidateNodes.size();
			if (!IsActive() || CurrentOutboundNodes >= Peer.MaxOutboundConnections)
				return false;

			Unique.Unlock();
			if (!ControlSys.Enqueue())
				return false;

			Cospawn([this, ErrorAddress = std::move(ErrorAddress)]() mutable
			{
				Discover(std::move(ErrorAddress), true).When([this](Option<SocketAddress>&& Address)
				{
					if (!ControlSys.Dequeue() || !Address)
						return;

					int32_t Status = ConnectOutboundNode(*Address);
					if (Status == -1)
						ReceiveOutboundNode(std::move(Address));
					else if (Status == 0)
						ReceiveOutboundNode(Optional::None);
				});
			});
			return true;
		}
		bool ServerNode::PushNextProcedure(Relay* State)
		{
			switch (State->TypeOf())
			{
				case NodeType::Inbound:
				{
					auto* Node = State->AsInboundNode();
					if (!Node)
						return false;

					Codefer([this, State, Node]() { PushProcedure(State, std::bind(&ServerNode::AbortInboundNode, this, Node)); });
					return true;
				}
				case NodeType::Outbound:
				{
					auto* Node = State->AsOutboundNode();
					if (!Node)
						return false;

					Codefer([this, State, Node]() { PushProcedure(State, std::bind(&ServerNode::AbortOutboundNode, this, Node)); });
					return true;
				}
				default:
					return false;
			}
		}
		bool ServerNode::IsActive()
		{
			return State == ServerState::Working;
		}
		bool ServerNode::IsSyncing()
		{
			UMutex<std::recursive_mutex> Unique(Sync.Block);
			return !Forks.empty();
		}
		double ServerNode::GetSyncProgress(const uint256_t& ForkTip, uint64_t CurrentNumber)
		{
			if (!CurrentNumber)
				return 1.0;

			UMutex<std::recursive_mutex> Unique(Sync.Block);
			auto It = Forks.find(ForkTip);
			return It != Forks.end() ? (CurrentNumber <= It->second.Number ? (double)CurrentNumber / (double)It->second.Number : 1.0) : 1.0;
		}
		const UnorderedMap<void*, Relay*>& ServerNode::GetNodes() const
		{
			return Nodes;
		}
		const UnorderedSet<OutboundNode*>& ServerNode::GetCandidateNodes() const
		{
			return CandidateNodes;
		}
		const SingleQueue<URef<RelayProcedure>>& ServerNode::GetMessages() const
		{
			return Messages;
		}
		ServiceControl::ServiceNode ServerNode::GetEntrypoint()
		{
			if (!Protocol::Now().User.P2P.Server && !Protocol::Now().User.P2P.MaxOutboundConnections)
				return ServiceControl::ServiceNode();

			ServiceControl::ServiceNode Entrypoint;
			Entrypoint.Startup = std::bind(&ServerNode::Startup, this);
			Entrypoint.Shutdown = std::bind(&ServerNode::Shutdown, this);
			return Entrypoint;
		}
		std::recursive_mutex& ServerNode::GetMutex()
		{
			return Exclusive;
		}
		Relay* ServerNode::Find(const SocketAddress& Address)
		{
			auto IpAddress = Address.GetIpAddress();
			if (!IpAddress)
				return nullptr;

			UMutex<std::recursive_mutex> Unique(Exclusive);
			for (auto& Node : Nodes)
			{
				auto& PeerAddress = Node.second->PeerAddress();
				if (PeerAddress == *IpAddress)
					return Node.second;
			}

			for (auto& Listener : Listeners)
			{
				if (*Listener->Address.GetIpAddress() == *IpAddress)
					return (Relay*)this;
			}

			return nullptr;
		}
		size_t ServerNode::SizeOf(NodeType Type)
		{
			UMutex<std::recursive_mutex> Unique(Exclusive);
			size_t Size = 0;
			for (auto& Node : Nodes)
				Size += Node.second->TypeOf() == Type ? 1 : 0;
			return Size;
		}
		int32_t ServerNode::ConnectOutboundNode(const SocketAddress& Address)
		{
			auto IpAddress = Address.GetIpAddress();
			if (!IpAddress)
				return -1;

			auto& Peer = Protocol::Now().User.P2P;
			UMutex<std::recursive_mutex> Unique(Exclusive);
			size_t CurrentOutboundNodes = CandidateNodes.size();
			if (CurrentOutboundNodes >= Peer.MaxOutboundConnections)
				return 1;

			for (auto& Node : CandidateNodes)
			{
				auto PeerIpAddress = Node->State.Address.GetIpAddress();
				if (PeerIpAddress && *PeerIpAddress == *IpAddress)
					return 0;
			}

			for (auto& Node : Nodes)
			{
				auto* Instance = Node.second->AsOutboundNode();
				if (!Instance)
					continue;

				++CurrentOutboundNodes;
				if (Node.second->PeerAddress() == *IpAddress)
					return 0;
			}

			OutboundNode* Node = new OutboundNode();
			CandidateNodes.insert(Node);
			Node->AddRef();
			Node->ConnectQueued(Address, true, PEER_NOT_SECURE, std::bind(&ServerNode::AcceptOutboundNode, this, Node, std::placeholders::_1));
			return 1;
		}
		Relay* ServerNode::FindNodeByInstance(void* Instance)
		{
			UMutex<std::recursive_mutex> Unique(Exclusive);
			auto It = Nodes.find(Instance);
			return It != Nodes.end() ? It->second : nullptr;
		}
		std::string_view ServerNode::NodeTypeOf(Relay* From)
		{
			switch (From->TypeOf())
			{
				case NodeType::Inbound:
					return "inbound";
				case NodeType::Outbound:
					return "outbound";
				default:
					return "relay";
			}
		}

		bool Routing::IsAddressReserved(const SocketAddress& Address)
		{
			if (Protocol::Now().Is(NetworkType::Regtest))
				return false;

			auto Value = Address.GetIpValue();
			if (!Value)
				return false;

			static std::array<SocketCidr, 20> ReservedIps =
			{
				*Vitex::Network::Utils::ParseAddressMask("0.0.0.0/8"),
				*Vitex::Network::Utils::ParseAddressMask("10.0.0.0/8"),
				*Vitex::Network::Utils::ParseAddressMask("100.64.0.0/10"),
				*Vitex::Network::Utils::ParseAddressMask("127.0.0.0/8"),
				*Vitex::Network::Utils::ParseAddressMask("169.254.0.0/16"),
				*Vitex::Network::Utils::ParseAddressMask("172.16.0.0/12"),
				*Vitex::Network::Utils::ParseAddressMask("192.0.0.0/24"),
				*Vitex::Network::Utils::ParseAddressMask("192.0.2.0/24"),
				*Vitex::Network::Utils::ParseAddressMask("192.168.0.0/16"),
				*Vitex::Network::Utils::ParseAddressMask("198.18.0.0/15"),
				*Vitex::Network::Utils::ParseAddressMask("198.51.100.0/24"),
				*Vitex::Network::Utils::ParseAddressMask("233.252.0.0/24"),
				*Vitex::Network::Utils::ParseAddressMask("255.255.255.255/32"),
				*Vitex::Network::Utils::ParseAddressMask("::/128"),
				*Vitex::Network::Utils::ParseAddressMask("::1/128"),
				*Vitex::Network::Utils::ParseAddressMask("::ffff:0:0/96"),
				*Vitex::Network::Utils::ParseAddressMask("::ffff:0:0:0/96"),
				*Vitex::Network::Utils::ParseAddressMask("2001:20::/28"),
				*Vitex::Network::Utils::ParseAddressMask("2001:db8::/32"),
				*Vitex::Network::Utils::ParseAddressMask("5f00::/16")
			};

			for (auto& Mask : ReservedIps)
			{
				if (Mask.IsMatching(*Value))
					return true;
			}

			return false;
		}
	}
}
